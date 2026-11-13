// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//   Copyright (c) Mullvad VPN AB. All rights reserved.
//
// SPDX-License-Identifier: MPL-2.0

//! Generic buffered `UdpTransport` implementation.

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use tokio::{
    io,
    sync::{OwnedSemaphorePermit, Semaphore, mpsc},
};

use crate::packet::Packet;
#[cfg(any(not(target_os = "linux"), test))]
use crate::packet::PacketBufPool;
use crate::task::Task;
#[cfg(any(not(target_os = "linux"), test))]
use crate::udp::UdpRecv;
use crate::udp::UdpSend;

/// Identifies buffered UDP runs when send timing or queue tracing is enabled.
static NEXT_DIAGNOSTIC_RUN_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// A [`UdpSend`] that wraps another [`UdpSend`] to provide buffering.
///
/// Packets sent on this [`UdpSend::send_to`] will be buffered on a channel, and asynchronously
/// processed on another task. This means [`UdpSend::send_to`] won't block unless the channel is
/// full.
#[derive(Clone)]
pub struct BufferedUdpSend {
    _send_task: Arc<Task>,

    /// One FIFO keeps packets ordered when a peer's endpoint changes address family.
    send_tx: mpsc::Sender<BufferedUdpMessage>,
    packet_slots: Arc<Semaphore>,
    packet_capacity: usize,
}

/// One queued datagram or one ordered run of datagrams.
/// Timing metadata is present only for opt-in UDP send diagnostics.
enum BufferedUdpMessage {
    Single(
        Packet,
        SocketAddr,
        OwnedSemaphorePermit,
        Option<crate::diag::UdpSendBatchDiagnostic>,
    ),
    Batch(
        Vec<(Packet, SocketAddr)>,
        OwnedSemaphorePermit,
        Option<crate::diag::UdpSendBatchDiagnostic>,
    ),
}

/// Send one same-family UDP run through the transport's reusable send buffer.
async fn flush_udp_packets<U: UdpSend>(
    udp_tx: &U,
    send_buf: &mut U::SendManyBuf,
    packets: &mut Vec<(Packet, SocketAddr)>,
    send_diagnostic: Option<crate::diag::UdpSendBatchDiagnostic>,
) {
    let diagnostic = crate::diag::PIPELINE.on();
    let packet_count = packets.len();
    if crate::diag::UDP_SINGLE_SENDS.on() {
        let mut sent = 0;
        for (packet, address) in packets.drain(..) {
            match udp_tx.send_to(packet, address).await {
                Ok(()) => sent += 1,
                Err(error) => tracing::trace!("send_to_err: {error:#}"),
            }
        }
        if diagnostic {
            eprintln!("pipeline stage=udp_socket_send packets={sent}/{packet_count} mode=single");
        }
        return;
    }

    match packets.len() {
        0 => {}
        1 => {
            let (packet, addr) = packets.pop().expect("one packet was counted");
            let result = udp_tx.send_to(packet, addr).await;
            if diagnostic {
                eprintln!(
                    "pipeline stage=udp_socket_send packets={} mode=single success={}",
                    u8::from(result.is_ok()),
                    result.is_ok()
                );
            }
            if let Err(error) = result {
                tracing::trace!("send_to_err: {error:#}");
            }
        }
        _ => {
            let result = match send_diagnostic {
                Some(send_diagnostic) => {
                    crate::diag::with_udp_send_batch(
                        send_diagnostic,
                        udp_tx.send_many_to(send_buf, packets),
                    )
                    .await
                }
                None => udp_tx.send_many_to(send_buf, packets).await,
            };
            if diagnostic {
                eprintln!(
                    "pipeline stage=udp_socket_send packets={} mode=batch success={}",
                    if result.is_ok() {
                        packet_count
                    } else {
                        packet_count - packets.len()
                    },
                    result.is_ok()
                );
            }
            if let Err(error) = result {
                tracing::trace!("send_to_many_err: {error:#}");
                packets.clear();
            }
        }
    }
}

/// Send a bounded run in as few transport calls as its maximum batch size allows.
async fn flush_udp_run<U: UdpSend>(
    udp_tx: &U,
    send_buf: &mut U::SendManyBuf,
    packets: Vec<(Packet, SocketAddr)>,
    max_packet_count: usize,
    send_diagnostic: Option<crate::diag::UdpSendBatchDiagnostic>,
) {
    if packets.len() <= max_packet_count {
        let mut packets = packets;
        flush_udp_packets(udp_tx, send_buf, &mut packets, send_diagnostic).await;
        return;
    }

    let mut packets = packets.into_iter();
    while packets.len() > 0 {
        let mut batch = packets.by_ref().take(max_packet_count).collect::<Vec<_>>();
        flush_udp_packets(udp_tx, send_buf, &mut batch, send_diagnostic).await;
    }
}

impl BufferedUdpSend {
    /// Wrap a [`UdpSend`] into a [`BufferedUdpSend`] with `capacity`.
    pub fn new(capacity: usize, udp_tx: impl UdpSend + 'static) -> Self {
        let (send_tx, mut send_rx) = mpsc::channel::<BufferedUdpMessage>(capacity);
        let packet_slots = Arc::new(Semaphore::new(capacity));

        let send_task = Task::spawn("buffered UDP send", async move {
            let mut buf = vec![];
            let max_packet_count = udp_tx.max_number_of_packets_to_send().max(1);
            let mut send_many_buf = Default::default();
            let mut singles = Vec::with_capacity(max_packet_count);
            let mut single_permits = Vec::with_capacity(max_packet_count);
            let mut single_diagnostics = Vec::new();

            loop {
                let count = send_rx.recv_many(&mut buf, max_packet_count).await;
                if count == 0 {
                    break;
                }

                for message in buf.drain(..) {
                    match message {
                        BufferedUdpMessage::Single(packet, addr, permit, diagnostic) => {
                            if singles.first().is_some_and(|(_, first_addr)| {
                                matches!(first_addr, SocketAddr::V4(..))
                                    != matches!(addr, SocketAddr::V4(..))
                            }) {
                                let send_diagnostic = single_diagnostics.first().copied();
                                flush_udp_packets(
                                    &udp_tx,
                                    &mut send_many_buf,
                                    &mut singles,
                                    send_diagnostic,
                                )
                                .await;
                                single_permits.clear();
                                single_diagnostics.clear();
                            }
                            singles.push((packet, addr));
                            single_permits.push(permit);
                            if let Some(diagnostic) = diagnostic {
                                single_diagnostics.push(diagnostic);
                            }
                            if singles.len() == max_packet_count {
                                let send_diagnostic = single_diagnostics.first().copied();
                                flush_udp_packets(
                                    &udp_tx,
                                    &mut send_many_buf,
                                    &mut singles,
                                    send_diagnostic,
                                )
                                .await;
                                single_permits.clear();
                                single_diagnostics.clear();
                            }
                        }
                        BufferedUdpMessage::Batch(packets, permit, diagnostic) => {
                            let packet_count = packets.len();
                            let single_diagnostic = single_diagnostics.first().copied();
                            flush_udp_packets(
                                &udp_tx,
                                &mut send_many_buf,
                                &mut singles,
                                single_diagnostic,
                            )
                            .await;
                            single_permits.clear();
                            single_diagnostics.clear();
                            flush_udp_run(
                                &udp_tx,
                                &mut send_many_buf,
                                packets,
                                max_packet_count,
                                diagnostic,
                            )
                            .await;
                            if crate::diag::SEND_QUEUE.on()
                                && let Some(diagnostic) = diagnostic
                            {
                                eprintln!(
                                    "send_many complete direction=udp sequence={} packets={packet_count}",
                                    diagnostic.sequence
                                );
                            }
                            drop(permit);
                        }
                    }
                }

                let send_diagnostic = single_diagnostics.first().copied();
                flush_udp_packets(&udp_tx, &mut send_many_buf, &mut singles, send_diagnostic).await;
                single_permits.clear();
                single_diagnostics.clear();
            }
        });

        Self {
            _send_task: Arc::new(send_task),
            send_tx,
            packet_slots,
            packet_capacity: capacity,
        }
    }
}

impl UdpSend for BufferedUdpSend {
    type SendManyBuf = ();

    async fn send_to(&self, packet: Packet, destination: SocketAddr) -> io::Result<()> {
        let send_timing = crate::diag::UDP_SEND_TIMING.on();
        let packet_permit_wait_started_ns = send_timing.then(crate::diag::udp_send_monotonic_now);
        let permit = Arc::clone(&self.packet_slots)
            .acquire_owned()
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))?;
        let packet_permit_wait_ns = packet_permit_wait_started_ns
            .map(|started_ns| crate::diag::udp_send_monotonic_now().saturating_sub(started_ns));
        if send_timing {
            let channel_reserve_wait_started_ns = crate::diag::udp_send_monotonic_now();
            let queue_permit = self
                .send_tx
                .reserve()
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))?;
            let channel_reserve_wait_ns = crate::diag::udp_send_monotonic_now()
                .saturating_sub(channel_reserve_wait_started_ns);
            let diagnostic = crate::diag::UdpSendBatchDiagnostic::new(
                0,
                self.packet_capacity
                    .saturating_sub(self.packet_slots.available_permits()),
                1,
                packet.len(),
                packet_permit_wait_ns.unwrap_or_default(),
                channel_reserve_wait_ns,
            );
            queue_permit.send(BufferedUdpMessage::Single(
                packet,
                destination,
                permit,
                Some(diagnostic),
            ));
        } else {
            self.send_tx
                .send(BufferedUdpMessage::Single(
                    packet,
                    destination,
                    permit,
                    None,
                ))
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))?;
        }
        Ok(())
    }

    async fn send_many_to(
        &self,
        _send_buf: &mut Self::SendManyBuf,
        packets: &mut Vec<(Packet, SocketAddr)>,
    ) -> io::Result<()> {
        if packets.is_empty() {
            return Ok(());
        }
        let is_v4 = matches!(packets[0].1, SocketAddr::V4(..));
        if packets
            .iter()
            .any(|(_, addr)| matches!(addr, SocketAddr::V4(..)) != is_v4)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a UDP run cannot mix address families",
            ));
        }
        while !packets.is_empty() {
            let count = packets.len().min(self.packet_capacity);
            let queue_trace = crate::diag::SEND_QUEUE.on();
            let send_timing = crate::diag::UDP_SEND_TIMING.on();
            let packet_permit_wait_started_ns =
                send_timing.then(crate::diag::udp_send_monotonic_now);
            let sequence =
                queue_trace.then(|| NEXT_DIAGNOSTIC_RUN_SEQUENCE.fetch_add(1, Ordering::Relaxed));
            if queue_trace && let Some(sequence) = sequence {
                eprintln!(
                    "send_many enqueue_wait direction=udp sequence={sequence} packets={count} available={}",
                    self.packet_slots.available_permits()
                );
            }
            let permit_count = u32::try_from(count).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("UDP run is too large: {e}"),
                )
            })?;
            let permit = Arc::clone(&self.packet_slots)
                .acquire_many_owned(permit_count)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))?;
            let packet_permit_wait_ns = packet_permit_wait_started_ns
                .map(|started_ns| crate::diag::udp_send_monotonic_now().saturating_sub(started_ns));
            if queue_trace && let Some(sequence) = sequence {
                eprintln!(
                    "send_many permit_acquired direction=udp sequence={sequence} packets={count}"
                );
            }
            let batch = if count == packets.len() {
                std::mem::take(packets)
            } else {
                packets.drain(..count).collect()
            };
            let batch_bytes = if send_timing {
                batch.iter().map(|(packet, _)| packet.len()).sum()
            } else {
                0
            };
            let enqueue_result = if send_timing {
                let channel_reserve_wait_started_ns = crate::diag::udp_send_monotonic_now();
                match self.send_tx.reserve().await {
                    Ok(queue_permit) => {
                        let channel_reserve_wait_ns = crate::diag::udp_send_monotonic_now()
                            .saturating_sub(channel_reserve_wait_started_ns);
                        let diagnostic = crate::diag::UdpSendBatchDiagnostic::new(
                            sequence.unwrap_or_default(),
                            self.packet_capacity
                                .saturating_sub(self.packet_slots.available_permits()),
                            count,
                            batch_bytes,
                            packet_permit_wait_ns.unwrap_or_default(),
                            channel_reserve_wait_ns,
                        );
                        queue_permit.send(BufferedUdpMessage::Batch(
                            batch,
                            permit,
                            Some(diagnostic),
                        ));
                        Ok(())
                    }
                    Err(_) => Err(batch),
                }
            } else {
                match self
                    .send_tx
                    .send(BufferedUdpMessage::Batch(batch, permit, None))
                    .await
                {
                    Ok(()) => Ok(()),
                    Err(error) => match error.0 {
                        BufferedUdpMessage::Batch(batch, _, _) => Err(batch),
                        BufferedUdpMessage::Single(..) => {
                            unreachable!("send_many_to queues a batch")
                        }
                    },
                }
            };
            if let Err(mut unsent) = enqueue_result {
                if queue_trace && let Some(sequence) = sequence {
                    eprintln!(
                        "send_many enqueue_failed direction=udp sequence={sequence} packets={count}"
                    );
                }
                unsent.append(packets);
                *packets = unsent;
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "UDP send task stopped",
                ));
            }
            if queue_trace && let Some(sequence) = sequence {
                eprintln!("send_many enqueued direction=udp sequence={sequence} packets={count}");
            }
        }
        Ok(())
    }

    fn max_number_of_packets_to_send(&self) -> usize {
        self.send_tx.max_capacity()
    }
}

/// A [`UdpRecv`] that wraps another [`UdpRecv`] to provide buffering.
///
/// This will spawn a background task that continuously calls [`UdpRecv::recv_from`] until the
/// buffer is full. Any call to [`UdpRecv::recv_from`] on _this_ object will not block unless the
/// buffer is empty.
#[cfg(any(not(target_os = "linux"), test))]
pub struct BufferedUdpReceive {
    _recv_task: Arc<Task>,
    recv_rx: mpsc::Receiver<io::Result<(Packet, SocketAddr)>>,
}

#[cfg(any(not(target_os = "linux"), test))]
impl BufferedUdpReceive {
    /// Wrap a [`UdpRecv`] into a [`BufferedUdpReceive`] with `capacity`.
    pub fn new(
        capacity: usize,
        mut udp_rx: impl UdpRecv + 'static,
        mut recv_pool: PacketBufPool,
    ) -> Self {
        let (recv_tx, recv_rx) = mpsc::channel(capacity);

        let recv_task = Task::spawn("buffered UDP receive", async move {
            let mut recv_many_buf = Default::default();
            let mut packet_bufs = vec![];
            let mut dropped: u64 = 0;

            loop {
                // Read packets from the socket. Only a gone socket ends this task; a bad
                // datagram is dropped, and what the batch delivered before it is forwarded.
                if let Err(err) = udp_rx
                    .recv_many_from(&mut recv_many_buf, &mut recv_pool, &mut packet_bufs)
                    .await
                {
                    if crate::udp::is_fatal_udp_error(&err) {
                        let _ = recv_tx.send(Err(err)).await;
                        return;
                    }
                    dropped += 1;
                    if dropped.is_power_of_two() {
                        tracing::warn!(
                            "Dropped undecodable UDP datagram ({dropped} so far): {err}"
                        );
                    }
                    tokio::task::yield_now().await;
                }

                for (packet_buf, src) in packet_bufs.drain(..) {
                    match recv_tx.try_send(Ok((packet_buf, src))) {
                        Ok(()) => (),
                        Err(mpsc::error::TrySendError::Full(packet)) => {
                            if recv_tx.send(packet).await.is_err() {
                                // Buffer dropped
                                return;
                            }
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => return,
                    }
                }
            }
        });

        Self {
            _recv_task: Arc::new(recv_task),
            recv_rx,
        }
    }
}

#[cfg(any(not(target_os = "linux"), test))]
impl UdpRecv for BufferedUdpReceive {
    type RecvManyBuf = ();

    async fn recv_from(&mut self, _pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        let Some(packet) = self.recv_rx.recv().await else {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "UDP receive task stopped",
            ));
        };
        packet
    }
}

#[cfg(all(test, target_os = "linux"))]
mod test {
    use super::*;
    use crate::udp::{
        UdpSend,
        socket::{SockOpt, UdpSocket},
    };
    use std::time::Duration;
    use tokio::sync::mpsc;
    use zerocopy::IntoBytes;

    /// Records datagrams that cross the buffered send boundary.
    #[derive(Clone)]
    struct RecordingUdpSend(mpsc::UnboundedSender<(Vec<u8>, SocketAddr)>);

    impl UdpSend for RecordingUdpSend {
        type SendManyBuf = ();

        async fn send_to(&self, packet: Packet, destination: SocketAddr) -> io::Result<()> {
            self.0
                .send((packet.as_bytes().to_vec(), destination))
                .expect("the test receiver remains open");
            Ok(())
        }
    }

    /// Hands out scripted receive results, then waits forever.
    struct Script(std::collections::VecDeque<io::Result<(Packet, SocketAddr)>>);

    impl UdpRecv for Script {
        type RecvManyBuf = ();

        async fn recv_from(
            &mut self,
            _pool: &mut PacketBufPool,
        ) -> io::Result<(Packet, SocketAddr)> {
            match self.0.pop_front() {
                Some(result) => result,
                None => std::future::pending().await,
            }
        }
    }

    fn datagram(payload: &[u8]) -> (Packet, SocketAddr) {
        (
            Packet::from_bytes(bytes::BytesMut::from(payload)),
            "127.0.0.1:51820".parse().unwrap(),
        )
    }

    /// A run larger than the buffer capacity is split without waiting for impossible permits.
    #[tokio::test]
    async fn send_many_splits_runs_larger_than_the_buffer_capacity() {
        let (sent_tx, mut sent_rx) = mpsc::unbounded_channel();
        let send = BufferedUdpSend::new(1, RecordingUdpSend(sent_tx));
        let address = "127.0.0.1:51820".parse().unwrap();
        let mut packets = vec![
            (
                Packet::from_bytes(bytes::BytesMut::from(&b"first"[..])),
                address,
            ),
            (
                Packet::from_bytes(bytes::BytesMut::from(&b"second"[..])),
                address,
            ),
            (
                Packet::from_bytes(bytes::BytesMut::from(&b"third"[..])),
                address,
            ),
        ];
        let mut send_buf = ();

        tokio::time::timeout(
            Duration::from_secs(1),
            send.send_many_to(&mut send_buf, &mut packets),
        )
        .await
        .expect("an oversized run must not wait for impossible capacity")
        .expect("the buffered send task must accept each chunk");
        assert!(packets.is_empty());

        for expected in [b"first".as_slice(), b"second", b"third"] {
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), sent_rx.recv())
                    .await
                    .expect("the packet must cross the buffer")
                    .expect("the send task remains open")
                    .0,
                expected
            );
        }
    }

    /// A peer that changes address family still sends its queued packets in slot order.
    #[tokio::test]
    async fn send_many_preserves_order_across_address_families() {
        let (sent_tx, mut sent_rx) = mpsc::unbounded_channel();
        let send = BufferedUdpSend::new(4, RecordingUdpSend(sent_tx));
        let address_v6 = "[::1]:51820".parse().unwrap();
        let address_v4 = "127.0.0.1:51820".parse().unwrap();
        let mut send_buf = ();
        let mut first = vec![(
            Packet::from_bytes(bytes::BytesMut::from(&b"first"[..])),
            address_v6,
        )];
        let mut second = vec![(
            Packet::from_bytes(bytes::BytesMut::from(&b"second"[..])),
            address_v4,
        )];

        send.send_many_to(&mut send_buf, &mut first)
            .await
            .expect("the first peer run is queued");
        send.send_many_to(&mut send_buf, &mut second)
            .await
            .expect("the next peer run is queued");

        for expected in [b"first".as_slice(), b"second"] {
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), sent_rx.recv())
                    .await
                    .expect("both peer runs must be sent")
                    .expect("the UDP send task remains open")
                    .0,
                expected,
            );
        }
    }

    /// A datagram the socket layer refuses (e.g. truncated) is dropped and the next one is
    /// still delivered; before #260 the first error stopped the receive task for good.
    #[tokio::test]
    async fn bad_datagram_is_dropped_and_the_next_one_passes() {
        let script = Script(
            [
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated UDP GRO receive",
                )),
                Ok(datagram(b"after-bad")),
            ]
            .into(),
        );
        let mut receiver = BufferedUdpReceive::new(16, script, PacketBufPool::new(4));

        let (packet, _) = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            receiver.recv_from(&mut PacketBufPool::new(1)),
        )
        .await
        .expect("the valid datagram must arrive")
        .expect("a bad datagram must not be reported as a receive failure");
        assert_eq!(&packet[..], b"after-bad");
    }

    /// A gone socket is still reported, and the receive task then stops.
    #[tokio::test]
    async fn closed_socket_still_stops_the_receiver() {
        let script = Script([Err(io::Error::from_raw_os_error(libc::EBADF))].into());
        let mut receiver = BufferedUdpReceive::new(16, script, PacketBufPool::new(4));
        let mut pool = PacketBufPool::new(1);

        let first = receiver.recv_from(&mut pool).await;
        assert_eq!(
            first.err().and_then(|e| e.raw_os_error()),
            Some(libc::EBADF)
        );
        let second = receiver.recv_from(&mut pool).await;
        assert_eq!(
            second.err().map(|e| e.kind()),
            Some(io::ErrorKind::BrokenPipe)
        );
    }

    #[test]
    fn only_a_gone_socket_is_fatal() {
        use crate::udp::is_fatal_udp_error;
        for kind in [
            io::ErrorKind::InvalidData,
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::WouldBlock,
        ] {
            assert!(!is_fatal_udp_error(&io::Error::from(kind)), "{kind:?}");
        }
        for err in [
            io::Error::from_raw_os_error(libc::EBADF),
            io::Error::from_raw_os_error(libc::ENOTSOCK),
            io::Error::from(io::ErrorKind::UnexpectedEof),
            io::Error::from(io::ErrorKind::BrokenPipe),
        ] {
            assert!(is_fatal_udp_error(&err), "{err:?}");
        }
    }

    #[tokio::test]
    /// Regression test for security advisory GHSA-6gxq-8xp9-742r.
    async fn empty_loopback_datagram_mustnt_stop_buffered_udp_receive() {
        let socket = UdpSocket::bind("127.0.0.1:0".parse().unwrap(), SockOpt::default()).unwrap();
        let addr = socket.local_addr().unwrap();
        let mut receiver = BufferedUdpReceive::new(16, socket, PacketBufPool::new(16));
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();

        sender.send_to(&[], addr).unwrap();
        sender.send_to(b"after-empty", addr).unwrap();

        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            receiver.recv_from(&mut PacketBufPool::new(1)),
        )
        .await
        .expect("the receive task must stop promptly")
        .expect("the panicked receive task must not close its channel");
    }
}
