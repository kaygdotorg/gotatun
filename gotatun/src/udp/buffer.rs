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

use std::{net::SocketAddr, sync::Arc};

use futures::{FutureExt, select};
use tokio::{io, sync::mpsc};

use crate::packet::Packet;
#[cfg(any(not(target_os = "linux"), test))]
use crate::packet::PacketBufPool;
use crate::task::Task;
#[cfg(any(not(target_os = "linux"), test))]
use crate::udp::UdpRecv;
use crate::udp::UdpSend;

/// A [`UdpSend`] that wraps another [`UdpSend`] to provide buffering.
///
/// Packets sent on this [`UdpSend::send_to`] will be buffered on a channel, and asynchronously
/// processed on another task. This means [`UdpSend::send_to`] won't block unless the channel is
/// full.
#[derive(Clone)]
pub struct BufferedUdpSend {
    _send_task: Arc<Task>,

    /// Channel where IPv4 packets are sent to `_send_task`
    send_tx_v4: mpsc::Sender<(Packet, SocketAddr)>,

    /// Channel where IPv6 packets are sent to `_send_task`
    send_tx_v6: mpsc::Sender<(Packet, SocketAddr)>,
}

impl BufferedUdpSend {
    /// Wrap a [`UdpSend`] into a [`BufferedUdpSend`] with `capacity`.
    pub fn new(capacity: usize, udp_tx: impl UdpSend + 'static) -> Self {
        let (send_tx_v4, mut send_rx_v4) = mpsc::channel::<(Packet, SocketAddr)>(capacity);
        let (send_tx_v6, mut send_rx_v6) = mpsc::channel::<(Packet, SocketAddr)>(capacity);

        let send_task = Task::spawn("buffered UDP send", async move {
            let mut buf_v4 = vec![];
            let mut buf_v6 = vec![];
            let max_packet_count = udp_tx.max_number_of_packets_to_send();
            let mut send_many_buf = Default::default();

            loop {
                // use seperate channels because we musn't call `send_many_to` with mixed IPv4/IPv6.
                let (count, buf) = select! {
                    // recv_many is cancel-safe
                    n = send_rx_v4.recv_many(&mut buf_v4, max_packet_count).fuse() => (n, &mut buf_v4),
                    n = send_rx_v6.recv_many(&mut buf_v6, max_packet_count).fuse() => (n, &mut buf_v6),
                };
                // Dequeue stamps for armed probes; the matching sent stamps follow the send.
                #[cfg(all(feature = "probe-trace", target_os = "linux"))]
                let probes: Vec<u64> = if crate::probe_trace::armed() {
                    let ts = crate::probe_trace::now_ns();
                    buf.iter()
                        .enumerate()
                        .filter_map(|(index, (packet, _))| {
                            let key = crate::probe_trace::armed_key(packet, true)?;
                            crate::probe_trace::record(
                                crate::probe_trace::Stage::UdpDequeue,
                                key,
                                ts,
                                crate::probe_trace::batch_pos(count, index),
                            );
                            Some(key)
                        })
                        .collect()
                } else {
                    Vec::new()
                };
                match count {
                    0 => break,
                    1 => {
                        let (packet, addr) =
                            buf.pop().expect("recv_many received 1 packet into buf");
                        let _ = udp_tx
                            .send_to(packet, addr)
                            .await
                            .inspect_err(|e| tracing::trace!("send_to_err: {e:#}"));
                    }
                    2.. => {
                        // send all packets at once
                        if let Err(e) = udp_tx.send_many_to(&mut send_many_buf, buf).await {
                            tracing::trace!("send_to_many_err: {e:#}");
                            if !buf.is_empty() {
                                tracing::trace!(
                                    "send_to_many dropping {} packets due to error.",
                                    buf.len()
                                );
                                buf.clear(); // give up, drop the packets we meant to send
                            }
                        }
                    }
                }
                #[cfg(all(feature = "probe-trace", target_os = "linux"))]
                if !probes.is_empty() {
                    let ts = crate::probe_trace::now_ns();
                    for key in probes {
                        crate::probe_trace::record(
                            crate::probe_trace::Stage::UdpSent,
                            key,
                            ts,
                            count as u64,
                        );
                    }
                }
            }
        });

        Self {
            _send_task: Arc::new(send_task),
            send_tx_v4,
            send_tx_v6,
        }
    }
}

impl UdpSend for BufferedUdpSend {
    type SendManyBuf = ();

    async fn send_to(&self, packet: Packet, destination: SocketAddr) -> io::Result<()> {
        let tx = match destination {
            SocketAddr::V4(..) => &self.send_tx_v4,
            SocketAddr::V6(..) => &self.send_tx_v6,
        };
        tx.send((packet, destination))
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))?;
        Ok(())
    }

    fn max_number_of_packets_to_send(&self) -> usize {
        debug_assert_eq!(
            self.send_tx_v4.max_capacity(),
            self.send_tx_v6.max_capacity(),
        );
        self.send_tx_v4.max_capacity()
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
    use crate::udp::socket::{SockOpt, UdpSocket};

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
