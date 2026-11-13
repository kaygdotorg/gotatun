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

use crate::packet::{Packet, PacketBufPool};
use crate::task::Task;
use crate::udp::{UdpRecv, UdpSend};

// Bound work handed to the device task so a large socket batch cannot monopolize it.
const UDP_RECEIVE_BATCH_LIMIT: usize = 64;

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
pub struct BufferedUdpReceive {
    _recv_task: Arc<Task>,
    recv_rx: mpsc::Receiver<io::Result<(Packet, SocketAddr)>>,
    pending_error: Option<io::Error>,
}

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

            loop {
                // Read packets from the socket.
                if let Err(err) = udp_rx
                    .recv_many_from(&mut recv_many_buf, &mut recv_pool, &mut packet_bufs)
                    .await
                {
                    let _ = recv_tx.send(Err(err)).await;
                    return;
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
            pending_error: None,
        }
    }
}

impl UdpRecv for BufferedUdpReceive {
    type RecvManyBuf = Vec<io::Result<(Packet, SocketAddr)>>;

    async fn recv_from(&mut self, _pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        if let Some(error) = self.pending_error.take() {
            return Err(error);
        }

        let Some(packet) = self.recv_rx.recv().await else {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "UDP receive task stopped",
            ));
        };
        packet
    }

    fn recv_many_from(
        &mut self,
        recv_buf: &mut Self::RecvManyBuf,
        _pool: &mut PacketBufPool,
        packets: &mut Vec<(Packet, SocketAddr)>,
    ) -> impl std::future::Future<Output = io::Result<()>> + Send {
        async move {
            if let Some(error) = self.pending_error.take() {
                return Err(error);
            }

            recv_buf.clear();
            let count = self
                .recv_rx
                .recv_many(recv_buf, UDP_RECEIVE_BATCH_LIMIT)
                .await;
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "UDP receive task stopped",
                ));
            }

            let mut received_any = false;
            for result in recv_buf.drain(..) {
                match result {
                    Ok(packet) => {
                        packets.push(packet);
                        received_any = true;
                    }
                    Err(error) if received_any => {
                        self.pending_error = Some(error);
                        break;
                    }
                    Err(error) => return Err(error),
                }
            }

            Ok(())
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod test {
    use super::*;
    use crate::udp::socket::{SockOpt, UdpSocket};

    struct BatchThenErrorUdpRecv {
        batch_sent: bool,
        packet_count: usize,
    }

    impl UdpRecv for BatchThenErrorUdpRecv {
        type RecvManyBuf = ();

        async fn recv_from(
            &mut self,
            _pool: &mut PacketBufPool,
        ) -> io::Result<(Packet, SocketAddr)> {
            std::future::pending().await
        }

        fn recv_many_from(
            &mut self,
            _recv_buf: &mut Self::RecvManyBuf,
            pool: &mut PacketBufPool,
            packets: &mut Vec<(Packet, SocketAddr)>,
        ) -> impl std::future::Future<Output = io::Result<()>> + Send {
            let batch_sent = std::mem::replace(&mut self.batch_sent, true);
            let packet_count = self.packet_count;
            async move {
                if batch_sent {
                    return Err(io::Error::other("synthetic receive error"));
                }

                let source = "127.0.0.1:51820".parse().expect("valid source address");
                for sequence in 0..packet_count {
                    let mut packet = pool.get();
                    packet.buf_mut().clear();
                    let sequence = u16::try_from(sequence).expect("test sequence fits in u16");
                    packet.buf_mut().extend_from_slice(&sequence.to_be_bytes());
                    packets.push((packet, source));
                }
                Ok(())
            }
        }
    }

    #[tokio::test]
    async fn buffered_udp_receive_batches_packets_in_order_before_forwarding_errors() {
        const PACKET_COUNT: usize = 130;

        let mut receiver = BufferedUdpReceive::new(
            256,
            BatchThenErrorUdpRecv {
                batch_sent: false,
                packet_count: PACKET_COUNT,
            },
            PacketBufPool::new(256),
        );
        let mut pool = PacketBufPool::new(1);
        let mut recv_buf = Default::default();
        let mut received = Vec::with_capacity(PACKET_COUNT);

        // Let the producer fill the bounded queue so this checks batch dequeue, not arrival timing.
        tokio::task::yield_now().await;

        loop {
            let mut batch = Vec::new();
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                receiver.recv_many_from(&mut recv_buf, &mut pool, &mut batch),
            )
            .await
            .expect("buffered UDP receive must not stall")
            .map(|()| batch);

            let batch = match result {
                Ok(batch) => batch,
                Err(error) => {
                    assert_eq!(error.kind(), io::ErrorKind::Other);
                    break;
                }
            };

            assert!(!batch.is_empty(), "successful receive must return packets");
            assert!(batch.len() <= 64, "receive batch must remain bounded");
            if received.is_empty() {
                assert!(
                    batch.len() > 1,
                    "queued datagrams should be drained together"
                );
            }

            for (packet, _) in batch {
                let sequence = usize::from(u16::from_be_bytes(
                    packet[..2].try_into().expect("sequence has two bytes"),
                ));
                received.push(sequence);
            }
        }

        assert_eq!(received, (0..PACKET_COUNT).collect::<Vec<_>>());
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
