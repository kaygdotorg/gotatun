// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

//! One receiver for the main socket and, when the device has one, the side socket
//! (#260, J1211; see `side_port` in the crate source).
//!
//! The device runs a single receive task, because handshake backlog, packet pool and crypto
//! ordering belong to it. [`WithSide`] lets that task listen on both sockets without a second
//! task: the main socket keeps its batch receive (`recvmmsg`, GRO, `recvmsg_x`) and the side
//! socket, which should see next to nothing, is read one datagram at a time.
//!
//! **Why listen at all.** A sender puts small datagrams on the side flow, and a receiver that
//! has the receive rule never moves its peer's endpoint to the side port, so nothing is
//! normally sent *to* a side port. Listening is insurance: a peer that reaches our side port
//! anyway (an older node's roam, a NAT mapping that rebinds onto it, a mark that an on-path
//! device cleared) is heard instead of black-holed.

use std::{io, net::SocketAddr};

use crate::{
    packet::{Packet, PacketBufPool},
    udp::UdpRecv,
};

/// The receive half of the main socket plus, optionally, the side socket's.
///
/// With `side` set to `None` it is exactly the main receiver: every method forwards, and
/// [`WithSide::recv_many_from`] adds no polling.
pub(crate) struct WithSide<R: UdpRecv> {
    /// The main socket's receiver.
    main: R,
    /// The side socket's receiver and its own small buffer pool. A separate pool because the
    /// main receive future borrows the device's pool while both are polled together.
    side: Option<(R, PacketBufPool)>,
}

impl<R: UdpRecv> WithSide<R> {
    /// Wrap `main`; `side` is the side socket's receiver, when the device bound one.
    pub(crate) fn new(main: R, side: Option<R>) -> Self {
        Self {
            main,
            side: side.map(|side| (side, PacketBufPool::new_lazy(SIDE_POOL))),
        }
    }
}

/// Buffers the side socket's pool keeps. It carries almost nothing; this only avoids an
/// allocation per datagram when a peer does use it.
const SIDE_POOL: usize = 16;

/// The scratch space [`WithSide`] hands to the main receiver, and which half the last call read.
#[derive(Default)]
pub(crate) struct SideRecvBuf<B> {
    /// The main receiver's own buffer.
    main: B,
    /// Whether the last call returned a datagram read from the side socket (it has no kernel
    /// receive stamp, so [`UdpRecv::rx_timestamp_ns`] answers 0 for it).
    from_side: bool,
}

impl<R: UdpRecv> UdpRecv for WithSide<R> {
    type RecvManyBuf = SideRecvBuf<R::RecvManyBuf>;

    async fn recv_from(&mut self, pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        // Only the batch path is used by the device; the single-datagram path serves the main
        // socket, which is all a caller of it can expect.
        self.main.recv_from(pool).await
    }

    /// Receive from the main socket, or one datagram from the side socket if that is ready
    /// first. The main socket is polled first, so the side socket never delays bulk.
    ///
    /// A failing side socket is dropped with a warning instead of failing the device: it is
    /// insurance, and the main socket still works.
    async fn recv_many_from(
        &mut self,
        recv_buf: &mut Self::RecvManyBuf,
        pool: &mut PacketBufPool,
        packets: &mut Vec<(Packet, SocketAddr)>,
    ) -> io::Result<()> {
        recv_buf.from_side = false;
        let Some((side, side_pool)) = self.side.as_mut() else {
            return self
                .main
                .recv_many_from(&mut recv_buf.main, pool, packets)
                .await;
        };
        let received_from_side = tokio::select! {
            biased;
            result = self.main.recv_many_from(&mut recv_buf.main, pool, packets) => {
                return result;
            }
            result = side.recv_from(side_pool) => result,
        };
        match received_from_side {
            Ok(received) => {
                recv_buf.from_side = true;
                packets.push(received);
                Ok(())
            }
            Err(error) => {
                tracing::warn!("The side UDP socket stopped receiving: {error}");
                self.side = None;
                Ok(())
            }
        }
    }

    fn rx_timestamp_ns(recv_buf: &Self::RecvManyBuf, index: usize) -> u64 {
        if recv_buf.from_side {
            0
        } else {
            R::rx_timestamp_ns(&recv_buf.main, index)
        }
    }

    fn release_recv_buf(&self, recv_buf: &mut Self::RecvManyBuf) {
        self.main.release_recv_buf(&mut recv_buf.main);
    }

    fn enable_udp_gro(&self) -> io::Result<()> {
        self.main.enable_udp_gro()
    }
}

#[cfg(test)]
mod tests {
    use super::WithSide;
    use crate::{
        packet::{Packet, PacketBufPool},
        udp::{
            UdpRecv, UdpTransportFactory, UdpTransportFactoryParams, socket::UdpSocketFactory,
        },
    };

    /// The default socket factory binds a side pair on its own port, and one receiver hears a
    /// datagram sent to either port: the main socket's and the side socket's.
    #[tokio::test]
    async fn one_receiver_hears_both_sockets() {
        let mut factory = UdpSocketFactory::default();
        let params = UdpTransportFactoryParams {
            addr: None,
            port: 0,
            #[cfg(target_os = "linux")]
            fwmark: None,
        };
        let (main_tx, main_rx) = factory.bind(&params).await.unwrap();
        let (side_tx, side_rx) = factory
            .bind_side(&main_tx, &params)
            .await
            .unwrap()
            .expect("the default socket factory has a side socket");
        let main_port = main_tx.local_addr().unwrap().port();
        let side_port = side_tx.local_addr().unwrap().port();
        assert_ne!(main_port, side_port, "the side socket has its own port");

        let mut merged = WithSide::new(main_rx, Some(side_rx));
        let mut pool = PacketBufPool::new(8);
        let mut buf = Default::default();
        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

        for (port, body) in [(main_port, b"main".as_slice()), (side_port, b"side".as_slice())] {
            sender
                .send_to(body, ("127.0.0.1", port))
                .await
                .expect("send");
            let mut packets: Vec<(Packet, std::net::SocketAddr)> = Vec::new();
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                merged.recv_many_from(&mut buf, &mut pool, &mut packets),
            )
            .await
            .expect("the datagram arrives")
            .unwrap();
            assert_eq!(packets.len(), 1);
            assert_eq!(&packets[0].0[..], body);
        }
        // Only the side datagram has no kernel receive stamp.
        assert_eq!(
            <WithSide<crate::udp::socket::UdpSocket> as UdpRecv>::rx_timestamp_ns(&buf, 0),
            0
        );
    }

    /// Without a side socket the wrapper is the main receiver alone.
    #[tokio::test]
    async fn without_a_side_socket_only_the_main_one_is_read() {
        let mut factory = UdpSocketFactory::default();
        let params = UdpTransportFactoryParams {
            addr: None,
            port: 0,
            #[cfg(target_os = "linux")]
            fwmark: None,
        };
        let (main_tx, main_rx) = factory.bind(&params).await.unwrap();
        let port = main_tx.local_addr().unwrap().port();
        let mut merged = WithSide::new(main_rx, None);
        let mut pool = PacketBufPool::new(8);
        let mut buf = Default::default();
        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender.send_to(b"x", ("127.0.0.1", port)).await.unwrap();
        let mut packets = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            merged.recv_many_from(&mut buf, &mut pool, &mut packets),
        )
        .await
        .expect("the datagram arrives")
        .unwrap();
        assert_eq!(packets.len(), 1);
    }
}
