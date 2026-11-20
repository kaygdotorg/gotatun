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

use std::{
    io::{self},
    net::SocketAddr,
};

use crate::{
    packet::{Packet, PacketBufPool},
    udp::{UdpRecv, UdpSend},
};

impl UdpSend for super::UdpSocket {
    type SendManyBuf = ();

    async fn send_to(&self, packet: Packet, dest: SocketAddr) -> io::Result<()> {
        let (socket, dest) = self.route(dest);
        // macOS: an endpoint's connected socket skips xnu's per-datagram route and policy
        // decision (#260, J744, J763; see `macos_connected`). Off, this is the plain `sendto`.
        #[cfg(target_os = "macos")]
        return self.inner.connected.send(socket, &packet, dest).await;
        #[cfg(not(target_os = "macos"))]
        {
            socket.send_to(&packet, dest).await?;
            Ok(())
        }
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        super::UdpSocket::local_addr(self).map(Some)
    }

    /// macOS: up to [`macos_batch::MAX_BATCH`](super::macos_batch::MAX_BATCH) datagrams per run
    /// when this socket can send them with `sendmsg_x` (see `macos_batch`); otherwise one.
    #[cfg(target_os = "macos")]
    fn max_number_of_packets_to_send(&self) -> usize {
        if self.inner.connected.batches_sends() {
            super::macos_batch::MAX_BATCH
        } else {
            1
        }
    }

    /// macOS: one `sendmsg_x` per run of datagrams that share a socket and a target (see
    /// `macos_batch` and `ConnectedSends::send_batch`). Every datagram is attempted; the last
    /// error is returned. Without batching, one `send_to` per datagram, as before.
    #[cfg(target_os = "macos")]
    async fn send_many_to(
        &self,
        _send_buf: &mut (),
        packets: &mut Vec<(Packet, SocketAddr)>,
    ) -> io::Result<()> {
        use super::macos_batch::MAX_BATCH;
        if packets.len() <= 1 || !self.inner.connected.batches_sends() {
            for (packet, destination) in packets.drain(..) {
                self.send_to(packet, destination).await?;
            }
            return Ok(());
        }
        let mut result = Ok(());
        let mut start = 0;
        while start < packets.len() {
            // One run: same route socket (so one family), at most one batch long. The routed
            // payloads and destinations live on the stack, so a run allocates nothing.
            let (socket, first) = self.route(packets[start].1);
            let mut run: [(&[u8], SocketAddr); MAX_BATCH] = [(&[][..], first); MAX_BATCH];
            let mut len = 0;
            while start + len < packets.len() && len < MAX_BATCH {
                let (packet, destination) = &packets[start + len];
                let (next, destination) = self.route(*destination);
                if !std::ptr::eq(next, socket) {
                    break;
                }
                run[len] = (&packet[..], destination);
                len += 1;
            }
            if let Err(error) = self.inner.connected.send_batch(socket, &run[..len]).await {
                result = Err(error);
            }
            start += len;
        }
        packets.clear();
        result
    }
}

impl UdpRecv for super::UdpSocket {
    #[cfg(not(target_os = "macos"))]
    type RecvManyBuf = ();
    /// macOS: spare buffers for `recvmsg_x` (unused while receive batching is off).
    #[cfg(target_os = "macos")]
    type RecvManyBuf = super::macos_batch::RecvBuf;

    /// macOS: with `recvmsg_x` allowed (see `macos_batch`), one batch from the first ready
    /// socket; otherwise one datagram, as before.
    ///
    /// The sockets are the wildcard socket (both sides of a split pair) and every pool socket.
    /// Which one is polled first rotates on every call, so one busy socket cannot starve the
    /// others.
    #[cfg(target_os = "macos")]
    async fn recv_many_from(
        &mut self,
        recv_buf: &mut Self::RecvManyBuf,
        pool: &mut PacketBufPool,
        packets: &mut Vec<(Packet, SocketAddr)>,
    ) -> io::Result<()> {
        if !super::macos_batch::policy().recv {
            let received = self.recv_from(pool).await?;
            packets.push(received);
            return Ok(());
        }
        let map_ipv4_to_ipv6 = self.map_ipv4_to_ipv6;
        let map = move |source| super::map_src_addr(map_ipv4_to_ipv6, source);
        let this = &mut *self;
        std::future::poll_fn(|cx| {
            let inner = &*this.inner;
            let wildcards = 1 + usize::from(inner.v4.is_some());
            let count = wildcards + inner.connected.pool_len();
            let start = this.recv_rotation % count;
            this.recv_rotation = this.recv_rotation.wrapping_add(1);
            for offset in 0..count {
                let index = (start + offset) % count;
                let (socket, pool_socket) = match index {
                    0 => (&inner.socket, false),
                    1 if wildcards == 2 => (inner.v4.as_ref().expect("split pair"), false),
                    _ => (inner.connected.pool_socket(index - wildcards), true),
                };
                match super::macos_connected::poll_recv_batch_one(
                    socket,
                    pool_socket,
                    cx,
                    recv_buf,
                    pool,
                    packets,
                    &map,
                ) {
                    std::task::Poll::Ready(result) => {
                        return std::task::Poll::Ready(result.map(|_| ()));
                    }
                    std::task::Poll::Pending => {}
                }
            }
            std::task::Poll::Pending
        })
        .await
    }

    async fn recv_from(&mut self, pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        let mut buf = pool.get();
        // macOS: an endpoint with a connected socket receives on it, so read those too.
        #[cfg(target_os = "macos")]
        let (n, src) = {
            let this = &mut *self;
            std::future::poll_fn(|cx| {
                // A split pair (connected sends off) reads its IPv4 and IPv6 sockets (#260, J834).
                if let Some(ready) = this.poll_recv_split(cx, &mut buf) {
                    return ready;
                }
                this.inner.connected.poll_recv(
                    &this.inner.socket,
                    &mut this.recv_view,
                    cx,
                    &mut buf,
                )
            })
            .await?
        };
        #[cfg(not(target_os = "macos"))]
        let (n, src) = self.socket().recv_from(&mut buf).await?;
        buf.truncate(n);
        let src = self.map_src(src);
        Ok((buf, src))
    }
}
