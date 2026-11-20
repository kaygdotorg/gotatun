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

    /// J1023 prototype: a run of up to the batch size when `GOTATUN_J1023_BATCH` batches sends.
    #[cfg(target_os = "macos")]
    fn max_number_of_packets_to_send(&self) -> usize {
        let mode = super::macos_batch::mode();
        if mode.send { mode.batch } else { 1 }
    }

    /// J1023 prototype: one `sendmsg_x` per same-target run (see `macos_batch`); otherwise
    /// one `send_to` per datagram, as before.
    #[cfg(target_os = "macos")]
    async fn send_many_to(
        &self,
        _send_buf: &mut (),
        packets: &mut Vec<(Packet, SocketAddr)>,
    ) -> io::Result<()> {
        if !super::macos_batch::mode().send || packets.is_empty() {
            for (packet, destination) in packets.drain(..) {
                self.send_to(packet, destination).await?;
            }
            return Ok(());
        }
        // Runs are usually one address family; split wherever the route's socket changes.
        let routed: Vec<(&tokio::net::UdpSocket, &[u8], SocketAddr)> = packets
            .iter()
            .map(|(packet, destination)| {
                let (socket, destination) = self.route(*destination);
                (socket, &packet[..], destination)
            })
            .collect();
        let mut result = Ok(());
        let mut start = 0;
        while start < routed.len() {
            let socket = routed[start].0;
            let end = routed[start..]
                .iter()
                .position(|(s, ..)| !std::ptr::eq(*s, socket))
                .map_or(routed.len(), |n| start + n);
            let run: Vec<(&[u8], SocketAddr)> =
                routed[start..end].iter().map(|(_, p, d)| (*p, *d)).collect();
            if let Err(error) = self.inner.connected.send_batch(socket, &run).await {
                result = Err(error);
            }
            start = end;
        }
        drop(routed);
        packets.clear();
        result
    }
}

impl UdpRecv for super::UdpSocket {
    #[cfg(not(target_os = "macos"))]
    type RecvManyBuf = ();
    /// macOS: spare buffers for the J1023 `recvmsg_x` prototype (unused when it is off).
    #[cfg(target_os = "macos")]
    type RecvManyBuf = super::macos_batch::RecvBuf;

    /// J1023 prototype: with `GOTATUN_J1023_BATCH` batching receives, one `recvmsg_x` from the
    /// first ready socket (split pair sides alternate, then the pool sockets); otherwise one
    /// datagram, as before.
    #[cfg(target_os = "macos")]
    async fn recv_many_from(
        &mut self,
        recv_buf: &mut Self::RecvManyBuf,
        pool: &mut PacketBufPool,
        packets: &mut Vec<(Packet, SocketAddr)>,
    ) -> io::Result<()> {
        if !super::macos_batch::mode().recv {
            let received = self.recv_from(pool).await?;
            packets.push(received);
            return Ok(());
        }
        let map_ipv4_to_ipv6 = self.map_ipv4_to_ipv6;
        let map = move |source| super::map_src_addr(map_ipv4_to_ipv6, source);
        let this = &mut *self;
        std::future::poll_fn(|cx| {
            let first_v4 = this.v4_first;
            this.v4_first = !this.v4_first;
            let mut sockets: Vec<(&tokio::net::UdpSocket, bool)> = Vec::with_capacity(2);
            match &this.inner.v4 {
                Some(v4) if first_v4 => sockets.extend([(v4, false), (&this.inner.socket, false)]),
                Some(v4) => sockets.extend([(&this.inner.socket, false), (v4, false)]),
                None => sockets.push((&this.inner.socket, false)),
            }
            sockets.extend(this.inner.connected.pool_sockets().map(|s| (s, true)));
            for (socket, pool_socket) in sockets {
                match super::macos_connected::poll_recv_batch_one(
                    socket,
                    pool_socket,
                    cx,
                    recv_buf,
                    pool,
                    packets,
                    &map,
                ) {
                    std::task::Poll::Ready(Ok(_)) => return std::task::Poll::Ready(Ok(())),
                    std::task::Poll::Ready(Err(error)) => return std::task::Poll::Ready(Err(error)),
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
