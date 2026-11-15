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
        let dest = self.map_dst(dest);
        // macOS: an endpoint's connected socket skips xnu's per-datagram route and policy
        // decision (#260, J744, J763; see `macos_connected`). Off, this is the plain `sendto`.
        #[cfg(target_os = "macos")]
        return self
            .inner
            .connected
            .send(self.socket(), &packet, dest)
            .await;
        #[cfg(not(target_os = "macos"))]
        {
            self.socket().send_to(&packet, dest).await?;
            Ok(())
        }
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        super::UdpSocket::local_addr(self).map(Some)
    }
}

impl UdpRecv for super::UdpSocket {
    type RecvManyBuf = ();

    async fn recv_from(&mut self, pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        let mut buf = pool.get();
        // macOS: an endpoint with a connected socket receives on it, so read those too.
        #[cfg(target_os = "macos")]
        let (n, src) = {
            let this = &mut *self;
            std::future::poll_fn(|cx| {
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
