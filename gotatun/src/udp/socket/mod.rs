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

//! Implementations of [`super::UdpSend`] and [`super::UdpRecv`] traits for [`UdpSocket`].

#[cfg(target_os = "linux")]
use nix::sys::socket::{getsockopt, setsockopt, sockopt};
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, Ordering};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use super::{UdpRecv, UdpTransportFactory, UdpTransportFactoryParams};

/// Implementations of [`super::UdpSend`]/[`super::UdpRecv`] for all targets
#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "windows")))]
mod generic;

/// Connected per-endpoint send sockets for macOS (#260, J744).
#[cfg(target_os = "macos")]
mod macos_connected;

/// Who holds a UDP port, from the kernel's socket list (macOS, #260, J815, J827).
#[cfg(target_os = "macos")]
mod macos_port_audit;

/// Batched sends and receives through xnu's private `sendmsg_x`/`recvmsg_x`, where they help
/// and the OS version allows them (#260, #554, J1036).
#[cfg(target_os = "macos")]
mod macos_batch;

/// Counters for benches: `[send_calls, send_datagrams, recv_calls, recv_datagrams]` through the
/// macOS batch calls since the process started (all zero while batching is off), so a bench can
/// report datagrams per system call.
#[cfg(target_os = "macos")]
pub fn macos_batch_stats() -> [u64; 4] {
    macos_batch::stats()
}

/// Implementations of [`super::UdpSend`]/[`super::UdpRecv`] for linux
#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux;

/// Implementations of [`super::UdpSend`]/[`super::UdpRecv`] for windows
#[cfg(target_os = "windows")]
mod windows;

/// An implementation of [`UdpTransportFactory`] for regular UDP sockets. This provides `bind`.
#[derive(Debug, Default)]
pub struct UdpSocketFactory {
    /// If `Some`, set `SO_RCVBUF` on the socket.
    pub recv_buffer_size: Option<usize>,
    /// If `Some`, set `SO_SNDBUF` on the socket.
    pub send_buffer_size: Option<usize>,
    /// macOS only (ignored elsewhere): whether the WireGuard socket uses connected
    /// per-endpoint sends (see `macos_connected`). `Some` is the owner's choice; `None` leaves
    /// it to the `GOTATUN_BENCH_MAC_CONNECTED` switch, which is off unless set (J789). An owner
    /// that turns them on still gets `sendto` wherever the pool cannot be proven safe (for
    /// example macOS 27's filtered socket list, J1108).
    pub mac_connected: Option<bool>,
}

impl UdpTransportFactory for UdpSocketFactory {
    type Send = UdpSocket;
    type Recv = UdpSocket;

    async fn bind(
        &mut self,
        params: &UdpTransportFactoryParams,
    ) -> io::Result<(Self::Send, Self::Recv)> {
        let udp = self.bind_socket(
            params,
            self.mac_connected,
            self.recv_buffer_size,
            self.send_buffer_size,
        )?;

        if let Err(err) = udp.enable_udp_gro() {
            tracing::warn!("Failed to enable UDP GRO: {err}");
        }

        Ok((udp.clone(), udp))
    }

    /// The side socket (#260, J1211): an ephemeral port on the main socket's address family and
    /// fwmark. It carries only small datagrams, so it keeps the system's default buffer sizes,
    /// enables no GRO, and on macOS never joins the connected-send pool (the pool shares the
    /// main port only inside one audited startup window).
    async fn bind_side(
        &mut self,
        _main: &Self::Send,
        params: &UdpTransportFactoryParams,
    ) -> io::Result<Option<(Self::Send, Self::Recv)>> {
        let params = UdpTransportFactoryParams {
            port: 0,
            ..params.clone()
        };
        let udp = self.bind_socket(&params, Some(false), None, None)?;
        Ok(Some((udp.clone(), udp)))
    }
}

impl UdpSocketFactory {
    /// Bind one socket for `params`, dual-stack unless `params.addr` names a family, falling
    /// back to IPv4 alone where IPv6 sockets are unavailable. The main socket and the side
    /// socket share this so both end up on the same family set-up.
    #[cfg_attr(not(target_os = "macos"), allow(unused_variables))]
    fn bind_socket(
        &self,
        params: &UdpTransportFactoryParams,
        mac_connected: Option<bool>,
        recv_buffer_size: Option<usize>,
        send_buffer_size: Option<usize>,
    ) -> io::Result<UdpSocket> {
        let dual_stack = params.addr.is_none();
        let only_v6 = match params.addr {
            Some(IpAddr::V6(..)) => Some(true),
            Some(IpAddr::V4(..)) => None,
            None => Some(false),
        };

        let opts = SockOpt {
            #[cfg(target_os = "linux")]
            fwmark: params.fwmark,
            recv_buffer_size,
            send_buffer_size,
            only_v6,
            #[cfg(target_os = "macos")]
            mac_connected,
        };

        let addr = params.addr.unwrap_or(Ipv6Addr::UNSPECIFIED.into());
        match UdpSocket::bind((addr, params.port).into(), opts) {
            Ok(udp) => Ok(udp),
            Err(e) if dual_stack && is_ipv6_unavailable(&e) => {
                tracing::warn!("IPv6 UDP sockets are unavailable; continuing with IPv4-only");
                UdpSocket::bind((Ipv4Addr::UNSPECIFIED, params.port).into(), opts)
            }
            Err(e) => Err(e),
        }
    }
}

/// Default UDP socket implementation
#[derive(Clone)]
pub struct UdpSocket {
    inner: Arc<UdpSocketState>,
    map_ipv4_to_ipv6: bool,
    /// This clone's copy of the connected sockets it receives from (#260, J744).
    #[cfg(target_os = "macos")]
    recv_view: macos_connected::RecvView,
    /// On a split pair, whether this clone's next receive polls the IPv4 socket first. It flips
    /// on every poll, so a busy family cannot starve the other.
    #[cfg(target_os = "macos")]
    v4_first: bool,
    /// Which socket this clone's next batched receive (`recvmsg_x`) polls first. It advances on
    /// every poll, so a busy socket cannot starve the others.
    #[cfg(target_os = "macos")]
    recv_rotation: usize,
}

/// How many kernel-picked ports [`UdpSocket::bind_split`] tries before it gives up: a port free
/// on IPv6 is almost always free on IPv4 too.
#[cfg(target_os = "macos")]
const SPLIT_PICKS: usize = 16;

/// Every WireGuard socket this process bound, for [`UdpSocket::underlay_changed_everywhere`]
/// (macOS, #260 J763). Dead entries are pruned on each bind.
#[cfg(target_os = "macos")]
static LIVE_SOCKETS: std::sync::Mutex<Vec<std::sync::Weak<UdpSocketState>>> =
    std::sync::Mutex::new(Vec::new());

struct UdpSocketState {
    /// The socket, or on a macOS split pair its `IPV6_V6ONLY` `[::]:<port>` side.
    socket: tokio::net::UdpSocket,
    /// macOS: the AF_INET `0.0.0.0:<port>` side of a split pair, which carries all IPv4 traffic
    /// (#260, J826 finding 1, J834). `None` for a single socket.
    #[cfg(target_os = "macos")]
    v4: Option<tokio::net::UdpSocket>,
    /// Connected per-endpoint send sockets, shared by every clone (#260, J744).
    #[cfg(target_os = "macos")]
    connected: macos_connected::ConnectedSends,
    #[cfg(target_os = "linux")]
    udp_gso_supported: bool,
    #[cfg(target_os = "linux")]
    udp_gso_disabled: AtomicBool,
}

/// Options set on the socket created by [`UdpSocket::bind`].
#[derive(Copy, Clone, Debug, Default)]
pub struct SockOpt {
    /// If `Some`, set `fwmark` on the socket.
    #[cfg(target_os = "linux")]
    pub fwmark: Option<u32>,
    /// If `Some`, set the receive buffer size: `SO_RCVBUFFORCE` on Linux when permitted,
    /// otherwise `SO_RCVBUF`.
    pub recv_buffer_size: Option<usize>,
    /// If `Some`, set the send buffer size: `SO_SNDBUFFORCE` on Linux when permitted,
    /// otherwise `SO_SNDBUF`.
    pub send_buffer_size: Option<usize>,
    /// If `Some`, set `IPV6_V6ONLY` on the socket.
    pub only_v6: Option<bool>,
    /// macOS: send through startup-bound, per-family connected pools (#260, J877). `None` follows the
    /// default: off, unless `GOTATUN_BENCH_MAC_CONNECTED` is set to something other than `0`
    /// Pending independent review, S remains opt-in.
    #[cfg(target_os = "macos")]
    pub mac_connected: Option<bool>,
}

impl UdpSocket {
    /// Create a UDP socket and bind it to `addr`.
    ///
    /// This also configures the following socket options:
    /// - `nonblocking`, to work with [`tokio`].
    /// - `only_v6`, to bind dual-stack sockets.
    /// - `mark`, only on linux.
    /// - `{recv,send}_buffer_size`, for better performance. See [`SockOpt`].
    ///
    /// On macOS a dual-stack request (`[::]` with `only_v6: Some(false)`)
    /// binds **two** sockets on one port instead: AF_INET `0.0.0.0:<port>` for IPv4 and
    /// `[::]:<port>` with `IPV6_V6ONLY` for IPv6 (#260, J826 finding 1, J834). The handle sends
    /// and receives through both and looks like one socket to its users. See
    /// [`UdpSocket::bind_split`] for why.
    pub fn bind(addr: SocketAddr, opts: SockOpt) -> io::Result<Self> {
        // The default Mac listener always owns an exclusive family pair. Opt-in pools
        // share it only during startup, with before/after audits; endpoints never bind.
        #[cfg(target_os = "macos")]
        let connected = opts.mac_connected.unwrap_or_else(macos_connected::wanted);
        #[cfg(target_os = "macos")]
        if addr.ip() == IpAddr::from(Ipv6Addr::UNSPECIFIED) && opts.only_v6 == Some(false) {
            return Self::bind_split(addr.port(), opts);
        }

        let udp_sock = configured_socket(addr, opts)?;

        udp_sock.bind(&addr.into())?;

        #[cfg(target_os = "macos")]
        let pool = if connected && !(addr.is_ipv6() && opts.only_v6 != Some(true)) {
            let local = udp_sock
                .local_addr()?
                .as_socket()
                .ok_or_else(|| io::Error::other("UDP socket has no IP address"))?;
            macos_connected::pool_for(&udp_sock, local, 1)?
        } else {
            macos_port_audit::ensure_alone(&udp_sock)?;
            Vec::new()
        };

        Self::from_bound(
            udp_sock,
            #[cfg(target_os = "macos")]
            None,
            addr.is_ipv6() && opts.only_v6 == Some(false),
            #[cfg(target_os = "macos")]
            pool,
        )
    }

    /// Bind a dual-stack port on macOS as one socket per family: an `IPV6_V6ONLY` `[::]:<port>`
    /// socket, then an AF_INET `0.0.0.0:<port>` socket, both exclusive (no `SO_REUSEPORT`).
    ///
    /// **Why (J826 finding 1, #260).** xnu's `in_pcbbind` lets a bind of a wildcard address skip
    /// the conflict check when both the new socket and the one already on the port are PF_INET6
    /// wildcards. A dual-stack `[::]:<port>` socket of ours serves IPv4 too, so another user could
    /// bind `::ffff:0.0.0.0:<port>` beside it at any time. From that foothold a specific address
    /// bound with `SO_REUSEADDR` passes the different-user check (the check compares against the
    /// best match, which is now the attacker's own socket) and receives every IPv4 datagram to
    /// that address. With an AF_INET socket on the IPv4 side the exemption never applies
    /// (`SOCK_DOM(t) != PF_INET6`), and a specific address fails the different-user check
    /// against our socket. That is the kernel's rule, not an audit or the list order, so it holds
    /// for the socket's whole life.
    ///
    /// With `port` 0 the IPv6 socket picks the port; if that port is already held on IPv4 the
    /// pair is dropped and another port is tried (at most [`SPLIT_PICKS`] times). With a fixed
    /// port, a refusal of either bind is returned as is, so a caller's `EADDRINUSE` fallback
    /// still works.
    ///
    /// **S-off needs no audit of the socket list (J834).** Each of our two binds is an exclusive wildcard
    /// bind (no `SO_REUSEPORT`). For such a bind the kernel looks up every socket of that family
    /// on the port and refuses ours if there is one. The PF_INET6 exemption cannot help a
    /// squatter, because our IPv4 side is PF_INET. On the Mac VM (macOS 26.5.2) the kernel by
    /// itself refused all of J827's pre-start squatters against the pair, with the audit
    /// removed, as root and as the same user. So the pair does not read `pcblist_n` and does not
    /// depend on its private record layout: a macOS update that moves the layout cannot stop the
    /// mesh. The same holds for the moment between the two binds, when the port is held on IPv6
    /// only: whatever another user binds on the IPv4 side then is on the port before our AF_INET
    /// bind, which the kernel refuses.
    ///
    /// Opt-in connected sends add a fixed startup pool for each family (J877). Each startup
    /// sharing window is audited before and after, counting both wildcards and completed pool
    /// sockets. Nothing binds or enables sharing again while the device runs. An unreadable
    /// pre-audit keeps the exclusive sockets with sendto; an unverified post-audit refuses the
    /// whole listener, carrying forward J826's no-unaudited-rebind rule.
    #[cfg(target_os = "macos")]
    fn bind_split(port: u16, opts: SockOpt) -> io::Result<Self> {
        let v6_opts = SockOpt {
            only_v6: Some(true),
            ..opts
        };
        for _ in 0..SPLIT_PICKS {
            let v6_addr = SocketAddr::from((Ipv6Addr::UNSPECIFIED, port));
            let v6 = configured_socket(v6_addr, v6_opts)?;
            v6.bind(&v6_addr.into())?;
            let picked = v6
                .local_addr()?
                .as_socket()
                .ok_or_else(|| io::Error::other("UDP socket has no IP address"))?
                .port();
            let v4_addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, picked));
            let v4 = configured_socket(v4_addr, opts)?;
            match v4.bind(&v4_addr.into()) {
                Ok(()) => {}
                // The port the kernel picked for IPv6 is held on IPv4: try another one.
                Err(error) if port == 0 && error.kind() == io::ErrorKind::AddrInUse => continue,
                Err(error) => return Err(error),
            }
            let mut pool = Vec::new();
            if opts.mac_connected.unwrap_or_else(macos_connected::wanted) {
                // Both exclusive wildcards exist before either startup window. Each audit
                // includes the other family's sockets, and failure drops the entire pair.
                pool = macos_connected::pool_for(
                    &v6,
                    v6.local_addr()?
                        .as_socket()
                        .ok_or_else(|| io::Error::other("IPv6 socket has no IP address"))?,
                    2,
                )?;
                let v4_pool = macos_connected::pool_for(&v4, v4_addr, 2 + pool.len())?;
                pool.extend(v4_pool);
            }
            return Self::from_bound(v6, Some(v4), false, pool);
        }
        Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            format!("no UDP port free on both IPv4 and IPv6 after {SPLIT_PICKS} tries"),
        ))
    }

    /// Wrap bound sockets in a handle: `socket` is the main one (the only one, or the IPv6 side
    /// of a split pair), `v4` the IPv4 side of a split pair. `map_ipv4_to_ipv6` says whether
    /// `socket` is dual-stack and takes IPv4 destinations in their v4-mapped form.
    fn from_bound(
        socket: socket2::Socket,
        #[cfg(target_os = "macos")] v4: Option<socket2::Socket>,
        map_ipv4_to_ipv6: bool,
        #[cfg(target_os = "macos")] pool: Vec<socket2::Socket>,
    ) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        let udp_gso_supported = getsockopt(&socket, sockopt::UdpGsoSegment).is_ok();

        let inner = tokio::net::UdpSocket::from_std(socket.into())?;
        #[cfg(target_os = "macos")]
        let v4 = v4
            .map(|v4| tokio::net::UdpSocket::from_std(v4.into()))
            .transpose()?;

        let socket = Self {
            inner: Arc::new(UdpSocketState {
                socket: inner,
                #[cfg(target_os = "macos")]
                v4,
                #[cfg(target_os = "linux")]
                udp_gso_supported,
                #[cfg(target_os = "linux")]
                udp_gso_disabled: AtomicBool::new(false),
                #[cfg(target_os = "macos")]
                connected: macos_connected::ConnectedSends::new(pool)?,
            }),
            map_ipv4_to_ipv6,
            #[cfg(target_os = "macos")]
            recv_view: macos_connected::RecvView::default(),
            #[cfg(target_os = "macos")]
            v4_first: false,
            #[cfg(target_os = "macos")]
            recv_rotation: 0,
        };
        #[cfg(target_os = "macos")]
        {
            let mut live = LIVE_SOCKETS
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            live.retain(|state| state.strong_count() > 0);
            live.push(Arc::downgrade(&socket.inner));
        }
        Ok(socket)
    }

    /// Get the inner [`tokio::net::UdpSocket`].
    #[inline(always)]
    pub fn socket(&self) -> &tokio::net::UdpSocket {
        &self.inner.socket
    }

    /// Returns the local address that this socket is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.socket.local_addr()
    }

    /// Tell every WireGuard socket of this process that the host's network changed.
    ///
    /// The same as [`UdpSocket::underlay_changed`] on each live socket, for an owner that holds
    /// no socket handle itself (the CLI's `SIGUSR1`). Elsewhere than macOS it does nothing.
    pub fn underlay_changed_everywhere() {
        #[cfg(target_os = "macos")]
        {
            let live: Vec<_> = LIVE_SOCKETS
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .iter()
                .filter_map(std::sync::Weak::upgrade)
                .collect();
            for state in live {
                state.connected.underlay_changed();
            }
        }
    }

    /// Tell the socket that the host's network changed (an address, route or link moved).
    ///
    /// On macOS this marks the connected pool sockets stale (#260, J877), since they keep the
    /// source address chosen when they connected; the next datagram to each endpoint reconnects
    /// on the current route. Call it from the owner's network-change signal before asking live
    /// sessions to announce their endpoint, so those announcements already leave from the new
    /// source. Every clone shares the effect. Elsewhere it does nothing.
    pub fn underlay_changed(&self) {
        #[cfg(target_os = "macos")]
        self.inner.connected.underlay_changed();
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn udp_gso_supported(&self) -> bool {
        self.inner.udp_gso_supported
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn udp_gso_disabled(&self) -> bool {
        self.inner.udp_gso_disabled.load(Ordering::Relaxed)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn disable_udp_gso(&self) {
        self.inner.udp_gso_disabled.store(true, Ordering::Relaxed);
    }

    /// The socket a datagram to `destination` leaves through, and the address to give it.
    ///
    /// A dual-stack socket takes IPv4 destinations in their v4-mapped IPv6 form. On a macOS
    /// split pair, IPv4 destinations, also when given v4-mapped, leave through the AF_INET socket
    /// as plain IPv4, and IPv6 ones through the IPv6-only socket.
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    #[inline(always)]
    fn route(&self, mut destination: SocketAddr) -> (&tokio::net::UdpSocket, SocketAddr) {
        #[cfg(target_os = "macos")]
        if let Some(v4) = &self.inner.v4 {
            if let SocketAddr::V6(v6) = destination
                && let Some(ip) = v6.ip().to_ipv4_mapped()
            {
                destination = SocketAddr::from((ip, v6.port()));
            }
            return match destination {
                SocketAddr::V4(_) => (v4, destination),
                SocketAddr::V6(_) => (&self.inner.socket, destination),
            };
        }
        if self.map_ipv4_to_ipv6
            && let std::net::IpAddr::V4(ip) = destination.ip()
        {
            destination.set_ip(ip.to_ipv6_mapped().into());
        }
        (&self.inner.socket, destination)
    }

    /// Every socket this handle binds, for tests that read their options back.
    #[cfg(all(test, target_os = "macos"))]
    fn bound_sockets(&self) -> Vec<&tokio::net::UdpSocket> {
        std::iter::once(&self.inner.socket)
            .chain(self.inner.v4.as_ref())
            .collect()
    }

    /// Receive one datagram on a macOS split pair, from either family, or `None` when this is
    /// not a split pair. Which socket is polled first alternates, so neither family starves.
    #[cfg(target_os = "macos")]
    fn poll_recv_split(
        &mut self,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> Option<std::task::Poll<io::Result<(usize, SocketAddr)>>> {
        let v4 = self.inner.v4.as_ref()?;
        let v4_first = self.v4_first;
        self.v4_first = !self.v4_first;
        for ipv4 in [v4_first, !v4_first] {
            if !ipv4 {
                if let std::task::Poll::Ready(result) =
                    self.inner
                        .connected
                        .poll_recv(&self.inner.socket, &mut self.recv_view, cx, buf)
                {
                    return Some(std::task::Poll::Ready(result));
                }
            } else {
                let mut read = tokio::io::ReadBuf::new(&mut *buf);
                if let std::task::Poll::Ready(result) = v4.poll_recv_from(cx, &mut read) {
                    return Some(std::task::Poll::Ready(
                        result.map(|source| (read.filled().len(), source)),
                    ));
                }
            }
        }
        Some(std::task::Poll::Pending)
    }
    /// Map an IPv6 address back to IPv4 if necessary.
    #[inline(always)]
    fn map_src(&self, addr: SocketAddr) -> SocketAddr {
        map_src_addr(self.map_ipv4_to_ipv6, addr)
    }
}

#[cfg(not(windows))]
impl std::os::fd::AsFd for UdpSocket {
    fn as_fd(&self) -> std::os::unix::prelude::BorrowedFd<'_> {
        self.inner.socket.as_fd()
    }
}

#[cfg(windows)]
impl std::os::windows::io::AsSocket for UdpSocket {
    fn as_socket(&self) -> std::os::windows::io::BorrowedSocket<'_> {
        self.inner.socket.as_socket()
    }
}

#[inline(always)]
fn map_src_addr(ipv4_over_ipv6: bool, mut addr: SocketAddr) -> SocketAddr {
    if ipv4_over_ipv6
        && let std::net::IpAddr::V6(ip) = addr.ip()
        && let Some(ipv4) = ip.to_ipv4_mapped()
    {
        addr.set_ip(ipv4.into());
    }
    addr
}

/// A UDP socket for `addr`'s family with `opts` applied, not yet bound.
///
/// It is non-blocking (for [`tokio`]) and carries `IPV6_V6ONLY` when asked (IPv6 only), the
/// Linux `fwmark`, and the buffer sizes. A buffer size the system refuses is an error in debug
/// builds and a logged warning in release builds.
fn configured_socket(addr: SocketAddr, opts: SockOpt) -> io::Result<socket2::Socket> {
    let domain = match addr {
        SocketAddr::V4(..) => socket2::Domain::IPV4,
        SocketAddr::V6(..) => socket2::Domain::IPV6,
    };

    // Construct the socket using `socket2` because we need to set the only_v6 flag.
    let udp_sock =
        socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    udp_sock.set_nonblocking(true)?;
    if let Some(only_v6) = opts.only_v6
        && addr.is_ipv6()
    {
        udp_sock.set_only_v6(only_v6)?;
    }
    #[cfg(target_os = "linux")]
    if let Some(mark) = opts.fwmark {
        udp_sock.set_mark(mark)?;
    }
    // Failing to set buffer sizes is not a fatal error - the tunnel will most likely work just
    // fine, even if not as performant as possible. In that case it is still a good idea to
    // tweak the buffer sizes.
    if let Some(recv_buffer_size) = opts.recv_buffer_size
        && let Err(err) = apply_buffer_size(
            || force_recv_buffer_size(&udp_sock, recv_buffer_size),
            || udp_sock.set_recv_buffer_size(recv_buffer_size),
        )
    {
        if cfg!(debug_assertions) {
            return Err(err);
        } else {
            tracing::error!("Failed to change UDP socket receive buffer size: {err}");
        }
    }
    if let Some(send_buffer_size) = opts.send_buffer_size
        && let Err(err) = apply_buffer_size(
            || force_send_buffer_size(&udp_sock, send_buffer_size),
            || udp_sock.set_send_buffer_size(send_buffer_size),
        )
    {
        if cfg!(debug_assertions) {
            return Err(err);
        } else {
            tracing::error!("Failed to change UDP socket send buffer size: {err}");
        }
    }
    Ok(udp_sock)
}

fn is_ipv6_unavailable(err: &io::Error) -> bool {
    cfg_select! {
        any(target_os = "linux", target_os = "android") => {
            matches!(
                err.raw_os_error(),
                Some(libc::EAFNOSUPPORT | libc::EADDRNOTAVAIL)
            )
        }
        _ => {
            let _ = err;
            false
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android", target_os = "windows"))]
fn check_send_max_number_of_packets(
    max_number_of_packets: usize,
    packets: &[(crate::packet::Packet, SocketAddr)],
) -> io::Result<()> {
    debug_assert!(packets.len() <= max_number_of_packets);
    if packets.len() > max_number_of_packets {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("send_many_to: Number of packets may not exceed {max_number_of_packets}"),
        ));
    }
    Ok(())
}

/// Which socket call applied a requested buffer size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BufferSizeApplied {
    /// The privileged call that ignores the system ceiling.
    Forced,
    /// The plain call, silently clamped to `net.core.{r,w}mem_max`.
    Capped,
}

/// Apply a socket buffer size, preferring the call that is not capped by the system limit.
///
/// `SO_RCVBUF`/`SO_SNDBUF` are clamped without error to `net.core.rmem_max`/`wmem_max`
/// (212,992 bytes on a stock kernel), so a 7 MiB request ends up near 416 KiB. Under a
/// sustained transfer that overflows: on the #260 R4b perf VM the receiving socket logged
/// 11,770 `RcvbufErrors` in a 10 s single-flow run, losing tunnel datagrams and loaded
/// latency probes. A Linux process that owns a TUN device already holds `CAP_NET_ADMIN`,
/// which permits `SO_RCVBUFFORCE`/`SO_SNDBUFFORCE`. Try those first; without the capability
/// (or off Linux) fall back to the clamped call, which keeps the previous behaviour.
fn apply_buffer_size(
    forced: impl FnOnce() -> io::Result<()>,
    capped: impl FnOnce() -> io::Result<()>,
) -> io::Result<BufferSizeApplied> {
    match forced() {
        Ok(()) => Ok(BufferSizeApplied::Forced),
        Err(_) => capped().map(|()| BufferSizeApplied::Capped),
    }
}

#[cfg(target_os = "linux")]
fn force_recv_buffer_size(socket: &socket2::Socket, size: usize) -> io::Result<()> {
    setsockopt(socket, sockopt::RcvBufForce, &size).map_err(io::Error::from)
}

#[cfg(target_os = "linux")]
fn force_send_buffer_size(socket: &socket2::Socket, size: usize) -> io::Result<()> {
    setsockopt(socket, sockopt::SndBufForce, &size).map_err(io::Error::from)
}

#[cfg(not(target_os = "linux"))]
fn force_recv_buffer_size(_: &socket2::Socket, _: usize) -> io::Result<()> {
    Err(io::ErrorKind::Unsupported.into())
}

#[cfg(not(target_os = "linux"))]
fn force_send_buffer_size(_: &socket2::Socket, _: usize) -> io::Result<()> {
    Err(io::ErrorKind::Unsupported.into())
}

#[cfg(test)]
#[cfg_attr(target_vendor = "apple", expect(clippy::let_unit_value))]
mod tests {
    use bytes::BytesMut;
    use tokio::time::timeout;
    use zerocopy::IntoBytes;

    use super::*;
    use crate::packet::{Packet, PacketBufPool};
    #[cfg(target_os = "linux")]
    use crate::udp::UdpRecv;
    use crate::udp::UdpSend;
    use std::iter;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn udp_gso_disabled_state_is_shared_by_clones() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0).into(), SockOpt::default()).unwrap();
        let clone = socket.clone();

        assert_eq!(socket.udp_gso_supported(), clone.udp_gso_supported());
        assert!(!socket.udp_gso_disabled());
        assert!(!clone.udp_gso_disabled());

        clone.disable_udp_gso();

        assert!(socket.udp_gso_disabled());
        assert!(clone.udp_gso_disabled());
    }

    async fn set_up_dual_stack_test() -> (
        (UdpSocket, u16),
        tokio::net::UdpSocket,
        tokio::net::UdpSocket,
    ) {
        // Bind dual-stack socket
        let mut factory = UdpSocketFactory::default();
        let params = UdpTransportFactoryParams {
            addr: None,
            port: 0,
            #[cfg(target_os = "linux")]
            fwmark: None,
        };
        let (dual_sock, _) = factory.bind(&params).await.expect("bind");
        let addr = dual_sock.local_addr().expect("local_addr");
        assert_eq!(addr.ip(), Ipv6Addr::UNSPECIFIED);

        // Assert that IPV6_V6ONLY is false. On macOS a dual-stack bind is a split pair whose
        // main socket is IPv6-only (#260, J834; see `split_family_tests`).
        #[cfg(not(any(windows, target_os = "macos")))]
        {
            use std::os::fd::{AsRawFd, FromRawFd};
            let raw_fd = dual_sock.socket().as_raw_fd();
            // SAFETY:
            // - raw_socket is an [owned socket](https://doc.rust-lang.org/stable/std/io/index.html#io-safety).
            // - raw_socket is open.
            let socket2 = unsafe { socket2::Socket::from_raw_fd(raw_fd) };
            assert!(!socket2.only_v6().unwrap());
            std::mem::forget(socket2); // Don't close the socket
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::{AsRawSocket, FromRawSocket};
            let raw_socket = dual_sock.socket().as_raw_socket();
            // SAFETY:
            // - raw_socket is an [owned socket](https://doc.rust-lang.org/stable/std/io/index.html#io-safety).
            // - raw_socket is open.
            // - raw_socket may be freed via [`closesocket`](https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-closesocket).
            let socket2 = unsafe { socket2::Socket::from_raw_socket(raw_socket) };
            assert!(!socket2.only_v6().unwrap());
            std::mem::forget(socket2); // Don't close the socket
        }

        // Bind two new sockets for receiving packets from `dual_sock`
        let bind = async |addr: IpAddr| tokio::net::UdpSocket::bind((addr, 0)).await.unwrap();
        let v4 = bind(Ipv4Addr::LOCALHOST.into()).await;
        let v6 = bind(Ipv6Addr::LOCALHOST.into()).await;

        ((dual_sock, addr.port()), v4, v6)
    }

    /// Test that we can bind and send from a dual-stack ipv4+ipv6 socket.
    #[tokio::test]
    async fn dual_stack_socket_send() {
        let ((dual_sock, ..), v4_sock, v6_sock) = set_up_dual_stack_test().await;

        let v4_addr = v4_sock.local_addr().unwrap();
        let v6_addr = v6_sock.local_addr().unwrap();

        let mut recv_v4 = BytesMut::new();
        let mut recv_v6 = BytesMut::new();

        // Test helpers
        let t = Duration::from_millis(100);
        let recv_some = async |s: &tokio::net::UdpSocket, buf: &mut BytesMut| {
            timeout(t, s.recv_buf(buf)).await.unwrap().unwrap();
        };
        let recv_none = async |s: &tokio::net::UdpSocket, buf: &mut BytesMut| {
            timeout(t, s.recv_buf(buf)).await.expect_err("no packets");
        };
        let packet = |s: &str| Packet::from_bytes(s.as_bytes().into());

        // Send & receive a packet over IPv4
        dual_sock.send_to(packet("v4"), v4_addr).await.unwrap();
        recv_some(&v4_sock, &mut recv_v4).await;
        recv_none(&v6_sock, &mut recv_v6).await;
        assert_eq!(recv_v4, packet("v4").as_bytes());

        // Send & receive a packet over IPv6
        dual_sock.send_to(packet("v6"), v6_addr).await.unwrap();
        recv_some(&v6_sock, &mut recv_v6).await;
        recv_none(&v4_sock, &mut recv_v4).await;
        assert_eq!(recv_v6, packet("v6").as_bytes());

        // Send & receive many packet over IPv4
        let n = dual_sock.max_number_of_packets_to_send();
        let packets = iter::repeat(packet("v4")).map(|p| (p, v4_addr)).take(n);
        let mut buf = Default::default();
        dual_sock
            .send_many_to(&mut buf, &mut packets.collect())
            .await
            .unwrap();
        recv_none(&v6_sock, &mut recv_v4).await;
        for _ in 0..n {
            recv_some(&v4_sock, &mut recv_v6).await;
        }
        recv_none(&v4_sock, &mut recv_v6).await;

        // Send & receive many packet over IPv6
        let packets = iter::repeat(packet("v6")).map(|p| (p, v6_addr)).take(n);
        let mut buf = Default::default();
        dual_sock
            .send_many_to(&mut buf, &mut packets.collect())
            .await
            .unwrap();
        recv_none(&v4_sock, &mut recv_v4).await;
        for _ in 0..n {
            recv_some(&v6_sock, &mut recv_v6).await;
        }
        recv_none(&v6_sock, &mut recv_v6).await;
    }

    /// Test that we can bind and recv from a dual-stack ipv4+ipv6 socket.
    #[tokio::test]
    async fn dual_stack_socket_recv() {
        let mut pool1 = PacketBufPool::new(10);
        let mut pool2 = PacketBufPool::new(10);

        let ((mut dual_sock, port), v4_sock, v6_sock) = set_up_dual_stack_test().await;

        let v4_addr = v4_sock.local_addr().unwrap();
        let v6_addr = v6_sock.local_addr().unwrap();

        let dual_sock_v4_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port);
        let dual_sock_v6_addr = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), port);

        // Test helpers
        let t = Duration::from_millis(100);
        let mut recv_some =
            async |s: &mut UdpSocket| timeout(t, s.recv_from(&mut pool1)).await.unwrap().unwrap();
        let mut recv_none = async |s: &mut UdpSocket| {
            timeout(t, s.recv_from(&mut pool2))
                .await
                .expect_err("no packets");
        };
        let packet = |s: &str| Packet::from_bytes(s.as_bytes().into());

        v4_sock
            .send_to(&packet("v4"), dual_sock_v4_addr)
            .await
            .unwrap();
        let (p, src) = recv_some(&mut dual_sock).await;
        assert_eq!(src, v4_addr);
        assert_eq!(&p[..], &packet("v4")[..]);
        recv_none(&mut dual_sock).await;

        v6_sock
            .send_to(&packet("v6"), dual_sock_v6_addr)
            .await
            .unwrap();
        let (p, src) = recv_some(&mut dual_sock).await;
        assert_eq!(src, v6_addr);
        assert_eq!(&p[..], &packet("v6")[..]);
        recv_none(&mut dual_sock).await;

        let mut n = 32;
        for _ in 0..n {
            v6_sock
                .send_to(&packet("v6"), dual_sock_v6_addr)
                .await
                .unwrap();
        }
        let mut buf = Default::default();
        while n > 0 {
            let mut out = vec![];
            dual_sock
                .recv_many_from(&mut buf, &mut pool1, &mut out)
                .await
                .unwrap();
            assert!(!out.is_empty() && out.len() <= n);
            n -= out.len();
            for (p, src) in out {
                assert_eq!(src, v6_addr);
                assert_eq!(&p[..], &packet("v6")[..]);
            }
        }
        recv_none(&mut dual_sock).await;

        let mut n = 32;
        for _ in 0..n {
            v4_sock
                .send_to(&packet("v4"), dual_sock_v4_addr)
                .await
                .unwrap();
        }
        let mut buf = Default::default();
        while n > 0 {
            let mut out = vec![];
            dual_sock
                .recv_many_from(&mut buf, &mut pool1, &mut out)
                .await
                .unwrap();
            assert!((1..=n).contains(&out.len()));
            n -= out.len();
            for (p, src) in out {
                assert_eq!(src, v4_addr);
                assert_eq!(&p[..], &packet("v4")[..]);
            }
        }
        recv_none(&mut dual_sock).await;
    }

    #[test]
    fn buffer_size_prefers_the_uncapped_call() {
        let capped_called = std::cell::Cell::new(false);
        let applied = apply_buffer_size(
            || Ok(()),
            || {
                capped_called.set(true);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(applied, BufferSizeApplied::Forced);
        assert!(!capped_called.get(), "a forced size must not be re-capped");
    }

    #[test]
    fn buffer_size_falls_back_without_privilege() {
        let applied =
            apply_buffer_size(|| Err(io::ErrorKind::PermissionDenied.into()), || Ok(())).unwrap();
        assert_eq!(applied, BufferSizeApplied::Capped);
    }

    #[test]
    fn buffer_size_reports_the_fallback_error() {
        let err = apply_buffer_size(
            || Err(io::ErrorKind::PermissionDenied.into()),
            || Err(io::ErrorKind::InvalidInput.into()),
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    /// Without `CAP_NET_ADMIN` the forced call fails; binding must still succeed
    /// (debug builds turn a buffer-size failure into a bind error) and keep a
    /// usable, nonzero buffer.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn oversized_buffer_request_binds_with_or_without_privilege() {
        let opts = SockOpt {
            recv_buffer_size: Some(7 * 1024 * 1024),
            send_buffer_size: Some(7 * 1024 * 1024),
            ..SockOpt::default()
        };
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0).into(), opts).unwrap();
        let rcvbuf = getsockopt(socket.socket(), sockopt::RcvBuf).unwrap();
        let sndbuf = getsockopt(socket.socket(), sockopt::SndBuf).unwrap();
        assert!(rcvbuf > 0 && sndbuf > 0, "rcvbuf={rcvbuf} sndbuf={sndbuf}");
    }
}

/// The WireGuard port is never shared with a socket that was on it first (macOS, #260, J815,
/// J827).
///
/// xnu lets an exclusive bind (no `SO_REUSEPORT`, connected sends off) of `[::]:<port>` succeed
/// beside a socket that another user bound earlier to `0.0.0.0:<port>` with `SO_REUSEPORT`, and
/// that socket then receives the port's IPv4 datagrams (J815 probe on #260). These tests bind
/// such a socket from another process before the WireGuard socket and expect the WireGuard bind
/// to fail with `EADDRINUSE`, whether the kernel refuses it or our audit does.
#[cfg(all(test, target_os = "macos"))]
mod shared_port_tests {
    use std::{
        io::{BufRead, BufReader},
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        os::unix::process::CommandExt,
        process::{Child, Command, Stdio},
    };

    use super::{SockOpt, UdpSocket};

    /// `nobody` on macOS. Under root the squatter runs as this user, so the test is the real
    /// cross-user case; otherwise it runs as the test's own user, in another process.
    const NOBODY: u32 = 4_294_967_294;

    /// Binds `$ARGV[0]:0` with `SO_REUSEPORT`, prints the port and holds it until stdin closes.
    const SQUAT: &str = r#"
        use Socket qw(:all);
        # Taint mode is on when the squatter runs as another user: untaint the address.
        my ($addr) = $ARGV[0] =~ /^([0-9a-f.:]+)$/ or die "bad address";
        my $v6 = $addr =~ /:/;
        socket(my $s, $v6 ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP) or die "socket: $!";
        setsockopt($s, SOL_SOCKET, eval { SO_REUSEPORT() } // 0x0200, 1) or die "reuseport: $!";
        my $sa = $v6 ? pack_sockaddr_in6(0, inet_pton(AF_INET6, $addr))
                     : pack_sockaddr_in(0, inet_aton($addr));
        bind($s, $sa) or die "bind: $!";
        my ($port) = $v6 ? unpack_sockaddr_in6(getsockname($s)) : unpack_sockaddr_in(getsockname($s));
        $| = 1;
        print "$port\n";
        my $wait = <STDIN>;
    "#;

    /// A squatter process holding `address` with `SO_REUSEPORT` on a port the kernel picks.
    /// Dropping it closes its stdin, which ends it.
    struct Squatter {
        child: Child,
        port: u16,
        uid: u32,
    }

    impl Squatter {
        fn bind(address: IpAddr) -> Self {
            let mut command = Command::new("/usr/bin/perl");
            command
                .args(["-e", SQUAT, &address.to_string()])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped());
            // SAFETY: `geteuid` has no preconditions and cannot fail.
            let uid = if unsafe { libc::geteuid() } == 0 {
                command.uid(NOBODY).gid(NOBODY);
                NOBODY
            } else {
                // SAFETY: as above.
                unsafe { libc::geteuid() }
            };
            let mut child = command.spawn().expect("start the squatter");
            let mut line = String::new();
            BufReader::new(child.stdout.take().expect("stdout"))
                .read_line(&mut line)
                .expect("read the squatter's port");
            let port = line
                .trim()
                .parse()
                .unwrap_or_else(|_| panic!("squatter on {address} printed {line:?}"));
            Self { child, port, uid }
        }
    }

    impl Drop for Squatter {
        fn drop(&mut self) {
            drop(self.child.stdin.take());
            let _ = self.child.wait();
        }
    }

    /// Held by each test here for its whole run: the squatter test's squatters must never land
    /// on the port `a_free_port_binds` frees for a moment (J826).
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Bind the WireGuard socket the way the product does, with connected sends off.
    fn wireguard_bind(address: SocketAddr) -> std::io::Result<UdpSocket> {
        let opts = SockOpt {
            only_v6: address.is_ipv6().then_some(false),
            mac_connected: Some(false),
            ..SockOpt::default()
        };
        UdpSocket::bind(address, opts)
    }

    /// Every squatter address, against the dual-stack bind and the IPv4-only fallback bind:
    /// the WireGuard bind fails with `EADDRINUSE` in every case.
    #[tokio::test]
    async fn a_port_another_process_bound_first_is_refused() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let squats: [IpAddr; 4] = [
            Ipv4Addr::UNSPECIFIED.into(),
            Ipv4Addr::LOCALHOST.into(),
            Ipv6Addr::UNSPECIFIED.into(),
            Ipv6Addr::LOCALHOST.into(),
        ];
        let ours: [IpAddr; 2] = [Ipv6Addr::UNSPECIFIED.into(), Ipv4Addr::UNSPECIFIED.into()];
        let mut shared = Vec::new();
        for squat in squats {
            for wildcard in ours {
                let squatter = Squatter::bind(squat);
                let result = wireguard_bind((wildcard, squatter.port).into());
                let outcome = match &result {
                    Ok(_) => "BOUND beside it".to_owned(),
                    Err(error) => format!("refused: {error}"),
                };
                eprintln!(
                    "squatter uid {} on {squat} (SO_REUSEPORT), WireGuard {wildcard}:{}: {outcome}",
                    squatter.uid, squatter.port
                );
                match result {
                    Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {}
                    // `[::1]` beside our IPv4-only socket is another family: it receives only
                    // datagrams to `[::1]`, never one of ours. macOS 26 refuses it through the
                    // audit; macOS 27 hides the squatter from the audit and the kernel lets the
                    // bind through, which shares nothing (J1108 on #260).
                    Ok(_) if squat == IpAddr::from(Ipv6Addr::LOCALHOST) && wildcard.is_ipv4() => {}
                    _ => shared.push(format!("{squat} vs {wildcard}: {outcome}")),
                }
            }
        }
        assert!(shared.is_empty(), "the port was shared: {shared:#?}");
    }

    /// Without a squatter the bind succeeds, on a fixed port too: the audit refuses only ports
    /// that someone else holds.
    ///
    /// The fixed-port step frees a kernel-chosen port and binds it again. A test running in
    /// parallel (the squatter test above binds many kernel-chosen ports) can be handed that port
    /// in between, and the kernel then refuses the re-bind outright (J826: 3 of 8 parallel runs
    /// on the Mac VM). The squatter test is kept out by [`SERIAL`]; any other test can still take
    /// the port, so a refusal by the kernel moves on to a fresh port. A refusal by our own audit,
    /// or by the kernel on every try, fails the test.
    #[tokio::test]
    async fn a_free_port_binds() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut refused = Vec::new();
        for _ in 0..8 {
            let first =
                wireguard_bind((Ipv6Addr::UNSPECIFIED, 0).into()).expect("bind a free port");
            let port = first.local_addr().expect("local").port();
            drop(first);
            match wireguard_bind((Ipv6Addr::UNSPECIFIED, port).into()) {
                Ok(_) => {
                    wireguard_bind((Ipv4Addr::UNSPECIFIED, 0).into()).expect("bind IPv4 only");
                    return;
                }
                // The kernel's own refusal (no message of ours): someone took the freed port.
                Err(error)
                    if error.kind() == std::io::ErrorKind::AddrInUse
                        && error.raw_os_error() == Some(libc::EADDRINUSE) =>
                {
                    refused.push(format!("{port}: {error}"));
                }
                Err(error) => panic!("bind the same port {port} again: {error}"),
            }
        }
        panic!("the same port never bound again: {refused:?}");
    }
}

/// A dual-stack WireGuard bind on macOS is one socket per family (#260, J826 finding 1, J834).
///
/// xnu exempts two PF_INET6 wildcard binds of one port from its conflict check, so while our
/// IPv4 traffic arrives on a dual-stack PF_INET6 socket, another user can bind beside it. With an
/// AF_INET socket for IPv4 and an `IPV6_V6ONLY` socket for IPv6, that exemption never applies to
/// our port. These tests read the options back from the kernel and check that each destination
/// leaves through the socket of its family. J826's kit on #260 covers the behaviour itself.
#[cfg(all(test, target_os = "macos"))]
mod split_family_tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use super::{UdpSocket, UdpSocketFactory};
    use crate::{
        packet::{Packet, PacketBufPool},
        udp::{UdpRecv, UdpSend, UdpTransportFactory, UdpTransportFactoryParams},
    };

    /// Bind the way the product does: no address (dual-stack), a kernel-picked port, connected
    /// sends at their default (off).
    async fn product_bind() -> (UdpSocket, UdpSocket) {
        let params = UdpTransportFactoryParams {
            addr: None,
            port: 0,
        };
        UdpSocketFactory::default()
            .bind(&params)
            .await
            .expect("dual-stack bind")
    }

    /// One AF_INET `0.0.0.0:P` and one `[::]:P` with `IPV6_V6ONLY`, neither with
    /// `SO_REUSEPORT`, on the same port.
    #[tokio::test]
    async fn a_dual_stack_bind_is_one_socket_per_family() {
        let (wireguard, _) = product_bind().await;
        let port = wireguard.local_addr().expect("local").port();
        let mut seen = Vec::new();
        for socket in wireguard.bound_sockets() {
            let local = socket.local_addr().expect("local");
            let options = socket2::SockRef::from(socket);
            assert!(
                !options.reuse_port().expect("SO_REUSEPORT"),
                "{local} carries SO_REUSEPORT"
            );
            let only_v6 = local.is_ipv6() && options.only_v6().expect("IPV6_V6ONLY");
            seen.push((local, only_v6));
        }
        let want = vec![
            (SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)), true),
            (SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)), false),
        ];
        assert_eq!(seen, want, "(address, IPV6_V6ONLY) of each socket");
    }

    /// IPv4 and v4-mapped destinations leave through the AF_INET socket as plain IPv4; IPv6
    /// destinations through the IPv6-only socket.
    #[tokio::test]
    async fn each_destination_leaves_through_its_family_socket() {
        let (wireguard, _) = product_bind().await;
        let v4 = SocketAddr::from((Ipv4Addr::LOCALHOST, 9));
        let mapped = SocketAddr::from((Ipv4Addr::LOCALHOST.to_ipv6_mapped(), 9));
        let v6 = SocketAddr::from((Ipv6Addr::LOCALHOST, 9));
        for destination in [v4, mapped] {
            let (socket, to) = wireguard.route(destination);
            assert!(
                socket.local_addr().expect("local").is_ipv4(),
                "{destination} would leave through {:?}",
                socket.local_addr()
            );
            assert_eq!(to, v4, "{destination} is sent as plain IPv4");
        }
        let (socket, to) = wireguard.route(v6);
        assert!(socket.local_addr().expect("local").is_ipv6());
        assert_eq!(to, v6);
    }

    /// Datagrams cross both ways on both families, and IPv4 sources come back as plain IPv4.
    #[tokio::test]
    async fn both_families_send_and_receive() {
        let (wireguard, mut receiver) = product_bind().await;
        let port = wireguard.local_addr().expect("local").port();
        let mut pool = PacketBufPool::new(4);
        let peers: [IpAddr; 2] = [Ipv4Addr::LOCALHOST.into(), Ipv6Addr::LOCALHOST.into()];
        for ip in peers {
            let peer = tokio::net::UdpSocket::bind((ip, 0)).await.expect("peer");
            let peer_addr = peer.local_addr().expect("peer address");
            peer.send_to(b"in", (ip, port)).await.expect("peer sends");
            let (packet, source) = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                receiver.recv_from(&mut pool),
            )
            .await
            .expect("a datagram in time")
            .expect("receive");
            assert_eq!((&packet[..], source), (&b"in"[..], peer_addr));
            wireguard
                .send_to(
                    Packet::from_bytes(bytes::BytesMut::from(&b"out"[..])),
                    peer_addr,
                )
                .await
                .expect("send");
            let mut buf = [0u8; 16];
            let (n, from) =
                tokio::time::timeout(std::time::Duration::from_secs(5), peer.recv_from(&mut buf))
                    .await
                    .expect("a reply in time")
                    .expect("peer receives");
            assert_eq!((&buf[..n], from.port()), (&b"out"[..], port));
        }
    }
}
