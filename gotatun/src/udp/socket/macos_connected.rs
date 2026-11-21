// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

//! Connected per-endpoint send sockets for macOS, from a pool bound once (#260, J744, J763,
//! J789, J815, J826, J877).
//!
//! **Why.** On macOS a `sendto` on an unconnected socket bound to the wildcard address costs
//! about 14 µs of kernel time per datagram on our Mac VM, because xnu re-decides the route and
//! the network policy for every datagram. A socket with a fixed 4-tuple (a *connected* socket)
//! keeps that decision, and the same `send` costs about 2 µs (J744 microbench, #260). The Mac's
//! single device runtime spends about half its time in `sendto` under load (J728), so this is the
//! largest per-datagram cost on the Mac send path. Runs of datagrams to one endpoint then go out
//! in one private `sendmsg_x` call where the OS allows it ([`super::macos_batch`]), which xnu
//! batches only on a connected socket like these.
//!
//! **How.** The WireGuard socket binds the wildcard address on its port as before. Right after
//! that pair binds, [`bind_pool_counted`] binds [`POOL_SIZE`] sockets per family to the same address and port; this
//! is the only time any socket of ours binds the port. From then on, an endpoint that receives
//! data gets one pool socket through `connect`, and later datagrams to it use `send` on that
//! socket. A new endpoint, an evicted one, and a fresh source after a network change are all a
//! *re-connect* of a pool socket, never a new bind. The kernel delivers an arriving datagram to
//! the most specific matching socket, so an endpoint's replies land on its pool socket: the
//! receive side reads the wildcard socket and every pool socket.
//!
//! **Why a pool, and why the port cannot be taken over (J789, J815, J826, J877).** Two sockets can share a
//! port only while `SO_REUSEPORT` is set on both the socket that binds and the socket already
//! there that best matches the requested address (`in_pcbbind`/`in6_pcbbind`). macOS applies no
//! effective same-user rule to that check (J763, J789: another uid co-bound even
//! `127.0.0.1:<port>`), and our sockets and another user's binds see the same "best match", so
//! *any* moment in which a socket of ours on the port carries the option is a moment in which
//! another user can join it. J763 opened such a moment for every new endpoint; J789 showed
//! another uid wins it in milliseconds and then receives every datagram no connected socket
//! matches. This module therefore opens the option exactly once per WireGuard socket, inside
//! [`bind_pool_counted`], and makes that one moment fail closed:
//! 1. The wildcard socket binds first **without** the option, so it binds only if nobody holds
//!    the port (the behaviour without this feature).
//! 2. The option is set on it, the pool sockets bind, and the option is cleared on every socket.
//!    After that no socket of ours carries it, ever, so no later bind by anyone can join.
//! 3. The kernel's own list of UDP sockets (`net.inet.udp.pcblist_n`) is read and the sockets on
//!    the port are counted. That list is built under the same lock every bind takes, so a bind
//!    that slipped into step 2 is in it. If the count is not exactly ours, someone joined:
//!    the WireGuard socket is refused with `EADDRINUSE`, which is what the owner sees today when
//!    another process holds the port before it starts. If the list cannot be read after the
//!    window, nothing proves the port is ours alone, and the socket is refused too.
//!
//! The list is also read once *before* step 2 (J826). It must show the wildcard socket alone. If
//! it cannot be read, or shows fewer than our already-bound sockets (the records are private kernel ABI and
//! an OS update may change them), the window is never opened and the socket carries on with
//! `sendto`: no pool, no audit needed, and no second bind of the port. If it shows someone
//! else already, the socket is refused before the window.
//!
//! So a local user can, at most, make the WireGuard socket fail to bind at start, which it can
//! already do without this feature by binding the port first; it can never share the port
//! silently, and nothing it does after start matters, because no socket of ours binds again.
//!
//! **A stale source.** `connect` fixes the source address the route chose at that moment, and
//! xnu keeps it. If the network changes, the socket would keep sending from the old address:
//! still working while that address and its path live, a black hole when the path is gone but the
//! address is not. A pool socket is marked *stale* by three things, none of them a timer (D81),
//! and the next data datagram to its endpoint re-connects it. A re-connect of a connected UDP
//! socket first disconnects it, which clears its source (`udp_disconnect`), so the new connect
//! picks the current route's source (J815 probe on #260):
//! - [`ConnectedSends::underlay_changed`]: the owner's network-change signal (the product's
//!   macOS routing-socket listener) marks every pool socket stale.
//! - A send error that says the path is gone (`EADDRNOTAVAIL` once the source address left the
//!   host, `ENETUNREACH`, `ENETDOWN`; `EHOSTUNREACH` after one retry, since it can also be a
//!   stale ICMP report) marks the socket stale, and that datagram leaves through `sendto` in the
//!   same call. Other send errors are in **Failing sends** below.
//! - Every message that is not data (handshake messages, cookie replies and keepalives) marks
//!   its endpoint's socket stale and leaves through `sendto`, which picks the current source. A
//!   Mac that sends data starts a handshake after 15 s without a reply; an idle or receive-only
//!   Mac sends a keepalive at least every persistent-keepalive interval. So even an unsignalled,
//!   error-free stale path ends at the protocol's own recovery point (J789).
//!
//! **Failing sends.** `sendto` on the wildcard socket is the reference path: connected sends
//! are only a faster way to do the same thing, so a pool socket's send error never loses a
//! datagram and never reaches the caller. Whatever the errno, the datagram goes through
//! `sendto`, and only `sendto`'s own error is returned. This matters because the kernel can
//! refuse connected sends for reasons the pool cannot know about. macOS Local Network privacy
//! refuses a process without the user's grant any flow it starts toward a LAN host; for a
//! connected socket the kernel's policy check marks the socket defunct and every `send` answers
//! `EPIPE`. A flow the peer started (its handshake reached the wildcard socket) stays allowed, so
//! `sendto` to that peer keeps working while a fresh pool socket to it never does (J1108 on an
//! M1 with macOS 27.2.1, after J1028 and J1036 on #260/#554). Before J1108 an errno the pool did
//! not recognise failed the datagram and every one after it, so that peer got no data at all.
//!
//! What happens to the socket depends on the error:
//! - **Path errors and ICMP reports** (above): the socket is stale and re-connects. One that
//!   keeps failing backs off instead of reconnecting before every datagram: the first failure
//!   re-connects on the next data datagram (a moved source usually works again at once); each
//!   further failure in a row keeps the endpoint on `sendto` for [`FIRST_BACKOFF`], doubling up
//!   to [`MAX_BACKOFF`]. One successful send clears the count, and a network change
//!   ([`ConnectedSends::underlay_changed`]) ends a back-off early. The back-off is checked on
//!   the send path; there is no timer (D81).
//! - **A full buffer** (`ENOBUFS`, `ENOMEM`): that datagram goes through `sendto`; the socket is
//!   fine.
//! - **Anything else** (`EPIPE` from a defunct socket, and an `EOPNOTSUPP` when re-connecting
//!   one): the socket is **retired**. A defunct socket cannot be re-connected or disconnected,
//!   and while it stays connected the kernel still hands it every datagram from that peer and
//!   drops them, so the peer's traffic is lost on *receive* too (J1108 on mba: the wildcard
//!   socket got 0 of the peer's datagrams until the pool socket was closed, then all of them).
//!   Retiring replaces the open file behind the slot's descriptor with a fresh UDP socket that
//!   is never bound ([`ConnectedSends::retire`]). That closes the defunct socket without a new
//!   bind on the port, so the invariant above holds, and the slot is never used again. The
//!   endpoint uses `sendto` until the next network change, which may lift the refusal; it then
//!   takes another pool socket, and loses it the same way if the refusal stands. So a refused
//!   endpoint costs at most one pool socket per network change and runs at `sendto` speed.
//!
//! **Family.** The default listener is an exclusive AF_INET / IPv6-only pair (J834).
//! Each family gets its own startup pool of [`POOL_SIZE`] sockets. A slot's family is fixed
//! by its bind, before any endpoint connects; reconnect never changes it. In particular, no
//! dual-stack socket serves IPv4, preserving the kernel exclusion established by J834.
//!
//! **Bounded.** The pool is [`POOL_SIZE`] sockets per family, open for its whole life
//! (one file descriptor and one reactor registration each). Keepalives, handshake messages and
//! cookie replies never take a pool socket; only data does, so a large mostly-idle mesh does not
//! churn connects. When no pool socket of the right family is free, the least recently used one
//! moves to the new endpoint only if it has been idle for at least [`ACTIVE_SENDS`] data sends;
//! when all of them are busier than that, the new endpoint keeps using `sendto` (~14 µs per
//! datagram) instead of moving a busy one.
//!
//! **Other invariants.**
//! - A datagram is sent on a pool socket only while that socket is connected to the datagram's
//!   endpoint: senders hold the socket's read lock across the `send` call, and a re-connect holds
//!   its write lock. A datagram never leaves toward an endpoint other than its own.
//! - A connected socket reports ICMP errors (`ECONNREFUSED` and friends) on its next call. On
//!   receive they are skipped; on send the datagram is retried once.
//! - A failure to *connect* (no route right now) never turns the feature off: that datagram uses
//!   `sendto` and the next one tries again.
//!
//! Off by default (J789): `GOTATUN_BENCH_MAC_CONNECTED=1` turns it on. Whether the pool makes it
//! safe to turn on by default is the owner's decision (#260).

use std::{
    io,
    net::SocketAddr,
    sync::{
        OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use parking_lot::{Mutex, RwLock};
use tokio::io::ReadBuf;

use crate::packet::WgPacketType;

/// How many sockets share the WireGuard port besides the wildcard socket, and so the most
/// endpoints that use connected sends at once.
///
/// All of them are bound when the WireGuard socket binds and stay open for its life: a device
/// pays these file descriptors even while idle (J815 fd budget on #260). Every receive poll
/// visits each of them.
pub(crate) const POOL_SIZE: usize = 16;

/// A pool socket used within this many data sends (to any endpoint) counts as busy and is never
/// moved to another endpoint.
pub(crate) const ACTIVE_SENDS: u64 = 1024;

/// The size of a WireGuard keepalive: a data header and an empty, authenticated payload.
/// Datagrams this small or smaller never use a pool socket.
const KEEPALIVE_LEN: usize = 32;

/// How long an endpoint stays on `sendto` after its pool socket hit a path error twice in a
/// row (see **Failing sends** in the module docs). Doubles with each further failure.
pub(crate) const FIRST_BACKOFF: Duration = Duration::from_secs(1);

/// The longest an endpoint whose connected sends keep failing waits between attempts.
pub(crate) const MAX_BACKOFF: Duration = Duration::from_secs(64);

/// Whether the switch's value turns connected sends on: a set value other than `0` does; no
/// value keeps them off (J789).
pub(crate) fn switch_on(value: Option<&str>) -> bool {
    value.is_some_and(|value| value.trim() != "0")
}

/// Whether connected sends are on for this process: off unless `GOTATUN_BENCH_MAC_CONNECTED` is
/// set to something other than `0`.
pub(crate) fn wanted() -> bool {
    static WANTED: OnceLock<bool> = OnceLock::new();
    *WANTED.get_or_init(|| {
        let on = switch_on(std::env::var("GOTATUN_BENCH_MAC_CONNECTED").ok().as_deref());
        if on {
            eprintln!("diag mac_connected on (GOTATUN_BENCH_MAC_CONNECTED)");
        }
        on
    })
}

/// Why [`bind_pool_counted`] produced no pool.
#[derive(Debug)]
pub(crate) enum PoolError {
    /// No pool, and the port holds only the wildcard socket: either the window never opened
    /// (the kernel's list cannot be read or understood before it), or the pool could not be
    /// built and the audit shows nobody joined. Carry on with `sendto`.
    Unavailable(io::Error),
    /// A socket that is not ours is on the port. It joined while the option was open, or was
    /// there before on an address the wildcard bind does not conflict with. The WireGuard socket
    /// must not be used (its port is shared with someone else).
    Joined(io::Error),
    /// The kernel's socket list could not be read after the window, so nothing proves the port
    /// is ours alone. The WireGuard socket must not be used. (Closing it and binding again
    /// without the pool would free the port for a moment and leave that bind unaudited.)
    Unverified(io::Error),
}

/// The pool for a WireGuard socket that [`super::UdpSocket::bind`] just bound to `local`
/// without `SO_REUSEPORT`: the sockets to use, none (connected sends off, logged), or an error
/// that refuses the WireGuard socket because the port may be shared.
pub(crate) fn pool_for(
    wildcard: &socket2::Socket,
    local: SocketAddr,
    existing: usize,
) -> io::Result<Vec<socket2::Socket>> {
    decide(
        bind_pool_counted(
            wildcard,
            local,
            POOL_SIZE,
            existing,
            |_| {},
            super::macos_port_audit::port_users,
        ),
        local.port(),
    )
}

/// What [`pool_for`] does with each outcome of [`bind_pool_counted`].
fn decide(
    result: Result<Vec<socket2::Socket>, PoolError>,
    port: u16,
) -> io::Result<Vec<socket2::Socket>> {
    match result {
        Ok(pool) => Ok(pool),
        Err(PoolError::Unavailable(error)) => {
            tracing::warn!("macOS UDP: no socket pool for connected sends ({error}); using sendto");
            Ok(Vec::new())
        }
        // Someone else shares the port: refuse it, as if they had held it first.
        Err(PoolError::Joined(error)) => Err(error),
        Err(PoolError::Unverified(error)) => Err(io::Error::new(
            error.kind(),
            format!(
                "cannot check who shares UDP port {port} after binding the connected-send pool \
                 ({error})"
            ),
        )),
    }
}

/// The error that refuses the WireGuard socket because `users` shows sockets on its port
/// beyond the `ours` this process bound.
fn joined(users: &super::macos_port_audit::PortUsers, port: u16, ours: usize) -> PoolError {
    PoolError::Joined(io::Error::new(
        io::ErrorKind::AddrInUse,
        format!(
            "{} sockets share UDP port {port} where this process bound {ours}; others (uid, \
             pid): {:?}",
            users.total, users.others
        ),
    ))
}

/// Bind the pool beside `wildcard`, which must already be bound to `local` **without**
/// `SO_REUSEPORT` (so it holds the port alone), and prove afterwards that nobody else joined.
///
/// Returns `size` sockets bound to `local`, not connected, with `SO_REUSEPORT` cleared on them
/// and on `wildcard`. See the module docs for why this is the only bind window and why it fails
/// closed.
#[cfg(test)]
pub(crate) fn bind_pool(
    wildcard: &socket2::Socket,
    local: SocketAddr,
    size: usize,
) -> Result<Vec<socket2::Socket>, PoolError> {
    bind_pool_with(
        wildcard,
        local,
        size,
        |_| {},
        super::macos_port_audit::port_users,
    )
}

/// [`bind_pool_counted`], with `in_window` called while the option is open (tests use it to join the
/// port the way another process could) and `read_users` reading who is on a port (the kernel's
/// list in the product; tests substitute failures and odd lists).
#[cfg(test)]
fn bind_pool_with(
    wildcard: &socket2::Socket,
    local: SocketAddr,
    size: usize,
    in_window: impl FnOnce(SocketAddr),
    read_users: impl Fn(u16) -> io::Result<super::macos_port_audit::PortUsers>,
) -> Result<Vec<socket2::Socket>, PoolError> {
    bind_pool_counted(wildcard, local, size, 1, in_window, read_users)
}

/// Bind one family's pool while counting all sockets already owned on the port, including
/// the other wildcard and its completed pool. An unreadable pre-audit never opens a window;
/// an unreadable post-audit refuses the whole listener, without releasing and re-binding it.
fn bind_pool_counted(
    wildcard: &socket2::Socket,
    local: SocketAddr,
    size: usize,
    existing: usize,
    in_window: impl FnOnce(SocketAddr),
    read_users: impl Fn(u16) -> io::Result<super::macos_port_audit::PortUsers>,
) -> Result<Vec<socket2::Socket>, PoolError> {
    // Before the window: the list must be readable and show the wildcard socket alone. If it
    // can't be read or doesn't show our socket, no window opens and nothing binds again.
    let before = read_users(local.port()).map_err(PoolError::Unavailable)?;
    if !before.others.is_empty() {
        return Err(joined(&before, local.port(), existing));
    }
    match before.total {
        count if count == existing => {}
        count if count < existing => {
            return Err(PoolError::Unavailable(io::Error::other(
                "the kernel's UDP socket list does not show this socket; its records may have \
                 changed",
            )));
        }
        _ => return Err(joined(&before, local.port(), existing)),
    }

    let mut pool = Vec::with_capacity(size);
    for _ in 0..size {
        // Nothing is open yet, so a failure here needs no audit.
        pool.push(pool_socket_like(wildcard, local).map_err(PoolError::Unavailable)?);
    }

    // The one window: the option on the wildcard socket and on each pool socket while it binds.
    let opened = (|| -> io::Result<()> {
        wildcard.set_reuse_port(true)?;
        for socket in &pool {
            socket.set_reuse_port(true)?;
            socket.bind(&local.into())?;
        }
        in_window(local);
        Ok(())
    })();
    // Closed on every socket whatever happened. A pool socket whose option cannot be cleared is
    // closed with the rest of the pool; the wildcard socket must be cleared or not be used.
    // Every socket is cleared even after a failure (no short-circuit).
    let wildcard_closed = wildcard.set_reuse_port(false);
    let mut pool_closed = Ok(());
    for socket in &pool {
        if let Err(error) = socket.set_reuse_port(false) {
            pool_closed = Err(error);
        }
    }
    if let Err(error) = wildcard_closed {
        return Err(PoolError::Unverified(error));
    }
    let kept = match opened.and(pool_closed) {
        Ok(()) => Ok(pool),
        Err(error) => {
            // Closing them takes them off the port before the audit counts it.
            drop(pool);
            Err(error)
        }
    };
    let ours = existing + kept.as_ref().map_or(0, Vec::len);

    let users = read_users(local.port()).map_err(PoolError::Unverified)?;
    if users.total != ours || !users.others.is_empty() {
        return Err(joined(&users, local.port(), ours));
    }
    kept.map_err(PoolError::Unavailable)
}

/// A fresh, unbound socket with the wildcard socket's family, dual-stack setting and buffers.
fn pool_socket_like(wildcard: &socket2::Socket, local: SocketAddr) -> io::Result<socket2::Socket> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(local),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    socket.set_nonblocking(true)?;
    if local.is_ipv6() {
        socket.set_only_v6(wildcard.only_v6()?)?;
    }
    // Match the wildcard socket's buffers, since this socket carries an endpoint's traffic.
    socket.set_recv_buffer_size(wildcard.recv_buffer_size()?)?;
    socket.set_send_buffer_size(wildcard.send_buffer_size()?)?;
    Ok(socket)
}

/// The address family fixed by a pool socket's bind (see the module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    V4,
    V6,
}

impl Family {
    /// The family of `destination`, in the form the wildcard socket sends to: a v4-mapped IPv6
    /// address is IPv4.
    fn of(destination: SocketAddr) -> Self {
        match destination {
            SocketAddr::V4(_) => Family::V4,
            SocketAddr::V6(address) if address.ip().to_ipv4_mapped().is_some() => Family::V4,
            SocketAddr::V6(_) => Family::V6,
        }
    }
}

/// One pool socket.
struct Slot {
    /// Bound to the WireGuard address and port; connected to `peer` when that is set.
    socket: tokio::net::UdpSocket,
    /// The endpoint the socket is connected to right now. Senders hold the read lock across
    /// their `send` call and a re-connect holds the write lock, so a datagram never leaves on a
    /// socket that is moving to another endpoint.
    peer: RwLock<Option<SocketAddr>>,
    /// Set when a send on this socket failed and the failure count in its [`Assignment`] is
    /// not zero, so a successful send knows (without the table lock) that it must clear it.
    failing: AtomicBool,
}

/// What the table knows about one pool socket (kept under the table lock).
#[derive(Clone, Copy, Debug, Default)]
struct Assignment {
    /// The endpoint the socket serves, if any.
    destination: Option<SocketAddr>,
    /// The family fixed by this slot's bind, installed before any endpoint can use it.
    family: Option<Family>,
    /// The source may be out of date: the next data datagram re-connects first.
    stale: bool,
    /// The table's send counter at this socket's last data send, for least-recently-used reuse.
    last_used: u64,
    /// Send failures in a row on this socket for this endpoint; zero after a successful send.
    failures: u32,
    /// While set and in the future, the endpoint uses `sendto` and the socket is not
    /// re-connected (the back-off of **Failing sends** in the module docs).
    retry_at: Option<Instant>,
    /// The socket was retired ([`ConnectedSends::retire`]) and serves nobody, ever. While
    /// `destination` is still set it keeps that endpoint on `sendto` until the next network
    /// change.
    retired: bool,
}

/// The pool of one WireGuard socket, shared by all of its clones.
pub(crate) struct ConnectedSends {
    /// The pool sockets; empty when connected sends are off. Fixed for the WireGuard socket's
    /// life: no socket is ever added (that would be a bind).
    slots: Box<[Slot]>,
    /// Which endpoint each pool socket serves, by index into `slots`.
    table: Mutex<Vec<Assignment>>,
    /// Counts data sends that asked for a pool socket; assignments record it as their last use.
    sends: AtomicU64,
    /// How many successful connects were made so far (tests and diagnostics).
    connects: AtomicU64,
    /// Whether the one warning about an unexpected send error was logged already.
    warned: AtomicBool,
    /// How many pool sockets were retired so far (tests and diagnostics).
    retirements: AtomicU64,
}

/// A receiver's position: where its next round of polls starts.
#[derive(Clone, Default)]
pub(crate) struct RecvView {
    /// Rotates the first socket polled, so one busy endpoint cannot starve the others.
    next: usize,
}

/// What happened to a datagram offered to a pool socket.
enum Sent {
    /// It left on the pool socket.
    Done,
    /// It did not leave; the caller sends it through `sendto`. A pool socket's own error is
    /// never returned to the caller (see **Failing sends** in the module docs).
    Fallback,
}

impl ConnectedSends {
    /// Connected sends through `pool`, sockets from [`bind_pool_counted`]. Must run inside the tokio
    /// runtime (the sockets register with its reactor).
    pub(crate) fn new(pool: Vec<socket2::Socket>) -> io::Result<Self> {
        let table = pool
            .iter()
            .map(|socket| {
                let local = socket
                    .local_addr()?
                    .as_socket()
                    .ok_or_else(|| io::Error::other("UDP pool socket has no IP address"))?;
                Ok(Assignment {
                    family: Some(Family::of(local)),
                    ..Assignment::default()
                })
            })
            .collect::<io::Result<Vec<_>>>()?;
        let slots = pool
            .into_iter()
            .map(|socket| {
                Ok(Slot {
                    socket: tokio::net::UdpSocket::from_std(socket.into())?,
                    peer: RwLock::new(None),
                    failing: AtomicBool::new(false),
                })
            })
            .collect::<io::Result<Box<[Slot]>>>()?;
        let mut connected = Self::with_slots(slots);
        connected.table = Mutex::new(table);
        Ok(connected)
    }

    /// A table over `slots`, none of them assigned.
    fn with_slots(slots: Box<[Slot]>) -> Self {
        Self {
            table: Mutex::new(vec![Assignment::default(); slots.len()]),
            slots,
            sends: AtomicU64::new(0),
            connects: AtomicU64::new(0),
            warned: AtomicBool::new(false),
            retirements: AtomicU64::new(0),
        }
    }

    /// How many endpoints have a pool socket with a current source right now.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.table
            .lock()
            .iter()
            .filter(|a| a.destination.is_some() && !a.stale && !a.retired)
            .count()
    }

    /// How many pool sockets were retired so far.
    #[cfg(test)]
    pub(crate) fn retirements(&self) -> u64 {
        self.retirements.load(Ordering::Relaxed)
    }

    /// How many successful connects this pool has made so far.
    #[cfg(test)]
    pub(crate) fn connects(&self) -> u64 {
        self.connects.load(Ordering::Relaxed)
    }

    /// Whether connected sends are on for this socket.
    #[cfg(test)]
    pub(crate) fn is_enabled(&self) -> bool {
        !self.slots.is_empty()
    }

    /// The host's network changed: every pool socket re-connects before its next data send.
    ///
    /// Each one keeps the source address and route chosen when it connected, which may be gone
    /// now. Call this from the owner's network-change signal, before asking sessions to announce
    /// themselves. It also ends every send back-off: the new path may take connected sends. The
    /// failure counts stay, so a path that still fails goes straight back to a long back-off.
    pub(crate) fn underlay_changed(&self) {
        let mut table = self.table.lock();
        let mut marked = 0;
        for assignment in table.iter_mut().filter(|a| a.destination.is_some()) {
            if assignment.retired {
                // The refused endpoint may try a live pool socket again.
                assignment.destination = None;
                continue;
            }
            assignment.stale = true;
            assignment.retry_at = None;
            marked += 1;
        }
        drop(table);
        if marked > 0 {
            tracing::debug!("macOS UDP: network changed; {marked} pool sockets re-connect");
        }
    }

    /// Send `payload` to `destination` (already mapped for the wildcard socket).
    ///
    /// Data uses the endpoint's pool socket, taking one first if the pool allows it. Everything
    /// else (handshake messages, cookie replies, keepalives) marks the endpoint's pool socket
    /// stale and leaves through `sendto`, so it picks the current source; the next data
    /// re-connects after it. Data also falls back to `sendto` whenever no pool socket can be
    /// used.
    pub(crate) async fn send(
        &self,
        wildcard: &tokio::net::UdpSocket,
        payload: &[u8],
        destination: SocketAddr,
    ) -> io::Result<()> {
        if !self.slots.is_empty() {
            if !carries_data(payload) {
                // `sendto` picks the current source; the next data re-connects after it.
                self.mark_stale(destination);
            } else if let Some(index) = self.slot_for(destination) {
                match self.send_on(index, payload, destination).await {
                    Sent::Done => return Ok(()),
                    Sent::Fallback => {}
                }
            }
        }
        wildcard.send_to(payload, destination).await.map(|_| ())
    }

    /// Send `payload` on pool socket `index` while it is connected to `destination`.
    ///
    /// Every error ends in [`Sent::Fallback`] (the caller uses `sendto`). ICMP reports are
    /// retried once first, because they usually belong to an earlier datagram; then they and
    /// path errors mark the socket stale with a back-off ([`Self::forget`]), a full buffer
    /// leaves the socket alone, and any other error retires it ([`Self::retire`]).
    async fn send_on(&self, index: usize, payload: &[u8], destination: SocketAddr) -> Sent {
        let slot = &self.slots[index];
        let mut icmp_retried = false;
        loop {
            let result = {
                let peer = slot.peer.read();
                if *peer != Some(destination) {
                    // Moved to another endpoint since the table handed it out.
                    return Sent::Fallback;
                }
                slot.socket.try_send(payload)
            };
            match result {
                Ok(_) => {
                    if slot.failing.load(Ordering::Relaxed) {
                        self.recovered(index, destination);
                    }
                    return Sent::Done;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    // Fails only when the runtime is shutting down: nothing to learn about the
                    // socket.
                    if slot.socket.writable().await.is_err() {
                        return Sent::Fallback;
                    }
                }
                // A pending ICMP error is reported once and cleared; the datagram was not sent.
                Err(error) if is_icmp_error(&error) && !icmp_retried => icmp_retried = true,
                Err(error) if is_icmp_error(&error) || is_path_error(&error) => {
                    self.forget(index, destination, &error);
                    return Sent::Fallback;
                }
                Err(error) if is_full_buffer(&error) => return Sent::Fallback,
                Err(error) => {
                    self.retire(index, destination, &error);
                    return Sent::Fallback;
                }
            }
        }
    }

    /// Receive one datagram from the wildcard socket or any pool socket.
    ///
    /// Errors from the wildcard socket are returned as before. ICMP errors that a pool socket
    /// reports are skipped: they belong to an earlier send, not to this receive.
    pub(crate) fn poll_recv(
        &self,
        wildcard: &tokio::net::UdpSocket,
        view: &mut RecvView,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        if self.slots.is_empty() {
            return poll_one(wildcard, cx, buf);
        }
        let count = self.slots.len() + 1;
        let start = view.next % count;
        view.next = view.next.wrapping_add(1);
        for offset in 0..count {
            let index = (start + offset) % count;
            if index == 0 {
                if let Poll::Ready(result) = poll_one(wildcard, cx, buf) {
                    return Poll::Ready(result);
                }
                continue;
            }
            let socket = &self.slots[index - 1].socket;
            loop {
                match poll_one(socket, cx, buf) {
                    Poll::Ready(Err(error)) if is_icmp_error(&error) => continue,
                    // Any other error stays with this pool socket; the wildcard socket and the
                    // other pool sockets keep receiving.
                    Poll::Ready(Err(error)) => {
                        tracing::debug!("macOS UDP: pool socket receive error ({error})");
                        break;
                    }
                    Poll::Ready(ok) => return Poll::Ready(ok),
                    Poll::Pending => break,
                }
            }
        }
        Poll::Pending
    }

    /// The pool socket for `destination`, connected first if it is new to the endpoint or
    /// stale. Only called for data ([`carries_data`]). `None` means "use `sendto`".
    fn slot_for(&self, destination: SocketAddr) -> Option<usize> {
        let now = self.sends.fetch_add(1, Ordering::Relaxed);
        let mut table = self.table.lock();
        if let Some(index) = table
            .iter()
            .position(|assignment| assignment.destination == Some(destination))
        {
            if table[index].retired {
                // Refused here before: `sendto` until the next network change.
                return None;
            }
            if let Some(retry_at) = table[index].retry_at
                && Instant::now() < retry_at
            {
                // Backing off: `sendto`. `last_used` stays old, so a busy endpoint may take
                // this socket over meanwhile.
                return None;
            }
            table[index].last_used = now;
            if !table[index].stale {
                return Some(index);
            }
            return self.connect_slot(&mut table, index, destination, now);
        }
        let index = pick(&table, Family::of(destination), now)?;
        self.connect_slot(&mut table, index, destination, now)
    }

    /// (Re-)connect pool socket `index` to `destination` and record it. A connected UDP socket
    /// is disconnected by the kernel first, which clears its source, so this also refreshes a
    /// stale source.
    fn connect_slot(
        &self,
        table: &mut [Assignment],
        index: usize,
        destination: SocketAddr,
        now: u64,
    ) -> Option<usize> {
        let slot = &self.slots[index];
        let mut peer = slot.peer.write();
        let family = table[index].family;
        match socket2::SockRef::from(&slot.socket).connect(&destination.into()) {
            Ok(()) => {
                // A re-connect to the same endpoint keeps its failure count and back-off; a move
                // to a new endpoint starts clean.
                let (failures, retry_at) = if table[index].destination == Some(destination) {
                    (table[index].failures, table[index].retry_at)
                } else {
                    slot.failing.store(false, Ordering::Relaxed);
                    (0, None)
                };
                *peer = Some(destination);
                table[index] = Assignment {
                    destination: Some(destination),
                    family,
                    stale: false,
                    last_used: now,
                    failures,
                    retry_at,
                    retired: false,
                };
                self.connects.fetch_add(1, Ordering::Relaxed);
                Some(index)
            }
            Err(error) if is_defunct_error(&error) => {
                drop(peer);
                self.retire_locked(table, index, destination, &error);
                None
            }
            Err(error) => {
                // Whatever it was connected to before, it is not connected now.
                *peer = None;
                let known = table[index].family;
                table[index] = Assignment {
                    family: known,
                    ..Assignment::default()
                };
                tracing::debug!(
                    "macOS UDP: no pool socket to {destination} for now ({error}); using sendto"
                );
                None
            }
        }
    }

    /// Mark pool socket `index` stale after a path error or an ICMP report on it, and start or
    /// extend its back-off (see **Failing sends** in the module docs): the first failure in a
    /// row re-connects on the next data datagram, later ones wait [`backoff`].
    fn forget(&self, index: usize, destination: SocketAddr, error: &io::Error) {
        tracing::debug!("macOS UDP: the pool socket to {destination} re-connects ({error})");
        let mut table = self.table.lock();
        let assignment = &mut table[index];
        if assignment.destination == Some(destination) {
            assignment.stale = true;
            assignment.failures = assignment.failures.saturating_add(1);
            assignment.retry_at = backoff(assignment.failures).map(|wait| Instant::now() + wait);
            self.slots[index].failing.store(true, Ordering::Relaxed);
        }
    }

    /// Retire pool socket `index` after `error` showed the kernel will not let it carry
    /// `destination`'s traffic (see **Failing sends** in the module docs).
    fn retire(&self, index: usize, destination: SocketAddr, error: &io::Error) {
        let mut table = self.table.lock();
        if table[index].destination == Some(destination) && !table[index].retired {
            self.retire_locked(&mut table, index, destination, error);
        }
    }

    /// [`Self::retire`] with the table lock held (taken before the slot's peer lock, the order
    /// [`Self::connect_slot`] uses).
    ///
    /// The open file behind the slot's descriptor is replaced (`dup2`) by a fresh UDP socket of
    /// the same family that is never bound and never used. The kernel closes the old socket, so
    /// it stops taking `destination`'s datagrams, and no socket binds the port. The descriptor
    /// stays valid for everything that holds the slot, and the receive loop finds the new socket
    /// never readable. If the replacement fails, the slot is still never used again.
    fn retire_locked(
        &self,
        table: &mut [Assignment],
        index: usize,
        destination: SocketAddr,
        error: &io::Error,
    ) {
        use std::os::fd::AsRawFd;
        let slot = &self.slots[index];
        let mut peer = slot.peer.write();
        *peer = None;
        let domain = match table[index].family {
            Some(Family::V6) => socket2::Domain::IPV6,
            _ => socket2::Domain::IPV4,
        };
        let closed = socket2::Socket::new(domain, socket2::Type::DGRAM, None).and_then(|fresh| {
            fresh.set_nonblocking(true)?;
            let target = slot.socket.as_raw_fd();
            // SAFETY: both descriptors are open and owned by this process; `dup2` atomically
            // makes `target` refer to the fresh socket and closes the file it referred to.
            // `target` stays owned by the slot's tokio socket; `fresh` closes its own copy on
            // drop.
            if unsafe { libc::dup2(fresh.as_raw_fd(), target) } < 0 {
                return Err(io::Error::last_os_error());
            }
            // `dup2` clears close-on-exec on the new descriptor.
            // SAFETY: `target` is an open descriptor; F_SETFD only sets its flags.
            if unsafe { libc::fcntl(target, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
        drop(peer);
        table[index] = Assignment {
            destination: Some(destination),
            family: table[index].family,
            retired: true,
            ..Assignment::default()
        };
        self.slots[index].failing.store(false, Ordering::Relaxed);
        self.retirements.fetch_add(1, Ordering::Relaxed);
        if !self.warned.swap(true, Ordering::Relaxed) {
            // Once per WireGuard socket; an endpoint that keeps being refused is not news.
            tracing::warn!(
                "macOS UDP: the kernel refused connected sends to {destination} ({error}); \
                 that endpoint uses sendto until the network changes"
            );
        } else {
            tracing::debug!("macOS UDP: pool socket to {destination} retired ({error})");
        }
        if let Err(close_error) = closed {
            tracing::warn!("macOS UDP: a retired pool socket could not be closed ({close_error})");
        }
    }

    /// A send on pool socket `index` to `destination` worked again: clear its failure count.
    fn recovered(&self, index: usize, destination: SocketAddr) {
        let mut table = self.table.lock();
        let assignment = &mut table[index];
        if assignment.destination == Some(destination) {
            assignment.failures = 0;
            assignment.retry_at = None;
            self.slots[index].failing.store(false, Ordering::Relaxed);
        }
    }

    /// Mark the pool socket serving `destination` stale, if there is one.
    fn mark_stale(&self, destination: SocketAddr) {
        let mut table = self.table.lock();
        if let Some(assignment) = table
            .iter_mut()
            .find(|assignment| assignment.destination == Some(destination))
        {
            assignment.stale = true;
        }
    }
}

/// Where one run of a batched send goes (see [`super::macos_batch`]).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Target {
    /// The route's unconnected socket, with a destination per datagram.
    Wildcard,
    /// Pool socket `.0`, connected to `.1`, no destination.
    Slot(usize, SocketAddr),
}

/// The marker error a [`SlotSink`] returns when its pool socket moved to another endpoint
/// between two calls: nothing was sent, and the rest goes through the wildcard socket.
#[derive(Debug)]
struct Moved;

impl std::fmt::Display for Moved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the pool socket moved to another endpoint")
    }
}

impl std::error::Error for Moved {}

/// Whether `error` is the [`Moved`] marker.
fn is_moved(error: &io::Error) -> bool {
    error.get_ref().is_some_and(|inner| inner.is::<Moved>())
}

/// A [`super::macos_batch::BatchSink`] over one pool socket while it serves `to`.
///
/// Every call takes the socket's read lock and checks that it is still connected to `to`, as
/// [`ConnectedSends::send_on`] does, so a datagram never leaves toward another endpoint.
struct SlotSink<'a> {
    /// The pool socket.
    slot: &'a Slot,
    /// The endpoint the run is for.
    to: SocketAddr,
    /// The payloads, in send order.
    payloads: &'a [(&'a [u8], SocketAddr)],
}

impl super::macos_batch::BatchSink for SlotSink<'_> {
    fn try_batch(&self, from: usize) -> io::Result<usize> {
        use std::os::fd::AsRawFd;
        let peer = self.slot.peer.read();
        if *peer != Some(self.to) {
            return Err(io::Error::other(Moved));
        }
        self.slot.socket.try_io(tokio::io::Interest::WRITABLE, || {
            super::macos_batch::send_x(
                self.slot.socket.as_raw_fd(),
                self.payloads[from..]
                    .iter()
                    .map(|(payload, _)| (*payload, None)),
            )
        })
    }

    fn try_single(&self, index: usize) -> io::Result<()> {
        let peer = self.slot.peer.read();
        if *peer != Some(self.to) {
            return Err(io::Error::other(Moved));
        }
        self.slot
            .socket
            .try_send(self.payloads[index].0)
            .map(|_| ())
    }

    async fn writable(&self) -> io::Result<()> {
        self.slot.socket.writable().await
    }
}

impl ConnectedSends {
    /// Whether runs of more than one datagram can use `sendmsg_x` on this WireGuard socket:
    /// on its pool sockets (connected sends on) or on its wildcard socket, as
    /// [`super::macos_batch::policy`] allows.
    pub(crate) fn batches_sends(&self) -> bool {
        let policy = super::macos_batch::policy();
        policy.send_wildcard || (policy.send_connected && !self.slots.is_empty())
    }

    /// Send a run that leaves through one wildcard socket, with as few system calls as the
    /// batching policy allows. `destination`s are already mapped for `wildcard`.
    ///
    /// Consecutive datagrams to the same target form one call: data to an endpoint with a pool
    /// socket goes on that connected socket without an address, everything else on `wildcard`
    /// with its destination. The pool's rules are those of [`ConnectedSends::send`]: non-data
    /// marks its endpoint stale and takes the wildcard socket, and a run on a pool socket is only
    /// sent while the socket is still connected to that endpoint.
    ///
    /// Every datagram is attempted; the last error, if any, is returned, as `sendto` would
    /// have reported it for that datagram.
    pub(crate) async fn send_batch(
        &self,
        wildcard: &tokio::net::UdpSocket,
        run: &[(&[u8], SocketAddr)],
    ) -> io::Result<()> {
        let mut result = Ok(());
        let mut start = 0;
        while start < run.len() {
            let target = self.target_of(run[start].0, run[start].1);
            let mut end = start + 1;
            while end < run.len() {
                let next = match target {
                    // Same endpoint, still data: stays on the slot without another table lookup.
                    Target::Slot(_, to) if run[end].1 == to && carries_data(run[end].0) => target,
                    Target::Slot(..) => break,
                    Target::Wildcard if self.slots.is_empty() => Target::Wildcard,
                    Target::Wildcard => {
                        // Peek without side effects; `target_of` runs for the next run's head.
                        if carries_data(run[end].0) && self.has_slot(run[end].1) {
                            break;
                        }
                        if !carries_data(run[end].0) {
                            self.mark_stale(run[end].1);
                        }
                        Target::Wildcard
                    }
                };
                if next != target {
                    break;
                }
                end += 1;
            }
            let chunk = &run[start..end];
            let sent = match target {
                Target::Wildcard => send_wildcard(wildcard, chunk).await,
                Target::Slot(index, to) => self.send_slot(wildcard, index, to, chunk).await,
            };
            if let Err(error) = sent {
                result = Err(error);
            }
            start = end;
        }
        result
    }

    /// Whether `destination` has a pool socket assigned or could get one; the next data
    /// datagram to it then ends a wildcard run. Only a hint for splitting runs.
    fn has_slot(&self, destination: SocketAddr) -> bool {
        let table = self.table.lock();
        table
            .iter()
            .any(|assignment| assignment.destination == Some(destination))
            || pick(
                &table,
                Family::of(destination),
                self.sends.load(Ordering::Relaxed),
            )
            .is_some()
    }

    /// The target of one datagram, taking a pool socket for new data endpoints as `send` does.
    fn target_of(&self, payload: &[u8], destination: SocketAddr) -> Target {
        if self.slots.is_empty() {
            return Target::Wildcard;
        }
        if !carries_data(payload) {
            self.mark_stale(destination);
            return Target::Wildcard;
        }
        match self.slot_for(destination) {
            Some(index) => Target::Slot(index, destination),
            None => Target::Wildcard,
        }
    }

    /// Send `chunk` on pool socket `index` while it is connected to `to`; whatever cannot go
    /// there (the socket moved, or any send error) leaves through `wildcard`, and only the
    /// wildcard socket's own errors are returned (see **Failing sends** in the module docs).
    ///
    /// With `sendmsg_x` allowed on connected sockets this is one batch call per socket-full;
    /// otherwise, and after an error that may have sent part of a batch, one `send` per
    /// datagram through [`ConnectedSends::send_on`].
    async fn send_slot(
        &self,
        wildcard: &tokio::net::UdpSocket,
        index: usize,
        to: SocketAddr,
        chunk: &[(&[u8], SocketAddr)],
    ) -> io::Result<()> {
        let mut done = 0;
        let mut result = Ok(());
        if super::macos_batch::policy().send_connected && chunk.len() > 1 {
            let sink = SlotSink {
                slot: &self.slots[index],
                to,
                payloads: chunk,
            };
            let mut icmp_retried = false;
            loop {
                let sink = SlotSink {
                    payloads: &chunk[done..],
                    ..sink
                };
                let stopped = super::macos_batch::send_loop(&sink, sink.payloads.len()).await;
                done += stopped.done;
                if let Some(error) = stopped.dropped {
                    result = Err(error);
                }
                let Some(error) = stopped.error else {
                    return result;
                };
                if is_moved(&error) {
                    return merge(result, send_wildcard(wildcard, &chunk[done..]).await);
                }
                // A pending ICMP error is reported once, before anything was sent: retry once.
                if is_icmp_error(&error) && !icmp_retried && !stopped.maybe_sent {
                    icmp_retried = true;
                    continue;
                }
                if is_icmp_error(&error) || is_path_error(&error) {
                    self.forget(index, to, &error);
                    return merge(result, send_wildcard(wildcard, &chunk[done..]).await);
                }
                tracing::trace!("sendmsg_x on a pool socket failed after {done} ({error})");
                // Exact per-datagram errors for the rest; a prefix may leave twice (module docs
                // of `macos_batch`), which the receiver's replay window drops.
                break;
            }
        }
        for (offset, (payload, destination)) in chunk[done..].iter().enumerate() {
            if let Sent::Fallback = self.send_on(index, payload, *destination).await {
                // The socket failed (now stale or retired) or moved: the rest of the chunk
                // leaves through the wildcard socket too, so one failing chunk counts once
                // toward the back-off instead of once per datagram (J1108).
                return merge(
                    result,
                    send_wildcard(wildcard, &chunk[done + offset..]).await,
                );
            }
        }
        result
    }

    /// How many pool sockets the batched receive reads besides the wildcard socket.
    pub(crate) fn pool_len(&self) -> usize {
        self.slots.len()
    }

    /// Pool socket `index` (below [`ConnectedSends::pool_len`]), for the batched receive.
    pub(crate) fn pool_socket(&self, index: usize) -> &tokio::net::UdpSocket {
        &self.slots[index].socket
    }
}

/// `first`, unless it is fine and `second` is an error.
fn merge(first: io::Result<()>, second: io::Result<()>) -> io::Result<()> {
    first.and(second)
}

/// Send `chunk` on the unconnected `wildcard` socket, each datagram to its destination.
///
/// With `sendmsg_x` allowed on the wildcard socket this is one batch call per socket-full;
/// otherwise, and after an error that may have sent part of a batch, one `sendto` per datagram.
async fn send_wildcard(
    wildcard: &tokio::net::UdpSocket,
    chunk: &[(&[u8], SocketAddr)],
) -> io::Result<()> {
    let mut done = 0;
    let mut result = Ok(());
    if super::macos_batch::policy().send_wildcard && chunk.len() > 1 {
        let sink = super::macos_batch::SocketSink {
            socket: wildcard,
            items: chunk,
            connected: false,
        };
        let stopped = super::macos_batch::send_loop(&sink, chunk.len()).await;
        done = stopped.done;
        if let Some(error) = stopped.dropped {
            result = Err(error);
        }
        match stopped.error {
            None => return result,
            // That datagram failed alone; the rest go one at a time below.
            Some(error) if !stopped.maybe_sent => {
                result = Err(error);
                done += 1;
            }
            Some(error) => {
                tracing::trace!("sendmsg_x failed after {done} ({error}); one at a time");
            }
        }
    }
    for (payload, destination) in &chunk[done.min(chunk.len())..] {
        if let Err(error) = wildcard.send_to(payload, *destination).await {
            result = Err(error);
        }
    }
    result
}

/// Read one `recvmsg_x` batch from `socket` if it has any.
///
/// `Ready(Ok(n))` with `n > 0` when datagrams were appended to `packets`, `Pending` (waker
/// registered) when it has none. On a pool socket (`pool_socket`), ICMP reports are skipped as
/// [`ConnectedSends::poll_recv`] does and other errors only logged.
pub(crate) fn poll_recv_batch_one(
    socket: &tokio::net::UdpSocket,
    pool_socket: bool,
    cx: &mut Context<'_>,
    buf: &mut super::macos_batch::RecvBuf,
    packet_pool: &mut crate::packet::PacketBufPool,
    packets: &mut Vec<(crate::packet::Packet, SocketAddr)>,
    map_src: &impl Fn(SocketAddr) -> SocketAddr,
) -> Poll<io::Result<usize>> {
    use std::os::fd::AsRawFd;
    loop {
        match socket.poll_recv_ready(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        let before = packets.len();
        match socket.try_io(tokio::io::Interest::READABLE, || {
            super::macos_batch::recv_x(socket.as_raw_fd(), buf, packet_pool, packets, map_src)
        }) {
            // Every datagram of the call was dropped (truncated): read on.
            Ok(_) if packets.len() == before => continue,
            Ok(_) => return Poll::Ready(Ok(packets.len() - before)),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) if pool_socket && is_icmp_error(&error) => continue,
            Err(error) if pool_socket => {
                tracing::debug!("macOS UDP: pool socket receive error ({error})");
                return Poll::Pending;
            }
            Err(error) => return Poll::Ready(Err(error)),
        }
    }
}

/// The pool socket a new endpoint of `family` gets: a free one of its bound family, else
/// the least recently used one of that family that has been idle for [`ACTIVE_SENDS`] data sends. `None` when every
/// candidate is busy.
fn pick(table: &[Assignment], family: Family, now: u64) -> Option<usize> {
    let free = |wanted: Option<Family>| {
        table
            .iter()
            .position(|a| a.destination.is_none() && !a.retired && a.family == wanted)
    };
    free(Some(family)).or_else(|| {
        let (index, idle) = table
            .iter()
            .enumerate()
            .filter(|(_, a)| a.family == Some(family) && !a.retired)
            .map(|(index, a)| (index, now.saturating_sub(a.last_used)))
            .max_by_key(|&(_, idle)| idle)?;
        // Every socket of the family is busy: this endpoint keeps `sendto`.
        (idle >= ACTIVE_SENDS).then_some(index)
    })
}

/// How long an endpoint stays on `sendto` after `failures` send failures in a row: none after
/// the first (re-connect at once), then [`FIRST_BACKOFF`] doubling up to [`MAX_BACKOFF`].
fn backoff(failures: u32) -> Option<Duration> {
    let doublings = failures.checked_sub(2)?;
    Some(
        FIRST_BACKOFF
            .checked_mul(1u32.checked_shl(doublings).unwrap_or(u32::MAX))
            .map_or(MAX_BACKOFF, |wait| wait.min(MAX_BACKOFF)),
    )
}

/// Poll one socket for a datagram.
fn poll_one(
    socket: &tokio::net::UdpSocket,
    cx: &mut Context<'_>,
    buf: &mut [u8],
) -> Poll<io::Result<(usize, SocketAddr)>> {
    let mut read = ReadBuf::new(buf);
    socket
        .poll_recv_from(cx, &mut read)
        .map(|result| result.map(|source| (read.filled().len(), source)))
}

/// Whether `payload` is a WireGuard data message that carries a packet: the only kind that uses
/// a pool socket. Keepalives (an empty data message) and handshake messages do not.
fn carries_data(payload: &[u8]) -> bool {
    payload.len() > KEEPALIVE_LEN && payload.first() == Some(&WgPacketType::Data.0)
}

/// An error a connected UDP socket reports for an ICMP message about an earlier datagram.
fn is_icmp_error(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::ECONNREFUSED | libc::EHOSTDOWN | libc::EHOSTUNREACH)
    )
}

/// A send error that means the socket's buffer is full right now; the socket itself is fine.
fn is_full_buffer(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::ENOBUFS | libc::ENOMEM))
}

/// A `connect` error from a socket the kernel has made defunct: it can never carry anything
/// again and must be retired.
fn is_defunct_error(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::EOPNOTSUPP))
}

/// A send error that says this connected socket's address or route no longer works.
fn is_path_error(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EADDRNOTAVAIL | libc::ENETUNREACH | libc::ENETDOWN | libc::EDESTADDRREQ)
    )
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, Ipv6Addr, SocketAddr},
        time::Duration,
    };

    use crate::{
        packet::{Packet, PacketBufPool},
        udp::{
            UdpRecv, UdpSend,
            socket::{SockOpt, UdpSocket},
        },
    };

    /// A data-message-shaped payload of `len` bytes (type 4), large enough to get a socket.
    fn data(len: usize) -> Vec<u8> {
        let mut payload = vec![0u8; len];
        payload[0] = 4;
        payload
    }

    /// A handshake-initiation-shaped payload (type 1, 148 bytes).
    fn initiation() -> Vec<u8> {
        let mut payload = vec![0u8; 148];
        payload[0] = 1;
        payload
    }

    /// A dual-stack WireGuard socket on a free port, the way the product binds it.
    fn wireguard_socket(connected: bool) -> UdpSocket {
        let opts = SockOpt {
            only_v6: Some(false),
            mac_connected: Some(connected),
            ..SockOpt::default()
        };
        UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0).into(), opts).expect("bind [::]:0")
    }

    /// A plain loopback peer.
    async fn peer() -> (tokio::net::UdpSocket, SocketAddr) {
        let socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind peer");
        let address = socket.local_addr().expect("peer address");
        (socket, address)
    }

    /// Wait for one datagram on `socket` (a hang check, not a speed check).
    async fn recv(socket: &mut UdpSocket) -> (Vec<u8>, SocketAddr) {
        let mut pool = PacketBufPool::new(4);
        let (packet, source) =
            tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut pool))
                .await
                .expect("a datagram within 5 s")
                .expect("receive");
        (packet.to_vec(), source)
    }

    /// Wait for one datagram on a plain peer socket (a hang check, not a speed check).
    async fn peer_recv(socket: &tokio::net::UdpSocket) -> (Vec<u8>, SocketAddr) {
        let mut buf = [0u8; 256];
        let (n, source) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buf))
            .await
            .expect("a datagram within 5 s")
            .expect("receive");
        (buf[..n].to_vec(), source)
    }

    /// Send `payload` from the WireGuard socket.
    async fn send(socket: &UdpSocket, payload: &[u8], to: SocketAddr) {
        socket
            .send_to(Packet::from_bytes(bytes::BytesMut::from(payload)), to)
            .await
            .expect("send");
    }

    /// The switch: off when unset, on only for a value other than `0` (J789: off by default until
    /// the port cannot be taken over during a connected socket's bind; see the module docs).
    #[test]
    fn connected_sends_are_off_unless_switched_on() {
        assert!(!super::switch_on(None));
        assert!(super::switch_on(Some("1")));
        assert!(!super::switch_on(Some("0")));
        assert!(!super::switch_on(Some(" 0\n")));
    }

    /// Binding the WireGuard socket the default way (no explicit choice) keeps `sendto`, so no
    /// socket of ours ever carries the shared-port option.
    #[tokio::test]
    async fn a_default_socket_keeps_sendto() {
        if std::env::var_os("GOTATUN_BENCH_MAC_CONNECTED").is_some() {
            return; // The switch decides; the default is what this test checks.
        }
        let opts = SockOpt {
            only_v6: Some(false),
            ..SockOpt::default()
        };
        let wireguard = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0).into(), opts).expect("bind");
        let (a, a_address) = peer().await;
        send(&wireguard, &data(64), a_address).await;
        peer_recv(&a).await;
        assert_eq!(wireguard.inner.connected.len(), 0);
    }

    /// The first data send to an endpoint gives it a connected socket on the WireGuard port. The
    /// endpoint sees the WireGuard port as the source, its replies (which the kernel now delivers
    /// to the connected socket) still arrive, and so do datagrams from other endpoints.
    #[tokio::test]
    async fn an_endpoint_gets_a_connected_socket_and_its_replies_still_arrive() {
        let mut wireguard = wireguard_socket(true);
        let port = wireguard.local_addr().expect("local").port();
        let (a, a_address) = peer().await;
        let (b, _) = peer().await;

        send(&wireguard, &data(64), a_address).await;
        let (payload, source) = peer_recv(&a).await;
        assert_eq!(payload, data(64));
        assert_eq!(source.port(), port, "the endpoint sees the WireGuard port");
        assert_eq!(
            wireguard.inner.connected.len(),
            1,
            "a connected socket for the endpoint"
        );

        let ours: SocketAddr = (Ipv4Addr::LOCALHOST, port).into();
        a.send_to(b"from-a", ours).await.expect("a replies");
        assert_eq!(recv(&mut wireguard).await, (b"from-a".to_vec(), a_address));
        b.send_to(b"from-b", ours).await.expect("b sends");
        let (payload, source) = recv(&mut wireguard).await;
        assert_eq!(payload, b"from-b");
        assert_eq!(source, b.local_addr().expect("b address"));

        send(&wireguard, &data(65), a_address).await;
        assert_eq!(peer_recv(&a).await.0, data(65));
        assert_eq!(wireguard.inner.connected.len(), 1, "the entry is reused");
    }

    /// While connected sends are on, no other wildcard socket can join the WireGuard port: the
    /// shared-port option is cleared once the pool is bound, and connecting an endpoint binds
    /// nothing (J763 measured that macOS lets any user co-bind a port that carries it, even a
    /// specific address that then steals its datagrams). A specific-address bind by the *same*
    /// user is allowed with or without this feature, so it is not checked here; the cross-user
    /// race harness is `j815_race_holder` (#260).
    #[tokio::test]
    async fn the_port_stays_closed_to_other_sockets() {
        let wireguard = wireguard_socket(true);
        let port = wireguard.local_addr().expect("local").port();
        let (a, a_address) = peer().await;
        send(&wireguard, &data(64), a_address).await;
        peer_recv(&a).await;
        assert_eq!(wireguard.inner.connected.len(), 1);

        for address in [
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)),
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)),
        ] {
            let other = socket2::Socket::new(
                socket2::Domain::for_address(address),
                socket2::Type::DGRAM,
                None,
            )
            .expect("socket");
            other.set_reuse_port(true).expect("SO_REUSEPORT");
            assert!(
                other.bind(&address.into()).is_err(),
                "another socket must not bind {address} beside ours"
            );
        }

        // Our next endpoint still gets a pool socket.
        let (b, b_address) = peer().await;
        send(&wireguard, &data(64), b_address).await;
        peer_recv(&b).await;
        assert_eq!(wireguard.inner.connected.len(), 2);
    }

    /// The startup pool uses only AF_INET and IPv6-only sockets, all exclusive after bind.
    /// Sending to mapped IPv4 selects an AF_INET slot, and the slot families never change.
    #[tokio::test]
    async fn the_split_pool_keeps_every_socket_exclusive_and_per_family() {
        let wireguard = wireguard_socket(true);
        let slots = &wireguard.inner.connected.slots;
        assert_eq!(slots.len(), 2 * super::POOL_SIZE);
        let mut v4_count = 0;
        for socket in wireguard
            .bound_sockets()
            .into_iter()
            .chain(slots.iter().map(|slot| &slot.socket))
        {
            let reference = socket2::SockRef::from(socket);
            assert!(!reference.reuse_port().expect("SO_REUSEPORT"));
            if socket.local_addr().expect("local").is_ipv6() {
                assert!(reference.only_v6().expect("IPV6_V6ONLY"));
            } else {
                v4_count += 1;
            }
        }
        assert_eq!(v4_count, super::POOL_SIZE + 1);
        let (peer, address) = peer().await;
        let SocketAddr::V4(ipv4) = address else {
            panic!("IPv4 peer")
        };
        send(
            &wireguard,
            &data(64),
            (ipv4.ip().to_ipv6_mapped(), ipv4.port()).into(),
        )
        .await;
        peer_recv(&peer).await;
        let table = wireguard.inner.connected.table.lock();
        assert!(
            table
                .iter()
                .any(|assignment| assignment.destination == Some(address)
                    && assignment.family == Some(super::Family::V4))
        );
    }

    /// A network change marks every pool socket stale; the next data re-connects and arrives.
    #[tokio::test]
    async fn a_network_change_reconnects_every_endpoint() {
        let wireguard = wireguard_socket(true);
        let (a, a_address) = peer().await;
        let (b, b_address) = peer().await;
        send(&wireguard, &data(64), a_address).await;
        send(&wireguard, &data(64), b_address).await;
        peer_recv(&a).await;
        peer_recv(&b).await;
        assert_eq!(wireguard.inner.connected.len(), 2);

        wireguard.underlay_changed();
        assert_eq!(
            wireguard.inner.connected.len(),
            0,
            "every pool socket stale"
        );

        let before = wireguard.inner.connected.connects();
        send(&wireguard, &data(66), a_address).await;
        assert_eq!(peer_recv(&a).await.0, data(66));
        assert_eq!(
            wireguard.inner.connected.connects(),
            before + 1,
            "a fresh connect"
        );
    }

    /// A network change while the receive task is running re-connects the same pool socket, so
    /// an endpoint whose route did not move gets its 4-tuple back without colliding with
    /// anything (J763's version re-created sockets and had to avoid that collision).
    #[tokio::test]
    async fn a_network_change_reconnects_while_the_receiver_runs() {
        let wireguard = wireguard_socket(true);
        let mut receiver = wireguard.clone();
        let task = tokio::spawn(async move {
            let mut pool = PacketBufPool::new(4);
            while receiver.recv_from(&mut pool).await.is_ok() {}
        });
        let (a, a_address) = peer().await;
        send(&wireguard, &data(64), a_address).await;
        peer_recv(&a).await;
        // sleep: let the receive task take the new entry into its view (the insert wakes it).
        tokio::time::sleep(Duration::from_millis(50)).await;

        wireguard.underlay_changed();
        let before = wireguard.inner.connected.connects();
        send(&wireguard, &data(66), a_address).await;
        assert_eq!(peer_recv(&a).await.0, data(66));
        assert_eq!(
            wireguard.inner.connected.connects(),
            before + 1,
            "the endpoint reconnected on its unchanged 4-tuple"
        );
        assert_eq!(wireguard.inner.connected.len(), 1);
        task.abort();
    }

    /// A handshake initiation leaves through the wildcard socket and marks its endpoint's pool
    /// socket stale, so a stale source ends at WireGuard's own retry even with no signal.
    #[tokio::test]
    async fn a_handshake_initiation_reconnects_its_endpoint() {
        let wireguard = wireguard_socket(true);
        let (a, a_address) = peer().await;
        send(&wireguard, &data(64), a_address).await;
        peer_recv(&a).await;
        assert_eq!(wireguard.inner.connected.len(), 1);

        send(&wireguard, &initiation(), a_address).await;
        assert_eq!(peer_recv(&a).await.0, initiation());
        assert_eq!(
            wireguard.inner.connected.len(),
            0,
            "the initiation marked the entry stale"
        );

        let before = wireguard.inner.connected.connects();
        send(&wireguard, &data(64), a_address).await;
        peer_recv(&a).await;
        assert_eq!(wireguard.inner.connected.connects(), before + 1);
    }

    /// Keepalives and handshake responses also leave through the wildcard socket and mark their
    /// endpoint's pool socket stale (J789). A Mac that is idle or only receives sends nothing but
    /// keepalives, and a responder sends no initiation. If these rode a stale connected socket,
    /// nothing would move the session to the current source until it expired (up to 9 minutes).
    /// Through `sendto` they leave from the current source, so the peer roams to it.
    #[tokio::test]
    async fn keepalives_and_responses_reconnect_their_endpoint() {
        let wireguard = wireguard_socket(true);
        let (a, a_address) = peer().await;
        let mut response = vec![0u8; 92];
        response[0] = 2;
        for (name, message) in [("keepalive", data(32)), ("handshake response", response)] {
            send(&wireguard, &data(64), a_address).await;
            peer_recv(&a).await;
            assert_eq!(
                wireguard.inner.connected.len(),
                1,
                "data made an entry before the {name}"
            );

            send(&wireguard, &message, a_address).await;
            assert_eq!(peer_recv(&a).await.0, message);
            assert_eq!(
                wireguard.inner.connected.len(),
                0,
                "the {name} marked the entry stale"
            );
        }
    }

    /// Keepalives and handshake messages never take a pool socket.
    #[tokio::test]
    async fn keepalives_and_handshakes_do_not_create_sockets() {
        let wireguard = wireguard_socket(true);
        let (a, a_address) = peer().await;
        let mut response = vec![0u8; 92];
        response[0] = 2;
        // Checked after each message: a later handshake message closes an entry, so one check at
        // the end would not see a socket that the keepalive created (J789 mutation run).
        for message in [data(32), initiation(), response] {
            send(&wireguard, &message, a_address).await;
            assert_eq!(peer_recv(&a).await.0, message);
            assert_eq!(
                wireguard.inner.connected.len(),
                0,
                "{} bytes made no entry",
                message.len()
            );
        }
    }

    /// An endpoint the kernel cannot reach right now gets `sendto` for that datagram, and
    /// connected sends stay on for everyone else: neither a failed `connect` nor a failed `send`
    /// is a refused port. On macOS 26 `connect` succeeds for unroutable addresses and the
    /// `send` fails (`0.0.0.1`: `EHOSTUNREACH`); `connect` itself fails with `EADDRNOTAVAIL`
    /// when no source can reach the endpoint, as when the Mac has no network at all, and port 0
    /// reproduces that error on loopback (J763 probe on #260).
    #[tokio::test]
    async fn an_unreachable_endpoint_does_not_turn_the_feature_off() {
        let wireguard = wireguard_socket(true);
        for nowhere in [
            SocketAddr::from((Ipv4Addr::new(0, 0, 0, 1), 9)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        ] {
            let result = wireguard
                .send_to(
                    Packet::from_bytes(bytes::BytesMut::from(&data(64)[..])),
                    nowhere,
                )
                .await;
            assert!(
                result.is_err(),
                "{nowhere} must be unreachable for this test"
            );
            assert!(
                wireguard.inner.connected.is_enabled(),
                "still on after {nowhere}"
            );
            assert_eq!(
                wireguard.inner.connected.len(),
                0,
                "no entry left for {nowhere}"
            );
        }

        let (a, a_address) = peer().await;
        send(&wireguard, &data(64), a_address).await;
        peer_recv(&a).await;
        assert_eq!(wireguard.inner.connected.len(), 1);
    }

    /// An ICMP "port unreachable" for a connected endpoint is reported on that socket's next
    /// call. It must neither stop the receive loop nor fail later sends.
    #[tokio::test]
    async fn icmp_errors_on_a_connected_socket_do_not_stop_sends_or_receives() {
        let mut wireguard = wireguard_socket(true);
        let port = wireguard.local_addr().expect("local").port();
        let (closed, closed_address) = peer().await;
        drop(closed);

        for _ in 0..3 {
            send(&wireguard, &data(64), closed_address).await;
            // sleep: give the kernel time to queue the ICMP error on the connected socket.
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let (b, b_address) = peer().await;
        b.send_to(b"from-b", (Ipv4Addr::LOCALHOST, port))
            .await
            .expect("b sends");
        assert_eq!(recv(&mut wireguard).await, (b"from-b".to_vec(), b_address));
    }

    /// A freshly bound WireGuard socket refuses other sockets on its port before it has sent
    /// anything: the shared-port option the pool needed is cleared at once, not at the first
    /// endpoint (J789 mutation run; an idle device may never connect one).
    #[tokio::test]
    async fn a_fresh_socket_keeps_its_port_closed() {
        let wireguard = wireguard_socket(true);
        let port = wireguard.local_addr().expect("local").port();
        for address in [
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)),
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)),
        ] {
            let other = socket2::Socket::new(
                socket2::Domain::for_address(address),
                socket2::Type::DGRAM,
                None,
            )
            .expect("socket");
            other.set_reuse_port(true).expect("SO_REUSEPORT");
            assert!(
                other.bind(&address.into()).is_err(),
                "another socket must not bind {address} beside a fresh WireGuard socket"
            );
        }
    }

    /// A receive task that is already parked reads a pool socket connected after it parked: the
    /// endpoint's replies now arrive on that socket, not on the wildcard one, so a receiver that
    /// did not poll it would miss them until some other datagram woke it (J789 mutation run).
    #[tokio::test]
    async fn a_parked_receiver_reads_a_new_connected_socket() {
        let wireguard = wireguard_socket(true);
        let port = wireguard.local_addr().expect("local").port();
        let mut receiver = wireguard.clone();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            let mut pool = PacketBufPool::new(4);
            while let Ok((packet, source)) = receiver.recv_from(&mut pool).await {
                if tx.send((packet.to_vec(), source)).is_err() {
                    break;
                }
            }
        });
        // sleep: let the receive task park on the wildcard socket before any entry exists.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let (a, a_address) = peer().await;
        send(&wireguard, &data(64), a_address).await;
        peer_recv(&a).await;
        assert_eq!(wireguard.inner.connected.len(), 1);
        a.send_to(b"reply", (Ipv4Addr::LOCALHOST, port))
            .await
            .expect("a replies");
        let received = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("the parked receiver reads the new connected socket")
            .expect("receiver alive");
        assert_eq!(received, (b"reply".to_vec(), a_address));
        task.abort();
    }

    /// A pending ICMP error on a connected socket is skipped by every receive, whichever socket
    /// the receive polls first (the first socket rotates), and never ends the receive loop
    /// (J789 mutation run: polling the wildcard socket first hid the error path).
    #[tokio::test]
    async fn an_icmp_error_never_reaches_the_receiver() {
        let mut wireguard = wireguard_socket(true);
        let port = wireguard.local_addr().expect("local").port();
        let (closed, closed_address) = peer().await;
        drop(closed);
        send(&wireguard, &data(64), closed_address).await;
        assert_eq!(wireguard.inner.connected.len(), 1);
        let (b, b_address) = peer().await;
        for round in 0..4 {
            // A fresh send whose port-unreachable report waits on the connected socket.
            send(&wireguard, &data(64), closed_address).await;
            // sleep: give the kernel time to queue the ICMP error on the connected socket.
            tokio::time::sleep(Duration::from_millis(20)).await;
            b.send_to(b"from-b", (Ipv4Addr::LOCALHOST, port))
                .await
                .expect("b sends");
            assert_eq!(
                recv(&mut wireguard).await,
                (b"from-b".to_vec(), b_address),
                "round {round}"
            );
        }
    }

    /// The send errors that mean "this socket's address or route is gone" (J763), and the ones
    /// that are a report about an earlier datagram instead (J789 mutation run).
    #[test]
    fn send_errors_are_classified() {
        let error = |code| std::io::Error::from_raw_os_error(code);
        for code in [
            libc::EADDRNOTAVAIL,
            libc::ENETUNREACH,
            libc::ENETDOWN,
            libc::EDESTADDRREQ,
        ] {
            assert!(super::is_path_error(&error(code)), "path error {code}");
            assert!(
                !super::is_icmp_error(&error(code)),
                "not an ICMP report {code}"
            );
        }
        for code in [libc::ECONNREFUSED, libc::EHOSTDOWN, libc::EHOSTUNREACH] {
            assert!(super::is_icmp_error(&error(code)), "ICMP report {code}");
            assert!(
                !super::is_path_error(&error(code)),
                "not a path error {code}"
            );
        }
        for code in [libc::ENOBUFS, libc::EAGAIN, libc::EPERM] {
            assert!(!super::is_path_error(&error(code)) && !super::is_icmp_error(&error(code)));
        }
    }

    /// The pool serves at most `POOL_SIZE` endpoints. Past it, a new endpoint takes over only an
    /// idle pool socket; when every one is busy it keeps `sendto`, and every endpoint keeps
    /// working.
    #[tokio::test]
    async fn a_full_table_evicts_only_idle_entries() {
        let wireguard = wireguard_socket(true);
        let mut peers = Vec::new();
        for _ in 0..super::POOL_SIZE {
            let (socket, address) = peer().await;
            send(&wireguard, &data(64), address).await;
            peers.push((socket, address));
        }
        assert_eq!(wireguard.inner.connected.len(), super::POOL_SIZE);
        let connects = wireguard.inner.connected.connects();

        // All sixteen are busy: a seventeenth endpoint uses `sendto` and evicts nobody.
        let (extra, extra_address) = peer().await;
        send(&wireguard, &data(64), extra_address).await;
        assert_eq!(peer_recv(&extra).await.0, data(64));
        assert_eq!(
            wireguard.inner.connected.connects(),
            connects,
            "no eviction"
        );

        // Keep only the first endpoint busy until the others count as idle.
        let (first, first_address) = &peers[0];
        for _ in 0..super::ACTIVE_SENDS {
            send(&wireguard, &data(40), *first_address).await;
            peer_recv(first).await;
        }
        send(&wireguard, &data(64), extra_address).await;
        assert_eq!(peer_recv(&extra).await.0, data(64));
        assert_eq!(wireguard.inner.connected.len(), super::POOL_SIZE);
        assert_eq!(
            wireguard.inner.connected.connects(),
            connects + 1,
            "an idle entry made room"
        );

        for (socket, _) in &peers[1..] {
            assert_eq!(
                peer_recv(socket).await.0,
                data(64),
                "each endpoint got its datagram"
            );
        }
    }

    /// Off, sends leave from the wildcard socket and no pool is bound.
    #[tokio::test]
    async fn switched_off_sends_from_the_wildcard_socket() {
        let wireguard = wireguard_socket(false);
        let (a, a_address) = peer().await;
        send(&wireguard, &data(64), a_address).await;
        assert_eq!(peer_recv(&a).await.0, data(64));
        assert_eq!(wireguard.inner.connected.len(), 0);
    }

    /// With connected sends off the WireGuard port stays closed too (J826 mutation run: setting
    /// the shared-port option before the first bind, J763's original order, survived every
    /// test, because only sockets with the pool were checked; without the pool nothing would
    /// ever clear it).
    #[tokio::test]
    async fn a_socket_without_the_pool_keeps_its_port_closed() {
        let wireguard = wireguard_socket(false);
        let port = wireguard.local_addr().expect("local").port();
        for address in [
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)),
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)),
        ] {
            let other = socket2::Socket::new(
                socket2::Domain::for_address(address),
                socket2::Type::DGRAM,
                None,
            )
            .expect("socket");
            other.set_reuse_port(true).expect("SO_REUSEPORT");
            assert!(
                other.bind(&address.into()).is_err(),
                "another socket must not bind {address} beside a WireGuard socket without a pool"
            );
        }
    }

    /// `destination` in the form the split listener records: IPv4 stays IPv4.
    fn mapped(destination: SocketAddr) -> SocketAddr {
        destination
    }

    /// A send error that says the pool socket's path is gone does not lose the datagram or
    /// fail the send: it leaves through `sendto`, and the next data re-connects the socket
    /// (J826 mutation run: ignoring path errors at the send survived, since only the error
    /// classes were tested). The path error here is `EDESTADDRREQ`, from a pool socket that was
    /// disconnected behind the table's back.
    #[tokio::test]
    async fn a_path_error_falls_back_and_reconnects() {
        use std::os::fd::AsRawFd;
        let wireguard = wireguard_socket(true);
        let (peer_socket, address) = peer().await;
        send(&wireguard, &data(64), address).await;
        peer_recv(&peer_socket).await;
        let pool = &wireguard.inner.connected;
        let index = pool
            .table
            .lock()
            .iter()
            .position(|assignment| assignment.destination == Some(mapped(address)))
            .expect("the endpoint has a pool socket");
        let connects = pool.connects();

        let unspec = libc::sockaddr {
            sa_len: std::mem::size_of::<libc::sockaddr>() as u8,
            sa_family: libc::AF_UNSPEC as libc::sa_family_t,
            sa_data: [0; 14],
        };
        // SAFETY: a valid socket descriptor and a valid `sockaddr` of the given length. xnu
        // disconnects a connected UDP socket before it looks at the new address, so the
        // socket ends up disconnected whatever this call returns.
        let _ = unsafe {
            libc::connect(
                pool.slots[index].socket.as_raw_fd(),
                &unspec,
                std::mem::size_of::<libc::sockaddr>() as libc::socklen_t,
            )
        };

        send(&wireguard, &data(65), address).await;
        assert_eq!(
            peer_recv(&peer_socket).await.0,
            data(65),
            "sent through sendto"
        );
        assert_eq!(
            pool.connects(),
            connects,
            "no re-connect in the failing send"
        );
        send(&wireguard, &data(66), address).await;
        assert_eq!(peer_recv(&peer_socket).await.0, data(66));
        assert_eq!(pool.connects(), connects + 1, "the next data re-connects");
        let assignment = pool.table.lock()[index];
        assert_eq!(
            (assignment.failures, assignment.retry_at),
            (0, None),
            "a send that works again clears the failure count"
        );
    }

    /// The pool socket serving `address`, by index.
    fn pool_index(wireguard: &UdpSocket, address: SocketAddr) -> usize {
        wireguard
            .inner
            .connected
            .table
            .lock()
            .iter()
            .position(|assignment| assignment.destination == Some(mapped(address)))
            .expect("the endpoint has a pool socket")
    }

    /// A pool socket the kernel refuses for good (`EPIPE`, what a defunct socket answers; on
    /// mba Local Network privacy made the pool's sockets defunct toward LAN peers, J1108 on
    /// #260) loses no datagram and is retired at its first failure: its descriptor no longer
    /// refers to a socket on the WireGuard port (a defunct socket left connected would swallow
    /// the peer's datagrams), the endpoint keeps `sendto` with no further connect, and only a
    /// network change lets it take another pool socket. `shutdown(SHUT_WR)` makes xnu's
    /// `sosend` answer `EPIPE` for good.
    #[tokio::test]
    async fn a_refused_pool_socket_is_retired_and_its_endpoint_uses_sendto() {
        use std::os::fd::AsRawFd;
        let mut wireguard = wireguard_socket(true);
        let port = wireguard.local_addr().expect("local").port();
        let (peer_socket, address) = peer().await;
        send(&wireguard, &data(64), address).await;
        peer_recv(&peer_socket).await;
        let pool = &wireguard.inner.connected;
        let index = pool_index(&wireguard, address);
        let connects = pool.connects();
        let fd = pool.slots[index].socket.as_raw_fd();
        // SAFETY: a valid socket descriptor this test's pool owns; shutting its sending side
        // down changes nothing but that socket.
        assert_eq!(unsafe { libc::shutdown(fd, libc::SHUT_WR) }, 0, "shutdown");

        for length in 65..90 {
            send(&wireguard, &data(length), address).await;
            assert_eq!(
                peer_recv(&peer_socket).await.0,
                data(length),
                "datagram {length} went through sendto"
            );
        }
        let pool = &wireguard.inner.connected;
        assert_eq!(pool.retirements(), 1, "retired at the first failure");
        assert_eq!(pool.connects(), connects, "never re-connected");
        assert_eq!(pool.len(), 0);
        let local = socket2::SockRef::from(&pool.slots[index].socket)
            .local_addr()
            .expect("getsockname")
            .as_socket()
            .map_or(0, |address| address.port());
        assert_ne!(
            local, port,
            "the retired descriptor is off the WireGuard port"
        );
        assert!(pool.is_enabled(), "the pool stays on for other endpoints");

        // The peer's datagrams still arrive (now on the wildcard socket).
        peer_socket
            .send_to(b"from-peer", (Ipv4Addr::LOCALHOST, port))
            .await
            .expect("peer sends");
        assert_eq!(recv(&mut wireguard).await.0, b"from-peer".to_vec());

        // A network change lets the endpoint try a live pool socket again.
        wireguard.underlay_changed();
        send(&wireguard, &data(90), address).await;
        assert_eq!(peer_recv(&peer_socket).await.0, data(90));
        let pool = &wireguard.inner.connected;
        assert_eq!(pool.connects(), connects + 1, "another pool socket");
        assert_ne!(
            pool_index(&wireguard, address),
            index,
            "never the retired one"
        );
        assert_eq!(pool.len(), 1);
    }

    /// An endpoint whose path keeps failing (`0.0.0.1`: `connect` works, every `send` answers
    /// `EHOSTUNREACH`) re-connects once at once, then backs off, so it does not cost a `connect`
    /// per datagram; the back-off ends at its deadline and at a network change (J1108).
    #[tokio::test]
    async fn a_path_that_keeps_failing_backs_off() {
        let wireguard = wireguard_socket(true);
        let nowhere = SocketAddr::from((Ipv4Addr::new(0, 0, 0, 1), 9));
        let attempt = async || {
            let _ = wireguard
                .send_to(
                    Packet::from_bytes(bytes::BytesMut::from(&data(64)[..])),
                    nowhere,
                )
                .await;
        };
        let pool = &wireguard.inner.connected;
        let connects = pool.connects();
        attempt().await;
        assert_eq!(pool.connects(), connects + 1, "the first data connects");
        attempt().await;
        assert_eq!(pool.connects(), connects + 2, "one re-connect at once");
        let index = pool_index(&wireguard, nowhere);
        let first = pool.table.lock()[index];
        assert_eq!(first.failures, 2);
        let wait = first
            .retry_at
            .expect("a second failure backs off")
            .saturating_duration_since(std::time::Instant::now());
        assert!(
            wait > super::FIRST_BACKOFF / 2 && wait <= super::FIRST_BACKOFF,
            "first back-off {wait:?}"
        );
        for _ in 0..20 {
            attempt().await;
        }
        assert_eq!(
            pool.connects(),
            connects + 2,
            "no connect during the back-off"
        );
        assert_eq!(pool.retirements(), 0, "a path error never retires");

        // The deadline passes: one more attempt, then a longer back-off.
        pool.table.lock()[index].retry_at = Some(std::time::Instant::now());
        attempt().await;
        assert_eq!(pool.connects(), connects + 3, "one retry at the deadline");
        let second = pool.table.lock()[index];
        assert_eq!(second.failures, 3);
        let wait = second
            .retry_at
            .expect("still backing off")
            .saturating_duration_since(std::time::Instant::now());
        assert!(
            wait > super::FIRST_BACKOFF && wait <= super::FIRST_BACKOFF * 2,
            "second back-off {wait:?}"
        );

        // A network change ends the back-off: the next data tries again.
        wireguard.underlay_changed();
        attempt().await;
        assert_eq!(
            pool.connects(),
            connects + 4,
            "a network change retries at once"
        );
    }

    /// Send errors that leave the socket alone (a full buffer) and the `connect` error of a
    /// defunct socket.
    #[test]
    fn full_buffers_and_defunct_sockets_are_classified() {
        let error = |code| std::io::Error::from_raw_os_error(code);
        for code in [libc::ENOBUFS, libc::ENOMEM] {
            assert!(super::is_full_buffer(&error(code)), "{code}");
        }
        assert!(!super::is_full_buffer(&error(libc::EPIPE)));
        assert!(super::is_defunct_error(&error(libc::EOPNOTSUPP)));
        assert!(!super::is_defunct_error(&error(libc::EADDRNOTAVAIL)));
    }

    /// The back-off after `n` failures in a row: none after one, then 1 s doubling to 64 s,
    /// and no overflow however long a socket keeps failing.
    #[test]
    fn the_back_off_doubles_up_to_its_cap() {
        use super::{MAX_BACKOFF, backoff};
        assert_eq!(backoff(0), None);
        assert_eq!(backoff(1), None, "the first failure re-connects at once");
        assert_eq!(backoff(2), Some(Duration::from_secs(1)));
        assert_eq!(backoff(3), Some(Duration::from_secs(2)));
        assert_eq!(backoff(8), Some(MAX_BACKOFF));
        assert_eq!(backoff(9), Some(MAX_BACKOFF));
        assert_eq!(backoff(40), Some(MAX_BACKOFF));
        assert_eq!(backoff(u32::MAX), Some(MAX_BACKOFF));
    }

    /// A sender that got a pool socket from the table, and finds it moved to another endpoint
    /// before its `send`, never sends on it (J826 mutation run: dropping that check survived,
    /// because the concurrent test below rarely lands in the gap). This test puts the move in
    /// the gap on purpose.
    #[tokio::test]
    async fn a_moved_pool_socket_never_carries_the_old_endpoints_datagram() {
        let wireguard = wireguard_socket(true);
        let (first, first_address) = peer().await;
        let (second, second_address) = peer().await;
        send(&wireguard, &data(64), first_address).await;
        peer_recv(&first).await;
        let pool = &wireguard.inner.connected;
        let index = pool
            .table
            .lock()
            .iter()
            .position(|assignment| assignment.destination == Some(mapped(first_address)))
            .expect("the first endpoint has a pool socket");

        // The move a take-over makes, between the first sender's lookup and its send.
        {
            let mut table = pool.table.lock();
            assert_eq!(
                pool.connect_slot(&mut table, index, mapped(second_address), 0),
                Some(index)
            );
        }
        assert!(matches!(
            pool.send_on(index, &data(64), mapped(first_address)).await,
            super::Sent::Fallback
        ));
        let mut buf = [0u8; 128];
        assert!(
            tokio::time::timeout(Duration::from_millis(300), second.recv_from(&mut buf))
                .await
                .is_err(),
            "the second endpoint got the first endpoint's datagram"
        );
    }

    /// A dual-stack socket bound to `[::]:port` with no `SO_REUSEPORT`, the way
    /// [`UdpSocket::bind`] binds the wildcard socket before the pool.
    fn bare_wildcard(port: u16) -> std::io::Result<(socket2::Socket, SocketAddr)> {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        socket.set_nonblocking(true)?;
        socket.set_only_v6(false)?;
        socket.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).into())?;
        let local = socket
            .local_addr()?
            .as_socket()
            .expect("an IP socket address");
        Ok((socket, local))
    }

    /// The sockets on `port` right now, from the kernel's list (the audit's own reader).
    fn port_users(port: u16) -> crate::udp::socket::macos_port_audit::PortUsers {
        crate::udp::socket::macos_port_audit::port_users(port).expect("read net.inet.udp.pcblist_n")
    }

    /// The pool is bound with the WireGuard socket and nothing binds the port after that: the
    /// kernel's count of sockets on the port stays `POOL_SIZE + 1` through new endpoints, an
    /// endpoint taking over an idle pool socket, handshakes and network changes (J815). The
    /// audit's reader also attributes every one of them to this process, which checks the
    /// record offsets it relies on.
    #[tokio::test]
    async fn the_pool_binds_once_and_never_again() {
        let wireguard = wireguard_socket(true);
        let port = wireguard.local_addr().expect("local").port();
        let check = |when: &str| {
            let users = port_users(port);
            assert_eq!(
                users.total,
                2 * (super::POOL_SIZE + 1),
                "sockets on the port {when}"
            );
            assert!(
                users.others.is_empty(),
                "only ours {when}: {:?}",
                users.others
            );
        };
        check("after bind");

        let mut peers = Vec::new();
        for _ in 0..super::POOL_SIZE + 2 {
            let (socket, address) = peer().await;
            send(&wireguard, &data(64), address).await;
            peers.push((socket, address));
        }
        check("with more endpoints than pool sockets");
        let connects = wireguard.inner.connected.connects();
        for _ in 0..super::ACTIVE_SENDS {
            send(&wireguard, &data(40), peers[0].1).await;
        }
        // The last endpoint takes over an idle pool socket.
        send(&wireguard, &data(64), peers[super::POOL_SIZE + 1].1).await;
        assert_eq!(wireguard.inner.connected.connects(), connects + 1);
        send(&wireguard, &initiation(), peers[0].1).await;
        wireguard.underlay_changed();
        for (_, address) in &peers {
            send(&wireguard, &data(64), *address).await;
        }
        check("after a take-over, a handshake and a network change");
    }

    /// Without anyone joining, the pool binds and the option ends cleared on every socket of
    /// ours, so the port is closed to everyone from then on.
    #[test]
    fn the_pool_bind_clears_the_option_everywhere() {
        let (wildcard, local) = bare_wildcard(0).expect("wildcard");
        let pool = super::bind_pool(&wildcard, local, 4).expect("pool");
        assert_eq!(pool.len(), 4);
        assert!(!wildcard.reuse_port().expect("SO_REUSEPORT"), "wildcard");
        for socket in &pool {
            assert!(!socket.reuse_port().expect("SO_REUSEPORT"), "pool socket");
            let bound = socket.local_addr().expect("local").as_socket().expect("ip");
            assert_eq!(bound.port(), local.port());
        }
    }

    /// A socket that joins the port while the pool binds is found by the audit and the pool is
    /// refused (`Joined`), so the WireGuard socket is never used beside it. The joiner here is
    /// this process (a test cannot switch users); the cross-user run is the race harness below.
    #[test]
    fn a_socket_that_joins_during_the_pool_bind_is_refused() {
        let (wildcard, local) = bare_wildcard(0).expect("wildcard");
        let mut joiner = None;
        let result = super::bind_pool_with(
            &wildcard,
            local,
            4,
            |local| {
                let other = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)
                    .expect("socket");
                other.set_reuse_port(true).expect("SO_REUSEPORT");
                other
                    .bind(&SocketAddr::from((Ipv4Addr::LOCALHOST, local.port())).into())
                    .expect("joins while the option is open");
                joiner = Some(other);
            },
            crate::udp::socket::macos_port_audit::port_users,
        );
        assert!(
            matches!(result, Err(super::PoolError::Joined(_))),
            "{result:?}"
        );
        drop(joiner);
    }

    /// A port reader for [`super::bind_pool_with`] that answers each call from `answers` in
    /// turn: `Some(n)` is a list with `n` sockets on the port, all ours; `None` a failed read.
    fn scripted_reader(
        answers: Vec<Option<usize>>,
    ) -> impl Fn(u16) -> std::io::Result<crate::udp::socket::macos_port_audit::PortUsers> {
        let answers = std::sync::Mutex::new(answers.into_iter());
        move |_| match answers.lock().expect("reader").next().flatten() {
            Some(total) => Ok(crate::udp::socket::macos_port_audit::PortUsers {
                total,
                others: Vec::new(),
            }),
            None => Err(std::io::Error::other("scripted: the list cannot be read")),
        }
    }

    /// If the kernel's list cannot be read, the pool is never bound and the option is never
    /// set (J826): nothing could prove afterwards who joined, so the window must not open. The
    /// WireGuard socket is kept as it is, with `sendto`, instead of being closed and bound again
    /// (that re-bind frees the port for a moment and is never audited).
    #[test]
    fn an_unreadable_list_opens_no_window() {
        let (wildcard, local) = bare_wildcard(0).expect("wildcard");
        let mut opened = false;
        let result = super::bind_pool_with(
            &wildcard,
            local,
            4,
            |_| opened = true,
            scripted_reader(vec![None, None]),
        );
        assert!(
            matches!(result, Err(super::PoolError::Unavailable(_))),
            "{result:?}"
        );
        assert!(!opened, "the window opened without a readable list");
        assert!(!wildcard.reuse_port().expect("SO_REUSEPORT"));
        assert_eq!(
            port_users(local.port()).total,
            1,
            "only the wildcard socket"
        );
    }

    /// A list that does not show our own wildcard socket means the reader no longer understands
    /// the kernel's records (they are private ABI). That is not someone joining: the pool stays
    /// off and the socket is kept, instead of refusing to bind on every start after an OS update
    /// (J826).
    #[test]
    fn a_list_without_our_socket_turns_the_pool_off() {
        let (wildcard, local) = bare_wildcard(0).expect("wildcard");
        let mut opened = false;
        let result = super::bind_pool_with(
            &wildcard,
            local,
            4,
            |_| opened = true,
            scripted_reader(vec![Some(0), Some(0)]),
        );
        assert!(
            matches!(result, Err(super::PoolError::Unavailable(_))),
            "{result:?}"
        );
        assert!(!opened, "the window opened although the reader is broken");
    }

    /// A list that cannot be read after the window refuses the WireGuard socket (J826): the
    /// option was open, so someone may share the port, and binding again without the pool would
    /// free the port and go unaudited. Before the window the same failure only turns the pool
    /// off.
    #[test]
    fn a_list_that_fails_after_the_window_refuses_the_socket() {
        let (wildcard, local) = bare_wildcard(0).expect("wildcard");
        let result = super::bind_pool_with(
            &wildcard,
            local,
            4,
            |_| {},
            scripted_reader(vec![Some(1), None]),
        );
        assert!(
            matches!(result, Err(super::PoolError::Unverified(_))),
            "{result:?}"
        );
        assert!(super::decide(result, local.port()).is_err(), "refused");
        let off = super::decide(
            Err(super::PoolError::Unavailable(std::io::Error::other("x"))),
            local.port(),
        )
        .expect("an unavailable pool keeps the socket");
        assert!(off.is_empty());
    }

    /// A socket that holds `0.0.0.0:<port>` with `SO_REUSEPORT` before the WireGuard socket
    /// binds is found too. xnu lets the exclusive dual-stack `[::]:<port>` bind succeed beside
    /// it, and that socket then receives the port's IPv4 datagrams (J815 probe on #260: another
    /// uid's squatter got a datagram sent to `127.0.0.1:<port>`). With connected sends on, the
    /// audit refuses the WireGuard socket instead of running beside it.
    #[tokio::test]
    async fn a_socket_already_on_the_port_is_found() {
        let squatter = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)
            .expect("socket");
        squatter.set_reuse_port(true).expect("SO_REUSEPORT");
        squatter
            .bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)).into())
            .expect("bind 0.0.0.0:0");
        let port = squatter
            .local_addr()
            .expect("local")
            .as_socket()
            .expect("ip")
            .port();
        let (wildcard, local) = bare_wildcard(port).expect("xnu binds [::] beside the squatter");
        let result = super::bind_pool(&wildcard, local, 2);
        assert!(
            matches!(result, Err(super::PoolError::Joined(_))),
            "{result:?}"
        );
        drop(wildcard);

        let opts = SockOpt {
            only_v6: Some(false),
            mac_connected: Some(true),
            ..SockOpt::default()
        };
        let error = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, port).into(), opts)
            .err()
            .expect("the WireGuard socket is refused beside the squatter");
        assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse, "{error}");
    }

    /// An IPv4 and an IPv6 endpoint each get a pool socket (a pool socket keeps the family of its
    /// first connect), each sees the WireGuard port as the source, and both replies arrive.
    #[tokio::test]
    async fn ipv4_and_ipv6_endpoints_each_get_a_pool_socket() {
        let mut wireguard = wireguard_socket(true);
        let port = wireguard.local_addr().expect("local").port();
        let (a, a_address) = peer().await;
        let b = tokio::net::UdpSocket::bind((Ipv6Addr::LOCALHOST, 0))
            .await
            .expect("bind [::1]:0");
        let b_address = b.local_addr().expect("b address");

        for _ in 0..2 {
            send(&wireguard, &data(64), a_address).await;
            send(&wireguard, &data(64), b_address).await;
            assert_eq!(peer_recv(&a).await.1.port(), port);
            assert_eq!(peer_recv(&b).await.1.port(), port);
        }
        assert_eq!(wireguard.inner.connected.len(), 2);
        assert_eq!(wireguard.inner.connected.connects(), 2);

        a.send_to(b"from-a", (Ipv4Addr::LOCALHOST, port))
            .await
            .expect("a replies");
        b.send_to(b"from-b", (Ipv6Addr::LOCALHOST, port))
            .await
            .expect("b replies");
        let mut got = vec![recv(&mut wireguard).await.0, recv(&mut wireguard).await.0];
        got.sort();
        assert_eq!(got, vec![b"from-a".to_vec(), b"from-b".to_vec()]);
    }

    /// Which pool socket a new endpoint gets: a free one of its family, then a never-used one,
    /// then the least recently used one of its family once idle for `ACTIVE_SENDS`; never one of
    /// the other family (xnu refuses that connect).
    #[test]
    fn a_pool_socket_serves_only_its_family() {
        use super::{ACTIVE_SENDS, Assignment, Family, pick};
        let somewhere = Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 9)));
        let used = |family, last_used| Assignment {
            destination: somewhere,
            family: Some(family),
            stale: false,
            last_used,
            ..Assignment::default()
        };
        let freed = |family| Assignment {
            family: Some(family),
            ..Assignment::default()
        };
        let table = [used(Family::V4, 0), freed(Family::V4), freed(Family::V6)];
        assert_eq!(
            pick(&table, Family::V6, 1),
            Some(2),
            "a free socket of the family"
        );
        assert_eq!(
            pick(&table, Family::V4, 1),
            Some(1),
            "then an unused IPv4 slot"
        );

        let table = [used(Family::V4, 0), freed(Family::V4)];
        assert_eq!(
            pick(&table, Family::V6, 5000),
            None,
            "never the other family"
        );

        let table = [used(Family::V4, 10), used(Family::V4, 5)];
        assert_eq!(
            pick(&table, Family::V4, 5 + ACTIVE_SENDS),
            Some(1),
            "idle long enough"
        );
        assert_eq!(
            pick(&table, Family::V4, 4 + ACTIVE_SENDS),
            None,
            "every one busy"
        );
        assert_eq!(
            pick(&table, Family::V6, 1 << 20),
            None,
            "idle, but the other family"
        );

        let mapped: SocketAddr = "[::ffff:192.0.2.1]:9".parse().expect("addr");
        assert_eq!(Family::of(mapped), Family::V4);
        assert_eq!(
            Family::of("[2001:db8::1]:9".parse().expect("addr")),
            Family::V6
        );
    }

    /// A datagram never leaves toward an endpoint other than its own while its pool socket moves
    /// between endpoints under concurrent senders: one pool socket, two endpoints taking it from
    /// each other, and a third task forcing re-connects. Each endpoint checks the tag of every
    /// datagram it receives.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_datagram_never_reaches_another_endpoint() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, AtomicU64, Ordering},
        };
        let wildcard = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)
            .expect("IPv4 socket");
        wildcard.set_nonblocking(true).expect("nonblocking");
        wildcard
            .bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)).into())
            .expect("bind");
        let local = wildcard
            .local_addr()
            .expect("local")
            .as_socket()
            .expect("IP socket");
        let pool = super::bind_pool(&wildcard, local, 1).expect("pool");
        let sends = Arc::new(super::ConnectedSends::new(pool).expect("pool sockets"));
        let wildcard =
            Arc::new(tokio::net::UdpSocket::from_std(wildcard.into()).expect("wildcard socket"));
        let done = Arc::new(AtomicBool::new(false));
        let wrong = Arc::new(AtomicU64::new(0));

        let mut senders = Vec::new();
        let mut drains = Vec::new();
        for tag in [b'A', b'B'] {
            let (socket, address) = peer().await;
            let destination = address;
            let (done, wrong) = (Arc::clone(&done), Arc::clone(&wrong));
            drains.push(tokio::spawn(async move {
                let mut buf = [0u8; 128];
                while !done.load(Ordering::Relaxed) {
                    if let Ok(Ok((n, _))) =
                        tokio::time::timeout(Duration::from_millis(50), socket.recv_from(&mut buf))
                            .await
                        && (n < 2 || buf[1] != tag)
                    {
                        wrong.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }));
            let (sends, wildcard) = (Arc::clone(&sends), Arc::clone(&wildcard));
            senders.push(tokio::spawn(async move {
                let mut payload = data(64);
                payload[1] = tag;
                for _ in 0..12 {
                    // A burst long enough that the other endpoint's socket counts as idle.
                    for _ in 0..super::ACTIVE_SENDS + 64 {
                        let _ = sends.send(&wildcard, &payload, destination).await;
                    }
                    tokio::task::yield_now().await;
                }
            }));
        }
        let churn = {
            let (sends, done) = (Arc::clone(&sends), Arc::clone(&done));
            tokio::spawn(async move {
                while !done.load(Ordering::Relaxed) {
                    sends.underlay_changed();
                    // sleep: pace the existing concurrent reconnect stress while senders run.
                    tokio::time::sleep(Duration::from_micros(200)).await;
                }
            })
        };
        for sender in senders {
            sender.await.expect("sender");
        }
        done.store(true, Ordering::Relaxed);
        churn.await.expect("churn");
        for drain in drains {
            drain.await.expect("drain");
        }
        assert_eq!(
            wrong.load(Ordering::Relaxed),
            0,
            "datagrams at the wrong endpoint"
        );
        assert!(sends.connects() >= 2, "the pool socket moved at least once");
    }

    /// Nothing binds the WireGuard port after the WireGuard socket itself (J815): every bind
    /// beside it needs `SO_REUSEPORT` open on our sockets for a moment, and J789 showed another
    /// local user wins that moment. So the kernel's count of sockets on the port right after the
    /// bind must still hold after new endpoints, handshakes and a network change.
    #[tokio::test]
    async fn the_port_gets_no_new_sockets_after_bind() {
        let wireguard = wireguard_socket(true);
        let port = wireguard.local_addr().expect("local").port();
        let count = || {
            crate::udp::socket::macos_port_audit::port_users(port)
                .expect("read net.inet.udp.pcblist_n")
                .total
        };
        let at_bind = count();
        let mut peers = Vec::new();
        for _ in 0..3 {
            let (socket, address) = peer().await;
            send(&wireguard, &data(64), address).await;
            peers.push((socket, address));
        }
        send(&wireguard, &initiation(), peers[0].1).await;
        wireguard.underlay_changed();
        for (_, address) in &peers {
            send(&wireguard, &data(64), *address).await;
        }
        assert_eq!(count(), at_bind, "sockets on the port since the bind");
    }

    /// Read and drop everything queued on a peer socket. The harness's peers must drain what
    /// they receive: undrained receive buffers exhaust the Mac's network memory, and xnu's mbuf
    /// watchdog then defuncts every socket of the process holding the most mbufs (J815: this
    /// harness, connected sends on or off alike; `netstat -m` "requests for memory denied").
    fn drain(socket: &tokio::net::UdpSocket) {
        let mut buf = [0u8; 256];
        while socket.try_recv_from(&mut buf).is_ok() {}
    }

    /// The harness's send: counts an error instead of panicking, and prints the pool's state for
    /// the first few so a failure can be read from the log.
    async fn harness_send(
        socket: &UdpSocket,
        payload: &[u8],
        to: SocketAddr,
        errors: &mut std::collections::BTreeMap<String, u64>,
    ) {
        let result = socket
            .send_to(Packet::from_bytes(bytes::BytesMut::from(payload)), to)
            .await;
        if let Err(error) = result {
            let count = errors.entry(error.to_string()).or_default();
            *count += 1;
            if *count <= 3 {
                let pool = &socket.inner.connected;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default();
                eprintln!(
                    "send to {to} ({} bytes) at unix {:.3}: {error}",
                    payload.len(),
                    now.as_secs_f64()
                );
                for (index, (slot, assignment)) in
                    pool.slots.iter().zip(pool.table.lock().iter()).enumerate()
                {
                    let raw = socket2::SockRef::from(&slot.socket);
                    eprintln!(
                        "  slot {index}: {assignment:?} peer-lock {:?} kernel local {:?} peer {:?}",
                        *slot.peer.read(),
                        raw.local_addr().ok().and_then(|a| a.as_socket()),
                        raw.peer_addr().ok().and_then(|a| a.as_socket()),
                    );
                }
            }
        }
    }

    /// J815 race harness (#260): run by hand **as root** while another uid loops `bind` on the
    /// port (`tools/macos-port-race/run-race.sh` drives both). Environment: `J815_PORT`,
    /// `J815_SECS` (default 70) and `J815_MODE`:
    /// - `steady`: bind once, then for the whole run move pool sockets between 24 endpoints
    ///   (v4 and v6), re-connect after handshakes and network changes, and check that each
    ///   endpoint's reply to our port arrives and that the kernel counts only our sockets on it;
    /// - `restart`: bind, check, close and bind again in a loop, so the attacker also races
    ///   every pool bind window. A bind that succeeds while a socket of someone else is on the
    ///   port (a silent share) must never happen.
    ///
    /// Prints one `J815 holder` line with the counts.
    #[tokio::test]
    #[ignore = "J815 cross-user race harness; run by hand as root beside attacker.pl"]
    async fn j815_race_holder() {
        let port: u16 = std::env::var("J815_PORT")
            .expect("J815_PORT")
            .parse()
            .expect("port");
        let secs: u64 = std::env::var("J815_SECS")
            .unwrap_or_else(|_| "70".into())
            .parse()
            .expect("secs");
        let mode = std::env::var("J815_MODE").unwrap_or_else(|_| "steady".into());
        // `J815_CONNECTED=0` runs the same load with connected sends off (the control).
        let connected = std::env::var("J815_CONNECTED").map_or(true, |value| value != "0");
        let ours = if connected {
            2 * (super::POOL_SIZE + 1)
        } else {
            2
        };
        let opts = SockOpt {
            only_v6: Some(false),
            mac_connected: Some(connected),
            ..SockOpt::default()
        };
        let started = std::time::Instant::now();
        let running = || started.elapsed() < Duration::from_secs(secs);
        let mut pool = PacketBufPool::new(8);

        if mode == "restart" {
            let (mut ok, mut joined, mut squatted, mut other) = (0u64, 0u64, 0u64, 0u64);
            let (mut lost, mut shared) = (0u64, 0u64);
            let probe = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("probe");
            while running() {
                match UdpSocket::bind((Ipv6Addr::UNSPECIFIED, port).into(), opts) {
                    Ok(mut wireguard) => {
                        ok += 1;
                        if port_users(port).total != ours {
                            shared += 1;
                        }
                        for _ in 0..3 {
                            probe
                                .send_to(b"probe", (Ipv4Addr::LOCALHOST, port))
                                .await
                                .expect("probe send");
                            let got = tokio::time::timeout(
                                Duration::from_millis(100),
                                wireguard.recv_from(&mut pool),
                            )
                            .await;
                            if !matches!(got, Ok(Ok(_))) {
                                lost += 1;
                            }
                        }
                    }
                    Err(error) if error.to_string().contains("share UDP port") => joined += 1,
                    Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => squatted += 1,
                    Err(error) => {
                        other += 1;
                        eprintln!("bind: {error}");
                    }
                }
            }
            println!(
                "J815 holder mode=restart secs={secs} binds_ok={ok} silent_shares={shared} \
                 lost_probes={lost} refused_joined={joined} refused_squatted={squatted} \
                 other_errors={other}"
            );
            return;
        }

        let mut wireguard =
            UdpSocket::bind((Ipv6Addr::UNSPECIFIED, port).into(), opts).expect("bind the port");
        let mut peers = Vec::new();
        for index in 0..24 {
            let (socket, ours_at): (tokio::net::UdpSocket, SocketAddr) = if index % 6 == 5 {
                let socket = tokio::net::UdpSocket::bind((Ipv6Addr::LOCALHOST, 0))
                    .await
                    .expect("v6 peer");
                (socket, (Ipv6Addr::LOCALHOST, port).into())
            } else {
                (peer().await.0, (Ipv4Addr::LOCALHOST, port).into())
            };
            let address = socket.local_addr().expect("peer address");
            peers.push((socket, address, ours_at));
        }
        let (mut rounds, mut lost, mut audits, mut foreign) = (0u64, 0u64, 0u64, 0u64);
        let mut errors = std::collections::BTreeMap::new();
        let mut phase = 0usize;
        while running() {
            // A burst to one endpoint leaves the others idle, so the next round moves pool
            // sockets between endpoints; every 3rd phase is a network change, and every 7th
            // round a handshake, both of which re-connect.
            let (_, hot, _) = &peers[phase % peers.len()];
            for _ in 0..=super::ACTIVE_SENDS {
                harness_send(&wireguard, &data(48), *hot, &mut errors).await;
            }
            drain(&peers[phase % peers.len()].0);
            if phase.is_multiple_of(3) {
                wireguard.underlay_changed();
            }
            for (index, (socket, address, ours_at)) in peers.iter().enumerate() {
                if (rounds + index as u64).is_multiple_of(7) {
                    harness_send(&wireguard, &initiation(), *address, &mut errors).await;
                }
                harness_send(&wireguard, &data(64), *address, &mut errors).await;
                drain(socket);
                let tag = rounds.to_be_bytes();
                if let Err(error) = socket.send_to(&tag, *ours_at).await {
                    *errors.entry(format!("peer reply: {error}")).or_default() += 1;
                }
                let deadline = tokio::time::Instant::now() + Duration::from_millis(200);
                let arrived = loop {
                    match tokio::time::timeout_at(deadline, wireguard.recv_from(&mut pool)).await {
                        Ok(Ok((packet, _))) if packet[..] == tag => break true,
                        Ok(Ok(_)) => continue,
                        _ => break false,
                    }
                };
                lost += u64::from(!arrived);
                rounds += 1;
            }
            let users = port_users(port);
            audits += 1;
            if users.total != ours || !users.others.is_empty() {
                foreign += 1;
                eprintln!("audit: {users:?}");
            }
            phase += 1;
        }
        println!(
            "J815 holder mode=steady connected={connected} secs={secs} rounds={rounds} connects={} lost_replies={lost} \
             audits={audits} audits_with_foreign_sockets={foreign} send_errors={errors:?}",
            wireguard.inner.connected.connects()
        );
    }

    /// The numbers of every datagram `socket` receives within `wait` of the last one.
    async fn numbers_received(socket: &tokio::net::UdpSocket, wait: Duration) -> Vec<u32> {
        let mut buf = [0u8; 2048];
        let mut numbers = Vec::new();
        while let Ok(Ok((n, _))) = tokio::time::timeout(wait, socket.recv_from(&mut buf)).await {
            assert!(n >= 8);
            numbers.push(u32::from_be_bytes(buf[4..8].try_into().expect("4 bytes")));
        }
        numbers
    }

    /// Data runs through `send_many_to`, with connected sends on and off: every datagram reaches
    /// its own endpoint exactly once and in order, also when a run mixes two endpoints and a
    /// handshake message, and whatever batching policy this process runs with.
    #[tokio::test]
    async fn batched_runs_reach_each_endpoint_once_and_in_order() {
        for connected in [false, true] {
            let wireguard = wireguard_socket(connected);
            let (a, a_address) = peer().await;
            let (b, b_address) = peer().await;
            for socket in [&a, &b] {
                socket2::SockRef::from(socket)
                    .set_recv_buffer_size(4 << 20)
                    .expect("SO_RCVBUF");
            }
            let max = wireguard.max_number_of_packets_to_send();
            let mut next = [0u32; 2];
            let mut expected = [Vec::new(), Vec::new()];
            for round in 0..20 {
                let mut packets = Vec::new();
                for i in 0..max {
                    // Mostly A, a few B, one handshake in the middle of some runs.
                    let (who, to) = if i % 7 == 3 {
                        (1, b_address)
                    } else {
                        (0, a_address)
                    };
                    let mut payload = if round % 3 == 0 && i == max / 2 {
                        initiation()
                    } else {
                        data(200)
                    };
                    payload[4..8].copy_from_slice(&next[who].to_be_bytes());
                    expected[who].push(next[who]);
                    next[who] += 1;
                    packets.push((Packet::from_bytes(bytes::BytesMut::from(&payload[..])), to));
                }
                let mut send_buf = ();
                wireguard
                    .send_many_to(&mut send_buf, &mut packets)
                    .await
                    .expect("send_many_to");
                assert!(packets.is_empty());
            }
            let got_a = numbers_received(&a, Duration::from_millis(300)).await;
            let got_b = numbers_received(&b, Duration::from_millis(300)).await;
            assert_eq!(got_a, expected[0], "connected={connected}, batch {max}");
            assert_eq!(got_b, expected[1], "connected={connected}, batch {max}");
        }
    }

    /// A pool socket that moved to another endpoint between the table lookup and a batched
    /// send never carries the run: the run leaves through the wildcard socket instead, all of
    /// it, once, and the other endpoint sees none of it.
    #[tokio::test]
    async fn a_moved_pool_socket_never_carries_a_batched_run() {
        let wireguard = wireguard_socket(true);
        let (first, first_address) = peer().await;
        let (second, second_address) = peer().await;
        send(&wireguard, &data(64), first_address).await;
        peer_recv(&first).await;
        let pool = &wireguard.inner.connected;
        let index = pool
            .table
            .lock()
            .iter()
            .position(|assignment| assignment.destination == Some(mapped(first_address)))
            .expect("the first endpoint has a pool socket");
        // Connect the socket to the second endpoint behind the table's back: the table still
        // hands it out for the first one.
        *pool.slots[index].peer.write() = Some(mapped(second_address));
        socket2::SockRef::from(&pool.slots[index].socket)
            .connect(&mapped(second_address).into())
            .expect("connect");
        let payloads: Vec<Vec<u8>> = (0..10u32)
            .map(|i| {
                let mut p = data(200);
                p[4..8].copy_from_slice(&i.to_be_bytes());
                p
            })
            .collect();
        let (wildcard, routed) = wireguard.route(first_address);
        let run: Vec<(&[u8], SocketAddr)> = payloads.iter().map(|p| (&p[..], routed)).collect();
        pool.send_batch(wildcard, &run).await.expect("send_batch");
        assert_eq!(
            numbers_received(&first, Duration::from_millis(300)).await,
            (0..10).collect::<Vec<_>>()
        );
        let mut buf = [0u8; 256];
        assert!(
            tokio::time::timeout(Duration::from_millis(300), second.recv_from(&mut buf))
                .await
                .is_err(),
            "the second endpoint got the first endpoint's datagrams"
        );
    }

    /// A pool socket whose sends fail with an errno the pool has no class for (`EPIPE` from
    /// `shutdown(SHUT_WR)`, as macOS 27.2.1 returned toward the LAN, J1028/J1036) loses no
    /// datagram of a batched run: the whole run arrives once and in order through the wildcard
    /// socket, the socket is retired once, and later runs go straight to the wildcard socket
    /// (J1108).
    #[tokio::test]
    async fn a_failing_pool_socket_loses_no_batched_run() {
        use std::os::fd::AsRawFd;
        let wireguard = wireguard_socket(true);
        let (peer_socket, address) = peer().await;
        send(&wireguard, &data(64), address).await;
        peer_recv(&peer_socket).await;
        let pool = &wireguard.inner.connected;
        let index = pool
            .table
            .lock()
            .iter()
            .position(|assignment| assignment.destination == Some(mapped(address)))
            .expect("the endpoint has a pool socket");
        // SAFETY: a valid socket descriptor this test's pool owns; shutting its sending side
        // down changes nothing but that socket.
        assert_eq!(
            unsafe { libc::shutdown(pool.slots[index].socket.as_raw_fd(), libc::SHUT_WR) },
            0
        );
        let connects = pool.connects();
        let mut next = 0u32;
        for round in 0..2 {
            let payloads: Vec<Vec<u8>> = (0..10u32)
                .map(|i| {
                    let mut p = data(200);
                    p[4..8].copy_from_slice(&(next + i).to_be_bytes());
                    p
                })
                .collect();
            let (wildcard, routed) = wireguard.route(address);
            let run: Vec<(&[u8], SocketAddr)> = payloads.iter().map(|p| (&p[..], routed)).collect();
            pool.send_batch(wildcard, &run).await.expect("send_batch");
            assert_eq!(
                numbers_received(&peer_socket, Duration::from_millis(300)).await,
                (next..next + 10).collect::<Vec<_>>(),
                "run {round}"
            );
            next += 10;
            assert_eq!(pool.retirements(), 1, "run {round}: retired once");
            assert_eq!(pool.connects(), connects, "run {round}: no re-connect");
        }
    }

    /// Batched data to an endpoint whose port is closed: the ICMP errors the connected socket
    /// reports neither stop later runs nor reach the caller as a fatal error, and data to a
    /// live endpoint in the same and later runs still arrives in full and in order.
    #[tokio::test]
    async fn icmp_errors_mid_batch_do_not_stop_other_endpoints() {
        let wireguard = wireguard_socket(true);
        let (closed, closed_address) = peer().await;
        drop(closed);
        let (live, live_address) = peer().await;
        socket2::SockRef::from(&live)
            .set_recv_buffer_size(4 << 20)
            .expect("SO_RCVBUF");
        let mut sent = 0u32;
        for _ in 0..10 {
            let mut packets = Vec::new();
            for i in 0..wireguard.max_number_of_packets_to_send() {
                let mut payload = data(200);
                let to = if i % 2 == 0 {
                    closed_address
                } else {
                    payload[4..8].copy_from_slice(&sent.to_be_bytes());
                    sent += 1;
                    live_address
                };
                packets.push((Packet::from_bytes(bytes::BytesMut::from(&payload[..])), to));
            }
            let result = wireguard.send_many_to(&mut (), &mut packets).await;
            if let Err(error) = result {
                assert!(
                    !crate::udp::is_fatal_udp_error(&error),
                    "a closed port is not fatal: {error}"
                );
            }
            // sleep: let the ICMP port-unreachable replies come back between runs.
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(
            numbers_received(&live, Duration::from_millis(300)).await,
            (0..sent).collect::<Vec<_>>()
        );
    }

    /// The batched receive reads the wildcard socket and the pool sockets: replies that the
    /// kernel delivers to a connected pool socket and datagrams from an endpoint without one
    /// both arrive, with their sources, in calls of more than one datagram where batching is on.
    #[tokio::test]
    async fn the_batched_receive_reads_pool_and_wildcard_sockets() {
        for connected in [false, true] {
            let mut wireguard = wireguard_socket(connected);
            let port = wireguard.local_addr().expect("local").port();
            let to = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
            let (a, a_address) = peer().await;
            let (b, b_address) = peer().await;
            // A gets a pool socket (with connected sends on); B never receives data from us.
            send(&wireguard, &data(64), a_address).await;
            peer_recv(&a).await;
            for i in 0..100u32 {
                let mut p = data(100);
                p[4..8].copy_from_slice(&i.to_be_bytes());
                a.send_to(&p, to).await.expect("a sends");
                b.send_to(&p, to).await.expect("b sends");
            }
            let mut pool = PacketBufPool::new(256);
            let mut recv_buf = Default::default();
            let mut packets = Vec::new();
            let mut calls = 0;
            while packets.len() < 200 {
                calls += 1;
                tokio::time::timeout(
                    Duration::from_secs(5),
                    wireguard.recv_many_from(&mut recv_buf, &mut pool, &mut packets),
                )
                .await
                .expect("datagrams within 5 s")
                .expect("receive");
            }
            assert_eq!(packets.len(), 200, "connected={connected}");
            for (address, name) in [(a_address, "a"), (b_address, "b")] {
                let numbers: Vec<u32> = packets
                    .iter()
                    .filter(|(_, source)| mapped(*source) == mapped(address))
                    .map(|(p, _)| u32::from_be_bytes(p[4..8].try_into().expect("4 bytes")))
                    .collect();
                assert_eq!(
                    numbers,
                    (0..100).collect::<Vec<_>>(),
                    "{name}, connected={connected}"
                );
            }
            if super::super::macos_batch::policy().recv {
                assert!(
                    calls < 200,
                    "connected={connected}: one datagram per call ({calls})"
                );
            }
        }
    }
}
