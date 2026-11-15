// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

//! Connected per-endpoint send sockets for macOS (#260, J744, J763).
//!
//! **Why.** On macOS a `sendto` on an unconnected socket bound to the wildcard address costs
//! about 14 µs of kernel time per datagram on our Mac VM, because xnu re-decides the route and
//! the network policy for every datagram. A socket with a fixed 4-tuple (a *connected* socket)
//! keeps that decision, and the same `send` costs about 2 µs (J744 microbench, #260). The Mac's
//! single device runtime spends about half its time in `sendto` under load (J728), so this is the
//! largest per-datagram cost on the Mac send path. The private batch call `sendmsg_x` saves only
//! about 3% on the same socket, so no private API is used here.
//!
//! **How.** The WireGuard socket keeps its wildcard bind. The first data datagram to an endpoint
//! creates one more socket bound to the same address and port and connected to that endpoint;
//! later datagrams to it use `send` on that socket. The kernel delivers an arriving datagram to
//! the most specific matching socket, so the endpoint's replies now land on its connected socket
//! rather than the wildcard one: the receive side therefore reads every connected socket as well
//! as the wildcard socket.
//!
//! **Sharing the port without opening it to others.** Two sockets can bind one port only while
//! `SO_REUSEPORT` is set on the sockets already there. On macOS that check has no same-user rule:
//! J763 measured on macOS 26.5.2 that while our port carries the option, a process of *any* user
//! can bind it too, including a specific address such as `127.0.0.1:<port>`, which then wins the
//! delivery of every datagram sent to that address. So the option is set only for the moment a
//! socket of ours binds and is cleared on every socket of ours right after
//! ([`ReusePortWindow`]). With it cleared, other users' binds are refused exactly as they are
//! without this feature (`EADDRINUSE`, same probe), and root can bind a specific address either
//! way. What remains is the window itself: a few system calls each time a connected socket is
//! created, which happens on the first data to an endpoint, after a network change and after a
//! handshake initiation (about every two minutes per active endpoint).
//!
//! **A stale source.** `connect` fixes the source address the route chose at that moment, and
//! xnu keeps it. If the network changes, the socket would keep sending from the old address:
//! still working while that address and its path live, a black hole when the path is gone but the
//! address is not. Three things replace an entry, none of them a timer (D81):
//! - [`ConnectedSends::underlay_changed`]: the owner's network-change signal (the product's
//!   macOS routing-socket listener) closes every connected socket at once, so the next datagram
//!   reconnects on the current route and source.
//! - A send error that says the path is gone (`EADDRNOTAVAIL` once the source address left the
//!   host, `ENETUNREACH`, `ENETDOWN`; `EHOSTUNREACH` after one retry, since it can also be a
//!   stale ICMP report) drops the entry, and that datagram leaves through `sendto` in the same
//!   call.
//! - Every message that is not data (handshake messages, cookie replies and keepalives) drops
//!   its endpoint's entry and leaves through `sendto`, which picks the current source. A Mac that
//!   sends data starts a handshake after 15 s without a reply (and retries every 5 s); an idle or
//!   receive-only Mac sends a keepalive at least every persistent-keepalive interval. So even an
//!   unsignalled, error-free stale path ends at the protocol's own recovery point, and the peer
//!   then roams to the current source. Keepalives matter as much as initiations here (J789):
//!   a Mac that sends no data never initiates, so if its keepalives rode the stale socket, the
//!   peer's endpoint for it would stay on the dead path until the session expired (180 s).
//!
//! **Bounded.** At most [`MAX_CONNECTED`] endpoints hold a connected socket (one file descriptor
//! and one reactor registration each). Keepalives, handshake messages and cookie replies never
//! create one; only data does, so a large mostly-idle mesh does not churn sockets. When the table
//! is full, the least recently used entry makes room only if it has been idle for at least
//! [`ACTIVE_SENDS`] data sends; when all of them are busier than that, the new endpoint keeps using
//! `sendto` (today's path, ~14 µs per datagram) instead of evicting a busy one, so more than
//! sixteen busy endpoints never thrash socket creation.
//!
//! **Other invariants.**
//! - A connected socket reports ICMP errors (`ECONNREFUSED` and friends) on its next call. On
//!   receive they are skipped; on send the datagram is retried once.
//! - A failure to share the port turns the feature off for this socket and logs once, so a host
//!   that refuses it keeps the old path. A failure to *connect* (no route right now) does not:
//!   that datagram uses `sendto` and the next one tries again.
//! - Datagrams still queued on a closed entry are lost, which WireGuard tolerates.
//!
//! On by default on macOS. `GOTATUN_BENCH_MAC_CONNECTED=0` turns it off for diagnosis.

use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc, OnceLock, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
};

use futures::task::AtomicWaker;
use parking_lot::Mutex;
use tokio::io::ReadBuf;

use crate::packet::WgPacketType;

/// The most endpoints that get their own connected socket.
///
/// A device usually talks to a handful of endpoints at once; each entry is one file descriptor
/// and one reactor registration, and every receive poll visits each entry.
pub(crate) const MAX_CONNECTED: usize = 16;

/// An entry used within this many sends (to any endpoint) counts as busy and is never evicted
/// to make room for a new endpoint.
pub(crate) const ACTIVE_SENDS: u64 = 1024;

/// The size of a WireGuard keepalive: a data header and an empty, authenticated payload.
/// Datagrams this small or smaller never use a connected socket.
const KEEPALIVE_LEN: usize = 32;

/// Whether the switch's value turns connected sends on: anything but `0` (or no value) does.
pub(crate) fn switch_on(value: Option<&str>) -> bool {
    value.is_none_or(|value| value.trim() != "0")
}

/// Whether connected sends are on for this process: on unless `GOTATUN_BENCH_MAC_CONNECTED=0`.
pub(crate) fn wanted() -> bool {
    static WANTED: OnceLock<bool> = OnceLock::new();
    *WANTED.get_or_init(|| {
        let on = switch_on(std::env::var("GOTATUN_BENCH_MAC_CONNECTED").ok().as_deref());
        if !on {
            eprintln!("diag mac_connected off (GOTATUN_BENCH_MAC_CONNECTED=0)");
        }
        on
    })
}

/// One endpoint's connected socket.
struct Entry {
    /// The endpoint, in the form the wildcard socket sends to (v4-mapped on a dual-stack socket).
    destination: SocketAddr,
    /// A socket bound to the WireGuard address and port and connected to `destination`.
    socket: tokio::net::UdpSocket,
    /// The table's send counter at this entry's last send, for least-recently-used eviction.
    last_used: AtomicU64,
}

/// The connected sockets of one WireGuard socket, shared by all of its clones.
pub(crate) struct ConnectedSends {
    /// Cleared for good after the port could not be shared.
    enabled: AtomicBool,
    /// The current entries, oldest first.
    entries: Mutex<Vec<Arc<Entry>>>,
    /// Bumped whenever `entries` changes, so a receiver refreshes its copy only then.
    generation: AtomicU64,
    /// Counts sends through [`ConnectedSends::send`]; entries record it as their last use.
    sends: AtomicU64,
    /// How many connected sockets were ever created (tests and diagnostics).
    connects: AtomicU64,
    /// The receive task waiting on the current entries; woken when a new entry appears so it
    /// starts polling that socket too.
    receiver: AtomicWaker,
}

/// A receiver's copy of the entries plus where its next round of polls starts.
///
/// The copy holds weak references: the table alone owns each socket, so removing an entry closes
/// its socket at once even while a receive task is parked on it. Otherwise the old socket would
/// stay open until the receiver next ran, and a reconnect to the same endpoint over the same
/// route would collide with it (one connected socket per 4-tuple).
#[derive(Clone, Default)]
pub(crate) struct RecvView {
    /// The `generation` that `entries` was copied at.
    generation: u64,
    /// The connected sockets this receiver polls after the wildcard socket.
    entries: Vec<Weak<Entry>>,
    /// Rotates the first socket polled, so one busy endpoint cannot starve the others.
    next: usize,
}

impl ConnectedSends {
    /// A table for a socket on which connected sends are (`enabled`) or are not wanted.
    pub(crate) fn new(enabled: bool) -> Self {
        Self {
            enabled: AtomicBool::new(enabled),
            entries: Mutex::new(Vec::with_capacity(if enabled { MAX_CONNECTED } else { 0 })),
            generation: AtomicU64::new(0),
            sends: AtomicU64::new(0),
            connects: AtomicU64::new(0),
            receiver: AtomicWaker::new(),
        }
    }

    /// How many endpoints have a connected socket right now.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.lock().len()
    }

    /// How many connected sockets this table has created so far.
    #[cfg(test)]
    pub(crate) fn connects(&self) -> u64 {
        self.connects.load(Ordering::Relaxed)
    }

    /// Whether connected sends are still on for this socket.
    #[cfg(test)]
    pub(crate) fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// The host's network changed: close every connected socket.
    ///
    /// Each one keeps the source address and route chosen when it connected, which may be gone
    /// now. The next data datagram to each endpoint reconnects on the current route. Call this
    /// from the owner's network-change signal, before asking sessions to announce themselves.
    pub(crate) fn underlay_changed(&self) {
        let mut entries = self.entries.lock();
        if entries.is_empty() {
            return;
        }
        let closed = entries.len();
        entries.clear();
        drop(entries);
        self.changed();
        tracing::debug!("macOS UDP: network changed; closed {closed} connected sockets");
    }

    /// Send `payload` to `destination` (already mapped for the wildcard socket).
    ///
    /// Data uses the endpoint's connected socket, creating it first if the table allows it.
    /// Everything else (handshake messages, cookie replies, keepalives) closes the endpoint's
    /// connected socket and leaves through `sendto`, so it picks the current source; the next data
    /// reconnects after it. Data also falls back to `sendto` whenever no connected socket can be
    /// used.
    pub(crate) async fn send(
        &self,
        wildcard: &tokio::net::UdpSocket,
        payload: &[u8],
        destination: SocketAddr,
    ) -> io::Result<()> {
        if self.enabled.load(Ordering::Relaxed) {
            if !carries_data(payload) {
                // `sendto` picks the current source; the next data reconnects after it.
                self.forget_destination(destination);
            } else if let Some(entry) = self.entry_for(wildcard, destination) {
                match entry.socket.send(payload).await {
                    Ok(_) => return Ok(()),
                    // A pending ICMP error is reported once and cleared; the datagram was not
                    // sent.
                    Err(error) if is_icmp_error(&error) => match entry.socket.send(payload).await {
                        Ok(_) => return Ok(()),
                        Err(error) => self.forget(&entry, &error),
                    },
                    Err(error) if is_path_error(&error) => self.forget(&entry, &error),
                    Err(error) => return Err(error),
                }
            }
        }
        wildcard.send_to(payload, destination).await.map(|_| ())
    }

    /// Receive one datagram from the wildcard socket or any connected socket.
    ///
    /// Errors from the wildcard socket are returned as before. ICMP errors that a connected
    /// socket reports are skipped: they belong to an earlier send, not to this receive.
    pub(crate) fn poll_recv(
        &self,
        wildcard: &tokio::net::UdpSocket,
        view: &mut RecvView,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        if !self.enabled.load(Ordering::Relaxed) && view.entries.is_empty() {
            return poll_one(wildcard, cx, buf);
        }
        // Register before reading the generation: an entry added after this point wakes us.
        self.receiver.register(cx.waker());
        let generation = self.generation.load(Ordering::Acquire);
        if generation != view.generation {
            view.entries = self.entries.lock().iter().map(Arc::downgrade).collect();
            view.generation = generation;
        }

        let count = view.entries.len() + 1;
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
            // Gone since the copy was made: its removal bumped the generation and woke us.
            let Some(entry) = view.entries[index - 1].upgrade() else {
                continue;
            };
            loop {
                match poll_one(&entry.socket, cx, buf) {
                    Poll::Ready(Err(error)) if is_icmp_error(&error) => continue,
                    // Any other error stays with this endpoint's socket; the wildcard socket
                    // and the other endpoints keep receiving.
                    Poll::Ready(Err(error)) => {
                        tracing::debug!("macOS UDP: connected receive error ({error})");
                        break;
                    }
                    Poll::Ready(ok) => return Poll::Ready(ok),
                    Poll::Pending => break,
                }
            }
        }
        Poll::Pending
    }

    /// The connected socket for `destination`, created on first use when the table has room for
    /// it. Only called for data ([`carries_data`]).
    fn entry_for(
        &self,
        wildcard: &tokio::net::UdpSocket,
        destination: SocketAddr,
    ) -> Option<Arc<Entry>> {
        let now = self.sends.fetch_add(1, Ordering::Relaxed);
        let mut entries = self.entries.lock();
        if let Some(entry) = entries
            .iter()
            .find(|entry| entry.destination == destination)
        {
            entry.last_used.store(now, Ordering::Relaxed);
            return Some(Arc::clone(entry));
        }
        let evict = if entries.len() < MAX_CONNECTED {
            None
        } else {
            let (index, idle) = entries
                .iter()
                .enumerate()
                .map(|(index, entry)| {
                    (
                        index,
                        now.saturating_sub(entry.last_used.load(Ordering::Relaxed)),
                    )
                })
                .max_by_key(|&(_, idle)| idle)?;
            if idle < ACTIVE_SENDS {
                // Every entry is busy: this endpoint keeps `sendto` rather than evict one.
                return None;
            }
            Some(index)
        };
        if let Some(index) = evict {
            entries.remove(index);
        }
        let socket = match connect(wildcard, &entries, destination) {
            Ok(socket) => socket,
            Err(ConnectError::Route(error)) => {
                tracing::debug!(
                    "macOS UDP: no connected socket to {destination} for now ({error}); using sendto"
                );
                if evict.is_some() {
                    drop(entries);
                    self.changed();
                }
                return None;
            }
            Err(ConnectError::Shared(error)) => {
                if self.enabled.swap(false, Ordering::Relaxed) {
                    tracing::warn!(
                        "macOS UDP: cannot share the WireGuard port for connected sends ({error}); \
                         using sendto"
                    );
                }
                if evict.is_some() {
                    drop(entries);
                    self.changed();
                }
                return None;
            }
        };
        self.connects.fetch_add(1, Ordering::Relaxed);
        let entry = Arc::new(Entry {
            destination,
            socket,
            last_used: AtomicU64::new(now),
        });
        entries.push(Arc::clone(&entry));
        drop(entries);
        self.changed();
        Some(entry)
    }

    /// Drop `entry` after a send error that says its path is gone; the next send reconnects.
    fn forget(&self, entry: &Arc<Entry>, error: &io::Error) {
        tracing::debug!(
            "macOS UDP: dropping the connected socket to {} ({error})",
            entry.destination
        );
        self.remove_where(|other| Arc::ptr_eq(other, entry));
    }

    /// Drop the entry for `destination`, if there is one.
    fn forget_destination(&self, destination: SocketAddr) {
        self.remove_where(|other| other.destination == destination);
    }

    /// Remove the entries `matches` selects and tell receivers when anything went.
    fn remove_where(&self, matches: impl Fn(&Arc<Entry>) -> bool) {
        let mut entries = self.entries.lock();
        let before = entries.len();
        entries.retain(|other| !matches(other));
        if entries.len() != before {
            drop(entries);
            self.changed();
        }
    }

    /// Tell receivers that the entries changed: they copy the table again on their next poll,
    /// and the parked one is woken now so it starts (or stops) polling the changed sockets.
    fn changed(&self) {
        self.generation.fetch_add(1, Ordering::Release);
        self.receiver.wake();
    }
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

/// Why a connected socket could not be created.
enum ConnectError {
    /// The port could not be shared (socket options or the bind): this host refuses the
    /// feature, so the caller turns it off.
    Shared(io::Error),
    /// The kernel has no route or source for the endpoint right now (`connect` failed): only
    /// this datagram falls back.
    Route(io::Error),
}

/// Sets `SO_REUSEPORT` on every socket of ours that holds the port for as long as it lives, and
/// clears it again on drop, so no other process can join the port outside that moment.
struct ReusePortWindow<'a> {
    /// The wildcard socket and the current connected sockets.
    sockets: Vec<socket2::SockRef<'a>>,
}

impl<'a> ReusePortWindow<'a> {
    /// Open the window on `sockets`; on error, whatever was set is cleared again.
    fn open(sockets: Vec<socket2::SockRef<'a>>) -> io::Result<Self> {
        let mut window = Self {
            sockets: Vec::with_capacity(sockets.len()),
        };
        for socket in sockets {
            socket.set_reuse_port(true)?;
            window.sockets.push(socket);
        }
        Ok(window)
    }
}

impl Drop for ReusePortWindow<'_> {
    fn drop(&mut self) {
        for socket in &self.sockets {
            if let Err(error) = socket.set_reuse_port(false) {
                tracing::warn!("macOS UDP: could not clear SO_REUSEPORT ({error})");
            }
        }
    }
}

/// Create a socket that shares the wildcard socket's address and port and is connected to
/// `destination`. `entries` are the connected sockets already on the port; the shared-port
/// option is set on all of them only while the new socket binds.
fn connect(
    wildcard: &tokio::net::UdpSocket,
    entries: &[Arc<Entry>],
    destination: SocketAddr,
) -> Result<tokio::net::UdpSocket, ConnectError> {
    let shared = ConnectError::Shared;
    let local = wildcard.local_addr().map_err(shared)?;
    let template = socket2::SockRef::from(wildcard);
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(local),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .map_err(shared)?;
    socket.set_nonblocking(true).map_err(shared)?;
    if local.is_ipv6() {
        socket
            .set_only_v6(template.only_v6().map_err(shared)?)
            .map_err(shared)?;
    }
    // Match the wildcard socket's buffers, since this socket now carries the endpoint's traffic.
    socket
        .set_recv_buffer_size(template.recv_buffer_size().map_err(shared)?)
        .map_err(shared)?;
    socket
        .set_send_buffer_size(template.send_buffer_size().map_err(shared)?)
        .map_err(shared)?;
    {
        let mut ours = Vec::with_capacity(entries.len() + 2);
        ours.push(socket2::SockRef::from(wildcard));
        ours.extend(
            entries
                .iter()
                .map(|entry| socket2::SockRef::from(&entry.socket)),
        );
        ours.push(socket2::SockRef::from(&socket));
        let _window = ReusePortWindow::open(ours).map_err(shared)?;
        socket.bind(&local.into()).map_err(shared)?;
    }
    socket
        .connect(&destination.into())
        .map_err(ConnectError::Route)?;
    tokio::net::UdpSocket::from_std(socket.into()).map_err(shared)
}

/// Whether `payload` is a WireGuard data message that carries a packet: the only kind that uses
/// a connected socket. Keepalives (an empty data message) and handshake messages do not.
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

    /// The switch: on when unset, off only for `0` (J763 makes it the macOS default).
    #[test]
    fn connected_sends_are_on_unless_switched_off() {
        assert!(super::switch_on(None));
        assert!(super::switch_on(Some("1")));
        assert!(!super::switch_on(Some("0")));
        assert!(!super::switch_on(Some(" 0\n")));
    }

    /// Binding the WireGuard socket the default way (no explicit choice) turns them on.
    #[tokio::test]
    async fn a_default_socket_sends_through_connected_sockets() {
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
        assert_eq!(wireguard.inner.connected.len(), 1);
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
    /// shared-port option is cleared after each of our binds (J763 measured that macOS lets any
    /// user co-bind a port that carries it, even a specific address that then steals its
    /// datagrams). A specific-address bind by the *same* user is allowed with or without this
    /// feature, so it is not checked here; the cross-user probe is on #260.
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

        // Our own next connected socket still binds.
        let (b, b_address) = peer().await;
        send(&wireguard, &data(64), b_address).await;
        peer_recv(&b).await;
        assert_eq!(wireguard.inner.connected.len(), 2);
    }

    /// A network change closes every connected socket; the next data reconnects and arrives.
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
            "every connected socket closed"
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

    /// A network change while the receive task is running closes the old sockets at once, so
    /// an endpoint whose route did not move reconnects on the same 4-tuple instead of colliding
    /// with a socket the receiver still holds (the kernel refuses a second connected socket with
    /// the same addresses and ports while the first is open).
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

    /// A handshake initiation leaves through the wildcard socket and closes its endpoint's
    /// connected socket, so a stale source ends at WireGuard's own retry even with no signal.
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
            "the initiation closed the entry"
        );

        let before = wireguard.inner.connected.connects();
        send(&wireguard, &data(64), a_address).await;
        peer_recv(&a).await;
        assert_eq!(wireguard.inner.connected.connects(), before + 1);
    }

    /// Keepalives and handshake responses also leave through the wildcard socket and close their
    /// endpoint's connected socket (J789). A Mac that is idle or only receives sends nothing but
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
                "the {name} closed the entry"
            );
        }
    }

    /// Keepalives and handshake messages never create a connected socket.
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
    /// anything: the shared-port option it needed for its own bind is cleared at once, not at the
    /// first connected socket (J789 mutation run; an idle device may never create one).
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

    /// A receive task that is already parked starts reading a connected socket created after it
    /// parked: the endpoint's replies now arrive on that socket, not on the wildcard one, so a
    /// receiver that is not woken would miss them until some other datagram woke it (J789
    /// mutation run).
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

    /// The table holds at most `MAX_CONNECTED` endpoints. Past it, a new endpoint evicts only an
    /// idle entry; when every entry is busy it keeps `sendto`, and every endpoint keeps working.
    #[tokio::test]
    async fn a_full_table_evicts_only_idle_entries() {
        let wireguard = wireguard_socket(true);
        let mut peers = Vec::new();
        for _ in 0..super::MAX_CONNECTED {
            let (socket, address) = peer().await;
            send(&wireguard, &data(64), address).await;
            peers.push((socket, address));
        }
        assert_eq!(wireguard.inner.connected.len(), super::MAX_CONNECTED);
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
        assert_eq!(wireguard.inner.connected.len(), super::MAX_CONNECTED);
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

    /// Off, sends leave from the wildcard socket and no extra socket is made.
    #[tokio::test]
    async fn switched_off_sends_from_the_wildcard_socket() {
        let wireguard = wireguard_socket(false);
        let (a, a_address) = peer().await;
        send(&wireguard, &data(64), a_address).await;
        assert_eq!(peer_recv(&a).await.0, data(64));
        assert_eq!(wireguard.inner.connected.len(), 0);
    }
}
