// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

//! Connected per-endpoint send sockets for macOS (#260, J744).
//!
//! **Why.** On macOS a `sendto` on an unconnected socket bound to the wildcard address costs
//! about 14 µs of kernel time per datagram on our Mac VM, because xnu re-decides the route and
//! the network policy for every datagram. A socket with a fixed 4-tuple (a *connected* socket)
//! keeps that decision, and the same `send` costs about 2 µs (J744 microbench, #260). The Mac's
//! single device runtime spends about half its time in `sendto` under load (J728), so this is the
//! largest per-datagram cost on the Mac send path. The private batch call `sendmsg_x` saves only
//! about 3% on the same socket, so no private API is used here.
//!
//! **How.** The WireGuard socket keeps its wildcard bind and is created with `SO_REUSEPORT`.
//! The first datagram to an endpoint creates one more socket bound to the same address and port
//! (also `SO_REUSEPORT`) and connected to that endpoint; later datagrams to it use `send` on that
//! socket. The kernel delivers an arriving datagram to the most specific matching socket, so the
//! endpoint's replies now land on its connected socket rather than the wildcard one: the
//! receive side therefore reads every connected socket as well as the wildcard socket.
//!
//! **Invariants.**
//! - At most [`MAX_CONNECTED`] endpoints get a connected socket. When the table is full, the
//!   oldest entry is closed to make room (an endpoint that roamed away no longer sends to it).
//!   Datagrams still queued on a closed entry are lost, which WireGuard tolerates.
//! - A connected socket reports ICMP errors (`ECONNREFUSED` and friends) on its next call. On
//!   receive they are skipped; on send the datagram is retried once, then the entry is dropped and
//!   the datagram falls back to the wildcard socket, as it would have gone before.
//! - Any failure to create a connected socket turns the feature off for this socket and logs once,
//!   so a host that refuses the shared port keeps the old path.
//! - No timers (D81): entries change only on sends and errors.
//!
//! The feature is off by default. `GOTATUN_BENCH_MAC_CONNECTED=1` turns it on for bench runs until
//! the owner decides (#260).

use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
};

use futures::task::AtomicWaker;
use parking_lot::Mutex;
use tokio::io::ReadBuf;

/// The most endpoints that get their own connected socket.
///
/// A device usually talks to a handful of endpoints at once; each entry is one file descriptor
/// and one reactor registration, and every receive poll visits each entry.
pub(crate) const MAX_CONNECTED: usize = 16;

/// Whether the bench switch asks for connected sends, read once per process.
pub(crate) fn wanted() -> bool {
    static WANTED: OnceLock<bool> = OnceLock::new();
    *WANTED.get_or_init(|| {
        let on = std::env::var("GOTATUN_BENCH_MAC_CONNECTED").is_ok_and(|value| value.trim() == "1");
        if on {
            eprintln!("diag mac_connected on max={MAX_CONNECTED}");
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
}

/// The connected sockets of one WireGuard socket, shared by all of its clones.
pub(crate) struct ConnectedSends {
    /// Cleared for good after a connected socket cannot be created.
    enabled: AtomicBool,
    /// The current entries, oldest first.
    entries: Mutex<Vec<Arc<Entry>>>,
    /// Bumped whenever `entries` changes, so a receiver refreshes its copy only then.
    generation: AtomicU64,
    /// The receive task waiting on the current entries; woken when a new entry appears so it
    /// starts polling that socket too.
    receiver: AtomicWaker,
}

/// A receiver's copy of the entries plus where its next round of polls starts.
#[derive(Clone, Default)]
pub(crate) struct RecvView {
    /// The `generation` that `entries` was copied at.
    generation: u64,
    /// The connected sockets this receiver polls after the wildcard socket.
    entries: Vec<Arc<Entry>>,
    /// Rotates the first socket polled, so one busy endpoint cannot starve the others.
    next: usize,
}

impl ConnectedSends {
    /// A table for a socket that was (`enabled`) or was not created with `SO_REUSEPORT`.
    pub(crate) fn new(enabled: bool) -> Self {
        Self {
            enabled: AtomicBool::new(enabled),
            entries: Mutex::new(Vec::with_capacity(if enabled { MAX_CONNECTED } else { 0 })),
            generation: AtomicU64::new(0),
            receiver: AtomicWaker::new(),
        }
    }

    /// How many endpoints have a connected socket right now.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.lock().len()
    }

    /// Send `payload` to `destination` (already mapped for the wildcard socket).
    ///
    /// Uses the endpoint's connected socket, creating it first if needed, and falls back to
    /// `sendto` on the wildcard socket whenever no connected socket can be used.
    pub(crate) async fn send(
        &self,
        wildcard: &tokio::net::UdpSocket,
        payload: &[u8],
        destination: SocketAddr,
    ) -> io::Result<()> {
        if let Some(entry) = self.entry_for(wildcard, destination) {
            match entry.socket.send(payload).await {
                Ok(_) => return Ok(()),
                // A pending ICMP error is reported once and cleared; the datagram was not sent.
                Err(error) if is_icmp_error(&error) => match entry.socket.send(payload).await {
                    Ok(_) => return Ok(()),
                    Err(error) => self.forget(&entry, &error),
                },
                Err(error) if is_path_error(&error) => self.forget(&entry, &error),
                Err(error) => return Err(error),
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
            view.entries = self.entries.lock().clone();
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
            let socket = &view.entries[index - 1].socket;
            loop {
                match poll_one(socket, cx, buf) {
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

    /// The connected socket for `destination`, created on first use while the table allows it.
    fn entry_for(
        &self,
        wildcard: &tokio::net::UdpSocket,
        destination: SocketAddr,
    ) -> Option<Arc<Entry>> {
        if !self.enabled.load(Ordering::Relaxed) {
            return None;
        }
        let mut entries = self.entries.lock();
        if let Some(entry) = entries.iter().find(|entry| entry.destination == destination) {
            return Some(Arc::clone(entry));
        }
        let socket = match connect(wildcard, destination) {
            Ok(socket) => socket,
            Err(error) => {
                if self.enabled.swap(false, Ordering::Relaxed) {
                    tracing::warn!(
                        "macOS UDP: cannot connect a send socket to {destination} ({error}); using sendto"
                    );
                }
                return None;
            }
        };
        if entries.len() == MAX_CONNECTED {
            entries.remove(0);
        }
        let entry = Arc::new(Entry {
            destination,
            socket,
        });
        entries.push(Arc::clone(&entry));
        drop(entries);
        self.generation.fetch_add(1, Ordering::Release);
        self.receiver.wake();
        Some(entry)
    }

    /// Drop `entry` after a send error that says its path is gone; the next send reconnects.
    fn forget(&self, entry: &Arc<Entry>, error: &io::Error) {
        tracing::debug!(
            "macOS UDP: dropping the connected socket to {} ({error})",
            entry.destination
        );
        let mut entries = self.entries.lock();
        let before = entries.len();
        entries.retain(|other| !Arc::ptr_eq(other, entry));
        if entries.len() != before {
            drop(entries);
            self.generation.fetch_add(1, Ordering::Release);
        }
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

/// Create a socket that shares the wildcard socket's address and port and is connected to
/// `destination`. The wildcard socket must have been created with `SO_REUSEPORT`.
fn connect(
    wildcard: &tokio::net::UdpSocket,
    destination: SocketAddr,
) -> io::Result<tokio::net::UdpSocket> {
    let local = wildcard.local_addr()?;
    let template = socket2::SockRef::from(wildcard);
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(local),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    socket.set_nonblocking(true)?;
    if local.is_ipv6() {
        socket.set_only_v6(template.only_v6()?)?;
    }
    socket.set_reuse_port(true)?;
    // Match the wildcard socket's buffers, since this socket now carries the endpoint's traffic.
    socket.set_recv_buffer_size(template.recv_buffer_size()?)?;
    socket.set_send_buffer_size(template.send_buffer_size()?)?;
    socket.bind(&local.into())?;
    socket.connect(&destination.into())?;
    tokio::net::UdpSocket::from_std(socket.into())
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
        let (packet, source) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut pool))
            .await
            .expect("a datagram within 5 s")
            .expect("receive");
        (packet.to_vec(), source)
    }

    /// Send `payload` from the WireGuard socket.
    async fn send(socket: &UdpSocket, payload: &[u8], to: SocketAddr) {
        socket
            .send_to(Packet::from_bytes(bytes::BytesMut::from(payload)), to)
            .await
            .expect("send");
    }

    /// The first send to an endpoint gives it a connected socket on the WireGuard port. The
    /// endpoint sees the WireGuard port as the source, its replies (which the kernel now delivers
    /// to the connected socket) still arrive, and so do datagrams from other endpoints.
    #[tokio::test]
    async fn an_endpoint_gets_a_connected_socket_and_its_replies_still_arrive() {
        let mut wireguard = wireguard_socket(true);
        let port = wireguard.local_addr().expect("local").port();
        let (a, a_address) = peer().await;
        let (b, _) = peer().await;

        send(&wireguard, b"to-a", a_address).await;
        let mut buf = [0u8; 64];
        let (n, source) = a.recv_from(&mut buf).await.expect("a receives");
        assert_eq!(&buf[..n], b"to-a");
        assert_eq!(source.port(), port, "the endpoint sees the WireGuard port");
        assert_eq!(wireguard.inner.connected.len(), 1, "a connected socket for the endpoint");

        let ours: SocketAddr = (Ipv4Addr::LOCALHOST, port).into();
        a.send_to(b"from-a", ours).await.expect("a replies");
        assert_eq!(recv(&mut wireguard).await, (b"from-a".to_vec(), a_address));
        b.send_to(b"from-b", ours).await.expect("b sends");
        let (payload, source) = recv(&mut wireguard).await;
        assert_eq!(payload, b"from-b");
        assert_eq!(source, b.local_addr().expect("b address"));

        send(&wireguard, b"to-a-again", a_address).await;
        let (n, _) = a.recv_from(&mut buf).await.expect("a receives again");
        assert_eq!(&buf[..n], b"to-a-again");
        assert_eq!(wireguard.inner.connected.len(), 1, "the entry is reused");
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
            send(&wireguard, b"to-nobody", closed_address).await;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let (b, b_address) = peer().await;
        b.send_to(b"from-b", (Ipv4Addr::LOCALHOST, port)).await.expect("b sends");
        assert_eq!(recv(&mut wireguard).await, (b"from-b".to_vec(), b_address));
    }

    /// The table holds at most `MAX_CONNECTED` endpoints; the oldest makes room and every
    /// endpoint keeps working.
    #[tokio::test]
    async fn a_full_table_closes_its_oldest_entry() {
        let wireguard = wireguard_socket(true);
        let mut peers = Vec::new();
        for _ in 0..super::MAX_CONNECTED + 2 {
            let (socket, address) = peer().await;
            send(&wireguard, b"hello", address).await;
            peers.push(socket);
        }
        assert_eq!(wireguard.inner.connected.len(), super::MAX_CONNECTED);
        let mut buf = [0u8; 16];
        for socket in &peers {
            let (n, _) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buf))
                .await
                .expect("each endpoint got its datagram")
                .expect("receive");
            assert_eq!(&buf[..n], b"hello");
        }
    }

    /// Off (the default), sends leave from the wildcard socket and no extra socket is made.
    #[tokio::test]
    async fn off_by_default_sends_from_the_wildcard_socket() {
        let wireguard = wireguard_socket(false);
        let (a, a_address) = peer().await;
        send(&wireguard, b"to-a", a_address).await;
        let mut buf = [0u8; 16];
        let (n, _) = a.recv_from(&mut buf).await.expect("a receives");
        assert_eq!(&buf[..n], b"to-a");
        assert_eq!(wireguard.inner.connected.len(), 0);
    }
}
