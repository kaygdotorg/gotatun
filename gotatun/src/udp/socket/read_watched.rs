// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

//! How a Linux or Android UDP socket waits: readable always, writable only while a send is
//! blocked (infraternal #260, J1255).
//!
//! tokio registers its own `UdpSocket` with epoll for readability *and* writability, edge
//! triggered. The kernel reports write space on a UDP socket each time it frees a datagram the
//! socket sent (`sock_wfree`), so every datagram sent produced an epoll event. Nobody was waiting
//! for it, but it still woke the runtime's parked worker, which then found nothing to do. On an
//! idle hub with thousands of peers that was 82-94% of all wakeups: one per keepalive.
//!
//! [`ReadWatchedSocket`] keeps the two directions apart:
//!
//! - The socket is registered once, for readability only. The kernel then drops write-space
//!   events before they reach epoll.
//! - A send makes its system call straight away. Only when the send buffer is full
//!   (`EWOULDBLOCK`) is writability watched, and only until that send goes through. The watch is
//!   a second descriptor of the same socket, because tokio cannot change the interest of a
//!   registration, and epoll takes one registration per descriptor.
//!
//! **Cost.** A send that does not block does what it did before: one unit of tokio's cooperative
//! budget and the system call. A blocked send additionally adds and removes one epoll
//! registration. Sends block only when the socket's send buffer is full.

use std::{
    io,
    net::{SocketAddr, UdpSocket},
    os::fd::{AsFd, OwnedFd},
};

use tokio::io::{Interest, unix::AsyncFd};

/// A nonblocking datagram socket registered with tokio for readability, which watches
/// writability only while a send waits for room in the send buffer. See the module docs.
///
/// Receives and sends go through [`ReadWatchedSocket::receive`],
/// [`ReadWatchedSocket::receive_from`] and [`ReadWatchedSocket::send`]; every other socket call
/// can use [`ReadWatchedSocket::get_ref`] directly.
pub(super) struct ReadWatchedSocket {
    /// The socket, in its one permanent registration: readability.
    read: AsyncFd<UdpSocket>,
    /// A second descriptor of the same socket, registered for writability while a send waits.
    ///
    /// The lock belongs to that waiting send: a descriptor can be registered only once at a
    /// time, so other sends that find the buffer full queue here and take their turn.
    write: tokio::sync::Mutex<OwnedFd>,
}

impl ReadWatchedSocket {
    /// Register `socket`, which must already be nonblocking, with the current tokio runtime.
    ///
    /// # Errors
    /// Fails if the descriptor cannot be duplicated or registered.
    pub(super) fn new(socket: UdpSocket) -> io::Result<Self> {
        let write = socket.as_fd().try_clone_to_owned()?;
        let read = AsyncFd::with_interest(socket, Interest::READABLE)?;
        Ok(Self {
            read,
            write: tokio::sync::Mutex::new(write),
        })
    }

    /// The socket itself, for calls that never wait: options, addresses and raw descriptors.
    #[inline(always)]
    pub(super) fn get_ref(&self) -> &UdpSocket {
        self.read.get_ref()
    }

    /// Run the nonblocking receive call `call`, waiting for the socket to be ready for
    /// `interest` (readable, optionally with errors) whenever it answers `EWOULDBLOCK`.
    ///
    /// # Errors
    /// Returns whatever `call` fails with, other than `EWOULDBLOCK`.
    pub(super) async fn receive<R>(
        &self,
        interest: Interest,
        mut call: impl FnMut() -> io::Result<R>,
    ) -> io::Result<R> {
        self.read.async_io(interest, |_| call()).await
    }

    /// Receive one datagram into `buf`, returning its length and source.
    ///
    /// # Errors
    /// Returns the socket's receive error.
    pub(super) async fn receive_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let socket = self.get_ref();
        self.receive(Interest::READABLE | Interest::ERROR, || {
            socket.recv_from(buf)
        })
        .await
    }

    /// Run the nonblocking send call `call`. It runs at once; if it answers `EWOULDBLOCK`, it
    /// runs again each time the send buffer has room, until it answers something else.
    ///
    /// Cancel safe: dropping the future removes the writability watch, and `call` has sent
    /// nothing unless the future completed.
    ///
    /// # Errors
    /// Returns whatever `call` fails with, other than `EWOULDBLOCK`, or the error of adding the
    /// writability watch.
    pub(super) async fn send<R>(&self, mut call: impl FnMut() -> io::Result<R>) -> io::Result<R> {
        // A send loop that never blocks must still give other tasks their turn.
        tokio::task::coop::consume_budget().await;
        match call() {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                self.send_when_writable(call).await
            }
            result => result,
        }
    }

    /// The blocked half of [`ReadWatchedSocket::send`]: watch writability, retry `call` on each
    /// report of room, and remove the watch on the way out.
    ///
    /// No report can be missed between the failed call and the new watch: adding a registration
    /// reports a socket that is already writable.
    #[cold]
    async fn send_when_writable<R>(
        &self,
        mut call: impl FnMut() -> io::Result<R>,
    ) -> io::Result<R> {
        let descriptor = self.write.lock().await;
        // Declared after the lock guard, so it is dropped (and the registration removed) before
        // the next sender can take the descriptor.
        let watch = AsyncFd::with_interest(descriptor.as_fd(), Interest::WRITABLE)?;
        watch.async_io(Interest::WRITABLE, |_| call()).await
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        io,
        net::{Ipv4Addr, UdpSocket},
        os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd},
        sync::Arc,
        time::Duration,
    };

    use super::ReadWatchedSocket;

    /// The epoll event bit for writability.
    const OUT: u32 = libc::EPOLLOUT as u32;
    /// The epoll event bit for readability.
    const IN: u32 = libc::EPOLLIN as u32;
    /// How many datagrams a blocked-send test pushes through a buffer that holds only a few.
    const DATAGRAMS: usize = 200;

    /// The event masks of every epoll registration, in this process, of the file behind
    /// `socket`: one per registered descriptor. Read from `/proc/self/fdinfo`.
    fn registrations(socket: BorrowedFd<'_>) -> Vec<u32> {
        let name = |fd: i32| std::fs::read_link(format!("/proc/self/fd/{fd}")).ok();
        let wanted = name(socket.as_raw_fd()).expect("the socket's own name");
        // tokio holds more than one descriptor of its epoll instance, and each one lists every
        // registration: keyed by registered descriptor, they count once.
        let mut found = BTreeMap::new();
        for entry in std::fs::read_dir("/proc/self/fd").expect("descriptor list") {
            let Some(fd) = entry
                .ok()
                .and_then(|entry| entry.file_name().to_str()?.parse::<i32>().ok())
            else {
                continue;
            };
            if name(fd).is_none_or(|link| link.as_os_str() != "anon_inode:[eventpoll]") {
                continue;
            }
            let Ok(info) = std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}")) else {
                continue;
            };
            for line in info.lines() {
                let mut words = line.split_whitespace();
                if words.next() != Some("tfd:") {
                    continue;
                }
                let target: i32 = words.next().and_then(|fd| fd.parse().ok()).expect("tfd");
                assert_eq!(words.next(), Some("events:"), "fdinfo format: {line}");
                let events =
                    u32::from_str_radix(words.next().expect("events"), 16).expect("hex events");
                if name(target).as_ref() == Some(&wanted) {
                    found.insert(target, events);
                }
            }
        }
        found.into_values().collect()
    }

    /// How many registrations of `socket` ask for writability.
    fn writable_watches(socket: &ReadWatchedSocket) -> usize {
        registrations(socket.get_ref().as_fd())
            .iter()
            .filter(|&&events| events & OUT != 0)
            .count()
    }

    /// A connected datagram pair whose sending half has a send buffer of only a few datagrams,
    /// so that a send really answers `EWOULDBLOCK` until the receiver reads. A UDP socket on
    /// loopback never does (the datagram leaves its send buffer during the call), so the pair is
    /// a unix one behind the standard UDP socket type: only `send`, `recv` and epoll are used.
    fn blocking_pair() -> (Arc<ReadWatchedSocket>, std::os::unix::net::UnixDatagram) {
        let (sender, receiver) = std::os::unix::net::UnixDatagram::pair().expect("pair");
        socket2::SockRef::from(&sender)
            .set_send_buffer_size(8 * 1024)
            .expect("small send buffer");
        sender.set_nonblocking(true).expect("nonblocking sender");
        receiver
            .set_nonblocking(true)
            .expect("nonblocking receiver");
        let sender = UdpSocket::from(OwnedFd::from(sender));
        (
            Arc::new(ReadWatchedSocket::new(sender).expect("registration")),
            receiver,
        )
    }

    /// Send [`DATAGRAMS`] datagrams in order, each starting with its number.
    async fn send_numbered(socket: Arc<ReadWatchedSocket>, first: usize) -> io::Result<()> {
        for number in first..first + DATAGRAMS {
            let mut datagram = [0u8; 1024];
            datagram[..8].copy_from_slice(&(number as u64).to_le_bytes());
            socket.send(|| socket.get_ref().send(&datagram)).await?;
        }
        Ok(())
    }

    /// Wait until `socket` has a writability watch, that is, until a send is blocked.
    async fn until_blocked(socket: &ReadWatchedSocket) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while writable_watches(socket) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the send blocks and watches writability");
    }

    /// Read `count` datagrams, letting the senders run whenever the queue is empty.
    async fn drain(receiver: &std::os::unix::net::UnixDatagram, count: usize) -> Vec<u64> {
        let mut numbers = Vec::with_capacity(count);
        let mut datagram = [0u8; 1024];
        tokio::time::timeout(Duration::from_secs(5), async {
            while numbers.len() < count {
                match receiver.recv(&mut datagram) {
                    Ok(_) => numbers.push(u64::from_le_bytes(
                        datagram[..8].try_into().expect("number"),
                    )),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        tokio::task::yield_now().await;
                    }
                    Err(error) => panic!("receive: {error}"),
                }
            }
        })
        .await
        .expect("every blocked send is woken once there is room");
        numbers
    }

    /// A bound socket has one registration, for readability and not writability, and sending and
    /// receiving through it leaves it that way.
    #[tokio::test]
    async fn a_bound_socket_is_registered_for_readability_only() {
        use crate::udp::socket::{SockOpt, UdpSocket as Socket};
        use crate::udp::{UdpRecv, UdpSend};

        let mut socket = Socket::bind((Ipv4Addr::LOCALHOST, 0).into(), SockOpt::default()).unwrap();
        let sender = socket.clone();
        let own = socket.local_addr().unwrap();
        let assert_read_only = |socket: &Socket| {
            let masks = registrations(socket.as_fd());
            assert_eq!(masks.len(), 1, "one registration: {masks:x?}");
            assert_ne!(masks[0] & IN, 0, "readable: {masks:x?}");
            assert_eq!(masks[0] & OUT, 0, "not writable: {masks:x?}");
        };
        assert_read_only(&socket);

        let pool = crate::packet::PacketBufPool::<4096>::new(2);
        let mut packet = pool.get();
        packet.truncate(5);
        sender.send_to(packet, own).await.unwrap();
        let mut receive_pool = crate::packet::PacketBufPool::<4096>::new(1);
        let (packet, source) =
            tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut receive_pool))
                .await
                .expect("the datagram arrives")
                .unwrap();
        assert_eq!((packet.len(), source), (5, own));
        assert_read_only(&socket);
    }

    /// A send that really finds the buffer full watches writability while it waits, delivers
    /// everything in order once there is room, and leaves no watch behind.
    #[tokio::test]
    async fn a_blocked_send_watches_writability_only_while_blocked() {
        let (socket, receiver) = blocking_pair();
        assert_eq!(writable_watches(&socket), 0);

        let sends = tokio::spawn(send_numbered(Arc::clone(&socket), 0));
        until_blocked(&socket).await;
        assert!(!sends.is_finished());
        let masks = registrations(socket.get_ref().as_fd());
        assert_eq!(masks.len(), 2, "the read registration and the watch");
        assert_eq!(
            masks.iter().filter(|&&events| events & IN != 0).count(),
            1,
            "the watch asks for writability only: {masks:x?}"
        );

        let numbers = drain(&receiver, DATAGRAMS).await;
        sends.await.unwrap().unwrap();
        assert_eq!(numbers, (0..DATAGRAMS as u64).collect::<Vec<_>>());
        assert_eq!(writable_watches(&socket), 0);
        assert_eq!(registrations(socket.get_ref().as_fd()).len(), 1);
    }

    /// Two tasks blocked on one socket take turns on the watch, and both finish.
    #[tokio::test]
    async fn two_blocked_sends_both_finish() {
        let (socket, receiver) = blocking_pair();
        let first = tokio::spawn(send_numbered(Arc::clone(&socket), 0));
        let second = tokio::spawn(send_numbered(Arc::clone(&socket), DATAGRAMS));
        until_blocked(&socket).await;
        assert_eq!(writable_watches(&socket), 1, "one watch at a time");

        let mut numbers = drain(&receiver, 2 * DATAGRAMS).await;
        first.await.unwrap().unwrap();
        second.await.unwrap().unwrap();
        numbers.sort_unstable();
        assert_eq!(numbers, (0..2 * DATAGRAMS as u64).collect::<Vec<_>>());
        assert_eq!(writable_watches(&socket), 0);
    }

    /// Cancelling a blocked send removes its watch, and a later send can add one again.
    #[tokio::test]
    async fn a_cancelled_blocked_send_leaves_no_watch() {
        let (socket, receiver) = blocking_pair();
        let cancelled = tokio::spawn(send_numbered(Arc::clone(&socket), 0));
        until_blocked(&socket).await;
        cancelled.abort();
        assert!(cancelled.await.unwrap_err().is_cancelled());
        assert_eq!(writable_watches(&socket), 0);

        let sends = tokio::spawn(send_numbered(Arc::clone(&socket), DATAGRAMS));
        until_blocked(&socket).await;
        // What the cancelled task had queued, then everything the second one sends.
        let mut datagram = [0u8; 1024];
        let numbers = tokio::time::timeout(Duration::from_secs(5), async {
            let mut numbers = Vec::new();
            while numbers.last() != Some(&(2 * DATAGRAMS as u64 - 1)) {
                match receiver.recv(&mut datagram) {
                    Ok(_) => numbers.push(u64::from_le_bytes(
                        datagram[..8].try_into().expect("number"),
                    )),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        tokio::task::yield_now().await;
                    }
                    Err(error) => panic!("receive: {error}"),
                }
            }
            numbers
        })
        .await
        .expect("the second send finishes");
        sends.await.unwrap().unwrap();
        let second = numbers
            .iter()
            .filter(|&&number| number >= DATAGRAMS as u64)
            .count();
        assert_eq!(second, DATAGRAMS);
        assert_eq!(writable_watches(&socket), 0);
    }
}
