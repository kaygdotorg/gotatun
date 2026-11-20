// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

//! Batched UDP sends and receives on macOS through xnu's private `sendmsg_x` and `recvmsg_x`
//! (#260, #554, J1023, J1036).
//!
//! **Why.** macOS has no public `sendmmsg`/`recvmmsg` and no UDP segmentation offload, so every
//! WireGuard datagram costs one `sendto` or `recvfrom`. xnu exports two private calls that move
//! many datagrams per system call. They pay off unevenly, so each one is used only where it was
//! measured to help:
//! - `sendmsg_x` is a real kernel batch (`sosend_list`) only on a *connected* datagram socket,
//!   and only since macOS 14 (xnu-10002). On an unconnected socket the kernel still runs its
//!   per-datagram send once per message, and on macOS 13 the call is a loop over that as well.
//!   So batching starts at macOS 14, and the connected pool sockets
//!   ([`super::macos_connected`]) and the unconnected wildcard socket are switched separately.
//! - `recvmsg_x` takes every queued datagram in one call. On macOS 14.0–15.5 its kernel side
//!   (`soreceive_m_list`) can leak the socket lock, which other projects saw as kernel panics,
//!   so it is used only on macOS 15.6 and later.
//!
//! **Fallback.** Both symbols are looked up at run time with `dlsym`, never linked, so a macOS
//! that drops them still loads the binary and simply keeps one datagram per call. An unknown
//! OS version turns both calls off. `GOTATUN_MAC_BATCH` overrides the defaults (see
//! [`Policy::from_env`]); it can switch calls off, never on where a gate forbids them.
//!
//! **Kernel semantics the send loop relies on** (J434 measured them on macOS 26; J1036's tests
//! pin them on the Macs we run):
//! - `sendmsg_x` returns how many datagrams it queued. A short count means the socket could not
//!   take more right now; the next call resumes at the first unsent datagram.
//! - Once at least one datagram has gone out, `EWOULDBLOCK`, `ENOBUFS`, `EINTR` and `EMSGSIZE`
//!   are swallowed and the count is returned. So `-1` with one of these means the *first*
//!   datagram of that call failed and nothing was sent.
//! - Any other `-1` may come after earlier datagrams of the same call already left (J434: an
//!   unsendable datagram at index 3 of 8). [`send_loop`] then stops and its caller sends the rest
//!   one at a time, so up to one batch can leave twice. WireGuard's replay window drops the
//!   copies; this only happens on a hard socket error, never under load.
//! - After `EWOULDBLOCK` the next attempt is a plain one-datagram send. That datagram follows
//!   tokio's readiness exactly, so a socket that reports writable while `sendmsg_x` keeps
//!   refusing (a stall others hit just under `SO_SNDBUF`) still makes progress.
//! - `recvmsg_x` reports neither `MSG_TRUNC` nor the real length of a datagram larger than its
//!   buffer. A datagram that fills its whole buffer is therefore dropped as truncated. The
//!   pool's 4 KiB buffers are far larger than any WireGuard datagram on our MTUs.
//!
//! [`stats`] counts calls and datagrams, so a bench can report datagrams per system call.

#![allow(unsafe_code)]

use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    os::fd::RawFd,
    sync::{
        OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};

use crate::packet::{Packet, PacketBufPool};

/// Most datagrams one `sendmsg_x` or `recvmsg_x` call carries.
///
/// It matches the buffered send and receive runs (`udp::buffer`), and is far below the kernel's
/// own cap (`kern.ipc.maxsendmsgx`, 256 since macOS 14). The header arrays live on the stack:
/// 64 headers and iovecs are about 4 KiB.
pub(crate) const MAX_BATCH: usize = 64;

/// Darwin's private `struct msghdr_x` (xnu `bsd/sys/socket_private.h`): a `msghdr` plus
/// `msg_datalen`, the byte count of that one datagram. Its layout has been the same since
/// OS X 10.10.
#[repr(C)]
#[derive(Clone, Copy)]
struct MsghdrX {
    msg_name: *mut libc::c_void,
    msg_namelen: libc::socklen_t,
    msg_iov: *mut libc::iovec,
    msg_iovlen: libc::c_int,
    msg_control: *mut libc::c_void,
    msg_controllen: libc::socklen_t,
    msg_flags: libc::c_int,
    msg_datalen: libc::size_t,
}

/// An empty header, for filling the stack arrays.
const EMPTY_HEADER: MsghdrX = MsghdrX {
    msg_name: std::ptr::null_mut(),
    msg_namelen: 0,
    msg_iov: std::ptr::null_mut(),
    msg_iovlen: 0,
    msg_control: std::ptr::null_mut(),
    msg_controllen: 0,
    msg_flags: 0,
    msg_datalen: 0,
};

/// An empty iovec, for filling the stack arrays.
const EMPTY_IOV: libc::iovec = libc::iovec {
    iov_base: std::ptr::null_mut(),
    iov_len: 0,
};

/// `ssize_t sendmsg_x(int, const struct msghdr_x *, u_int, int)`; `recvmsg_x` has the same
/// shape and writes into the array.
type MsgX = unsafe extern "C" fn(libc::c_int, *mut MsghdrX, libc::c_uint, libc::c_int) -> isize;

/// The private calls this macOS exports, each `None` when its symbol is missing.
#[derive(Clone, Copy)]
struct Calls {
    send: Option<MsgX>,
    recv: Option<MsgX>,
}

/// Look both calls up once per process.
fn calls() -> Calls {
    static CALLS: OnceLock<Calls> = OnceLock::new();
    *CALLS.get_or_init(|| Calls {
        send: lookup(c"sendmsg_x"),
        recv: lookup(c"recvmsg_x"),
    })
}

/// The address of `name` in the loaded images, as a [`MsgX`], or `None` when it is missing.
fn lookup(name: &std::ffi::CStr) -> Option<MsgX> {
    // SAFETY: dlsym only reads the NUL-terminated name and searches the loaded images.
    let symbol = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) };
    if symbol.is_null() {
        return None;
    }
    // SAFETY: both names are xnu's syscall wrappers, whose C signature is `MsgX`.
    Some(unsafe { std::mem::transmute::<*mut libc::c_void, MsgX>(symbol) })
}

/// Which socket kinds use the batch calls in this process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Policy {
    /// `sendmsg_x` on connected pool sockets (connected sends on).
    pub(crate) send_connected: bool,
    /// `sendmsg_x` on the unconnected wildcard socket, with a destination per datagram.
    pub(crate) send_wildcard: bool,
    /// `recvmsg_x` on every socket the WireGuard socket reads.
    pub(crate) recv: bool,
}

impl Policy {
    /// No batch calls at all: today's one datagram per call.
    pub(crate) const OFF: Self = Self {
        send_connected: false,
        send_wildcard: false,
        recv: false,
    };

    /// What runs when nothing overrides it, before the version and symbol gates.
    ///
    /// Every call is on where its gate allows it, because each one measured faster than one
    /// datagram per call (J1036, #554; two GotaTun engines over loopback, Gbit/s):
    /// - M1 on macOS 27.2: with connected sends, `sendmsg_x` on them ×1.18–1.26 and all calls
    ///   ×1.34–1.45 (CPU per Gbit −22%); without, `sendmsg_x` on the wildcard socket ×1.08–1.10,
    ///   `recvmsg_x` ×1.03–1.04, both ×1.12–1.15.
    /// - Mac VM on macOS 26.5: all calls ×1.27–1.62 over connected sends alone.
    const DEFAULT: Self = Self {
        send_connected: true,
        send_wildcard: true,
        recv: true,
    };

    /// The policy that `GOTATUN_MAC_BATCH` asks for, before any gate.
    ///
    /// - unset, empty or `auto`: [`Policy::DEFAULT`];
    /// - `0`, `off` or `none`: [`Policy::OFF`] (the kill switch);
    /// - otherwise a comma-separated list of `connected`, `wildcard` and `recv`, each turning
    ///   one call on (`send` is short for `connected,wildcard`, `all` for all three). Unknown
    ///   words are ignored, so a typo switches that call off rather than on.
    pub(crate) fn from_env(value: Option<&str>) -> Self {
        let value = value.map(str::trim).unwrap_or("");
        match value {
            "" | "auto" => return Self::DEFAULT,
            "0" | "off" | "none" => return Self::OFF,
            _ => {}
        }
        let mut policy = Self::OFF;
        for word in value.split(',').map(str::trim) {
            match word {
                "connected" => policy.send_connected = true,
                "wildcard" => policy.send_wildcard = true,
                "send" => (policy.send_connected, policy.send_wildcard) = (true, true),
                "recv" => policy.recv = true,
                "all" | "both" => policy = Self::DEFAULT,
                _ => {}
            }
        }
        policy
    }

    /// `self` with every call removed that this OS version or its symbols cannot carry safely.
    ///
    /// `version` is macOS's `(major, minor)`; `None` (unreadable) turns everything off, since
    /// the gates exist because of kernel bugs in known versions.
    pub(crate) fn gated(self, version: Option<(u32, u32)>, calls: (bool, bool)) -> Self {
        let Some(version) = version else {
            return Self::OFF;
        };
        let (have_send, have_recv) = calls;
        let send = have_send && version >= SEND_SINCE;
        Self {
            send_connected: self.send_connected && send,
            send_wildcard: self.send_wildcard && send,
            recv: self.recv && have_recv && version >= RECV_SINCE,
        }
    }
}

/// The first macOS whose `sendmsg_x` batches in the kernel (xnu-10002, macOS 14).
const SEND_SINCE: (u32, u32) = (14, 0);

/// The first macOS whose `recvmsg_x` no longer leaks the socket lock (15.6).
const RECV_SINCE: (u32, u32) = (15, 6);

/// This process's policy: `GOTATUN_MAC_BATCH`, then the version and symbol gates. Read once.
pub(crate) fn policy() -> Policy {
    static POLICY: OnceLock<Policy> = OnceLock::new();
    *POLICY.get_or_init(|| {
        let asked = Policy::from_env(std::env::var("GOTATUN_MAC_BATCH").ok().as_deref());
        let calls = calls();
        let version = os_version();
        let policy = asked.gated(version, (calls.send.is_some(), calls.recv.is_some()));
        if policy != asked {
            tracing::debug!(
                "macOS UDP batching narrowed to {policy:?} (asked {asked:?}, macOS {version:?}, \
                 sendmsg_x {}, recvmsg_x {})",
                calls.send.is_some(),
                calls.recv.is_some()
            );
        }
        policy
    })
}

/// macOS's `(major, minor)` from `kern.osproductversion`, e.g. `(27, 2)` for "27.2.1".
fn os_version() -> Option<(u32, u32)> {
    let mut buf = [0u8; 32];
    let mut len = buf.len();
    // SAFETY: sysctlbyname writes at most `len` bytes into `buf` and updates `len`.
    let rc = unsafe {
        libc::sysctlbyname(
            c"kern.osproductversion".as_ptr(),
            buf.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return None;
    }
    parse_version(std::str::from_utf8(&buf[..len]).ok()?)
}

/// `(major, minor)` of a dotted version string; a missing minor counts as 0.
fn parse_version(text: &str) -> Option<(u32, u32)> {
    let mut parts = text.trim_end_matches('\0').trim().split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().map_or(Some(0), |minor| minor.parse().ok())?;
    Some((major, minor))
}

/// Calls and datagrams through the batch calls: send calls, send datagrams, receive calls,
/// receive datagrams.
static STATS: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];

/// Snapshot of the counters: `[send_calls, send_datagrams, recv_calls, recv_datagrams]`.
pub(crate) fn stats() -> [u64; 4] {
    STATS.each_ref().map(|count| count.load(Ordering::Relaxed))
}

/// One `sendmsg_x` call on `fd` for the first [`MAX_BATCH`] of `items`: each item is a payload
/// and, on an unconnected socket, its destination (`None` on a connected socket).
///
/// Returns how many datagrams the kernel took, at least 1. `Err` with `EWOULDBLOCK`, `ENOBUFS`,
/// `EINTR` or `EMSGSIZE` means none were taken; any other error may follow a sent prefix (see
/// the module docs). `Unsupported` when this macOS has no `sendmsg_x`.
pub(crate) fn send_x<'a>(
    fd: RawFd,
    items: impl IntoIterator<Item = (&'a [u8], Option<SocketAddr>)>,
) -> io::Result<usize> {
    let send = calls().send.ok_or(io::ErrorKind::Unsupported)?;
    let mut headers = [EMPTY_HEADER; MAX_BATCH];
    let mut iov = [EMPTY_IOV; MAX_BATCH];
    // SAFETY: an all-zero sockaddr_storage is a valid empty value.
    let mut names: [libc::sockaddr_storage; MAX_BATCH] = unsafe { std::mem::zeroed() };
    let mut count = 0;
    for (payload, destination) in items.into_iter().take(MAX_BATCH) {
        iov[count] = libc::iovec {
            iov_base: payload.as_ptr().cast_mut().cast(),
            iov_len: payload.len(),
        };
        let namelen = destination.map_or(0, |to| write_name(to, &mut names[count]));
        headers[count] = MsghdrX {
            msg_name: if namelen == 0 {
                std::ptr::null_mut()
            } else {
                (&raw mut names[count]).cast()
            },
            msg_namelen: namelen,
            msg_iov: &raw mut iov[count],
            msg_iovlen: 1,
            ..EMPTY_HEADER
        };
        count += 1;
    }
    if count == 0 {
        return Ok(0);
    }
    // SAFETY: the first `count` headers point into `iov` and `names`, which outlive the call,
    // and each iovec describes a live payload the caller borrows for the call.
    let sent = unsafe { send(fd, headers.as_mut_ptr(), count as libc::c_uint, 0) };
    STATS[0].fetch_add(1, Ordering::Relaxed);
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    let sent = sent as usize;
    STATS[1].fetch_add(sent as u64, Ordering::Relaxed);
    if sent == 0 {
        // Never seen; treat it as "full right now" so the caller waits instead of spinning.
        return Err(io::ErrorKind::WouldBlock.into());
    }
    Ok(sent)
}

/// Write `address` into `name` as the kernel expects it; returns its length.
fn write_name(address: SocketAddr, name: &mut libc::sockaddr_storage) -> libc::socklen_t {
    let address = socket2::SockAddr::from(address);
    let len = address.len();
    // SAFETY: a SockAddr is at most one sockaddr_storage long; source and target do not overlap.
    unsafe {
        std::ptr::copy_nonoverlapping(
            address.as_ptr().cast::<u8>(),
            (name as *mut libc::sockaddr_storage).cast::<u8>(),
            len as usize,
        );
    }
    len
}

/// One socket that [`send_loop`] drives: a batch call from an index and a plain one-datagram
/// send of an index, both non-blocking, plus a way to wait until the socket may take more.
pub(crate) trait BatchSink {
    /// Send `items[from..]` in one batch call; returns how many left (see [`send_x`]).
    fn try_batch(&self, from: usize) -> io::Result<usize>;
    /// Send `items[index]` alone with a plain `send`/`sendto`.
    fn try_single(&self, index: usize) -> io::Result<()>;
    /// Wait until the socket reports writable.
    fn writable(&self) -> impl Future<Output = io::Result<()>> + Send;
}

/// Where [`send_loop`] stopped.
#[derive(Debug)]
pub(crate) struct Stopped {
    /// How many items, from the start, are done: sent, or dropped with a per-datagram error.
    pub(crate) done: usize,
    /// Why it stopped early; `None` when every item is done.
    pub(crate) error: Option<io::Error>,
    /// Whether some items after `done` may already have left with the batch call that
    /// returned `error` (the ambiguous "error after a sent prefix" case).
    pub(crate) maybe_sent: bool,
    /// The last per-datagram error of an item that was dropped, as `sendto` would report it.
    pub(crate) dropped: Option<io::Error>,
}

/// Send items `0..len` through `sink` with as few batch calls as possible.
///
/// - A short count resumes at the first unsent item.
/// - `EWOULDBLOCK` waits for writability, and the next item then goes out alone through
///   [`BatchSink::try_single`] before batching resumes (see the module docs for why).
/// - `ENOBUFS` and `EMSGSIZE` drop the first item of the call, exactly as one `sendto` would
///   have failed for it, and the rest carry on. `EINTR` retries.
/// - Any other error stops the loop and is returned with `done` at the first item it may
///   concern; the caller decides (retry, another socket, or one at a time).
pub(crate) async fn send_loop(sink: &impl BatchSink, len: usize) -> Stopped {
    let mut stopped = Stopped {
        done: 0,
        error: None,
        maybe_sent: false,
        dropped: None,
    };
    let mut single_next = false;
    while stopped.done < len {
        let from = stopped.done;
        let batch = !single_next && len - from > 1;
        let result = if batch {
            sink.try_batch(from)
        } else {
            sink.try_single(from).map(|()| 1)
        };
        match result {
            Ok(sent) => {
                stopped.done += sent;
                single_next = false;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if let Err(error) = sink.writable().await {
                    stopped.error = Some(error);
                    return stopped;
                }
                single_next = true;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if matches!(error.raw_os_error(), Some(libc::ENOBUFS | libc::EMSGSIZE)) => {
                stopped.done += 1;
                stopped.dropped = Some(error);
            }
            Err(error) => {
                stopped.maybe_sent = batch;
                stopped.error = Some(error);
                return stopped;
            }
        }
    }
    stopped
}

/// The kernel's `struct sockaddr_storage`, so receive names can sit in a `Send` buffer.
#[derive(Clone, Copy)]
struct Name(libc::sockaddr_storage);

/// Receive buffers kept between [`recv_x`] calls, so a call that gets few datagrams does not
/// hand the rest back to the pool and take them again next time.
#[derive(Default)]
pub struct RecvBuf {
    /// Buffers from the pool, full length, not yet filled.
    spare: Vec<Packet>,
}

/// One `recvmsg_x` call on `fd`: appends every datagram it returns to `packets` with its source
/// (mapped by `map_src`), and returns how many. `EWOULDBLOCK` when nothing was queued;
/// `Unsupported` when this macOS has no `recvmsg_x`.
///
/// A datagram that fills its buffer may have been cut short (the call does not say), so it is
/// dropped, as is one without an IP source. Both still count as received for the call.
pub(crate) fn recv_x(
    fd: RawFd,
    buf: &mut RecvBuf,
    pool: &mut PacketBufPool,
    packets: &mut Vec<(Packet, SocketAddr)>,
    map_src: impl Fn(SocketAddr) -> SocketAddr,
) -> io::Result<usize> {
    let recv = calls().recv.ok_or(io::ErrorKind::Unsupported)?;
    while buf.spare.len() < MAX_BATCH {
        buf.spare.push(pool.get());
    }
    let mut received = [(0usize, None); MAX_BATCH];
    let got = recv_into(
        recv,
        fd,
        buf.spare.iter_mut().map(|packet| &mut packet[..]),
        &mut received,
    )?;
    let rest = buf.spare.split_off(got);
    let filled = std::mem::replace(&mut buf.spare, rest);
    for (mut packet, (len, source)) in filled.into_iter().zip(received) {
        let Some(source) = source else { continue };
        if len >= packet.len() {
            continue;
        }
        packet.truncate(len);
        packets.push((packet, map_src(source)));
    }
    Ok(got)
}

/// The `recvmsg_x` call itself, into plain byte buffers: fills `received[i]` with the length
/// and source of datagram `i` and returns how many arrived.
fn recv_into<'a>(
    recv: MsgX,
    fd: RawFd,
    buffers: impl IntoIterator<Item = &'a mut [u8]>,
    received: &mut [(usize, Option<SocketAddr>)],
) -> io::Result<usize> {
    let mut headers = [EMPTY_HEADER; MAX_BATCH];
    let mut iov = [EMPTY_IOV; MAX_BATCH];
    // SAFETY: an all-zero sockaddr_storage is a valid empty value.
    let mut names: [Name; MAX_BATCH] = unsafe { std::mem::zeroed() };
    let limit = received.len().min(MAX_BATCH);
    let mut count = 0;
    for buffer in buffers.into_iter().take(limit) {
        let index = count;
        count += 1;
        iov[index] = libc::iovec {
            iov_base: buffer.as_mut_ptr().cast(),
            iov_len: buffer.len(),
        };
        headers[index] = MsghdrX {
            msg_name: (&raw mut names[index].0).cast(),
            msg_namelen: size_of::<libc::sockaddr_storage>() as libc::socklen_t,
            msg_iov: &raw mut iov[index],
            msg_iovlen: 1,
            ..EMPTY_HEADER
        };
    }
    // SAFETY: the first `count` headers point at live, writable buffers and names of the
    // stated lengths, all of which outlive the call.
    let got = unsafe { recv(fd, headers.as_mut_ptr(), count as libc::c_uint, 0) };
    STATS[2].fetch_add(1, Ordering::Relaxed);
    if got < 0 {
        return Err(io::Error::last_os_error());
    }
    let got = (got as usize).min(count);
    if got == 0 {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    STATS[3].fetch_add(got as u64, Ordering::Relaxed);
    for (slot, (header, name)) in received
        .iter_mut()
        .zip(headers.iter().zip(&names))
        .take(got)
    {
        *slot = (header.msg_datalen, parse(&name.0));
    }
    Ok(got)
}

/// The IPv4 or IPv6 address in a `sockaddr_storage` the kernel filled in.
fn parse(name: &libc::sockaddr_storage) -> Option<SocketAddr> {
    match libc::c_int::from(name.ss_family) {
        libc::AF_INET => {
            // SAFETY: the family says this storage holds a sockaddr_in.
            let a =
                unsafe { &*(name as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>() };
            Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr)),
                u16::from_be(a.sin_port),
            )))
        }
        libc::AF_INET6 => {
            // SAFETY: the family says this storage holds a sockaddr_in6.
            let a =
                unsafe { &*(name as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>() };
            Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(a.sin6_addr.s6_addr),
                u16::from_be(a.sin6_port),
                a.sin6_flowinfo,
                a.sin6_scope_id,
            )))
        }
        _ => None,
    }
}

/// A [`BatchSink`] over one tokio UDP socket and a slice of `(payload, destination)` items.
///
/// `connected` sends without addresses (the socket's own peer); otherwise each item carries its
/// destination, already mapped for this socket.
pub(crate) struct SocketSink<'a> {
    /// The socket the items leave through.
    pub(crate) socket: &'a tokio::net::UdpSocket,
    /// The items, in send order.
    pub(crate) items: &'a [(&'a [u8], SocketAddr)],
    /// Whether `socket` is connected (no per-datagram address).
    pub(crate) connected: bool,
}

impl BatchSink for SocketSink<'_> {
    fn try_batch(&self, from: usize) -> io::Result<usize> {
        use std::os::fd::AsRawFd;
        let connected = self.connected;
        self.socket.try_io(tokio::io::Interest::WRITABLE, || {
            send_x(
                self.socket.as_raw_fd(),
                self.items[from..]
                    .iter()
                    .map(|(payload, to)| (*payload, (!connected).then_some(*to))),
            )
        })
    }

    fn try_single(&self, index: usize) -> io::Result<()> {
        let (payload, to) = self.items[index];
        if self.connected {
            self.socket.try_send(payload).map(|_| ())
        } else {
            self.socket.try_send_to(payload, to).map(|_| ())
        }
    }

    async fn writable(&self) -> io::Result<()> {
        self.socket.writable().await
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        os::fd::AsRawFd,
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use super::*;

    /// The version gates and the kill switch, without touching the OS.
    #[test]
    fn policy_follows_the_switch_and_the_version_gates() {
        let all = (true, true);
        let gated = |value: Option<&str>, version| Policy::from_env(value).gated(version, all);
        assert_eq!(gated(None, Some((27, 2))), Policy::DEFAULT);
        assert_eq!(gated(Some("auto"), Some((26, 5))), Policy::DEFAULT);
        assert_eq!(gated(Some("off"), Some((27, 2))), Policy::OFF);
        assert_eq!(gated(Some("0"), Some((27, 2))), Policy::OFF);
        // macOS 13 loops per datagram in the kernel: no batch call at all.
        assert_eq!(gated(None, Some((13, 6))), Policy::OFF);
        // macOS 14.0–15.5: sends batch, receives stay single (soreceive_m_list lock leak).
        let sends_only = Policy {
            recv: false,
            ..Policy::DEFAULT
        };
        assert_eq!(gated(None, Some((14, 0))), sends_only);
        assert_eq!(gated(None, Some((15, 5))), sends_only);
        assert_eq!(gated(None, Some((15, 6))), Policy::DEFAULT);
        // An unreadable version turns everything off.
        assert_eq!(gated(None, None), Policy::OFF);
        // A missing symbol turns its own direction off.
        assert_eq!(
            Policy::DEFAULT.gated(Some((27, 2)), (false, true)),
            Policy {
                send_connected: false,
                send_wildcard: false,
                recv: true
            }
        );
        assert_eq!(
            Policy::DEFAULT.gated(Some((27, 2)), (true, false)),
            sends_only
        );
        // Lists switch single calls on, typos switch nothing on, and the gates still win.
        assert_eq!(
            gated(Some("connected"), Some((27, 2))),
            Policy {
                send_connected: true,
                ..Policy::OFF
            }
        );
        assert_eq!(gated(Some("send, recv"), Some((27, 2))), Policy::DEFAULT);
        assert_eq!(gated(Some("recieve"), Some((27, 2))), Policy::OFF);
        assert_eq!(gated(Some("recv"), Some((15, 5))), Policy::OFF);
    }

    /// Version strings as `kern.osproductversion` reports them.
    #[test]
    fn versions_parse() {
        assert_eq!(parse_version("27.2.1"), Some((27, 2)));
        assert_eq!(parse_version("15.6\0"), Some((15, 6)));
        assert_eq!(parse_version("14"), Some((14, 0)));
        assert_eq!(parse_version("x.1"), None);
        assert_eq!(parse_version(""), None);
        let here = os_version().expect("this Mac reports its version");
        assert!(here >= (13, 0), "{here:?}");
    }

    /// A scripted [`BatchSink`]: each call pops the next scripted result and records which
    /// kind of call it was and from which index.
    struct Script {
        results: Mutex<VecDeque<io::Result<usize>>>,
        calls: Mutex<Vec<(&'static str, usize)>>,
        waits: AtomicUsize,
    }

    impl Script {
        fn new(results: impl IntoIterator<Item = io::Result<usize>>) -> Self {
            Self {
                results: Mutex::new(results.into_iter().collect()),
                calls: Mutex::new(Vec::new()),
                waits: AtomicUsize::new(0),
            }
        }
        fn next(&self, kind: &'static str, index: usize) -> io::Result<usize> {
            self.calls.lock().expect("calls").push((kind, index));
            self.results
                .lock()
                .expect("results")
                .pop_front()
                .expect("the loop made more calls than scripted")
        }
    }

    impl BatchSink for Script {
        fn try_batch(&self, from: usize) -> io::Result<usize> {
            self.next("batch", from)
        }
        fn try_single(&self, index: usize) -> io::Result<()> {
            self.next("single", index).map(|_| ())
        }
        async fn writable(&self) -> io::Result<()> {
            self.waits.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    fn os(code: i32) -> io::Result<usize> {
        Err(io::Error::from_raw_os_error(code))
    }

    fn run(script: &Script, len: usize) -> Stopped {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime")
            .block_on(send_loop(script, len))
    }

    /// A short count resumes at the first unsent item.
    #[test]
    fn a_partial_send_resumes_where_it_stopped() {
        let script = Script::new([Ok(3), Ok(4), Ok(1)]);
        let stopped = run(&script, 8);
        assert_eq!(stopped.done, 8);
        assert!(stopped.error.is_none());
        assert_eq!(
            *script.calls.lock().expect("calls"),
            [("batch", 0), ("batch", 3), ("single", 7)]
        );
    }

    /// `EWOULDBLOCK` waits, then sends one item alone before batching again, so a socket that
    /// keeps refusing batches but takes plain sends cannot stall the loop.
    #[test]
    fn a_full_socket_waits_and_then_sends_one_alone() {
        let would_block = || Err(io::ErrorKind::WouldBlock.into());
        let script = Script::new([Ok(2), would_block(), would_block(), Ok(1), Ok(5)]);
        let stopped = run(&script, 8);
        assert_eq!(stopped.done, 8);
        assert_eq!(script.waits.load(Ordering::Relaxed), 2);
        assert_eq!(
            *script.calls.lock().expect("calls"),
            [
                ("batch", 0),
                ("batch", 2),
                ("single", 2),
                ("single", 2),
                ("batch", 3)
            ]
        );
    }

    /// `ENOBUFS` and `EMSGSIZE` on a call mean its first item failed alone: it is dropped (and
    /// reported), the rest still go out. `EINTR` retries the same call.
    #[test]
    fn a_per_datagram_error_drops_only_that_datagram() {
        let script = Script::new([
            Ok(3),
            os(libc::EMSGSIZE),
            os(libc::EINTR),
            Ok(2),
            os(libc::ENOBUFS),
            Ok(1),
        ]);
        let stopped = run(&script, 8);
        assert_eq!(stopped.done, 8);
        assert!(stopped.error.is_none());
        assert_eq!(
            stopped.dropped.and_then(|e| e.raw_os_error()),
            Some(libc::ENOBUFS)
        );
        assert_eq!(
            *script.calls.lock().expect("calls"),
            [
                ("batch", 0),
                ("batch", 3),
                ("batch", 4),
                ("batch", 4),
                ("batch", 6),
                ("single", 7)
            ]
        );
    }

    /// Any other error stops the loop at the first item it may concern. From a batch call the
    /// items after it may already have left; from a single send they have not.
    #[test]
    fn a_hard_error_stops_and_says_whether_a_prefix_may_have_left() {
        let script = Script::new([Ok(2), os(libc::EHOSTUNREACH)]);
        let stopped = run(&script, 8);
        assert_eq!(stopped.done, 2);
        assert!(stopped.maybe_sent);
        assert_eq!(
            stopped.error.and_then(|e| e.raw_os_error()),
            Some(libc::EHOSTUNREACH)
        );
        let script = Script::new([Ok(7), os(libc::ECONNREFUSED)]);
        let stopped = run(&script, 8);
        assert_eq!(stopped.done, 7);
        assert!(!stopped.maybe_sent, "the last item went out alone");
    }

    /// A pair of loopback sockets: a nonblocking receiver and a sender, connected or not.
    fn pair(connected: bool) -> (std::net::UdpSocket, std::net::UdpSocket, SocketAddr) {
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
        receiver.set_nonblocking(true).expect("nonblocking");
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind sender");
        let to = receiver.local_addr().expect("receiver address");
        if connected {
            sender.connect(to).expect("connect");
        }
        (receiver, sender, to)
    }

    /// Drain `receiver` with `recvmsg_x` until `want` datagrams arrived or it stays empty.
    fn drain(receiver: &std::net::UdpSocket, want: usize) -> (Vec<(Packet, SocketAddr)>, usize) {
        let mut pool = PacketBufPool::new(256);
        let mut buf = RecvBuf::default();
        let mut packets = Vec::new();
        let mut calls = 0;
        let mut idle = 0;
        while packets.len() < want && idle < 200 {
            calls += 1;
            match recv_x(
                receiver.as_raw_fd(),
                &mut buf,
                &mut pool,
                &mut packets,
                |s| s,
            ) {
                Ok(_) => idle = 0,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    idle += 1;
                    // sleep: loopback delivery is asynchronous; give it a moment, bounded by `idle`.
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(e) => panic!("recvmsg_x: {e}"),
            }
        }
        (packets, calls)
    }

    /// `send_x` then `recv_x` move 100 datagrams in order between two loopback sockets, in
    /// calls of more than one datagram, with the right source, on unconnected and connected
    /// senders (layout and semantics of both private calls).
    #[test]
    fn a_batch_round_trip_keeps_order_and_source() {
        for connected in [false, true] {
            let (receiver, sender, to) = pair(connected);
            let payloads: Vec<Vec<u8>> =
                (0..100u8).map(|i| vec![i; 100 + usize::from(i)]).collect();
            let mut done = 0;
            while done < payloads.len() {
                done += send_x(
                    sender.as_raw_fd(),
                    payloads[done..]
                        .iter()
                        .map(|p| (&p[..], (!connected).then_some(to))),
                )
                .expect("sendmsg_x");
            }
            let (packets, calls) = drain(&receiver, 100);
            assert_eq!(packets.len(), 100, "connected={connected}");
            assert!(
                calls < 100,
                "recvmsg_x returned one datagram per call ({calls} calls)"
            );
            for (i, (packet, source)) in packets.iter().enumerate() {
                assert_eq!(&packet[..], &payloads[i][..]);
                assert_eq!(*source, sender.local_addr().expect("sender address"));
            }
        }
    }

    /// An oversize datagram in the middle of a batch: the kernel sends the prefix and returns
    /// its count, the next call fails with `EMSGSIZE` for that datagram alone, and the loop
    /// drops just it. Every other datagram arrives exactly once, in order.
    #[test]
    fn an_oversize_datagram_mid_batch_is_dropped_alone() {
        for connected in [false, true] {
            let (receiver, sender, to) = pair(connected);
            let tokio_rt = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .build()
                .expect("runtime");
            let payloads: Vec<Vec<u8>> = (0..8u8)
                .map(|i| {
                    if i == 3 {
                        vec![i; 70_000]
                    } else {
                        vec![i; 200]
                    }
                })
                .collect();
            let first = send_x(
                sender.as_raw_fd(),
                payloads
                    .iter()
                    .map(|p| (&p[..], (!connected).then_some(to))),
            )
            .expect("the prefix is sent");
            assert_eq!(
                first, 3,
                "connected={connected}: sendmsg_x stops before the oversize datagram"
            );
            let error = send_x(
                sender.as_raw_fd(),
                payloads[3..]
                    .iter()
                    .map(|p| (&p[..], (!connected).then_some(to))),
            )
            .expect_err("the oversize datagram fails alone");
            assert_eq!(error.raw_os_error(), Some(libc::EMSGSIZE));
            // The loop over the same items, through a tokio socket.
            let stopped = tokio_rt.block_on(async {
                sender.set_nonblocking(true).expect("nonblocking");
                let socket = tokio::net::UdpSocket::from_std(sender.try_clone().expect("clone"))
                    .expect("tokio socket");
                let items: Vec<(&[u8], SocketAddr)> =
                    payloads.iter().map(|p| (&p[..], to)).collect();
                let sink = SocketSink {
                    socket: &socket,
                    items: &items,
                    connected,
                };
                send_loop(&sink, items.len()).await
            });
            assert_eq!(stopped.done, 8);
            assert!(stopped.error.is_none());
            assert_eq!(
                stopped.dropped.and_then(|e| e.raw_os_error()),
                Some(libc::EMSGSIZE)
            );
            let (packets, _) = drain(&receiver, 10);
            let firsts: Vec<u8> = packets.iter().map(|(p, _)| p[0]).collect();
            assert_eq!(
                firsts,
                [0, 1, 2, 0, 1, 2, 4, 5, 6, 7],
                "connected={connected}"
            );
        }
    }

    /// At the send-buffer edge: with `SO_SNDBUF` just above one datagram, every datagram of a
    /// large batch still arrives once, whatever mix of short counts and `EWOULDBLOCK` the
    /// kernel returns, and the loop never spins without progress.
    #[test]
    fn the_send_buffer_edge_neither_stalls_nor_duplicates() {
        for connected in [false, true] {
            let (receiver, sender, to) = pair(connected);
            let size = 1400;
            socket2::SockRef::from(&sender)
                .set_send_buffer_size(size + 64)
                .expect("SO_SNDBUF");
            sender.set_nonblocking(true).expect("nonblocking");
            socket2::SockRef::from(&receiver)
                .set_recv_buffer_size(4 << 20)
                .expect("SO_RCVBUF");
            let payloads: Vec<Vec<u8>> = (0..512u32)
                .map(|i| {
                    let mut p = vec![0u8; size];
                    p[..4].copy_from_slice(&i.to_be_bytes());
                    p
                })
                .collect();
            let items: Vec<(&[u8], SocketAddr)> = payloads.iter().map(|p| (&p[..], to)).collect();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .expect("runtime");
            let stopped = rt.block_on(async {
                let socket = tokio::net::UdpSocket::from_std(sender).expect("tokio socket");
                let sink = SocketSink {
                    socket: &socket,
                    items: &items,
                    connected,
                };
                let send = tokio::time::timeout(
                    std::time::Duration::from_secs(20),
                    send_loop(&sink, items.len()),
                );
                send.await.expect("the loop finishes; no stall")
            });
            let (received, _) = drain(&receiver, items.len());
            assert_eq!(stopped.done, items.len(), "connected={connected}");
            assert!(stopped.error.is_none(), "{:?}", stopped.error);
            let mut seen: Vec<u32> = received
                .iter()
                .map(|(p, _)| u32::from_be_bytes(p[..4].try_into().expect("4 bytes")))
                .collect();
            let arrived = seen.len();
            seen.dedup();
            assert_eq!(
                seen.len(),
                arrived,
                "connected={connected}: a datagram arrived twice"
            );
            assert!(seen.windows(2).all(|w| w[0] < w[1]), "out of order");
            // Loopback may drop under a tiny buffer only as ENOBUFS, which the loop reports.
            if arrived < items.len() {
                assert!(
                    stopped.dropped.is_some(),
                    "connected={connected}: lost without an error"
                );
            }
        }
    }

    /// `recvmsg_x` does not flag truncation: a datagram larger than its buffer comes back with
    /// a length equal to the buffer, which `recv_into`'s caller must treat as truncated. A
    /// datagram that fits is reported with its exact length.
    #[test]
    fn a_datagram_that_fills_its_buffer_reads_as_truncated() {
        let recv = calls().recv.expect("recvmsg_x");
        let (receiver, sender, to) = pair(false);
        sender.send_to(&[7u8; 300], to).expect("send big");
        sender.send_to(&[9u8; 50], to).expect("send small");
        let mut a = [0u8; 100];
        let mut b = [0u8; 100];
        let mut received = [(0usize, None); 2];
        let mut got = 0;
        for _ in 0..200 {
            let buffers = [&mut a[..], &mut b[..]].into_iter().skip(got);
            match recv_into(recv, receiver.as_raw_fd(), buffers, &mut received[got..]) {
                Ok(n) => got += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => panic!("recvmsg_x: {e}"),
            }
            if got == 2 {
                break;
            }
            // sleep: loopback delivery is asynchronous; bounded by the loop count.
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert_eq!(got, 2);
        assert_eq!(
            received[0].0, 100,
            "the 300-byte datagram fills its 100-byte buffer"
        );
        assert_eq!(received[1].0, 50);
        // And `recv_x` drops the full one.
        sender
            .send_to(&[1u8; 5000], to)
            .expect("send oversize for a pool buffer");
        sender.send_to(&[2u8; 60], to).expect("send small");
        let (packets, _) = drain(&receiver, 1);
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].0.len(), 60);
    }
}
