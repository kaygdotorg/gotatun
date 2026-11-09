// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

//! Batched UDP I/O for macOS, behind the `macos-batch-io` feature (#260, owner 2026-11-09).
//!
//! # Why
//!
//! On macOS each WireGuard datagram used to cost one `sendto` and one `recvfrom` system call.
//! A J421 profile on the Mac VM put the send call alone at 37–42% of the sending engine's CPU,
//! while encryption was 3%. Darwin's kernel has two calls that move many datagrams per trap,
//! `sendmsg_x` and `recvmsg_x`. libsystem_kernel exports them, but they are not public API,
//! so this module treats them as optional:
//!
//! - It looks them up with `dlsym` once per process, so a system without them still links
//!   and runs.
//! - When a socket is bound, a `recvmsg_x` call on the fresh non-blocking socket must fail
//!   with `EWOULDBLOCK`. That proves the call exists and accepts our header layout without
//!   sending anything.
//! - `GOTATUN_MACOS_BATCH_UDP=0` (or `off`/`false`) forces the per-packet path at runtime.
//! - A batch call that later reports `ENOSYS`/`EOPNOTSUPP` turns batching off for the whole
//!   process, and the batch it was handling goes out one packet at a time.
//!
//! The path chosen is logged once per process. When batching is off, this module behaves like
//! the generic Unix implementation: one `sendto`/`recvfrom` per datagram.
//!
//! # Error semantics
//!
//! The per-packet path drops only the datagram whose send failed. The batch path keeps that
//! promise. A transient stop (`EWOULDBLOCK`, `ENOBUFS`, `EINTR`) after some datagrams went
//! out returns their count, and the next call continues from the first unsent one. Any
//! other error returns `-1` even when the datagrams before the failing one were already sent,
//! so the rest of that chunk (at most [`SEND_BATCH`]) is sent again one datagram at a time.
//! Only a datagram that fails on its own is dropped. The head of the chunk may go out twice,
//! and WireGuard's replay window discards the duplicates. Batching resumes with the next
//! chunk.
//!
//! Removing this module (and the feature) restores the generic implementation exactly.

use std::{
    ffi::{c_int, c_uint, c_void},
    io,
    mem::{self, MaybeUninit},
    net::SocketAddr,
    os::fd::AsRawFd,
    sync::{
        OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};

use socket2::SockAddr;
use tokio::io::Interest;

use crate::{
    packet::{Packet, PacketBufPool},
    udp::{UdpRecv, UdpSend},
};

/// Most datagrams handed to one `sendmsg_x` call.
///
/// The kernel clamps a call to `kern.ipc.maxsendmsgx` (256 by default), and the buffered
/// sender drains its queue in runs of this size. 64 covers a full congestion-window burst at
/// 1420-byte packets without holding the send task in one call for long.
pub(crate) const SEND_BATCH: usize = 64;

/// Most datagrams read by one `recvmsg_x` call.
///
/// Each slot holds one pool buffer (4 KiB), so this bounds the receive buffers parked in
/// [`RecvManyBuf`] at 128 KiB per socket.
pub(crate) const RECV_BATCH: usize = 32;

/// The environment variable that turns batching off at runtime.
const BATCH_ENV: &str = "GOTATUN_MACOS_BATCH_UDP";

/// One message header for `sendmsg_x`/`recvmsg_x`: Darwin's `struct msghdr_x`.
///
/// This is `struct msghdr` plus a trailing `msg_datalen`, which `recvmsg_x` sets to the
/// number of bytes received into that message. `sendmsg_x` ignores `msg_datalen`. The layout
/// is checked at bind time by the probe call (see [`probe_socket`]).
#[repr(C)]
#[derive(Clone, Copy)]
struct MsghdrX {
    /// Optional address: the destination for a send, filled with the source on a receive.
    msg_name: *mut c_void,
    /// Size of `msg_name`. On a receive the kernel writes back the size it used.
    msg_namelen: libc::socklen_t,
    /// Scatter/gather array.
    msg_iov: *mut libc::iovec,
    /// Number of elements in `msg_iov`.
    msg_iovlen: c_int,
    /// Ancillary data. Unused here (null).
    msg_control: *mut c_void,
    /// Length of `msg_control`.
    msg_controllen: libc::socklen_t,
    /// Flags on a received message. Not used: see [`recv_batch`] on truncation.
    msg_flags: c_int,
    /// Bytes received into this message (receive only).
    msg_datalen: usize,
}

impl MsghdrX {
    /// An empty header with every pointer null.
    const EMPTY: MsghdrX = MsghdrX {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: std::ptr::null_mut(),
        msg_iovlen: 0,
        msg_control: std::ptr::null_mut(),
        msg_controllen: 0,
        msg_flags: 0,
        msg_datalen: 0,
    };
}

/// Signature shared by `sendmsg_x` and `recvmsg_x`: `(fd, headers, count, flags) -> count`.
type MsgXFn = unsafe extern "C" fn(c_int, *const MsghdrX, c_uint, c_int) -> isize;

/// The two batch calls, once resolved.
#[derive(Clone, Copy)]
pub(crate) struct BatchFns {
    /// `sendmsg_x`: send many datagrams, returns how many went out.
    send: MsgXFn,
    /// `recvmsg_x`: receive many datagrams, returns how many arrived.
    recv: MsgXFn,
}

/// Per-socket batching state, shared by every clone of a [`super::UdpSocket`].
pub(crate) struct BatchState {
    /// The resolved calls, or `None` when this socket uses the per-packet path from the start.
    fns: Option<BatchFns>,
    /// Set when a batch call reported that it is unsupported. Checked before every batch.
    disabled: AtomicBool,
}

/// Process-wide switch, set when any socket's batch call reports "unsupported".
static PROCESS_DISABLED: AtomicBool = AtomicBool::new(false);

impl BatchState {
    /// Decide how a freshly bound, non-blocking socket does its I/O, and log the choice once.
    pub(crate) fn for_socket(socket: &socket2::Socket) -> Self {
        let fns = if batching_wanted() {
            resolve().and_then(|fns| match probe_socket(fns, socket.as_raw_fd()) {
                Ok(()) => Some(fns),
                Err(err) => {
                    log_choice_once(format_args!(
                        "macOS UDP: recvmsg_x probe failed ({err}); one datagram per call"
                    ));
                    None
                }
            })
        } else {
            None
        };
        if fns.is_some() {
            log_choice_once(format_args!(
                "macOS UDP: batched sendmsg_x/recvmsg_x (send {SEND_BATCH}, receive {RECV_BATCH})"
            ));
        } else if !batching_wanted() {
            log_choice_once(format_args!(
                "macOS UDP: {BATCH_ENV} turns batching off; one datagram per call"
            ));
        } else if resolve().is_none() {
            log_choice_once(format_args!(
                "macOS UDP: sendmsg_x/recvmsg_x not found; one datagram per call"
            ));
        }
        Self::with_fns(fns)
    }

    /// Build the state from an explicit probe result. Tests use this to force a failed probe.
    pub(crate) fn with_fns(fns: Option<BatchFns>) -> Self {
        Self {
            fns,
            disabled: AtomicBool::new(false),
        }
    }

    /// The batch calls, if this socket should batch right now.
    fn active(&self) -> Option<BatchFns> {
        if self.disabled.load(Ordering::Relaxed) || PROCESS_DISABLED.load(Ordering::Relaxed) {
            return None;
        }
        self.fns
    }

    /// Stop batching on this socket and in the whole process, after an "unsupported" error.
    fn disable(&self, err: &io::Error) {
        self.disabled.store(true, Ordering::Relaxed);
        if !PROCESS_DISABLED.swap(true, Ordering::Relaxed) {
            tracing::warn!("macOS UDP: batch call unsupported ({err}); one datagram per call");
        }
    }
}

/// Whether the runtime switch allows batching. Read once per process.
fn batching_wanted() -> bool {
    static WANTED: OnceLock<bool> = OnceLock::new();
    *WANTED.get_or_init(|| {
        !std::env::var(BATCH_ENV).is_ok_and(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "0" | "off" | "false" | "no"
            )
        })
    })
}

/// Log which UDP path this process uses, the first time a socket decides.
fn log_choice_once(message: std::fmt::Arguments<'_>) {
    static LOGGED: AtomicBool = AtomicBool::new(false);
    if !LOGGED.swap(true, Ordering::Relaxed) {
        tracing::info!("{message}");
    }
}

/// Look up `sendmsg_x` and `recvmsg_x` in the already loaded system libraries, once.
fn resolve() -> Option<BatchFns> {
    static FNS: OnceLock<Option<BatchFns>> = OnceLock::new();
    *FNS.get_or_init(|| {
        let send = lookup(c"sendmsg_x")?;
        let recv = lookup(c"recvmsg_x")?;
        Some(BatchFns { send, recv })
    })
}

/// Resolve one symbol from the default search scope, or `None` if it is absent.
fn lookup(name: &std::ffi::CStr) -> Option<MsgXFn> {
    // SAFETY: `name` is NUL-terminated and RTLD_DEFAULT searches the loaded images only.
    let ptr = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) };
    if ptr.is_null() {
        return None;
    }
    // SAFETY: both symbols are libsystem_kernel's system call wrappers, declared in XNU as
    // `ssize_t f(int, const struct msghdr_x *, u_int, int)`, which is exactly `MsgXFn`.
    Some(unsafe { mem::transmute::<*mut c_void, MsgXFn>(ptr) })
}

/// Check that `recvmsg_x` works on this socket without consuming anything real.
///
/// The socket was bound a moment ago and nobody knows its port yet, so it has nothing queued.
/// A working call on a non-blocking socket reports `EWOULDBLOCK`. Anything else (a missing
/// call, a rejected header) means the batch path must not be used. A datagram that does
/// arrive in that instant would be a stray one, and dropping it is harmless.
fn probe_socket(fns: BatchFns, fd: c_int) -> io::Result<()> {
    let mut byte = [0u8; 1];
    let mut name = MaybeUninit::<libc::sockaddr_storage>::zeroed();
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: byte.len(),
    };
    let header = MsghdrX {
        msg_name: name.as_mut_ptr().cast(),
        msg_namelen: socklen_of::<libc::sockaddr_storage>(),
        msg_iov: &mut iov,
        msg_iovlen: 1,
        ..MsghdrX::EMPTY
    };
    // SAFETY: one header, whose name and iovec point at live stack buffers of the stated sizes.
    let ret = unsafe { (fns.recv)(fd, &header, 1, libc::MSG_DONTWAIT) };
    if ret >= 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    if err.kind() == io::ErrorKind::WouldBlock {
        Ok(())
    } else {
        Err(err)
    }
}

/// `size_of::<T>()` as a `socklen_t`. Only used for socket address types, which are tiny.
fn socklen_of<T>() -> libc::socklen_t {
    libc::socklen_t::try_from(mem::size_of::<T>()).expect("a sockaddr fits in socklen_t")
}

/// Whether a batch call failed because the kernel does not offer it on this socket.
fn is_unsupported(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(libc::ENOSYS) | Some(libc::EOPNOTSUPP)
    )
}

/// Reusable send-side buffer: the encoded destination of each datagram in the batch.
#[derive(Default)]
pub struct SendManyBuf {
    /// One destination per datagram, already mapped for a dual-stack socket.
    targets: Vec<SockAddr>,
}

impl UdpSend for super::UdpSocket {
    type SendManyBuf = SendManyBuf;

    async fn send_to(&self, packet: Packet, dest: SocketAddr) -> io::Result<()> {
        self.send_one(&packet, dest).await
    }

    fn max_number_of_packets_to_send(&self) -> usize {
        if self.inner.batch.active().is_some() {
            SEND_BATCH
        } else {
            1
        }
    }

    async fn send_many_to(
        &self,
        buf: &mut SendManyBuf,
        packets: &mut Vec<(Packet, SocketAddr)>,
    ) -> io::Result<()> {
        let mut first_error = None;
        let mut start = 0;
        buf.targets.clear();
        buf.targets.extend(
            packets
                .iter()
                .map(|(_, dest)| SockAddr::from(self.map_dst(*dest))),
        );

        while start < packets.len() {
            let Some(fns) = self.inner.batch.active() else {
                break;
            };
            let end = packets.len().min(start + SEND_BATCH);
            let result = self
                .socket()
                .async_io(Interest::WRITABLE, || {
                    send_batch(
                        fns,
                        self.socket().as_raw_fd(),
                        &packets[start..end],
                        &buf.targets[start..end],
                    )
                })
                .await;
            match result {
                Ok(sent) if sent > 0 => start += sent,
                Err(err) if is_unsupported(&err) => {
                    self.inner.batch.disable(&err);
                    break;
                }
                other => {
                    // A non-transient error (or a call that sent nothing). XNU reports `-1`
                    // even when it already sent the datagrams before the failing one, so how
                    // far it got is unknown: send the rest of this chunk one at a time. Only
                    // a datagram that fails on its own is dropped; at most this chunk's head
                    // is sent twice, which the receiver's replay window discards.
                    if let Err(err) = other {
                        tracing::trace!("macOS UDP batch send failed: {err}");
                    }
                    for (packet, dest) in &packets[start..end] {
                        if let Err(err) = self.send_one(packet, *dest).await {
                            first_error.get_or_insert(err);
                        }
                    }
                    start = end;
                }
            }
        }

        // Per-packet path: batching is off, or was turned off in the middle of this batch.
        for (packet, dest) in packets.drain(..).skip(start) {
            if let Err(err) = self.send_to(packet, dest).await {
                first_error.get_or_insert(err);
            }
        }
        packets.clear();
        first_error.map_or(Ok(()), Err)
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        super::UdpSocket::local_addr(self).map(Some)
    }
}

impl super::UdpSocket {
    /// Send one datagram with `sendto`: the per-packet path, also used to retry inside a batch.
    async fn send_one(&self, packet: &Packet, dest: SocketAddr) -> io::Result<()> {
        self.socket().send_to(packet, self.map_dst(dest)).await?;
        Ok(())
    }
}

/// One non-blocking `sendmsg_x` call over `packets`. Returns how many datagrams went out.
///
/// `WouldBlock` comes back as an error, so tokio's `async_io` waits for the socket to become
/// writable and calls this again.
fn send_batch(
    fns: BatchFns,
    fd: c_int,
    packets: &[(Packet, SocketAddr)],
    targets: &[SockAddr],
) -> io::Result<usize> {
    debug_assert_eq!(packets.len(), targets.len());
    debug_assert!(packets.len() <= SEND_BATCH);
    let count = packets.len().min(targets.len()).min(SEND_BATCH);
    let mut iovs = [libc::iovec {
        iov_base: std::ptr::null_mut(),
        iov_len: 0,
    }; SEND_BATCH];
    let mut headers = [MsghdrX::EMPTY; SEND_BATCH];
    for (i, ((packet, _), target)) in packets.iter().zip(targets).take(count).enumerate() {
        iovs[i] = libc::iovec {
            // The kernel only reads through this pointer when sending.
            iov_base: packet.as_ptr().cast_mut().cast(),
            iov_len: packet.len(),
        };
        headers[i] = MsghdrX {
            msg_name: target.as_ptr().cast_mut().cast(),
            msg_namelen: target.len(),
            msg_iov: &mut iovs[i],
            msg_iovlen: 1,
            ..MsghdrX::EMPTY
        };
    }
    let count_arg = c_uint::try_from(count).expect("batch size fits in u_int");
    // SAFETY: `count` headers are initialised; each names a live socket address and one iovec
    // over a live packet buffer, all borrowed for the duration of this call.
    let ret = unsafe { (fns.send)(fd, headers.as_ptr(), count_arg, libc::MSG_DONTWAIT) };
    usize::try_from(ret).map_err(|_| io::Error::last_os_error())
}

/// Reusable receive-side buffer: pool buffers waiting for the next `recvmsg_x` call, and the
/// space for their source addresses.
///
/// Datagrams are received straight into pool buffers, so a received packet costs no copy.
/// Unused buffers stay here between calls, so the receive task does not ask the pool for
/// [`RECV_BATCH`] buffers on every wakeup.
pub struct RecvManyBuf {
    /// Empty pool buffers, at full length, ready to receive into.
    spares: Vec<Packet>,
    /// Source address slots, one per spare.
    names: Box<[libc::sockaddr_storage; RECV_BATCH]>,
}

impl Default for RecvManyBuf {
    fn default() -> Self {
        Self {
            spares: Vec::with_capacity(RECV_BATCH),
            // SAFETY: an all-zero `sockaddr_storage` is a valid (AF_UNSPEC) value.
            names: Box::new(unsafe { mem::zeroed() }),
        }
    }
}

/// What `recvmsg_x` reported for one message.
#[derive(Clone, Copy, Default)]
struct Received {
    /// Bytes written into the buffer.
    len: usize,
    /// Size of the source address the kernel wrote.
    namelen: libc::socklen_t,
}

impl UdpRecv for super::UdpSocket {
    type RecvManyBuf = RecvManyBuf;

    async fn recv_from(&mut self, pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        let mut buf = pool.get();
        let (n, src) = self.socket().recv_from(&mut buf).await?;
        buf.truncate(n);
        let src = self.map_src(src);
        Ok((buf, src))
    }

    async fn recv_many_from(
        &mut self,
        recv_buf: &mut RecvManyBuf,
        pool: &mut PacketBufPool,
        packets: &mut Vec<(Packet, SocketAddr)>,
    ) -> io::Result<()> {
        let Some(fns) = self.inner.batch.active() else {
            let (packet, src) = self.recv_from(pool).await?;
            packets.push((packet, src));
            return Ok(());
        };

        while recv_buf.spares.len() < RECV_BATCH {
            recv_buf.spares.push(pool.get());
        }
        let mut received = [Received::default(); RECV_BATCH];
        let fd = self.socket().as_raw_fd();
        let RecvManyBuf { spares, names } = recv_buf;
        let result = self
            .socket()
            .async_io(Interest::READABLE, || {
                recv_batch(fns, fd, spares, names, &mut received)
            })
            .await;

        let count = match result {
            Ok(count) => count,
            Err(err) if is_unsupported(&err) => {
                self.inner.batch.disable(&err);
                let (packet, src) = self.recv_from(pool).await?;
                packets.push((packet, src));
                return Ok(());
            }
            Err(err) => return Err(err),
        };

        let map_ipv4_to_ipv6 = self.map_ipv4_to_ipv6;
        for (i, (mut packet, info)) in recv_buf.spares.drain(..count).zip(received).enumerate() {
            let Some(src) = source_addr(&recv_buf.names[i], info.namelen) else {
                tracing::trace!("macOS UDP: datagram without an IP source");
                continue;
            };
            packet.truncate(info.len);
            packets.push((packet, super::map_src_addr(map_ipv4_to_ipv6, src)));
        }
        Ok(())
    }
}

/// Decode the source address `recvmsg_x` wrote into `name`, or `None` if it is not IPv4/IPv6
/// or shorter than its family requires.
fn source_addr(name: &libc::sockaddr_storage, len: libc::socklen_t) -> Option<SocketAddr> {
    let len = usize::try_from(len).ok()?;
    match c_int::from(name.ss_family) {
        libc::AF_INET if len >= mem::size_of::<libc::sockaddr_in>() => {
            // SAFETY: the family says this storage holds a `sockaddr_in`, which is smaller
            // than and alignment-compatible with `sockaddr_storage`.
            let sin = unsafe { &*std::ptr::from_ref(name).cast::<libc::sockaddr_in>() };
            let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            Some(SocketAddr::from((ip, u16::from_be(sin.sin_port))))
        }
        libc::AF_INET6 if len >= mem::size_of::<libc::sockaddr_in6>() => {
            // SAFETY: as above, for `sockaddr_in6`.
            let sin6 = unsafe { &*std::ptr::from_ref(name).cast::<libc::sockaddr_in6>() };
            let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            Some(SocketAddr::V6(std::net::SocketAddrV6::new(
                ip,
                u16::from_be(sin6.sin6_port),
                sin6.sin6_flowinfo,
                sin6.sin6_scope_id,
            )))
        }
        _ => None,
    }
}

/// One non-blocking `recvmsg_x` call into `spares`. Returns how many datagrams arrived and
/// records each one's length and source size in `received`.
///
/// A datagram longer than its pool buffer arrives cut to the buffer, exactly as with
/// `recvfrom`: on macOS 26.5 `recvmsg_x` reports neither `MSG_TRUNC` nor a longer
/// `msg_datalen` for it (J434 measured this), so it cannot be told apart here. Such a datagram
/// cannot be a valid WireGuard message and fails authentication further up.
fn recv_batch(
    fns: BatchFns,
    fd: c_int,
    spares: &mut [Packet],
    names: &mut [libc::sockaddr_storage; RECV_BATCH],
    received: &mut [Received; RECV_BATCH],
) -> io::Result<usize> {
    let count = spares.len().min(RECV_BATCH);
    let mut iovs = [libc::iovec {
        iov_base: std::ptr::null_mut(),
        iov_len: 0,
    }; RECV_BATCH];
    let mut headers = [MsghdrX::EMPTY; RECV_BATCH];
    for (i, (packet, name)) in spares
        .iter_mut()
        .zip(names.iter_mut())
        .take(count)
        .enumerate()
    {
        iovs[i] = libc::iovec {
            iov_base: packet.as_mut_ptr().cast(),
            iov_len: packet.len(),
        };
        headers[i] = MsghdrX {
            msg_name: std::ptr::from_mut(name).cast(),
            msg_namelen: socklen_of::<libc::sockaddr_storage>(),
            msg_iov: &mut iovs[i],
            msg_iovlen: 1,
            ..MsghdrX::EMPTY
        };
    }
    let count_arg = c_uint::try_from(count).expect("batch size fits in u_int");
    // SAFETY: `count` headers are initialised; each points at a live, writable pool buffer and
    // a live `sockaddr_storage`, all exclusively borrowed for the duration of this call.
    let ret = unsafe { (fns.recv)(fd, headers.as_mut_ptr(), count_arg, libc::MSG_DONTWAIT) };
    let got = usize::try_from(ret).map_err(|_| io::Error::last_os_error())?;
    let got = got.min(count);
    for ((slot, header), packet) in received
        .iter_mut()
        .zip(&headers)
        .zip(spares.iter())
        .take(got)
    {
        // Never trust a length beyond the buffer we offered.
        *slot = Received {
            len: header.msg_datalen.min(packet.len()),
            namelen: header.msg_namelen,
        };
    }
    Ok(got)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::time::timeout;

    use super::*;
    use crate::udp::socket::{SockOpt, UdpSocket, UdpSocketState};

    /// Bind a loopback socket whose batching state is chosen by the test.
    fn bind_with(addr: SocketAddr, fns: Option<BatchFns>) -> UdpSocket {
        let socket = UdpSocket::bind(addr, SockOpt::default()).unwrap();
        let state = Arc::try_unwrap(socket.inner)
            .ok()
            .expect("fresh socket is unshared");
        UdpSocket {
            inner: Arc::new(UdpSocketState {
                socket: state.socket,
                batch: BatchState::with_fns(fns),
            }),
            map_ipv4_to_ipv6: socket.map_ipv4_to_ipv6,
        }
    }

    fn payload(i: usize) -> Packet {
        Packet::from_bytes(format!("datagram {i:03}").as_bytes().into())
    }

    /// Send `n` numbered datagrams from `tx` to `rx` with `send_many_to`, then read them all
    /// with `recv_many_from`, check every one arrived intact and in order, and return how
    /// many receive calls that took.
    async fn round_trip(tx: &UdpSocket, rx: &mut UdpSocket, n: usize) -> usize {
        let dest = rx.local_addr().unwrap();
        let mut send_buf = SendManyBuf::default();
        let max = tx.max_number_of_packets_to_send();
        let all: Vec<_> = (0..n).map(|i| (payload(i), dest)).collect();
        for chunk in all.chunks(max) {
            let mut batch = chunk.to_vec();
            tx.send_many_to(&mut send_buf, &mut batch).await.unwrap();
            assert!(batch.is_empty(), "send_many_to must drain on success");
        }

        let mut pool = PacketBufPool::new(4);
        let mut recv_buf = RecvManyBuf::default();
        let mut got = vec![];
        let mut calls = 0;
        while got.len() < n {
            let mut out = vec![];
            timeout(
                Duration::from_secs(2),
                rx.recv_many_from(&mut recv_buf, &mut pool, &mut out),
            )
            .await
            .expect("datagrams arrive")
            .unwrap();
            calls += 1;
            for (packet, src) in out {
                assert_eq!(src, tx.local_addr().unwrap());
                let text = std::str::from_utf8(&packet).unwrap();
                got.push(
                    text.trim_start_matches("datagram ")
                        .parse::<usize>()
                        .unwrap(),
                );
            }
        }
        assert_eq!(got, (0..n).collect::<Vec<_>>());
        calls
    }

    fn loopback_v4() -> SocketAddr {
        (Ipv4Addr::LOCALHOST, 0).into()
    }

    #[test]
    fn msghdr_x_layout_matches_darwin() {
        // XNU's struct msghdr_x on LP64: 8 + 4(+4) + 8 + 4(+4) + 8 + 4 + 4 + 8.
        assert_eq!(mem::size_of::<MsghdrX>(), 56);
        assert_eq!(mem::offset_of!(MsghdrX, msg_iov), 16);
        assert_eq!(mem::offset_of!(MsghdrX, msg_control), 32);
        assert_eq!(mem::offset_of!(MsghdrX, msg_datalen), 48);
    }

    #[test]
    fn batch_calls_resolve_on_this_system() {
        assert!(
            resolve().is_some(),
            "libsystem_kernel exports sendmsg_x/recvmsg_x"
        );
    }

    #[tokio::test]
    async fn probe_accepts_a_fresh_socket() {
        let socket = bind_with(loopback_v4(), None);
        probe_socket(resolve().unwrap(), socket.socket().as_raw_fd()).unwrap();
    }

    #[tokio::test]
    async fn batched_round_trip_delivers_every_datagram_in_order() {
        let fns = resolve();
        let tx = bind_with(loopback_v4(), fns);
        let mut rx = bind_with(loopback_v4(), fns);
        assert_eq!(tx.max_number_of_packets_to_send(), SEND_BATCH);
        let calls = round_trip(&tx, &mut rx, 3 * SEND_BATCH + 5).await;
        assert!(
            calls < 3 * SEND_BATCH + 5,
            "recvmsg_x must return more than one datagram per call ({calls} calls)"
        );
    }

    /// The owner's condition: when the probe fails, the socket falls back to one datagram per
    /// call and still delivers everything.
    #[tokio::test]
    async fn failed_probe_falls_back_to_one_datagram_per_call() {
        let tx = bind_with(loopback_v4(), None);
        let mut rx = bind_with(loopback_v4(), None);
        assert_eq!(tx.max_number_of_packets_to_send(), 1);
        let calls = round_trip(&tx, &mut rx, 40).await;
        assert_eq!(calls, 40, "the fallback reads one datagram per call");
    }

    #[tokio::test]
    async fn probe_rejects_a_call_that_fails() {
        let socket = bind_with(loopback_v4(), None);
        let broken = BatchFns {
            send: fail_enosys,
            recv: fail_enosys,
        };
        let err = probe_socket(broken, socket.socket().as_raw_fd()).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ENOSYS));
    }

    /// A stand-in batch call that fails as if the kernel lacked it.
    unsafe extern "C" fn fail_enosys(_: c_int, _: *const MsghdrX, _: c_uint, _: c_int) -> isize {
        // SAFETY: `__error` returns this thread's errno slot.
        unsafe { *libc::__error() = libc::ENOSYS };
        -1
    }

    /// A batch call that starts failing with ENOSYS is turned off, and the batch it was
    /// handling still arrives through the per-packet path. Only the sender is broken here, so
    /// the process-wide switch is tested on a socket of its own.
    #[tokio::test]
    async fn unsupported_send_at_runtime_falls_back_without_loss() {
        let real = resolve().unwrap();
        let state = BatchState::with_fns(Some(BatchFns {
            send: fail_enosys,
            recv: real.recv,
        }));
        let tx = bind_with(loopback_v4(), None);
        let tx = UdpSocket {
            inner: Arc::new(UdpSocketState {
                socket: Arc::try_unwrap(tx.inner).ok().unwrap().socket,
                batch: state,
            }),
            map_ipv4_to_ipv6: false,
        };
        let rx = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let dest = rx.local_addr().unwrap();
        let mut batch: Vec<_> = (0..10).map(|i| (payload(i), dest)).collect();
        tx.send_many_to(&mut SendManyBuf::default(), &mut batch)
            .await
            .unwrap();
        assert!(
            tx.inner.batch.active().is_none(),
            "ENOSYS turns batching off"
        );
        let mut buf = [0u8; 64];
        for i in 0..10 {
            let n = timeout(Duration::from_secs(2), rx.recv(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&buf[..n], payload(i).as_ref());
        }
        // Undo the process-wide switch so other tests in this binary keep batching.
        PROCESS_DISABLED.store(false, Ordering::Relaxed);
    }

    /// One unroutable destination in the middle of a batch drops only that datagram.
    #[tokio::test]
    async fn a_bad_destination_drops_only_its_own_datagram() {
        let tx = bind_with(loopback_v4(), resolve());
        let rx = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let good = rx.local_addr().unwrap();
        // Broadcast without SO_BROADCAST: the kernel refuses this one datagram.
        let bad: SocketAddr = (Ipv4Addr::BROADCAST, good.port()).into();
        let mut batch: Vec<_> = (0..8)
            .map(|i| (payload(i), if i == 3 { bad } else { good }))
            .collect();
        let result = tx
            .send_many_to(&mut SendManyBuf::default(), &mut batch)
            .await;
        let err = result.expect_err("the bad datagram's error is reported");
        assert!(batch.is_empty());
        // Read until quiet. The datagrams before the failing one may arrive twice (see the
        // module docs); what matters is that every good datagram arrives, in order.
        let mut buf = [0u8; 64];
        let mut got = vec![];
        while let Ok(Ok(n)) = timeout(Duration::from_millis(300), rx.recv(&mut buf)).await {
            let text = std::str::from_utf8(&buf[..n]).unwrap();
            got.push(
                text.trim_start_matches("datagram ")
                    .parse::<usize>()
                    .unwrap(),
            );
        }
        let mut first_seen = got.clone();
        let mut seen = std::collections::HashSet::new();
        first_seen.retain(|i| seen.insert(*i));
        eprintln!("bad destination: error {err}; received {got:?}");
        assert_eq!(first_seen, vec![0, 1, 2, 4, 5, 6, 7]);
        assert!(
            got.len() - first_seen.len() <= 3,
            "only the chunk's head may be sent twice"
        );
    }

    #[tokio::test]
    async fn batched_receive_reports_ipv6_sources() {
        let fns = resolve();
        let tx = bind_with((Ipv6Addr::LOCALHOST, 0).into(), fns);
        let mut rx = bind_with((Ipv6Addr::LOCALHOST, 0).into(), fns);
        round_trip(&tx, &mut rx, 20).await;
    }

    /// A datagram longer than a pool buffer arrives cut to the buffer, as on the per-packet
    /// path, and does not disturb the datagram after it.
    #[tokio::test]
    async fn oversized_datagram_is_cut_like_recvfrom_and_the_next_is_intact() {
        let mut rx = bind_with(loopback_v4(), resolve());
        let tx = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let dest = rx.local_addr().unwrap();
        tx.send_to(&[7u8; 6000], dest).await.unwrap();
        tx.send_to(b"small", dest).await.unwrap();
        let mut pool = PacketBufPool::new(4);
        let mut recv_buf = RecvManyBuf::default();
        let mut out = vec![];
        while out.len() < 2 {
            timeout(
                Duration::from_secs(2),
                rx.recv_many_from(&mut recv_buf, &mut pool, &mut out),
            )
            .await
            .unwrap()
            .unwrap();
        }
        assert_eq!(out.len(), 2);
        assert_eq!(&out[0].0[..], &[7u8; 4096][..]);
        assert_eq!(&out[1].0[..], b"small");
    }
}
