// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

//! Batched UDP sends for macOS, behind the `macos-batch-io` feature (#260, owner 2026-11-09).
//!
//! # Why
//!
//! On macOS each WireGuard datagram used to cost one `sendto` system call. A J421 profile on
//! the Mac VM put that call alone at 37–42% of the sending engine's CPU, while encryption was
//! 3%. Darwin's kernel can send many datagrams per trap with `sendmsg_x`. libsystem_kernel
//! exports it (and its sibling `recvmsg_x`), but neither is public API, so this module treats
//! them as optional:
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
//! the generic Unix implementation: one `sendto` per datagram.
//!
//! # Receives stay one datagram per call
//!
//! J434 also tried `recvmsg_x` for receiving, with a fixed 32 and with a count that follows
//! arrivals. In both `sample` profiles on the Mac VM it cost more than `recvfrom` in every
//! one of 8 comparisons (for example 896 against 359 samples on the ACK side of one TCP
//! flow, 1276 against 858 on the data side). So receives use `recvfrom`, and `recvmsg_x`
//! serves only as the harmless probe.
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

/// The environment variable that turns batching off at runtime.
const BATCH_ENV: &str = "GOTATUN_MACOS_BATCH_UDP";

/// One message header for `sendmsg_x`/`recvmsg_x`: Darwin's `struct msghdr_x`.
///
/// This is `struct msghdr` plus a trailing `msg_datalen`, which `recvmsg_x` sets to the
/// number of bytes received into that message. `sendmsg_x` ignores `msg_datalen`. The probe
/// (see [`probe_socket`]) passes this layout to the kernel at bind time.
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
    /// Flags on a received message. Unused here.
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
    /// `recvmsg_x`: receive many datagrams. Used only by the bind-time probe.
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
                "macOS UDP: batched sendmsg_x (up to {SEND_BATCH} datagrams per call)"
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

/// Receives stay one `recvfrom` per datagram: batching them measured slower (module docs).
impl UdpRecv for super::UdpSocket {
    type RecvManyBuf = ();

    async fn recv_from(&mut self, pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        let mut buf = pool.get();
        let (n, src) = self.socket().recv_from(&mut buf).await?;
        buf.truncate(n);
        let src = self.map_src(src);
        Ok((buf, src))
    }
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

    /// Send `n` numbered datagrams from `tx` to `rx` with `send_many_to` in runs of the
    /// socket's maximum, then read them all with `recv_from` and check every one arrived intact,
    /// from `tx`, and in order.
    async fn round_trip(tx: &UdpSocket, rx: &mut UdpSocket, n: usize) {
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
        let mut got = vec![];
        while got.len() < n {
            let (packet, src) = timeout(Duration::from_secs(2), rx.recv_from(&mut pool))
                .await
                .expect("datagrams arrive")
                .unwrap();
            assert_eq!(src, tx.local_addr().unwrap());
            got.push(number(&packet));
        }
        assert_eq!(got, (0..n).collect::<Vec<_>>());
    }

    /// The number in a datagram made by [`payload`].
    fn number(bytes: &[u8]) -> usize {
        let text = std::str::from_utf8(bytes).unwrap();
        text.trim_start_matches("datagram ").parse().unwrap()
    }

    /// `sendmsg_x` calls made through [`counting_send`].
    static COUNTED_SENDS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    /// The real `sendmsg_x`, counted, so a test can prove it sent many datagrams per call.
    unsafe extern "C" fn counting_send(
        fd: c_int,
        headers: *const MsghdrX,
        count: c_uint,
        flags: c_int,
    ) -> isize {
        COUNTED_SENDS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: the caller's arguments are passed through unchanged.
        unsafe { (resolve().unwrap().send)(fd, headers, count, flags) }
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
        let real = resolve().unwrap();
        let fns = BatchFns {
            send: counting_send,
            recv: real.recv,
        };
        let tx = bind_with(loopback_v4(), Some(fns));
        let mut rx = bind_with(loopback_v4(), None);
        assert_eq!(tx.max_number_of_packets_to_send(), SEND_BATCH);
        let n = 3 * SEND_BATCH + 5;
        round_trip(&tx, &mut rx, n).await;
        let calls = COUNTED_SENDS.load(Ordering::Relaxed);
        assert!(
            (4..n / 4).contains(&calls),
            "sendmsg_x must carry many datagrams per call ({calls} calls for {n})"
        );
    }

    /// The owner's condition: when the probe fails, the socket falls back to one datagram per
    /// call and still delivers everything. A failed probe leaves no batch call to make, so
    /// every datagram goes through `sendto`.
    #[tokio::test]
    async fn failed_probe_falls_back_to_one_datagram_per_call() {
        let tx = bind_with(loopback_v4(), None);
        let mut rx = bind_with(loopback_v4(), None);
        assert!(tx.inner.batch.active().is_none());
        assert_eq!(tx.max_number_of_packets_to_send(), 1);
        round_trip(&tx, &mut rx, 40).await;
        // A caller that ignores the maximum still gets every datagram, one call each.
        let dest = rx.local_addr().unwrap();
        let mut batch: Vec<_> = (0..10).map(|i| (payload(i), dest)).collect();
        tx.send_many_to(&mut SendManyBuf::default(), &mut batch)
            .await
            .unwrap();
        let mut pool = PacketBufPool::new(4);
        for i in 0..10 {
            let (packet, _) = timeout(Duration::from_secs(2), rx.recv_from(&mut pool))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(number(&packet), i);
        }
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
            got.push(number(&buf[..n]));
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

    /// Batched sends to IPv6 destinations arrive intact and in order.
    #[tokio::test]
    async fn batched_send_over_ipv6() {
        let tx = bind_with((Ipv6Addr::LOCALHOST, 0).into(), resolve());
        let mut rx = bind_with((Ipv6Addr::LOCALHOST, 0).into(), None);
        round_trip(&tx, &mut rx, 70).await;
    }

    /// A dual-stack socket maps IPv4 destinations to IPv6 before a batched send.
    #[tokio::test]
    async fn batched_send_from_dual_stack_reaches_ipv4() {
        let opts = SockOpt {
            only_v6: Some(false),
            ..SockOpt::default()
        };
        let dual = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0).into(), opts).unwrap();
        assert!(dual.inner.batch.active().is_some(), "the probe passes here");
        let rx = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let dest = rx.local_addr().unwrap();
        let mut batch: Vec<_> = (0..5).map(|i| (payload(i), dest)).collect();
        dual.send_many_to(&mut SendManyBuf::default(), &mut batch)
            .await
            .unwrap();
        let mut buf = [0u8; 64];
        for i in 0..5 {
            let n = timeout(Duration::from_secs(2), rx.recv(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(number(&buf[..n]), i);
        }
    }
}
