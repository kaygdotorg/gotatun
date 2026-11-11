// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

//! Bounded macOS UDP send batching with a runtime-checked private syscall.
//!
//! The feature is opt-in at build time because `sendmsg_x` is private. This module resolves the
//! system symbols at runtime and probes a fresh nonblocking socket before using them. If either
//! symbol or the probe is unavailable, a batch call reports an unsupported error, or
//! `GOTATUN_MACOS_BATCH_UDP` is set to `0`, sends use Tokio's per-datagram path instead. Receives
//! stay on the ordinary one-datagram path.
//!
//! Each batch is limited to [`SEND_BATCH`] messages. When the private call cannot report how far
//! it progressed, the current short batch is retried one datagram at a time; an already-sent
//! prefix can therefore be duplicated. The protocol rejects duplicate packets through its replay
//! window, and this bound limits that retry to one small run.
//!
//! A bounded FIFO sends batches on one OS thread so synchronous syscalls yield the packet executor
//! between batches. The one-request channel adds no unbounded backlog.

use std::{
    ffi::{CStr, c_int, c_uint, c_void},
    io,
    mem::{self, MaybeUninit},
    net::SocketAddr,
    os::fd::AsRawFd,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
};

use socket2::SockAddr;
use tokio::{
    io::Interest,
    sync::{mpsc, oneshot},
};

#[cfg(test)]
use std::sync::atomic::AtomicUsize;

use crate::{
    packet::{Packet, PacketBufPool},
    udp::{UdpRecv, UdpSend},
};

/// Maximum datagrams passed to one `sendmsg_x` call.
///
/// This caps the time spent in one syscall and the temporary header arrays while amortizing the
/// trap cost across a useful run. The queue remains separately bounded by the device pipeline.
pub(crate) const SEND_BATCH: usize = 64;

/// Runtime switch for falling back to one datagram per socket send.
const BATCH_ENV: &str = "GOTATUN_MACOS_BATCH_UDP";

/// Darwin's LP64 `struct msghdr_x`, used by the private send and receive calls.
///
/// The trailing data length is present even for sends. The runtime probe checks this layout on
/// the socket before the batched path is enabled.
#[repr(C)]
#[derive(Clone, Copy)]
struct MsghdrX {
    /// Optional address: the destination for a send, filled with the source on a receive.
    msg_name: *mut c_void,
    /// Size of `msg_name`.
    msg_namelen: libc::socklen_t,
    /// Scatter/gather array for the datagram payload.
    msg_iov: *mut libc::iovec,
    /// Number of elements in `msg_iov`.
    msg_iovlen: c_int,
    /// Ancillary data pointer, unused by this module.
    msg_control: *mut c_void,
    /// Size of `msg_control`.
    msg_controllen: libc::socklen_t,
    /// Receive flags, unused by this module.
    msg_flags: c_int,
    /// Number of bytes in this datagram on receive; ignored on send.
    msg_datalen: usize,
}

impl MsghdrX {
    /// An empty header whose unused pointers and fields start at zero.
    const EMPTY: Self = Self {
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

/// C signature for the send call, whose message array is read-only.
type SendMsgXFn = unsafe extern "C" fn(c_int, *const MsghdrX, c_uint, c_int) -> isize;

/// C signature for the receive call, whose message array may be updated by the kernel.
type RecvMsgXFn = unsafe extern "C" fn(c_int, *mut MsghdrX, c_uint, c_int) -> isize;

/// Runtime-resolved macOS batch calls.
#[derive(Clone, Copy)]
struct BatchFns {
    /// Sends one or more datagrams from an array of message headers.
    send: SendMsgXFn,
    /// Probes whether the kernel accepts the message-header layout.
    recv: RecvMsgXFn,
}

/// Owns one bounded request while the macOS sender thread calls `sendmsg_x`.
struct SendBatchRequest {
    /// Private syscall functions selected by the socket's runtime probe.
    fns: BatchFns,
    /// Socket descriptor kept alive by the sending socket until its request completes.
    fd: c_int,
    /// The ordered packet list returned to the async caller after the syscall.
    packets: Vec<(Packet, SocketAddr)>,
    /// Mapped destinations returned so the caller can reuse their allocation.
    targets: Vec<SockAddr>,
    /// Start of the current bounded batch within `packets` and `targets`.
    start: usize,
    /// End of the current bounded batch within `packets` and `targets`.
    end: usize,
    /// Returns the syscall result and the owned buffers to the async caller.
    response: oneshot::Sender<SendBatchResponse>,
}

/// Returns the batch result and reusable buffers to the socket task.
struct SendBatchResponse {
    /// Number of datagrams accepted by the socket, or the syscall error.
    result: io::Result<usize>,
    /// Original packet ownership, unchanged by the syscall.
    packets: Vec<(Packet, SocketAddr)>,
    /// Mapped destinations, retained for the next batch.
    targets: Vec<SockAddr>,
}

/// Runs serialized private UDP batch syscalls away from the packet executor.
///
/// Its one-message channel keeps work bounded. Dropping the last sender closes the channel and
/// lets the OS thread leave its blocking receive loop.
struct SendWorker {
    /// One queued batch at most, so a stalled syscall cannot build a second hidden backlog.
    sender: mpsc::Sender<SendBatchRequest>,
    /// Keeps the thread handle available for diagnostics and detaches it on worker drop.
    _thread: JoinHandle<()>,
    /// Test-only count used to prove sends reach this worker through the real socket path.
    #[cfg(test)]
    calls: Arc<AtomicUsize>,
}

impl SendWorker {
    /// Start a single OS thread that sends each batch then returns its packet buffers.
    fn new() -> io::Result<Self> {
        let (sender, mut receiver) = mpsc::channel(1);
        #[cfg(test)]
        let calls = Arc::new(AtomicUsize::new(0));
        #[cfg(test)]
        let worker_calls = Arc::clone(&calls);
        let worker = thread::Builder::new()
            .name("gotatun-macos-udp-send".to_owned())
            .spawn(move || {
                while let Some(request) = receiver.blocking_recv() {
                    #[cfg(test)]
                    worker_calls.fetch_add(1, Ordering::Relaxed);
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        send_batch(
                            request.fns,
                            request.fd,
                            &request.packets[request.start..request.end],
                            &request.targets[request.start..request.end],
                        )
                    }))
                    .unwrap_or_else(|_| Err(io::Error::other("macOS UDP send worker panicked")));
                    let _ = request.response.send(SendBatchResponse {
                        result,
                        packets: request.packets,
                        targets: request.targets,
                    });
                }
            })?;
        Ok(Self {
            sender,
            _thread: worker,
            #[cfg(test)]
            calls,
        })
    }

    /// Send one bounded batch on the worker, waiting for socket readiness without blocking the
    /// async executor. A `WouldBlock` result clears Tokio's stale writable notification and retries.
    async fn send_batch(
        &self,
        socket: &tokio::net::UdpSocket,
        fns: BatchFns,
        fd: c_int,
        packets: &mut Vec<(Packet, SocketAddr)>,
        targets: &mut Vec<SockAddr>,
        start: usize,
        end: usize,
    ) -> io::Result<usize> {
        loop {
            socket.writable().await?;
            let (response, reply) = oneshot::channel();
            let request = SendBatchRequest {
                fns,
                fd,
                packets: std::mem::take(packets),
                targets: std::mem::take(targets),
                start,
                end,
                response,
            };
            let request = match self.sender.send(request).await {
                Ok(()) => {
                    let response = reply.await.map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "macOS UDP send worker stopped before replying",
                        )
                    })?;
                    *packets = response.packets;
                    *targets = response.targets;
                    response.result
                }
                Err(error) => {
                    let request = error.0;
                    *packets = request.packets;
                    *targets = request.targets;
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "macOS UDP send worker stopped before accepting a batch",
                    ));
                }
            };
            match request {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    let _ = socket.try_io(Interest::WRITABLE, || {
                        Err::<(), _>(io::ErrorKind::WouldBlock.into())
                    });
                }
                result => {
                    tokio::task::yield_now().await;
                    return result;
                }
            }
        }
    }
}

/// Batching state shared by every clone of one [`super::UdpSocket`].
pub(crate) struct BatchState {
    /// The resolved calls, or `None` when this socket starts on per-datagram sends.
    fns: Option<BatchFns>,
    /// A bounded sender thread created only after the runtime probe enables batching.
    send_worker: Option<SendWorker>,
    /// Set after a runtime error shows that this socket cannot use the private send call.
    disabled: AtomicBool,
}

impl BatchState {
    /// Select a send path for a newly bound socket and log the first decision once.
    pub(crate) fn for_socket(socket: &socket2::Socket) -> Self {
        if !batching_wanted() {
            log_choice_once(|| {
                tracing::info!("macOS UDP: {BATCH_ENV} disables batching; using per-datagram sends")
            });
            return Self::with_fns(None);
        }

        let Some(fns) = resolve() else {
            log_choice_once(|| {
                tracing::info!("macOS UDP: sendmsg_x unavailable; using per-datagram sends")
            });
            return Self::with_fns(None);
        };

        if let Err(error) = probe_socket(fns, socket.as_raw_fd()) {
            log_choice_once(|| {
                tracing::info!(
                    "macOS UDP: sendmsg_x probe failed ({error}); using per-datagram sends"
                )
            });
            return Self::with_fns(None);
        }

        log_choice_once(|| {
            tracing::info!("macOS UDP: using sendmsg_x batches of up to {SEND_BATCH} datagrams")
        });
        let mut state = Self::with_fns(Some(fns));
        match SendWorker::new() {
            Ok(worker) => state.send_worker = Some(worker),
            Err(error) => tracing::warn!(
                "macOS UDP: cannot start private batch sender thread ({error}); using in-executor sends"
            ),
        }
        state
    }

    /// Store a runtime result, with tests able to inject missing or failing calls.
    fn with_fns(fns: Option<BatchFns>) -> Self {
        Self {
            fns,
            send_worker: None,
            disabled: AtomicBool::new(false),
        }
    }

    /// Return the calls only while this socket remains eligible for batching.
    fn active(&self) -> Option<BatchFns> {
        (!self.disabled.load(Ordering::Relaxed))
            .then_some(self.fns)
            .flatten()
    }

    /// Permanently switch this socket to per-datagram sends after an unsupported-call error.
    fn disable(&self, error: &io::Error) {
        if !self.disabled.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                "macOS UDP: sendmsg_x is unsupported on this socket ({error}); using per-datagram sends"
            );
        }
    }
}

/// Decide whether the runtime switch allows batching for one process.
fn batching_wanted() -> bool {
    static WANTED: OnceLock<bool> = OnceLock::new();
    *WANTED.get_or_init(|| batch_switch_allows(std::env::var(BATCH_ENV).ok().as_deref()))
}

/// Interpret the runtime switch, treating only explicit off values as disabled.
fn batch_switch_allows(value: Option<&str>) -> bool {
    let Some(value) = value else {
        return true;
    };
    let value = value.trim();
    !["0", "off", "false", "no"]
        .iter()
        .any(|disabled| value.eq_ignore_ascii_case(disabled))
}

/// Log a path decision once so a process can report its selected send path without log noise.
fn log_choice_once(message: impl FnOnce()) {
    static LOGGED: AtomicBool = AtomicBool::new(false);
    if !LOGGED.swap(true, Ordering::Relaxed) {
        message();
    }
}

/// Resolve both private calls once; a partial result is not enough to enable batching.
fn resolve() -> Option<BatchFns> {
    static FNS: OnceLock<Option<BatchFns>> = OnceLock::new();
    *FNS.get_or_init(|| {
        let send = lookup_send(c"sendmsg_x")?;
        let recv = lookup_recv(c"recvmsg_x")?;
        Some(BatchFns { send, recv })
    })
}

/// Find the send symbol in the current process and convert it to its documented C signature.
fn lookup_send(name: &CStr) -> Option<SendMsgXFn> {
    // SAFETY: `name` is NUL-terminated and RTLD_DEFAULT searches already loaded images.
    let symbol = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) };
    if symbol.is_null() {
        return None;
    }
    // SAFETY: the private system entry point uses `(int, const msghdr_x *, u_int, int)`.
    Some(unsafe { mem::transmute::<*mut c_void, SendMsgXFn>(symbol) })
}

/// Find the receive symbol with a writable message-array pointer for kernel output fields.
fn lookup_recv(name: &CStr) -> Option<RecvMsgXFn> {
    // SAFETY: `name` is NUL-terminated and RTLD_DEFAULT searches already loaded images.
    let symbol = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) };
    if symbol.is_null() {
        return None;
    }
    // SAFETY: the private system entry point uses `(int, msghdr_x *, u_int, int)`.
    Some(unsafe { mem::transmute::<*mut c_void, RecvMsgXFn>(symbol) })
}

/// Verify the header layout by receiving from a freshly bound, nonblocking socket.
///
/// No caller knows this socket's port yet. A valid call therefore returns either a datagram that
/// arrived in the meantime or `WouldBlock`; a missing syscall or rejected header falls back.
fn probe_socket(fns: BatchFns, fd: c_int) -> io::Result<()> {
    let mut byte = [0u8; 1];
    let mut address = MaybeUninit::<libc::sockaddr_storage>::zeroed();
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: byte.len(),
    };
    let mut header = MsghdrX {
        msg_name: address.as_mut_ptr().cast(),
        msg_namelen: socklen_of::<libc::sockaddr_storage>(),
        msg_iov: &mut iov,
        msg_iovlen: 1,
        ..MsghdrX::EMPTY
    };

    // SAFETY: the header, address storage, byte buffer and iovec remain live for this call.
    let result = unsafe { (fns.recv)(fd, &mut header, 1, libc::MSG_DONTWAIT) };
    if result >= 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::WouldBlock {
        Ok(())
    } else {
        Err(error)
    }
}

/// Convert a small socket structure size to `socklen_t`.
fn socklen_of<T>() -> libc::socklen_t {
    libc::socklen_t::try_from(mem::size_of::<T>()).expect("a socket address fits in socklen_t")
}

/// Check whether an error means this private syscall is unavailable at runtime.
fn is_unsupported(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::ENOSYS) | Some(libc::EOPNOTSUPP)
    )
}

/// Reusable destination storage for one call to [`UdpSend::send_many_to`].
#[derive(Default)]
pub struct SendManyBuf {
    /// One mapped destination per packet, kept alive while the kernel reads the headers.
    targets: Vec<SockAddr>,
}

impl UdpSend for super::UdpSocket {
    type SendManyBuf = SendManyBuf;

    /// Send one datagram through Tokio's ordinary per-datagram path.
    async fn send_to(&self, packet: Packet, destination: SocketAddr) -> io::Result<()> {
        self.send_one(&packet, destination).await
    }

    /// Return the maximum run this socket can batch, or one when fallback is active.
    fn max_number_of_packets_to_send(&self) -> usize {
        if self.inner.batch.active().is_some() {
            SEND_BATCH
        } else {
            1
        }
    }

    /// Send a bounded run with the private syscall and retry safely when it is unavailable.
    async fn send_many_to(
        &self,
        send_buf: &mut SendManyBuf,
        packets: &mut Vec<(Packet, SocketAddr)>,
    ) -> io::Result<()> {
        if packets.is_empty() {
            return Ok(());
        }

        let first_is_v4 = matches!(packets[0].1, SocketAddr::V4(..));
        if packets
            .iter()
            .any(|(_, address)| matches!(address, SocketAddr::V4(..)) != first_is_v4)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "one UDP send run cannot mix IPv4 and IPv6 destinations",
            ));
        }

        send_buf.targets.clear();
        let mut first_error = None;
        if self.inner.batch.active().is_none() {
            for (packet, destination) in packets.drain(..) {
                if let Err(error) = self.send_one(&packet, destination).await {
                    first_error.get_or_insert(error);
                }
            }
            return first_error.map_or(Ok(()), Err);
        }

        send_buf.targets.extend(
            packets
                .iter()
                .map(|(_, address)| SockAddr::from(self.map_dst(*address))),
        );

        let mut pending = std::mem::take(packets);
        let mut targets = std::mem::take(&mut send_buf.targets);
        let mut start = 0;
        while start < pending.len() {
            let Some(fns) = self.inner.batch.active() else {
                break;
            };
            let end = pending.len().min(start + SEND_BATCH);
            let result = if let Some(worker) = &self.inner.batch.send_worker {
                worker
                    .send_batch(
                        self.socket(),
                        fns,
                        self.socket().as_raw_fd(),
                        &mut pending,
                        &mut targets,
                        start,
                        end,
                    )
                    .await
            } else {
                self.socket()
                    .async_io(Interest::WRITABLE, || {
                        send_batch(
                            fns,
                            self.socket().as_raw_fd(),
                            &pending[start..end],
                            &targets[start..end],
                        )
                    })
                    .await
            };

            match result {
                Ok(sent) if sent > 0 => start += sent,
                Err(error) if is_unsupported(&error) => {
                    self.inner.batch.disable(&error);
                    break;
                }
                result => {
                    if let Err(error) = result {
                        tracing::trace!(
                            "macOS UDP sendmsg_x failed; retrying this bounded run per datagram: {error}"
                        );
                    }
                    for (packet, destination) in &pending[start..end] {
                        if let Err(error) = self.send_one(packet, *destination).await {
                            first_error.get_or_insert(error);
                        }
                    }
                    start = end;
                }
            }
        }

        for (packet, destination) in pending.drain(..).skip(start) {
            if let Err(error) = self.send_one(&packet, destination).await {
                first_error.get_or_insert(error);
            }
        }
        targets.clear();
        send_buf.targets = targets;
        first_error.map_or(Ok(()), Err)
    }

    /// Return the bound address used by this socket.
    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        super::UdpSocket::local_addr(self).map(Some)
    }
}

impl super::UdpSocket {
    /// Send one packet through Tokio's ordinary UDP path for direct sends and safe fallback.
    async fn send_one(&self, packet: &Packet, destination: SocketAddr) -> io::Result<()> {
        self.socket()
            .send_to(packet, self.map_dst(destination))
            .await?;
        Ok(())
    }
}

/// Send one bounded run through `sendmsg_x` and return the number accepted by the kernel.
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

    for (index, ((packet, _), target)) in packets.iter().zip(targets).take(count).enumerate() {
        iovs[index] = libc::iovec {
            iov_base: packet.as_ptr().cast_mut().cast(),
            iov_len: packet.len(),
        };
        headers[index] = MsghdrX {
            msg_name: target.as_ptr().cast_mut().cast(),
            msg_namelen: target.len(),
            msg_iov: &mut iovs[index],
            msg_iovlen: 1,
            ..MsghdrX::EMPTY
        };
    }

    let count_arg = c_uint::try_from(count).expect("the bounded send count fits in u_int");
    // SAFETY: initialized headers point to live SockAddr and Packet storage for this call.
    let result = unsafe { (fns.send)(fd, headers.as_ptr(), count_arg, libc::MSG_DONTWAIT) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    let sent = usize::try_from(result).map_err(io::Error::other)?;
    if sent > count {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "sendmsg_x returned more datagrams than the submitted run",
        ));
    }
    Ok(sent)
}

impl UdpRecv for super::UdpSocket {
    type RecvManyBuf = ();

    /// Receive one datagram and map dual-stack sources back to IPv4 when needed.
    async fn recv_from(&mut self, pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        let mut buffer = pool.get();
        let (received, source) = self.socket().recv_from(&mut buffer).await?;
        buffer.truncate(received);
        Ok((buffer, self.map_src(source)))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use tokio::time::timeout;

    use super::*;
    use crate::{
        packet::PacketBufPool,
        udp::socket::{SockOpt, UdpSocket, UdpSocketState},
    };

    /// Bind a socket with the exact private-call state selected by the test.
    fn bind_with(address: SocketAddr, fns: Option<BatchFns>) -> UdpSocket {
        let socket = UdpSocket::bind(address, SockOpt::default()).expect("bind UDP socket");
        let state = Arc::try_unwrap(socket.inner)
            .ok()
            .expect("the new socket has no clones");
        UdpSocket {
            inner: Arc::new(UdpSocketState {
                socket: state.socket,
                batch: BatchState::with_fns(fns),
            }),
            map_ipv4_to_ipv6: socket.map_ipv4_to_ipv6,
        }
    }

    /// Make a small numbered datagram so tests can verify content and ordering.
    fn payload(index: usize) -> Packet {
        Packet::from_bytes(format!("packet {index:03}").as_bytes().into())
    }

    /// Read the number from a packet made by [`payload`].
    fn packet_number(bytes: &[u8]) -> usize {
        std::str::from_utf8(bytes)
            .expect("test payload is UTF-8")
            .trim_start_matches("packet ")
            .parse()
            .expect("test payload contains a number")
    }

    /// Send numbered packets in the socket's advertised run sizes and verify every receive.
    async fn round_trip(tx: &UdpSocket, rx: &mut UdpSocket, count: usize) {
        let destination = rx.local_addr().expect("receive address");
        let max = tx.max_number_of_packets_to_send();
        let all: Vec<_> = (0..count)
            .map(|index| (payload(index), destination))
            .collect();
        let mut send_buf = SendManyBuf::default();
        for chunk in all.chunks(max) {
            let mut packets = chunk.to_vec();
            tx.send_many_to(&mut send_buf, &mut packets)
                .await
                .expect("send run");
            assert!(packets.is_empty(), "successful sends drain their input");
        }

        let mut pool = PacketBufPool::new(4);
        let mut received = Vec::with_capacity(count);
        while received.len() < count {
            let (packet, source) = timeout(Duration::from_secs(2), rx.recv_from(&mut pool))
                .await
                .expect("all datagrams arrive")
                .expect("receive datagram");
            assert_eq!(source, tx.local_addr().expect("send address"));
            received.push(packet_number(&packet));
        }
        assert_eq!(received, (0..count).collect::<Vec<_>>());
    }

    /// The Darwin arm64 header has the offsets expected by the private system call.
    #[test]
    fn msghdr_x_layout_matches_darwin_arm64() {
        assert_eq!(mem::size_of::<MsghdrX>(), 56);
        assert_eq!(mem::align_of::<MsghdrX>(), 8);
        assert_eq!(mem::offset_of!(MsghdrX, msg_iov), 16);
        assert_eq!(mem::offset_of!(MsghdrX, msg_control), 32);
        assert_eq!(mem::offset_of!(MsghdrX, msg_datalen), 48);
    }

    /// Explicit off values disable batching without changing the default-on runtime choice.
    #[test]
    fn runtime_switch_disables_only_explicit_off_values() {
        assert!(batch_switch_allows(None));
        assert!(batch_switch_allows(Some("1")));
        for value in ["0", "off", "FALSE", " no "] {
            assert!(!batch_switch_allows(Some(value)), "{value:?}");
        }
    }

    /// Binding uses the bounded batch limit only when symbol lookup and the socket probe pass.
    #[tokio::test]
    async fn socket_limit_matches_runtime_probe_and_switch() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0).into(), SockOpt::default())
            .expect("bind UDP socket");
        let supported = batching_wanted()
            && resolve().is_some_and(|fns| probe_socket(fns, socket.socket().as_raw_fd()).is_ok());
        let expected = if supported { SEND_BATCH } else { 1 };
        assert_eq!(socket.max_number_of_packets_to_send(), expected);
    }

    /// A process started with the runtime switch off keeps the ordinary per-datagram path.
    #[tokio::test]
    async fn runtime_switch_off_preserves_packet_delivery() {
        if batch_switch_allows(std::env::var(BATCH_ENV).ok().as_deref()) {
            return;
        }
        let tx = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0).into(), SockOpt::default())
            .expect("bind send socket");
        let rx = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind receive socket");
        assert_eq!(tx.max_number_of_packets_to_send(), 1);
        let destination = rx.local_addr().expect("receive address");
        let mut packets: Vec<_> = (0..8).map(|index| (payload(index), destination)).collect();
        tx.send_many_to(&mut SendManyBuf::default(), &mut packets)
            .await
            .expect("per-datagram fallback sends every packet");
        assert!(packets.is_empty());
        let mut buffer = [0u8; 64];
        for index in 0..8 {
            let length = timeout(Duration::from_secs(2), rx.recv(&mut buffer))
                .await
                .expect("packet arrives")
                .expect("receive packet");
            assert_eq!(packet_number(&buffer[..length]), index);
        }
    }

    /// `sendmsg_x` calls made by [`counting_send`].
    static COUNTED_SENDS: AtomicUsize = AtomicUsize::new(0);

    /// Call the real private send function and count how many batches reached it.
    unsafe extern "C" fn counting_send(
        fd: c_int,
        headers: *const MsghdrX,
        count: c_uint,
        flags: c_int,
    ) -> isize {
        COUNTED_SENDS.fetch_add(1, Ordering::Relaxed);
        let Some(fns) = resolve() else {
            // SAFETY: `__error` returns this thread's errno slot on macOS.
            unsafe { *libc::__error() = libc::ENOSYS };
            return -1;
        };
        // SAFETY: the test forwards the live arguments unchanged to the resolved call.
        unsafe { (fns.send)(fd, headers, count, flags) }
    }

    /// One unconnected socket can send each message to its own IPv4 destination in one syscall.
    #[tokio::test]
    async fn batched_send_uses_each_ipv4_destination() {
        let Some(real) = resolve() else {
            return;
        };
        let fns = BatchFns {
            send: counting_send,
            recv: real.recv,
        };
        COUNTED_SENDS.store(0, Ordering::Relaxed);
        let tx = bind_with((Ipv4Addr::LOCALHOST, 0).into(), Some(fns));
        let first = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind first receiver");
        let second = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind second receiver");
        let mut packets = vec![
            (payload(0), first.local_addr().expect("first address")),
            (payload(1), second.local_addr().expect("second address")),
        ];
        tx.send_many_to(&mut SendManyBuf::default(), &mut packets)
            .await
            .expect("send to both destinations");
        assert!(packets.is_empty());
        assert_eq!(COUNTED_SENDS.load(Ordering::Relaxed), 1);

        let mut buffer = [0u8; 64];
        let length = timeout(Duration::from_secs(2), first.recv(&mut buffer))
            .await
            .expect("first datagram arrives")
            .expect("receive first datagram");
        assert_eq!(packet_number(&buffer[..length]), 0);
        let length = timeout(Duration::from_secs(2), second.recv(&mut buffer))
            .await
            .expect("second datagram arrives")
            .expect("receive second datagram");
        assert_eq!(packet_number(&buffer[..length]), 1);
    }

    /// A batch sender on a separate thread delivers packets in FIFO order.
    #[tokio::test]
    async fn batched_send_runs_on_independent_sender_thread() {
        if resolve().is_none() {
            return;
        }
        let tx = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0).into(), SockOpt::default())
            .expect("bind send socket");
        let Some(worker) = tx.inner.batch.send_worker.as_ref() else {
            return;
        };
        assert_ne!(worker._thread.thread().id(), std::thread::current().id());
        let calls = worker.calls.load(Ordering::Relaxed);

        let receiver = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind receiver");
        let destination = receiver.local_addr().expect("receiver address");
        let mut packets = vec![(payload(0), destination), (payload(1), destination)];
        tx.send_many_to(&mut SendManyBuf::default(), &mut packets)
            .await
            .expect("send through the independent worker");
        assert!(packets.is_empty());
        assert!(worker.calls.load(Ordering::Relaxed) > calls);

        let mut buffer = [0u8; 64];
        for index in 0..2 {
            let length = timeout(Duration::from_secs(2), receiver.recv(&mut buffer))
                .await
                .expect("packet arrives")
                .expect("receive packet");
            assert_eq!(packet_number(&buffer[..length]), index);
        }
    }

    /// A batch to IPv6 loopback carries every packet in order.
    #[tokio::test]
    async fn batched_send_over_ipv6() {
        let Some(real) = resolve() else {
            return;
        };
        let tx = bind_with((Ipv6Addr::LOCALHOST, 0).into(), Some(real));
        let mut rx = bind_with((Ipv6Addr::LOCALHOST, 0).into(), None);
        round_trip(&tx, &mut rx, 70).await;
    }

    /// A dual-stack socket maps IPv4 destinations before passing them to the batch syscall.
    #[tokio::test]
    async fn batched_send_from_dual_stack_reaches_ipv4() {
        if resolve().is_none() {
            return;
        }
        let opts = SockOpt {
            only_v6: Some(false),
            ..SockOpt::default()
        };
        let dual = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0).into(), opts)
            .expect("bind dual-stack socket");
        let receiver = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind IPv4 receiver");
        let destination = receiver.local_addr().expect("receive address");
        let mut packets: Vec<_> = (0..5).map(|index| (payload(index), destination)).collect();
        dual.send_many_to(&mut SendManyBuf::default(), &mut packets)
            .await
            .expect("send to mapped IPv4 destination");
        let mut buffer = [0u8; 64];
        for index in 0..5 {
            let length = timeout(Duration::from_secs(2), receiver.recv(&mut buffer))
                .await
                .expect("packet arrives")
                .expect("receive packet");
            assert_eq!(packet_number(&buffer[..length]), index);
        }
    }

    /// Return an unsupported error so the next send must use the ordinary path.
    unsafe extern "C" fn fail_enosys(_: c_int, _: *const MsghdrX, _: c_uint, _: c_int) -> isize {
        // SAFETY: `__error` returns this thread's errno slot on macOS.
        unsafe { *libc::__error() = libc::ENOSYS };
        -1
    }

    /// A runtime unsupported error disables batching and still delivers the whole run.
    #[tokio::test]
    async fn unsupported_runtime_call_falls_back_without_loss() {
        let Some(real) = resolve() else {
            return;
        };
        let tx = bind_with(
            (Ipv4Addr::LOCALHOST, 0).into(),
            Some(BatchFns {
                send: fail_enosys,
                recv: real.recv,
            }),
        );
        let receiver = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind receiver");
        let destination = receiver.local_addr().expect("receive address");
        let mut packets: Vec<_> = (0..10).map(|index| (payload(index), destination)).collect();
        tx.send_many_to(&mut SendManyBuf::default(), &mut packets)
            .await
            .expect("per-datagram retry delivers the run");
        assert!(packets.is_empty());
        assert_eq!(tx.max_number_of_packets_to_send(), 1);

        let mut buffer = [0u8; 64];
        for index in 0..10 {
            let length = timeout(Duration::from_secs(2), receiver.recv(&mut buffer))
                .await
                .expect("packet arrives")
                .expect("receive packet");
            assert_eq!(packet_number(&buffer[..length]), index);
        }
    }
}
