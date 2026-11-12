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

use std::{
    ffi::{CStr, c_int, c_uint, c_void},
    io,
    mem::{self, MaybeUninit},
    net::SocketAddr,
    os::fd::AsRawFd,
    sync::{
        OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use socket2::SockAddr;
use tokio::io::Interest;

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

/// Batching state shared by every clone of one [`super::UdpSocket`].
pub(crate) struct BatchState {
    /// The resolved calls, or `None` when this socket starts on per-datagram sends.
    fns: Option<BatchFns>,
    /// Set after a runtime error shows that this socket cannot use the private send call.
    disabled: AtomicBool,
    /// Bounded timing summaries, allocated only when send diagnostics were enabled at startup.
    diagnostics: Option<SendTimingDiagnostics>,
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
        Self::with_fns(Some(fns))
    }

    /// Store a runtime result, with tests able to inject missing or failing calls.
    fn with_fns(fns: Option<BatchFns>) -> Self {
        Self {
            fns,
            disabled: AtomicBool::new(false),
            diagnostics: crate::diag::UDP_SEND_TIMING
                .on()
                .then(SendTimingDiagnostics::default),
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

    /// Return the enabled collector to the send path without checking the environment again.
    fn diagnostics(&self) -> Option<&SendTimingDiagnostics> {
        self.diagnostics.as_ref()
    }
}

impl Drop for BatchState {
    /// Emit one compact summary after the socket's measured work has ended.
    fn drop(&mut self) {
        if let Some(diagnostics) = &self.diagnostics {
            diagnostics.write_summary();
        }
    }
}

/// Number of logarithmic buckets used for each per-batch latency histogram.
const SEND_TIMING_BUCKETS: usize = 64 * 8;

/// A fixed-size histogram for one monotonic per-batch duration.
struct TimingHistogram {
    /// Counts by logarithmic time bucket; updates never allocate or wait on a mutex.
    buckets: [AtomicU64; SEND_TIMING_BUCKETS],
    /// Number of durations recorded in this histogram.
    count: AtomicU64,
    /// Smallest exact duration recorded, in nanoseconds.
    min_ns: AtomicU64,
    /// Largest exact duration recorded, in nanoseconds.
    max_ns: AtomicU64,
}

impl Default for TimingHistogram {
    /// Create an empty histogram whose storage is bounded for the socket's lifetime.
    fn default() -> Self {
        Self {
            buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            count: AtomicU64::new(0),
            min_ns: AtomicU64::new(u64::MAX),
            max_ns: AtomicU64::new(0),
        }
    }
}

impl TimingHistogram {
    /// Add one duration to its bucket and retain the exact minimum and maximum.
    fn record(&self, ns: u64) {
        self.buckets[timing_bucket(ns)].fetch_add(1, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
        self.min_ns.fetch_min(ns, Ordering::Relaxed);
        self.max_ns.fetch_max(ns, Ordering::Relaxed);
    }

    /// Estimate a percentile using the upper edge of its bounded histogram bucket.
    fn percentile_ns(&self, percentile: u64) -> Option<u64> {
        let count = self.count.load(Ordering::Relaxed);
        if count == 0 {
            return None;
        }
        let target = u64::try_from((u128::from(count) * u128::from(percentile) + 99) / 100)
            .unwrap_or(u64::MAX);
        let mut cumulative = 0_u64;
        for (index, bucket) in self.buckets.iter().enumerate() {
            cumulative = cumulative.saturating_add(bucket.load(Ordering::Relaxed));
            if cumulative >= target {
                return Some(timing_bucket_upper_ns(index));
            }
        }
        Some(u64::MAX)
    }

    /// Return the exact minimum when this histogram contains at least one duration.
    fn min_ns(&self) -> Option<u64> {
        (self.count.load(Ordering::Relaxed) > 0).then(|| self.min_ns.load(Ordering::Relaxed))
    }

    /// Return the exact maximum when this histogram contains at least one duration.
    fn max_ns(&self) -> Option<u64> {
        (self.count.load(Ordering::Relaxed) > 0).then(|| self.max_ns.load(Ordering::Relaxed))
    }
}

/// Diagnostic counters shared by all buffered sends on one UDP socket.
///
/// Each batch updates only fixed-size relaxed atomics. The output is deferred until the owning
/// socket is dropped, so measurement does not format or write one log line per send call.
struct SendTimingDiagnostics {
    /// Number of batched send calls observed.
    batches: AtomicU64,
    /// Total datagrams offered to the private send call.
    offered: AtomicU64,
    /// Total datagrams accepted by the private send call.
    accepted: AtomicU64,
    /// Number of calls that returned EAGAIN.
    eagain: AtomicU64,
    /// Number of calls that returned ENOBUFS.
    enobufs: AtomicU64,
    /// Queue-entry-to-syscall-start duration distribution.
    queue_to_start: TimingHistogram,
    /// Private syscall wall-time distribution.
    syscall_wall: TimingHistogram,
    /// Send-buffer occupancy sampled before the private send call.
    so_nwrite_before: SocketOccupancyStats,
    /// Send-buffer occupancy sampled after the private send call.
    so_nwrite_after: SocketOccupancyStats,
    /// Queue depth and payload size attached to each buffered send run.
    queue_state: QueueStateStats,
}

impl Default for SendTimingDiagnostics {
    /// Allocate a bounded collector for one socket after the diagnostic switch is enabled.
    fn default() -> Self {
        Self {
            batches: AtomicU64::new(0),
            offered: AtomicU64::new(0),
            accepted: AtomicU64::new(0),
            eagain: AtomicU64::new(0),
            enobufs: AtomicU64::new(0),
            queue_to_start: TimingHistogram::default(),
            syscall_wall: TimingHistogram::default(),
            so_nwrite_before: SocketOccupancyStats::default(),
            so_nwrite_after: SocketOccupancyStats::default(),
            queue_state: QueueStateStats::default(),
        }
    }
}

/// One completed private send call passed to the bounded timing collector.
struct SendBatchObservation {
    /// Number of datagrams offered to this syscall.
    offered: usize,
    /// Number of datagrams accepted by this syscall.
    accepted: usize,
    /// Queue-entry-to-syscall-start duration, when the buffered queue supplied a timestamp.
    queue_to_start_ns: Option<u128>,
    /// Wall time spent inside the private syscall.
    syscall_wall_ns: Option<u128>,
    /// Whether this call returned EAGAIN.
    eagain: bool,
    /// Whether this call returned ENOBUFS.
    enobufs: bool,
    /// Readable send-buffer occupancy before the syscall, if available.
    so_nwrite_before: Option<libc::c_int>,
    /// Readable send-buffer occupancy after the syscall, if available.
    so_nwrite_after: Option<libc::c_int>,
    /// Reserved packet count when the buffered queue supplied it.
    outstanding_packets: Option<usize>,
    /// Datagrams in the queued run, when the buffered queue supplied it.
    batch_packets: Option<usize>,
    /// Payload bytes in the queued run, when the buffered queue supplied it.
    batch_bytes: Option<usize>,
}

impl SendTimingDiagnostics {
    /// Record one batch without formatting, allocating, or waiting for another sender.
    fn record(&self, observation: SendBatchObservation) {
        self.batches.fetch_add(1, Ordering::Relaxed);
        self.offered.fetch_add(
            u64::try_from(observation.offered).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
        self.accepted.fetch_add(
            u64::try_from(observation.accepted).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
        if let Some(ns) = observation.queue_to_start_ns {
            self.queue_to_start
                .record(u64::try_from(ns).unwrap_or(u64::MAX));
        }
        if let Some(ns) = observation.syscall_wall_ns {
            self.syscall_wall
                .record(u64::try_from(ns).unwrap_or(u64::MAX));
        }
        if observation.eagain {
            self.eagain.fetch_add(1, Ordering::Relaxed);
        }
        if observation.enobufs {
            self.enobufs.fetch_add(1, Ordering::Relaxed);
        }
        self.so_nwrite_before.record(observation.so_nwrite_before);
        self.so_nwrite_after.record(observation.so_nwrite_after);
        self.queue_state.record(
            observation.outstanding_packets,
            observation.batch_packets,
            observation.batch_bytes,
        );
    }

    /// Print one bounded summary after measured work, including approximate percentiles.
    fn write_summary(&self) {
        let batches = self.batches.load(Ordering::Relaxed);
        if batches == 0 {
            return;
        }
        eprintln!(
            "udp_sendmsg_x_summary batches={batches} offered={} accepted={} eagain={} enobufs={} queue_samples={} queue_p50_ns={:?} queue_p95_ns={:?} queue_p99_ns={:?} queue_min_ns={:?} queue_max_ns={:?} syscall_samples={} syscall_p50_ns={:?} syscall_p95_ns={:?} syscall_p99_ns={:?} syscall_min_ns={:?} syscall_max_ns={:?} so_nwrite_before_samples={} so_nwrite_before_unavailable={} so_nwrite_before_min={:?} so_nwrite_before_max={:?} so_nwrite_after_samples={} so_nwrite_after_unavailable={} so_nwrite_after_min={:?} so_nwrite_after_max={:?} queue_state_samples={} outstanding_packets_max={} batch_packets_max={} batch_bytes_max={}",
            self.offered.load(Ordering::Relaxed),
            self.accepted.load(Ordering::Relaxed),
            self.eagain.load(Ordering::Relaxed),
            self.enobufs.load(Ordering::Relaxed),
            self.queue_to_start.count.load(Ordering::Relaxed),
            self.queue_to_start.percentile_ns(50),
            self.queue_to_start.percentile_ns(95),
            self.queue_to_start.percentile_ns(99),
            self.queue_to_start.min_ns(),
            self.queue_to_start.max_ns(),
            self.syscall_wall.count.load(Ordering::Relaxed),
            self.syscall_wall.percentile_ns(50),
            self.syscall_wall.percentile_ns(95),
            self.syscall_wall.percentile_ns(99),
            self.syscall_wall.min_ns(),
            self.syscall_wall.max_ns(),
            self.so_nwrite_before.readable.load(Ordering::Relaxed),
            self.so_nwrite_before.unavailable.load(Ordering::Relaxed),
            self.so_nwrite_before.min_value(),
            self.so_nwrite_before.max_value(),
            self.so_nwrite_after.readable.load(Ordering::Relaxed),
            self.so_nwrite_after.unavailable.load(Ordering::Relaxed),
            self.so_nwrite_after.min_value(),
            self.so_nwrite_after.max_value(),
            self.queue_state.samples.load(Ordering::Relaxed),
            self.queue_state
                .outstanding_packets_max
                .load(Ordering::Relaxed),
            self.queue_state.batch_packets_max.load(Ordering::Relaxed),
            self.queue_state.batch_bytes_max.load(Ordering::Relaxed),
        );
    }
}

/// Bounded high-water marks for queue depth and payload size.
struct QueueStateStats {
    /// Number of send calls with queue metadata.
    samples: AtomicU64,
    /// Largest reserved packet count observed before a syscall.
    outstanding_packets_max: AtomicU64,
    /// Largest queued run size observed before a syscall.
    batch_packets_max: AtomicU64,
    /// Largest queued payload size observed before a syscall.
    batch_bytes_max: AtomicU64,
}

impl Default for QueueStateStats {
    /// Start with no queue samples.
    fn default() -> Self {
        Self {
            samples: AtomicU64::new(0),
            outstanding_packets_max: AtomicU64::new(0),
            batch_packets_max: AtomicU64::new(0),
            batch_bytes_max: AtomicU64::new(0),
        }
    }
}

impl QueueStateStats {
    /// Record one run's bounded queue and payload high-water values.
    fn record(
        &self,
        outstanding_packets: Option<usize>,
        batch_packets: Option<usize>,
        batch_bytes: Option<usize>,
    ) {
        let (Some(outstanding_packets), Some(batch_packets), Some(batch_bytes)) =
            (outstanding_packets, batch_packets, batch_bytes)
        else {
            return;
        };
        self.samples.fetch_add(1, Ordering::Relaxed);
        self.outstanding_packets_max.fetch_max(
            u64::try_from(outstanding_packets).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
        self.batch_packets_max.fetch_max(
            u64::try_from(batch_packets).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
        self.batch_bytes_max.fetch_max(
            u64::try_from(batch_bytes).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }
}

/// Summary counters for one optional `SO_NWRITE` occupancy measurement.
struct SocketOccupancyStats {
    /// Number of successful reads.
    readable: AtomicU64,
    /// Number of failed or invalid reads.
    unavailable: AtomicU64,
    /// Smallest readable occupancy in bytes.
    min_bytes: AtomicU64,
    /// Largest readable occupancy in bytes.
    max_bytes: AtomicU64,
}

impl Default for SocketOccupancyStats {
    /// Start with no readable occupancy samples.
    fn default() -> Self {
        Self {
            readable: AtomicU64::new(0),
            unavailable: AtomicU64::new(0),
            min_bytes: AtomicU64::new(u64::MAX),
            max_bytes: AtomicU64::new(0),
        }
    }
}

impl SocketOccupancyStats {
    /// Record a readable occupancy or count the missing sample.
    fn record(&self, bytes: Option<libc::c_int>) {
        let Some(bytes) = bytes.and_then(|value| u64::try_from(value).ok()) else {
            self.unavailable.fetch_add(1, Ordering::Relaxed);
            return;
        };
        self.readable.fetch_add(1, Ordering::Relaxed);
        self.min_bytes.fetch_min(bytes, Ordering::Relaxed);
        self.max_bytes.fetch_max(bytes, Ordering::Relaxed);
    }

    /// Return the smallest readable occupancy, if any sample succeeded.
    fn min_value(&self) -> Option<u64> {
        (self.readable.load(Ordering::Relaxed) > 0).then(|| self.min_bytes.load(Ordering::Relaxed))
    }

    /// Return the largest readable occupancy, if any sample succeeded.
    fn max_value(&self) -> Option<u64> {
        (self.readable.load(Ordering::Relaxed) > 0).then(|| self.max_bytes.load(Ordering::Relaxed))
    }
}

/// Map one nanosecond duration into a fixed logarithmic histogram bucket.
fn timing_bucket(ns: u64) -> usize {
    if ns < 8 {
        return usize::try_from(ns).unwrap_or(7);
    }
    let exponent = 63 - ns.leading_zeros() as usize;
    let base = 1_u64 << exponent;
    let subdivision = (((u128::from(ns - base) * 8) / u128::from(base)).min(7)) as usize;
    8 + (exponent - 3) * 8 + subdivision
}

/// Return the exclusive upper edge of a logarithmic timing bucket.
fn timing_bucket_upper_ns(index: usize) -> u64 {
    if index < 8 {
        return index as u64;
    }
    let relative = index - 8;
    let exponent = 3 + relative / 8;
    let subdivision = relative % 8;
    let base = 1_u64 << exponent;
    let width = base / 8;
    base.saturating_add(width.saturating_mul((subdivision + 1) as u64))
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

        let mut start = 0;
        while start < packets.len() {
            let Some(fns) = self.inner.batch.active() else {
                break;
            };
            let end = packets.len().min(start + SEND_BATCH);
            let diagnostics = self.inner.batch.diagnostics();
            let result = self
                .socket()
                .async_io(Interest::WRITABLE, || {
                    send_batch(
                        fns,
                        self.socket().as_raw_fd(),
                        &packets[start..end],
                        &send_buf.targets[start..end],
                        diagnostics,
                    )
                })
                .await;

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
                    for (packet, destination) in &packets[start..end] {
                        if let Err(error) = self.send_one(packet, *destination).await {
                            first_error.get_or_insert(error);
                        }
                    }
                    start = end;
                }
            }
        }

        for (packet, destination) in packets.drain(..).skip(start) {
            if let Err(error) = self.send_one(&packet, destination).await {
                first_error.get_or_insert(error);
            }
        }
        send_buf.targets.clear();
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

/// Read the number of bytes waiting in the socket's send buffer when Darwin exposes it.
///
/// `SO_NWRITE` is sampled only during opt-in send-queue diagnostics; unreadable values remain
/// absent instead of changing the send decision.
fn socket_nwrite_bytes(fd: c_int) -> Option<libc::c_int> {
    let mut bytes = 0;
    let mut length = socklen_of::<libc::c_int>();
    // SAFETY: both output pointers refer to live writable values for this getsockopt call.
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_NWRITE,
            (&mut bytes as *mut libc::c_int).cast(),
            &mut length,
        )
    };
    (result == 0).then_some(bytes)
}

/// Send one bounded run through `sendmsg_x` and return the number accepted by the kernel.
///
/// With `GOTATUN_DIAG_UDP_SEND_TIMING` set, this records queue age, syscall duration, the
/// partial-send result, transient kernel errors and `SO_NWRITE` around the syscall. It updates a
/// bounded histogram and emits one summary when the owning socket is dropped. Normal sends make
/// none of the timestamp or socket-option calls.
fn send_batch(
    fns: BatchFns,
    fd: c_int,
    packets: &[(Packet, SocketAddr)],
    targets: &[SockAddr],
    diagnostics: Option<&SendTimingDiagnostics>,
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
    let diagnostics_enabled = diagnostics.is_some();
    let send_diagnostic = diagnostics_enabled
        .then(crate::diag::current_udp_send_batch)
        .flatten();
    let so_nwrite_before = diagnostics_enabled
        .then(|| socket_nwrite_bytes(fd))
        .flatten();
    let syscall_started = diagnostics_enabled.then(crate::diag::udp_send_monotonic_now);
    // SAFETY: initialized headers point to live SockAddr and Packet storage for this call.
    let result = unsafe { (fns.send)(fd, headers.as_ptr(), count_arg, libc::MSG_DONTWAIT) };
    let syscall_finished = diagnostics_enabled.then(crate::diag::udp_send_monotonic_now);
    let error = (result < 0).then(io::Error::last_os_error);
    let so_nwrite_after = diagnostics_enabled
        .then(|| socket_nwrite_bytes(fd))
        .flatten();
    let accepted = usize::try_from(result).unwrap_or(0);
    let queue_to_start_ns = send_diagnostic
        .zip(syscall_started)
        .map(|(diagnostic, started_ns)| {
            u128::from(started_ns.saturating_sub(diagnostic.enqueued_mono_ns))
        });
    let syscall_wall_ns = syscall_started
        .zip(syscall_finished)
        .map(|(started_ns, finished_ns)| u128::from(finished_ns.saturating_sub(started_ns)));
    let eagain = error
        .as_ref()
        .is_some_and(|error| error.raw_os_error() == Some(libc::EAGAIN));
    let enobufs = error
        .as_ref()
        .is_some_and(|error| error.raw_os_error() == Some(libc::ENOBUFS));
    if let Some(diagnostics) = diagnostics {
        diagnostics.record(SendBatchObservation {
            offered: count,
            accepted,
            queue_to_start_ns,
            syscall_wall_ns,
            eagain,
            enobufs,
            so_nwrite_before,
            so_nwrite_after,
            outstanding_packets: send_diagnostic.map(|diagnostic| diagnostic.outstanding_packets),
            batch_packets: send_diagnostic.map(|diagnostic| diagnostic.batch_packets),
            batch_bytes: send_diagnostic.map(|diagnostic| diagnostic.batch_bytes),
        });
    }
    if let Some(error) = error {
        return Err(error);
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
        process::Command,
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
        udp::buffer::BufferedUdpSend,
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

    /// Run the real buffered sender in a fresh process so its environment switch starts unset.
    fn send_diagnostic_child(enabled: bool) -> String {
        let mut command = Command::new(std::env::current_exe().expect("test executable path"));
        command
            .arg("udp_send_diagnostic_child")
            .arg("--nocapture")
            .env_remove("GOTATUN_DIAG_PIPELINE")
            .env_remove("GOTATUN_DIAG_SEND_QUEUE")
            .env_remove("GOTATUN_DIAG_UDP_SEND_TIMING");
        if enabled {
            command.env("GOTATUN_DIAG_UDP_SEND_TIMING", "1");
        }
        let output = command.output().expect("diagnostic child test starts");
        assert!(
            output.status.success(),
            "diagnostic child failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    }

    /// Keep queue and syscall measurements silent unless the send-queue diagnostic switch is set.
    #[test]
    fn udp_send_diagnostics_are_silent_by_default() {
        let output = send_diagnostic_child(false);

        assert!(!output.contains("udp_sendmsg_x "), "{output}");
    }

    /// Report UDP timing without enabling the broader packet-pipeline traces.
    #[test]
    fn udp_send_diagnostics_include_queue_and_syscall_measurements() {
        let output = send_diagnostic_child(true);
        let summaries: Vec<_> = output
            .lines()
            .filter(|line| line.contains("udp_sendmsg_x_summary "))
            .collect();

        assert!(
            summaries.len() == 1,
            "UDP timing switch should emit one bounded summary: {output}"
        );
        assert!(!output.contains("pipeline stage="), "{output}");
        assert!(!output.contains("udp_sendmsg_x batch_id="), "{output}");
        let summary = summaries[0];
        assert!(
            summary.contains("queue_samples=")
                && !summary.contains("queue_p99_ns=None")
                && summary.contains("syscall_samples=")
                && summary.contains("offered=5")
                && summary.contains("accepted=3")
                && summary.contains("eagain=1")
                && summary.contains("enobufs=1")
                && summary.contains("so_nwrite_before_samples=")
                && summary.contains("so_nwrite_after_samples=")
                && summary.contains("outstanding_packets_max=")
                && summary.contains("batch_bytes_max="),
            "{output}"
        );
    }

    /// Exercise the buffered queue and injected syscall errors in an isolated process.
    #[tokio::test]
    async fn udp_send_diagnostic_child() {
        let Some(real) = resolve() else {
            return;
        };
        let tx = bind_with(
            (Ipv4Addr::LOCALHOST, 0).into(),
            Some(BatchFns {
                send: counting_send,
                recv: real.recv,
            }),
        );
        let receiver = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind receiver");
        let destination = receiver.local_addr().expect("receive address");
        let sender = BufferedUdpSend::new(8, tx.clone());
        let mut packets: Vec<_> = (0..3).map(|index| (payload(index), destination)).collect();
        sender
            .send_many_to(&mut (), &mut packets)
            .await
            .expect("the queue accepts the run and retries syscall errors per datagram");
        assert!(packets.is_empty());

        let mut buffer = [0u8; 64];
        for index in 0..3 {
            let length = timeout(Duration::from_secs(2), receiver.recv(&mut buffer))
                .await
                .expect("buffered datagram arrives")
                .expect("receive buffered datagram");
            assert_eq!(packet_number(&buffer[..length]), index);
        }

        DIAGNOSTIC_SEND_CALLS.store(0, Ordering::Relaxed);
        let destination = SockAddr::from(destination);
        let packet = [(
            payload(3),
            destination.as_socket().expect("IPv4 socket address"),
        )];
        for (index, expected_errno) in [libc::EAGAIN, libc::ENOBUFS].into_iter().enumerate() {
            let result = send_batch(
                BatchFns {
                    send: fail_eagain_then_enobufs,
                    recv: real.recv,
                },
                tx.socket().as_raw_fd(),
                &packet,
                std::slice::from_ref(&destination),
                tx.inner.batch.diagnostics(),
            );
            assert_eq!(
                result
                    .expect_err("the injected transient error is returned")
                    .raw_os_error(),
                Some(expected_errno),
                "injected syscall {index}"
            );
        }
    }

    /// Number the two injected send errors before the safe per-datagram fallback is exercised.
    static DIAGNOSTIC_SEND_CALLS: AtomicUsize = AtomicUsize::new(0);

    /// Return EAGAIN, then ENOBUFS, so diagnostics prove that both errors are counted.
    unsafe extern "C" fn fail_eagain_then_enobufs(
        _: c_int,
        _: *const MsghdrX,
        _: c_uint,
        _: c_int,
    ) -> isize {
        let call = DIAGNOSTIC_SEND_CALLS.fetch_add(1, Ordering::Relaxed);
        let errno = match call {
            0 => libc::EAGAIN,
            1 => libc::ENOBUFS,
            _ => libc::EIO,
        };
        // SAFETY: `__error` returns this thread's errno slot on macOS.
        unsafe { *libc::__error() = errno };
        -1
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
