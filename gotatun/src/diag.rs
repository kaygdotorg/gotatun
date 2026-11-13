//! Opt-in diagnostic switches for investigating the packet pipeline.
//!
//! Each switch is an environment variable that is checked once, on first use, and then cached
//! for the life of the process. The packet path asks a switch on every packet, and reading the
//! environment each time takes the process-wide environment lock and allocates a copy of the
//! value. That cost showed up as a measurable slowdown in debug builds (#260). Set the variable
//! before the process starts; changing it later has no effect.
//!
//! ```text
//! GOTATUN_DIAG_PIPELINE=1 cargo test ...
//! ```

use std::{future::Future, sync::OnceLock, time::Instant};

/// Process-relative monotonic origin for opt-in UDP send measurements.
static UDP_SEND_EPOCH: OnceLock<Instant> = OnceLock::new();

tokio::task_local! {
    /// Carries one buffered UDP run's enqueue time into the socket send future.
    static UDP_SEND_BATCH: UdpSendBatchDiagnostic;
}

/// Metadata recorded when one datagram run enters the buffered UDP queue.
///
/// The socket layer reads this from the current Tokio task immediately before `sendmsg_x`, so
/// queue delay and syscall duration use the same run identifier without changing the public UDP
/// transport trait.
#[derive(Clone, Copy)]
pub(crate) struct UdpSendBatchDiagnostic {
    /// Monotonic run number shared with optional send-queue trace messages.
    pub(crate) sequence: u64,
    /// Process-relative monotonic timestamp for the queue insertion event.
    pub(crate) enqueued_mono_ns: u64,
    /// Time spent waiting for packet permits before the run entered the send channel.
    pub(crate) packet_permit_wait_ns: u64,
    /// Time spent waiting for the bounded send-channel slot before queue insertion.
    pub(crate) channel_reserve_wait_ns: u64,
    /// Total packet permits reserved, including this run and work already being sent.
    pub(crate) outstanding_packets: usize,
    /// Number of datagrams in this queued run.
    pub(crate) batch_packets: usize,
    /// Payload bytes in this queued run.
    pub(crate) batch_bytes: usize,
}

impl UdpSendBatchDiagnostic {
    /// Capture queue metadata after the bounded channel has accepted a slot for this run.
    pub(crate) fn new(
        sequence: u64,
        outstanding_packets: usize,
        batch_packets: usize,
        batch_bytes: usize,
        packet_permit_wait_ns: u64,
        channel_reserve_wait_ns: u64,
    ) -> Self {
        let enqueued_mono_ns = udp_send_monotonic_now();
        Self {
            sequence,
            enqueued_mono_ns,
            packet_permit_wait_ns,
            channel_reserve_wait_ns,
            outstanding_packets,
            batch_packets,
            batch_bytes,
        }
    }
}

/// Return the current process-relative monotonic timestamp in nanoseconds.
pub(crate) fn udp_send_monotonic_now() -> u64 {
    let epoch = *UDP_SEND_EPOCH.get_or_init(Instant::now);
    let now = Instant::now();
    let elapsed = now.saturating_duration_since(epoch).as_nanos();
    u64::try_from(elapsed).unwrap_or(u64::MAX)
}

/// Make one buffered run's metadata visible to the nested UDP socket future.
pub(crate) async fn with_udp_send_batch<F>(
    diagnostic: UdpSendBatchDiagnostic,
    future: F,
) -> F::Output
where
    F: Future + Send,
{
    UDP_SEND_BATCH.scope(diagnostic, future).await
}

/// Read the current buffered run's metadata from the active Tokio task, if it has one.
pub(crate) fn current_udp_send_batch() -> Option<UdpSendBatchDiagnostic> {
    UDP_SEND_BATCH.try_with(|diagnostic| *diagnostic).ok()
}

/// One environment-controlled diagnostic switch, read once and then cached.
///
/// Declare a switch as a `static` and ask it with [`Switch::on`]. Only the variable's presence
/// matters, not its value.
pub(crate) struct Switch {
    /// Name of the environment variable that turns this switch on.
    name: &'static str,
    /// Cached presence of the variable, filled on the first call to [`Switch::on`].
    enabled: OnceLock<bool>,
}

impl Switch {
    /// Declare a switch controlled by the environment variable `name`.
    const fn new(name: &'static str) -> Self {
        Self {
            name,
            enabled: OnceLock::new(),
        }
    }

    /// Whether the switch's environment variable was set when it was first checked.
    pub(crate) fn on(&self) -> bool {
        *self
            .enabled
            .get_or_init(|| std::env::var_os(self.name).is_some())
    }
}

/// Print a line for each stage a packet run passes through.
pub(crate) static PIPELINE: Switch = Switch::new("GOTATUN_DIAG_PIPELINE");

/// Print UDP and TUN send-queue reservations and releases.
pub(crate) static SEND_QUEUE: Switch = Switch::new("GOTATUN_DIAG_SEND_QUEUE");

/// Record buffered UDP queue and macOS send syscall timings without enabling pipeline traces.
pub(crate) static UDP_SEND_TIMING: Switch = Switch::new("GOTATUN_DIAG_UDP_SEND_TIMING");

/// Never hand peer crypto runs to the worker pool.
pub(crate) static FORCE_INLINE: Switch = Switch::new("GOTATUN_DIAG_FORCE_INLINE");

/// Hand every peer crypto run to the worker pool.
pub(crate) static FORCE_WORKERS: Switch = Switch::new("GOTATUN_DIAG_FORCE_WORKERS");

/// Write TUN packets one at a time instead of in batches.
pub(crate) static TUN_SINGLE_SENDS: Switch = Switch::new("GOTATUN_DIAG_TUN_SINGLE_SENDS");

/// Send UDP datagrams one at a time instead of in batches.
pub(crate) static UDP_SINGLE_SENDS: Switch = Switch::new("GOTATUN_DIAG_UDP_SINGLE_SENDS");

/// Session age after which an initiator rekeys, in milliseconds, for rekey-under-load tests.
///
/// Read once from `GOTATUN_DIAG_REKEY_AFTER_MS`. When it is set, every new peer that has no
/// explicit timer parameters starts with this `rekey_after_time` instead of the protocol's 120 s.
/// Use it to provoke many rekeys in a short run (#260); never set it in production.
pub(crate) fn rekey_after() -> Option<std::time::Duration> {
    static REKEY_AFTER: OnceLock<Option<std::time::Duration>> = OnceLock::new();
    *REKEY_AFTER.get_or_init(|| {
        let value = std::env::var("GOTATUN_DIAG_REKEY_AFTER_MS").ok()?;
        match value.parse::<u64>() {
            Ok(ms) if ms > 0 => Some(std::time::Duration::from_millis(ms)),
            _ => {
                tracing::warn!("ignoring invalid GOTATUN_DIAG_REKEY_AFTER_MS={value:?}");
                None
            }
        }
    })
}

/// Capacity override for the buffered UDP receive queue, for queue-size experiments (#260).
///
/// Read once from `GOTATUN_DIAG_UDP_RX_QUEUE` (a packet count of at least 1). Unset or invalid
/// keeps the platform default. Never set it in production.
pub(crate) fn udp_rx_queue() -> Option<usize> {
    static QUEUE: OnceLock<Option<usize>> = OnceLock::new();
    *QUEUE.get_or_init(|| {
        let value = std::env::var("GOTATUN_DIAG_UDP_RX_QUEUE").ok()?;
        match value.parse::<usize>() {
            Ok(packets) if packets > 0 => Some(packets),
            _ => {
                tracing::warn!("ignoring invalid GOTATUN_DIAG_UDP_RX_QUEUE={value:?}");
                None
            }
        }
    })
}

/// Record per-stage packet-path timings and queue occupancy, printed once a second.
///
/// Set `GOTATUN_DIAG_PATH_TIMING` before the process starts. Each metric is a fixed
/// logarithmic histogram of relaxed atomics, so a packet costs a clock read and two atomic adds
/// and nothing is formatted on the packet path. A background thread swaps every histogram to
/// zero once a second and prints the non-empty buckets as one `gotatun_path_diag` line per
/// metric, stamped with Unix milliseconds. A benchmark can then cut the lines by its own case
/// boundaries (#260, J566). Never set it in production.
pub(crate) static PATH_TIMING: Switch = Switch::new("GOTATUN_DIAG_PATH_TIMING");

/// Logarithmic histogram used by [`PATH_TIMING`]: 8 sub-buckets per power of two.
pub(crate) const PATH_BUCKETS: usize = 64 * 8;

/// One interval histogram for a [`PATH_TIMING`] metric.
pub(crate) struct PathHistogram {
    /// Short metric name printed on each line, with its unit as a suffix (`_ns`, `_pkts`, …).
    name: &'static str,
    /// Counts by bucket since the last print; the printer swaps them back to zero.
    buckets: [std::sync::atomic::AtomicU64; PATH_BUCKETS],
    /// Largest exact value since the last print.
    max: std::sync::atomic::AtomicU64,
}

impl PathHistogram {
    /// Declare an empty histogram called `name`.
    pub(crate) const fn new(name: &'static str) -> Self {
        Self {
            name,
            buckets: [const { std::sync::atomic::AtomicU64::new(0) }; PATH_BUCKETS],
            max: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Add one value. Starts the printer thread the first time any metric records.
    pub(crate) fn record(&'static self, value: u64) {
        use std::sync::atomic::Ordering::Relaxed;
        start_path_printer();
        self.buckets[path_bucket(value)].fetch_add(1, Relaxed);
        self.max.fetch_max(value, Relaxed);
    }

    /// Print and reset this interval's buckets, if it recorded anything.
    fn flush(&self, unix_ms: u128) {
        use std::fmt::Write as _;
        use std::sync::atomic::Ordering::Relaxed;
        let mut line = String::new();
        for (index, bucket) in self.buckets.iter().enumerate() {
            let count = bucket.swap(0, Relaxed);
            if count > 0 {
                let _ = write!(line, "{index}:{count},");
            }
        }
        let max = self.max.swap(0, Relaxed);
        if !line.is_empty() {
            eprintln!(
                "gotatun_path_diag t={unix_ms} name={} max={max} buckets={line}",
                self.name
            );
        }
    }
}

/// Map a value into its [`PATH_BUCKETS`] bucket: exact below 8, then 8 slices per power of two.
pub(crate) fn path_bucket(value: u64) -> usize {
    if value < 8 {
        return usize::try_from(value).unwrap_or(0);
    }
    let exponent = 63 - value.leading_zeros() as usize;
    let base = 1_u64 << exponent;
    let slice = usize::try_from(((u128::from(value - base)) * 8) / u128::from(base)).unwrap_or(7);
    (8 + (exponent - 3) * 8 + slice.min(7)).min(PATH_BUCKETS - 1)
}

/// Every [`PATH_TIMING`] metric, in print order. Units are in the names.
pub(crate) mod path {
    use super::PathHistogram;

    /// UDP `recvfrom` completion → `handle_incoming` dequeue, per datagram (receive queue wait).
    pub(crate) static UDP_RX_QUEUE_WAIT_NS: PathHistogram =
        PathHistogram::new("udp_rx_queue_wait_ns");
    /// Datagrams waiting in the buffered UDP receive queue when one is dequeued.
    pub(crate) static UDP_RX_QUEUE_PKTS: PathHistogram = PathHistogram::new("udp_rx_queue_pkts");
    /// Oldest UDP `recvfrom` completion in a run → that run's TUN write finished.
    pub(crate) static RX_TO_TUN_WRITTEN_NS: PathHistogram =
        PathHistogram::new("rx_to_tun_written_ns");
    /// TUN send queue entry → its dequeue by the TUN writer task, per run.
    pub(crate) static TUN_TX_QUEUE_WAIT_NS: PathHistogram =
        PathHistogram::new("tun_tx_queue_wait_ns");
    /// Packets reserved in the TUN send queue (queued plus in service) at each entry.
    pub(crate) static TUN_TX_QUEUE_PKTS: PathHistogram = PathHistogram::new("tun_tx_queue_pkts");
    /// Wall time of one inner TUN write call (one packet or one run).
    pub(crate) static TUN_WRITE_NS: PathHistogram = PathHistogram::new("tun_write_ns");
    /// Inner TUN `recv` return → the buffered TUN receive queue's dequeue, oldest packet per call.
    pub(crate) static TUN_RX_QUEUE_WAIT_NS: PathHistogram =
        PathHistogram::new("tun_rx_queue_wait_ns");
    /// Packets waiting in the buffered TUN receive queue at each dequeue (including those taken).
    pub(crate) static TUN_RX_QUEUE_PKTS: PathHistogram = PathHistogram::new("tun_rx_queue_pkts");
    /// Buffered TUN receive dequeue → the resulting run entering the UDP send queue (encrypt).
    pub(crate) static TUN_RX_TO_UDP_QUEUE_NS: PathHistogram =
        PathHistogram::new("tun_rx_to_udp_queue_ns");

    /// All metrics, for the printer.
    pub(crate) static ALL: [&PathHistogram; 9] = [
        &UDP_RX_QUEUE_WAIT_NS,
        &UDP_RX_QUEUE_PKTS,
        &RX_TO_TUN_WRITTEN_NS,
        &TUN_TX_QUEUE_WAIT_NS,
        &TUN_TX_QUEUE_PKTS,
        &TUN_WRITE_NS,
        &TUN_RX_QUEUE_WAIT_NS,
        &TUN_RX_QUEUE_PKTS,
        &TUN_RX_TO_UDP_QUEUE_NS,
    ];
}

/// Oldest UDP receive completion not yet handed to the TUN send queue (0 = none), shared
/// between the receive dequeue and the TUN enqueue when [`PATH_TIMING`] is on.
///
/// Packets keep their order between the two points, so the oldest pending receive time is the
/// oldest datagram behind the next TUN run. With crypto workers it can be later than the true
/// one; it never makes a delay look longer than it was.
pub(crate) static PENDING_UDP_RX_NS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Oldest buffered-TUN-receive dequeue not yet handed to the UDP send queue (0 = none), the
/// outgoing twin of [`PENDING_UDP_RX_NS`].
pub(crate) static PENDING_TUN_RX_NS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Remember `now_ns` as the oldest pending start, unless an older one is already waiting.
pub(crate) fn mark_pending(slot: &std::sync::atomic::AtomicU64, now_ns: u64) {
    use std::sync::atomic::Ordering::Relaxed;
    let _ = slot.compare_exchange(0, now_ns.max(1), Relaxed, Relaxed);
}

/// Take the oldest pending start and record its age in `metric`.
pub(crate) fn take_pending(slot: &std::sync::atomic::AtomicU64, metric: &'static PathHistogram) {
    use std::sync::atomic::Ordering::Relaxed;
    let started = slot.swap(0, Relaxed);
    if started != 0 {
        metric.record(udp_send_monotonic_now().saturating_sub(started));
    }
}

/// Start the once-a-second printer thread the first time a metric records.
fn start_path_printer() {
    static STARTED: OnceLock<()> = OnceLock::new();
    STARTED.get_or_init(|| {
        let _ = std::thread::Builder::new()
            .name("gotatun-path-diag".into())
            .spawn(|| {
                loop {
                    // sleep: print interval of the opt-in diagnostic, not a packet-path wait
                    std::thread::sleep(std::time::Duration::from_secs(1));
                    let unix_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_millis())
                        .unwrap_or(0);
                    for metric in &path::ALL {
                        metric.flush(unix_ms);
                    }
                }
            });
    });
}

#[cfg(test)]
mod path_timing_tests {
    //! Pins the path-timing bucket map that the offline aggregator inverts (#260, J566).
    use super::{PATH_BUCKETS, path_bucket};

    /// Small values are exact; larger ones land in one of 8 slices per power of two, the map is
    /// monotonic, and the largest value stays inside the table.
    #[test]
    fn path_buckets_are_exact_then_logarithmic_and_monotonic() {
        assert_eq!(
            (0..8).map(path_bucket).collect::<Vec<_>>(),
            (0..8).collect::<Vec<_>>()
        );
        assert_eq!(path_bucket(8), 8);
        assert_eq!(path_bucket(15), 15);
        assert_eq!(path_bucket(16), 16);
        assert_eq!(path_bucket(1024), 8 + 7 * 8);
        let mut last = 0;
        for value in (0..1_000_000_u64).step_by(97).chain([u64::MAX]) {
            let bucket = path_bucket(value);
            assert!(
                bucket >= last && bucket < PATH_BUCKETS,
                "{value} → {bucket}"
            );
            last = bucket;
        }
    }
}
