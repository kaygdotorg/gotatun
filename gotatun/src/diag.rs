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

use std::{
    future::Future,
    sync::{
        OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

/// Process-relative monotonic origin for opt-in UDP send measurements.
static UDP_SEND_EPOCH: OnceLock<Instant> = OnceLock::new();

/// Process-wide, bounded measurements for the buffered UDP-to-TUN return path.
static UDP_TO_TUN_STATS: OnceLock<UdpToTunTiming> = OnceLock::new();

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

/// The oldest enabled receive timestamp in one prepared incoming run, or zero when disabled.
#[derive(Clone, Copy, Default)]
pub(crate) struct OldestReceiveTime(u64);

impl OldestReceiveTime {
    /// Keep the earliest nonzero process-relative timestamp supplied by buffered receive.
    pub(crate) fn record(&mut self, received_at_ns: u64) {
        if received_at_ns != 0 && (self.0 == 0 || received_at_ns < self.0) {
            self.0 = received_at_ns;
        }
    }

    /// Return the retained timestamp, or zero when diagnostics were disabled for the run.
    pub(crate) const fn get(self) -> u64 {
        self.0
    }
}

/// Bounded latency distributions for receive buffering and ordered tunnel delivery.
#[derive(Default)]
pub(crate) struct UdpToTunTiming {
    /// Time from socket receive completion until the buffered receiver dequeues a packet.
    buffered_receive_age: DurationHistogram,
    /// Time from socket receive completion until the device starts writing to its tunnel.
    receive_to_tun_start: DurationHistogram,
    /// Time from socket receive completion until the tunnel send finishes.
    receive_to_tun_done: DurationHistogram,
}

impl UdpToTunTiming {
    /// Record one packet's time inside GotaTun's bounded UDP receive channel.
    fn record_buffered_receive(&self, received_at_ns: u64, dequeued_at_ns: u64) {
        self.buffered_receive_age
            .record(dequeued_at_ns.saturating_sub(received_at_ns));
    }

    /// Record one incoming run from its oldest socket receive through tunnel send completion.
    fn record_delivery(&self, received_at_ns: u64, started_at_ns: u64, completed_at_ns: u64) {
        self.receive_to_tun_start
            .record(started_at_ns.saturating_sub(received_at_ns));
        self.receive_to_tun_done
            .record(completed_at_ns.saturating_sub(received_at_ns));
    }

    /// Print a single summary after measured device traffic has stopped.
    fn write_summary(&self) {
        let samples = self.receive_to_tun_done.count.load(Ordering::Relaxed);
        let buffered_samples = self.buffered_receive_age.count.load(Ordering::Relaxed);
        if samples == 0 && buffered_samples == 0 {
            return;
        }
        eprintln!(
            "udp_to_tun_summary buffered_samples={buffered_samples} buffered_age_p50_ns={:?} buffered_age_p95_ns={:?} buffered_age_p99_ns={:?} buffered_age_max_ns={:?} delivery_batches={samples} receive_to_tun_start_p50_ns={:?} receive_to_tun_start_p95_ns={:?} receive_to_tun_start_p99_ns={:?} receive_to_tun_start_max_ns={:?} receive_to_tun_done_p50_ns={:?} receive_to_tun_done_p95_ns={:?} receive_to_tun_done_p99_ns={:?} receive_to_tun_done_max_ns={:?}",
            self.buffered_receive_age.percentile_ns(50),
            self.buffered_receive_age.percentile_ns(95),
            self.buffered_receive_age.percentile_ns(99),
            self.buffered_receive_age.max_ns(),
            self.receive_to_tun_start.percentile_ns(50),
            self.receive_to_tun_start.percentile_ns(95),
            self.receive_to_tun_start.percentile_ns(99),
            self.receive_to_tun_start.max_ns(),
            self.receive_to_tun_done.percentile_ns(50),
            self.receive_to_tun_done.percentile_ns(95),
            self.receive_to_tun_done.percentile_ns(99),
            self.receive_to_tun_done.max_ns(),
        );
    }
}

/// Fixed-size latency histogram; the exact maximum is retained alongside approximate percentiles.
struct DurationHistogram {
    /// Counts by logarithmic duration bucket; updates allocate no memory and take no lock.
    buckets: [AtomicU64; 64],
    /// Number of durations recorded.
    count: AtomicU64,
    /// Exact maximum duration recorded in nanoseconds.
    max_ns: AtomicU64,
}

impl Default for DurationHistogram {
    /// Build the bounded histogram buckets without allocating.
    fn default() -> Self {
        Self {
            buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            count: AtomicU64::new(0),
            max_ns: AtomicU64::new(0),
        }
    }
}

impl DurationHistogram {
    /// Add one duration to its logarithmic bucket and retain its exact maximum.
    fn record(&self, ns: u64) {
        let bucket = if ns == 0 {
            0
        } else {
            (u64::BITS - 1 - ns.leading_zeros()) as usize
        };
        self.buckets[bucket].fetch_add(1, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
        self.max_ns.fetch_max(ns, Ordering::Relaxed);
    }

    /// Estimate a percentile using the upper edge of its logarithmic bucket.
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
                return Some(if index == 63 {
                    u64::MAX
                } else {
                    (1_u64 << (index + 1)) - 1
                });
            }
        }
        Some(u64::MAX)
    }

    /// Return the exact maximum duration when this histogram contains samples.
    fn max_ns(&self) -> Option<u64> {
        (self.count.load(Ordering::Relaxed) > 0)
            .then(|| self.max_ns.load(Ordering::Relaxed))
    }
}

/// Record the time a packet waited in GotaTun's buffered UDP receive channel.
pub(crate) fn record_buffered_udp_receive(received_at_ns: u64, dequeued_at_ns: u64) {
    UDP_TO_TUN_STATS
        .get_or_init(UdpToTunTiming::default)
        .record_buffered_receive(received_at_ns, dequeued_at_ns);
}

/// Record the oldest datagram in a run through the ordered tunnel send completion.
pub(crate) fn record_udp_to_tun_delivery(
    received_at_ns: u64,
    started_at_ns: u64,
    completed_at_ns: u64,
) {
    UDP_TO_TUN_STATS
        .get_or_init(UdpToTunTiming::default)
        .record_delivery(received_at_ns, started_at_ns, completed_at_ns);
}

/// Print the process-wide UDP-to-TUN summary, if an enabled receive path recorded samples.
pub(crate) fn write_udp_to_tun_summary() {
    if let Some(stats) = UDP_TO_TUN_STATS.get() {
        stats.write_summary();
    }
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

/// Measure buffered UDP receive through ordered tunnel delivery and completion.
pub(crate) static UDP_TO_TUN_TIMING: Switch = Switch::new("GOTATUN_DIAG_UDP_TO_TUN_TIMING");

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

#[cfg(test)]
mod tests {
    //! Checks monotonic stage accounting without asserting on real wall-clock speed.
    use super::*;

    /// Receive buffering and tunnel delivery keep their stage durations separate.
    #[test]
    fn udp_to_tun_histograms_measure_monotonic_stage_durations() {
        let timings = UdpToTunTiming::default();

        timings.record_buffered_receive(100, 180);
        timings.record_delivery(100, 200, 260);

        assert_eq!(timings.buffered_receive_age.max_ns(), Some(80));
        assert_eq!(timings.receive_to_tun_start.max_ns(), Some(100));
        assert_eq!(timings.receive_to_tun_done.max_ns(), Some(160));
    }

    /// An incoming run retains its earliest real receive time and ignores disabled timestamps.
    #[test]
    fn oldest_receive_time_ignores_zero_and_keeps_the_earliest_value() {
        let mut received = OldestReceiveTime::default();

        received.record(200);
        received.record(300);
        received.record(100);
        received.record(0);

        assert_eq!(received.get(), 100);
    }
}
