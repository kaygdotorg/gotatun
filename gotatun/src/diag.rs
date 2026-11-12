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

use std::sync::{
    OnceLock,
    atomic::{AtomicU64, Ordering},
};

/// Shared origin for timestamps in one opt-in pipeline diagnostic run.
static PIPELINE_EPOCH: OnceLock<std::time::Instant> = OnceLock::new();

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

/// Minimum time between opt-in crypto-queue snapshots, in nanoseconds.
const CRYPTO_QUEUE_SAMPLE_INTERVAL_NS: u64 = 100_000_000;

/// Marker used before the first sampled queue event.
const NO_CRYPTO_QUEUE_SAMPLE: u64 = u64::MAX;

/// Rate-limit sampled crypto-queue snapshots without locking the queue itself.
/// The atomic only reserves a sample time; queue contents use their own counter.
pub(crate) struct QueueDepthSampler {
    /// Monotonic timestamp of the last snapshot claimed by any queue worker.
    last_sample_ns: AtomicU64,
}

impl QueueDepthSampler {
    /// Start with no sample claimed so the first enabled queue event is recorded.
    pub(crate) const fn new() -> Self {
        Self {
            last_sample_ns: AtomicU64::new(NO_CRYPTO_QUEUE_SAMPLE),
        }
    }

    /// Whether this event may emit a sample at `now_ns`, at most once per 100 ms.
    pub(crate) fn is_due(&self, now_ns: u64) -> bool {
        let mut previous = self.last_sample_ns.load(Ordering::Relaxed);
        loop {
            if previous != NO_CRYPTO_QUEUE_SAMPLE
                && now_ns.saturating_sub(previous) < CRYPTO_QUEUE_SAMPLE_INTERVAL_NS
            {
                return false;
            }
            // This atomic only coordinates sample claims, so it needs no ordering with queue data.
            match self.last_sample_ns.compare_exchange_weak(
                previous,
                now_ns,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => previous = actual,
            }
        }
    }
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

/// Print one queue-depth snapshot at most every 100 ms when the queue changes.
pub(crate) static CRYPTO_QUEUE_DEPTH: Switch = Switch::new("GOTATUN_DIAG_CRYPTO_QUEUE_DEPTH");

/// Return monotonic nanoseconds since the first pipeline diagnostic event in this process.
pub(crate) fn pipeline_timestamp_ns() -> u128 {
    PIPELINE_EPOCH
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_nanos()
}

/// Print UDP and TUN send-queue reservations and releases.
pub(crate) static SEND_QUEUE: Switch = Switch::new("GOTATUN_DIAG_SEND_QUEUE");

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
    //! Keep the opt-in queue sampler bounded without relying on wall-clock sleeps.

    use super::QueueDepthSampler;

    /// Allow the first sample and then no more than one sample in each 100 ms interval.
    #[test]
    fn crypto_queue_depth_sampler_limits_samples_to_100ms_intervals() {
        let sampler = QueueDepthSampler::new();

        assert!(sampler.is_due(12));
        assert!(!sampler.is_due(100_000_011));
        assert!(sampler.is_due(100_000_012));
        assert!(!sampler.is_due(150_000_012));
        assert!(sampler.is_due(200_000_012));
    }
}
