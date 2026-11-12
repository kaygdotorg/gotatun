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
    /// Monotonic run number used to join queue and syscall log lines.
    pub(crate) sequence: u64,
    /// Instant at which a queue permit accepted this run.
    pub(crate) enqueued_at: Instant,
    /// Process-relative monotonic timestamp for the queue insertion event.
    pub(crate) enqueued_mono_ns: u64,
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
    ) -> Self {
        let (enqueued_at, enqueued_mono_ns) = udp_send_monotonic_now();
        Self {
            sequence,
            enqueued_at,
            enqueued_mono_ns,
            outstanding_packets,
            batch_packets,
            batch_bytes,
        }
    }
}

/// Return the current instant and its process-relative monotonic timestamp.
pub(crate) fn udp_send_monotonic_now() -> (Instant, u64) {
    let epoch = *UDP_SEND_EPOCH.get_or_init(Instant::now);
    let now = Instant::now();
    let elapsed = now.saturating_duration_since(epoch).as_nanos();
    (now, u64::try_from(elapsed).unwrap_or(u64::MAX))
}

/// Convert a captured instant into the process-relative send-diagnostic clock.
pub(crate) fn udp_send_monotonic_ns(at: Instant) -> u64 {
    let epoch = *UDP_SEND_EPOCH.get_or_init(|| at);
    let elapsed = at.saturating_duration_since(epoch).as_nanos();
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
