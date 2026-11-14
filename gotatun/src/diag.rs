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

use std::sync::OnceLock;

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

/// Capacity of the TUN-read channel for a queue-size sweep (#260, J639).
///
/// Read once from `GOTATUN_DIAG_TUN_READ_QUEUE`; a positive packet count replaces the platform's
/// TUN-read channel capacity. Never set it in production.
pub(crate) fn tun_read_queue() -> Option<usize> {
    static QUEUE: OnceLock<Option<usize>> = OnceLock::new();
    *QUEUE.get_or_init(|| {
        let value = std::env::var("GOTATUN_DIAG_TUN_READ_QUEUE").ok()?;
        value.parse::<usize>().ok().filter(|n| *n > 0)
    })
}

/// Sample queue occupancy and batch sizes along the packet path (#260, J639).
///
/// When `GOTATUN_DIAG_QUEUE_DEPTH` is set, each stage records one value per batch into a
/// [`Gauge`], and a reporter thread prints one `qdepth` line to stderr every 100 ms with the
/// mean, maximum and count of every gauge since the previous line. Recording is a handful of
/// relaxed atomic operations per batch, not per packet, so the switch barely perturbs the
/// path it measures. Never set it in production.
pub(crate) static QUEUE_DEPTH: Switch = Switch::new("GOTATUN_DIAG_QUEUE_DEPTH");

/// One sampled quantity: running sum, sample count and maximum since the last report.
pub(crate) struct Gauge {
    /// Short name printed in the report line.
    name: &'static str,
    /// Sum of the values recorded since the last report.
    sum: std::sync::atomic::AtomicU64,
    /// Number of values recorded since the last report.
    count: std::sync::atomic::AtomicU64,
    /// Largest value recorded since the last report.
    max: std::sync::atomic::AtomicU64,
}

impl Gauge {
    /// Declare a gauge printed as `name`.
    const fn new(name: &'static str) -> Self {
        use std::sync::atomic::AtomicU64;
        Self {
            name,
            sum: AtomicU64::new(0),
            count: AtomicU64::new(0),
            max: AtomicU64::new(0),
        }
    }

    /// Record one value when [`QUEUE_DEPTH`] is on; a no-op otherwise.
    pub(crate) fn record(&self, value: usize) {
        use std::sync::atomic::Ordering::Relaxed;
        if !QUEUE_DEPTH.on() {
            return;
        }
        start_reporter();
        let value = value as u64;
        self.sum.fetch_add(value, Relaxed);
        self.count.fetch_add(1, Relaxed);
        self.max.fetch_max(value, Relaxed);
    }

    /// Take and reset this gauge's figures as `name=mean/max/count`.
    fn take(&self) -> String {
        use std::sync::atomic::Ordering::Relaxed;
        let sum = self.sum.swap(0, Relaxed);
        let count = self.count.swap(0, Relaxed);
        let max = self.max.swap(0, Relaxed);
        let mean = if count == 0 { 0 } else { sum / count };
        format!("{}={mean}/{max}/{count}", self.name)
    }
}

/// Packets waiting in the TUN-read channel right after the reader queued a batch.
pub(crate) static TUN_READ_OCCUPANCY: Gauge = Gauge::new("tun_read_occ");
/// Packets one TUN read returned (after GSO splitting).
pub(crate) static TUN_READ_BATCH: Gauge = Gauge::new("tun_read_batch");
/// Packets the outgoing task took from the TUN-read channel in one receive.
pub(crate) static OUTGOING_TAKE: Gauge = Gauge::new("out_take");
/// Packets held in the buffered UDP send queue right after a run was admitted.
pub(crate) static UDP_SEND_OCCUPANCY: Gauge = Gauge::new("udp_send_occ");
/// Packets in one run the UDP send task flushed.
pub(crate) static UDP_SEND_RUN: Gauge = Gauge::new("udp_send_run");
/// Datagrams one socket receive returned.
pub(crate) static UDP_RECV_BATCH: Gauge = Gauge::new("udp_recv_batch");
/// Packets held in the buffered TUN write queue right after a run was admitted.
pub(crate) static TUN_WRITE_OCCUPANCY: Gauge = Gauge::new("tun_write_occ");

/// Every gauge, in report order.
static GAUGES: [&Gauge; 7] = [
    &TUN_READ_BATCH,
    &TUN_READ_OCCUPANCY,
    &OUTGOING_TAKE,
    &UDP_SEND_OCCUPANCY,
    &UDP_SEND_RUN,
    &UDP_RECV_BATCH,
    &TUN_WRITE_OCCUPANCY,
];

/// Process-wide reference instant for diagnostic timestamps.
fn epoch() -> std::time::Instant {
    static EPOCH: OnceLock<std::time::Instant> = OnceLock::new();
    *EPOCH.get_or_init(std::time::Instant::now)
}

/// Start the 100 ms reporter thread once.
fn start_reporter() {
    static STARTED: OnceLock<()> = OnceLock::new();
    STARTED.get_or_init(|| {
        let _ = epoch();
        let _ = std::thread::Builder::new()
            .name("diag-qdepth".into())
            .spawn(|| {
                loop {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    let mut line = format!("qdepth t_ms={}", epoch().elapsed().as_millis());
                    for gauge in GAUGES {
                        line.push(' ');
                        line.push_str(&gauge.take());
                    }
                    eprintln!("{line}");
                }
            });
    });
}
