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

/// Bench override of one packet-queue capacity, read once from the environment (#260, J687).
///
/// Returns `default` unless the variable `name` holds a positive integer. Used only to sweep the
/// macOS pipeline capacities without rebuilding; never set it in production.
pub(crate) fn capacity(name: &'static str, default: usize) -> usize {
    match std::env::var(name).ok().map(|value| value.parse::<usize>()) {
        Some(Ok(value)) if value > 0 => {
            eprintln!("diag capacity {name}={value} (default {default})");
            value
        }
        _ => default,
    }
}

/// How full one packet queue is right now, or `None` once the queue is gone.
pub(crate) type DepthProbe = Box<dyn Fn() -> Option<usize> + Send>;

/// Start the queue-depth sampler when `GOTATUN_DIAG_QUEUES` is set (#260, J687).
///
/// The variable's value is the sampling period in microseconds (default 1000). A plain OS
/// thread reads each named probe every period, so the sampler adds no wakes to the packet
/// runtime. Once per second it prints one line to stderr:
///
/// ```text
/// diag queues t_ms=<unix ms> n=<samples> out_tun=<p50>/<p99>/<max> udp_tx=... udp_rx=... in_tun=...
/// ```
///
/// The thread ends when every probe reports its queue gone. Bench builds only: it costs a
/// thread and a few hundred reads a second.
pub(crate) fn spawn_queue_sampler(probes: Vec<(&'static str, DepthProbe)>) {
    let Some(period) = std::env::var("GOTATUN_DIAG_QUEUES").ok() else {
        return;
    };
    let period = std::time::Duration::from_micros(period.parse().unwrap_or(1000).max(50));
    let spawned = std::thread::Builder::new()
        .name("diag-queues".into())
        .spawn(move || {
            let mut samples: Vec<Vec<usize>> = vec![Vec::with_capacity(2048); probes.len()];
            let mut second = std::time::Instant::now();
            loop {
                let mut alive = false;
                for ((_, probe), values) in probes.iter().zip(samples.iter_mut()) {
                    if let Some(depth) = probe() {
                        alive = true;
                        values.push(depth);
                    }
                }
                if !alive {
                    return;
                }
                if second.elapsed() >= std::time::Duration::from_secs(1) {
                    second = std::time::Instant::now();
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| d.as_millis());
                    let mut line = format!("diag queues t_ms={now}");
                    for ((name, _), values) in probes.iter().zip(samples.iter_mut()) {
                        values.sort_unstable();
                        let at = |q: usize| {
                            values
                                .get((values.len() * q / 100).min(values.len().saturating_sub(1)))
                                .copied()
                                .unwrap_or(0)
                        };
                        line.push_str(&format!(
                            " {name}={}/{}/{} n_{name}={}",
                            at(50),
                            at(99),
                            values.last().copied().unwrap_or(0),
                            values.len()
                        ));
                        values.clear();
                    }
                    eprintln!("{line}");
                }
                std::thread::sleep(period);
            }
        });
    if let Err(error) = spawned {
        eprintln!("diag queues: no sampler thread: {error}");
    }
}
