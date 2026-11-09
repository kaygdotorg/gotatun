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
