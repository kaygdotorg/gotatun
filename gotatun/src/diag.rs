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

/// Print each buffered stage's queue depth about ten times a second.
pub(crate) static QUEUE_DEPTH: Switch = Switch::new("GOTATUN_DIAG_QUEUE_DEPTH");

/// Reports how many packets wait in one buffered pipeline stage, for [`QUEUE_DEPTH`].
///
/// Each stage keeps one reporter and calls [`DepthReporter::sample`] whenever it dequeues. The
/// reporter remembers the deepest queue it saw and prints one line per ~100 ms window:
/// `queue_depth stage=<name> now=<packets> max=<packets>`. With the switch off a sample is one
/// cached flag check, so the packet path pays nothing measurable.
pub(crate) struct DepthReporter {
    /// Short stage name printed on each line, for example `tun_tx`.
    stage: &'static str,
    /// Start of the current reporting window.
    window_start: std::time::Instant,
    /// Deepest queue seen in the current window.
    max: usize,
}

impl DepthReporter {
    /// Create a reporter for the stage called `stage`.
    pub(crate) fn new(stage: &'static str) -> Self {
        Self {
            stage,
            window_start: std::time::Instant::now(),
            max: 0,
        }
    }

    /// Record that `queued` packets are waiting right now, printing once per window.
    pub(crate) fn sample(&mut self, queued: usize) {
        if !QUEUE_DEPTH.on() {
            return;
        }
        self.max = self.max.max(queued);
        if self.window_start.elapsed() >= std::time::Duration::from_millis(100) {
            eprintln!(
                "queue_depth stage={} now={queued} max={}",
                self.stage, self.max
            );
            self.max = 0;
            self.window_start = std::time::Instant::now();
        }
    }
}
