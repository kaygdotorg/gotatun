// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Receive-side active queue management: GotaTun bounds its own queue (infraternal D397, #260).
//!
//! # Why this exists
//! A TUN device orphans every skb when the kernel hands it to us, so TCP Small Queues never sees
//! the packets waiting inside this engine. Bulk TCP flows through the tunnel therefore run at
//! their full congestion window, and that window stands as queue on the receiving side: mostly
//! in the UDP socket's receive buffer, then in the decrypt-and-order stage (J657, J691). Nothing
//! in the engine ever drops, so loss-based senders (cubic) grow into that queue without bound.
//!
//! This module lets the engine bound the queue itself. It measures each packet's *sojourn time*
//! from the moment the kernel timestamped the datagram on the UDP socket (`SO_TIMESTAMPNS`) to
//! the moment an in-order run is ready for the buffered TUN handoff. That interval covers the
//! socket backlog, crypto and ordering delays, and time waiting behind previous TUN handoffs. A CoDel controller (RFC 8289) then signals
//! congestion at that dequeue point when the sojourn stays above `target` for at least
//! `interval`: by default (RFC 3168) by setting CE on an ECN-capable inner packet, and by
//! dropping only packets that are not ECN-capable.
//!
//! Wall time measures receive age. Monotonic time drives episode deadlines and credit refill.
//! Below-target ages or an observed gap between one peer's dequeue and its next arrival end the
//! episode. A gap in observations alone can be a CPU, peer-lock or TUN stall. It expires old
//! congestion evidence after one interval without treating the backlog as empty.
//!
//! Small packets share one per-peer byte allowance, independent of flow keys: at most 256 bytes
//! per authenticated plaintext frame (including padding), 32 KiB per 10 ms, and a 64 KiB
//! burst. Larger frames remain subject to CoDel; header changes use only the validated IP packet.
//! See [`SparseBudget`] for measurement rationale, overload and recovery behavior.
//!
//! # Defaults and how to turn it off
//! On by default where the kernel gives us receive stamps (Linux), in ECN mode, with a 1 ms
//! target and a 10 ms interval. J711 measured those on backup01: RFC 8289's 5 ms / 100 ms barely
//! fires, because one receive batch alone spends ~2.5 ms in the pipeline. Elsewhere there is no
//! stamp to judge, so the bound stays off and the data path is unchanged.
//!
//! The environment of the process that runs the device can change it, read once at start:
//! - `GOTATUN_AQM=off` turns the bound off (diagnosis: the engine behaves as it did before the
//!   bound); `=drop` drops instead of marking; `=ecn` is the default.
//! - `GOTATUN_AQM_TARGET_US` (default 1000) and `GOTATUN_AQM_INTERVAL_US` (default 10000) are
//!   the CoDel target and interval, in microseconds.
//! - `GOTATUN_AQM_STATS_MS` and/or `GOTATUN_AQM_STATS_PATH` turn on a counter line per period
//!   (default 1000 ms) with the cumulative packets seen, drops, CE marks and the sojourn mean/max
//!   of that period. The lines go to stderr, or are appended to `$GOTATUN_AQM_STATS_PATH.<pid>`
//!   when that is set (a harness may own the engine's stderr). Without either variable the data
//!   path keeps only the drop and mark counters, which move once per signal, not per packet.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// How the controller signals congestion once CoDel decides to act on a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AqmMode {
    /// No AQM: every packet passes, as before the bound existed.
    Off,
    /// Drop the packet CoDel picks.
    Drop,
    /// Mark CE on the packet CoDel picks when its inner IP header is ECN-capable; drop otherwise.
    Ecn,
}

/// Whether this platform's UDP receive path records kernel receive stamps. Without them no
/// sojourn can be measured, so the bound is off whatever the environment says.
const STAMPS_SUPPORTED: bool = cfg!(target_os = "linux");

/// The default CoDel target, 1 ms (J711, see the module docs).
const DEFAULT_TARGET_US: u64 = 1_000;
/// The default CoDel interval, 10 ms (J711, see the module docs).
const DEFAULT_INTERVAL_US: u64 = 10_000;

/// The process-wide AQM settings, read once from the environment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AqmConfig {
    /// What to do with a packet CoDel picks.
    pub(crate) mode: AqmMode,
    /// Sojourn time the queue may keep standing without being signalled, in nanoseconds.
    pub(crate) target_ns: u64,
    /// How long the sojourn must stay above target before the first signal, in nanoseconds.
    /// It is also the base of CoDel's control law (`interval / sqrt(count)`).
    pub(crate) interval_ns: u64,
    /// The stats period in milliseconds, or `None` when no stats were asked for. Per-packet
    /// sojourn counters only run when this is set, so the default path pays no shared atomics.
    pub(crate) stats_ms: Option<u64>,
}

impl AqmConfig {
    /// Read the configuration through `lookup` (the environment in production, a map in tests).
    /// Unset, empty, unparsable or overflowing durations use their defaults. An unknown mode
    /// warns and keeps ECN mode enabled.
    fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        let mode = match lookup("GOTATUN_AQM").as_deref().map(str::trim) {
            None | Some("" | "ecn" | "on" | "1") => AqmMode::Ecn,
            Some("off" | "0" | "none") => AqmMode::Off,
            Some("drop" | "codel") => AqmMode::Drop,
            Some(other) => {
                tracing::warn!("GOTATUN_AQM={other:?} is not off|ecn|drop; keeping ecn");
                AqmMode::Ecn
            }
        };
        let positive = |name: &str| {
            lookup(name)
                .and_then(|value| value.trim().parse::<u64>().ok())
                .filter(|&value| value > 0)
        };
        let stats_ms = match (
            positive("GOTATUN_AQM_STATS_MS"),
            lookup("GOTATUN_AQM_STATS_PATH").is_some(),
        ) {
            (Some(period), _) => Some(period),
            (None, true) => Some(1_000),
            (None, false) => None,
        };
        let nanos = |name, default_us| {
            positive(name)
                .and_then(|us| us.checked_mul(1_000))
                .unwrap_or(default_us * 1_000)
        };
        Self {
            mode,
            target_ns: nanos("GOTATUN_AQM_TARGET_US", DEFAULT_TARGET_US),
            interval_ns: nanos("GOTATUN_AQM_INTERVAL_US", DEFAULT_INTERVAL_US),
            stats_ms,
        }
    }

    /// Whether the bound judges packets at all: a mode other than off, on a platform with
    /// receive stamps.
    fn active(&self) -> bool {
        STAMPS_SUPPORTED && self.mode != AqmMode::Off
    }
}

/// The settings for this process. The first call reads the environment and, when stats were
/// asked for, starts the stats printer.
pub(crate) fn config() -> &'static AqmConfig {
    static CONFIG: OnceLock<AqmConfig> = OnceLock::new();
    CONFIG.get_or_init(|| {
        let config = AqmConfig::from_lookup(|name| std::env::var(name).ok());
        if config.active()
            && let Some(period_ms) = config.stats_ms
        {
            start_stats_printer(config, period_ms);
        }
        config
    })
}

/// Whether receive timestamps are needed and packets are judged. Cheap after the first call.
pub(crate) fn enabled() -> bool {
    config().active()
}

/// Packets dropped by the controller, since start.
static DROPS: AtomicU64 = AtomicU64::new(0);
/// Packets marked CE by the controller, since start.
static MARKS: AtomicU64 = AtomicU64::new(0);
/// Packets the controller looked at, since start (stats only).
static SEEN: AtomicU64 = AtomicU64::new(0);
/// Packets that arrived without a kernel timestamp and so could not be judged (stats only).
static UNSTAMPED: AtomicU64 = AtomicU64::new(0);
/// Sum of sojourn times in the current stats period, in microseconds (stats only).
static SOJOURN_SUM_US: AtomicU64 = AtomicU64::new(0);
/// Number of sojourn samples in the current stats period (stats only).
static SOJOURN_COUNT: AtomicU64 = AtomicU64::new(0);
/// Largest sojourn in the current stats period, in microseconds (stats only).
static SOJOURN_MAX_US: AtomicU64 = AtomicU64::new(0);

/// Print one cumulative counter line per period on a plain thread, so the data path never pays
/// for formatting. The thread lives as long as the process; it only exists when asked for.
fn start_stats_printer(config: AqmConfig, period_ms: u64) {
    use std::io::Write as _;
    let mut file = std::env::var("GOTATUN_AQM_STATS_PATH")
        .ok()
        .and_then(|path| {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(format!("{path}.{}", std::process::id()))
                .ok()
        });
    let spawned = std::thread::Builder::new()
        .name("gotatun-aqm-stats".into())
        .spawn(move || {
            loop {
                std::thread::sleep(Duration::from_millis(period_ms));
                let count = SOJOURN_COUNT.swap(0, Ordering::Relaxed);
                let sum = SOJOURN_SUM_US.swap(0, Ordering::Relaxed);
                let max = SOJOURN_MAX_US.swap(0, Ordering::Relaxed);
                let line = format!(
                    "gotatun-aqm t={:.3} mode={:?} target_us={} interval_us={} seen={} drops={} marks={} unstamped={} sojourn_mean_us={} sojourn_max_us={max}",
                    realtime_ns() as f64 / 1e9,
                    config.mode,
                    config.target_ns / 1_000,
                    config.interval_ns / 1_000,
                    SEEN.load(Ordering::Relaxed),
                    DROPS.load(Ordering::Relaxed),
                    MARKS.load(Ordering::Relaxed),
                    UNSTAMPED.load(Ordering::Relaxed),
                    sum.checked_div(count).unwrap_or(0),
                );
                match file.as_mut() {
                    Some(file) => {
                        let _ = writeln!(file, "{line}");
                    }
                    None => eprintln!("{line}"),
                }
            }
        });
    if let Err(err) = spawned {
        tracing::warn!("AQM stats printer did not start: {err}");
    }
}

/// The wall clock in nanoseconds, on the same clock (`CLOCK_REALTIME`) as `SO_TIMESTAMPNS`.
pub(crate) fn realtime_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// What the controller decided for one packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Deliver unchanged.
    Pass,
    /// Deliver with CE set (already applied to the packet).
    Marked,
    /// Do not deliver.
    Drop,
}

/// The two clocks sampled together at the first eligible dequeue in an in-order run.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct DequeueTime {
    /// Realtime nanoseconds since the Unix epoch, comparable with the kernel receive stamp.
    wall_ns: u64,
    /// Monotonic nanoseconds since an arbitrary, process-wide starting point.
    mono_ns: u64,
}

impl DequeueTime {
    /// Read both clocks once under the peer lock, before handing the run to the TUN.
    pub(crate) fn now() -> Self {
        use std::time::Instant;
        static START: OnceLock<Instant> = OnceLock::new();
        let start = START.get_or_init(Instant::now);
        Self {
            wall_ns: realtime_ns(),
            mono_ns: u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX),
        }
    }
}

/// State of one peer's receive queue, with an observation phase before signalling.
#[derive(Debug, Default)]
pub(crate) struct Codel {
    /// Initial observation deadline or next signal deadline. Zero means no current evidence.
    deadline_ns: u64,
    /// The newest above-target observation and the reference for an arrival after dequeue.
    last_above: DequeueTime,
    /// Signals earned in this episode. Zero while observing.
    count: u32,
    /// Signals deferred by the small-packet budget, capped to avoid an unbounded burst.
    owed: u8,
    /// Aggregate byte credit; packet addresses and flow keys never affect eligibility.
    sparse: SparseBudget,
}

/// Maximum pending signals transferred to subsequent non-exempt packets.
const MAX_OWED_SIGNALS: u8 = 4;
/// Largest exempt authenticated frame, above measured 216-byte SSH packets plus normal padding.
const SPARSE_MAX_PACKET_BYTES: usize = 256;
/// Small-packet allowance per refill interval, covering measured ACK and interactive bursts.
const SPARSE_BYTES: u64 = 32 * 1024;
/// Fixed 10 ms refill period, independent of a diagnostic CoDel interval override.
const SPARSE_INTERVAL_NS: u64 = 10_000_000;
/// Maximum accumulated allowance; two refill windows prevent interval-edge burst penalties.
const SPARSE_BURST_BYTES: u64 = 64 * 1024;
/// Receive ages beyond one second or in the future are invalid and never signal.
/// Realtime receive stamps cannot distinguish smaller clock steps from genuine queue age.
const MAX_SOJOURN_NS: u64 = 1_000_000_000;

/// One peer's aggregate small-packet token bucket, without flow classification or allocation.
///
/// Measurements on #260 chose a 256-byte ceiling, 32 KiB per 10 ms, and a 64 KiB burst.
/// Lengths include authenticated padding before IP decoding truncates the frame. A peer cannot
/// hide a large decrypt/queue workload behind a small inner IP total-length field.
/// All above-target eligible bytes spend credit, including packets with no signal due. Large
/// packets never receive or consume the allowance, so line-rate bulk cannot starve keystrokes,
/// ACKs or probes. Small-packet floods exhaust it and become subject to the same controller.
/// A signal does not replenish credit. Drain and invalid timestamps reset it. At zero credit,
/// 20 ms without eligible traffic restores the whole burst; there is no inherited byte debt.
///
/// Below-envelope traffic passes even if every packet changes keys: with equal sizes, times
/// and queue samples, keys cannot affect the verdict. Such sparse aggregate traffic is within
/// the allowance, rather than a churn escape. No finite allowance can protect unlimited small
/// traffic, so simultaneous sparse streams must share the stated envelope.
#[derive(Debug)]
struct SparseBudget {
    /// Byte-nanoseconds of credit, so frequent sub-byte refills cannot lose fractional bytes.
    credit: u64,
    /// Most recent refill time; moving the clock backwards cannot mint duplicate credit.
    last_ns: u64,
}

impl Default for SparseBudget {
    /// Begin with one bounded burst, also used after a queue drain or invalid timestamp.
    fn default() -> Self {
        Self {
            credit: SPARSE_BURST_BYTES * SPARSE_INTERVAL_NS,
            last_ns: 0,
        }
    }
}

impl SparseBudget {
    /// Spend the whole eligible packet from the shared bucket, whether or not a signal is due.
    /// Saturating multiplication and the burst cap bound arbitrary gaps and clock values.
    fn exempt(&mut self, len: usize, now_ns: u64) -> bool {
        if len > SPARSE_MAX_PACKET_BYTES {
            return false;
        }
        let elapsed = now_ns.saturating_sub(self.last_ns);
        self.credit = self
            .credit
            .saturating_add(elapsed.saturating_mul(SPARSE_BYTES))
            .min(SPARSE_BURST_BYTES * SPARSE_INTERVAL_NS);
        self.last_ns = self.last_ns.max(now_ns);
        let cost = len as u64 * SPARSE_INTERVAL_NS;
        if self.credit < cost {
            return false;
        }
        self.credit -= cost;
        true
    }
}

impl Codel {
    /// Discard evidence and deferred signals without replenishing the byte allowance.
    fn end_episode(&mut self) {
        self.deadline_ns = 0;
        self.count = 0;
        self.owed = 0;
    }

    /// Realtime of the latest above-target dequeue, for the socket-to-TUN regression.
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn above_target_wall_ns(&self) -> Option<u64> {
        (self.deadline_ns != 0).then_some(self.last_above.wall_ns)
    }

    /// Update congestion evidence and return whether this observation earns a signal.
    fn should_signal(
        &mut self,
        now: DequeueTime,
        rx_ns: u64,
        sojourn_ns: u64,
        config: &AqmConfig,
    ) -> bool {
        if sojourn_ns < config.target_ns {
            *self = Self::default();
            return false;
        }
        let gap = now.mono_ns.saturating_sub(self.last_above.mono_ns);
        if self.deadline_ns != 0 {
            let drained_by_age = gap > sojourn_ns;
            let drained_by_stamp = rx_ns > self.last_above.wall_ns;
            if drained_by_age && drained_by_stamp {
                // Both comparisons place the next arrival after the prior dequeue.
                *self = Self::default();
            } else if gap > config.interval_ns
                || drained_by_age
                || (drained_by_stamp && rx_ns - self.last_above.wall_ns <= gap)
            {
                // A long silence expires old observations. A drain indicated by age alone
                // may have been hidden by a backward wall-clock step. A newer stamp within
                // the previous wall epoch's monotonic window could have preceded a forward
                // step that inflated its age. A stamp beyond that window can be fresh in
                // the new epoch, so it cannot establish a drain on its own.
                // Keep byte credit when the two comparisons disagree.
                self.end_episode();
            }
        }
        self.last_above = now;
        if self.deadline_ns == 0 {
            self.deadline_ns = now.mono_ns.saturating_add(config.interval_ns);
            return false;
        }

        let deadline = self.deadline_ns;
        if now.mono_ns < deadline {
            return false;
        }

        let first = self.count == 0;
        self.count = self.count.saturating_add(1);
        let spacing = (config.interval_ns as f64 / f64::from(self.count).sqrt()) as u64;
        let spacing = spacing.max(1);
        let next = deadline.saturating_add(spacing);
        // Keep the control law's phase through small scheduling delays. Once another deadline
        // is already past, rebase the schedule so a stalled run can earn only one new signal.
        self.deadline_ns = if first || next <= now.mono_ns {
            now.mono_ns.saturating_add(spacing)
        } else {
            next
        };
        true
    }
}

/// Judge one in-order packet about to be written to the TUN, and apply the verdict's header
/// change. `authenticated_len` includes padding before IP validation trims the plaintext.
/// The size ceiling and credit use that length; only `packet` is ever changed.
/// `rx_ns` is the kernel receive timestamp of its datagram (0 if none). Reuse `now` for the run.
pub(crate) fn judge(
    codel: &mut Codel,
    packet: &mut [u8],
    authenticated_len: usize,
    rx_ns: u64,
    now: DequeueTime,
) -> Verdict {
    let config = config();
    if !config.active() {
        return Verdict::Pass;
    }
    judge_frame_with(codel, packet, authenticated_len, rx_ns, now, config)
}

/// Test seam for ordinary frames with their normal sixteen-byte padding alignment.
#[cfg(test)]
fn judge_with(
    codel: &mut Codel,
    packet: &mut [u8],
    rx_ns: u64,
    now_ns: u64,
    config: &AqmConfig,
) -> Verdict {
    judge_with_time(codel, packet, rx_ns, test_time(now_ns), config)
}

/// Judge a normally padded frame with independently controlled clocks.
#[cfg(test)]
fn judge_with_time(
    codel: &mut Codel,
    packet: &mut [u8],
    rx_ns: u64,
    now: DequeueTime,
    config: &AqmConfig,
) -> Verdict {
    let authenticated_len = packet.len().next_multiple_of(16);
    judge_frame_with(codel, packet, authenticated_len, rx_ns, now, config)
}

/// Both clocks advance together in the ordinary virtual dequeue trace.
#[cfg(test)]
fn test_time(ns: u64) -> DequeueTime {
    DequeueTime {
        wall_ns: ns,
        mono_ns: ns,
    }
}

/// Judge validated IP bytes with the pre-trim authenticated plaintext length, assumed active.
/// Clamp an undersized caller value to the inner length so it cannot undercharge the packet.
fn judge_frame_with(
    codel: &mut Codel,
    packet: &mut [u8],
    authenticated_len: usize,
    rx_ns: u64,
    now: DequeueTime,
    config: &AqmConfig,
) -> Verdict {
    let stats = config.stats_ms.is_some();
    if stats {
        SEEN.fetch_add(1, Ordering::Relaxed);
    }
    if rx_ns == 0 {
        if stats {
            UNSTAMPED.fetch_add(1, Ordering::Relaxed);
        }
        return Verdict::Pass;
    }
    let Some(sojourn_ns) = now
        .wall_ns
        .checked_sub(rx_ns)
        .filter(|&age| age <= MAX_SOJOURN_NS)
    else {
        // An invalid sample breaks continuity. Forget deadlines and debt so the next valid
        // packet must establish a fresh above-target interval instead of catching up signals.
        *codel = Codel::default();
        return Verdict::Pass;
    };
    if stats {
        let sojourn_us = sojourn_ns / 1_000;
        SOJOURN_SUM_US.fetch_add(sojourn_us, Ordering::Relaxed);
        SOJOURN_COUNT.fetch_add(1, Ordering::Relaxed);
        SOJOURN_MAX_US.fetch_max(sojourn_us, Ordering::Relaxed);
    }

    let due = codel.should_signal(now, rx_ns, sojourn_ns, config);
    if codel.deadline_ns == 0 {
        return Verdict::Pass;
    }
    let charged_len = authenticated_len.max(packet.len());
    let exempt = codel.sparse.exempt(charged_len, now.mono_ns);
    if due {
        codel.owed = codel.owed.saturating_add(1).min(MAX_OWED_SIGNALS);
    }
    if codel.owed == 0 || exempt {
        return Verdict::Pass;
    }
    codel.owed -= 1;
    if config.mode == AqmMode::Ecn && set_ce(packet) {
        MARKS.fetch_add(1, Ordering::Relaxed);
        return Verdict::Marked;
    }
    DROPS.fetch_add(1, Ordering::Relaxed);
    Verdict::Drop
}

/// The ECN codepoint "Congestion Experienced" (RFC 3168 §5).
const ECN_CE: u8 = 0b11;

/// Set CE in an IPv4 or IPv6 header if the packet is ECN-capable (ECT(0), ECT(1) or already CE).
///
/// Returns false, leaving the packet untouched, for Not-ECT packets and anything too short to be
/// an IP header: RFC 3168 §5 forbids marking a transport that didn't negotiate ECN, so those are
/// dropped instead. IPv4 keeps its header checksum valid with the incremental update of RFC 1624
/// (only the first 16-bit word changes); IPv6 has no header checksum.
pub(crate) fn set_ce(packet: &mut [u8]) -> bool {
    let Some(&first) = packet.first() else {
        return false;
    };
    match first >> 4 {
        4 if packet.len() >= 20 => {
            let ecn = packet[1] & 0b11;
            if ecn == 0 {
                return false;
            }
            if ecn == ECN_CE {
                return true;
            }
            let old_word = u16::from_be_bytes([packet[0], packet[1]]);
            packet[1] |= ECN_CE;
            let new_word = u16::from_be_bytes([packet[0], packet[1]]);
            let old_sum = u16::from_be_bytes([packet[10], packet[11]]);
            // RFC 1624 eqn. 3: HC' = ~(~HC + ~m + m'), in one's-complement arithmetic.
            let mut sum = u32::from(!old_sum) + u32::from(!old_word) + u32::from(new_word);
            while sum > 0xffff {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            let new_sum = !(sum as u16);
            packet[10..12].copy_from_slice(&new_sum.to_be_bytes());
            true
        }
        6 if packet.len() >= 40 => {
            // Traffic class spans the low nibble of byte 0 and the high nibble of byte 1; its two
            // ECN bits are bits 5..4 of byte 1.
            let ecn = (packet[1] >> 4) & 0b11;
            if ecn == 0 {
                return false;
            }
            packet[1] |= ECN_CE << 4;
            true
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: u64 = 1_000_000;

    fn config(mode: AqmMode) -> AqmConfig {
        AqmConfig {
            mode,
            target_ns: 5 * MS,
            interval_ns: 100 * MS,
            stats_ms: None,
        }
    }

    /// The configuration a process would read from exactly these environment variables.
    fn from_vars(vars: &[(&str, &str)]) -> AqmConfig {
        AqmConfig::from_lookup(|name| {
            vars.iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_owned())
        })
    }

    #[test]
    fn default_is_ecn_one_ms_target_ten_ms_interval_without_stats() {
        let config = from_vars(&[]);
        assert_eq!(config.mode, AqmMode::Ecn);
        assert_eq!(config.target_ns, MS);
        assert_eq!(config.interval_ns, 10 * MS);
        assert_eq!(config.stats_ms, None);
        assert_eq!(config.active(), cfg!(target_os = "linux"));
    }

    #[test]
    fn the_off_switch_turns_the_bound_off() {
        for value in ["off", "0", "none", " off "] {
            let config = from_vars(&[("GOTATUN_AQM", value)]);
            assert_eq!(config.mode, AqmMode::Off, "{value:?}");
            assert!(!config.active());
        }
    }

    #[test]
    fn modes_and_knobs_are_read_and_typos_keep_ecn() {
        let config = from_vars(&[
            ("GOTATUN_AQM", "drop"),
            ("GOTATUN_AQM_TARGET_US", "2500"),
            ("GOTATUN_AQM_INTERVAL_US", "50000"),
            ("GOTATUN_AQM_STATS_PATH", "/tmp/x"),
        ]);
        assert_eq!(config.mode, AqmMode::Drop);
        assert_eq!(config.target_ns, 2_500_000);
        assert_eq!(config.interval_ns, 50 * MS);
        assert_eq!(config.stats_ms, Some(1_000));
        let typo = from_vars(&[("GOTATUN_AQM", "of"), ("GOTATUN_AQM_TARGET_US", "0")]);
        assert_eq!(typo.mode, AqmMode::Ecn);
        assert_eq!(typo.target_ns, MS, "zero falls back to the default");
    }

    /// A one's-complement IPv4 header checksum over the 20-byte header, for checking.
    fn ipv4_checksum_ok(header: &[u8]) -> bool {
        let mut sum: u32 = header[..20]
            .chunks(2)
            .map(|word| u32::from(u16::from_be_bytes([word[0], word[1]])))
            .sum();
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        sum == 0xffff
    }

    fn ipv4_header(tos: u8) -> Vec<u8> {
        let mut header = vec![
            0x45, tos, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 10, 0, 0, 1, 10,
            0, 0, 2,
        ];
        let mut sum: u32 = header
            .chunks(2)
            .map(|word| u32::from(u16::from_be_bytes([word[0], word[1]])))
            .sum();
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        header[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
        header
    }

    #[test]
    fn below_target_never_signals() {
        let mut codel = Codel::default();
        let config = config(AqmMode::Drop);
        for step in 0..10_000 {
            assert!(!codel.should_signal(test_time(step * MS), 0, 4 * MS, &config));
        }
    }

    /// A continuous backlog gets its first signal at the observation deadline.
    #[test]
    fn first_signal_waits_one_interval_above_target() {
        let mut codel = Codel::default();
        let config = config(AqmMode::Drop);
        let stamp = 4 * MS;
        assert!(!codel.should_signal(test_time(10 * MS), stamp, 6 * MS, &config));
        assert!(!codel.should_signal(test_time(109 * MS), stamp, 105 * MS, &config));
        assert!(codel.should_signal(test_time(110 * MS), stamp, 106 * MS, &config));
    }

    #[test]
    fn signal_spacing_shrinks_with_the_square_root_of_count() {
        let mut codel = Codel::default();
        let config = config(AqmMode::Drop);
        codel.should_signal(test_time(0), 0, 6 * MS, &config);
        let mut signals = Vec::new();
        for step in 1..=400 {
            let now = step * MS;
            if codel.should_signal(test_time(now), 0, 6 * MS, &config) {
                signals.push(now);
            }
        }
        // Entry at 100 ms (count 1), the next one interval/sqrt(1) later, then 100/sqrt(2) ≈
        // 70.7 ms and 100/sqrt(3) ≈ 57.7 ms apart (checked on 1 ms steps).
        assert_eq!(signals[0], 100 * MS);
        assert_eq!(signals[1], 200 * MS);
        assert_eq!(signals[2], 271 * MS);
        assert_eq!(signals[3], 329 * MS);
        assert!(signals.windows(2).all(|pair| pair[1] > pair[0]));
    }

    /// A below-target packet clears the prior episode before fresh backlog can signal.
    #[test]
    fn falling_below_target_leaves_the_signalling_state() {
        let mut codel = Codel::default();
        let config = config(AqmMode::Drop);
        let stamp = 4 * MS;
        codel.should_signal(test_time(10 * MS), stamp, 6 * MS, &config);
        assert!(codel.should_signal(test_time(110 * MS), stamp, 106 * MS, &config));
        assert!(!codel.should_signal(test_time(111 * MS), 110 * MS, MS, &config));
        // A new episode needs another full interval above target.
        let stamp = 111 * MS;
        assert!(!codel.should_signal(test_time(117 * MS), stamp, 6 * MS, &config));
        assert!(!codel.should_signal(test_time(216 * MS), stamp, 105 * MS, &config));
        assert!(codel.should_signal(test_time(217 * MS), stamp, 106 * MS, &config));
    }

    #[test]
    fn ce_mark_keeps_the_ipv4_checksum_valid() {
        for tos in [0x01, 0x02, 0xb9, 0xfe] {
            let mut header = ipv4_header(tos);
            assert!(ipv4_checksum_ok(&header));
            assert!(set_ce(&mut header));
            assert_eq!(header[1] & 0b11, ECN_CE);
            assert_eq!(header[1] >> 2, tos >> 2, "DSCP is preserved");
            assert!(ipv4_checksum_ok(&header), "tos {tos:#x}");
        }
    }

    #[test]
    fn not_ect_packets_are_not_marked() {
        let mut header = ipv4_header(0xb8);
        let before = header.clone();
        assert!(!set_ce(&mut header));
        assert_eq!(header, before);

        let mut ipv6 = vec![0u8; 40];
        ipv6[0] = 0x60;
        assert!(!set_ce(&mut ipv6));
    }

    #[test]
    fn ipv6_ect_is_marked_in_the_traffic_class() {
        let mut ipv6 = vec![0u8; 40];
        // Version 6, traffic class 0xb9 (DSCP 46, ECT(1)), flow label 0x12345.
        ipv6[0] = 0x6b;
        ipv6[1] = 0x91;
        ipv6[2] = 0x23;
        ipv6[3] = 0x45;
        assert!(set_ce(&mut ipv6));
        let traffic_class = ((ipv6[0] & 0x0f) << 4) | (ipv6[1] >> 4);
        assert_eq!(traffic_class, 0xbb);
        assert_eq!(ipv6[1] & 0x0f, 0x01, "flow label is preserved");
    }

    /// A 1,400-byte IPv4 TCP segment of the flow `10.0.0.1:sport → 10.0.0.2:5201` with the given
    /// ECN field, as a bulk sender would put on the wire.
    fn tcp_v4(sport: u16, ecn: u8, len: usize) -> Vec<u8> {
        let mut packet = ipv4_header(ecn);
        packet[2..4].copy_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
        packet.resize(len, 0);
        packet[20..22].copy_from_slice(&sport.to_be_bytes());
        packet[22..24].copy_from_slice(&5201_u16.to_be_bytes());
        packet
    }

    /// An 84-byte Not-ECT ICMP echo, the shape of the kit's latency probes.
    fn icmp_probe() -> Vec<u8> {
        let mut packet = ipv4_header(0);
        packet[9] = 1;
        packet.resize(84, 0);
        packet
    }

    /// The working configuration: ECN mode, 1 ms target, 10 ms interval.
    fn ecn_1_10() -> AqmConfig {
        AqmConfig {
            mode: AqmMode::Ecn,
            target_ns: MS,
            interval_ns: 10 * MS,
            stats_ms: None,
        }
    }

    /// Drive `flows` interleaved bulk flows (one packet each per 10 µs step, sojourn 3 ms) for
    /// `duration_ms`, starting at `start_ns`. Returns the verdicts per flow and the end time.
    fn drive_bulk(
        codel: &mut Codel,
        config: &AqmConfig,
        flows: u16,
        ecn: u8,
        start_ns: u64,
        duration_ms: u64,
    ) -> (Vec<Vec<Verdict>>, u64) {
        let mut verdicts = vec![Vec::new(); usize::from(flows)];
        let mut now = start_ns;
        let end = start_ns + duration_ms * MS;
        while now < end {
            for flow in 0..flows {
                let mut packet = tcp_v4(40_000 + flow, ecn, 1_400);
                let verdict = judge_with(codel, &mut packet, now - 3 * MS, now, config);
                verdicts[usize::from(flow)].push(verdict);
                now += 10_000;
            }
        }
        (verdicts, now)
    }

    #[test]
    fn a_sparse_packet_never_takes_a_due_signal_the_next_bulk_packet_does() {
        let config = ecn_1_10();
        let mut codel = Codel::default();
        // An ECN bulk sender that never backs off (BBRv1) keeps the controller signalling.
        let (verdicts, now) = drive_bulk(&mut codel, &config, 1, 0b10, 10 * MS, 200);
        assert!(
            verdicts[0].contains(&Verdict::Marked),
            "the bulk flow is signalled"
        );
        assert!(codel.count != 0);
        // The next signal is due exactly when a Not-ECT probe reaches the TUN.
        let due = codel.deadline_ns.max(now);
        let mut probe = icmp_probe();
        assert_eq!(
            judge_with(&mut codel, &mut probe, due - 3 * MS, due, &config),
            Verdict::Pass,
            "a probe sharing the tunnel with bulk is never dropped for the bulk's queue"
        );
        let mut bulk = tcp_v4(40_000, 0b10, 1_400);
        assert_eq!(
            judge_with(
                &mut codel,
                &mut bulk,
                due - 3 * MS + 10_000,
                due + 10_000,
                &config
            ),
            Verdict::Marked,
            "the signal the probe skipped goes to the queue-heavy flow"
        );
    }

    #[test]
    fn probes_beside_a_bulk_flow_that_never_backs_off_are_never_dropped() {
        let config = ecn_1_10();
        let mut codel = Codel::default();
        let mut now = 10 * MS;
        let mut probe_drops = 0;
        let mut marks = 0;
        // 2 s of bulk at one packet per 10 µs, a probe every 0.25 ms, and the probe placed
        // right on the due signal whenever one is pending (the worst case for the probe).
        for step in 0..200_000_u64 {
            if step % 25 == 0 || (codel.count != 0 && now >= codel.deadline_ns) {
                let mut probe = icmp_probe();
                if judge_with(&mut codel, &mut probe, now - 3 * MS, now, &config) == Verdict::Drop {
                    probe_drops += 1;
                }
            }
            let mut bulk = tcp_v4(40_000, 0b01, 1_400);
            if judge_with(&mut codel, &mut bulk, now - 3 * MS, now, &config) == Verdict::Marked {
                marks += 1;
            }
            now += 10_000;
        }
        assert_eq!(probe_drops, 0);
        assert!(marks > 1_000, "the bulk flow keeps being marked: {marks}");
    }

    #[test]
    fn a_not_ect_bulk_flow_is_dropped_when_it_fills_the_queue() {
        let config = ecn_1_10();
        let mut codel = Codel::default();
        let (verdicts, _) = drive_bulk(&mut codel, &config, 1, 0, 10 * MS, 200);
        assert!(verdicts[0].contains(&Verdict::Drop));
        assert!(!verdicts[0].contains(&Verdict::Marked));
    }

    #[test]
    fn every_one_of_eight_equal_bulk_flows_is_signalled() {
        let config = ecn_1_10();
        let mut codel = Codel::default();
        let (verdicts, _) = drive_bulk(&mut codel, &config, 8, 0b10, 10 * MS, 500);
        for (flow, flow_verdicts) in verdicts.iter().enumerate() {
            let marks = flow_verdicts
                .iter()
                .filter(|v| **v == Verdict::Marked)
                .count();
            assert!(marks > 10, "flow {flow} escaped the bound: {marks} marks");
        }
    }

    #[test]
    fn pure_acks_of_a_reverse_bulk_flow_are_never_dropped() {
        let config = ecn_1_10();
        let mut codel = Codel::default();
        let mut now = 10 * MS;
        let mut ack_drops = 0;
        for step in 0..100_000_u64 {
            if step % 4 == 0 || (codel.count != 0 && now >= codel.deadline_ns) {
                // A 52-byte Not-ECT pure ACK of another TCP connection (RFC 3168 §6.1.4).
                let mut ack = tcp_v4(22, 0, 52);
                if judge_with(&mut codel, &mut ack, now - 3 * MS, now, &config) == Verdict::Drop {
                    ack_drops += 1;
                }
            }
            let mut bulk = tcp_v4(40_000, 0b10, 1_400);
            judge_with(&mut codel, &mut bulk, now - 3 * MS, now, &config);
            now += 10_000;
        }
        assert_eq!(ack_drops, 0);
    }

    #[test]
    fn owed_signals_are_forgotten_once_the_queue_drains() {
        let config = ecn_1_10();
        let mut codel = Codel::default();
        let (_, now) = drive_bulk(&mut codel, &config, 1, 0b10, 10 * MS, 100);
        let due = codel.deadline_ns.max(now);
        let mut probe = icmp_probe();
        assert_eq!(
            judge_with(&mut codel, &mut probe, due - 3 * MS, due, &config),
            Verdict::Pass
        );
        assert_eq!(codel.owed, 1);
        // The queue empties: the next bulk packet sees no sojourn and nothing is owed any more.
        let mut bulk = tcp_v4(40_000, 0b10, 1_400);
        assert_eq!(
            judge_with(&mut codel, &mut bulk, due + 10_000, due + 10_000, &config),
            Verdict::Pass
        );
        assert_eq!(codel.owed, 0);
    }

    /// Unknown and future stamps must pass even while signals are pending.
    #[test]
    fn j853_unknown_and_future_stamps_fail_safe() {
        let config = ecn_1_10();
        let mut codel = Codel::default();
        let (_, now) = drive_bulk(&mut codel, &config, 1, 2, 10 * MS, 200);
        let due = codel.deadline_ns.max(now);
        for stamp in [0, due + MS, u64::MAX] {
            let mut packet = tcp_v4(40_000, 2, 1_400);
            assert_eq!(
                judge_with(&mut codel, &mut packet, stamp, due, &config),
                Verdict::Pass
            );
        }
    }

    /// A stale stamp across a forward wall-clock step must not invent congestion.
    #[test]
    fn j853_forward_clock_step_does_not_mark() {
        let config = ecn_1_10();
        let mut codel = Codel::default();
        let (_, now) = drive_bulk(&mut codel, &config, 1, 2, 10 * MS, 200);
        let jumped = now + 3_600_000 * MS;
        let mut signals = 0;
        // One batch can contain many datagrams stamped just before the clock step.
        for _ in 0..64 {
            let mut packet = tcp_v4(40_000, 2, 1_400);
            signals += usize::from(
                judge_with(&mut codel, &mut packet, now, jumped, &config) != Verdict::Pass,
            );
        }
        eprintln!("J853 forward clock step: signals={signals} in 64 stale-stamped packets");
        assert_eq!(signals, 0, "a clock discontinuity invented congestion");
    }

    /// A timestamp from a monotonic epoch must not be treated as real queue age.
    #[test]
    fn j853_wrong_clock_domain_fails_safe() {
        let config = ecn_1_10();
        let mut codel = Codel::default();
        let epoch = 1_800_000_000_000_000_000;
        let (_, now) = drive_bulk(&mut codel, &config, 1, 2, epoch, 200);
        let due = codel.deadline_ns.max(now);
        let mut packet = tcp_v4(40_000, 2, 1_400);
        let verdict = judge_with(&mut codel, &mut packet, 10 * MS, due, &config);
        eprintln!("J853 wrong clock domain: {verdict:?}");
        assert_eq!(verdict, Verdict::Pass);
    }

    /// The age ceiling passes invalid samples, clears debt, and requires a new interval.
    #[test]
    fn j855_invalid_age_resets_before_valid_samples_resume() {
        let config = ecn_1_10();
        for case in 0..3 {
            let mut codel = Codel::default();
            let (_, now) = drive_bulk(&mut codel, &config, 1, 2, 10 * MS, 200);
            let jumped = now + MAX_SOJOURN_NS + 1;
            let stamp = match case {
                0 => jumped + 1,
                1 => 1,
                _ => jumped - MAX_SOJOURN_NS - 1,
            };
            let mut packet = tcp_v4(40_000, 2, 1400);
            assert_eq!(
                judge_with(&mut codel, &mut packet, stamp, jumped, &config),
                Verdict::Pass
            );
            assert!(codel.count == 0);
            assert_eq!(codel.owed, 0);
            assert_eq!(
                judge_with(&mut codel, &mut packet, jumped - 3 * MS, jumped, &config),
                Verdict::Pass
            );
            assert_eq!(codel.deadline_ns, jumped + config.interval_ns);
            let (verdicts, _) = drive_bulk(&mut codel, &config, 1, 2, jumped, 200);
            assert!(verdicts[0].contains(&Verdict::Marked));
        }
    }

    /// The conservative age ceiling still judges genuine queues on its accepted side.
    #[test]
    fn j855_age_ceiling_keeps_plausible_congestion_visible() {
        let config = ecn_1_10();
        let mut codel = Codel::default();
        let (_, now) = drive_bulk(&mut codel, &config, 1, 2, 10 * MS, 200);
        let due = codel.deadline_ns.max(now);
        let wall = 2 * MAX_SOJOURN_NS;
        let mut packet = tcp_v4(40_000, 2, 1400);
        assert_eq!(
            judge_with_time(
                &mut codel,
                &mut packet,
                wall - MAX_SOJOURN_NS,
                DequeueTime {
                    wall_ns: wall,
                    mono_ns: due
                },
                &config,
            ),
            Verdict::Marked
        );
    }

    /// Changing only keys cannot alter aggregate eligibility at any tested packet rate.
    /// Continuous bulk signals. At slower single-packet cadences each new arrival follows drain.
    #[test]
    fn aggregate_churn_has_no_key_dependency() {
        let config = ecn_1_10();
        for len in [80, 256, 257, 1400] {
            for spacing in [10_000, MS, 10 * MS, 100 * MS] {
                let mut stable = Codel::default();
                let mut churn = Codel::default();
                let mut signals = 0;
                for step in 0..100_000_u64 {
                    let now = 10 * MS + step * spacing;
                    let mut a = tcp_v4(40_000, 2, len);
                    let mut b = tcp_v4(10_000 + (step % 50_000) as u16, 2, len);
                    let va = judge_with(&mut stable, &mut a, now - 3 * MS, now, &config);
                    let vb = judge_with(&mut churn, &mut b, now - 3 * MS, now, &config);
                    assert_eq!(va, vb, "len={len} spacing={spacing} step={step}");
                    signals += usize::from(vb != Verdict::Pass);
                }
                let overload =
                    spacing <= MS && (len > SPARSE_MAX_PACKET_BYTES || spacing == 10_000);
                eprintln!(
                    "J870 churn len={len} spacing_ns={spacing} signals={signals} overload={overload}"
                );
                assert_eq!(signals > 0, overload);
            }
        }
    }

    /// Sustained SSH-like traffic remains exempt for 100 seconds of observed standing queue.
    #[test]
    fn steady_interactive_traffic_is_exempt_for_one_hundred_seconds() {
        let config = ecn_1_10();
        let mut codel = Codel::default();
        for step in 0..100_000_u64 {
            let now = 10 * MS + step * MS;
            let mut packet = tcp_v4(22, 0, 96);
            assert_eq!(
                judge_with(&mut codel, &mut packet, now - 3 * MS, now, &config),
                Verdict::Pass
            );
        }
        assert_eq!(codel.owed, MAX_OWED_SIGNALS);
    }

    /// Refill is continuous across interval edges, bounded, fractional and independent of signals.
    #[test]
    fn aggregate_credit_has_no_interval_edge_or_rounding_loophole() {
        let mut budget = SparseBudget::default();
        let start = 10 * MS - 1;
        for _ in 0..SPARSE_BURST_BYTES / 256 {
            assert!(budget.exempt(256, start));
        }
        assert!(!budget.exempt(1, start));
        assert!(
            !budget.exempt(1, start + 2),
            "crossing a window boundary does not reset credit"
        );
        // Keep every fractional refill: 1 byte needs ceil(I/B) = 306 ns.
        for delta in 3..306 {
            assert!(!budget.exempt(1, start + delta));
        }
        assert!(budget.exempt(1, start + 306));
        assert!(!budget.exempt(1, start - 1), "rollback cannot refill twice");
        assert!(!budget.exempt(257, u64::MAX));
        assert!(budget.exempt(256, u64::MAX));
        assert!(budget.credit <= SPARSE_BURST_BYTES * SPARSE_INTERVAL_NS);
    }

    /// Empty credit recovers fully in 20 ms; marking itself never renews a sparse allowance.
    #[test]
    fn overload_has_bounded_recovery_and_signals_do_not_mint_credit() {
        let config = ecn_1_10();
        let mut codel = Codel::default();
        let start = 10 * MS;
        codel.should_signal(test_time(start), start - 3 * MS, 3 * MS, &config);
        let due = start + config.interval_ns;
        for _ in 0..SPARSE_BURST_BYTES / 256 {
            let mut packet = tcp_v4(22, 2, 256);
            assert_eq!(
                judge_with(&mut codel, &mut packet, start - 3 * MS, due, &config),
                Verdict::Pass
            );
        }
        assert_eq!(codel.sparse.credit, 0);
        let mut packet = tcp_v4(22, 2, 256);
        assert_eq!(
            judge_with(&mut codel, &mut packet, due - 3 * MS, due, &config),
            Verdict::Marked
        );
        assert_eq!(codel.sparse.credit, 0);
        // Force due signals so success cannot depend on a quiet point in the control law.
        let recovered = due + 20 * MS;
        for step in 0..100_000_u64 {
            let now = recovered + step * MS;
            codel.deadline_ns = now;
            let mut ssh = tcp_v4(22, 0, 96);
            assert_eq!(
                judge_with(&mut codel, &mut ssh, now - 3 * MS, now, &config),
                Verdict::Pass
            );
        }
        assert!(codel.owed <= MAX_OWED_SIGNALS);
    }

    /// Observed drain clears the bucket and signal debt and requires another full interval.
    #[test]
    fn drain_resets_all_aggregate_state() {
        let config = ecn_1_10();
        let mut codel = Codel::default();
        codel.sparse.credit = 0;
        codel.owed = MAX_OWED_SIGNALS;
        let now = 10 * MS;
        let mut packet = tcp_v4(22, 2, 256);
        assert_eq!(
            judge_with(&mut codel, &mut packet, now, now, &config),
            Verdict::Pass
        );
        assert_eq!(codel.sparse.credit, SPARSE_BURST_BYTES * SPARSE_INTERVAL_NS);
        assert_eq!(codel.owed, 0);
        assert_eq!(
            judge_with(&mut codel, &mut packet, now, now + 3 * MS, &config),
            Verdict::Pass
        );
        assert_eq!(codel.deadline_ns, now + 3 * MS + config.interval_ns);
    }

    /// State is constant per peer with no per-flow entries or heap allocations.
    #[test]
    fn aggregate_state_is_small_and_constant() {
        let bytes = std::mem::size_of::<Codel>();
        eprintln!(
            "J870 Codel={bytes} budget={} bytes4096={}",
            std::mem::size_of::<SparseBudget>(),
            bytes * 4096
        );
        assert_eq!(bytes, 48);
        assert_eq!(std::mem::size_of::<SparseBudget>(), 16);
    }

    /// Replay captured real SSH and ACK sizes/times beside a standing line-rate bulk stream.
    #[test]
    fn measured_ssh_ack_and_probe_envelopes_pass_beside_bulk() {
        let config = ecn_1_10();
        for phase in ["ssh-keystrokes", "ssh-paste", "tcp-acks", "kit-probes"] {
            let mut codel = Codel::default();
            let mut now = 10 * MS;
            let mut marks = 0;
            let mut packets = 0;
            for line in include_str!("aqm_sparse_trace.txt")
                .lines()
                .filter(|line| !line.starts_with('#'))
            {
                let mut fields = line.split_whitespace();
                if fields.next() != Some(phase) {
                    continue;
                }
                let offset: u64 = fields.next().unwrap().parse().unwrap();
                let len: usize = fields.next().unwrap().parse().unwrap();
                let at = 10 * MS + offset;
                while now < at {
                    let mut bulk = tcp_v4(40_000, 2, 1400);
                    marks += usize::from(
                        judge_with(&mut codel, &mut bulk, now - 3 * MS, now, &config)
                            == Verdict::Marked,
                    );
                    now += 2_000; // 5.6 Gbit/s of 1400-byte packets; virtual clock only.
                }
                let at = now.max(at);
                // Place a pending signal on each captured packet to exercise the exemption.
                if codel.count != 0 {
                    codel.deadline_ns = at;
                }
                let mut sparse = tcp_v4(22, 0, len);
                assert_eq!(
                    judge_with(&mut codel, &mut sparse, at - 3 * MS, at, &config),
                    Verdict::Pass,
                    "phase={phase} offset={offset} len={len}"
                );
                packets += 1;
            }
            // The 10ms ACK burst needs another interval to enter signalling.
            let (bulk, _) = drive_bulk(&mut codel, &config, 1, 2, now, 20);
            assert!(marks > 0 || bulk[0].contains(&Verdict::Marked));
            assert!(packets > 0);
            eprintln!(
                "J870 captured phase={phase} replayed={packets} sparse_signals=0 bulk_marks={marks}"
            );
        }
    }

    /// The public off switch bypasses packet changes, controller state and telemetry creation.
    #[test]
    fn public_off_switch_preserves_everything() {
        if std::env::var_os("J870_OFF_CHILD").is_some() {
            let mut codel = Codel {
                owed: MAX_OWED_SIGNALS,
                sparse: SparseBudget {
                    credit: 0,
                    last_ns: 0,
                },
                ..Codel::default()
            };
            let before = format!("{codel:?}");
            for step in 0..100 {
                let now = 10 * MS + step * MS;
                let mut packet = tcp_v4(22, 2, 1400);
                let original = packet.clone();
                assert_eq!(
                    judge(&mut codel, &mut packet, 1400, now - 3 * MS, test_time(now)),
                    Verdict::Pass
                );
                assert_eq!(packet, original);
            }
            assert_eq!(format!("{codel:?}"), before);
            assert_eq!(DROPS.load(Ordering::Relaxed), 0);
            assert_eq!(MARKS.load(Ordering::Relaxed), 0);
            assert_eq!(SEEN.load(Ordering::Relaxed), 0);
            let path = std::env::var("GOTATUN_AQM_STATS_PATH").unwrap();
            assert!(!std::path::Path::new(&format!("{path}.{}", std::process::id())).exists());
            return;
        }
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "aqm::tests::public_off_switch_preserves_everything",
                "--nocapture",
            ])
            .env("J870_OFF_CHILD", "1")
            .env("GOTATUN_AQM", "off")
            .env("GOTATUN_AQM_STATS_MS", "1")
            .env(
                "GOTATUN_AQM_STATS_PATH",
                std::env::temp_dir().join(format!("j870-off-{}", std::process::id())),
            )
            .status()
            .unwrap();
        assert!(status.success());
    }

    /// One small allowance covers the measured ACK burst, SSH and probe traffic together.
    #[test]
    fn mixed_small_packets_keep_credit_beside_line_rate_bulk() {
        let config = ecn_1_10();
        let mut codel = Codel::default();
        let mut sparse_packets = 0;
        let mut bulk_marks = 0;
        for step in 0..500_000_u64 {
            let now = 10 * MS + step * 2_000;
            if step % 5_000 == 0 {
                // Repeat the busiest captured 10ms ACK burst, plus SSH and 4000 probes/s.
                for len in std::iter::repeat_n(52, 176)
                    .chain([96, 96, 216, 216])
                    .chain(std::iter::repeat_n(84, 40))
                {
                    if codel.count != 0 {
                        codel.deadline_ns = now;
                    }
                    let mut packet = tcp_v4(22, 0, len);
                    assert_eq!(
                        judge_with(&mut codel, &mut packet, now - 3 * MS, now, &config),
                        Verdict::Pass
                    );
                    sparse_packets += 1;
                }
            }
            let mut bulk = tcp_v4(40_000, 2, 1400);
            bulk_marks += usize::from(
                judge_with(&mut codel, &mut bulk, now - 3 * MS, now, &config) == Verdict::Marked,
            );
        }
        eprintln!(
            "J870 mixed sparse_packets={sparse_packets} sparse_signals=0 bulk_marks={bulk_marks}"
        );
        assert!(bulk_marks > 0);
    }

    /// Real IP decoding trims padding, but both eligibility and credit bill the whole frame.
    #[test]
    fn authenticated_padding_cannot_hide_a_large_frame() {
        let config = ecn_1_10();
        let mut codel = Codel::default();
        let start = 10 * MS;
        codel.should_signal(test_time(start), start - 3 * MS, 3 * MS, &config);
        let now = start + config.interval_ns;
        let mut bytes = icmp_probe();
        bytes[2..4].copy_from_slice(&84_u16.to_be_bytes());
        bytes.resize(1400, 0);
        let authenticated_len = bytes.len();
        let mut packet: crate::packet::Packet<crate::packet::Ip> =
            crate::packet::Packet::from_bytes(bytes::BytesMut::from(bytes.as_slice()))
                .try_into_ipvx()
                .unwrap()
                .either(|ip| ip.into(), |ip| ip.into());
        assert_eq!(
            zerocopy::IntoBytes::as_bytes(&*packet).len(),
            84,
            "IP decoding really removed the padding"
        );
        let credit = codel.sparse.credit;
        assert_eq!(
            judge_frame_with(
                &mut codel,
                zerocopy::IntoBytes::as_mut_bytes(&mut *packet),
                authenticated_len,
                start - 3 * MS,
                test_time(now),
                &config
            ),
            Verdict::Drop,
            "84 inner bytes padded to 1400 bytes are a large frame, never exempt"
        );
        assert_eq!(
            codel.sparse.credit, credit,
            "large frames do not consume small-frame credit"
        );
        assert_eq!(
            zerocopy::IntoBytes::as_bytes(&*packet).len(),
            84,
            "only validated inner bytes reach the TUN"
        );

        let mut ssh = tcp_v4(22, 0, 216);
        ssh.resize(224, 0);
        let authenticated_len = ssh.len();
        let mut packet: crate::packet::Packet<crate::packet::Ip> =
            crate::packet::Packet::from_bytes(bytes::BytesMut::from(ssh.as_slice()))
                .try_into_ipvx()
                .unwrap()
                .either(|ip| ip.into(), |ip| ip.into());
        assert_eq!(zerocopy::IntoBytes::as_bytes(&*packet).len(), 216);
        codel.deadline_ns = now;
        assert_eq!(
            judge_frame_with(
                &mut codel,
                zerocopy::IntoBytes::as_mut_bytes(&mut *packet),
                authenticated_len,
                start - 3 * MS,
                test_time(now),
                &config
            ),
            Verdict::Pass,
            "a measured SSH packet plus its eight normal padding bytes stays exempt"
        );
        assert_eq!(
            codel.sparse.credit,
            credit - 224 * SPARSE_INTERVAL_NS,
            "the full padded length is charged, rather than 216 inner bytes"
        );
        eprintln!(
            "J870 padding: inner84/plaintext1400=Drop; inner216/plaintext224=Pass, charged224"
        );
    }

    /// Independent peers keep separate credit and owed signals under a small-packet flood.
    #[test]
    fn j881_peer_isolation_under_small_packet_flood() {
        let cfg = ecn_1_10();
        let mut flood = Codel::default();
        let mut victim = Codel::default();
        let mut reference = Codel::default();
        let mut signs = 0;
        for n in 0..100_000u64 {
            let now = 10 * MS + n * 1_000;
            let mut p = tcp_v4((n % 50_000) as u16 + 1, 2, 256);
            signs += usize::from(
                judge_with(&mut flood, &mut p, now - 3 * MS, now, &cfg) != Verdict::Pass,
            );
            if n % 1000 == 0 {
                let mut a = tcp_v4(22, 0, 216);
                let mut b = a.clone();
                assert_eq!(
                    judge_with(&mut victim, &mut a, now - 3 * MS, now, &cfg),
                    judge_with(&mut reference, &mut b, now - 3 * MS, now, &cfg)
                );
                assert_eq!(a, b);
                assert_eq!(format!("{victim:?}"), format!("{reference:?}"));
            }
        }
        assert!(signs > 0);
        assert_eq!(victim.owed, MAX_OWED_SIGNALS);
        eprintln!("J881 flood signals={signs}; independent peer remains exempt");
    }

    /// Irregular mixed-size offers obey the burst-plus-refill bound even at window edges.
    #[test]
    fn j881_irregular_credit_conserves_bytes() {
        let mut budget = SparseBudget::default();
        let mut random = 0x123456789abcdefu64;
        let mut now = 10 * MS;
        let start = now;
        let mut allowed = 0u64;
        let mut refused = 0u64;
        for n in 0..200_000 {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            now += [0, 1, 305, 306, 10_000, 9_999][n % 6];
            let len = [1, 52, 80, 216, 224, 256, 257, 1400][random as usize % 8];
            let before = budget.credit;
            let exempt = budget.exempt(len, now);
            if len > 256 {
                assert!(!exempt);
                assert!(budget.credit >= before);
            } else if exempt {
                allowed += len as u64;
            } else {
                refused += 1;
            }
            assert!(budget.credit <= SPARSE_BURST_BYTES * SPARSE_INTERVAL_NS);
            assert!(
                allowed as u128 * SPARSE_INTERVAL_NS as u128
                    <= SPARSE_BURST_BYTES as u128 * SPARSE_INTERVAL_NS as u128
                        + (now - start) as u128 * SPARSE_BYTES as u128
            );
        }
        assert!(refused > 0);
        eprintln!(
            "J881 irregular accepted={allowed} refused={refused} elapsed_ns={}",
            now - start
        );
    }

    /// Mixed refill-edge bursts cannot suppress all congestion signals.
    #[test]
    fn j881_mixed_overload_cannot_hide_due_signals() {
        let cfg = ecn_1_10();
        let mut codel = Codel::default();
        let mut small = 0;
        let mut large = 0;
        for n in 0..200_000u64 {
            let now = 10 * MS + (n / 1000) * 10 * MS + (n % 1000);
            let len = if n % 3 == 0 { 1400 } else { 256 };
            let mut p = tcp_v4((n % 50000) as u16 + 1, 2, len);
            if judge_with(&mut codel, &mut p, now - 10 * MS + 1, now, &cfg) != Verdict::Pass {
                if len == 256 {
                    small += 1;
                } else {
                    large += 1;
                }
            }
        }
        assert!(small + large > 0);
        eprintln!("J881 refill-edge mixed small_signals={small} large_signals={large}");
    }

    /// Parsed diagnostic durations must not panic or wrap into a zero-nanosecond controller.
    #[test]
    fn j881_diagnostic_duration_conversion_is_overflow_safe() {
        let mut invalid = Vec::new();
        for knob in ["GOTATUN_AQM_TARGET_US", "GOTATUN_AQM_INTERVAL_US"] {
            let result = std::panic::catch_unwind(|| from_vars(&[(knob, "2305843009213693952")]));
            match result {
                Err(_) => {
                    eprintln!("J881 {knob}: panicked");
                    invalid.push(knob);
                }
                Ok(cfg) => {
                    eprintln!(
                        "J881 {knob}: target_ns={} interval_ns={}",
                        cfg.target_ns, cfg.interval_ns
                    );
                    if cfg.target_ns == 0 || cfg.interval_ns == 0 {
                        invalid.push(knob);
                    }
                }
            }
        }
        assert!(
            invalid.is_empty(),
            "overflowing diagnostic durations: {invalid:?}"
        );
    }

    /// Fresh receive stamps follow a wall-clock step while all congestion deadlines stay put.
    #[test]
    fn j881_clock_steps_with_fresh_stamps_preserve_deadlines() {
        let cfg = ecn_1_10();
        let epoch = 1_800_000_000_000_000_000;
        for ecn in [0, 2] {
            let mut stable = None;
            for shift_ms in [0_i64, -3_600_000, 3_600_000] {
                let mut codel = Codel::default();
                let (before, now) = drive_bulk(&mut codel, &cfg, 1, ecn, epoch, 200);
                assert!(before[0].iter().any(|&v| v != Verdict::Pass));
                let after = now.checked_add_signed(shift_ms * MS as i64).unwrap();
                let mut signals = 0;
                for step in 0..100_000_u64 {
                    let at = DequeueTime {
                        wall_ns: after + step * 10_000,
                        mono_ns: now + step * 10_000,
                    };
                    let age = 3 * MS + step * 1_000;
                    let mut p = tcp_v4(40_000, ecn, 1400);
                    let verdict = judge_with_time(&mut codel, &mut p, at.wall_ns - age, at, &cfg);
                    signals += usize::from(verdict != Verdict::Pass);
                }
                eprintln!(
                    "J881 fresh stamps ecn={ecn} shift_ms={shift_ms} signals={signals}/100000"
                );
                assert!(signals > 0 && signals < 100_000);
                assert_eq!(signals, *stable.get_or_insert(signals));
            }
        }
    }

    /// An idle gap followed by a fresh burst never inherits a warm controller's debt.
    #[test]
    fn j881_idle_resume_does_not_reuse_old_signal_schedule() {
        let cfg = ecn_1_10();
        for gap in [
            4 * MS,
            10 * MS - 1,
            10 * MS,
            10 * MS + 1,
            20 * MS - 1,
            20 * MS,
            20 * MS + 1,
            200 * MS - 1,
            200 * MS,
            200 * MS + 1,
            3_600_000 * MS,
        ] {
            let mut warm = Codel::default();
            let (_, previous) = drive_bulk(&mut warm, &cfg, 1, 0, 1_800_000_000_000_000_000, 200);
            assert!(warm.count != 0);
            warm.owed = MAX_OWED_SIGNALS;
            let resumed = previous + gap;
            let mut fresh = Codel::default();
            for step in 0..10_u64 {
                let now = resumed + step * 10_000;
                let stamp = now - 3 * MS;
                assert!(stamp > previous);
                let mut a = tcp_v4(40_000, 0, 1400);
                let mut b = a.clone();
                assert_eq!(
                    judge_with(&mut warm, &mut a, stamp, now, &cfg),
                    judge_with(&mut fresh, &mut b, stamp, now, &cfg),
                    "gap={gap}, step={step}",
                );
                assert_eq!(warm.owed, 0);
            }
            assert_eq!(warm.deadline_ns, resumed + cfg.interval_ns);
        }
    }

    /// A stalled run can earn one overdue signal, then waits for a future deadline.
    #[test]
    fn overdue_schedule_earns_only_one_new_signal_at_a_dequeue() {
        let cfg = ecn_1_10();
        let mut codel = Codel::default();
        let (_, previous) = drive_bulk(&mut codel, &cfg, 1, 0, 10 * MS, 200);
        let resumed = codel.last_above.mono_ns + cfg.interval_ns;
        assert!(resumed > previous && resumed > codel.deadline_ns);
        let stamp = previous - 3 * MS;
        let mut signals = 0;
        for _ in 0..64 {
            let mut p = tcp_v4(40_000, 0, 1400);
            signals +=
                usize::from(judge_with(&mut codel, &mut p, stamp, resumed, &cfg) == Verdict::Drop);
        }
        assert_eq!(signals, 1);
        assert!(codel.deadline_ns > resumed);
    }

    /// Silence expires congestion evidence when an old stamp shows that the backlog did not drain.
    #[test]
    fn stale_evidence_during_a_stall_does_not_reset_credit() {
        let cfg = ecn_1_10();
        let mut codel = Codel::default();
        let (_, previous) = drive_bulk(&mut codel, &cfg, 1, 2, 10 * MS, 200);
        let last = codel.last_above.mono_ns;
        codel.owed = MAX_OWED_SIGNALS;
        codel.sparse.credit = 0;
        codel.sparse.last_ns = last;
        let resumed = last + cfg.interval_ns + 1;
        let mut small = tcp_v4(40_000, 2, 256);
        assert_eq!(
            judge_with(&mut codel, &mut small, previous - 3 * MS, resumed, &cfg),
            Verdict::Pass
        );
        assert_eq!(codel.deadline_ns, resumed + cfg.interval_ns);
        assert_eq!(codel.owed, 0);
        assert_eq!(
            codel.sparse.credit,
            (cfg.interval_ns + 1) * SPARSE_BYTES - 256 * SPARSE_INTERVAL_NS
        );
    }

    /// A fresh realtime epoch cannot replenish or freeze a peer's credit.
    #[test]
    fn fresh_clock_steps_leave_monotonic_refill_unchanged() {
        let cfg = ecn_1_10();
        let epoch = 1_800_000_000_000_000_000;
        for shift_ms in [-3_600_000_i64, 0, 3_600_000] {
            let mut codel = Codel::default();
            let mut packet = tcp_v4(40_000, 2, 256);
            let initial = DequeueTime {
                wall_ns: epoch,
                mono_ns: 10 * MS,
            };
            judge_with_time(&mut codel, &mut packet, epoch - 6 * MS, initial, &cfg);
            codel.sparse.credit = 0;
            let at = DequeueTime {
                wall_ns: (epoch + 5 * MS)
                    .checked_add_signed(shift_ms * MS as i64)
                    .unwrap(),
                mono_ns: initial.mono_ns + 5 * MS,
            };
            assert_eq!(
                judge_with_time(&mut codel, &mut packet, at.wall_ns - 6 * MS, at, &cfg),
                Verdict::Pass
            );
            assert_eq!(
                codel.sparse.credit,
                5 * MS * SPARSE_BYTES - 256 * SPARSE_INTERVAL_NS
            );
        }
    }

    /// Invalid old stamps fail open in both wall-step directions, then a new sample rearms AQM.
    #[test]
    fn stale_stamps_from_both_wall_clock_steps_end_the_episode() {
        let cfg = ecn_1_10();
        for shift_ms in [-3_600_000_i64, 3_600_000] {
            let mut codel = Codel::default();
            let (_, previous) = drive_bulk(&mut codel, &cfg, 1, 2, 1_800_000_000_000_000_000, 200);
            let at = DequeueTime {
                wall_ns: previous.checked_add_signed(shift_ms * MS as i64).unwrap(),
                mono_ns: previous,
            };
            codel.owed = MAX_OWED_SIGNALS;
            codel.sparse.credit = 0;
            let mut p = tcp_v4(40_000, 2, 1400);
            assert_eq!(
                judge_with_time(&mut codel, &mut p, previous - 3 * MS, at, &cfg),
                Verdict::Pass
            );
            assert_eq!(codel.deadline_ns, 0);
            assert_eq!(codel.owed, 0);
            assert_eq!(codel.sparse.credit, SPARSE_BURST_BYTES * SPARSE_INTERVAL_NS);
            assert_eq!(
                judge_with_time(&mut codel, &mut p, at.wall_ns - 3 * MS, at, &cfg),
                Verdict::Pass
            );
            assert_eq!(codel.deadline_ns, at.mono_ns + cfg.interval_ns);
        }
    }

    /// A real drain still starts a new episode when fresh stamps use a new wall epoch.
    #[test]
    fn j891_drained_peer_resumes_across_clock_step() {
        let cfg = ecn_1_10();
        let epoch = 1_800_000_000_000_000_000;
        let mut results = Vec::new();
        for shift in [
            0_i64,
            3_600_000 * MS as i64,
            -3_600_000 * MS as i64,
            -7 * MS as i64,
        ] {
            let mut warm = Codel::default();
            let (_, _) = drive_bulk(&mut warm, &cfg, 1, 0, epoch, 200);
            for _ in 0..MAX_OWED_SIGNALS {
                let when = warm.deadline_ns;
                let mut small = tcp_v4(22, 0, 216);
                assert_eq!(
                    judge_with(&mut warm, &mut small, when - 3 * MS, when, &cfg),
                    Verdict::Pass
                );
            }
            assert_eq!(warm.owed, MAX_OWED_SIGNALS);
            let last = warm.last_above.mono_ns;
            let resumed = last + cfg.interval_ns - 100_000;
            assert!(
                resumed - 3 * MS > last,
                "the new packets arrive after drain"
            );
            warm.sparse.credit = 0;
            warm.sparse.last_ns = last;
            let mut fresh = Codel::default();
            let mut warm_drops = 0;
            let mut fresh_drops = 0;
            for step in 0..10 {
                let mono_ns = resumed + step * 10_000;
                let wall_ns = mono_ns.checked_add_signed(shift).unwrap();
                let at = DequeueTime { wall_ns, mono_ns };
                let stamp = wall_ns - 3 * MS;
                let mut packet = tcp_v4(40_000, 0, 1400);
                warm_drops += usize::from(
                    judge_with_time(&mut warm, &mut packet, stamp, at, &cfg) == Verdict::Drop,
                );
                fresh_drops += usize::from(
                    judge_with_time(&mut fresh, &mut packet, stamp, at, &cfg) == Verdict::Drop,
                );
            }
            eprintln!(
                "J891 shift_ns={shift} gap_ns=9900000 warm_drops={warm_drops} fresh_drops={fresh_drops}"
            );
            results.push((warm_drops, fresh_drops));
            // Bulk packets never touch the bucket. Only the two agreeing drain
            // comparisons can renew it immediately.
            let expected_credit = if shift >= 0 {
                SPARSE_BURST_BYTES * SPARSE_INTERVAL_NS
            } else {
                0
            };
            assert_eq!(warm.sparse.credit, expected_credit, "shift_ns={shift}");
        }
        assert_eq!(results, vec![(0, 0); 4]);
    }

    /// A forward clock step between receive and dequeue must not carry a drained episode's debt.
    #[test]
    fn j908_forward_step_after_receive_clears_drained_episode() {
        let cfg = ecn_1_10();
        let epoch = 1_800_000_000_000_000_000;
        let mut verdicts = Vec::new();
        for shift in [0, 7 * MS] {
            let mut warm = Codel::default();
            drive_bulk(&mut warm, &cfg, 1, 0, epoch, 200);
            for _ in 0..MAX_OWED_SIGNALS {
                let now = warm.deadline_ns;
                let mut small = tcp_v4(22, 0, 216);
                assert_eq!(
                    judge_with(&mut warm, &mut small, now - 3 * MS, now, &cfg),
                    Verdict::Pass
                );
            }
            assert_eq!(warm.owed, MAX_OWED_SIGNALS);
            warm.sparse.credit = 0;
            let last = warm.last_above;
            warm.sparse.last_ns = last.mono_ns;
            let resumed = last.mono_ns + 9 * MS + 900_000;
            // The new datagram arrived 6.9 ms after the prior dequeue. Its stamp
            // precedes the step, so the measured age grows from 3 ms to 10 ms.
            let stamp = resumed - 3 * MS;
            assert!(stamp > last.wall_ns);
            let at = DequeueTime {
                wall_ns: resumed + shift,
                mono_ns: resumed,
            };
            let mut packet = tcp_v4(40_000, 0, 1400);
            let mut fresh = Codel::default();
            let warm_result = judge_with_time(&mut warm, &mut packet, stamp, at, &cfg);
            let fresh_result = judge_with_time(&mut fresh, &mut packet, stamp, at, &cfg);
            eprintln!(
                "shift_ns={shift} age_ns={} warm={warm_result:?} fresh={fresh_result:?} owed={} credit={} deadline={} expected_deadline={}",
                at.wall_ns - stamp,
                warm.owed,
                warm.sparse.credit,
                warm.deadline_ns,
                resumed + cfg.interval_ns
            );
            verdicts.push((
                warm_result,
                fresh_result,
                warm.owed,
                warm.sparse.credit,
                warm.deadline_ns,
            ));
            assert_eq!(fresh.deadline_ns, resumed + cfg.interval_ns);
        }
        assert_eq!(
            verdicts[0],
            (
                Verdict::Pass,
                Verdict::Pass,
                0,
                SPARSE_BURST_BYTES * SPARSE_INTERVAL_NS,
                verdicts[0].4
            )
        );
        assert_eq!(
            verdicts[1],
            (Verdict::Pass, Verdict::Pass, 0, 0, verdicts[0].4)
        );
    }

    /// Bulk frames leave sparse credit available independently at the 4,096-peer design scale.
    #[test]
    fn j908_mixed_credit_is_independent_at_mesh_scale() {
        let cfg = ecn_1_10();
        let mut peers: Vec<_> = (0..4096).map(|_| Codel::default()).collect();
        let initial = 20 * MS;
        for peer in &mut peers {
            let mut bulk = tcp_v4(40_000, 2, 1400);
            judge_with(peer, &mut bulk, initial - 3 * MS, initial, &cfg);
        }
        for peer in &mut peers[..2048] {
            let mut small = tcp_v4(22, 0, 256);
            for _ in 0..256 {
                judge_with(peer, &mut small, initial - 3 * MS, initial, &cfg);
            }
            assert_eq!(peer.sparse.credit, 0);
        }
        // Present one above-target sample before the interval elapses on each peer.
        let midpoint = initial + 5 * MS;
        for peer in &mut peers {
            let mut bulk = tcp_v4(40_000, 2, 1400);
            judge_with(peer, &mut bulk, midpoint - 8 * MS, midpoint, &cfg);
        }
        let due = initial + 10 * MS;
        for (index, peer) in peers.iter_mut().enumerate() {
            let mut small = tcp_v4(22, 0, 216);
            let mut bulk = tcp_v4(40_000, 2, 1400);
            assert_eq!(
                judge_with(peer, &mut small, due - 13 * MS, due, &cfg),
                Verdict::Pass
            );
            assert_eq!(
                judge_with(peer, &mut bulk, due - 13 * MS, due, &cfg),
                Verdict::Marked
            );
            let credit = if index < 2048 {
                SPARSE_BYTES
            } else {
                SPARSE_BURST_BYTES
            };
            assert_eq!(peer.sparse.credit, (credit - 224) * SPARSE_INTERVAL_NS);
        }
        eprintln!(
            "peers={} controller_bytes={} total_bytes={}",
            peers.len(),
            size_of::<Codel>(),
            peers.len() * size_of::<Codel>()
        );
    }

    /// An overdue deadline equal to the candidate next deadline only earns one signal.
    #[test]
    fn j891_catch_up_at_next_deadline_equality() {
        let cfg = ecn_1_10();
        let mut codel = Codel::default();
        drive_bulk(&mut codel, &cfg, 1, 0, 10 * MS, 200);
        assert!(codel.count > 0);
        let spacing = (cfg.interval_ns as f64 / f64::from(codel.count + 1).sqrt()) as u64;
        let now = codel.deadline_ns + spacing;
        let stamp = codel.last_above.wall_ns - 3 * MS;
        let mut packet = tcp_v4(40_000, 0, 1400);
        assert_eq!(
            judge_with(&mut codel, &mut packet, stamp, now, &cfg),
            Verdict::Drop
        );
        assert_eq!(
            judge_with(&mut codel, &mut packet, stamp, now, &cfg),
            Verdict::Pass
        );
        assert!(codel.deadline_ns > now);
    }

    /// The environment cannot select zero timing or wrap a near-u64 deadline.
    #[test]
    fn j891_timing_bounds_and_saturation() {
        let normal = ecn_1_10();
        let zero = from_vars(&[
            ("GOTATUN_AQM_INTERVAL_US", "0"),
            ("GOTATUN_AQM_TARGET_US", "0"),
        ]);
        assert_eq!(zero, normal);
        let maximum = (u64::MAX / 1_000).to_string();
        let huge = from_vars(&[("GOTATUN_AQM_INTERVAL_US", &maximum)]);
        assert_eq!(huge.interval_ns, u64::MAX / 1_000 * 1_000);
        let wall_ns = 1_800_000_000_000_000_000;
        let mut codel = Codel::default();
        let mut packet = tcp_v4(40_000, 2, 1400);
        for mono_ns in [u64::MAX - 2, u64::MAX - 1] {
            let at = DequeueTime { wall_ns, mono_ns };
            assert_eq!(
                judge_with_time(&mut codel, &mut packet, wall_ns - 3 * MS, at, &huge),
                Verdict::Pass
            );
            assert_eq!(codel.deadline_ns, u64::MAX);
        }
        eprintln!(
            "J891 state_bytes={} sparse_bytes={}",
            size_of::<Codel>(),
            size_of::<SparseBudget>()
        );
    }
}
