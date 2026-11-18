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
//! the moment the in-order packet is about to be written to the TUN. That interval covers the
//! socket backlog and the engine's own pipeline. A CoDel controller (RFC 8289) then signals
//! congestion at that dequeue point when the sojourn stays above `target` for at least
//! `interval`: by default (RFC 3168) by setting CE on an ECN-capable inner packet, and by
//! dropping only packets that are not ECN-capable.
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
    /// Unset, empty or unparsable numbers fall back to the defaults; an unknown mode keeps the
    /// default ECN mode, so a typo never turns the bound off silently (it logs a warning).
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
        Self {
            mode,
            target_ns: positive("GOTATUN_AQM_TARGET_US").unwrap_or(DEFAULT_TARGET_US) * 1_000,
            interval_ns: positive("GOTATUN_AQM_INTERVAL_US").unwrap_or(DEFAULT_INTERVAL_US) * 1_000,
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

/// CoDel state for one queue (here: one peer's receive path).
///
/// This follows the state machine RFC 8289 §5 describes, in our own structure: a packet is "above
/// target" once its sojourn exceeds `target`; once packets have stayed above target for a whole
/// `interval`, the controller enters the signalling state and signals one packet, then the next
/// one after `interval / sqrt(count)`, and so on, until a packet's sojourn falls below target.
/// Re-entering soon after leaving resumes near the previous signalling rate, so a persistent
/// queue doesn't restart from one signal per interval.
#[derive(Debug, Default)]
pub(crate) struct Codel {
    /// When the sojourn first went above target in this episode, plus one interval; 0 when the
    /// sojourn is below target.
    first_above_ns: u64,
    /// When the next signal is due while signalling.
    signal_next_ns: u64,
    /// Signals in the current signalling episode.
    count: u32,
    /// `count` when the previous episode ended, for the quick re-entry rule.
    last_count: u32,
    /// Whether the controller is in its signalling state.
    signalling: bool,
    /// Due signals deferred by the small-packet budget, capped to avoid an unbounded burst.
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
    /// The time of the next signal after `from`, `interval / sqrt(count)` later (RFC 8289's
    /// control law). Called rarely (once per signal), so the float square root costs nothing.
    fn control_law(from_ns: u64, interval_ns: u64, count: u32) -> u64 {
        let spacing = interval_ns as f64 / f64::from(count.max(1)).sqrt();
        from_ns.saturating_add(spacing as u64)
    }

    /// Whether the last judged packet found the queue standing above target (the window in
    /// which the sparse-flow exemption counts bytes).
    fn above_target(&self) -> bool {
        self.first_above_ns != 0
    }

    /// Whether the packet dequeued at `now_ns` with `sojourn_ns` of queueing should be signalled.
    pub(crate) fn should_signal(
        &mut self,
        now_ns: u64,
        sojourn_ns: u64,
        config: &AqmConfig,
    ) -> bool {
        // Step 1: has the queue stood above target for at least one interval?
        let persistent = if sojourn_ns < config.target_ns {
            self.first_above_ns = 0;
            false
        } else if self.first_above_ns == 0 {
            self.first_above_ns = now_ns.saturating_add(config.interval_ns);
            false
        } else {
            now_ns >= self.first_above_ns
        };

        // Step 2: run the signalling state machine.
        if self.signalling {
            if !persistent {
                self.signalling = false;
                return false;
            }
            if now_ns >= self.signal_next_ns {
                self.count = self.count.saturating_add(1);
                self.signal_next_ns =
                    Self::control_law(self.signal_next_ns, config.interval_ns, self.count);
                return true;
            }
            return false;
        }
        if persistent {
            self.signalling = true;
            // Re-entering within 16 intervals of the last signal keeps most of the old rate.
            let delta = self.count.saturating_sub(self.last_count);
            let recent =
                now_ns.saturating_sub(self.signal_next_ns) < config.interval_ns.saturating_mul(16);
            self.count = if delta > 1 && recent { delta } else { 1 };
            self.last_count = self.count;
            self.signal_next_ns = Self::control_law(now_ns, config.interval_ns, self.count);
            return true;
        }
        false
    }
}

/// Judge one in-order packet about to be written to the TUN, and apply the verdict's header
/// change. `authenticated_len` includes padding before IP validation trims the plaintext.
/// The size ceiling and credit use that length; only `packet` is ever changed.
/// `rx_ns` is the kernel receive timestamp of its datagram (0 if none); `now_ns` comes
/// from [`realtime_ns`] once per delivered run.
pub(crate) fn judge(
    codel: &mut Codel,
    packet: &mut [u8],
    authenticated_len: usize,
    rx_ns: u64,
    now_ns: u64,
) -> Verdict {
    let config = config();
    if !config.active() {
        return Verdict::Pass;
    }
    judge_frame_with(codel, packet, authenticated_len, rx_ns, now_ns, config)
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
    let authenticated_len = packet.len().next_multiple_of(16);
    judge_frame_with(codel, packet, authenticated_len, rx_ns, now_ns, config)
}

/// Judge validated IP bytes with the pre-trim authenticated plaintext length, assumed active.
/// Clamp an undersized caller value to the inner length so it cannot undercharge the packet.
fn judge_frame_with(
    codel: &mut Codel,
    packet: &mut [u8],
    authenticated_len: usize,
    rx_ns: u64,
    now_ns: u64,
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
    let Some(sojourn_ns) = now_ns
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

    let due = codel.should_signal(now_ns, sojourn_ns, config);
    if !codel.above_target() {
        // Observed drain ends both the signal debt and the sparse-credit episode.
        codel.owed = 0;
        codel.sparse = SparseBudget::default();
        return Verdict::Pass;
    }
    let charged_len = authenticated_len.max(packet.len());
    let exempt = codel.sparse.exempt(charged_len, now_ns);
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
            assert!(!codel.should_signal(step * MS, 4 * MS, &config));
        }
    }

    #[test]
    fn first_signal_waits_one_interval_above_target() {
        let mut codel = Codel::default();
        let config = config(AqmMode::Drop);
        assert!(!codel.should_signal(0, 6 * MS, &config));
        assert!(!codel.should_signal(99 * MS, 6 * MS, &config));
        assert!(codel.should_signal(100 * MS, 6 * MS, &config));
    }

    #[test]
    fn signal_spacing_shrinks_with_the_square_root_of_count() {
        let mut codel = Codel::default();
        let config = config(AqmMode::Drop);
        codel.should_signal(0, 6 * MS, &config);
        let mut signals = Vec::new();
        for step in 1..=400 {
            let now = step * MS;
            if codel.should_signal(now, 6 * MS, &config) {
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

    #[test]
    fn falling_below_target_leaves_the_signalling_state() {
        let mut codel = Codel::default();
        let config = config(AqmMode::Drop);
        codel.should_signal(0, 6 * MS, &config);
        assert!(codel.should_signal(100 * MS, 6 * MS, &config));
        assert!(!codel.should_signal(101 * MS, MS, &config));
        // A new episode needs another full interval above target.
        assert!(!codel.should_signal(102 * MS, 6 * MS, &config));
        assert!(!codel.should_signal(201 * MS, 6 * MS, &config));
        assert!(codel.should_signal(202 * MS, 6 * MS, &config));
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
        assert!(codel.signalling);
        // The next signal is due exactly when a Not-ECT probe reaches the TUN.
        let due = codel.signal_next_ns.max(now);
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
            if step % 25 == 0 {
                let at = if codel.signalling {
                    codel.signal_next_ns.max(now)
                } else {
                    now
                };
                let mut probe = icmp_probe();
                if judge_with(&mut codel, &mut probe, at - 3 * MS, at, &config) == Verdict::Drop {
                    probe_drops += 1;
                }
                now = at;
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
            if step % 4 == 0 {
                let at = if codel.signalling {
                    codel.signal_next_ns.max(now)
                } else {
                    now
                };
                // A 52-byte Not-ECT pure ACK of another TCP connection (RFC 3168 §6.1.4).
                let mut ack = tcp_v4(22, 0, 52);
                if judge_with(&mut codel, &mut ack, at - 3 * MS, at, &config) == Verdict::Drop {
                    ack_drops += 1;
                }
                now = at;
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
        let due = codel.signal_next_ns.max(now);
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
        let due = codel.signal_next_ns.max(now);
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
        let due = codel.signal_next_ns.max(now);
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
            assert!(!codel.signalling);
            assert_eq!(codel.owed, 0);
            assert_eq!(
                judge_with(&mut codel, &mut packet, jumped - 3 * MS, jumped, &config),
                Verdict::Pass
            );
            assert_eq!(codel.first_above_ns, jumped + config.interval_ns);
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
        let due = codel.signal_next_ns.max(now) + MAX_SOJOURN_NS;
        let mut packet = tcp_v4(40_000, 2, 1400);
        assert_eq!(
            judge_with(&mut codel, &mut packet, due - MAX_SOJOURN_NS, due, &config),
            Verdict::Marked
        );
    }

    /// Changing only keys cannot alter aggregate eligibility at any tested packet rate.
    /// Small churn within the envelope passes; above it signals. Large churn always signals.
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
                let overload = len > SPARSE_MAX_PACKET_BYTES || spacing == 10_000;
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
        codel.should_signal(start, 3 * MS, &config);
        let due = start + config.interval_ns;
        for _ in 0..SPARSE_BURST_BYTES / 256 {
            let mut packet = tcp_v4(22, 2, 256);
            assert_eq!(
                judge_with(&mut codel, &mut packet, due - 3 * MS, due, &config),
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
            codel.signal_next_ns = now;
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
        assert_eq!(codel.first_above_ns, now + 3 * MS + config.interval_ns);
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
                if codel.signalling {
                    codel.signal_next_ns = at;
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
            let mut codel = Codel::default();
            codel.owed = MAX_OWED_SIGNALS;
            codel.sparse.credit = 0;
            let before = format!("{codel:?}");
            for step in 0..100 {
                let now = 10 * MS + step * MS;
                let mut packet = tcp_v4(22, 2, 1400);
                let original = packet.clone();
                assert_eq!(
                    judge(&mut codel, &mut packet, 1400, now - 3 * MS, now),
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
                    if codel.signalling {
                        codel.signal_next_ns = now;
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
        codel.should_signal(start, 3 * MS, &config);
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
                now - 3 * MS,
                now,
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
        codel.signal_next_ns = now;
        assert_eq!(
            judge_frame_with(
                &mut codel,
                zerocopy::IntoBytes::as_mut_bytes(&mut *packet),
                authenticated_len,
                now - 3 * MS,
                now,
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
}
