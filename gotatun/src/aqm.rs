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
}

impl Codel {
    /// The time of the next signal after `from`, `interval / sqrt(count)` later (RFC 8289's
    /// control law). Called rarely (once per signal), so the float square root costs nothing.
    fn control_law(from_ns: u64, interval_ns: u64, count: u32) -> u64 {
        let spacing = interval_ns as f64 / f64::from(count.max(1)).sqrt();
        from_ns.saturating_add(spacing as u64)
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
/// change. `rx_ns` is the kernel receive timestamp of its datagram (0 if none); `now_ns` comes
/// from [`realtime_ns`] once per delivered run.
pub(crate) fn judge(codel: &mut Codel, packet: &mut [u8], rx_ns: u64, now_ns: u64) -> Verdict {
    let config = config();
    if !config.active() {
        return Verdict::Pass;
    }
    judge_with(codel, packet, rx_ns, now_ns, config)
}

/// [`judge`] with an explicit configuration, assumed active; tests drive the controller here.
fn judge_with(
    codel: &mut Codel,
    packet: &mut [u8],
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
    // A wall-clock step backwards reads as zero sojourn; that only delays a signal.
    let sojourn_ns = now_ns.saturating_sub(rx_ns);
    if stats {
        let sojourn_us = sojourn_ns / 1_000;
        SOJOURN_SUM_US.fetch_add(sojourn_us, Ordering::Relaxed);
        SOJOURN_COUNT.fetch_add(1, Ordering::Relaxed);
        SOJOURN_MAX_US.fetch_max(sojourn_us, Ordering::Relaxed);
    }

    if !codel.should_signal(now_ns, sojourn_ns, config) {
        return Verdict::Pass;
    }
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
}
