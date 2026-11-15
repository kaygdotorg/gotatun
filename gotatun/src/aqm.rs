// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Receive-side active queue management, a measurement prototype (infraternal #260, J711).
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
//! `interval`: either by dropping the packet, or (RFC 3168) by setting CE on an ECN-capable
//! inner packet and dropping only packets that are not ECN-capable.
//!
//! # How to use it
//! Off unless `GOTATUN_J711_AQM` is set, so a default build behaves exactly like the pin:
//! - `GOTATUN_J711_AQM=codel` drops; `=ecn` marks ECT packets CE and drops the rest.
//! - `GOTATUN_J711_TARGET_US` (default 5000) and `GOTATUN_J711_INTERVAL_US` (default 100000)
//!   are the CoDel target and interval, in microseconds.
//! - `GOTATUN_J711_STATS_MS` (default 1000) prints one `j711-aqm …` line per period with the
//!   cumulative drops, CE marks and the sojourn mean/max of that period, so a bench can report
//!   them next to its own counters. The lines go to stderr, or are appended to
//!   `$GOTATUN_J711_STATS_PATH.<pid>` when that is set (a harness may own the engine's stderr).
//!
//! Prototype only: the knobs are environment variables so one binary can sweep values on the
//! perf VM. It is not proposed for the product pin.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// How the controller signals congestion once CoDel decides to act on a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AqmMode {
    /// No AQM: every packet passes, as on the pin.
    Off,
    /// Drop the packet CoDel picks.
    Drop,
    /// Mark CE on the packet CoDel picks when its inner IP header is ECN-capable; drop otherwise.
    Ecn,
}

/// The process-wide AQM settings, read once from the environment.
#[derive(Clone, Copy, Debug)]
pub(crate) struct AqmConfig {
    /// What to do with a packet CoDel picks.
    pub(crate) mode: AqmMode,
    /// Sojourn time the queue may keep standing without being signalled, in nanoseconds.
    pub(crate) target_ns: u64,
    /// How long the sojourn must stay above target before the first signal, in nanoseconds.
    /// It is also the base of CoDel's control law (`interval / sqrt(count)`).
    pub(crate) interval_ns: u64,
}

impl AqmConfig {
    /// Read the configuration from `GOTATUN_J711_*` (see the module docs).
    fn from_env() -> Self {
        let mode = match std::env::var("GOTATUN_J711_AQM").as_deref() {
            Ok("codel" | "drop") => AqmMode::Drop,
            Ok("ecn") => AqmMode::Ecn,
            _ => AqmMode::Off,
        };
        let micros = |name: &str, default: u64| {
            std::env::var(name)
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|&value| value > 0)
                .unwrap_or(default)
                * 1_000
        };
        Self {
            mode,
            target_ns: micros("GOTATUN_J711_TARGET_US", 5_000),
            interval_ns: micros("GOTATUN_J711_INTERVAL_US", 100_000),
        }
    }
}

/// The settings for this process. The first call reads the environment and, when AQM is on,
/// starts the stats printer.
pub(crate) fn config() -> &'static AqmConfig {
    static CONFIG: OnceLock<AqmConfig> = OnceLock::new();
    CONFIG.get_or_init(|| {
        let config = AqmConfig::from_env();
        if config.mode != AqmMode::Off {
            start_stats_printer(config);
        }
        config
    })
}

/// Whether receive timestamps are needed at all. Cheap after the first call.
pub(crate) fn enabled() -> bool {
    config().mode != AqmMode::Off
}

/// Packets dropped by the controller, since start.
static DROPS: AtomicU64 = AtomicU64::new(0);
/// Packets marked CE by the controller, since start.
static MARKS: AtomicU64 = AtomicU64::new(0);
/// Packets the controller looked at, since start.
static SEEN: AtomicU64 = AtomicU64::new(0);
/// Packets that arrived without a kernel timestamp and so could not be judged.
static UNSTAMPED: AtomicU64 = AtomicU64::new(0);
/// Sum of sojourn times in the current stats period, in microseconds.
static SOJOURN_SUM_US: AtomicU64 = AtomicU64::new(0);
/// Number of sojourn samples in the current stats period.
static SOJOURN_COUNT: AtomicU64 = AtomicU64::new(0);
/// Largest sojourn in the current stats period, in microseconds.
static SOJOURN_MAX_US: AtomicU64 = AtomicU64::new(0);

/// Print one cumulative counter line per period on a plain thread, so the data path never pays
/// for formatting. The thread lives as long as the process; that is fine for a bench binary.
fn start_stats_printer(config: AqmConfig) {
    use std::io::Write as _;
    let mut file = std::env::var("GOTATUN_J711_STATS_PATH").ok().and_then(|path| {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(format!("{path}.{}", std::process::id()))
            .ok()
    });
    let period_ms = std::env::var("GOTATUN_J711_STATS_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|&value| value > 0)
        .unwrap_or(1_000);
    let spawned = std::thread::Builder::new()
        .name("j711-aqm-stats".into())
        .spawn(move || {
            loop {
                std::thread::sleep(Duration::from_millis(period_ms));
                let count = SOJOURN_COUNT.swap(0, Ordering::Relaxed);
                let sum = SOJOURN_SUM_US.swap(0, Ordering::Relaxed);
                let max = SOJOURN_MAX_US.swap(0, Ordering::Relaxed);
                let line = format!(
                    "j711-aqm t={:.3} mode={:?} target_us={} interval_us={} seen={} drops={} marks={} unstamped={} sojourn_mean_us={} sojourn_max_us={max}",
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
        tracing::warn!("j711 AQM stats printer did not start: {err}");
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
    pub(crate) fn should_signal(&mut self, now_ns: u64, sojourn_ns: u64, config: &AqmConfig) -> bool {
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
            let recent = now_ns.saturating_sub(self.signal_next_ns)
                < config.interval_ns.saturating_mul(16);
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
    if config.mode == AqmMode::Off {
        return Verdict::Pass;
    }
    SEEN.fetch_add(1, Ordering::Relaxed);
    if rx_ns == 0 {
        UNSTAMPED.fetch_add(1, Ordering::Relaxed);
        return Verdict::Pass;
    }
    // A wall-clock step backwards reads as zero sojourn; that only delays a signal.
    let sojourn_ns = now_ns.saturating_sub(rx_ns);
    let sojourn_us = sojourn_ns / 1_000;
    SOJOURN_SUM_US.fetch_add(sojourn_us, Ordering::Relaxed);
    SOJOURN_COUNT.fetch_add(1, Ordering::Relaxed);
    SOJOURN_MAX_US.fetch_max(sojourn_us, Ordering::Relaxed);

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
        }
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
            0x45, tos, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 10, 0, 0, 1,
            10, 0, 0, 2,
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
