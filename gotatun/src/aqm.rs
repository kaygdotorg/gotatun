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
    /// Signals CoDel made due that landed on a sparse flow's packet and are still owed to the
    /// next packet of a queue-heavy flow (at most [`MAX_OWED_SIGNALS`]).
    owed: u8,
    /// Recent bytes per flow while the queue stands above target, to tell queue-heavy flows from
    /// sparse ones (see [`FlowShares`]).
    flows: FlowShares,
}

/// How many skipped signals may wait for a queue-heavy packet. A few cover the rare case of
/// sparse packets landing on several due signals in a row; more would turn into a burst of
/// signals on one bulk packet run, which CoDel's spacing exists to avoid.
const MAX_OWED_SIGNALS: u8 = 4;

/// How many flows [`FlowShares`] tracks per peer. Eight bulk flows and their probes fit with
/// room to spare. New keys replace the smallest entry; the peer-wide exemption budget below
/// bounds how much traffic can escape signalling through repeated replacements.
const TRACKED_FLOWS: usize = 16;

/// A flow needs at least this many recent bytes (decayed, see [`FlowShares`]) to count as
/// queue-heavy. It sits far above what latency probes, keystrokes and DNS put on a link in one
/// interval (a 145 probes/s ping is ~2 KiB/s), and far below one bulk flow (5 Gbit/s is
/// ~6 MiB per 10 ms interval).
const HEAVY_FLOOR_BYTES: u32 = 16 * 1024;

/// New keys replacing occupied slots may exempt this many bytes before a peer-wide fallback.
/// The allowance lasts until a signal is delivered or the queue drains; it never decays with
/// time, so slower sustained churn cannot stay exempt forever. Stable sparse flows do not
/// spend it. Each tracked slot contributes one heavy-flow floor of replacement allowance.
const EXEMPT_BUDGET_BYTES: u32 = TRACKED_FLOWS as u32 * HEAVY_FLOOR_BYTES;

/// Receive ages over one second are not trustworthy enough to signal. Linux SO_TIMESTAMPNS
/// supplies realtime stamps, without a monotonic selection for this socket option. Rejecting
/// implausible ages avoids inventing congestion after large forward clock steps or a foreign
/// epoch. Real queues over this ceiling also pass; sub-second steps cannot be distinguished
/// from genuine queue age with these stamps. No clock-source dependency is added.
const MAX_SOJOURN_NS: u64 = 1_000_000_000;

/// Per-peer byte counts of the flows that crossed the queue recently, the sparse-flow
/// exemption's memory (orchestrator decision on #260, J747).
///
/// Why: a sender that never backs off (BBRv1 ignores CE and loss) keeps CoDel signalling for
/// the whole load, and a signal lands on whichever packet reaches the TUN when it is due. With
/// one queue per peer that is sometimes a Not-ECT latency probe, a keystroke or a DNS reply,
/// which ECN mode then has to drop although that flow put almost nothing in the queue (J711:
/// 10–19 of 8,000 probes). This table lets a due signal skip such packets and go to the next
/// packet of a flow that actually fills the queue, without per-flow queues.
///
/// How: flows are keyed by a 64-bit hash of the inner 5-tuple (addresses, protocol, ports when
/// the packet carries them), so two flows practically never share an entry. Bytes are only
/// counted while the sojourn stands above target, so an idle or uncongested peer pays nothing,
/// and they are halved once per CoDel interval, so the counts follow the last few intervals.
/// A flow is heavy when its count is at least [`HEAVY_FLOOR_BYTES`] and at least half the
/// average of the tracked flows. Eight equal bulk flows are all heavy; a probe next to them
/// never is. Replacing an occupied slot also spends a peer-wide byte allowance. Once exhausted,
/// a due signal may land on any packet. Delivering a signal or draining the queue renews the
/// allowance; time alone does not, so sustained churn cannot evade signalling at lower rates.
#[derive(Debug, Default)]
pub(crate) struct FlowShares {
    /// Flow hash of each entry; 0 marks a free entry (a real hash of 0 is folded to 1).
    keys: [u64; TRACKED_FLOWS],
    /// Decayed recent bytes of each entry.
    bytes: [u32; TRACKED_FLOWS],
    /// When the counts are next halved, in the same clock as the packet times.
    next_decay_ns: u64,
    /// The entry the previous packet used. Packets of one flow arrive in runs (one GRO batch,
    /// one TSO segment), so this usually skips the scan.
    last: u32,
    /// Bytes of new keys that replaced occupied slots since the last signal or queue drain.
    /// Packing this beside the cached index keeps the table at 208 bytes on 64-bit platforms.
    exempt_bytes: u32,
}

impl FlowShares {
    /// Halve the counts once per elapsed interval since the last decay.
    fn decay(&mut self, now_ns: u64, interval_ns: u64) {
        if now_ns < self.next_decay_ns {
            return;
        }
        let elapsed = (now_ns - self.next_decay_ns) / interval_ns.max(1) + 1;
        let shift = u32::try_from(elapsed.min(32)).unwrap_or(32);
        for (key, bytes) in self.keys.iter_mut().zip(self.bytes.iter_mut()) {
            *bytes = bytes.checked_shr(shift).unwrap_or(0);
            if *bytes == 0 {
                *key = 0;
            }
        }
        self.next_decay_ns = now_ns.saturating_add(interval_ns);
    }

    /// Count `len` bytes for flow `key` and return its entry. A new flow takes a free entry or
    /// replaces the one with the fewest bytes, starting from its own bytes only (never the
    /// evicted count), so a sparse newcomer can't inherit a heavy flow's share.
    fn account(&mut self, key: u64, len: usize, now_ns: u64, interval_ns: u64) -> usize {
        self.decay(now_ns, interval_ns);
        let len = u32::try_from(len).unwrap_or(u32::MAX);
        let hit = (self.keys[self.last as usize] == key)
            .then_some(self.last as usize)
            .or_else(|| self.keys.iter().position(|&entry| entry == key));
        let index = match hit {
            Some(index) => index,
            None => {
                let index = self
                    .bytes
                    .iter()
                    .enumerate()
                    .min_by_key(|&(_, &bytes)| bytes)
                    .map_or(0, |(index, _)| index);
                if self.keys[index] != 0 {
                    self.exempt_bytes = self.exempt_bytes.saturating_add(len);
                }
                self.keys[index] = key;
                self.bytes[index] = 0;
                index
            }
        };
        self.bytes[index] = self.bytes[index].saturating_add(len);
        self.last = index as u32;
        index
    }

    /// Whether the flow in entry `index` is queue-heavy (see the type docs). Only called when a
    /// signal is due, so the scan over the table costs nothing on ordinary packets.
    fn is_heavy(&self, index: usize) -> bool {
        let bytes = u64::from(self.bytes[index]);
        if bytes < u64::from(HEAVY_FLOOR_BYTES) {
            return false;
        }
        let (total, active) = self
            .bytes
            .iter()
            .filter(|&&count| count > 0)
            .fold((0_u64, 0_u64), |(total, active), &count| {
                (total + u64::from(count), active + 1)
            });
        // bytes ≥ (total / active) / 2, without division.
        bytes * 2 * active >= total
    }
}

/// A 64-bit hash of the packet's inner flow: addresses, protocol and, for TCP, UDP, UDP-Lite,
/// SCTP and DCCP packets that are not later IPv4 fragments, the two ports. Never 0 (0 marks a
/// free [`FlowShares`] entry). Anything that is not an IP packet hashes as one "other" flow.
///
/// IPv6 extension headers are not walked: a packet behind one hashes by addresses and its
/// first next-header value, which still separates it from a bulk TCP flow between the same
/// hosts. The hash only needs to tell flows apart within one peer, not resist an attacker: a
/// peer that forges flows can only make its own packets exempt or signalled.
pub(crate) fn flow_key(packet: &[u8]) -> u64 {
    /// Port-carrying protocols, whose first four transport bytes are source and destination port.
    fn has_ports(protocol: u8) -> bool {
        matches!(protocol, 6 | 17 | 33 | 132 | 136)
    }
    let mut hash = Fold::default();
    match packet.first().map(|first| first >> 4) {
        Some(4) if packet.len() >= 20 => {
            let header_len = usize::from(packet[0] & 0x0f) * 4;
            let protocol = packet[9];
            hash.add(&packet[12..20]);
            hash.add(&[4, protocol]);
            let later_fragment = u16::from_be_bytes([packet[6], packet[7]]) & 0x1fff != 0;
            if has_ports(protocol)
                && !later_fragment
                && let Some(ports) = packet.get(header_len..header_len + 4)
            {
                hash.add(ports);
            }
        }
        Some(6) if packet.len() >= 40 => {
            let next_header = packet[6];
            hash.add(&packet[8..40]);
            hash.add(&[6, next_header]);
            if has_ports(next_header)
                && let Some(ports) = packet.get(40..44)
            {
                hash.add(ports);
            }
        }
        _ => hash.add(&[0]),
    }
    hash.finish().max(1)
}

/// A small multiply-rotate hash over byte slices, enough to tell a peer's flows apart. Not a
/// keyed hash on purpose: see [`flow_key`].
#[derive(Default)]
struct Fold(u64);

impl Fold {
    /// Mix `bytes` into the hash, eight at a time.
    fn add(&mut self, bytes: &[u8]) {
        for chunk in bytes.chunks(8) {
            let mut word = [0_u8; 8];
            word[..chunk.len()].copy_from_slice(chunk);
            self.0 = (self.0.rotate_left(5) ^ u64::from_le_bytes(word))
                .wrapping_mul(0x51_7c_c1_b7_27_22_0a_95);
        }
    }

    /// The final mixed value.
    fn finish(&self) -> u64 {
        let mut value = self.0;
        value ^= value >> 33;
        value = value.wrapping_mul(0xff51_afd7_ed55_8ccd);
        value ^ (value >> 33)
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
        // The queue drained: nothing is owed to anyone any more.
        codel.owed = 0;
        codel.flows.exempt_bytes = 0;
        return Verdict::Pass;
    }
    // Sparse-flow exemption (see `FlowShares`): count this packet's flow, and hand a due signal
    // only to a queue-heavy flow. A signal that lands on a sparse packet waits for the next
    // heavy one instead of being spent on a flow that didn't build the queue.
    let entry = codel
        .flows
        .account(flow_key(packet), packet.len(), now_ns, config.interval_ns);
    if due {
        codel.owed = codel.owed.saturating_add(1).min(MAX_OWED_SIGNALS);
    }
    if codel.owed == 0 {
        return Verdict::Pass;
    }
    if !codel.flows.is_heavy(entry) && codel.flows.exempt_bytes < EXEMPT_BUDGET_BYTES {
        return Verdict::Pass;
    }
    codel.owed -= 1;
    codel.flows.exempt_bytes = 0;
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
    fn flow_keys_separate_ports_protocols_and_fragments() {
        let a = flow_key(&tcp_v4(40_000, 0, 1_400));
        assert_eq!(
            a,
            flow_key(&tcp_v4(40_000, 0b10, 60)),
            "ECN and length don't matter"
        );
        assert_ne!(a, flow_key(&tcp_v4(40_001, 0, 1_400)));
        assert_ne!(a, flow_key(&icmp_probe()));
        let mut fragment = tcp_v4(40_000, 0, 1_400);
        fragment[7] = 0x10; // fragment offset 16: no ports in this packet
        assert_ne!(a, flow_key(&fragment));
        let mut ipv6 = vec![0_u8; 60];
        ipv6[0] = 0x60;
        ipv6[6] = 6;
        ipv6[40..42].copy_from_slice(&40_000_u16.to_be_bytes());
        let v6 = flow_key(&ipv6);
        ipv6[40..42].copy_from_slice(&40_001_u16.to_be_bytes());
        assert_ne!(v6, flow_key(&ipv6));
        assert_ne!(flow_key(&[]), 0);
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

    /// Rotating through more keys than the fixed table must not exempt an entire busy peer.
    #[test]
    fn j853_flow_churn_cannot_exempt_a_busy_peer_forever() {
        let config = ecn_1_10();
        let mut codel = Codel::default();
        let mut signals = 0;
        for step in 0..100_000_u64 {
            let now = 10 * MS + step * 10_000;
            let mut packet = tcp_v4(10_000 + (step % 50_000) as u16, 2, 1_400);
            signals += usize::from(
                judge_with(&mut codel, &mut packet, now - 3 * MS, now, &config) != Verdict::Pass,
            );
        }
        eprintln!(
            "J853 churn: 100000 packets, 140000000 bytes, 50000 rotating ports, signals={signals}"
        );
        assert!(
            signals > 0,
            "a continuously backlogged peer escaped every signal"
        );
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

    /// The new peer budget fits in the cached-index padding instead of growing per-peer state.
    #[test]
    fn j855_state_stays_bounded() {
        let peer = std::mem::size_of::<Codel>();
        let flows = std::mem::size_of::<FlowShares>();
        eprintln!(
            "J855 state: Codel={peer} FlowShares={flows} at4096={}",
            peer * 4096
        );
        assert_eq!(peer, 240);
        assert_eq!(flows, 208);
    }

    /// Changing interactive keys at a sparse rate stays exempt even beside a standing queue.
    #[test]
    fn j855_sparse_keystrokes_keep_their_exemption() {
        let config = ecn_1_10();
        let mut codel = Codel::default();
        let (_, mut now) = drive_bulk(&mut codel, &config, 1, 2, 10 * MS, 200);
        for key in 0..2000_u16 {
            now = codel.signal_next_ns.max(now) + MS;
            let mut keystroke = tcp_v4(10_000 + key, 0, 80);
            assert_eq!(
                judge_with(&mut codel, &mut keystroke, now - 3 * MS, now, &config),
                Verdict::Pass
            );
            let mut bulk = tcp_v4(40_000, 2, 1400);
            judge_with(&mut codel, &mut bulk, now - 3 * MS, now, &config);
        }
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
        // Refill a heavy entry after the long gap, then use an age exactly at the ceiling.
        codel
            .flows
            .account(flow_key(&packet), 1024 * 1024, due, config.interval_ns);
        assert_eq!(
            judge_with(&mut codel, &mut packet, due - MAX_SOJOURN_NS, due, &config),
            Verdict::Marked
        );
    }

    /// A churn fallback must also work below a decaying peer-byte budget's steady-state rate.
    #[test]
    fn j855_slow_churn_cannot_remain_exempt_forever() {
        let config = ecn_1_10();
        let mut codel = Codel::default();
        let mut signals = 0;
        for step in 0..100_000_u64 {
            let now = 10 * MS + step * MS;
            let mut packet = tcp_v4(10_000 + (step % 50_000) as u16, 2, 1_400);
            signals += usize::from(
                judge_with(&mut codel, &mut packet, now - 3 * MS, now, &config) != Verdict::Pass,
            );
        }
        eprintln!("J855 slow churn: 140000000 bytes at 1ms steps, signals={signals}");
        assert!(signals > 0);
    }

    /// A stable sparse flow must never spend the churn allowance, however long a trace lasts.
    #[test]
    fn j855_stable_sparse_flow_does_not_exhaust_churn_allowance() {
        let config = ecn_1_10();
        let mut codel = Codel::default();
        for step in 0..100_000_u64 {
            let now = 10 * MS + step * MS;
            let mut packet = tcp_v4(22, 0, 80);
            assert_eq!(
                judge_with(&mut codel, &mut packet, now - 3 * MS, now, &config),
                Verdict::Pass
            );
        }
        assert_eq!(codel.flows.exempt_bytes, 0);
    }
}
