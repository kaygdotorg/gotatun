// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

//! When a tunnel's timers next need a visit, so a device can sleep until then (infraternal #260).
//!
//! [`Tunn::update_timers`] has to run whenever one of the WireGuard timers (rekey, keepalive,
//! handshake retry, key zeroing, session and cookie expiry) is due. The original device polled
//! every tunnel every 250 ms to find out, which costs CPU and wakeups in proportion to the peer
//! count even when every peer is idle. This module lets a tunnel say *when* it is next due
//! instead:
//!
//! - [`Tunn::next_timer_deadline`] mirrors `update_timers` branch by branch and returns the
//!   earliest time at which a visit can do anything. It may be early (a visit then does nothing
//!   and the deadline is computed again), but it is never later than the first action. That
//!   one-sided error is the invariant the whole design rests on.
//! - A [`TimerHook`] installed with [`Tunn::set_timer_hook`] receives every new deadline. The
//!   tunnel reports one only on the transitions that can move its deadline *earlier* (a keepalive
//!   or handshake timer armed, the first data after a session, a session established, an
//!   initiation sent, a cookie, a keepalive request, a reset or a configuration change).
//!   Transitions that only push deadlines later report nothing; the stale, earlier entry causes
//!   one empty visit at most. So the per-packet path compares two durations and calls nothing in
//!   steady state.
//! - With a hook installed, the tunnel runs an *event clock*. Without one, packet timestamps are
//!   the time of the last `update_timers` call (`TimeCurrent`), which the old poll advanced every
//!   250 ms. Without the poll that value would go stale, so a hooked tunnel stamps events with the
//!   current time rounded down to [`TIMER_TICK`] (never below `TimeCurrent`). That keeps the old
//!   error bound (a stamp is at most one tick early) and the old "same tick" equality that the
//!   rekey-on-send rule depends on: data sent in the same tick as the handshake still does not
//!   count as sent after it.
//!
//!   The clock is read once per *run* of packets, not per stamp: [`Tunn::refresh_timer_clock`]
//!   runs at the top of each public entry point (`handle_incoming_packet`,
//!   `handle_outgoing_packet`, …), and the device calls it once before each batch it prepares
//!   or completes under one peer lock, then uses the crate-internal per-packet functions, which
//!   do not read the clock. A clock read per packet cost 2.5–4.6% of loaded throughput on the
//!   perf VM (#260, J1111), in the section serialised by the peer lock. A stamp is therefore at
//!   most one run's duration (microseconds) older than its event, on top of the one-tick
//!   rounding. Debug builds check on every stamp that the clock was refreshed within the last
//!   two ticks, so a call site that forgets the refresh fails the tests; in release it would
//!   only make that peer's timers fire early, never late.
//!
//! A tunnel without a hook behaves exactly as before, so direct users of [`Tunn`] that call
//! `update_timers` on their own schedule are unaffected.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use super::TimerName::{
    TimeCookieReceived, TimeCurrent, TimeLastDataPacketReceived, TimeLastDataPacketSent,
    TimeLastHandshakeStarted, TimeSessionEstablished,
};
use super::{
    COOKIE_EXPIRATION_TIME, KEEPALIVE_TIMEOUT, REJECT_AFTER_TIME, REKEY_TIMEOUT, TimerName, Timers,
};
use crate::noise::Tunn;

#[cfg(feature = "mock_instant")]
use mock_instant::thread_local::Instant;

#[cfg(not(feature = "mock_instant"))]
use crate::sleepyinstant::Instant;

/// The firing granularity of WireGuard timers: the old poll interval.
///
/// A device visits a tunnel no earlier than one tick after its previous visit and rounds wake-ups
/// up to this grid, so every timer fires within one tick after it is due, as it did when every
/// tunnel was polled every 250 ms. The event clock rounds timestamps down to the same grid.
pub(crate) const TIMER_TICK: Duration = Duration::from_millis(250);

/// The smallest step past an exact boundary.
///
/// Session slots expire when their age is strictly greater than `REJECT_AFTER_TIME`, so their
/// deadline is one step after the boundary, not on it.
const JUST_AFTER: Duration = Duration::from_nanos(1);

/// Where a tunnel reports its next timer deadline.
///
/// The callback receives the time from now until the tunnel next needs
/// [`Tunn::update_timers`], or `None` when nothing is due until some new event (for example an
/// expired handshake). Each call replaces the previous one. The callback runs while the caller
/// holds whatever lock protects the tunnel, so it must not block or call back into the tunnel.
#[derive(Clone)]
pub(crate) struct TimerHook(Arc<dyn Fn(Option<Duration>) + Send + Sync>);

impl TimerHook {
    /// Wrap a callback that records a tunnel's next deadline (see [`TimerHook`]).
    #[cfg_attr(not(feature = "device"), allow(dead_code))]
    pub(crate) fn new(report: impl Fn(Option<Duration>) + Send + Sync + 'static) -> Self {
        Self(Arc::new(report))
    }
}

impl fmt::Debug for TimerHook {
    /// A hook is an opaque callback; print only that one is present.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TimerHook")
    }
}

/// The scheduling state a tunnel keeps next to its timers.
///
/// `scheduled` is the deadline last reported through `hook`, in the tunnel's own time frame
/// (time since the tunnel started). It is what the scheduler believes; a transition that would be
/// due earlier reports a new deadline, anything later is left to the next visit.
#[derive(Debug, Default)]
pub(crate) struct Schedule {
    /// The callback that receives new deadlines, or `None` for an unscheduled tunnel.
    hook: Option<TimerHook>,
    /// The last deadline reported, or `None` if none is pending.
    scheduled: Option<Duration>,
}

impl Timers {
    /// Debug builds only: panic if a hooked tunnel stamps an event while `TimeCurrent` is more
    /// than two ticks old, which means the caller skipped [`Tunn::refresh_timer_clock`].
    pub(super) fn debug_assert_event_clock_fresh(&self) {
        #[cfg(debug_assertions)]
        if self.schedule.hook.is_some() {
            let elapsed = Instant::now()
                .checked_duration_since(self.time_started)
                .unwrap_or(Duration::ZERO);
            assert!(
                elapsed.saturating_sub(self[TimeCurrent]) <= TIMER_TICK * 2,
                "a timer stamp without a fresh event clock: call Tunn::refresh_timer_clock first"
            );
        }
    }

    /// Advance `TimeCurrent` to now, rounded down to the tick, before an event is stamped.
    ///
    /// Only a hooked tunnel runs this event clock (see the module docs). The result never moves
    /// `TimeCurrent` backwards, so every timestamp stays monotonic and no later than
    /// [`Timers::now`].
    pub(super) fn refresh_event_clock(&mut self) {
        if self.schedule.hook.is_none() {
            return;
        }
        let elapsed = Instant::now()
            .checked_duration_since(self.time_started)
            .unwrap_or(Duration::ZERO);
        let tick = TIMER_TICK.as_nanos();
        let rounded = elapsed.as_nanos() / tick * tick;
        let rounded = Duration::from_nanos(u64::try_from(rounded).unwrap_or(u64::MAX));
        if rounded > self[TimeCurrent] {
            self[TimeCurrent] = rounded;
        }
    }
}

impl<R: rand::RngCore + Send> Tunn<R> {
    /// Bring the event clock up to date before stamping a run of packets (see the module docs).
    ///
    /// One clock read; nothing without a hook. Call it once after taking the peer lock and before
    /// a batch of `prepare_outgoing_packet`, `prepare_queued_packet` or `complete_incoming_packet`
    /// calls. The public entry points call it themselves.
    pub(crate) fn refresh_timer_clock(&mut self) {
        self.timers.refresh_event_clock();
    }

    /// Report this tunnel's deadlines to `hook` from now on, and report the first one at once.
    ///
    /// Also starts the event clock (see the module docs). Call it once, before the tunnel sees
    /// any traffic; the device does so when it adds a peer.
    #[cfg_attr(not(feature = "device"), allow(dead_code))]
    pub(crate) fn set_timer_hook(&mut self, hook: TimerHook) {
        self.timers.schedule.hook = Some(hook);
        self.reschedule_timers(Duration::ZERO);
    }

    /// The earliest time, in this tunnel's frame (time since it started), at which
    /// [`Tunn::update_timers`] can act, or `None` if it cannot act before a new event.
    ///
    /// Each line mirrors one check in `update_timers`, in the same order, so the two are easy to
    /// compare. The result may be earlier than the first real action, never later.
    pub(crate) fn next_timer_deadline(&self) -> Option<Duration> {
        let timers = &self.timers;
        let current = timers[TimeCurrent];

        // A requested keepalive goes out on the next pass, or is dropped there if the handshake
        // has expired meanwhile. Either way the pass is due now.
        if timers.keepalive_requested {
            return Some(current);
        }
        // An expired connection does nothing until a new packet or handshake revives it, and
        // each of those reports a new deadline.
        if self.handshake.is_expired() {
            return None;
        }

        let session_established = timers[TimeSessionEstablished];
        // Key zeroing after three times the reject time without a new session.
        let mut due = session_established + REJECT_AFTER_TIME * 3;
        // Each session slot is forgotten (and its timer restarted) once it is older than the
        // reject time. Empty slots restart their timer too, so they count as well.
        for &slot in &timers.session_timers {
            due = due.min(slot + REJECT_AFTER_TIME + JUST_AFTER);
        }
        if self.handshake.has_cookie() {
            due = due.min(timers[TimeCookieReceived] + COOKIE_EXPIRATION_TIME);
        }

        if let Some(time_init_sent) = self.handshake.timer() {
            // A handshake is in flight: only the give-up time and the retry matter, as in
            // `update_timers`, which skips every other rule in this state.
            due = due.min(timers[TimeLastHandshakeStarted] + timers.params.rekey_attempt_time);
            let retry_in = self
                .handshake_retry_delay()
                .saturating_sub(time_init_sent.elapsed());
            due = due.min(timers.now() + retry_in);
            return Some(due);
        }

        if timers.is_initiator {
            // Rekey after REKEY_AFTER_TIME, once data was sent on this session.
            if session_established < timers[TimeLastDataPacketSent] {
                due = due.min(session_established + timers.rekey_after_time);
            }
            // Rekey before the session would be rejected, once data was received on it.
            if session_established < timers[TimeLastDataPacketReceived] {
                due = due.min(
                    session_established + REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT,
                );
            }
        }
        // New handshake after sending data and hearing nothing back.
        if let Some(since) = timers.want_handshake {
            due = due.min(since + timers.new_handshake_timeout);
        }
        // Passive keepalive after receiving data and sending nothing back.
        if let Some(since) = timers.want_keepalive {
            due = due.min(since + timers.keepalive_timeout);
        }
        // Persistent keepalive: now if one is owed, otherwise one interval after the last packet.
        if let Some(interval) = timers.persistent_keepalive {
            due = due.min(if timers.persistent_keepalive_due {
                current
            } else {
                timers.persistent_keepalive_at(interval)
            });
        }
        Some(due)
    }

    /// Compute the next deadline from scratch and report it, at least `not_before` from now.
    ///
    /// A device calls this after each visit with one [`TIMER_TICK`], so a tunnel is never
    /// visited twice in one tick (an early deadline could otherwise spin). The tunnel itself
    /// calls it with zero after events that change several timers at once. Does nothing without
    /// a hook.
    pub(crate) fn reschedule_timers(&mut self, not_before: Duration) {
        if self.timers.schedule.hook.is_none() {
            return;
        }
        let now = self.timers.now();
        let deadline = self
            .next_timer_deadline()
            .map(|due| due.max(now + not_before));
        self.report_deadline(deadline, now);
    }

    /// Withdraw this tunnel's deadline, for a peer the device cannot serve yet (no endpoint).
    ///
    /// The next transition that arms a timer reports a new one, since nothing is pending.
    #[cfg_attr(not(feature = "device"), allow(dead_code))]
    pub(crate) fn unschedule_timers(&mut self) {
        if self.timers.schedule.hook.is_some() {
            let now = self.timers.now();
            self.report_deadline(None, now);
        }
    }

    /// Whether the pending deadline is no later than the real one, allowing the one-tick floor
    /// that [`Tunn::reschedule_timers`] applies after a visit.
    ///
    /// Tests call this on every tick to verify that no transition armed an earlier timer without
    /// reporting it. Always `true` without a hook.
    #[cfg(all(test, feature = "mock_instant"))]
    pub(crate) fn timer_schedule_is_consistent(&self) -> bool {
        if self.timers.schedule.hook.is_none() {
            return true;
        }
        match (self.next_timer_deadline(), self.timers.schedule.scheduled) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(due), Some(pending)) => pending <= due.max(self.timers.now() + TIMER_TICK),
        }
    }

    /// Report a deadline that one event has just armed, if it is earlier than the one pending.
    ///
    /// This is the per-packet check: when nothing gets earlier it compares two durations and
    /// returns. Calls nothing without a hook.
    fn arm_timer_deadline(&mut self, candidate: Duration) {
        let schedule = &self.timers.schedule;
        if schedule.hook.is_none()
            || schedule
                .scheduled
                .is_some_and(|pending| pending <= candidate)
        {
            return;
        }
        let now = self.timers.now();
        self.report_deadline(Some(candidate), now);
    }

    /// Record `deadline` as pending and pass it to the hook as a delay from `now`.
    fn report_deadline(&mut self, deadline: Option<Duration>, now: Duration) {
        let schedule = &mut self.timers.schedule;
        schedule.scheduled = deadline;
        if let Some(hook) = &schedule.hook {
            (hook.0)(deadline.map(|due| due.saturating_sub(now)));
        }
    }

    /// Report what one [`Tunn::timer_tick`] armed. `before` is the stamp it replaced.
    ///
    /// Only the data stamps arm deadlines that can be earlier than the pending one; the other
    /// stamps either push deadlines later (keepalive resets) or are followed by a full
    /// [`Tunn::reschedule_timers`] once the whole event is recorded (session established,
    /// initiation sent), or are handled here in full because they are rare (cookie).
    pub(super) fn timer_tick_armed(&mut self, timer_name: TimerName, before: Duration) {
        if self.timers.schedule.hook.is_none() {
            return;
        }
        let timers = &self.timers;
        let session_established = timers[TimeSessionEstablished];
        // The first data stamp after the session started turns a rekey rule on.
        let first_after_session = timers.is_initiator
            && before <= session_established
            && session_established < timers[TimeCurrent];
        match timer_name {
            TimeLastDataPacketReceived => {
                if let Some(since) = timers.want_keepalive {
                    self.arm_timer_deadline(since + self.timers.keepalive_timeout);
                }
                if first_after_session {
                    self.arm_timer_deadline(
                        session_established + REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT,
                    );
                }
            }
            TimeLastDataPacketSent => {
                if let Some(since) = timers.want_handshake {
                    self.arm_timer_deadline(since + self.timers.new_handshake_timeout);
                }
                if first_after_session {
                    self.arm_timer_deadline(session_established + self.timers.rekey_after_time);
                }
            }
            TimeCookieReceived => self.reschedule_timers(Duration::ZERO),
            _ => {}
        }
    }

    /// Report a keepalive request: the next pass is due now.
    pub(super) fn arm_requested_keepalive(&mut self) {
        let current = self.timers[TimeCurrent];
        self.arm_timer_deadline(current);
    }
}

/// The old schedule against the new one (#260, J1111).
///
/// Two tunnels exchange random traffic over a lossy link that sometimes goes down for long
/// enough to exhaust handshake retries. The same script runs twice on the mock clock: once with
/// the old driver, which calls `update_timers` on both tunnels on every 250 ms tick, and once
/// with the new one, which calls it only on ticks at or after the deadline the tunnel reported.
/// Every packet either tunnel produces is logged with its time, and the two logs must be
/// identical: same packets, same order, same times. The new run also checks on every tick that
/// no tunnel's reported deadline is later than its real one.
#[cfg(all(test, feature = "mock_instant"))]
mod tests {
    use super::*;
    use crate::noise::{TunnResult, index_table::IndexTable, rate_limiter::RateLimiter};
    use crate::packet::{Packet, WgKind};
    use crate::x25519::{PublicKey, StaticSecret};
    use bytes::BytesMut;
    use mock_instant::thread_local::MockClock;
    use rand::{Rng, SeedableRng, rngs::StdRng};
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    /// What a tunnel sent, as the log records it.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Sent {
        Init,
        Response,
        Cookie,
        Data,
        Keepalive,
    }

    /// One logged packet: when (ns on the mock clock), which side (0 = A), and what.
    type Entry = (u128, usize, Sent);

    /// A tunnel in the simulation, with the deadline its hook last reported (absolute, mock time).
    struct Side {
        tunnel: Tunn<StdRng>,
        due: Arc<Mutex<Option<Duration>>>,
    }

    /// Classify a packet for the log.
    fn kind(packet: &WgKind) -> Sent {
        match packet {
            WgKind::HandshakeInit(_) => Sent::Init,
            WgKind::HandshakeResp(_) => Sent::Response,
            WgKind::CookieReply(_) => Sent::Cookie,
            WgKind::Data(data) if data.is_keepalive() => Sent::Keepalive,
            WgKind::Data(_) => Sent::Data,
        }
    }

    /// A small IPv4/UDP packet to send through the tunnel.
    fn ip_packet() -> Packet {
        let header = etherparse::PacketBuilder::ipv4([10, 0, 0, 1], [10, 0, 0, 2], 5).udp(5678, 23);
        let payload = [7u8; 32];
        let mut bytes = Vec::with_capacity(header.size(payload.len()));
        header.write(&mut bytes, &payload).unwrap();
        Packet::from_bytes(BytesMut::from(&bytes[..]))
    }

    /// One-way link delay. Not a round number, so no delivery lands exactly on a tick: at a tick
    /// both drivers run their passes first, as on a real link where a packet produced by a pass
    /// arrives a little later.
    const LATENCY: Duration = Duration::from_nanos(500_001);

    /// Something the simulation does at a given time.
    enum Event {
        /// A packet arrives at this side.
        Deliver(usize, WgKind),
        /// This side's application sends a data packet.
        Send(usize),
    }

    /// The simulated world: two tunnels, a link, the script's randomness and the log.
    struct World {
        sides: [Side; 2],
        rng: StdRng,
        /// Probability that one packet is lost.
        loss: f64,
        /// The link drops everything until this time.
        down_until: Duration,
        /// Pending events by (time, insertion order).
        events: BTreeMap<(Duration, u64), Event>,
        next_event: u64,
        log: Vec<Entry>,
    }

    impl World {
        /// Two fresh tunnels at mock time zero; A has a persistent keepalive if `keepalive`.
        /// With `coalesced`, both follow a device's idle policy.
        fn new(seed: u64, hooked: bool, keepalive: Option<u16>, coalesced: bool) -> Self {
            MockClock::set_time(Duration::ZERO);
            let origin = Instant::now();
            let a_key = StaticSecret::random_from_rng(rand_core::OsRng);
            let b_key = StaticSecret::random_from_rng(rand_core::OsRng);
            let make = |own: &StaticSecret, other: &StaticSecret, keepalive, jitter_seed| {
                let limiter = Arc::new(RateLimiter::new(&PublicKey::from(own), 100));
                let mut tunnel = Tunn::new_with_rng(
                    own.clone(),
                    PublicKey::from(other),
                    None,
                    keepalive,
                    IndexTable::from_os_rng(),
                    limiter,
                    StdRng::seed_from_u64(jitter_seed),
                );
                if coalesced {
                    tunnel.coalesce_idle_timers(origin);
                }
                let due = Arc::new(Mutex::new(None));
                if hooked {
                    let report = Arc::clone(&due);
                    tunnel.set_timer_hook(TimerHook::new(move |due_in: Option<Duration>| {
                        *report.lock().unwrap() = due_in.map(|delay| MockClock::time() + delay);
                    }));
                }
                Side { tunnel, due }
            };
            let a = make(&a_key, &b_key, keepalive, seed ^ 0xa);
            let b = make(&b_key, &a_key, None, seed ^ 0xb);
            World {
                sides: [a, b],
                rng: StdRng::seed_from_u64(seed),
                loss: 0.0,
                down_until: Duration::ZERO,
                events: BTreeMap::new(),
                next_event: 0,
                log: Vec::new(),
            }
        }

        /// Queue an event at `at`.
        fn schedule(&mut self, at: Duration, event: Event) {
            self.events.insert((at, self.next_event), event);
            self.next_event += 1;
        }

        /// Log `packet` from side `from` and, unless the link loses it, deliver it to the other
        /// side one link delay later.
        fn send(&mut self, from: usize, packet: WgKind) {
            let now = MockClock::time();
            self.log.push((now.as_nanos(), from, kind(&packet)));
            if now < self.down_until || self.rng.random_bool(self.loss) {
                return;
            }
            self.schedule(now + LATENCY, Event::Deliver(1 - from, packet));
        }

        /// Run every event before `until`, in time order, on the mock clock.
        fn run_until(&mut self, until: Duration) {
            while let Some(entry) = self.events.first_entry() {
                let (at, _) = *entry.key();
                if at >= until {
                    break;
                }
                let event = entry.remove();
                MockClock::set_time(at);
                match event {
                    Event::Deliver(to, packet) => {
                        let result = self.sides[to].tunnel.handle_incoming_packet(packet);
                        if let TunnResult::WriteToNetwork(answer) = result {
                            self.send(to, answer);
                        }
                        self.flush(to);
                    }
                    Event::Send(side) => {
                        if let Some(packet) = self.sides[side]
                            .tunnel
                            .handle_outgoing_packet(ip_packet(), None)
                        {
                            self.send(side, packet);
                        }
                    }
                }
            }
        }

        /// Send packets a side queued while it waited for a handshake, once it has a session.
        fn flush(&mut self, side: usize) {
            while self.sides[side].tunnel.has_current_session() {
                let Some(queued) = self.sides[side].tunnel.take_queued_packet() else {
                    break;
                };
                match self.sides[side].tunnel.handle_outgoing_packet(queued, None) {
                    Some(packet) => self.send(side, packet),
                    None => break,
                }
            }
        }

        /// One timer pass at the current tick. The old driver visits both tunnels; the new one
        /// only those whose reported deadline has come.
        fn timer_pass(&mut self, hooked: bool) {
            let now = MockClock::time();
            for side in 0..2 {
                if hooked {
                    assert!(
                        self.sides[side].tunnel.timer_schedule_is_consistent(),
                        "side {side} was scheduled later than its real deadline at {now:?}"
                    );
                    let due = *self.sides[side].due.lock().unwrap();
                    if due.is_none_or(|due| due > now) {
                        continue;
                    }
                }
                let result = self.sides[side].tunnel.update_timers();
                if hooked {
                    self.sides[side].tunnel.reschedule_timers(TIMER_TICK);
                }
                if let Ok(Some(packet)) = result {
                    self.send(side, packet);
                }
            }
        }

        /// The script's traffic until the next tick: a send per side at a random microsecond.
        fn traffic(&mut self, tick_start: Duration, rate: [f64; 2]) {
            for (side, &p) in rate.iter().enumerate() {
                if self.rng.random_bool(p) {
                    let micros = self.rng.random_range(1..TIMER_TICK.as_micros() as u64);
                    self.schedule(
                        tick_start + Duration::from_micros(micros),
                        Event::Send(side),
                    );
                }
            }
        }
    }

    /// Run one seeded script for `ticks` ticks and return the log.
    fn simulate(seed: u64, hooked: bool, coalesced: bool, ticks: u64) -> Vec<Entry> {
        let mut script = StdRng::seed_from_u64(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15));
        let keepalive = script.random_bool(0.5).then_some(25);
        let mut world = World::new(seed, hooked, keepalive, coalesced);
        let mut rate = [0.0, 0.0];
        for tick in 0..ticks {
            let start = TIMER_TICK * u32::try_from(tick).unwrap();
            world.run_until(start);
            MockClock::set_time(start);
            // Phases change about every 20 s: quiet, one-way, two-way or bursty traffic, a
            // lossy link, and sometimes an outage long enough to give up on a handshake.
            if tick % 80 == 0 {
                rate = match script.random_range(0..5) {
                    0 => [0.0, 0.0],
                    1 => [0.3, 0.0],
                    2 => [0.0, 0.2],
                    3 => [0.5, 0.5],
                    _ => [0.02, 0.01],
                };
                world.loss = [0.0, 0.0, 0.1, 0.5][script.random_range(0..4)];
                if script.random_bool(0.15) {
                    world.down_until = start + Duration::from_secs(script.random_range(5..130));
                }
            }
            world.timer_pass(hooked);
            world.traffic(start, rate);
        }
        world.log
    }

    /// The deadline driver sends exactly what the 250 ms poll sends, when it sends it.
    #[test]
    fn deadline_schedule_matches_the_polled_schedule() {
        // 20 simulated minutes per script: long enough for rekeys, retries, give-ups and key
        // zeroing (9 minutes without a new session) to happen.
        const TICKS: u64 = 4 * 60 * 20;
        let mut packets = 0;
        for (seed, coalesced) in (0..48).map(|seed| (seed, seed % 2 == 1)) {
            let polled = simulate(seed, false, coalesced, TICKS);
            let scheduled = simulate(seed, true, coalesced, TICKS);
            if let Some(at) = polled.iter().zip(&scheduled).position(|(a, b)| a != b) {
                panic!(
                    "seed {seed}: first difference at entry {at}: polled {:?}, scheduled {:?}",
                    &polled[at.saturating_sub(3)..(at + 3).min(polled.len())],
                    &scheduled[at.saturating_sub(3)..(at + 3).min(scheduled.len())],
                );
            }
            assert_eq!(
                polled.len(),
                scheduled.len(),
                "seed {seed}: different lengths"
            );
            packets += polled.len();
        }
        assert!(
            packets > 10_000,
            "the scripts produced too little traffic: {packets}"
        );
    }

    /// An idle tunnel with nothing due is not visited at all between its deadlines.
    #[test]
    fn an_idle_tunnel_reports_no_deadline_once_expired() {
        let mut world = World::new(7, true, None, false);
        // Never any traffic: the only deadlines are session-slot restarts and key zeroing.
        let mut visits = 0;
        for tick in 0..(4 * 60 * 12) {
            MockClock::set_time(TIMER_TICK * tick);
            let now = MockClock::time();
            let due = *world.sides[0].due.lock().unwrap();
            if due.is_some_and(|due| due <= now) {
                visits += 1;
                let _ = world.sides[0].tunnel.update_timers();
                world.sides[0].tunnel.reschedule_timers(TIMER_TICK);
            }
        }
        // Slot restarts at 180 s and 360 s, zeroing at 540 s, then nothing until an event.
        assert!(
            visits <= 4,
            "an idle tunnel was visited {visits} times in 12 minutes"
        );
        assert_eq!(*world.sides[0].due.lock().unwrap(), None);
    }
}
