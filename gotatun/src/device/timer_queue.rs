// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

//! The device's queue of per-peer timer deadlines, so the timer task wakes only when a peer has
//! something due (infraternal #260, J1111).
//!
//! Each peer's tunnel reports its next deadline through a [`TimerHook`] (see
//! `noise::timers::deadline`). The queue keeps the latest one per peer in a min-heap, and the
//! timer task sleeps until the earliest, then visits only the peers that are due. Before this,
//! the task visited every peer every 250 ms: 125 wakeups and 7.7 ms of CPU per second at 4,096
//! idle peers (J1077, table A on #260).
//!
//! # Timing rules
//!
//! - Wake-ups are rounded up to a [`TIMER_TICK`] grid. Every timer still fires within one tick
//!   after it is due, as with the old poll, and deadlines that fall in one tick share a wake.
//! - A deadline that is already due is served at once, so a requested keepalive still leaves
//!   immediately.
//! - The task never sleeps longer than [`MAX_SLEEP`]. Deadlines are measured on the WireGuard
//!   clock, which keeps running while the system sleeps; the runtime's sleep timer may not. The
//!   cap bounds how late a timer can be after the system wakes up.
//!
//! # Consistency
//!
//! An entry is replaced whenever its peer reports again, and older heap items are skipped by a
//! sequence number (lazy deletion), so the heap holds at most one live item per peer plus stale
//! ones that are discarded as they surface. The queue's lock is a short synchronous one: it is
//! taken under a peer-state lock (by the hook) and never the other way round, and it is never
//! held across an await.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::sync::Weak;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::Mutex;

use super::peer_state::PeerState;
use crate::noise::{TIMER_TICK, TimerHook};

#[cfg(feature = "mock_instant")]
use mock_instant::thread_local::Instant;

#[cfg(not(feature = "mock_instant"))]
use crate::sleepyinstant::Instant;

/// The longest the timer task sleeps, even with nothing due.
///
/// One cheap wake per second, independent of the peer count. It bounds how late a timer fires
/// after the system resumes from sleep (see the module docs).
pub(crate) const MAX_SLEEP: Duration = Duration::from_secs(1);

/// How often the timer task visits every peer regardless of its deadline.
///
/// A safety net while the deadline queue is new: a visit is always correct, so a missed report
/// can delay a timer by at most this long. Each sweep also counts peers whose reported deadline
/// was later than their real one ([`TimerQueue::sweep_misses`], which must stay at zero). It costs
/// one old-style pass every ten seconds, a fortieth of the old poll.
pub(crate) const SAFETY_SWEEP: Duration = Duration::from_secs(10);

/// A peer the timer task should visit, as stored in the queue.
type PeerHandle = Weak<Mutex<PeerState>>;

/// Per-peer timer deadlines shared by the peers' hooks and the timer task.
#[derive(Default)]
pub(crate) struct TimerQueue {
    /// Deadlines and the heap that orders them.
    state: parking_lot::Mutex<QueueState>,
    /// Wakes the timer task when a deadline earlier than the one it sleeps for arrives. A
    /// `Notify` keeps one permit, so a report made just before the task waits is not lost.
    wake: tokio::sync::Notify,
    /// The time origin of every deadline in this queue.
    epoch: Epoch,
    /// Peers whose reported deadline was later than their real one when a sweep checked.
    misses: AtomicU64,
}

/// The queue's clock origin, on the same clock as the tunnels' timers.
struct Epoch(Instant);

impl Default for Epoch {
    /// Start the queue's clock now.
    fn default() -> Self {
        Self(Instant::now())
    }
}

/// The deadlines, guarded by [`TimerQueue::state`].
#[derive(Default)]
struct QueueState {
    /// Every pending deadline, earliest first: (due, sequence number, peer key).
    heap: BinaryHeap<Reverse<(Duration, u64, usize)>>,
    /// The live deadline of each scheduled peer, by peer key. A heap item whose sequence number
    /// differs from its entry here is stale.
    entries: HashMap<usize, Entry>,
    /// Source of sequence numbers, so a replaced deadline never matches a later one.
    next_seq: u64,
}

/// One peer's live deadline.
struct Entry {
    /// Matches the heap item that carries this deadline.
    seq: u64,
    /// The peer to visit. Weak, so a removed peer is not kept alive by its deadline.
    peer: PeerHandle,
}

impl TimerQueue {
    /// The current time on the queue's clock.
    pub(crate) fn now(&self) -> Duration {
        Instant::now()
            .checked_duration_since(self.epoch.0)
            .unwrap_or(Duration::ZERO)
    }

    /// A hook for the peer at `peer`, to install in its tunnel with `Tunn::set_timer_hook`.
    ///
    /// The peer key is the address of its state, as everywhere else in the device.
    pub(crate) fn hook(self: &std::sync::Arc<Self>, peer: PeerHandle) -> TimerHook {
        let queue = std::sync::Arc::downgrade(self);
        TimerHook::new(move |due_in| {
            if let Some(queue) = queue.upgrade() {
                queue.set(&peer, due_in);
            }
        })
    }

    /// Replace a peer's deadline with `due_in` from now, or remove it if `None`.
    ///
    /// Wakes the timer task if the new deadline is earlier than every other one, since the task
    /// may be sleeping for that one.
    pub(crate) fn set(&self, peer: &PeerHandle, due_in: Option<Duration>) {
        let key = peer.as_ptr() as usize;
        let earliest = {
            let mut state = self.state.lock();
            let Some(due_in) = due_in else {
                state.entries.remove(&key);
                return;
            };
            let due = self.now() + due_in;
            let seq = state.next_seq;
            state.next_seq += 1;
            let earliest = state.peek_live().is_none_or(|head| due < head);
            state.entries.insert(
                key,
                Entry {
                    seq,
                    peer: peer.clone(),
                },
            );
            state.heap.push(Reverse((due, seq, key)));
            earliest
        };
        if earliest {
            self.wake.notify_one();
        }
    }

    /// Forget a removed peer's deadline.
    pub(crate) fn forget(&self, key: usize) {
        self.state.lock().entries.remove(&key);
    }

    /// Forget every deadline, when the device drops all its peers.
    pub(crate) fn clear(&self) {
        let mut state = self.state.lock();
        state.entries.clear();
        state.heap.clear();
    }

    /// Remove and return every peer due at or before `now` that still exists.
    pub(crate) fn take_due(&self, now: Duration) -> Vec<std::sync::Arc<Mutex<PeerState>>> {
        let mut state = self.state.lock();
        let mut due = Vec::new();
        while let Some(head) = state.peek_live() {
            if head > now {
                break;
            }
            let Reverse((_, _, key)) = state.heap.pop().expect("peek_live saw a head");
            if let Some(entry) = state.entries.remove(&key)
                && let Some(peer) = entry.peer.upgrade()
            {
                due.push(peer);
            }
        }
        due
    }

    /// The earliest pending deadline, if any.
    pub(crate) fn next_due(&self) -> Option<Duration> {
        self.state.lock().peek_live()
    }

    /// How long the timer task should sleep at `now`: until the earliest deadline rounded up to
    /// the tick grid, zero if one is already due, and never more than `cap`.
    pub(crate) fn sleep_for(&self, now: Duration, cap: Duration) -> Duration {
        let Some(due) = self.next_due() else {
            return cap;
        };
        if due <= now {
            return Duration::ZERO;
        }
        let tick = TIMER_TICK.as_nanos();
        let wake = due.as_nanos().div_ceil(tick) * tick;
        let wake = Duration::from_nanos(u64::try_from(wake).unwrap_or(u64::MAX));
        wake.saturating_sub(now).min(cap)
    }

    /// Wait until a deadline earlier than the current earliest one is reported.
    pub(crate) async fn notified(&self) {
        self.wake.notified().await;
    }

    /// Record a peer whose deadline was found later than its real one by a sweep.
    pub(crate) fn record_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Peers that sweeps found scheduled too late, since the device started. Must stay at zero;
    /// anything else is a missing report in the tunnel and a timer that fired up to one sweep
    /// late.
    pub(crate) fn sweep_misses(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }
}

impl QueueState {
    /// The earliest live deadline, discarding stale heap items on the way.
    fn peek_live(&mut self) -> Option<Duration> {
        while let Some(&Reverse((due, seq, key))) = self.heap.peek() {
            if self.entries.get(&key).is_some_and(|entry| entry.seq == seq) {
                return Some(due);
            }
            self.heap.pop();
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// A peer state handle for queue tests; the queue never locks it.
    fn peer() -> Arc<Mutex<PeerState>> {
        use crate::noise::{Tunn, index_table::IndexTable, rate_limiter::RateLimiter};
        use crate::x25519::{PublicKey, StaticSecret};
        let own = StaticSecret::random_from_rng(rand_core::OsRng);
        let theirs = PublicKey::from(&StaticSecret::random_from_rng(rand_core::OsRng));
        let limiter = Arc::new(RateLimiter::new(&PublicKey::from(&own), 100));
        let tunnel = Tunn::new(own, theirs, None, None, IndexTable::from_os_rng(), limiter);
        Arc::new(Mutex::new(PeerState::new(
            tunnel,
            None,
            &[],
            #[cfg(feature = "daita")]
            None,
        )))
    }

    /// The earliest deadline comes out first, a replaced one only once, a removed one never.
    #[test]
    fn replaced_and_forgotten_deadlines_do_not_resurface() {
        let queue = TimerQueue::default();
        let (a, b, c) = (peer(), peer(), peer());
        let now = queue.now();
        queue.set(&Arc::downgrade(&a), Some(Duration::from_secs(30)));
        queue.set(&Arc::downgrade(&b), Some(Duration::from_secs(20)));
        queue.set(&Arc::downgrade(&c), Some(Duration::from_secs(10)));
        // Move a earlier, then later again: only the last report counts.
        queue.set(&Arc::downgrade(&a), Some(Duration::from_secs(5)));
        queue.set(&Arc::downgrade(&a), Some(Duration::from_secs(25)));
        queue.forget(Arc::as_ptr(&b) as usize);

        let due = queue.next_due().expect("two peers remain");
        assert!(due >= now + Duration::from_secs(10) && due < now + Duration::from_secs(11));
        let taken = queue.take_due(now + Duration::from_secs(60));
        let order: Vec<_> = taken.iter().map(Arc::as_ptr).collect();
        assert_eq!(order, vec![Arc::as_ptr(&c), Arc::as_ptr(&a)]);
        assert!(queue.next_due().is_none());
    }

    /// Wake-ups land on the tick grid, never wait for a due deadline, and respect the cap.
    #[test]
    fn sleep_rounds_up_to_the_tick_and_is_capped() {
        let queue = TimerQueue::default();
        let a = peer();
        assert_eq!(queue.sleep_for(Duration::ZERO, MAX_SLEEP), MAX_SLEEP);

        queue.set(&Arc::downgrade(&a), Some(Duration::ZERO));
        assert_eq!(
            queue.sleep_for(queue.now() + Duration::from_millis(1), MAX_SLEEP),
            Duration::ZERO
        );

        // Put the deadline at a known point by forging the clock reading passed in.
        let due = queue.next_due().unwrap();
        let now = due.saturating_sub(Duration::from_millis(1));
        let sleep = queue.sleep_for(now, Duration::from_secs(60));
        let wake = now + sleep;
        assert!(wake >= due, "woke before the deadline");
        assert!(wake < due + TIMER_TICK, "woke more than one tick late");
        assert_eq!(
            wake.as_nanos() % TIMER_TICK.as_nanos(),
            0,
            "off the tick grid"
        );
    }

    /// A removed peer's deadline is dropped, not served.
    #[test]
    fn dropped_peers_are_not_returned() {
        let queue = TimerQueue::default();
        let a = peer();
        queue.set(&Arc::downgrade(&a), Some(Duration::ZERO));
        drop(a);
        assert!(
            queue
                .take_due(queue.now() + Duration::from_secs(1))
                .is_empty()
        );
    }
}
