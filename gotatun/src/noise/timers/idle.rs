// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

//! What a device does so that peers nobody is talking to cost few wakeups (infraternal #260,
//! J1253, D81: idle CPU zero).
//!
//! A bare [`Tunn`] follows the plain WireGuard timings. A device turns this policy on with
//! [`Tunn::back_off_when_idle`], and then:
//!
//! - **Handshake retries back off** while nothing but keepalives waits for a peer without a
//!   session: 5 s, 10 s, then 20 s apart, until the give-up time. An offline peer with a
//!   persistent keepalive costs six initiations instead of eighteen. The cap keeps the gap under
//!   the 30 s that connection trackers keep an unanswered UDP mapping, so a NAT opened by one
//!   attempt is still open at the next. As soon as data waits for the peer, or the caller forces
//!   a handshake, the ordinary retry interval applies again.

use std::time::Duration;

use crate::noise::Tunn;

/// How often the retry interval doubles for a peer that only keepalives wait for: 5, 10, 20 s.
const RETRY_DOUBLINGS: u32 = 2;

/// The policy a device applies to idle peers. The default, for a bare [`Tunn`], is none.
#[derive(Debug, Clone, Copy, Default)]
pub(in crate::noise) struct IdlePolicy {
    /// How often the handshake retry interval doubles while only keepalives wait for a peer.
    retry_doublings: u32,
}

impl<R: rand::RngCore + Send> Tunn<R> {
    /// Apply the device's idle policy to this tunnel (see the module docs).
    ///
    /// Call it once, before the tunnel sees traffic; the device does so when it adds a peer.
    #[cfg_attr(not(feature = "device"), allow(dead_code))]
    pub(crate) fn back_off_when_idle(&mut self) {
        self.timers.idle = IdlePolicy {
            retry_doublings: RETRY_DOUBLINGS,
        };
        self.reschedule_timers(Duration::ZERO);
    }

    /// How long after the last initiation the next retransmission is due.
    ///
    /// The sampled rekey timeout. While the peer has no session and no data waits for it, the
    /// shortest rekey timeout is doubled once per retransmission (at most [`RETRY_DOUBLINGS`]
    /// times) and the sample's jitter is added once, so the gap never grows past 21 s.
    pub(in crate::noise) fn handshake_retry_delay(&self) -> Duration {
        let base = self.timers.rekey_timeout;
        let doublings = self
            .timers
            .unanswered_retries
            .min(self.timers.idle.retry_doublings);
        if doublings == 0
            || self.has_current_session()
            || self.packet_queue.iter().any(|packet| !packet.is_empty())
        {
            return base;
        }
        let shortest = *self.timers.params.rekey_timeout.start();
        base.saturating_add(shortest.saturating_mul((1 << doublings) - 1))
    }
}

#[cfg(all(test, feature = "mock_instant"))]
mod tests {
    use super::*;
    use crate::noise::{index_table::IndexTable, rate_limiter::RateLimiter};
    use crate::packet::{Packet, WgKind};
    use crate::x25519::{PublicKey, StaticSecret};
    use bytes::BytesMut;
    use mock_instant::thread_local::MockClock;
    use std::sync::Arc;

    /// The poll step the tests drive timers with: finer than any retry interval.
    const STEP: Duration = Duration::from_millis(250);

    /// A tunnel to a peer that never answers, with a 25 s persistent keepalive and the idle
    /// policy on, at mock time zero.
    fn offline_tunnel() -> Tunn {
        MockClock::set_time(Duration::ZERO);
        let own = StaticSecret::random_from_rng(rand_core::OsRng);
        let theirs = PublicKey::from(&StaticSecret::random_from_rng(rand_core::OsRng));
        let limiter = Arc::new(RateLimiter::new(&PublicKey::from(&own), 100));
        let mut tunnel = Tunn::new(
            own,
            theirs,
            None,
            Some(25),
            IndexTable::from_os_rng(),
            limiter,
        );
        tunnel.back_off_when_idle();
        tunnel
    }

    /// Poll the timers from now until `until`, returning the seconds at which an initiation left.
    fn run_until(tunnel: &mut Tunn, until: Duration) -> Vec<u64> {
        let mut sent = Vec::new();
        while MockClock::time() < until {
            if let Ok(Some(WgKind::HandshakeInit(_))) = tunnel.update_timers() {
                sent.push(MockClock::time().as_secs());
            }
            MockClock::advance(STEP);
        }
        sent
    }

    /// Assert that each time is within the jitter and polling slack after the expected one.
    fn assert_near(sent: &[u64], expected: &[u64]) {
        assert_eq!(sent.len(), expected.len(), "initiations at {sent:?}");
        for (&at, &want) in sent.iter().zip(expected) {
            assert!(
                at >= want && at <= want + 3,
                "initiations at {sent:?}, expected about {expected:?}"
            );
        }
    }

    /// An offline peer that only a persistent keepalive waits for is tried at 0, 5, 15, 35, 55
    /// and 75 s, then never again.
    #[test]
    fn retries_to_an_offline_peer_back_off_and_stop() {
        let mut tunnel = offline_tunnel();
        let sent = run_until(&mut tunnel, Duration::from_secs(200));
        assert_near(&sent, &[0, 5, 15, 35, 55, 75]);
        assert!(tunnel.is_expired(), "the attempt was given up");
        assert_eq!(tunnel.next_timer_deadline(), None, "nothing is left due");
    }

    /// Data waiting for the peer brings back the ordinary 5 s retry: the retry held up by the
    /// back-off leaves at once.
    #[test]
    fn queued_data_ends_the_back_off() {
        let mut tunnel = offline_tunnel();
        // Initiations at 0, 5, 15 and 35 s; the next would be at 55 s.
        run_until(&mut tunnel, Duration::from_secs(42));
        let data = Packet::from_bytes(BytesMut::from(&[0x45_u8; 40][..]));
        assert!(
            tunnel.handle_outgoing_packet(data, None).is_none(),
            "an initiation is already in flight"
        );
        let sent = run_until(&mut tunnel, Duration::from_secs(60));
        assert_near(&sent, &[42, 47, 52, 57]);
    }
}
