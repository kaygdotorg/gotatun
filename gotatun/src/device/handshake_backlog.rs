// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The receive task's queue of handshake messages waiting for their key agreement (#260, J1112).
//!
//! A handshake message costs one or two X25519 key agreements, a thousand times a data packet's
//! header work, and the device runs them in its single UDP receive task. WireGuard's rule for
//! when to demand cookies is "under load", and the paper and kernel WireGuard decide load by how
//! many handshake messages are waiting, not by how many one address sent. This module gives the
//! receive task that queue, so the backlog is something it can count:
//!
//! - [`HandshakeBacklog::offer`] takes every received WireGuard message. Data and cookie replies
//!   come straight back to be processed at once. A handshake initiation or response with a valid
//!   MAC1 is copied into the queue (its packet buffer goes back to the pool) and the caller moves
//!   on; one with a bad MAC1, or one that finds the queue full, is dropped.
//! - [`HandshakeBacklog::serve`] hands queued messages back, oldest first, for at most
//!   [`SERVE_BUDGET`] per receive turn, after the turn's data. Before each one it reports the
//!   number waiting to the [`RateLimiter`], which is then under load at
//!   [`UNDER_LOAD_BACKLOG`] or more, and for one second after.
//!
//! Why this measures real backlog: a receive turn reads up to a socket batch (64 or 100
//! datagrams) but serves only about a millisecond of handshakes, so when handshakes arrive faster
//! than the task completes them, they pile up here instead of in the socket buffer, where the
//! task could not count them. When the task keeps up, the queue empties every turn, so a burst of
//! responses to our own initiations (a node restart with a thousand peers behind one NAT) is
//! served without a cookie. Before this, 100 messages per source address per second meant load,
//! and the other 900 such peers waited five seconds for their retry (J1077 table B).
//!
//! This relies on the receiver handing over everything already waiting, up to its batch, in one
//! call: Linux's `recvmmsg` socket does, and on other systems the device puts a
//! `BufferedUdpReceive` (batches of 64) in front of the socket. A receiver that returns one
//! datagram per call (the trait's default, used by test channels) never shows a backlog, so the
//! device behind it is never under load.
//!
//! Data first, with a bounded handshake share, also keeps a handshake storm from stalling every
//! peer's packets: a turn used to run a whole batch of key agreements (64 × ~100 µs) before the
//! next datagram.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use zerocopy::IntoBytes;

use crate::noise::rate_limiter::RateLimiter;
use crate::packet::{Packet, PacketBufPool, WgHandshakeInit, WgKind};

/// How many handshake messages the queue holds; past it new ones are dropped.
///
/// wireguard-go's handshake queue size. Every entry is a copy of at most one initiation (148
/// bytes) plus its source, so a full queue is about 180 KiB and holds no packet buffers. A
/// legitimate initiator whose message is dropped retries after five seconds, as after a loss.
pub(crate) const HANDSHAKE_BACKLOG_CAPACITY: usize = 1024;

/// Waiting handshake messages at which the device is under load: an eighth of the queue.
///
/// The ratio kernel WireGuard and wireguard-go use. At about 100 µs per initiation that is about
/// 13 ms of key agreement waiting in this one task, beyond which a flood should cost its senders
/// a cookie round trip. `GOTATUN_BENCH_HANDSHAKE_BACKLOG` overrides it for measurements.
pub(crate) fn under_load_backlog() -> u64 {
    static LIMIT: OnceLock<u64> = OnceLock::new();
    *LIMIT.get_or_init(|| {
        crate::diag::capacity(
            "GOTATUN_BENCH_HANDSHAKE_BACKLOG",
            UNDER_LOAD_BACKLOG as usize,
        ) as u64
    })
}

/// The default of [`under_load_backlog`].
pub(crate) const UNDER_LOAD_BACKLOG: u64 = (HANDSHAKE_BACKLOG_CAPACITY / 8) as u64;

/// How long one receive turn may spend serving queued handshakes before it reads the socket
/// again.
///
/// About ten initiations, or hundreds of cookie replies under load. It must stay well below what
/// a socket batch brings in (see the module doc), or the backlog would wait in the socket where
/// it cannot be counted, and short enough that data waits at most this long behind handshakes.
pub(crate) const SERVE_BUDGET: Duration = Duration::from_millis(1);

/// One queued handshake message: its bytes and where it came from.
struct Queued {
    /// Large enough for an initiation; a response uses the first 92 bytes.
    bytes: [u8; WgHandshakeInit::LEN],
    len: u8,
    source: SocketAddr,
}

/// The receive task's handshake queue; see the module doc.
#[derive(Default)]
pub(crate) struct HandshakeBacklog {
    queue: VecDeque<Queued>,
    /// When the current turn started serving, if it has.
    serving_since: Option<Instant>,
    /// Messages dropped because the queue was full, for the rate-limited warning.
    dropped: u64,
}

impl HandshakeBacklog {
    /// An empty queue. It allocates on the first handshake, not here.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Whether no handshake message is waiting.
    pub(crate) fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Take one received message: data and cookie replies come back to be processed now; a
    /// handshake message is queued (valid MAC1) or dropped (bad MAC1, or a full queue), and
    /// `None` comes back.
    pub(crate) fn offer(
        &mut self,
        message: WgKind,
        source: SocketAddr,
        rate_limiter: &RateLimiter,
    ) -> Option<WgKind> {
        match message {
            WgKind::HandshakeInit(init) => {
                if rate_limiter.mac1_valid(&init) {
                    self.push((*init).as_bytes(), source, rate_limiter);
                }
                None
            }
            WgKind::HandshakeResp(resp) => {
                if rate_limiter.mac1_valid(&resp) {
                    self.push((*resp).as_bytes(), source, rate_limiter);
                }
                None
            }
            other => Some(other),
        }
    }

    /// Queue one MAC1-valid handshake message, or drop it when the queue is full.
    fn push(&mut self, message: &[u8], source: SocketAddr, rate_limiter: &RateLimiter) {
        if self.queue.len() >= HANDSHAKE_BACKLOG_CAPACITY {
            // A full queue is load by any measure; say so even if nothing is served this turn.
            rate_limiter.note_handshake_backlog(self.queue.len());
            self.dropped += 1;
            if self.dropped.is_power_of_two() {
                tracing::warn!(
                    "Handshake queue full: dropped {} handshake messages so far",
                    self.dropped
                );
            }
            return;
        }
        let mut bytes = [0; WgHandshakeInit::LEN];
        bytes[..message.len()].copy_from_slice(message);
        self.queue.push_back(Queued {
            bytes,
            len: u8::try_from(message.len()).expect("a handshake message is under 256 bytes"),
            source,
        });
    }

    /// Start a new receive turn: the next [`serve`](Self::serve) starts a fresh budget.
    pub(crate) fn start_turn(&mut self) {
        self.serving_since = None;
    }

    /// The oldest waiting message, rebuilt in a pool buffer, or `None` when the queue is empty
    /// or this turn's [`SERVE_BUDGET`] is spent.
    ///
    /// Reports the backlog (counting this message) to `rate_limiter` first, so the caller's
    /// `verify_packet` decides cookie or not on the queue as it is now.
    pub(crate) fn serve(
        &mut self,
        pool: &mut PacketBufPool,
        rate_limiter: &RateLimiter,
    ) -> Option<(Packet, SocketAddr)> {
        if self.queue.is_empty() {
            return None;
        }
        let now = Instant::now();
        let since = *self.serving_since.get_or_insert(now);
        if now.duration_since(since) >= SERVE_BUDGET {
            return None;
        }
        rate_limiter.note_handshake_backlog(self.queue.len());
        let queued = self.queue.pop_front()?;
        let mut packet = pool.get();
        packet.buf_mut().clear();
        packet
            .buf_mut()
            .extend_from_slice(&queued.bytes[..usize::from(queued.len)]);
        Some((packet, queued.source))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::index_table::IndexTable;
    use crate::noise::{Tunn, TunnResult};
    use crate::x25519;
    use std::sync::Arc;

    /// A responder's rate limiter at the device's threshold, and an initiator that targets it.
    fn pair() -> (RateLimiter, Tunn) {
        let responder = x25519::StaticSecret::random_from_rng(rand_core::OsRng);
        let responder_public = x25519::PublicKey::from(&responder);
        let initiator = x25519::StaticSecret::random_from_rng(rand_core::OsRng);
        let initiator_public = x25519::PublicKey::from(&initiator);
        let tunn = Tunn::new(
            initiator,
            responder_public,
            None,
            None,
            IndexTable::from_os_rng(),
            Arc::new(RateLimiter::new(&initiator_public, UNDER_LOAD_BACKLOG)),
        );
        (
            RateLimiter::new(&responder_public, UNDER_LOAD_BACKLOG),
            tunn,
        )
    }

    fn initiation(tunn: &mut Tunn) -> WgKind {
        WgKind::HandshakeInit(
            tunn.format_handshake_initiation(true)
                .expect("a forced initiation"),
        )
    }

    fn source() -> SocketAddr {
        "192.0.2.7:51820".parse().unwrap()
    }

    /// Serve every waiting message regardless of the per-turn budget, and count cookies.
    fn serve_all(
        backlog: &mut HandshakeBacklog,
        pool: &mut PacketBufPool,
        limiter: &RateLimiter,
    ) -> (usize, usize) {
        let (mut accepted, mut cookies) = (0, 0);
        loop {
            backlog.start_turn();
            let Some((packet, from)) = backlog.serve(pool, limiter) else {
                break;
            };
            match limiter.verify_packet(from, packet) {
                Ok(WgKind::HandshakeInit(_)) => accepted += 1,
                Err(TunnResult::WriteToNetwork(WgKind::CookieReply(_))) => cookies += 1,
                other => panic!("unexpected verdict {}", other.is_ok()),
            }
        }
        (accepted, cookies)
    }

    /// J1077 table B, reduced: many messages from one address that the task keeps up with
    /// (never more than a few waiting) draw no cookie however many there are. The old per-source
    /// count sent cookies from the 101st on.
    #[test]
    fn a_burst_the_task_keeps_up_with_draws_no_cookie() {
        let (limiter, mut tunn) = pair();
        let mut backlog = HandshakeBacklog::new();
        let mut pool = PacketBufPool::new_lazy(64);
        let mut total = (0, 0);
        for _ in 0..1_000 {
            for _ in 0..4 {
                assert!(
                    backlog
                        .offer(initiation(&mut tunn), source(), &limiter)
                        .is_none()
                );
            }
            let (accepted, cookies) = serve_all(&mut backlog, &mut pool, &limiter);
            total = (total.0 + accepted, total.1 + cookies);
        }
        assert_eq!(total, (4_000, 0));
        assert!(!limiter.is_under_load());
    }

    /// A backlog of an eighth of the queue puts the device under load: from then on a message
    /// without MAC2 is answered with a cookie, initiations from every source alike.
    #[test]
    fn a_backlog_at_the_threshold_demands_cookies() {
        let (limiter, mut tunn) = pair();
        let mut backlog = HandshakeBacklog::new();
        let mut pool = PacketBufPool::new_lazy(64);
        for _ in 0..UNDER_LOAD_BACKLOG {
            backlog.offer(initiation(&mut tunn), source(), &limiter);
        }
        assert_eq!(backlog.queue.len(), UNDER_LOAD_BACKLOG as usize);
        let (accepted, cookies) = serve_all(&mut backlog, &mut pool, &limiter);
        assert_eq!((accepted, cookies), (0, UNDER_LOAD_BACKLOG as usize));
        assert!(limiter.is_under_load(), "the hold outlasts the backlog");
    }

    /// One below the threshold is not load.
    #[test]
    fn a_backlog_below_the_threshold_is_not_load() {
        let (limiter, mut tunn) = pair();
        let mut backlog = HandshakeBacklog::new();
        let mut pool = PacketBufPool::new_lazy(64);
        for _ in 0..UNDER_LOAD_BACKLOG - 1 {
            backlog.offer(initiation(&mut tunn), source(), &limiter);
        }
        let (accepted, cookies) = serve_all(&mut backlog, &mut pool, &limiter);
        assert_eq!((accepted, cookies), (UNDER_LOAD_BACKLOG as usize - 1, 0));
    }

    /// Forged messages (bad MAC1) never take a place in the queue, and a full queue drops new
    /// messages and counts as load.
    #[test]
    fn bad_mac1_is_never_queued_and_a_full_queue_drops() {
        let (limiter, mut tunn) = pair();
        let mut backlog = HandshakeBacklog::new();
        let WgKind::HandshakeInit(mut forged) = initiation(&mut tunn) else {
            unreachable!()
        };
        forged.mac1[0] ^= 1;
        backlog.offer(WgKind::HandshakeInit(forged), source(), &limiter);
        assert!(backlog.is_empty());

        for _ in 0..HANDSHAKE_BACKLOG_CAPACITY + 10 {
            backlog.offer(initiation(&mut tunn), source(), &limiter);
        }
        assert_eq!(backlog.queue.len(), HANDSHAKE_BACKLOG_CAPACITY);
        assert_eq!(backlog.dropped, 10);
        assert!(limiter.is_under_load());
    }

    /// One turn serves for at most [`SERVE_BUDGET`]; the next turn starts a new budget.
    #[test]
    fn a_turn_stops_serving_when_its_budget_is_spent() {
        let (limiter, mut tunn) = pair();
        let mut backlog = HandshakeBacklog::new();
        let mut pool = PacketBufPool::new_lazy(64);
        for _ in 0..3 {
            backlog.offer(initiation(&mut tunn), source(), &limiter);
        }
        backlog.start_turn();
        assert!(backlog.serve(&mut pool, &limiter).is_some());
        // sleep: the budget is wall-clock time; this spends it without serving.
        std::thread::sleep(SERVE_BUDGET + Duration::from_millis(1));
        assert!(backlog.serve(&mut pool, &limiter).is_none());
        assert_eq!(backlog.queue.len(), 2);
        backlog.start_turn();
        assert!(backlog.serve(&mut pool, &limiter).is_some());
    }

    /// Data and cookie replies are not handshake work: they come straight back.
    #[test]
    fn other_messages_pass_through() {
        let (limiter, _tunn) = pair();
        let mut backlog = HandshakeBacklog::new();
        let cookie = limiter.format_cookie_reply(1, [0; 16], &[0; 16]);
        let pool: PacketBufPool = PacketBufPool::new_lazy(1);
        let mut packet = pool.get();
        packet.buf_mut().clear();
        packet.buf_mut().extend_from_slice(cookie.as_bytes());
        let kind = packet.try_into_wg().unwrap();
        assert!(matches!(
            backlog.offer(kind, source(), &limiter),
            Some(WgKind::CookieReply(_))
        ));
        assert!(backlog.is_empty());
    }
}
