// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

//! Small data datagrams leave from a second UDP socket, so they get their own `fq` flow
//! (#260, J1159).
//!
//! **Why.** Every datagram GotaTun sends to a peer has the same 5-tuple, so a flow-fair qdisc
//! (`fq`, `fq_codel`) on the sending host queues a probe, a pure ACK or a keystroke behind all of
//! our own bulk to that peer. J1140 measured it on a CPU-bound virtio pairing: a separate 200 B
//! UDP flow waited p50 0.35 ms in eth0's `fq` under full-speed load, while GotaTun's own probe
//! waited 1.5–4 ms there. Replies-first (`priority`) already moves those datagrams to
//! the front of our own queues; this module moves them into their own kernel flow too.
//!
//! **What moves.** Only WireGuard *data* messages whose encrypted length is above a keepalive
//! (32 B) and at most `priority::REPLY_MAX`: the datagrams replies-first's `tx` lane
//! already picks, minus handshakes, cookies and keepalives. Those stay on the main socket, so the
//! peer's view of our endpoint, NAT refresh by keepalives and handshake roaming are unchanged.
//!
//! **The mark.** The sender sets [`MARK`] in reserved header byte [`MARK_OFFSET`] of a datagram
//! it sends from the side socket. The data header (type, reserved bytes, receiver index, counter)
//! is not authenticated by the AEAD, so the mark is free to set and clear after encryption.
//! GotaTun's parser looks only at the type byte, so it accepts a marked datagram. Stock WireGuard
//! implementations read the first four bytes as one little-endian type and *drop* a marked
//! datagram, which is why a peer must opt in (`PeerMut::set_side_port`).
//!
//! **The receiver does not roam on a marked datagram.** A marked data packet that decrypts is
//! delivered, but it moves neither the peer's endpoint nor its confirmed endpoint (see
//! `PeerState::complete_incoming_data`), so the peer keeps sending to our main port. An on-path
//! attacker that flips the mark can only stop a packet from moving the endpoint, which it can
//! already do by dropping the packet; one that clears the mark makes the peer roam to our side
//! port, which an on-path attacker can already do by rewriting the source address.
//!
//! **When the side socket is used.** Only while the main socket sent bulk (a datagram larger
//! than `priority::REPLY_MAX`) to the same destination within [`BULK_RECENT`]
//! ([`BulkRecency`]). Then our own bulk keeps the main NAT mapping fresh, and there is a flow to
//! compete with. With no bulk, everything leaves through the main socket exactly as before, so
//! keepalive timers, NAT mappings and roaming behave as with one socket. The side socket's NAT
//! mapping never needs inbound traffic: nothing is ever sent to it.
//!
//! Switch (bench, until the embedding application sets it per peer): `GOTATUN_SIDE_SOCKET=1`
//! binds the side socket and opts every peer in. Unset, `0` or anything else leaves it off.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::OnceLock,
    time::{Duration, Instant},
};

/// Index of the reserved header byte that carries the mark (the first byte after the type).
pub(crate) const MARK_OFFSET: usize = 1;

/// The mark value. Any non-zero value would do; a stock sender always writes zero.
pub(crate) const MARK: u8 = 0x01;

/// WireGuard's data message type, the only one ever marked.
const DATA_TYPE: u8 = 4;

/// Encrypted length of a keepalive (16 B header + 16 B tag, no payload): never marked.
const KEEPALIVE_LEN: usize = 32;

/// Largest encrypted datagram that may leave from the side socket. It equals
/// `priority::REPLY_MAX` (a test checks), so the side socket carries a subset of what
/// replies-first's `tx` lane carries; it is repeated here because the receive side (`noise`)
/// is built without the `device` feature too.
pub(crate) const MAX_LEN: usize = 256;

/// How long after the last bulk datagram to a destination its small datagrams still use the
/// side socket. One second is far below any NAT timeout and far above the gaps inside a bulk
/// transfer, so the side flow does not flap during a transfer.
pub(crate) const BULK_RECENT: Duration = Duration::from_secs(1);

/// Whether the bench switch `GOTATUN_SIDE_SOCKET=1` is set, read once.
pub(crate) fn wanted() -> bool {
    static WANTED: OnceLock<bool> = OnceLock::new();
    *WANTED.get_or_init(|| {
        let on = std::env::var("GOTATUN_SIDE_SOCKET").is_ok_and(|v| v.trim() == "1");
        if on {
            eprintln!("diag side_socket on");
        }
        on
    })
}

/// Whether an encrypted datagram may leave from the side socket: a data message with a payload
/// (not a keepalive) of at most [`MAX_LEN`] bytes.
pub(crate) fn eligible(datagram: &[u8]) -> bool {
    datagram.first() == Some(&DATA_TYPE)
        && datagram.len() > KEEPALIVE_LEN
        && datagram.len() <= MAX_LEN
}

/// Whether `datagram` carries the side mark.
#[inline]
pub(crate) fn is_marked(datagram: &[u8]) -> bool {
    datagram.get(MARK_OFFSET) == Some(&MARK)
}

/// Set the side mark on an eligible datagram (see [`eligible`]); others are left alone.
#[inline]
pub(crate) fn mark(datagram: &mut [u8]) {
    if eligible(datagram) {
        datagram[MARK_OFFSET] = MARK;
    }
}

/// Clear the side mark, so a datagram that leaves through the main socket roams as usual.
#[inline]
pub(crate) fn clear(datagram: &mut [u8]) {
    if let Some(byte) = datagram.get_mut(MARK_OFFSET) {
        *byte = 0;
    }
}

/// Remembers when the main socket last sent bulk to each destination (see the module docs).
///
/// Owned by the UDP send task alone, so it needs no lock. Bulk runs record one timestamp per run,
/// not per datagram. Entries older than [`BULK_RECENT`] are pruned once the map grows past
/// [`BulkRecency::PRUNE_AT`], so it stays as small as the set of peers with live bulk.
#[derive(Default)]
pub(crate) struct BulkRecency {
    last_bulk: HashMap<SocketAddr, Instant>,
}

impl BulkRecency {
    /// Prune stale entries when the map holds more destinations than this.
    const PRUNE_AT: usize = 64;

    /// Record that bulk to `destination` just left through the main socket.
    pub(crate) fn bulk_sent(&mut self, destination: SocketAddr, now: Instant) {
        if self.last_bulk.len() >= Self::PRUNE_AT && !self.last_bulk.contains_key(&destination) {
            self.last_bulk
                .retain(|_, at| now.saturating_duration_since(*at) < BULK_RECENT);
        }
        self.last_bulk.insert(destination, now);
    }

    /// Whether bulk to `destination` left within [`BULK_RECENT`] of `now`.
    pub(crate) fn recent(&self, destination: &SocketAddr, now: Instant) -> bool {
        self.last_bulk
            .get(destination)
            .is_some_and(|at| now.saturating_duration_since(*at) < BULK_RECENT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(len: usize) -> Vec<u8> {
        let mut d = vec![0u8; len];
        d[0] = DATA_TYPE;
        d
    }

    #[test]
    fn only_small_data_with_a_payload_is_eligible() {
        assert!(!eligible(&data(32)), "keepalive stays on the main socket");
        assert!(eligible(&data(48)), "smallest data with a payload");
        assert!(eligible(&data(MAX_LEN)));
        assert!(!eligible(&data(MAX_LEN + 1)), "bulk");
        let mut init = vec![0u8; 148];
        init[0] = 1;
        assert!(!eligible(&init), "handshake initiation");
        let mut cookie = vec![0u8; 64];
        cookie[0] = 3;
        assert!(!eligible(&cookie), "cookie reply");
        assert!(!eligible(&[]));
    }

    #[cfg(feature = "device")]
    #[test]
    fn the_side_socket_carries_a_subset_of_the_reply_lane() {
        assert_eq!(MAX_LEN, crate::priority::REPLY_MAX);
    }

    #[test]
    fn mark_and_clear_touch_only_the_reserved_byte() {
        let mut d = data(80);
        d[2] = 0xaa;
        mark(&mut d);
        assert!(is_marked(&d));
        assert_eq!((d[0], d[2]), (DATA_TYPE, 0xaa));
        clear(&mut d);
        assert!(!is_marked(&d));
        assert_eq!(d, {
            let mut e = data(80);
            e[2] = 0xaa;
            e
        });

        let mut keepalive = data(32);
        mark(&mut keepalive);
        assert!(
            !is_marked(&keepalive),
            "an ineligible datagram is never marked"
        );
    }

    #[test]
    fn bulk_recency_expires_and_prunes() {
        let t0 = Instant::now();
        let a: SocketAddr = "10.0.0.1:51820".parse().unwrap();
        let b: SocketAddr = "10.0.0.2:51820".parse().unwrap();
        let mut r = BulkRecency::default();
        assert!(!r.recent(&a, t0), "no bulk yet");
        r.bulk_sent(a, t0);
        assert!(r.recent(&a, t0 + Duration::from_millis(999)));
        assert!(!r.recent(&a, t0 + BULK_RECENT), "expired after a second");
        assert!(!r.recent(&b, t0), "per destination");

        for port in 0..BulkRecency::PRUNE_AT as u16 {
            r.bulk_sent(SocketAddr::from(([10, 0, 1, 1], port)), t0);
        }
        let later = t0 + BULK_RECENT * 2;
        r.bulk_sent(b, later);
        assert_eq!(r.last_bulk.len(), 1, "stale destinations were pruned");
        assert!(r.recent(&b, later));
    }
}
