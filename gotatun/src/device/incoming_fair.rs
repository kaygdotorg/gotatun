// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//   Copyright (c) Mullvad VPN AB. All rights reserved.
//
// SPDX-License-Identifier: MPL-2.0

//! Bounded deficit round robin for packets awaiting per-peer receive crypto.
//!
//! The receive task identifies a peer from the live WireGuard receiver index, then places its
//! unverified data packet here before AEAD work. The peer key is only a scheduling identity: it
//! grants no authentication, endpoint update, or delivery privilege. Unknown indices never make
//! queue state. Each peer keeps FIFO order, the queue bounds packets and bytes, and an idle queue
//! owns no timer or worker that could wake the device.

use std::collections::{HashMap, VecDeque};

use crate::packet_hash::PacketHash;

/// Per-datagram charge for parse, lookup, and fixed crypto setup alongside packet bytes.
pub(super) const DATAGRAM_WORK_BYTES: usize = 256;

/// Byte credit given to each active peer when its DRR turn begins.
const PEER_QUANTUM_BYTES: usize = 4 * 1024;

/// Maximum unverified datagrams retained across all peers.
const MAX_QUEUED_PACKETS: usize = 512;

/// Maximum charged bytes retained across all peers.
const MAX_QUEUED_BYTES: usize = 512 * 1024;

/// Maximum unverified datagrams retained for one peer before the receive task schedules work.
const MAX_PEER_PACKETS: usize = 16;

/// Keep one per-peer slot available for a packet from a candidate roaming endpoint.
const MAX_CONFIRMED_PEER_PACKETS: usize = MAX_PEER_PACKETS - 1;

/// Allow one roaming candidate per peer to be tested without letting source churn allocate lanes.
const MAX_ROAMING_PEER_PACKETS: usize = 1;

/// Maximum charged bytes retained for one peer, including room for a single jumbo UDP datagram.
const MAX_CONFIRMED_PEER_BYTES: usize = 128 * 1024;

/// Maximum charged bytes retained for the single candidate roaming datagram.
const MAX_ROAMING_PEER_BYTES: usize = u16::MAX as usize + DATAGRAM_WORK_BYTES;

/// Maximum total charged bytes held for any one peer across both endpoint classes.
const MAX_PEER_BYTES: usize = MAX_CONFIRMED_PEER_BYTES + MAX_ROAMING_PEER_BYTES;

/// One packet waiting for its peer's decryption turn and the work it consumes from that turn.
struct Queued<T> {
    /// Charged packet bytes plus the fixed per-datagram cost.
    cost: usize,
    /// Whether the source differed from the last known endpoint or could not be checked promptly.
    roaming_hint: bool,
    /// The packet and metadata that remain tied to this peer until crypto dispatch.
    value: T,
}

/// One active peer's FIFO and its byte credit for deficit round robin.
struct PeerQueue<T> {
    /// Packets keep their receive order within a peer.
    packets: VecDeque<Queued<T>>,
    /// Bytes currently waiting for this peer's turn.
    bytes: usize,
    /// Confirmed-endpoint packets currently waiting for service.
    confirmed_packets: usize,
    /// Candidate roaming packets currently waiting for service.
    roaming_packets: usize,
    /// Charged bytes for confirmed-endpoint packets.
    confirmed_bytes: usize,
    /// Charged bytes for candidate roaming packets.
    roaming_bytes: usize,
    /// Work this peer may still spend before yielding to the next active peer.
    deficit: usize,
    /// Whether this peer is still spending the quantum granted at its current DRR turn.
    turn_open: bool,
}

impl<T> Default for PeerQueue<T> {
    fn default() -> Self {
        Self {
            packets: VecDeque::new(),
            bytes: 0,
            confirmed_packets: 0,
            roaming_packets: 0,
            confirmed_bytes: 0,
            roaming_bytes: 0,
            deficit: 0,
            turn_open: false,
        }
    }
}

/// A bounded, work-conserving DRR queue keyed by the configured peer handle.
///
/// The caller owns authentication and delivery. This type only decides which already-classified
/// peer receives the next bounded share of pre-decryption work.
pub(super) struct IncomingFairQueue<T> {
    /// Per-peer FIFO state, present only while that peer has queued packets.
    peers: HashMap<usize, PeerQueue<T>, PacketHash>,
    /// Active peers in DRR order. A peer stays at the front while it has byte credit left.
    active: VecDeque<usize>,
    /// Total waiting datagrams across all peers.
    packets: usize,
    /// Total charged bytes across all peers.
    bytes: usize,
}

impl<T> Default for IncomingFairQueue<T> {
    fn default() -> Self {
        Self {
            peers: HashMap::default(),
            active: VecDeque::new(),
            packets: 0,
            bytes: 0,
        }
    }
}

impl<T> IncomingFairQueue<T> {
    /// Create an empty scheduler without starting a task or allocating per-peer state.
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// Whether no peer has unverified packets waiting for a decryption turn.
    pub(super) fn is_empty(&self) -> bool {
        self.packets == 0
    }

    /// The total number of queued packets, for bounded service decisions and tests.
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.packets
    }

    /// Number of queued packets for one peer, for bounded control ordering and tests.
    pub(super) fn peer_len(&self, peer_key: usize) -> usize {
        self.peers
            .get(&peer_key)
            .map_or(0, |peer| peer.packets.len())
    }

    /// Whether a packet can use its confirmed-endpoint or reserved roaming share.
    fn can_push_class(&self, peer_key: usize, cost: usize, roaming_hint: bool) -> bool {
        if self.packets >= MAX_QUEUED_PACKETS
            || self.bytes.saturating_add(cost) > MAX_QUEUED_BYTES
            || self.peer_len(peer_key) >= MAX_PEER_PACKETS
        {
            return false;
        }
        let (packet_limit, byte_limit) = if roaming_hint {
            (MAX_ROAMING_PEER_PACKETS, MAX_ROAMING_PEER_BYTES)
        } else {
            (MAX_CONFIRMED_PEER_PACKETS, MAX_CONFIRMED_PEER_BYTES)
        };
        match self.peers.get(&peer_key) {
            Some(peer) => {
                peer.bytes.saturating_add(cost) <= MAX_PEER_BYTES
                    && if roaming_hint {
                        peer.roaming_packets < packet_limit
                            && peer.roaming_bytes.saturating_add(cost) <= byte_limit
                    } else {
                        peer.confirmed_packets < packet_limit
                            && peer.confirmed_bytes.saturating_add(cost) <= byte_limit
                    }
            }
            None => cost <= byte_limit,
        }
    }

    /// Add one unverified packet, or return it unchanged when a queue bound is full.
    pub(super) fn try_push(
        &mut self,
        peer_key: usize,
        cost: usize,
        roaming_hint: bool,
        value: T,
    ) -> Result<(), T> {
        if !self.can_push_class(peer_key, cost, roaming_hint) {
            return Err(value);
        }
        let peer = self.peers.entry(peer_key).or_default();
        if peer.packets.is_empty() {
            self.active.push_back(peer_key);
        }
        peer.bytes += cost;
        if roaming_hint {
            peer.roaming_packets += 1;
            peer.roaming_bytes += cost;
        } else {
            peer.confirmed_packets += 1;
            peer.confirmed_bytes += cost;
        }
        peer.packets.push_back(Queued {
            cost,
            roaming_hint,
            value,
        });
        self.packets += 1;
        self.bytes += cost;
        Ok(())
    }

    /// Take the next packet in DRR order, granting one quantum per visit to each peer.
    ///
    /// A peer can use the rest of its quantum over several calls. If its next packet needs more
    /// than one quantum, the deficit carries across visits. If it is the only active peer, it keeps
    /// receiving turns until the packet fits, so a sole sender never waits for another peer.
    pub(super) fn pop_next(&mut self) -> Option<(usize, T)> {
        loop {
            let peer_key = *self.active.front()?;
            let peer = self.peers.get_mut(&peer_key)?;
            let next_cost = peer.packets.front()?.cost;
            if !peer.turn_open {
                peer.deficit = peer.deficit.saturating_add(PEER_QUANTUM_BYTES);
                peer.turn_open = true;
            }
            if peer.deficit >= next_cost {
                peer.deficit -= next_cost;
                let queued = peer
                    .packets
                    .pop_front()
                    .expect("the front packet was checked");
                peer.bytes -= queued.cost;
                if queued.roaming_hint {
                    peer.roaming_packets -= 1;
                    peer.roaming_bytes -= queued.cost;
                } else {
                    peer.confirmed_packets -= 1;
                    peer.confirmed_bytes -= queued.cost;
                }
                self.packets -= 1;
                self.bytes -= queued.cost;
                if peer.packets.is_empty() {
                    self.active.pop_front();
                    self.peers.remove(&peer_key);
                } else if peer
                    .packets
                    .front()
                    .is_some_and(|next| next.cost > peer.deficit)
                {
                    peer.turn_open = false;
                    self.active.rotate_left(1);
                }
                return Some((peer_key, queued.value));
            }
            peer.turn_open = false;
            self.active.rotate_left(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Make a queue small enough to exercise its public admission behavior without packet data.
    fn filled_queue() -> IncomingFairQueue<u8> {
        let mut queue = IncomingFairQueue::new();
        for value in 0..MAX_CONFIRMED_PEER_PACKETS as u8 {
            queue
                .try_push(1, 1, false, value)
                .expect("the confirmed endpoint has room");
        }
        queue
            .try_push(1, 1, true, MAX_CONFIRMED_PEER_PACKETS as u8)
            .expect("the reserved roaming slot has room");
        queue
    }

    /// A single backlogged peer gets all available service without waiting for another peer.
    #[test]
    fn one_active_peer_is_work_conserving() {
        let mut queue = IncomingFairQueue::new();
        for value in 0..100_u8 {
            queue
                .try_push(1, 1500, false, value)
                .expect("queue bounds fit this test");
            assert_eq!(queue.pop_next(), Some((1, value)));
        }
        assert!(queue.is_empty());
    }

    /// A continuously busy peer yields after spending one quantum and before it receives another.
    #[test]
    fn a_busy_peer_yields_after_its_quantum() {
        let mut queue = IncomingFairQueue::new();
        for value in 0..8_u8 {
            queue
                .try_push(1, 1500, false, value)
                .expect("peer one has room");
        }
        queue
            .try_push(2, 1500, false, 99)
            .expect("peer two has room");

        assert_eq!(queue.pop_next(), Some((1, 0)));
        assert_eq!(queue.pop_next(), Some((1, 1)));
        assert_eq!(queue.pop_next(), Some((2, 99)));
        assert_eq!(queue.peer_len(1), 6);
    }

    /// Queue capacity is enforced without creating state for the rejected peer.
    #[test]
    fn bounds_reject_without_allocating_a_new_peer_queue() {
        let mut queue = filled_queue();
        assert_eq!(queue.peer_len(1), MAX_PEER_PACKETS);
        assert_eq!(queue.try_push(1, 1, false, 99), Err(99));
        assert_eq!(queue.try_push(1, 1, true, 101), Err(101));
        assert_eq!(queue.try_push(2, MAX_QUEUED_BYTES, false, 100), Err(100));
        assert_eq!(queue.peer_len(2), 0);
    }

    /// A new peer cannot exceed its own byte limit before it has an allocated queue entry.
    #[test]
    fn first_packet_obeys_its_endpoint_class_byte_limit() {
        let mut queue = IncomingFairQueue::new();
        assert_eq!(
            queue.try_push(1, MAX_CONFIRMED_PEER_BYTES + 1, false, 1),
            Err(1)
        );
        assert_eq!(
            queue.try_push(2, MAX_ROAMING_PEER_BYTES + 1, true, 2),
            Err(2)
        );
        assert!(queue.is_empty());
    }

    /// A new endpoint has one bounded admission reserved without reordering peer receive data.
    #[test]
    fn roaming_candidate_uses_reserved_slot_in_receive_order() {
        let mut queue = IncomingFairQueue::new();
        for value in 0..MAX_CONFIRMED_PEER_PACKETS as u8 {
            queue.try_push(1, 1500, false, value).unwrap();
        }
        queue
            .try_push(1, 1500, true, 99)
            .expect("roaming keeps one bounded route to authentication");
        assert_eq!(queue.try_push(1, 1500, true, 100), Err(100));
        assert_eq!(queue.try_push(1, 1500, false, 101), Err(101));

        for value in 0..MAX_CONFIRMED_PEER_PACKETS as u8 {
            assert_eq!(queue.pop_next(), Some((1, value)));
        }
        assert_eq!(queue.pop_next(), Some((1, 99)));
        assert!(queue.is_empty());
    }

    /// Preparing earlier data for a control packet still gives every active peer its DRR turn.
    #[test]
    fn control_order_drain_respects_drr_between_peers() {
        let mut queue = IncomingFairQueue::new();
        for value in 10..14 {
            queue.try_push(1, 1500, false, value).unwrap();
        }
        queue.try_push(2, 1500, false, 20).unwrap();

        let mut scheduled = Vec::new();
        while queue.peer_len(1) > 0 {
            scheduled.push(queue.pop_next().expect("peer one is still queued"));
        }
        assert_eq!(scheduled, [(1, 10), (1, 11), (2, 20), (1, 12), (1, 13)]);
    }
}
