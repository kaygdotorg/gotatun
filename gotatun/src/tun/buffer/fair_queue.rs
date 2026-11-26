// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

//! Bounded two-level DRR for authenticated packets waiting to enter the TUN.
//!
//! One TUN writer owns this queue. It shares service between peers, then between each peer's
//! inner IP flows, while each flow keeps a FIFO. Packet payloads move through a fixed slot pool;
//! admitting another packet to a flow that already exists does not allocate. The queue has
//! per-flow, per-peer, and endpoint byte limits, and it blocks on no timer while idle. It runs
//! after authentication at the shared TUN boundary; its opaque peer key can be carried earlier
//! by a future ingress arbiter without making this scheduler depend on decryption internals.

use std::collections::{HashMap, VecDeque};

use tokio::sync::OwnedSemaphorePermit;
use zerocopy::IntoBytes;

use crate::{packet::Ip, packet::Packet, packet_hash::PacketHash};

const DEFAULT_FLOW_QUANTUM_BYTES: usize = 64 * 1024;
const DEFAULT_MAX_BATCH_PACKETS: usize = 64;
const DEFAULT_MAX_TOTAL_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_MAX_PEER_BYTES: usize = 512 * 1024;
const DEFAULT_MAX_FLOW_BYTES: usize = 256 * 1024;
const DEFAULT_MAX_FLOWS_PER_PEER: usize = 256;

/// The packet-classification key used by the fair queue.
///
/// A key contains the inner addresses, protocol, and transport ports when they are present. A
/// fragment uses its datagram identifier instead of ports, and protocols without ports share a
/// conservative address-and-protocol queue. Keeping the full tuple avoids turning hash collisions
/// into flow collisions; the containing map still uses a per-process keyed hasher.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct FlowKey {
    family: u8,
    protocol: u8,
    source: [u8; 16],
    destination: [u8; 16],
    source_port: u16,
    destination_port: u16,
    discriminator: u32,
}

impl FlowKey {
    /// A shared queue for flows that exceed the bounded flow-state inventory of one peer.
    const OVERFLOW: Self = Self {
        family: 0,
        protocol: 0,
        source: [0; 16],
        destination: [0; 16],
        source_port: 0,
        destination_port: 0,
        discriminator: u32::MAX,
    };

    /// Classify a validated IP packet without copying its payload or allocating temporary data.
    fn from_bytes(bytes: &[u8]) -> Self {
        match bytes.first().map(|byte| byte >> 4) {
            Some(4) => Self::ipv4(bytes),
            Some(6) => Self::ipv6(bytes),
            _ => Self::fallback(bytes),
        }
    }

    /// Classify IPv4 TCP, UDP, ICMP, fragments, and packets without transport ports.
    fn ipv4(bytes: &[u8]) -> Self {
        if bytes.len() < 20 {
            return Self::fallback(bytes);
        }
        let header_len = usize::from(bytes[0] & 0x0f) * 4;
        if header_len < 20 || bytes.len() < header_len {
            return Self::fallback(bytes);
        }

        let mut key = Self::base(4, bytes[9], &bytes[12..16], &bytes[16..20]);
        let fragment = u16::from_be_bytes([bytes[6], bytes[7]]);
        if fragment & 0x3fff != 0 {
            key.discriminator = u32::from_be_bytes([0, 0, bytes[4], bytes[5]]).saturating_add(1);
            return key;
        }

        Self::set_transport_key(&mut key, bytes, header_len);
        key
    }

    /// Classify IPv6 TCP, UDP, ICMPv6, fragments, and bounded extension-header chains.
    fn ipv6(bytes: &[u8]) -> Self {
        if bytes.len() < 40 {
            return Self::fallback(bytes);
        }
        let mut key = Self::base(6, bytes[6], &bytes[8..24], &bytes[24..40]);
        let mut next_header = bytes[6];
        let mut offset = 40_usize;

        // A valid packet may carry several extension headers. Bound the walk so unusual or
        // malformed chains fall back to their network-layer key instead of delaying the writer.
        for _ in 0..8 {
            match next_header {
                0 | 43 | 60 | 135 => {
                    if bytes.len().saturating_sub(offset) < 2 {
                        return key;
                    }
                    let length = (usize::from(bytes[offset + 1]) + 1) * 8;
                    if bytes.len().saturating_sub(offset) < length {
                        return key;
                    }
                    next_header = bytes[offset];
                    offset += length;
                }
                44 => {
                    if bytes.len().saturating_sub(offset) < 8 {
                        return key;
                    }
                    key.protocol = bytes[offset];
                    key.discriminator = u32::from_be_bytes([
                        bytes[offset + 4],
                        bytes[offset + 5],
                        bytes[offset + 6],
                        bytes[offset + 7],
                    ])
                    .saturating_add(1);
                    return key;
                }
                51 => {
                    if bytes.len().saturating_sub(offset) < 2 {
                        return key;
                    }
                    let length = (usize::from(bytes[offset + 1]) + 2) * 4;
                    if bytes.len().saturating_sub(offset) < length {
                        return key;
                    }
                    next_header = bytes[offset];
                    offset += length;
                }
                _ => break,
            }
        }

        // If the chain exceeds the bounded walk, do not interpret another extension header as
        // transport data. Keep packets in the network-layer queue until a later packet has a
        // chain the classifier can fully understand.
        if matches!(next_header, 0 | 43 | 44 | 51 | 60 | 135) {
            return key;
        }
        key.protocol = next_header;
        Self::set_transport_key(&mut key, bytes, offset);
        key
    }

    /// Add ports or an ICMP identifier when a complete transport prefix is present.
    fn set_transport_key(key: &mut Self, bytes: &[u8], offset: usize) {
        if bytes.len().saturating_sub(offset) < 4 {
            return;
        }
        match key.protocol {
            6 | 17 => {
                key.source_port = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
                key.destination_port = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]);
            }
            1 | 58 if bytes.len().saturating_sub(offset) >= 8 => {
                key.source_port = u16::from_be_bytes([bytes[offset + 4], bytes[offset + 5]]);
                key.destination_port = u16::from(bytes[offset])
                    .wrapping_shl(8)
                    .wrapping_add(u16::from(bytes[offset + 1]));
                key.discriminator = 2;
            }
            _ => {}
        }
    }

    /// Build the common address-and-protocol part of a flow key.
    fn base(family: u8, protocol: u8, source: &[u8], destination: &[u8]) -> Self {
        let mut key = Self {
            family,
            protocol,
            source: [0; 16],
            destination: [0; 16],
            source_port: 0,
            destination_port: 0,
            discriminator: 0,
        };
        if family == 4 {
            key.source[12..].copy_from_slice(source);
            key.destination[12..].copy_from_slice(destination);
        } else if source.len() == 16 && destination.len() == 16 {
            key.source.copy_from_slice(source);
            key.destination.copy_from_slice(destination);
        }
        key
    }

    /// Return a stable fallback key for bytes that do not contain a complete IP header.
    fn fallback(bytes: &[u8]) -> Self {
        let mut key = Self::OVERFLOW;
        key.discriminator = 0;
        if let Some(version) = bytes.first().map(|byte| byte >> 4) {
            key.family = version;
            key.protocol = match version {
                4 if bytes.len() > 9 => bytes[9],
                6 if bytes.len() > 6 => bytes[6],
                _ => 0,
            };
        }
        key
    }

    /// Report whether this is the per-peer overflow queue key rather than an IP flow.
    fn is_overflow(self) -> bool {
        self == Self::OVERFLOW
    }
}

/// One FIFO of packets for a peer's inner flow.
#[derive(Default)]
struct FlowQueue {
    head: Option<usize>,
    tail: Option<usize>,
    queued_bytes: usize,
    deficit: usize,
    turn_open: bool,
}

/// Peer state and the active-flow round used by the second DRR level.
struct PeerQueue {
    flows: HashMap<FlowKey, FlowQueue, PacketHash>,
    active_flows: VecDeque<FlowKey>,
    queued_bytes: usize,
    deficit: usize,
    active: bool,
    turn_open: bool,
}

impl Default for PeerQueue {
    /// Create empty peer state with independently seeded flow hashing.
    fn default() -> Self {
        Self {
            flows: HashMap::default(),
            active_flows: VecDeque::new(),
            queued_bytes: 0,
            deficit: 0,
            active: false,
            turn_open: false,
        }
    }
}

/// One preallocated node that owns a queued packet and its bounded-buffer permit.
struct PacketSlot {
    packet: Option<Packet<Ip>>,
    permit: Option<OwnedSemaphorePermit>,
    next: Option<usize>,
    bytes: usize,
}

impl PacketSlot {
    /// Create an unused packet slot.
    fn empty() -> Self {
        Self {
            packet: None,
            permit: None,
            next: None,
            bytes: 0,
        }
    }
}

/// Bounds for scheduler memory and the byte service granted per peer and flow.
#[derive(Clone, Copy)]
struct FairQueueLimits {
    max_total_bytes: usize,
    max_peer_bytes: usize,
    max_flow_bytes: usize,
    max_peer_states: usize,
    max_flow_states: usize,
    max_flows_per_peer: usize,
    quantum_bytes: usize,
    max_batch_packets: usize,
}

impl FairQueueLimits {
    /// Choose conservative fixed defaults and a state inventory that matches the packet pool.
    fn for_capacity(capacity: usize) -> Self {
        Self {
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            max_peer_bytes: DEFAULT_MAX_PEER_BYTES,
            max_flow_bytes: DEFAULT_MAX_FLOW_BYTES,
            max_peer_states: capacity.max(1),
            max_flow_states: capacity.saturating_mul(2).max(256),
            max_flows_per_peer: DEFAULT_MAX_FLOWS_PER_PEER,
            quantum_bytes: DEFAULT_FLOW_QUANTUM_BYTES,
            max_batch_packets: DEFAULT_MAX_BATCH_PACKETS,
        }
    }
}

/// A packet scheduler shared by every authenticated peer on one device.
///
/// Packet nodes are allocated once from `capacity`; flow state is retained between bursts and
/// pruned only when a bounded inventory needs room for a new key. An overfull queue drops its
/// newest packet, so one peer cannot block admission for every other peer.
pub(super) struct FairQueue {
    slots: Vec<PacketSlot>,
    free: Vec<usize>,
    peers: HashMap<u64, PeerQueue, PacketHash>,
    active_peers: VecDeque<u64>,
    queued_bytes: usize,
    queued_packets: usize,
    flow_states: usize,
    limits: FairQueueLimits,
}

impl FairQueue {
    /// Allocate the fixed packet-slot pool and initialize an empty two-level DRR scheduler.
    pub(super) fn new(capacity: usize) -> Self {
        assert!(
            capacity > 0,
            "the fair queue needs at least one packet slot"
        );
        let limits = FairQueueLimits::for_capacity(capacity);
        let slots = (0..capacity).map(|_| PacketSlot::empty()).collect();
        let free = (0..capacity).rev().collect();
        Self {
            slots,
            free,
            peers: HashMap::default(),
            active_peers: VecDeque::with_capacity(capacity),
            queued_bytes: 0,
            queued_packets: 0,
            flow_states: 0,
            limits,
        }
    }

    /// Report whether at least one packet is waiting for TUN service.
    pub(super) fn is_empty(&self) -> bool {
        self.queued_packets == 0
    }

    /// Move a peer's run into fixed packet slots and release permits for rejected packets.
    ///
    /// A full peer or flow queue drops its newest packet. The count returned is useful for one
    /// aggregated warning rather than one log record per dropped packet.
    pub(super) fn enqueue_run(
        &mut self,
        peer_key: u64,
        packets: Vec<Packet<Ip>>,
        mut permit: OwnedSemaphorePermit,
    ) -> usize {
        debug_assert_eq!(permit.num_permits(), packets.len());
        let mut dropped = 0;
        for packet in packets {
            let packet_permit = permit
                .split(1)
                .expect("each packet run owns one permit per packet");
            if !self.enqueue_one(peer_key, packet, packet_permit) {
                dropped += 1;
            }
        }
        drop(permit);
        dropped
    }

    /// Add one packet to its bounded peer and flow FIFOs without allocating a packet node.
    fn enqueue_one(
        &mut self,
        peer_key: u64,
        packet: Packet<Ip>,
        permit: OwnedSemaphorePermit,
    ) -> bool {
        let bytes = packet.as_bytes().len();
        if bytes == 0
            || self.free.is_empty()
            || self.queued_bytes.saturating_add(bytes) > self.limits.max_total_bytes
        {
            return false;
        }
        if self.peers.get(&peer_key).is_some_and(|peer| {
            peer.queued_bytes.saturating_add(bytes) > self.limits.max_peer_bytes
        }) {
            return false;
        }
        if !self.ensure_peer(peer_key) {
            return false;
        }

        let flow_key = classify_packet(packet.as_bytes());
        let Some(flow_key) = self.ensure_flow(peer_key, flow_key) else {
            return false;
        };
        let Some(flow) = self
            .peers
            .get(&peer_key)
            .and_then(|peer| peer.flows.get(&flow_key))
        else {
            return false;
        };
        if flow.queued_bytes.saturating_add(bytes) > self.limits.max_flow_bytes {
            return false;
        }

        let slot_index = self.free.pop().expect("the packet slot was checked above");
        self.slots[slot_index] = PacketSlot {
            packet: Some(packet),
            permit: Some(permit),
            next: None,
            bytes,
        };

        let (flow_was_empty, peer_was_idle, old_tail) = {
            let peer = self
                .peers
                .get_mut(&peer_key)
                .expect("the peer state was installed above");
            let flow = peer
                .flows
                .get_mut(&flow_key)
                .expect("the flow state was installed above");
            let old_tail = flow.tail;
            let flow_was_empty = flow.head.is_none();
            let peer_was_idle = !peer.active;
            flow.tail = Some(slot_index);
            flow.queued_bytes += bytes;
            peer.queued_bytes += bytes;
            peer.active = true;
            (flow_was_empty, peer_was_idle, old_tail)
        };
        if let Some(tail) = old_tail {
            self.slots[tail].next = Some(slot_index);
        } else {
            self.peers
                .get_mut(&peer_key)
                .and_then(|peer| peer.flows.get_mut(&flow_key))
                .expect("the flow state remains installed")
                .head = Some(slot_index);
        }
        if flow_was_empty {
            self.peers
                .get_mut(&peer_key)
                .expect("the peer state remains installed")
                .active_flows
                .push_back(flow_key);
        }
        if peer_was_idle {
            self.active_peers.push_back(peer_key);
        }
        self.queued_bytes += bytes;
        self.queued_packets += 1;
        true
    }

    /// Ensure the peer map has room, evicting cached idle peers before refusing admission.
    fn ensure_peer(&mut self, peer_key: u64) -> bool {
        if self.peers.contains_key(&peer_key) {
            return true;
        }
        if self.peers.len() >= self.limits.max_peer_states {
            let mut remaining = self
                .peers
                .len()
                .saturating_sub(self.limits.max_peer_states)
                .saturating_add(1);
            let mut removed_flows = 0;
            self.peers.retain(|_, peer| {
                if !peer.active && remaining > 0 {
                    remaining -= 1;
                    removed_flows += peer.flows.len();
                    false
                } else {
                    true
                }
            });
            self.flow_states = self.flow_states.saturating_sub(removed_flows);
        }
        if self.peers.len() >= self.limits.max_peer_states {
            return false;
        }
        self.peers.insert(peer_key, PeerQueue::default());
        true
    }

    /// Return an existing flow key or install a bounded flow state for a new tuple.
    fn ensure_flow(&mut self, peer_key: u64, flow_key: FlowKey) -> Option<FlowKey> {
        if self
            .peers
            .get(&peer_key)
            .is_some_and(|peer| peer.flows.contains_key(&flow_key))
        {
            return Some(flow_key);
        }

        // Keep one slot for the shared overflow queue so a busy peer cannot add state past the
        // configured per-peer cap by opening many distinct tuples.
        let peer_flow_limit = self.limits.max_flows_per_peer.max(1);
        let tracked_flow_limit = peer_flow_limit.saturating_sub(1);
        if self
            .peers
            .get(&peer_key)
            .is_some_and(|peer| peer.flows.len() >= tracked_flow_limit)
        {
            self.prune_peer_flows(peer_key);
        }
        if self.flow_states >= self.limits.max_flow_states {
            self.prune_idle_flows();
        }

        let peer_has_room = self
            .peers
            .get(&peer_key)
            .is_some_and(|peer| peer.flows.len() < tracked_flow_limit);
        if peer_has_room && self.flow_states < self.limits.max_flow_states {
            self.peers
                .get_mut(&peer_key)
                .expect("the peer state was installed above")
                .flows
                .insert(flow_key, FlowQueue::default());
            self.flow_states += 1;
            return Some(flow_key);
        }

        if self
            .peers
            .get(&peer_key)
            .is_some_and(|peer| peer.flows.contains_key(&FlowKey::OVERFLOW))
        {
            return Some(FlowKey::OVERFLOW);
        }
        if self
            .peers
            .get(&peer_key)
            .is_some_and(|peer| peer.flows.len() >= peer_flow_limit)
        {
            return None;
        }
        if self.flow_states >= self.limits.max_flow_states {
            self.prune_idle_flows();
        }
        if self.flow_states >= self.limits.max_flow_states {
            return None;
        }
        self.peers
            .get_mut(&peer_key)
            .expect("the peer state was installed above")
            .flows
            .insert(FlowKey::OVERFLOW, FlowQueue::default());
        self.flow_states += 1;
        Some(FlowKey::OVERFLOW)
    }

    /// Remove idle flow keys from one peer when its cached flow inventory is full.
    fn prune_peer_flows(&mut self, peer_key: u64) {
        let removed = if let Some(peer) = self.peers.get_mut(&peer_key) {
            let before = peer.flows.len();
            peer.flows
                .retain(|key, flow| key.is_overflow() || flow.head.is_some());
            before - peer.flows.len()
        } else {
            0
        };
        self.flow_states = self.flow_states.saturating_sub(removed);
    }

    /// Remove idle flow keys across peers when the endpoint inventory is full.
    fn prune_idle_flows(&mut self) {
        let mut removed = 0;
        for peer in self.peers.values_mut() {
            peer.flows.retain(|key, flow| {
                let keep = key.is_overflow() || flow.head.is_some();
                if !keep {
                    removed += 1;
                }
                keep
            });
            if self.flow_states.saturating_sub(removed) < self.limits.max_flow_states {
                break;
            }
        }
        self.flow_states = self.flow_states.saturating_sub(removed);
    }

    /// Take one peer-flow DRR quantum into reusable vectors for the TUN writer.
    pub(super) fn dequeue_batch(
        &mut self,
        packets: &mut Vec<Packet<Ip>>,
        permits: &mut Vec<OwnedSemaphorePermit>,
    ) -> bool {
        packets.clear();
        permits.clear();
        let Some(peer_key) = self.active_peers.front().copied() else {
            return false;
        };
        let Some(flow_key) = self
            .peers
            .get(&peer_key)
            .and_then(|peer| peer.active_flows.front().copied())
        else {
            self.active_peers.pop_front();
            if let Some(peer) = self.peers.get_mut(&peer_key) {
                peer.active = false;
                peer.deficit = 0;
                peer.turn_open = false;
            }
            return false;
        };

        {
            let peer = self
                .peers
                .get_mut(&peer_key)
                .expect("the active peer has queue state");
            if !peer.turn_open {
                peer.deficit = peer.deficit.saturating_add(self.limits.quantum_bytes);
                peer.turn_open = true;
            }
            let flow = peer
                .flows
                .get_mut(&flow_key)
                .expect("the active flow has queue state");
            if !flow.turn_open {
                flow.deficit = flow.deficit.saturating_add(self.limits.quantum_bytes);
                flow.turn_open = true;
            }
        }

        loop {
            if packets.len() >= self.limits.max_batch_packets {
                break;
            }
            let Some(slot_index) = self
                .peers
                .get(&peer_key)
                .and_then(|peer| peer.flows.get(&flow_key))
                .and_then(|flow| flow.head)
            else {
                break;
            };
            let bytes = self.slots[slot_index].bytes;
            let Some(peer) = self.peers.get(&peer_key) else {
                break;
            };
            let Some(flow) = peer.flows.get(&flow_key) else {
                break;
            };
            let peer_deficit_short = bytes > peer.deficit;
            let flow_deficit_short = bytes > flow.deficit;
            if (peer_deficit_short || flow_deficit_short) && !packets.is_empty() {
                break;
            }
            if peer_deficit_short {
                // The byte quantum should normally be at least as large as the device MTU, but
                // a legal large IP packet must still leave this bounded scheduler.
                self.peers
                    .get_mut(&peer_key)
                    .expect("the active peer remains installed")
                    .deficit = bytes;
            }
            if flow_deficit_short {
                self.peers
                    .get_mut(&peer_key)
                    .and_then(|peer| peer.flows.get_mut(&flow_key))
                    .expect("the active flow remains installed")
                    .deficit = bytes;
            }
            let Some((packet, permit)) = self.pop_front(peer_key, flow_key) else {
                break;
            };
            let peer = self
                .peers
                .get_mut(&peer_key)
                .expect("the active peer remains installed");
            peer.deficit -= bytes;
            let flow = peer
                .flows
                .get_mut(&flow_key)
                .expect("the active flow remains installed");
            flow.deficit -= bytes;
            packets.push(packet);
            permits.push(permit);
        }

        let (flow_empty, flow_deficit, flow_next_bytes) = {
            let peer = self
                .peers
                .get(&peer_key)
                .expect("the active peer remains installed");
            let flow = peer
                .flows
                .get(&flow_key)
                .expect("the active flow remains installed");
            let flow_next_bytes = flow.head.map(|slot| self.slots[slot].bytes).unwrap_or(0);
            (flow.head.is_none(), flow.deficit, flow_next_bytes)
        };
        if flow_empty {
            self.peers
                .get_mut(&peer_key)
                .expect("the active peer remains installed")
                .active_flows
                .pop_front();
            if let Some(flow) = self
                .peers
                .get_mut(&peer_key)
                .and_then(|peer| peer.flows.get_mut(&flow_key))
            {
                flow.deficit = 0;
                flow.turn_open = false;
            }
        } else if flow_deficit == 0 || flow_deficit < flow_next_bytes {
            if let Some(flow) = self
                .peers
                .get_mut(&peer_key)
                .and_then(|peer| peer.flows.get_mut(&flow_key))
            {
                flow.turn_open = false;
            }
            self.rotate_active_flow(peer_key);
        }

        let (peer_empty, peer_deficit, peer_next_bytes) = {
            let peer = self
                .peers
                .get(&peer_key)
                .expect("the active peer remains installed");
            let next_bytes = peer
                .active_flows
                .front()
                .and_then(|key| peer.flows.get(key))
                .and_then(|flow| flow.head)
                .map(|slot| self.slots[slot].bytes)
                .unwrap_or(0);
            (peer.active_flows.is_empty(), peer.deficit, next_bytes)
        };
        if peer_empty {
            self.active_peers.pop_front();
            if let Some(peer) = self.peers.get_mut(&peer_key) {
                peer.active = false;
                peer.deficit = 0;
                peer.turn_open = false;
            }
        } else if peer_deficit == 0 || peer_deficit < peer_next_bytes {
            if let Some(peer) = self.peers.get_mut(&peer_key) {
                peer.turn_open = false;
            }
            self.active_peers.rotate_left(1);
        }
        !packets.is_empty()
    }

    /// Move the selected active flow to the back of its peer's round.
    fn rotate_active_flow(&mut self, peer_key: u64) {
        if let Some(peer) = self.peers.get_mut(&peer_key) {
            peer.active_flows.rotate_left(1);
        }
    }

    /// Remove one packet from a flow and return its packet buffer and permit to the caller.
    fn pop_front(
        &mut self,
        peer_key: u64,
        flow_key: FlowKey,
    ) -> Option<(Packet<Ip>, OwnedSemaphorePermit)> {
        let slot_index = self.peers.get(&peer_key)?.flows.get(&flow_key)?.head?;
        let bytes = self.slots[slot_index].bytes;
        let next = self.slots[slot_index].next;
        let packet = self.slots[slot_index].packet.take()?;
        let permit = self.slots[slot_index].permit.take()?;
        self.slots[slot_index].next = None;
        self.slots[slot_index].bytes = 0;
        self.free.push(slot_index);

        let peer = self.peers.get_mut(&peer_key)?;
        let flow = peer.flows.get_mut(&flow_key)?;
        flow.head = next;
        if next.is_none() {
            flow.tail = None;
        }
        flow.queued_bytes -= bytes;
        peer.queued_bytes -= bytes;
        self.queued_bytes -= bytes;
        self.queued_packets -= 1;
        Some((packet, permit))
    }
}

/// Create one unambiguous tuple key for IPv4 and IPv6 packets.
fn classify_packet(bytes: &[u8]) -> FlowKey {
    FlowKey::from_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, sync::Arc};

    use bytes::BytesMut;
    use tokio::sync::{OwnedSemaphorePermit, Semaphore};
    use zerocopy::IntoBytes;

    use crate::packet::{Ip, Packet};

    use super::{FairQueue, FairQueueLimits, FlowKey};

    /// Build an IPv4 UDP packet whose identification can vary without changing its flow.
    fn udp_packet(id: u16, source_port: u16, destination_port: u16, len: usize) -> Packet<Ip> {
        let len = len.max(28);
        let mut bytes = BytesMut::zeroed(len);
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        bytes[4..6].copy_from_slice(&id.to_be_bytes());
        bytes[9] = 17;
        bytes[12..16].copy_from_slice(&Ipv4Addr::new(10, 0, 0, 1).octets());
        bytes[16..20].copy_from_slice(&Ipv4Addr::new(10, 0, 0, 2).octets());
        bytes[20..22].copy_from_slice(&source_port.to_be_bytes());
        bytes[22..24].copy_from_slice(&destination_port.to_be_bytes());
        Packet::from_bytes(bytes)
            .try_into_ip()
            .expect("valid IPv4 header")
    }

    /// Return test limits with independent caps that fit the requested fixed packet pool.
    fn limits(capacity: usize) -> FairQueueLimits {
        FairQueueLimits {
            max_total_bytes: 1024 * 1024,
            max_peer_bytes: 512 * 1024,
            max_flow_bytes: 256 * 1024,
            max_peer_states: capacity.max(1),
            max_flow_states: capacity.saturating_mul(2).max(1),
            max_flows_per_peer: 256,
            quantum_bytes: 64 * 1024,
            max_batch_packets: 64,
        }
    }

    /// Acquire one owned permit for each packet in a run.
    async fn run_permit(count: usize) -> OwnedSemaphorePermit {
        let semaphore = Arc::new(Semaphore::new(count));
        semaphore
            .acquire_many_owned(count as u32)
            .await
            .expect("the test semaphore has enough permits")
    }

    /// Move a packet run into the queue and return the number rejected by a configured bound.
    async fn enqueue(queue: &mut FairQueue, peer: u64, packets: Vec<Packet<Ip>>) -> usize {
        let permit = run_permit(packets.len()).await;
        queue.enqueue_run(peer, packets, permit)
    }

    /// Read the IPv4 identification from a scheduled packet for ordering assertions.
    fn packet_id(packet: &Packet<Ip>) -> u16 {
        u16::from_be_bytes([packet.as_bytes()[4], packet.as_bytes()[5]])
    }

    /// Small test queues can set byte caps without allocating production-sized traffic.
    #[test]
    fn ipv4_flow_uses_the_full_tuple_and_ignores_identification() {
        let first = udp_packet(1, 1200, 443, 64);
        let same_flow = udp_packet(2, 1200, 443, 64);
        let other_flow = udp_packet(3, 1201, 443, 64);

        assert_eq!(
            FlowKey::from_bytes(first.as_bytes()),
            FlowKey::from_bytes(same_flow.as_bytes())
        );
        assert_ne!(
            FlowKey::from_bytes(first.as_bytes()),
            FlowKey::from_bytes(other_flow.as_bytes())
        );
    }

    /// IPv4 fragments with one datagram identifier stay in one FIFO even without transport ports.
    #[test]
    fn ipv4_fragments_share_their_datagram_key() {
        let mut first = udp_packet(7, 1200, 443, 64);
        let mut later = udp_packet(7, 0, 0, 64);
        let first_bytes = zerocopy::IntoBytes::as_mut_bytes(&mut *first);
        let later_bytes = zerocopy::IntoBytes::as_mut_bytes(&mut *later);
        first_bytes[6..8].copy_from_slice(&0x2000_u16.to_be_bytes());
        later_bytes[6..8].copy_from_slice(&1_u16.to_be_bytes());

        assert_eq!(
            FlowKey::from_bytes(first.as_bytes()),
            FlowKey::from_bytes(later.as_bytes())
        );
    }

    /// IPv6 UDP keys use the complete address and transport tuple.
    #[test]
    fn ipv6_flow_uses_the_transport_tuple() {
        /// Build an IPv6 UDP packet with the requested transport ports.
        fn ipv6_udp(source_port: u16, destination_port: u16) -> Packet<Ip> {
            let mut bytes = BytesMut::zeroed(48);
            bytes[0] = 0x60;
            bytes[4..6].copy_from_slice(&8_u16.to_be_bytes());
            bytes[6] = 17;
            bytes[8] = 0x20;
            bytes[23] = 1;
            bytes[24] = 0x20;
            bytes[39] = 2;
            bytes[40..42].copy_from_slice(&source_port.to_be_bytes());
            bytes[42..44].copy_from_slice(&destination_port.to_be_bytes());
            Packet::from_bytes(bytes)
                .try_into_ip()
                .expect("valid IPv6 UDP header")
        }

        let first = ipv6_udp(1200, 443);
        let same_flow = ipv6_udp(1200, 443);
        let other_flow = ipv6_udp(1201, 443);
        assert_eq!(
            FlowKey::from_bytes(first.as_bytes()),
            FlowKey::from_bytes(same_flow.as_bytes())
        );
        assert_ne!(
            FlowKey::from_bytes(first.as_bytes()),
            FlowKey::from_bytes(other_flow.as_bytes())
        );
    }

    /// More than eight IPv6 extension headers conservatively share their network-layer key.
    #[test]
    fn ipv6_extension_walk_stops_before_treating_an_extension_as_transport() {
        /// Build an IPv6 packet with nine destination-options headers and TCP ports.
        fn ipv6_with_long_extension_chain(source_port: u16, destination_port: u16) -> Packet<Ip> {
            let mut bytes = BytesMut::zeroed(40 + 9 * 8 + 20);
            bytes[0] = 0x60;
            let payload_len = (bytes.len() - 40) as u16;
            bytes[4..6].copy_from_slice(&payload_len.to_be_bytes());
            bytes[6] = 60;
            bytes[8] = 0x20;
            bytes[23] = 1;
            bytes[24] = 0x20;
            bytes[39] = 2;
            for index in 0..9 {
                let offset = 40 + index * 8;
                bytes[offset] = if index == 8 { 6 } else { 60 };
                bytes[offset + 1] = 0;
            }
            bytes[112..114].copy_from_slice(&source_port.to_be_bytes());
            bytes[114..116].copy_from_slice(&destination_port.to_be_bytes());
            Packet::from_bytes(bytes)
                .try_into_ip()
                .expect("valid IPv6 extension headers")
        }

        let first = ipv6_with_long_extension_chain(1200, 443);
        let other_transport_tuple = ipv6_with_long_extension_chain(1201, 8443);
        assert_eq!(
            FlowKey::from_bytes(first.as_bytes()),
            FlowKey::from_bytes(other_transport_tuple.as_bytes())
        );
    }

    /// DRR gives one flow a bounded run before another flow while preserving each FIFO's order.
    #[tokio::test]
    async fn inner_flows_take_turns_without_reordering_their_packets() {
        let mut queue = FairQueue {
            limits: limits(256),
            ..FairQueue::new(256)
        };
        let first_flow = (0..100).map(|id| udp_packet(id, 1200, 443, 1400)).collect();
        let second_flow = (1000..1100)
            .map(|id| udp_packet(id, 1201, 443, 1400))
            .collect();
        assert_eq!(enqueue(&mut queue, 9, first_flow).await, 0);
        assert_eq!(enqueue(&mut queue, 9, second_flow).await, 0);

        let mut packets = Vec::with_capacity(64);
        let mut permits = Vec::with_capacity(64);
        assert!(queue.dequeue_batch(&mut packets, &mut permits));
        let first: Vec<_> = packets.iter().map(packet_id).collect();
        assert_eq!(first.first().copied(), Some(0));
        assert_eq!(first.last().copied(), Some(first.len() as u16 - 1));
        packets.clear();
        permits.clear();

        assert!(queue.dequeue_batch(&mut packets, &mut permits));
        let second: Vec<_> = packets.iter().map(packet_id).collect();
        assert_eq!(second.first().copied(), Some(1000));
        assert_eq!(second.last().copied(), Some(1000 + second.len() as u16 - 1));
        packets.clear();
        permits.clear();

        assert!(queue.dequeue_batch(&mut packets, &mut permits));
        assert_eq!(packet_id(&packets[0]), first.len() as u16);
    }

    /// The outer round rotates to another peer after one equal byte quantum.
    #[tokio::test]
    async fn peers_take_turns_before_one_peer_can_fill_the_writer() {
        let mut queue = FairQueue {
            limits: limits(256),
            ..FairQueue::new(256)
        };
        assert_eq!(
            enqueue(
                &mut queue,
                1,
                (0..100).map(|id| udp_packet(id, 1200, 443, 1400)).collect(),
            )
            .await,
            0
        );
        assert_eq!(
            enqueue(
                &mut queue,
                2,
                (1000..1100)
                    .map(|id| udp_packet(id, 1200, 443, 1400))
                    .collect(),
            )
            .await,
            0
        );

        let mut packets = Vec::with_capacity(64);
        let mut permits = Vec::with_capacity(64);
        assert!(queue.dequeue_batch(&mut packets, &mut permits));
        assert_eq!(packet_id(&packets[0]), 0);
        packets.clear();
        permits.clear();
        assert!(queue.dequeue_batch(&mut packets, &mut permits));
        assert_eq!(packet_id(&packets[0]), 1000);
    }

    /// The newest packet is rejected when its flow, peer, or endpoint byte budget is full.
    #[tokio::test]
    async fn flow_and_peer_limits_drop_newest_without_growing_the_slot_pool() {
        let mut limits = limits(8);
        limits.max_total_bytes = 1024;
        limits.max_peer_bytes = 250;
        limits.max_flow_bytes = 150;
        let mut queue = FairQueue {
            limits,
            ..FairQueue::new(8)
        };
        let capacity = queue.slots.capacity();
        assert_eq!(
            enqueue(
                &mut queue,
                3,
                vec![
                    udp_packet(1, 1200, 443, 100),
                    udp_packet(2, 1200, 443, 100),
                    udp_packet(3, 1200, 443, 100),
                ],
            )
            .await,
            2
        );
        assert_eq!(queue.queued_bytes, 100);
        assert_eq!(queue.slots.capacity(), capacity);
    }

    /// A packet already in the overflow flow keeps the per-peer state inventory bounded.
    #[tokio::test]
    async fn excess_flow_keys_share_one_bounded_peer_queue() {
        let mut limits = limits(8);
        limits.max_flows_per_peer = 1;
        let mut queue = FairQueue {
            limits,
            ..FairQueue::new(8)
        };
        assert_eq!(
            enqueue(
                &mut queue,
                4,
                vec![udp_packet(1, 1200, 443, 64), udp_packet(2, 1201, 443, 64)],
            )
            .await,
            0
        );
        let peer = queue.peers.get(&4).expect("the peer state is retained");
        assert!(peer.flows.contains_key(&FlowKey::OVERFLOW));
        assert_eq!(peer.flows.len(), 1);
    }
}
