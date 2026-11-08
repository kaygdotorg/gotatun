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

//! Fairly schedules a bounded batch of packets by peer and inner flow.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::packet::{Ip, Packet};
use zerocopy::IntoBytes;

#[derive(Debug, Eq, Hash, PartialEq)]
pub(super) struct FlowKey {
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    discriminator: FlowDiscriminator,
}

#[derive(Debug, Eq, Hash, PartialEq)]
enum FlowDiscriminator {
    Ports(u16, u16),
    Echo { kind: u8, code: u8, identifier: u16 },
    Fragment(u32),
    Network,
}

/// Identify an inner flow without depending on payload bytes or trusting packet lengths.
pub(super) fn packet_flow_key(packet: &Packet<Ip>) -> FlowKey {
    let bytes = packet.as_bytes();
    let version = bytes.first().map_or(0, |first| first >> 4);
    let unspecified = match version {
        6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        _ => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    };
    let source = packet.source().unwrap_or(unspecified);
    let destination = packet.destination().unwrap_or(unspecified);

    let (protocol, discriminator) = match version {
        4 => ipv4_flow_discriminator(bytes),
        6 => ipv6_flow_discriminator(bytes),
        _ => (0, FlowDiscriminator::Network),
    };

    FlowKey {
        source,
        destination,
        protocol,
        discriminator,
    }
}

fn ipv4_flow_discriminator(bytes: &[u8]) -> (u8, FlowDiscriminator) {
    let Some(header) = bytes.get(..20) else {
        return (0, FlowDiscriminator::Network);
    };
    let header_len = usize::from(header[0] & 0x0f) * 4;
    if header_len < 20 || bytes.len() < header_len {
        return (header[9], FlowDiscriminator::Network);
    }

    let protocol = header[9];
    let fragment = read_u16(bytes, 6).unwrap_or(0);
    if fragment & 0x3fff != 0 {
        return (
            protocol,
            FlowDiscriminator::Fragment(u32::from(read_u16(bytes, 4).unwrap_or(0))),
        );
    }

    (
        protocol,
        transport_discriminator(bytes, header_len, protocol),
    )
}

fn ipv6_flow_discriminator(bytes: &[u8]) -> (u8, FlowDiscriminator) {
    let Some(header) = bytes.get(..40) else {
        return (0, FlowDiscriminator::Network);
    };
    let mut protocol = header[6];
    let mut offset = 40;

    for _ in 0..8 {
        let extension_len = match protocol {
            // Hop-by-hop, routing, destination, mobility, HIP and Shim6 headers.
            0 | 43 | 60 | 135 | 139 | 140 => {
                let Some(length) = bytes.get(offset + 1).copied() else {
                    return (protocol, FlowDiscriminator::Network);
                };
                (usize::from(length) + 1) * 8
            }
            // Authentication header length is measured in 32-bit words, excluding two words.
            51 => {
                let Some(length) = bytes.get(offset + 1).copied() else {
                    return (protocol, FlowDiscriminator::Network);
                };
                (usize::from(length) + 2) * 4
            }
            44 => {
                let Some(fragment) = bytes.get(offset..offset + 8) else {
                    return (protocol, FlowDiscriminator::Network);
                };
                let next_protocol = fragment[0];
                let offset_and_flags = u16::from_be_bytes([fragment[2], fragment[3]]);
                let more_fragments = offset_and_flags & 1 != 0;
                let fragment_offset = offset_and_flags & 0xfff8 != 0;
                if more_fragments || fragment_offset {
                    let identifier =
                        u32::from_be_bytes([fragment[4], fragment[5], fragment[6], fragment[7]]);
                    return (next_protocol, FlowDiscriminator::Fragment(identifier));
                }
                protocol = next_protocol;
                offset += 8;
                continue;
            }
            _ => return (protocol, transport_discriminator(bytes, offset, protocol)),
        };

        let Some(extension) = bytes.get(offset..offset.saturating_add(extension_len)) else {
            return (protocol, FlowDiscriminator::Network);
        };
        protocol = extension[0];
        offset += extension_len;
    }

    (protocol, FlowDiscriminator::Network)
}

fn transport_discriminator(bytes: &[u8], offset: usize, protocol: u8) -> FlowDiscriminator {
    match protocol {
        6 | 17 => match (read_u16(bytes, offset), read_u16(bytes, offset + 2)) {
            (Some(source), Some(destination)) => FlowDiscriminator::Ports(source, destination),
            _ => FlowDiscriminator::Network,
        },
        1 | 58 => {
            let Some(kind) = bytes.get(offset).copied() else {
                return FlowDiscriminator::Network;
            };
            let Some(code) = bytes.get(offset + 1).copied() else {
                return FlowDiscriminator::Network;
            };
            let is_echo = matches!((protocol, kind), (1, 0 | 8) | (58, 128 | 129));
            if is_echo {
                read_u16(bytes, offset + 4).map_or(FlowDiscriminator::Network, |identifier| {
                    FlowDiscriminator::Echo {
                        kind,
                        code,
                        identifier,
                    }
                })
            } else {
                FlowDiscriminator::Network
            }
        }
        _ => FlowDiscriminator::Network,
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let bytes = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

/// Fairly order packets from one routed batch, retaining each route key's metadata with its packet.
///
/// The caller passes only packets from the current bounded receive batch. The function retains no
/// packets after returning, and stable FIFO order is preserved within each peer and inner flow.
pub(super) fn fair_schedule_routed_batch<P, M>(
    packets: impl IntoIterator<Item = (P, Packet<Ip>, M)>,
) -> Vec<(Packet<Ip>, M)>
where
    P: Eq + Hash,
{
    fair_schedule(packets.into_iter().map(|(peer, packet, metadata)| {
        let flow = packet_flow_key(&packet);
        (peer, flow, (packet, metadata))
    }))
}

struct FlowQueue<T> {
    packets: VecDeque<T>,
}

struct PeerQueue<T> {
    flows: Vec<FlowQueue<T>>,
    active_flows: VecDeque<usize>,
}

/// Return the batch in hierarchical round-robin order, keeping FIFO within each flow.
///
/// The caller supplies one already-bounded receive batch. This scheduler only moves its packets
/// between temporary per-flow queues; it never retains work across calls. A batch with one peer
/// and one flow is already in fair FIFO order and bypasses the keyed queue construction.
pub(super) fn fair_schedule<P, F, T>(packets: impl IntoIterator<Item = (P, F, T)>) -> Vec<T>
where
    P: Eq + Hash,
    F: Eq + Hash,
{
    let batch = packets.into_iter().collect::<Vec<_>>();
    let one_flow = batch.first().is_some_and(|(first_peer, first_flow, _)| {
        batch
            .iter()
            .all(|(peer, flow, _)| peer == first_peer && flow == first_flow)
    });
    if one_flow {
        return batch.into_iter().map(|(_, _, packet)| packet).collect();
    }

    let mut peers: Vec<PeerQueue<T>> = Vec::new();
    let mut peer_indices: HashMap<P, usize> = HashMap::new();
    let mut flow_indices: HashMap<(usize, F), usize> = HashMap::new();
    let mut packet_count = 0;

    for (peer, flow, packet) in batch {
        let peer_index = match peer_indices.entry(peer) {
            std::collections::hash_map::Entry::Occupied(entry) => *entry.get(),
            std::collections::hash_map::Entry::Vacant(entry) => {
                let index = peers.len();
                peers.push(PeerQueue {
                    flows: Vec::new(),
                    active_flows: VecDeque::new(),
                });
                entry.insert(index);
                index
            }
        };

        let flow_index = match flow_indices.entry((peer_index, flow)) {
            std::collections::hash_map::Entry::Occupied(entry) => *entry.get(),
            std::collections::hash_map::Entry::Vacant(entry) => {
                let index = peers[peer_index].flows.len();
                peers[peer_index].flows.push(FlowQueue {
                    packets: VecDeque::new(),
                });
                peers[peer_index].active_flows.push_back(index);
                entry.insert(index);
                index
            }
        };

        peers[peer_index].flows[flow_index]
            .packets
            .push_back(packet);
        packet_count += 1;
    }

    let mut active_peers: VecDeque<usize> = (0..peers.len()).collect();
    let mut scheduled = Vec::with_capacity(packet_count);
    while let Some(peer_index) = active_peers.pop_front() {
        let peer = &mut peers[peer_index];
        let flow_index = peer
            .active_flows
            .pop_front()
            .expect("active peer has an active flow");
        let has_more = {
            let flow = &mut peer.flows[flow_index];
            scheduled.push(
                flow.packets
                    .pop_front()
                    .expect("active flow has a queued packet"),
            );
            !flow.packets.is_empty()
        };

        if has_more {
            peer.active_flows.push_back(flow_index);
        }
        if !peer.active_flows.is_empty() {
            active_peers.push_back(peer_index);
        }
    }

    scheduled
}

#[cfg(test)]
mod tests {
    use super::{fair_schedule, fair_schedule_routed_batch, packet_flow_key};
    use crate::packet::{Ip, Packet};

    /// A sparse flow gets service between packets from one bulk flow.
    #[test]
    fn sparse_inner_flow_advances_before_bulk_fifo_is_exhausted() {
        let scheduled = fair_schedule([
            (1, 10, "bulk-0"),
            (1, 10, "bulk-1"),
            (1, 11, "probe-0"),
            (1, 10, "bulk-2"),
            (1, 11, "probe-1"),
        ]);

        assert_eq!(
            scheduled,
            ["bulk-0", "probe-0", "bulk-1", "probe-1", "bulk-2"]
        );
    }

    /// Peer turns are equal while each peer's flows retain their own FIFO order.
    #[test]
    fn peers_get_equal_turns_and_each_inner_flow_keeps_fifo() {
        let scheduled = fair_schedule([
            (1, 10, "peer-a-bulk-0"),
            (1, 10, "peer-a-bulk-1"),
            (1, 11, "peer-a-sparse-0"),
            (2, 20, "peer-b-0"),
            (2, 20, "peer-b-1"),
            (1, 10, "peer-a-bulk-2"),
            (1, 11, "peer-a-sparse-1"),
        ]);

        assert_eq!(
            scheduled,
            [
                "peer-a-bulk-0",
                "peer-b-0",
                "peer-a-sparse-0",
                "peer-b-1",
                "peer-a-bulk-1",
                "peer-a-sparse-1",
                "peer-a-bulk-2",
            ]
        );
    }

    /// A batch with only one active peer and flow keeps its original order.
    #[test]
    fn one_peer_and_flow_keeps_fifo_order() {
        let scheduled = fair_schedule([(1, 10, "first"), (1, 10, "second"), (1, 10, "third")]);

        assert_eq!(scheduled, ["first", "second", "third"]);
    }

    /// TCP packets in one five-tuple stay together, while another source port is a separate flow.
    #[test]
    fn tcp_flow_key_uses_ports_and_ignores_payload() {
        let first = packet_v4(6, 0, 0, &[0x13, 0x88, 0x01, 0xbb, 1]);
        let later = packet_v4(6, 0, 0, &[0x13, 0x88, 0x01, 0xbb, 2]);
        let other_port = packet_v4(6, 0, 0, &[0x13, 0x89, 0x01, 0xbb, 1]);

        assert_eq!(packet_flow_key(&first), packet_flow_key(&later));
        assert_ne!(packet_flow_key(&first), packet_flow_key(&other_port));
    }

    /// Echo sequence numbers vary per probe, but one echo identifier names the same probe flow.
    #[test]
    fn icmp_flow_key_uses_echo_identifier_and_ignores_sequence() {
        let first = packet_v4(1, 0, 0, &[8, 0, 0, 0, 0x12, 0x34, 0, 1]);
        let later = packet_v4(1, 0, 0, &[8, 0, 0, 0, 0x12, 0x34, 0, 2]);
        let other_identifier = packet_v4(1, 0, 0, &[8, 0, 0, 0, 0x12, 0x35, 0, 1]);

        assert_eq!(packet_flow_key(&first), packet_flow_key(&later));
        assert_ne!(packet_flow_key(&first), packet_flow_key(&other_identifier));
    }

    /// IPv6 transport keys are found after a bounded hop-by-hop extension header.
    #[test]
    fn ipv6_flow_key_walks_hop_by_hop_extension_headers() {
        let first = packet_v6_with_hop_by_hop(&[0x13, 0x88, 0x01, 0xbb, 1]);
        let later = packet_v6_with_hop_by_hop(&[0x13, 0x88, 0x01, 0xbb, 2]);
        let other_port = packet_v6_with_hop_by_hop(&[0x13, 0x89, 0x01, 0xbb, 1]);

        assert_eq!(packet_flow_key(&first), packet_flow_key(&later));
        assert_ne!(packet_flow_key(&first), packet_flow_key(&other_port));
    }

    /// All fragments of one IPv4 datagram stay in the same scheduling flow.
    #[test]
    fn fragmented_ipv4_packets_use_the_datagram_identifier() {
        let first_fragment = packet_v4(6, 0x2000, 0x2222, &[0x13, 0x88, 0x01, 0xbb]);
        let later_fragment = packet_v4(6, 0x0001, 0x2222, &[0xaa, 0xbb]);
        let other_datagram = packet_v4(6, 0x2000, 0x2223, &[0x13, 0x88, 0x01, 0xbb]);

        assert_eq!(
            packet_flow_key(&first_fragment),
            packet_flow_key(&later_fragment)
        );
        assert_ne!(
            packet_flow_key(&first_fragment),
            packet_flow_key(&other_datagram)
        );
    }

    /// A truncated transport header falls back to its network flow without panicking.
    #[test]
    fn truncated_transport_header_uses_network_flow_key() {
        let first = packet_v4(17, 0, 0, &[0x13, 0x88]);
        let second = packet_v4(17, 0, 0, &[0x13, 0x89]);

        assert_eq!(packet_flow_key(&first), packet_flow_key(&second));
    }

    /// One peer and one flow are already FIFO ordered, so their keys should not be hashed.
    #[test]
    fn one_peer_and_flow_bypasses_key_hashing() {
        let scheduled = fair_schedule([
            (HashForbidden, HashForbidden, "first"),
            (HashForbidden, HashForbidden, "second"),
            (HashForbidden, HashForbidden, "third"),
        ]);

        assert_eq!(scheduled, ["first", "second", "third"]);
    }

    /// A key that fails the test if a known single-flow batch reaches a hasher.
    #[derive(PartialEq, Eq)]
    struct HashForbidden;

    impl std::hash::Hash for HashForbidden {
        fn hash<H: std::hash::Hasher>(&self, _state: &mut H) {
            panic!("single-flow batches must bypass key hashing");
        }
    }

    /// A sparse ICMP probe advances between bulk TCP packets assigned to the same peer.
    #[test]
    fn sparse_probe_advances_between_same_peer_tcp_packets() {
        let scheduled = fair_schedule_routed_batch([
            (
                1,
                packet_v4(6, 0, 0, &[0x13, 0x88, 0x01, 0xbb, 1]),
                "bulk-0",
            ),
            (
                1,
                packet_v4(6, 0, 0, &[0x13, 0x88, 0x01, 0xbb, 2]),
                "bulk-1",
            ),
            (
                1,
                packet_v4(1, 0, 0, &[8, 0, 0, 0, 0x12, 0x34, 0, 1]),
                "probe-0",
            ),
            (
                1,
                packet_v4(6, 0, 0, &[0x13, 0x88, 0x01, 0xbb, 3]),
                "bulk-2",
            ),
            (
                1,
                packet_v4(1, 0, 0, &[8, 0, 0, 0, 0x12, 0x34, 0, 2]),
                "probe-1",
            ),
        ]);
        let labels = scheduled
            .into_iter()
            .map(|(_, label)| label)
            .collect::<Vec<_>>();

        assert_eq!(labels, ["bulk-0", "probe-0", "bulk-1", "probe-1", "bulk-2"]);
    }

    /// A routed batch preserves the peer key's turn order and keeps each route with its packet.
    #[test]
    fn routed_batch_keeps_peer_metadata_with_fairly_ordered_packets() {
        let scheduled = fair_schedule_routed_batch([
            (
                1,
                packet_v4(6, 0, 0, &[0x13, 0x88, 0x01, 0xbb, 1]),
                "a-bulk-0",
            ),
            (
                1,
                packet_v4(6, 0, 0, &[0x13, 0x88, 0x01, 0xbb, 2]),
                "a-bulk-1",
            ),
            (
                2,
                packet_v4(17, 0, 0, &[0x13, 0x89, 0x01, 0xbb, 1]),
                "b-only",
            ),
            (
                1,
                packet_v4(1, 0, 0, &[8, 0, 0, 0, 0x12, 0x34, 0, 1]),
                "a-probe",
            ),
        ]);

        assert_eq!(
            scheduled
                .iter()
                .map(|(_, label)| *label)
                .collect::<Vec<_>>(),
            ["a-bulk-0", "b-only", "a-probe", "a-bulk-1"]
        );
        for (packet, label) in scheduled {
            match label {
                "a-probe" => assert_eq!(packet_flow_key(&packet).protocol, 1),
                "b-only" => assert_eq!(packet_flow_key(&packet).protocol, 17),
                "a-bulk-0" | "a-bulk-1" => assert_eq!(packet_flow_key(&packet).protocol, 6),
                _ => panic!("unexpected route metadata: {label}"),
            }
        }
    }

    fn packet_v4(protocol: u8, fragment: u16, identification: u16, payload: &[u8]) -> Packet<Ip> {
        let total_length = 20 + payload.len();
        let mut bytes = vec![0; total_length];
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&(total_length as u16).to_be_bytes());
        bytes[4..6].copy_from_slice(&identification.to_be_bytes());
        bytes[6..8].copy_from_slice(&fragment.to_be_bytes());
        bytes[8] = 64;
        bytes[9] = protocol;
        bytes[12..16].copy_from_slice(&[192, 0, 2, 10]);
        bytes[16..20].copy_from_slice(&[198, 51, 100, 20]);
        bytes[20..].copy_from_slice(payload);
        Packet::copy_from(bytes.as_slice()).try_into_ip().unwrap()
    }

    fn packet_v6_with_hop_by_hop(payload: &[u8]) -> Packet<Ip> {
        let payload_length = 8 + payload.len();
        let mut bytes = vec![0; 40 + payload_length];
        bytes[0] = 0x60;
        bytes[4..6].copy_from_slice(&(payload_length as u16).to_be_bytes());
        bytes[6] = 0; // Hop-by-Hop options.
        bytes[7] = 64;
        bytes[8..24].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        bytes[24..40].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        bytes[40] = 6; // TCP after the extension header.
        bytes[41] = 0; // One 8-byte extension header.
        bytes[48..].copy_from_slice(payload);
        Packet::copy_from(bytes.as_slice()).try_into_ip().unwrap()
    }
}
