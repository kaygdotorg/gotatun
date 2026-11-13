// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

//! Tests and helpers for building ordered Linux TUN GSO frames.

use crate::packet::{
    Ip, Ipv4Header, Ipv6Header, Packet, TcpHeader, UdpHeader, util::checksum_ipv4_with_skip,
};
use crate::tun::tun_async_device::virtio::{Flags, GsoType, VirtioNetHeader};
use bytes::BytesMut;
use std::{mem::offset_of, ops::Deref};
use zerocopy::IntoBytes;

/// Maximum number of input packets represented by one Linux TUN GSO frame.
const MAX_GSO_SEGMENTS: usize = 64;

/// Maximum frame size accepted for a coalesced TUN write, including its virtio header.
const MAX_GSO_FRAME_LEN: usize = 64 * 1024;

/// IP version carried by a packet that can be described by Linux GSO metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IpVersion {
    /// IPv4 with no IP options.
    V4,
    /// IPv6 with no extension headers.
    V6,
}

/// Transport protocol carried by a packet that can be described by Linux GSO metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransportProtocol {
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol.
    Udp,
}

/// Header offsets and flow data needed to test whether two packets can share a GSO frame.
#[derive(Clone, Copy, Debug)]
struct PacketMetadata {
    ip_version: IpVersion,
    protocol: TransportProtocol,
    ip_header_len: usize,
    transport_header_len: usize,
    payload_offset: usize,
    payload_len: usize,
    tcp_sequence: Option<u32>,
}

impl PacketMetadata {
    /// Return the byte length of the IP and transport headers kept in the GSO frame.
    fn header_len(self) -> usize {
        self.ip_header_len + self.transport_header_len
    }

    /// Return the virtio GSO type that describes this packet's IP and transport protocols.
    fn gso_type(self) -> GsoType {
        match (self.ip_version, self.protocol) {
            (IpVersion::V4, TransportProtocol::Tcp) => GsoType::VIRTIO_NET_HDR_GSO_TCPV4,
            (IpVersion::V6, TransportProtocol::Tcp) => GsoType::VIRTIO_NET_HDR_GSO_TCPV6,
            (_, TransportProtocol::Udp) => GsoType::VIRTIO_NET_HDR_GSO_UDP_L4,
        }
    }

    /// Return the transport checksum field offset expected by `NEEDS_CSUM` metadata.
    fn checksum_offset(self) -> usize {
        match self.protocol {
            TransportProtocol::Tcp => offset_of!(TcpHeader, checksum),
            TransportProtocol::Udp => offset_of!(UdpHeader, checksum),
        }
    }
}

/// One TUN frame and the number of original IP packets it represents.
pub(super) struct CoalescedFrame {
    /// The virtio header followed by a complete IP packet or GSO super-packet.
    pub(super) frame: Packet<[u8]>,
}

impl Deref for CoalescedFrame {
    type Target = Packet<[u8]>;

    /// Borrow the frame bytes for callers that only need to inspect or write the packet.
    fn deref(&self) -> &Self::Target {
        &self.frame
    }
}

/// Coalesce only adjacent, compatible packets and preserve their input order.
///
/// TCP groups require matching normalized headers and contiguous sequence numbers. UDP-L4 groups
/// require matching normalized headers and full-sized datagrams before the final datagram. Each
/// output GSO frame is bounded by Linux's 64-segment and 64-KiB limits; unsupported headers and
/// refused offloads stay as individual `GSO_NONE` frames.
pub(super) fn coalesce_packets(
    packets: Vec<Packet<Ip>>,
    tcp_tso: bool,
    udp_uso: bool,
) -> Vec<CoalescedFrame> {
    let mut pending = packets.into_iter().peekable();
    let mut frames = Vec::with_capacity(pending.size_hint().0);

    while let Some(first) = pending.next() {
        let Some(first_metadata) = packet_metadata(first.as_bytes()) else {
            frames.push(single_frame(first));
            continue;
        };
        let offload_enabled = match first_metadata.protocol {
            TransportProtocol::Tcp => tcp_tso,
            TransportProtocol::Udp => udp_uso,
        };
        if !offload_enabled {
            frames.push(single_frame(first));
            continue;
        }

        let mut group = vec![first];
        let mut last_metadata = first_metadata;
        let mut group_payload_len = first_metadata.payload_len;
        while group.len() < MAX_GSO_SEGMENTS {
            let Some(next) = pending.peek() else {
                break;
            };
            let Some(next_metadata) = packet_metadata(next.as_bytes()) else {
                break;
            };
            if !can_append(
                group[0].as_bytes(),
                first_metadata,
                last_metadata,
                next.as_bytes(),
                next_metadata,
                group_payload_len,
                group.len(),
            ) {
                break;
            }

            let next = pending.next().expect("peeked packet remains available");
            group_payload_len += next_metadata.payload_len;
            last_metadata = next_metadata;
            group.push(next);
        }

        if group.len() == 1 {
            frames.push(single_frame(group.pop().expect("one packet is present")));
        } else {
            frames.push(gso_frame(group, first_metadata, group_payload_len));
        }
    }

    frames
}

/// Parse a direct TCP or UDP packet without accepting IP fragments or extension headers.
fn packet_metadata(bytes: &[u8]) -> Option<PacketMetadata> {
    let version = bytes.first()? >> 4;
    let (ip_version, ip_header_len, total_len, protocol_number) = match version {
        4 => {
            let ip_header_len = usize::from(bytes.first()? & 0x0f) * 4;
            if ip_header_len != Ipv4Header::LEN {
                return None;
            }
            let total_len = usize::from(read_u16(bytes, 2)?);
            let fragment = read_u16(bytes, 6)?;
            if total_len != bytes.len() || fragment & 0xbfff != 0 {
                return None;
            }
            (IpVersion::V4, ip_header_len, total_len, *bytes.get(9)?)
        }
        6 => {
            if bytes.len() < Ipv6Header::LEN {
                return None;
            }
            let total_len = Ipv6Header::LEN + usize::from(read_u16(bytes, 4)?);
            if total_len != bytes.len() {
                return None;
            }
            (IpVersion::V6, Ipv6Header::LEN, total_len, *bytes.get(6)?)
        }
        _ => return None,
    };

    let transport_offset = ip_header_len;
    let (protocol, transport_header_len, tcp_sequence) = match protocol_number {
        6 => {
            let tcp_header_len = usize::from(*bytes.get(transport_offset + 12)? >> 4) * 4;
            let flags = *bytes.get(transport_offset + 13)?;
            let payload_offset = transport_offset.checked_add(tcp_header_len)?;
            if tcp_header_len < TcpHeader::LEN || payload_offset > total_len || flags & 0xe7 != 0 {
                // SYN, FIN, RST, URG, ECE, and CWR require per-packet header semantics.
                return None;
            }
            let payload_len = total_len - payload_offset;
            if payload_len == 0 {
                return None;
            }
            (
                TransportProtocol::Tcp,
                tcp_header_len,
                Some(read_u32(bytes, transport_offset + 4)?),
            )
        }
        17 => {
            let udp_len = usize::from(read_u16(bytes, transport_offset + 4)?);
            if udp_len < UdpHeader::LEN || transport_offset + udp_len != total_len {
                return None;
            }
            // A zero UDP checksum has special optional semantics in IPv4 and is invalid in IPv6;
            // in either case leave the original datagram untouched.
            if read_u16(bytes, transport_offset + 6)? == 0 {
                return None;
            }
            let payload_len = udp_len - UdpHeader::LEN;
            if payload_len == 0 {
                return None;
            }
            (TransportProtocol::Udp, UdpHeader::LEN, None)
        }
        _ => return None,
    };

    let payload_offset = transport_offset.checked_add(transport_header_len)?;
    Some(PacketMetadata {
        ip_version,
        protocol,
        ip_header_len,
        transport_header_len,
        payload_offset,
        payload_len: total_len - payload_offset,
        tcp_sequence,
    })
}

/// Return whether a next packet can extend the current ordered GSO group.
fn can_append(
    first_packet: &[u8],
    first: PacketMetadata,
    last: PacketMetadata,
    next_packet: &[u8],
    next: PacketMetadata,
    grouped_payload_len: usize,
    grouped_packet_count: usize,
) -> bool {
    if first.ip_version != next.ip_version
        || first.protocol != next.protocol
        || first.header_len() != next.header_len()
        || next.payload_len == 0
        || next.payload_len > first.payload_len
        || last.payload_len < first.payload_len
        || grouped_packet_count >= MAX_GSO_SEGMENTS
        || !headers_match(first_packet, next_packet, first)
    {
        return false;
    }

    let Some(combined_payload_len) = grouped_payload_len.checked_add(next.payload_len) else {
        return false;
    };
    if VirtioNetHeader::LEN + first.header_len() + combined_payload_len > MAX_GSO_FRAME_LEN {
        return false;
    }

    match first.protocol {
        TransportProtocol::Tcp => {
            let Some(last_sequence) = last.tcp_sequence else {
                return false;
            };
            let Some(next_sequence) = next.tcp_sequence else {
                return false;
            };
            next_sequence == last_sequence.wrapping_add(last.payload_len as u32)
        }
        TransportProtocol::Udp => true,
    }
}

/// Compare IP and transport headers while ignoring fields that naturally change per segment.
///
/// Address and port bytes remain part of the comparison, so this also enforces the 5-tuple for
/// TCP and the 4-tuple for UDP. Only lengths, IPv4 IDs/checksums, TCP sequence/checksum, and UDP
/// length/checksum may differ.
fn headers_match(first: &[u8], next: &[u8], metadata: PacketMetadata) -> bool {
    let header_len = metadata.header_len();
    let Some(first_header) = first.get(..header_len) else {
        return false;
    };
    let Some(next_header) = next.get(..header_len) else {
        return false;
    };

    let (ip_dynamic, transport_dynamic): (&[(usize, usize)], &[(usize, usize)]) = match metadata {
        PacketMetadata {
            ip_version: IpVersion::V4,
            protocol: TransportProtocol::Tcp,
            ..
        } => (&[(2, 4), (4, 6), (10, 12)], &[(4, 8), (16, 18)]),
        PacketMetadata {
            ip_version: IpVersion::V4,
            protocol: TransportProtocol::Udp,
            ..
        } => (&[(2, 4), (4, 6), (10, 12)], &[(4, 6), (6, 8)]),
        PacketMetadata {
            ip_version: IpVersion::V6,
            protocol: TransportProtocol::Tcp,
            ..
        } => (&[(4, 6)], &[(4, 8), (16, 18)]),
        PacketMetadata {
            ip_version: IpVersion::V6,
            protocol: TransportProtocol::Udp,
            ..
        } => (&[(4, 6)], &[(4, 6), (6, 8)]),
    };

    bytes_equal_ignoring(
        &first_header[..metadata.ip_header_len],
        &next_header[..metadata.ip_header_len],
        ip_dynamic,
    ) && bytes_equal_ignoring(
        &first_header[metadata.ip_header_len..],
        &next_header[metadata.ip_header_len..],
        transport_dynamic,
    )
}

/// Compare equal-length byte slices except for ranges whose fields vary across segments.
fn bytes_equal_ignoring(left: &[u8], right: &[u8], ignored: &[(usize, usize)]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .enumerate()
            .all(|(index, (left, right))| {
                ignored
                    .iter()
                    .any(|(start, end)| (*start..*end).contains(&index))
                    || left == right
            })
}

/// Write one packet with a zeroed virtio header when no GSO group can be formed.
fn single_frame(packet: Packet<Ip>) -> CoalescedFrame {
    let packet = packet.into_bytes();
    let header = VirtioNetHeader {
        flags: Flags::new(),
        gso_type: GsoType::VIRTIO_NET_HDR_GSO_NONE,
        hdr_len: 0,
        gso_size: 0,
        csum_start: 0,
        csum_offset: 0,
    };
    let mut bytes = BytesMut::with_capacity(VirtioNetHeader::LEN + packet.len());
    bytes.extend_from_slice(header.as_bytes());
    bytes.extend_from_slice(packet.as_bytes());
    CoalescedFrame {
        frame: Packet::from_bytes(bytes),
    }
}

/// Build one `NEEDS_CSUM` GSO frame from validated, ordered packets in a group.
fn gso_frame(
    group: Vec<Packet<Ip>>,
    metadata: PacketMetadata,
    payload_len: usize,
) -> CoalescedFrame {
    let gso_size = u16::try_from(metadata.payload_len)
        .expect("a single input packet's payload fits the IP length field");
    let header_len = metadata.header_len();
    let first_packet = group.first().expect("a GSO group has an input packet");
    let mut bytes = BytesMut::with_capacity(VirtioNetHeader::LEN + header_len + payload_len);
    let header = VirtioNetHeader {
        flags: Flags::new().with_needs_csum(true),
        gso_type: metadata.gso_type(),
        hdr_len: u16::try_from(header_len).expect("IP and transport headers fit in u16"),
        gso_size,
        csum_start: u16::try_from(metadata.ip_header_len).expect("IP header fits in u16"),
        csum_offset: u16::try_from(metadata.checksum_offset())
            .expect("transport checksum offset fits in u16"),
    };
    bytes.extend_from_slice(header.as_bytes());
    bytes.extend_from_slice(&first_packet.as_bytes()[..header_len]);
    for packet in &group {
        let packet_metadata = packet_metadata(packet.as_bytes())
            .expect("every packet in a GSO group was validated before it was added");
        let payload_end = packet_metadata.payload_offset + packet_metadata.payload_len;
        bytes.extend_from_slice(&packet.as_bytes()[packet_metadata.payload_offset..payload_end]);
    }

    let ip_offset = VirtioNetHeader::LEN;
    let total_ip_len = header_len + payload_len;
    match metadata.ip_version {
        IpVersion::V4 => {
            let total_len = u16::try_from(total_ip_len)
                .expect("the 64-KiB GSO frame bound keeps IPv4 total length representable");
            bytes[ip_offset + offset_of!(Ipv4Header, total_len)
                ..ip_offset + offset_of!(Ipv4Header, total_len) + 2]
                .copy_from_slice(&total_len.to_be_bytes());
            let checksum_offset = ip_offset + offset_of!(Ipv4Header, header_checksum);
            bytes[checksum_offset..checksum_offset + 2].fill(0);
            let checksum =
                checksum_ipv4_with_skip(&bytes[ip_offset..ip_offset + metadata.ip_header_len]);
            bytes[checksum_offset..checksum_offset + 2].copy_from_slice(&checksum.to_be_bytes());
        }
        IpVersion::V6 => {
            let payload_len = u16::try_from(total_ip_len - Ipv6Header::LEN)
                .expect("the 64-KiB GSO frame bound keeps IPv6 payload length representable");
            bytes[ip_offset + offset_of!(Ipv6Header, payload_length)
                ..ip_offset + offset_of!(Ipv6Header, payload_length) + 2]
                .copy_from_slice(&payload_len.to_be_bytes());
        }
    }

    let transport_offset = ip_offset + metadata.ip_header_len;
    let checksum_seed = partial_checksum_seed(
        &bytes[ip_offset..ip_offset + total_ip_len],
        metadata,
        total_ip_len - metadata.ip_header_len,
    );
    match metadata.protocol {
        TransportProtocol::Tcp => {
            let checksum_offset = transport_offset + metadata.checksum_offset();
            bytes[checksum_offset..checksum_offset + 2]
                .copy_from_slice(&checksum_seed.to_be_bytes());
        }
        TransportProtocol::Udp => {
            let udp_len = u16::try_from(UdpHeader::LEN + payload_len)
                .expect("the 64-KiB GSO frame bound keeps UDP length representable");
            let length_offset = transport_offset + offset_of!(UdpHeader, length);
            bytes[length_offset..length_offset + 2].copy_from_slice(&udp_len.to_be_bytes());
            let checksum_offset = transport_offset + metadata.checksum_offset();
            bytes[checksum_offset..checksum_offset + 2]
                .copy_from_slice(&checksum_seed.to_be_bytes());
        }
    }

    CoalescedFrame {
        frame: Packet::from_bytes(bytes),
    }
}

/// Calculate the one's-complement pseudo-header checksum seed for `CHECKSUM_PARTIAL`.
///
/// The kernel completes each segment checksum from this seed and the segment's transport header
/// and payload. A zero seed would omit the IP addresses, protocol, and transport length.
fn partial_checksum_seed(packet: &[u8], metadata: PacketMetadata, transport_len: usize) -> u16 {
    let (source_offset, address_len) = match metadata.ip_version {
        IpVersion::V4 => (offset_of!(Ipv4Header, source_address), 4),
        IpVersion::V6 => (offset_of!(Ipv6Header, source_address), 16),
    };
    let destination_offset = source_offset + address_len;
    let mut sum = sum_network_words(&packet[source_offset..source_offset + address_len])
        + sum_network_words(&packet[destination_offset..destination_offset + address_len]);
    let protocol: u8 = match metadata.protocol {
        TransportProtocol::Tcp => 6,
        TransportProtocol::Udp => 17,
    };

    match metadata.ip_version {
        IpVersion::V4 => {
            let length = u16::try_from(transport_len)
                .expect("the TUN GSO frame limit keeps IPv4 transport length representable");
            sum += u32::from(protocol) + u32::from(length);
        }
        IpVersion::V6 => {
            let length = u32::try_from(transport_len)
                .expect("the TUN GSO frame limit keeps IPv6 transport length representable");
            sum += (length >> 16) + (length & 0xffff) + u32::from(protocol);
        }
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Sum 16-bit network-order words as required by an Internet checksum.
fn sum_network_words(bytes: &[u8]) -> u32 {
    bytes
        .chunks_exact(2)
        .map(|word| u32::from(u16::from_be_bytes([word[0], word[1]])))
        .sum()
}

/// Read a network-order 16-bit field without indexing beyond a malformed packet.
fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?,
    ))
}

/// Read a network-order 32-bit field without indexing beyond a malformed packet.
fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_be_bytes(
        bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}

#[cfg(test)]
/// Unit tests for Linux TUN GSO header construction and packet ordering.
mod tests {
    use super::{CoalescedFrame, coalesce_packets};
    use crate::{
        packet::{
            Ip, IpNextProtocol, Ipv4, Ipv4Header, Ipv4VersionIhl, Ipv6, Ipv6Header,
            Ipv6VersionTrafficFlow, Packet, PseudoHeaderV4, PseudoHeaderV6, Tcp, TcpDataOffset,
            TcpFlags, TcpHeader, Udp, UdpHeader, checksum_ipv4_with_skip, checksum_udp_with_skip,
        },
        tun::tun_async_device::{
            tso,
            virtio::{GsoType, VirtioNetHeader},
        },
    };
    use bytes::BytesMut;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use zerocopy::{FromBytes, IntoBytes, big_endian};

    /// Builds a valid IPv4 TCP packet with the selected source address and sequence number.
    fn ipv4_tcp(flow: u8, seq_num: u32, payload: &[u8]) -> Packet<Ip> {
        let tcp_header = TcpHeader {
            source_port: 111.into(),
            destination_port: 222.into(),
            seq_num: seq_num.into(),
            ack_num: 444.into(),
            data_offset: TcpDataOffset::no_options(),
            flags: TcpFlags::new().with_ack(true),
            window: 555.into(),
            checksum: 0.into(),
            urgent_pointer: 0.into(),
        };
        let tcp_len = TcpHeader::LEN + payload.len();
        let ip_header = Ipv4Header::new_for_length(
            Ipv4Addr::new(10, 0, 0, flow),
            Ipv4Addr::new(10, 0, 1, 1),
            IpNextProtocol::Tcp,
            tcp_len.try_into().unwrap(),
        );
        let mut bytes = BytesMut::with_capacity(Ipv4Header::LEN + tcp_len);
        bytes.extend_from_slice(ip_header.as_bytes());
        bytes.extend_from_slice(tcp_header.as_bytes());
        bytes.extend_from_slice(payload);

        let mut packet: Packet<Ipv4<Tcp>> = Packet::from_bytes(bytes)
            .try_into_ipvx()
            .unwrap()
            .unwrap_left()
            .try_into_tcp()
            .unwrap();
        packet.update_tcp_checksum();
        let ip_checksum = packet.header.compute_checksum();
        packet.header.header_checksum = ip_checksum.into();
        Packet::<Ip>::from(packet)
    }

    /// Builds a valid IPv6 TCP packet with the selected source address and sequence number.
    fn ipv6_tcp(flow: u16, seq_num: u32, payload: &[u8]) -> Packet<Ip> {
        let tcp_header = TcpHeader {
            source_port: 111.into(),
            destination_port: 222.into(),
            seq_num: seq_num.into(),
            ack_num: 444.into(),
            data_offset: TcpDataOffset::no_options(),
            flags: TcpFlags::new().with_ack(true),
            window: 555.into(),
            checksum: 0.into(),
            urgent_pointer: 0.into(),
        };
        let tcp_len = TcpHeader::LEN + payload.len();
        let ip_header = Ipv6Header {
            version_traffic_flow: Ipv6VersionTrafficFlow::new().with_version(6),
            payload_length: tcp_len.try_into().unwrap(),
            next_header: IpNextProtocol::Tcp,
            hop_limit: 64,
            source_address: big_endian::U128::new(u128::from(Ipv6Addr::new(
                0x2001, 0x0db8, 0, 0, 0, 0, 0, flow,
            ))),
            destination_address: big_endian::U128::new(u128::from(Ipv6Addr::LOCALHOST)),
        };
        let mut bytes = BytesMut::with_capacity(Ipv6Header::LEN + tcp_len);
        bytes.extend_from_slice(ip_header.as_bytes());
        bytes.extend_from_slice(tcp_header.as_bytes());
        bytes.extend_from_slice(payload);

        let mut packet: Packet<Ipv6<Tcp>> = Packet::from_bytes(bytes)
            .try_into_ipvx()
            .unwrap()
            .unwrap_right()
            .try_into_tcp()
            .unwrap();
        packet.update_tcp_checksum();
        Packet::<Ip>::from(packet)
    }

    /// Builds a valid IPv4 UDP datagram with a distinct source address for each flow.
    fn ipv4_udp(flow: u8, payload: &[u8]) -> Packet<Ip> {
        let udp_len = UdpHeader::LEN + payload.len();
        let udp_header = UdpHeader::new(111, 222, udp_len.try_into().unwrap(), 0);
        let ip_header = Ipv4Header::new_for_length(
            Ipv4Addr::new(10, 0, 0, flow),
            Ipv4Addr::new(10, 0, 1, 1),
            IpNextProtocol::Udp,
            udp_len.try_into().unwrap(),
        );
        let mut bytes = BytesMut::with_capacity(Ipv4Header::LEN + udp_len);
        bytes.extend_from_slice(ip_header.as_bytes());
        bytes.extend_from_slice(udp_header.as_bytes());
        bytes.extend_from_slice(payload);

        let mut packet: Packet<Ipv4<Udp>> = Packet::from_bytes(bytes)
            .try_into_ipvx()
            .unwrap()
            .unwrap_left()
            .try_into_udp()
            .unwrap();
        let pseudo = PseudoHeaderV4::from_udp(
            packet.header.source_address,
            packet.header.destination_address,
            &packet.payload,
        );
        packet.payload.header.checksum = checksum_udp_with_skip(pseudo, &packet.payload).into();
        let ip_checksum = packet.header.compute_checksum();
        packet.header.header_checksum = ip_checksum.into();
        Packet::<Ip>::from(packet)
    }

    /// Builds a valid IPv6 UDP datagram with the selected source address.
    fn ipv6_udp(flow: u16, payload: &[u8]) -> Packet<Ip> {
        let udp_len = UdpHeader::LEN + payload.len();
        let udp_header = UdpHeader::new(111, 222, udp_len.try_into().unwrap(), 0);
        let ip_header = Ipv6Header {
            version_traffic_flow: Ipv6VersionTrafficFlow::new().with_version(6),
            payload_length: udp_len.try_into().unwrap(),
            next_header: IpNextProtocol::Udp,
            hop_limit: 64,
            source_address: big_endian::U128::new(u128::from(Ipv6Addr::new(
                0x2001, 0x0db8, 0, 0, 0, 0, 0, flow,
            ))),
            destination_address: big_endian::U128::new(u128::from(Ipv6Addr::LOCALHOST)),
        };
        let mut bytes = BytesMut::with_capacity(Ipv6Header::LEN + udp_len);
        bytes.extend_from_slice(ip_header.as_bytes());
        bytes.extend_from_slice(udp_header.as_bytes());
        bytes.extend_from_slice(payload);

        let mut packet: Packet<Ipv6<Udp>> = Packet::from_bytes(bytes)
            .try_into_ipvx()
            .unwrap()
            .unwrap_right()
            .try_into_udp()
            .unwrap();
        let pseudo = PseudoHeaderV6::from_udp(
            packet.header.source_address,
            packet.header.destination_address,
            &packet.payload,
        );
        packet.payload.header.checksum = checksum_udp_with_skip(pseudo, &packet.payload).into();
        Packet::<Ip>::from(packet)
    }

    /// Adds a valid four-byte IPv4 option area to a packet without changing its transport data.
    fn with_ipv4_options(packet: Packet<Ip>) -> Packet<Ip> {
        let options = [1, 1, 1, 1];
        let original = packet.as_bytes();
        let new_len = original.len() + options.len();
        let mut bytes = BytesMut::with_capacity(new_len);
        bytes.extend_from_slice(&original[..Ipv4Header::LEN]);
        let version_and_ihl = Ipv4VersionIhl::new().with_version(4).with_ihl(6);
        bytes[0] = version_and_ihl.as_bytes()[0];
        bytes[2..4].copy_from_slice(&(new_len as u16).to_be_bytes());
        bytes[10..12].fill(0);
        bytes.extend_from_slice(&options);
        bytes.extend_from_slice(&original[Ipv4Header::LEN..]);
        let checksum = checksum_ipv4_with_skip(&bytes[..Ipv4Header::LEN + options.len()]);
        bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
        Packet::copy_from(&bytes[..]).try_into_ip().unwrap()
    }

    /// Adds a hop-by-hop extension header so IPv6 packets must stay out of GSO groups.
    fn with_ipv6_extension(packet: Packet<Ip>) -> Packet<Ip> {
        let original = packet.as_bytes();
        let mut header = *Ipv6Header::ref_from_bytes(&original[..Ipv6Header::LEN]).unwrap();
        header.next_header = IpNextProtocol::Hopopt;
        header.payload_length = (header.payload_length.get() + 8).into();

        let mut bytes = BytesMut::with_capacity(original.len() + 8);
        bytes.extend_from_slice(header.as_bytes());
        bytes.extend_from_slice(&[6, 0, 0, 0, 0, 0, 0, 0]);
        bytes.extend_from_slice(&original[Ipv6Header::LEN..]);
        Packet::copy_from(&bytes[..]).try_into_ip().unwrap()
    }

    /// Reads the virtio header from a TUN frame.
    fn frame_header(frame: &Packet<[u8]>) -> VirtioNetHeader {
        *VirtioNetHeader::ref_from_bytes(&frame.as_bytes()[..VirtioNetHeader::LEN]).unwrap()
    }

    /// Parses the IP packet bytes from a non-GSO TUN frame.
    fn ip_packet(frame: &Packet<[u8]>) -> Packet<Ip> {
        Packet::copy_from(&frame.as_bytes()[VirtioNetHeader::LEN..])
            .try_into_ip()
            .unwrap()
    }

    /// Returns the payload of a non-GSO IPv4 TCP TUN frame.
    fn ipv4_tcp_payload(frame: &Packet<[u8]>) -> Vec<u8> {
        ip_packet(frame)
            .try_into_ipvx()
            .unwrap()
            .unwrap_left()
            .try_into_tcp()
            .unwrap()
            .payload
            .payload()
            .unwrap()
            .to_vec()
    }

    /// Returns the payload of a decoded IPv4 TCP packet.
    fn ipv4_tcp_packet_payload(packet: &Packet<Ip>) -> Vec<u8> {
        Packet::copy_from(packet.as_bytes())
            .try_into_ipvx()
            .unwrap()
            .unwrap_left()
            .try_into_tcp()
            .unwrap()
            .payload
            .payload()
            .unwrap()
            .to_vec()
    }

    /// Returns the payload of a decoded IPv6 TCP packet.
    fn ipv6_tcp_packet_payload(packet: &Packet<Ip>) -> Vec<u8> {
        Packet::copy_from(packet.as_bytes())
            .try_into_ipvx()
            .unwrap()
            .unwrap_right()
            .try_into_tcp()
            .unwrap()
            .payload
            .payload()
            .unwrap()
            .to_vec()
    }

    /// Returns the payload of a non-GSO IPv4 UDP TUN frame.
    fn ipv4_udp_payload(frame: &Packet<[u8]>) -> Vec<u8> {
        ip_packet(frame)
            .try_into_ipvx()
            .unwrap()
            .unwrap_left()
            .try_into_udp()
            .unwrap()
            .payload
            .payload
            .to_vec()
    }

    /// Returns the payload of a decoded IPv4 UDP packet.
    fn ipv4_udp_packet_payload(packet: &Packet<Ip>) -> Vec<u8> {
        Packet::copy_from(packet.as_bytes())
            .try_into_ipvx()
            .unwrap()
            .unwrap_left()
            .try_into_udp()
            .unwrap()
            .payload
            .payload
            .to_vec()
    }

    /// Returns the payload of a decoded IPv6 UDP packet.
    fn ipv6_udp_packet_payload(packet: &Packet<Ip>) -> Vec<u8> {
        Packet::copy_from(packet.as_bytes())
            .try_into_ipvx()
            .unwrap()
            .unwrap_right()
            .try_into_udp()
            .unwrap()
            .payload
            .payload
            .to_vec()
    }

    /// Segments a TUN GSO frame with GotaTun's real receive-side parser.
    fn segments(frame: &Packet<[u8]>) -> Vec<Packet<Ip>> {
        tso::new_tso_iter_from_vnet(Packet::copy_from(frame.as_bytes()))
            .unwrap()
            .collect()
    }

    /// Verifies TCP checksums after the GSO frame has been segmented by the receive parser.
    fn assert_tcp_checksums_are_complete(packets: Vec<Packet<Ip>>, ipv6: bool) {
        for packet in packets {
            let ip = packet.try_into_ipvx().unwrap();
            if ipv6 {
                let tcp = ip.unwrap_right().try_into_tcp().unwrap();
                assert_eq!(
                    tcp.calculate_tcp_checksum(),
                    tcp.payload.header.checksum.get()
                );
            } else {
                let tcp = ip.unwrap_left().try_into_tcp().unwrap();
                assert_eq!(
                    tcp.calculate_tcp_checksum(),
                    tcp.payload.header.checksum.get()
                );
            }
        }
    }

    /// Verifies UDP checksums after the GSO frame has been segmented by the receive parser.
    fn assert_udp_checksums_are_complete(packets: Vec<Packet<Ip>>, ipv6: bool) {
        for packet in packets {
            let ip = packet.try_into_ipvx().unwrap();
            if ipv6 {
                let udp = ip.unwrap_right().try_into_udp().unwrap();
                let pseudo = PseudoHeaderV6::from_udp(
                    udp.header.source_address,
                    udp.header.destination_address,
                    &udp.payload,
                );
                assert_eq!(
                    udp.payload.header.checksum.get(),
                    checksum_udp_with_skip(pseudo, &udp.payload)
                );
            } else {
                let udp = ip.unwrap_left().try_into_udp().unwrap();
                let pseudo = PseudoHeaderV4::from_udp(
                    udp.header.source_address,
                    udp.header.destination_address,
                    &udp.payload,
                );
                assert_eq!(
                    udp.payload.header.checksum.get(),
                    checksum_udp_with_skip(pseudo, &udp.payload)
                );
            }
        }
    }

    /// Computes the independently expected one's-complement checksum of an IP pseudo-header.
    fn expected_partial_checksum_seed(
        packet: &[u8],
        ip_header_len: usize,
        ipv6: bool,
        protocol: u8,
    ) -> u16 {
        let transport_len = u32::try_from(packet.len() - ip_header_len).unwrap();
        let mut pseudo_header = Vec::new();
        if ipv6 {
            pseudo_header.extend_from_slice(&packet[8..40]);
            pseudo_header.extend_from_slice(&transport_len.to_be_bytes());
            pseudo_header.extend_from_slice(&[0, 0, 0, protocol]);
        } else {
            pseudo_header.extend_from_slice(&packet[12..20]);
            pseudo_header.extend_from_slice(&[0, protocol]);
            pseudo_header.extend_from_slice(&(transport_len as u16).to_be_bytes());
        }

        let mut sum: u32 = pseudo_header
            .chunks_exact(2)
            .map(|word| u32::from(u16::from_be_bytes([word[0], word[1]])))
            .sum();
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// Checks that a coalesced frame carries the pseudo-header seed required by partial checksum.
    fn assert_partial_checksum_seed(
        frame: &CoalescedFrame,
        ip_header_len: usize,
        ipv6: bool,
        protocol: u8,
    ) {
        let header = frame_header(frame);
        assert!(header.flags.needs_csum());
        let packet = &frame.as_bytes()[VirtioNetHeader::LEN..];
        let checksum_offset =
            VirtioNetHeader::LEN + usize::from(header.csum_start) + usize::from(header.csum_offset);
        let actual = u16::from_be_bytes(
            frame.as_bytes()[checksum_offset..checksum_offset + 2]
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            actual,
            expected_partial_checksum_seed(packet, ip_header_len, ipv6, protocol),
            "partial checksum field must contain the IP pseudo-header seed"
        );
    }

    /// TCP and UDP GSO frames carry the pseudo-header checksum seed Linux completes per segment.
    #[test]
    fn gso_frames_contain_partial_pseudo_header_checksum_seed() {
        let mut tcp_v4 = coalesce_packets(
            vec![ipv4_tcp(1, 1000, b"first"), ipv4_tcp(1, 1005, b"other")],
            true,
            false,
        );
        let mut tcp_v6 = coalesce_packets(
            vec![ipv6_tcp(1, 2000, b"first"), ipv6_tcp(1, 2005, b"other")],
            true,
            false,
        );
        let mut udp_v4 = coalesce_packets(
            vec![ipv4_udp(1, b"first"), ipv4_udp(1, b"other")],
            false,
            true,
        );
        let mut udp_v6 = coalesce_packets(
            vec![ipv6_udp(1, b"first"), ipv6_udp(1, b"other")],
            false,
            true,
        );

        assert_partial_checksum_seed(&tcp_v4.pop().unwrap(), Ipv4Header::LEN, false, 6);
        assert_partial_checksum_seed(&tcp_v6.pop().unwrap(), Ipv6Header::LEN, true, 6);
        assert_partial_checksum_seed(&udp_v4.pop().unwrap(), Ipv4Header::LEN, false, 17);
        assert_partial_checksum_seed(&udp_v6.pop().unwrap(), Ipv6Header::LEN, true, 17);
    }

    /// Adjacent IPv4 TCP segments become one frame with valid kernel metadata and checksums.
    #[test]
    fn tcp_v4_superframe_has_kernel_metadata_and_round_trips_checksums() {
        let packets = vec![ipv4_tcp(1, 1000, b"first"), ipv4_tcp(1, 1005, b"other")];

        let mut frames = coalesce_packets(packets, true, false);

        assert_eq!(frames.len(), 1);
        assert_eq!(segments(&frames[0]).len(), 2);
        let frame = frames.pop().unwrap();
        let header = frame_header(&frame);
        assert_eq!(header.gso_type, GsoType::VIRTIO_NET_HDR_GSO_TCPV4);
        assert!(header.flags.needs_csum());
        let hdr_len = header.hdr_len;
        let gso_size = header.gso_size;
        let csum_start = header.csum_start;
        let csum_offset = header.csum_offset;
        assert_eq!(hdr_len, (Ipv4Header::LEN + TcpHeader::LEN) as u16);
        assert_eq!(gso_size, 5);
        assert_eq!(csum_start, Ipv4Header::LEN as u16);
        assert_eq!(csum_offset, 16);

        let packets = segments(&frame);
        assert_eq!(packets.len(), 2);
        assert_eq!(ipv4_tcp_packet_payload(&packets[0]).as_slice(), b"first");
        assert_eq!(ipv4_tcp_packet_payload(&packets[1]).as_slice(), b"other");
        assert_tcp_checksums_are_complete(packets, false);
    }

    /// Adjacent IPv6 TCP segments use the TCPv6 metadata and complete checksums on split.
    #[test]
    fn tcp_v6_superframe_has_kernel_metadata_and_round_trips_checksums() {
        let packets = vec![ipv6_tcp(1, 2000, b"first"), ipv6_tcp(1, 2005, b"other")];

        let frames = coalesce_packets(packets, true, false);

        assert_eq!(frames.len(), 1);
        let header = frame_header(&frames[0]);
        assert_eq!(header.gso_type, GsoType::VIRTIO_NET_HDR_GSO_TCPV6);
        assert!(header.flags.needs_csum());
        let hdr_len = header.hdr_len;
        let gso_size = header.gso_size;
        let csum_start = header.csum_start;
        let csum_offset = header.csum_offset;
        assert_eq!(hdr_len, (Ipv6Header::LEN + TcpHeader::LEN) as u16);
        assert_eq!(gso_size, 5);
        assert_eq!(csum_start, Ipv6Header::LEN as u16);
        assert_eq!(csum_offset, 16);

        let packets = segments(&frames[0]);
        assert_eq!(packets.len(), 2);
        assert_eq!(ipv6_tcp_packet_payload(&packets[0]).as_slice(), b"first");
        assert_eq!(ipv6_tcp_packet_payload(&packets[1]).as_slice(), b"other");
        assert_tcp_checksums_are_complete(packets, true);
    }

    /// UDP-L4 coalescing uses negotiated metadata and restores each IPv4 checksum on split.
    #[test]
    fn udp_v4_superframe_has_kernel_metadata_and_round_trips_checksums() {
        let packets = vec![ipv4_udp(1, b"first"), ipv4_udp(1, b"other")];

        let frames = coalesce_packets(packets, false, true);

        assert_eq!(frames.len(), 1);
        assert_eq!(segments(&frames[0]).len(), 2);
        let header = frame_header(&frames[0]);
        assert_eq!(header.gso_type, GsoType::VIRTIO_NET_HDR_GSO_UDP_L4);
        assert!(header.flags.needs_csum());
        let hdr_len = header.hdr_len;
        let gso_size = header.gso_size;
        let csum_start = header.csum_start;
        let csum_offset = header.csum_offset;
        assert_eq!(hdr_len, (Ipv4Header::LEN + UdpHeader::LEN) as u16);
        assert_eq!(gso_size, 5);
        assert_eq!(csum_start, Ipv4Header::LEN as u16);
        assert_eq!(csum_offset, 6);

        let packets = segments(&frames[0]);
        assert_eq!(packets.len(), 2);
        assert_eq!(ipv4_udp_packet_payload(&packets[0]).as_slice(), b"first");
        assert_eq!(ipv4_udp_packet_payload(&packets[1]).as_slice(), b"other");
        assert_udp_checksums_are_complete(packets, false);
    }

    /// UDP-L4 coalescing uses negotiated metadata and restores each IPv6 checksum on split.
    #[test]
    fn udp_v6_superframe_has_kernel_metadata_and_round_trips_checksums() {
        let packets = vec![ipv6_udp(1, b"first"), ipv6_udp(1, b"other")];

        let frames = coalesce_packets(packets, false, true);

        assert_eq!(frames.len(), 1);
        let header = frame_header(&frames[0]);
        assert_eq!(header.gso_type, GsoType::VIRTIO_NET_HDR_GSO_UDP_L4);
        assert!(header.flags.needs_csum());
        let hdr_len = header.hdr_len;
        let gso_size = header.gso_size;
        let csum_start = header.csum_start;
        let csum_offset = header.csum_offset;
        assert_eq!(hdr_len, (Ipv6Header::LEN + UdpHeader::LEN) as u16);
        assert_eq!(gso_size, 5);
        assert_eq!(csum_start, Ipv6Header::LEN as u16);
        assert_eq!(csum_offset, 6);

        let packets = segments(&frames[0]);
        assert_eq!(packets.len(), 2);
        assert_eq!(ipv6_udp_packet_payload(&packets[0]).as_slice(), b"first");
        assert_eq!(ipv6_udp_packet_payload(&packets[1]).as_slice(), b"other");
        assert_udp_checksums_are_complete(packets, true);
    }

    /// UDP-L4 coalescing preserves a shorter final datagram and rebuilds its checksum.
    #[test]
    fn udp_short_final_datagram_keeps_its_boundary_and_checksum() {
        let packets = vec![ipv4_udp(1, b"first"), ipv4_udp(1, b"end")];

        let frames = coalesce_packets(packets, false, true);

        assert_eq!(frames.len(), 1);
        let header = frame_header(&frames[0]);
        assert_eq!(header.gso_type, GsoType::VIRTIO_NET_HDR_GSO_UDP_L4);
        let gso_size = header.gso_size;
        assert_eq!(gso_size, 5);
        let packets = segments(&frames[0]);
        assert_eq!(packets.len(), 2);
        assert_eq!(ipv4_udp_packet_payload(&packets[0]).as_slice(), b"first");
        assert_eq!(ipv4_udp_packet_payload(&packets[1]).as_slice(), b"end");
        assert_udp_checksums_are_complete(packets, false);
    }

    /// TCP packets stay separate when TUN TCP segmentation was refused.
    #[test]
    fn tcp_v4_uses_single_frames_when_tso_was_refused() {
        let packets = vec![ipv4_tcp(1, 1000, b"first"), ipv4_tcp(1, 1005, b"other")];

        let frames = coalesce_packets(packets, false, false);

        assert_eq!(frames.len(), 2);
        for frame in &frames {
            let header = frame_header(frame);
            assert_eq!(header.gso_type, GsoType::VIRTIO_NET_HDR_GSO_NONE);
            let gso_size = header.gso_size;
            assert_eq!(gso_size, 0);
            assert!(!header.flags.needs_csum());
        }
    }

    /// UDP packets stay separate when TUN UDP segmentation was refused.
    #[test]
    fn udp_v4_uses_single_frames_when_uso_was_refused() {
        let packets = vec![ipv4_udp(1, b"first"), ipv4_udp(1, b"other")];

        let frames = coalesce_packets(packets, true, false);

        assert_eq!(frames.len(), 2);
        for frame in &frames {
            let header = frame_header(frame);
            assert_eq!(header.gso_type, GsoType::VIRTIO_NET_HDR_GSO_NONE);
            assert!(!header.flags.needs_csum());
        }
        assert_eq!(ipv4_udp_payload(&frames[0]).as_slice(), b"first");
        assert_eq!(ipv4_udp_payload(&frames[1]).as_slice(), b"other");
    }

    /// A sequence gap breaks a TCP group instead of fabricating missing bytes.
    #[test]
    fn tcp_sequence_gap_starts_a_new_frame() {
        let packets = vec![ipv4_tcp(1, 1000, b"first"), ipv4_tcp(1, 1006, b"other")];

        let frames = coalesce_packets(packets, true, false);

        assert_eq!(frames.len(), 2);
        assert_eq!(ipv4_tcp_payload(&frames[0]).as_slice(), b"first");
        assert_eq!(ipv4_tcp_payload(&frames[1]).as_slice(), b"other");
    }

    /// Interleaved flows retain input order and do not coalesce across one another.
    #[test]
    fn interleaved_tcp_flows_keep_order_without_cross_flow_coalescing() {
        let packets = vec![
            ipv4_tcp(1, 1000, b"first"),
            ipv4_tcp(2, 2000, b"other"),
            ipv4_tcp(1, 1005, b"later"),
        ];

        let frames = coalesce_packets(packets, true, false);

        assert_eq!(frames.len(), 3);
        assert_eq!(ipv4_tcp_payload(&frames[0]).as_slice(), b"first");
        assert_eq!(ipv4_tcp_payload(&frames[1]).as_slice(), b"other");
        assert_eq!(ipv4_tcp_payload(&frames[2]).as_slice(), b"later");
    }

    /// IPv4 options and IPv6 extension headers remain unchanged as single TUN packets.
    #[test]
    fn ip_options_and_ipv6_extensions_are_passed_through_uncoalesced() {
        let ipv4 = with_ipv4_options(ipv4_tcp(1, 1000, b"first"));
        let ipv4_second = with_ipv4_options(ipv4_tcp(1, 1005, b"other"));
        let ipv6 = with_ipv6_extension(ipv6_tcp(1, 2000, b"first"));
        let ipv6_second = with_ipv6_extension(ipv6_tcp(1, 2005, b"other"));

        let v4_frames = coalesce_packets(vec![ipv4, ipv4_second], true, false);
        let v6_frames = coalesce_packets(vec![ipv6, ipv6_second], true, false);

        assert_eq!(v4_frames.len(), 2);
        assert_eq!(v6_frames.len(), 2);
        for (frame, original) in v4_frames
            .iter()
            .zip([ipv4_tcp(1, 1000, b"first"), ipv4_tcp(1, 1005, b"other")])
        {
            assert_eq!(
                frame_header(frame).gso_type,
                GsoType::VIRTIO_NET_HDR_GSO_NONE
            );
            assert_eq!(
                &frame.as_bytes()[VirtioNetHeader::LEN + Ipv4Header::LEN
                    ..VirtioNetHeader::LEN + Ipv4Header::LEN + 4],
                &[1, 1, 1, 1]
            );
            assert!(frame.as_bytes().len() > original.as_bytes().len());
        }
        for frame in &v6_frames {
            assert_eq!(
                frame_header(frame).gso_type,
                GsoType::VIRTIO_NET_HDR_GSO_NONE
            );
            assert_eq!(
                &frame.as_bytes()[VirtioNetHeader::LEN + Ipv6Header::LEN
                    ..VirtioNetHeader::LEN + Ipv6Header::LEN + 2],
                &[6, 0]
            );
        }
    }

    /// Coalescing stops at the kernel's 64-segment limit and preserves the remaining packet.
    #[test]
    fn tcp_superframes_do_not_exceed_kernel_segment_count() {
        let packets = (0..65)
            .map(|index| ipv4_tcp(1, 1000 + index * 400, &[index as u8; 400]))
            .collect();

        let frames = coalesce_packets(packets, true, false);

        assert_eq!(frames.len(), 2);
        let first_header = frame_header(&frames[0]);
        assert_eq!(first_header.gso_type, GsoType::VIRTIO_NET_HDR_GSO_TCPV4);
        let first_gso_size = first_header.gso_size;
        let first_hdr_len = first_header.hdr_len;
        assert_eq!(first_gso_size, 400);
        let first_payload_len =
            frames[0].as_bytes().len() - VirtioNetHeader::LEN - usize::from(first_hdr_len);
        assert_eq!(first_payload_len / usize::from(first_gso_size), 64);
        assert_eq!(
            frame_header(&frames[1]).gso_type,
            GsoType::VIRTIO_NET_HDR_GSO_NONE
        );
        let first_segments = segments(&frames[0]);
        assert_eq!(first_segments.len(), 64);
        for (index, packet) in first_segments.iter().enumerate() {
            assert_eq!(ipv4_tcp_packet_payload(packet), vec![index as u8; 400]);
        }
        assert_eq!(ipv4_tcp_payload(&frames[1]), vec![64; 400]);
    }

    /// Coalescing keeps every TUN frame within 64 KiB even when the segment limit allows more.
    #[test]
    fn tcp_superframes_do_not_exceed_kernel_frame_size() {
        let packets = (0..64)
            .map(|index| ipv4_tcp(1, 1000 + index * 1450, &[index as u8; 1450]))
            .collect();

        let frames = coalesce_packets(packets, true, false);

        assert!(frames.len() > 1);
        assert!(
            frames
                .iter()
                .all(|frame| frame.as_bytes().len() <= 64 * 1024)
        );
    }

    /// UDP-L4 coalescing respects the kernel's 64-segment limit.
    #[test]
    fn udp_superframes_do_not_exceed_kernel_segment_count() {
        let packets = (0..65)
            .map(|index| ipv4_udp(1, &[index as u8; 400]))
            .collect();

        let frames = coalesce_packets(packets, false, true);

        assert_eq!(frames.len(), 2);
        let first_header = frame_header(&frames[0]);
        assert_eq!(first_header.gso_type, GsoType::VIRTIO_NET_HDR_GSO_UDP_L4);
        let first_gso_size = first_header.gso_size;
        assert_eq!(first_gso_size, 400);
        assert_eq!(segments(&frames[0]).len(), 64);
        assert_eq!(
            frame_header(&frames[1]).gso_type,
            GsoType::VIRTIO_NET_HDR_GSO_NONE
        );
        assert_eq!(ipv4_udp_payload(&frames[1]), vec![64; 400]);
    }

    /// Sum and fold network words without complementing, as CHECKSUM_PARTIAL requires.
    fn j338_fold(bytes: &[u8]) -> u16 {
        let mut sum: u32 = bytes
            .chunks(2)
            .map(|w| u32::from(w[0]) * 256 + u32::from(*w.get(1).unwrap_or(&0)))
            .sum();
        while sum >> 16 != 0 {
            sum = (sum & 65535) + (sum >> 16);
        }
        sum as u16
    }

    /// Build the pseudo-header independently of production checksum helpers.
    fn j338_pseudo(packet: &[u8]) -> Vec<u8> {
        if packet[0] >> 4 == 4 {
            let mut p = packet[12..20].to_vec();
            p.extend_from_slice(&[0, packet[9]]);
            p.extend_from_slice(&((packet.len() - 20) as u16).to_be_bytes());
            p
        } else {
            let mut p = packet[8..40].to_vec();
            p.extend_from_slice(&((packet.len() - 40) as u32).to_be_bytes());
            p.extend_from_slice(&[0, 0, 0, packet[6]]);
            p
        }
    }

    /// Make routable, checksum-valid fixture packets and optionally set PSH or a chosen IPv4 ID.
    fn j338_edit(packet: Packet<Ip>, psh: bool, id: u16) -> Packet<Ip> {
        let mut b = packet.as_bytes().to_vec();
        let v4 = b[0] >> 4 == 4;
        let h = if v4 { 20 } else { 40 };
        let tcp = b[if v4 { 9 } else { 6 }] == 6;
        if !v4 {
            b[24..40].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        }
        if psh {
            b[h + 13] |= 8;
        }
        if v4 {
            b[4..6].copy_from_slice(&id.to_be_bytes());
            b[10..12].fill(0);
            let c = !j338_fold(&b[..20]);
            b[10..12].copy_from_slice(&c.to_be_bytes());
        }
        let off = h + if tcp { 16 } else { 6 };
        b[off..off + 2].fill(0);
        let mut p = j338_pseudo(&b);
        p.extend_from_slice(&b[h..]);
        let c = !j338_fold(&p);
        b[off..off + 2].copy_from_slice(&c.to_be_bytes());
        Packet::copy_from(&b[..]).try_into_ip().unwrap()
    }

    /// Export real builder output for an independent Linux forwarding/segmentation check.
    #[test]
    #[ignore = "manual kernel segmentation proof requires J338_FRAMES output directory"]
    fn j338_export_kernel_frames() {
        let dir = std::env::var("J338_FRAMES").unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        let cases = [
            (
                "tcp4",
                vec![ipv4_tcp(1, 1000, b"first"), ipv4_tcp(1, 1005, b"other")],
            ),
            (
                "tcp6",
                vec![ipv6_tcp(1, 1000, b"first"), ipv6_tcp(1, 1005, b"other")],
            ),
            (
                "tcp4tail",
                vec![ipv4_tcp(1, 1000, b"first"), ipv4_tcp(1, 1005, b"end")],
            ),
            (
                "tcp6tail",
                vec![ipv6_tcp(1, 1000, b"first"), ipv6_tcp(1, 1005, b"end")],
            ),
            ("udp4", vec![ipv4_udp(1, b"first"), ipv4_udp(1, b"end")]),
            ("udp6", vec![ipv6_udp(1, b"first"), ipv6_udp(1, b"end")]),
        ];
        for (name, psh, ids) in [
            ("tcp4psh", true, [100, 101]),
            ("tcp4ids", false, [100, 900]),
        ] {
            let packets = vec![
                j338_edit(ipv4_tcp(1, 1000, b"first"), psh, ids[0]),
                j338_edit(ipv4_tcp(1, 1005, b"other"), psh, ids[1]),
            ];
            for (i, p) in packets.iter().enumerate() {
                std::fs::write(format!("{dir}/{name}-input{i}.ip"), p.as_bytes()).unwrap();
            }
            let frames = coalesce_packets(packets, true, true);
            assert_eq!(frames.len(), 1);
            std::fs::write(format!("{dir}/{name}.bin"), frames[0].as_bytes()).unwrap();
        }
        for (name, packets) in cases {
            let packets: Vec<_> = packets
                .into_iter()
                .enumerate()
                .map(|(i, p)| j338_edit(p, false, 100 + i as u16))
                .collect();
            for (i, p) in packets.iter().enumerate() {
                std::fs::write(format!("{dir}/{name}-input{i}.ip"), p.as_bytes()).unwrap();
            }
            let frames = coalesce_packets(packets, true, true);
            assert_eq!(frames.len(), 1);
            std::fs::write(format!("{dir}/{name}.bin"), frames[0].as_bytes()).unwrap();
        }
    }

    /// The transport checksum field must hold a folded sum, not its complement.
    #[test]
    fn j338_partial_seed_matches_linux() {
        for packets in [
            vec![ipv4_tcp(1, 1000, b"first"), ipv4_tcp(1, 1005, b"other")],
            vec![ipv6_tcp(1, 1000, b"first"), ipv6_tcp(1, 1005, b"other")],
            vec![ipv4_udp(1, b"first"), ipv4_udp(1, b"end")],
            vec![ipv6_udp(1, b"first"), ipv6_udp(1, b"end")],
        ] {
            let frames = coalesce_packets(packets, true, true);
            let f = &frames[0];
            let h = frame_header(f);
            let off = 10 + usize::from(h.csum_start) + usize::from(h.csum_offset);
            let actual = u16::from_be_bytes(f.as_bytes()[off..off + 2].try_into().unwrap());
            let expected = j338_fold(&j338_pseudo(&f.as_bytes()[10..]));
            assert_eq!(
                actual, expected,
                "CHECKSUM_PARTIAL seed must be the uncomplemented folded pseudo-header sum"
            );
        }
    }

    /// PSH on an earlier segment must end a run instead of becoming a middle PSH.
    #[test]
    fn j338_psh_cannot_appear_in_middle() {
        let packets = vec![
            j338_edit(ipv4_tcp(1, 1000, b"first"), true, 100),
            j338_edit(ipv4_tcp(1, 1005, b"other"), true, 101),
        ];
        assert_eq!(
            coalesce_packets(packets, true, true).len(),
            2,
            "PSH packet must end a coalescing run"
        );
    }

    /// Re-segmentation cannot represent arbitrary IPv4 identification changes.
    #[test]
    fn j338_nonconsecutive_ipv4_ids_stay_separate() {
        let packets = vec![
            j338_edit(ipv4_tcp(1, 1000, b"first"), false, 100),
            j338_edit(ipv4_tcp(1, 1005, b"other"), false, 900),
        ];
        assert_eq!(
            coalesce_packets(packets, true, true).len(),
            2,
            "nonconsecutive IDs cannot round-trip through GSO"
        );
    }

    /// Exercise truncations and deterministic peer-controlled mutations without timing claims.
    #[test]
    fn j338_hostile_mutation_sweep() {
        let seeds = [
            ipv4_tcp(1, 1000, b"first"),
            ipv6_tcp(1, 1000, b"first"),
            ipv4_udp(1, b"first"),
            ipv6_udp(1, b"first"),
        ];
        let mut accepted = 0;
        for seed in seeds {
            let bytes = seed.as_bytes();
            for len in 0..=bytes.len() {
                if let Ok(p) = Packet::copy_from(&bytes[..len]).try_into_ip() {
                    let _ = coalesce_packets(vec![p], true, true);
                    accepted += 1;
                }
            }
            for i in 0..bytes.len() {
                for value in 0..=255u8 {
                    let mut b = bytes.to_vec();
                    b[i] = value;
                    if let Ok(p) = Packet::copy_from(&b[..]).try_into_ip() {
                        let mut next = p.as_bytes().to_vec();
                        // Keep a parsed TCP pair contiguous so mutations reach frame construction.
                        if let Some(metadata) = super::packet_metadata(&next) {
                            if let Some(sequence) = metadata.tcp_sequence {
                                let offset = metadata.ip_header_len + 4;
                                next[offset..offset + 4].copy_from_slice(
                                    &sequence
                                        .wrapping_add(metadata.payload_len as u32)
                                        .to_be_bytes(),
                                );
                            }
                        }
                        let q = Packet::copy_from(&next[..]).try_into_ip().unwrap();
                        let _ = coalesce_packets(vec![p, q], true, true);
                        accepted += 1;
                    }
                }
            }
        }
        eprintln!("J338_MUTATION_ACCEPTED={accepted}");
    }

    /// Coalescing must stop at each header field whose value cannot be reconstructed.
    #[test]
    fn j338_header_guard_matrix() {
        let cases = [
            (8usize, 63u8),
            (1, 1),
            (12, 11),
            (16, 11),
            (20, 1),
            (22, 1),
            (32, 0x60),
            (33, 0x11),
            (33, 0x12),
            (33, 0x14),
            (33, 0x30),
            (33, 0x50),
            (6, 0x20),
            (7, 1),
        ];
        for (offset, value) in cases {
            let first = ipv4_tcp(1, 1000, b"first");
            let second = ipv4_tcp(1, 1005, b"other");
            let mut b = second.as_bytes().to_vec();
            b[offset] = value;
            let second = Packet::copy_from(&b[..]).try_into_ip().unwrap();
            assert_eq!(
                coalesce_packets(vec![first, second], true, true).len(),
                2,
                "offset {offset} value {value}"
            );
        }
        for offset in [0usize, 1, 2, 3, 7, 8, 24, 40, 42] {
            let first = ipv6_tcp(1, 1000, b"first");
            let second = ipv6_tcp(1, 1005, b"other");
            let mut b = second.as_bytes().to_vec();
            b[offset] ^= 1;
            if let Ok(second) = Packet::copy_from(&b[..]).try_into_ip() {
                assert_eq!(
                    coalesce_packets(vec![first, second], true, true).len(),
                    2,
                    "IPv6 offset {offset}"
                );
            }
        }
    }
}
