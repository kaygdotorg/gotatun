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
use std::{future::Future, io, mem::offset_of, ops::Deref};
use zerocopy::IntoBytes;

/// Maximum number of input packets represented by one Linux TUN GSO frame.
const MAX_GSO_SEGMENTS: usize = 64;

/// Maximum frame size accepted for a coalesced TUN write, including its virtio header.
const MAX_GSO_FRAME_LEN: usize = 64 * 1024;

/// TCP's push bit belongs only on the last segment emitted from one GSO frame.
const TCP_FLAG_PSH: u8 = 0x08;

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
    /// Whether the packet uses IPv4 or IPv6 headers.
    ip_version: IpVersion,
    /// Whether the packet carries TCP or UDP.
    protocol: TransportProtocol,
    /// Number of bytes in the IP header, including the IPv6 base header.
    ip_header_len: usize,
    /// Number of bytes in the transport header, including TCP options.
    transport_header_len: usize,
    /// Offset of the first payload byte in the original packet.
    payload_offset: usize,
    /// Number of payload bytes in the original packet.
    payload_len: usize,
    /// TCP sequence number, present only for TCP packets.
    tcp_sequence: Option<u32>,
    /// TCP control flags, present only for TCP packets.
    tcp_flags: Option<u8>,
    /// IPv4 identification value, present only for IPv4 packets.
    ipv4_identification: Option<u16>,
    /// Whether an IPv4 packet sets DF, present only for IPv4 packets.
    ipv4_dont_fragment: Option<bool>,
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
    /// Original segments kept only for a GSO frame that the TUN may reject.
    source_packets: Option<Vec<Packet<Ip>>>,
}

impl Deref for CoalescedFrame {
    type Target = Packet<[u8]>;

    /// Borrow the frame bytes for callers that only need to inspect or write the packet.
    fn deref(&self) -> &Self::Target {
        &self.frame
    }
}

impl CoalescedFrame {
    /// Split the encoded frame from the original segments retained for a refusal fallback.
    pub(super) fn into_write_parts(self) -> (Packet<[u8]>, Option<Vec<Packet<Ip>>>) {
        (self.frame, self.source_packets)
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
    let (
        ip_version,
        ip_header_len,
        total_len,
        protocol_number,
        ipv4_identification,
        ipv4_dont_fragment,
    ) = match version {
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
            (
                IpVersion::V4,
                ip_header_len,
                total_len,
                *bytes.get(9)?,
                Some(read_u16(bytes, 4)?),
                Some(fragment & 0x4000 != 0),
            )
        }
        6 => {
            if bytes.len() < Ipv6Header::LEN {
                return None;
            }
            let total_len = Ipv6Header::LEN + usize::from(read_u16(bytes, 4)?);
            if total_len != bytes.len() {
                return None;
            }
            (
                IpVersion::V6,
                Ipv6Header::LEN,
                total_len,
                *bytes.get(6)?,
                None,
                None,
            )
        }
        _ => return None,
    };

    let transport_offset = ip_header_len;
    let (protocol, transport_header_len, tcp_sequence, tcp_flags) = match protocol_number {
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
                Some(flags),
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
            (TransportProtocol::Udp, UdpHeader::LEN, None, None)
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
        tcp_flags,
        ipv4_identification,
        ipv4_dont_fragment,
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
        || (first.ip_version == IpVersion::V4 && !ipv4_identification_can_follow(last, next))
        || (first.protocol == TransportProtocol::Tcp
            && (last.tcp_flags.is_none_or(|flags| flags & TCP_FLAG_PSH != 0)
                || !tcp_flags_match_ignoring_psh(first_packet, next_packet, first)))
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

/// Check the IPv4 ID rule before merging two packets into one GSO frame.
///
/// Non-DF packets keep their original, consecutive IDs so a later fragment cannot collide with
/// another datagram. DF packets are atomic and may use different IDs.
fn ipv4_identification_can_follow(last: PacketMetadata, next: PacketMetadata) -> bool {
    match (
        last.ipv4_identification,
        last.ipv4_dont_fragment,
        next.ipv4_identification,
        next.ipv4_dont_fragment,
    ) {
        (Some(_), Some(true), Some(_), Some(true)) => true,
        (Some(last_id), Some(false), Some(next_id), Some(false)) => {
            next_id == last_id.wrapping_add(1)
        }
        _ => false,
    }
}

/// Compare TCP control flags while allowing only a trailing packet to carry PSH.
fn tcp_flags_match_ignoring_psh(first: &[u8], next: &[u8], metadata: PacketMetadata) -> bool {
    let flags_offset = metadata.ip_header_len + offset_of!(TcpHeader, flags);
    match (first.get(flags_offset), next.get(flags_offset)) {
        (Some(first), Some(next)) => *first & !TCP_FLAG_PSH == *next & !TCP_FLAG_PSH,
        _ => false,
    }
}

/// Compare IP and transport headers while ignoring fields that naturally change per segment.
///
/// Address and port bytes remain part of the comparison, so this also enforces the 5-tuple for
/// TCP and the 4-tuple for UDP. Only lengths, IPv4 IDs/checksums, TCP sequence/checksum/PSH, and
/// UDP length/checksum may differ; the IPv4 ID and TCP PSH rules are checked separately.
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
        } => (
            &[(2, 4), (4, 6), (10, 12)],
            &[
                (4, 8),
                (
                    offset_of!(TcpHeader, flags),
                    offset_of!(TcpHeader, flags) + 1,
                ),
                (16, 18),
            ],
        ),
        PacketMetadata {
            ip_version: IpVersion::V4,
            protocol: TransportProtocol::Udp,
            ..
        } => (&[(2, 4), (4, 6), (10, 12)], &[(4, 6), (6, 8)]),
        PacketMetadata {
            ip_version: IpVersion::V6,
            protocol: TransportProtocol::Tcp,
            ..
        } => (
            &[(4, 6)],
            &[
                (4, 8),
                (
                    offset_of!(TcpHeader, flags),
                    offset_of!(TcpHeader, flags) + 1,
                ),
                (16, 18),
            ],
        ),
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
        source_packets: None,
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
    if metadata.protocol == TransportProtocol::Tcp {
        let flags_offset = ip_offset + metadata.ip_header_len + offset_of!(TcpHeader, flags);
        let first_flags = bytes[flags_offset];
        let last_packet = group.last().expect("a GSO group has an input packet");
        let last_flags =
            last_packet.as_bytes()[metadata.ip_header_len + offset_of!(TcpHeader, flags)];
        // Linux uses the super-packet's PSH flag to put PSH on its final output segment.
        bytes[flags_offset] = (first_flags & !TCP_FLAG_PSH) | (last_flags & TCP_FLAG_PSH);
    }

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
        source_packets: Some(group),
    }
}

/// Write a TUN frame and retry its original packets if the kernel refuses its GSO metadata.
///
/// The retry is limited to `EINVAL` and `EOPNOTSUPP`-style errors. A rejected GSO write is atomic,
/// so writing the retained source packets individually cannot duplicate an accepted segment.
pub(super) async fn write_frame_with_fallback<F, Fut>(
    frame: CoalescedFrame,
    mut write: F,
) -> io::Result<()>
where
    F: FnMut(Packet<[u8]>) -> Fut,
    Fut: Future<Output = io::Result<()>>,
{
    let (frame_bytes, source_packets) = frame.into_write_parts();
    match write(frame_bytes).await {
        Ok(()) => Ok(()),
        Err(error) if is_tun_gso_refusal(&error) => {
            let Some(packets) = source_packets else {
                return Err(error);
            };
            let mut first_error = None;
            for packet in packets {
                let fallback = single_frame(packet).frame;
                if let Err(error) = write(fallback).await {
                    if crate::tun::is_fatal_tun_error(&error) {
                        return Err(error);
                    }
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
            first_error.map_or(Ok(()), Err)
        }
        Err(error) => Err(error),
    }
}

/// Identify errors that mean the TUN rejected this GSO frame's metadata.
fn is_tun_gso_refusal(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::InvalidInput | io::ErrorKind::Unsupported
    )
}

/// Return the folded, uncomplemented pseudo-header sum required by `CHECKSUM_PARTIAL`.
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
    sum as u16
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
            Ip, IpNextProtocol, Ipv4, Ipv4FlagsFragmentOffset, Ipv4Header, Ipv4VersionIhl, Ipv6,
            Ipv6Header, Ipv6VersionTrafficFlow, Packet, PseudoHeaderV4, PseudoHeaderV6, Tcp,
            TcpDataOffset, TcpFlags, TcpHeader, Udp, UdpHeader, checksum_ipv4_with_skip,
            checksum_udp_with_skip,
        },
        tun::tun_async_device::{
            tso,
            virtio::{GsoType, VirtioNetHeader},
        },
    };
    use bytes::BytesMut;
    use std::{
        ffi::CString,
        fs::File,
        io,
        net::{Ipv4Addr, Ipv6Addr},
        os::fd::{AsRawFd, FromRawFd, OwnedFd},
        panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
        process::Command,
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };
    use zerocopy::{FromBytes, IntoBytes, big_endian};

    /// Builds a valid IPv4 TCP packet with the selected source address and sequence number.
    fn ipv4_tcp(flow: u8, seq_num: u32, payload: &[u8]) -> Packet<Ip> {
        ipv4_tcp_with_fields(flow, seq_num, payload, 0, true, false)
    }

    /// Builds IPv4 TCP with explicit identification, DF, and PSH fields for boundary tests.
    fn ipv4_tcp_with_fields(
        flow: u8,
        seq_num: u32,
        payload: &[u8],
        identification: u16,
        dont_fragment: bool,
        psh: bool,
    ) -> Packet<Ip> {
        let tcp_header = TcpHeader {
            source_port: 111.into(),
            destination_port: 222.into(),
            seq_num: seq_num.into(),
            ack_num: 444.into(),
            data_offset: TcpDataOffset::no_options(),
            flags: TcpFlags::new().with_ack(true).with_psh(psh),
            window: 555.into(),
            checksum: 0.into(),
            urgent_pointer: 0.into(),
        };
        let tcp_len = TcpHeader::LEN + payload.len();
        let mut ip_header = Ipv4Header::new_for_length(
            Ipv4Addr::new(10, 0, 0, flow),
            Ipv4Addr::new(10, 0, 1, 1),
            IpNextProtocol::Tcp,
            tcp_len.try_into().unwrap(),
        );
        ip_header.identification = identification.into();
        ip_header.flags_and_fragment_offset =
            Ipv4FlagsFragmentOffset::new().with_dont_fragment(dont_fragment);
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
            destination_address: big_endian::U128::new(u128::from(Ipv6Addr::new(
                0xfd38, 1, 0, 0, 0, 0, 0, 1,
            ))),
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
        ipv4_udp_with_fields(flow, payload, 0, true)
    }

    /// Builds IPv4 UDP with explicit identification and DF fields for boundary tests.
    fn ipv4_udp_with_fields(
        flow: u8,
        payload: &[u8],
        identification: u16,
        dont_fragment: bool,
    ) -> Packet<Ip> {
        let udp_len = UdpHeader::LEN + payload.len();
        let udp_header = UdpHeader::new(111, 222, udp_len.try_into().unwrap(), 0);
        let mut ip_header = Ipv4Header::new_for_length(
            Ipv4Addr::new(10, 0, 0, flow),
            Ipv4Addr::new(10, 0, 1, 1),
            IpNextProtocol::Udp,
            udp_len.try_into().unwrap(),
        );
        ip_header.identification = identification.into();
        ip_header.flags_and_fragment_offset =
            Ipv4FlagsFragmentOffset::new().with_dont_fragment(dont_fragment);
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
            destination_address: big_endian::U128::new(u128::from(Ipv6Addr::new(
                0xfd38, 1, 0, 0, 0, 0, 0, 1,
            ))),
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

    /// Computes the independently expected folded pseudo-header sum used by `CHECKSUM_PARTIAL`.
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
        sum as u16
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

    /// A PSH packet can close a GSO group, but later packets must begin another frame.
    #[test]
    fn tcp_psh_packet_ends_its_gso_group() {
        let packets = vec![
            ipv4_tcp_with_fields(1, 1000, b"first", 10, true, false),
            ipv4_tcp_with_fields(1, 1005, b"push!", 11, true, true),
            ipv4_tcp_with_fields(1, 1010, b"later", 12, true, false),
        ];

        let frames = coalesce_packets(packets, true, false);

        assert_eq!(frames.len(), 2);
        assert_eq!(
            frame_header(&frames[0]).gso_type,
            GsoType::VIRTIO_NET_HDR_GSO_TCPV4
        );
        let grouped = segments(&frames[0]);
        assert_eq!(grouped.len(), 2);
        assert_eq!(grouped[0].as_bytes()[Ipv4Header::LEN + 13] & 0x08, 0);
        assert_eq!(grouped[1].as_bytes()[Ipv4Header::LEN + 13] & 0x08, 0x08);
        assert_eq!(
            frame_header(&frames[1]).gso_type,
            GsoType::VIRTIO_NET_HDR_GSO_NONE
        );
        assert_eq!(ipv4_tcp_payload(&frames[1]).as_slice(), b"later");
    }

    /// Non-DF IPv4 packets merge only while each identification follows the previous one.
    #[test]
    fn ipv4_non_df_gso_requires_consecutive_identification_values() {
        let packets = vec![
            ipv4_tcp_with_fields(1, 1000, b"first", 100, false, false),
            ipv4_tcp_with_fields(1, 1005, b"other", 101, false, false),
            ipv4_tcp_with_fields(1, 1010, b"later", 900, false, false),
        ];

        let frames = coalesce_packets(packets, true, false);

        assert_eq!(frames.len(), 2);
        assert_eq!(segments(&frames[0]).len(), 2);
        assert_eq!(
            frame_header(&frames[1]).gso_type,
            GsoType::VIRTIO_NET_HDR_GSO_NONE
        );
        assert_eq!(ipv4_tcp_payload(&frames[1]).as_slice(), b"later");
    }

    /// DF-set IPv4 packets can share a GSO frame even when their IDs differ.
    #[test]
    fn ipv4_df_gso_allows_nonconsecutive_identification_values() {
        let packets = vec![
            ipv4_tcp_with_fields(1, 1000, b"first", 100, true, false),
            ipv4_tcp_with_fields(1, 1005, b"other", 900, true, false),
        ];

        let frames = coalesce_packets(packets, true, false);

        assert_eq!(frames.len(), 1);
        assert_eq!(segments(&frames[0]).len(), 2);
    }

    /// Non-DF IPv4 UDP packets with unrelated IDs remain separate datagrams.
    #[test]
    fn ipv4_udp_non_df_gso_requires_consecutive_identification_values() {
        let packets = vec![
            ipv4_udp_with_fields(1, b"first", 100, false),
            ipv4_udp_with_fields(1, b"other", 900, false),
        ];

        let frames = coalesce_packets(packets, false, true);

        assert_eq!(frames.len(), 2);
        assert!(
            frames
                .iter()
                .all(|frame| { frame_header(frame).gso_type == GsoType::VIRTIO_NET_HDR_GSO_NONE })
        );
    }

    /// A rejected GSO write retries its exact source packets as individual `GSO_NONE` frames.
    #[tokio::test]
    async fn refused_gso_frame_retries_the_original_packets_individually() {
        let packets = vec![
            ipv4_tcp_with_fields(1, 1000, b"first", 100, true, false),
            ipv4_tcp_with_fields(1, 1005, b"other", 101, true, false),
        ];
        let expected: Vec<Vec<u8>> = packets
            .iter()
            .map(|packet| packet.as_bytes().to_vec())
            .collect();
        let frame = coalesce_packets(packets, true, false).pop().unwrap();
        let writes = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let mut writer = {
            let writes = Arc::clone(&writes);
            move |bytes: Packet<[u8]>| {
                let writes = Arc::clone(&writes);
                async move {
                    let is_gso = bytes.as_bytes()[1] != GsoType::VIRTIO_NET_HDR_GSO_NONE.bits();
                    writes.lock().unwrap().push(bytes.as_bytes().to_vec());
                    if is_gso {
                        Err(io::Error::from(io::ErrorKind::InvalidInput))
                    } else {
                        Ok(())
                    }
                }
            }
        };

        let result = super::write_frame_with_fallback(frame, &mut writer).await;

        assert!(result.is_ok());
        drop(writer);
        let writes = Arc::try_unwrap(writes).unwrap().into_inner().unwrap();
        assert_eq!(writes.len(), 3, "one refused GSO write plus two retries");
        assert_ne!(writes[0][1], GsoType::VIRTIO_NET_HDR_GSO_NONE.bits());
        for (retry, original) in writes[1..].iter().zip(expected) {
            assert_eq!(retry[1], GsoType::VIRTIO_NET_HDR_GSO_NONE.bits());
            assert_eq!(&retry[VirtioNetHeader::LEN..], original.as_slice());
        }
    }

    /// A non-refusal error is returned without retrying the source packets.
    #[tokio::test]
    async fn non_refusal_gso_error_does_not_retry_original_packets() {
        let frame = coalesce_packets(
            vec![ipv4_tcp(1, 1000, b"first"), ipv4_tcp(1, 1005, b"other")],
            true,
            false,
        )
        .pop()
        .unwrap();
        let writes = Arc::new(Mutex::new(0));
        let mut writer = {
            let writes = Arc::clone(&writes);
            move |_bytes: Packet<[u8]>| {
                let writes = Arc::clone(&writes);
                async move {
                    *writes.lock().unwrap() += 1;
                    Err(io::Error::from(io::ErrorKind::PermissionDenied))
                }
            }
        };

        let result = super::write_frame_with_fallback(frame, &mut writer).await;

        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(*writes.lock().unwrap(), 1);
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

    /// Linux splits and checksums coalesced TCP and UDP frames before forwarding them out a veth.
    #[test]
    #[ignore = "requires root, Linux network namespaces, TUN GSO, veth, and ethtool"]
    fn forwarded_gso_segments_have_valid_checksums_for_all_ip_transports() {
        assert_eq!(unsafe { libc::geteuid() }, 0, "run this proof as root");
        // SAFETY: this test runs in its own libtest worker thread; the child commands inherit the
        // new network namespace, and the worker drops it when the test returns.
        let status = unsafe { libc::unshare(libc::CLONE_NEWNET) };
        assert_eq!(
            status,
            0,
            "create isolated network namespace: {}",
            io::Error::last_os_error()
        );

        let mut configuration = tun::Configuration::default();
        configuration.tun_name("j316tn").layer(tun::Layer::L3);
        configuration.platform_config(|platform| {
            platform.ensure_root_privileges(false);
            platform.vnet_hdr(true);
        });
        let device = tun::create(&configuration).expect("open a virtio-header TUN");
        let offloads = libc::TUN_F_CSUM
            | libc::TUN_F_TSO4
            | libc::TUN_F_TSO6
            | libc::TUN_F_USO4
            | libc::TUN_F_USO6;
        // SAFETY: TUNSETOFFLOAD takes the integer flags as an ioctl argument, and `device` owns
        // the descriptor for the duration of this call.
        let status = unsafe {
            libc::ioctl(
                device.as_raw_fd(),
                libc::TUNSETOFFLOAD,
                offloads as libc::c_ulong,
            )
        };
        assert_eq!(
            status,
            0,
            "enable TCP and UDP TUN GSO: {}",
            io::Error::last_os_error()
        );

        let peer_namespace = configure_forwarding_veth();
        let capture = peer_namespace.open_packet_capture("j316vb");
        let payloads = forwarding_payloads();

        let mut tcp_v4_sequence = 50_000;
        let tcp_v4 = payloads
            .iter()
            .map(|payload| {
                let packet = ipv4_tcp_with_fields(2, tcp_v4_sequence, payload, 0, true, false);
                tcp_v4_sequence = tcp_v4_sequence.wrapping_add(payload.len() as u32);
                packet
            })
            .collect();
        let mut tcp_v6_sequence = 70_000;
        let tcp_v6 = payloads
            .iter()
            .map(|payload| {
                let packet = ipv6_tcp(2, tcp_v6_sequence, payload);
                tcp_v6_sequence = tcp_v6_sequence.wrapping_add(payload.len() as u32);
                packet
            })
            .collect();
        let cases: Vec<(&str, Vec<Packet<Ip>>, bool, bool)> = vec![
            ("IPv4 TCP", tcp_v4, true, false),
            ("IPv6 TCP", tcp_v6, true, false),
            (
                "IPv4 UDP",
                payloads
                    .iter()
                    .map(|payload| ipv4_udp_with_fields(2, payload, 0, true))
                    .collect(),
                false,
                true,
            ),
            (
                "IPv6 UDP",
                payloads
                    .iter()
                    .map(|payload| ipv6_udp(2, payload))
                    .collect(),
                false,
                true,
            ),
        ];

        for (name, packets, tcp_tso, udp_uso) in cases {
            let expected_payloads: Vec<Vec<u8>> = packets
                .iter()
                .map(|packet| wire_packet_payload(packet.as_bytes()))
                .collect();
            let mut frames = coalesce_packets(packets, tcp_tso, udp_uso);
            assert_eq!(frames.len(), 1, "{name} should be one GSO frame");
            let frame = frames.pop().unwrap();
            assert!(
                frame_header(&frame).flags.needs_csum(),
                "{name} needs checksum completion"
            );
            drain_packet_capture(capture.as_raw_fd());
            let written = device
                .send(frame.as_bytes())
                .unwrap_or_else(|error| panic!("write {name} GSO frame to TUN: {error}"));
            assert_eq!(written, frame.as_bytes().len(), "short {name} TUN write");

            let emitted = capture_forwarded_packets(capture.as_raw_fd(), expected_payloads.len());
            let capture_samples: Vec<String> = emitted
                .iter()
                .take(12)
                .map(|packet| format!("{:02x?}", &packet[..packet.len().min(80)]))
                .collect();
            assert_eq!(
                emitted.len(),
                expected_payloads.len(),
                "{name} segment count; first captured packets: {capture_samples:?}"
            );
            let actual_payloads: Vec<Vec<u8>> = emitted
                .iter()
                .map(|packet| {
                    assert_forwarded_checksums(packet, name);
                    wire_packet_payload(packet)
                })
                .collect();
            assert_eq!(
                actual_payloads, expected_payloads,
                "{name} payload or order changed"
            );
        }
    }

    /// Build a private IPv4/IPv6 forwarding route and disable veth segmentation/checksum offloads.
    fn configure_forwarding_veth() -> PeerNetworkNamespace {
        run_root_command("ip", &["link", "set", "lo", "up"]);
        run_root_command("ip", &["addr", "add", "10.0.0.254/24", "dev", "j316tn"]);
        run_root_command(
            "ip",
            &[
                "-6",
                "addr",
                "add",
                "fd38::ffff/64",
                "dev",
                "j316tn",
                "nodad",
            ],
        );
        run_root_command("ip", &["link", "set", "j316tn", "mtu", "1500", "up"]);
        run_root_command(
            "ip",
            &[
                "link", "add", "j316va", "type", "veth", "peer", "name", "j316vb",
            ],
        );
        let peer_namespace = PeerNetworkNamespace::new();
        run_root_command(
            "ip",
            &["link", "set", "j316vb", "netns", &peer_namespace.name],
        );
        run_root_command(
            "ip",
            &[
                "-n",
                &peer_namespace.name,
                "link",
                "set",
                "j316vb",
                "address",
                "02:00:00:00:00:99",
            ],
        );
        run_root_command("ip", &["link", "set", "j316va", "up"]);
        run_root_command(
            "ip",
            &["-n", &peer_namespace.name, "link", "set", "j316vb", "up"],
        );
        run_root_command(
            "ethtool",
            &[
                "-K", "j316va", "tx", "off", "tso", "off", "gso", "off", "sg", "off",
            ],
        );
        peer_namespace.run("ethtool", &["-K", "j316vb", "gro", "off", "rx", "off"]);
        run_root_command(
            "sysctl",
            &[
                "-qw",
                "net.ipv4.ip_forward=1",
                "net.ipv6.conf.all.forwarding=1",
                "net.ipv4.conf.all.rp_filter=0",
                "net.ipv4.conf.j316tn.rp_filter=0",
                "net.ipv4.conf.j316tn.forwarding=1",
                "net.ipv6.conf.j316tn.forwarding=1",
            ],
        );
        run_root_command("ip", &["route", "add", "10.0.1.0/24", "dev", "j316va"]);
        run_root_command(
            "ip",
            &["-6", "route", "add", "fd38:1::/64", "dev", "j316va"],
        );
        run_root_command(
            "ip",
            &[
                "neigh",
                "add",
                "10.0.1.1",
                "lladdr",
                "02:00:00:00:00:99",
                "dev",
                "j316va",
                "nud",
                "permanent",
            ],
        );
        run_root_command(
            "ip",
            &[
                "-6",
                "neigh",
                "add",
                "fd38:1::1",
                "lladdr",
                "02:00:00:00:00:99",
                "dev",
                "j316va",
                "nud",
                "permanent",
            ],
        );
        peer_namespace
    }

    /// A separate receive namespace prevents forwarded packets from routing back into the sender.
    struct PeerNetworkNamespace {
        name: String,
    }

    impl PeerNetworkNamespace {
        /// Create a uniquely named namespace whose mount disappears when this fixture is dropped.
        fn new() -> Self {
            let name = format!("j316-gso-{}", std::process::id());
            run_root_command("ip", &["netns", "add", &name]);
            Self { name }
        }

        /// Run a command inside the receive namespace and fail with the command's stderr.
        fn run(&self, program: &str, arguments: &[&str]) {
            let mut command = Command::new("ip");
            command.args(["netns", "exec", self.name.as_str(), program]);
            command.args(arguments);
            let output = command
                .output()
                .unwrap_or_else(|error| panic!("run {program} in {}: {error}", self.name));
            assert!(
                output.status.success(),
                "run {program} {arguments:?} in {} failed: {}",
                self.name,
                String::from_utf8_lossy(&output.stderr)
            );
        }

        /// Open an AF_PACKET socket in the peer namespace and restore the test thread's namespace.
        fn open_packet_capture(&self, interface: &str) -> OwnedFd {
            let original =
                File::open("/proc/self/ns/net").expect("open original network namespace");
            let target = File::open(format!("/run/netns/{}", self.name))
                .expect("open peer network namespace");
            // SAFETY: `target` is an open network-namespace descriptor and this test runs as root.
            let status = unsafe { libc::setns(target.as_raw_fd(), libc::CLONE_NEWNET) };
            assert_eq!(
                status,
                0,
                "enter peer network namespace: {}",
                io::Error::last_os_error()
            );

            let capture = catch_unwind(AssertUnwindSafe(|| open_packet_capture(interface)));
            // SAFETY: `original` is the open network-namespace descriptor saved before setns(2).
            let restore_status = unsafe { libc::setns(original.as_raw_fd(), libc::CLONE_NEWNET) };
            assert_eq!(
                restore_status,
                0,
                "restore original network namespace: {}",
                io::Error::last_os_error()
            );
            match capture {
                Ok(capture) => capture,
                Err(payload) => resume_unwind(payload),
            }
        }
    }

    impl Drop for PeerNetworkNamespace {
        fn drop(&mut self) {
            let _ = Command::new("ip")
                .args(["netns", "del", self.name.as_str()])
                .status();
        }
    }

    /// Run one root-only setup command and show its stderr when the kernel rejects it.
    fn run_root_command(program: &str, arguments: &[&str]) {
        let output = Command::new(program)
            .args(arguments)
            .output()
            .unwrap_or_else(|error| panic!("run {program} {arguments:?}: {error}"));
        assert!(
            output.status.success(),
            "{program} {arguments:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// Bind an AF_PACKET socket to the veth's receiving side for software-segmented frames.
    fn open_packet_capture(interface: &str) -> OwnedFd {
        let protocol = (libc::ETH_P_ALL as u16).to_be();
        // SAFETY: socket(2) receives a valid Linux packet-socket domain, type, and protocol.
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                i32::from(protocol),
            )
        };
        assert!(
            fd >= 0,
            "open AF_PACKET capture: {}",
            io::Error::last_os_error()
        );
        // SAFETY: `fd` is a newly opened descriptor owned by this function.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let name = CString::new(interface).unwrap();
        // SAFETY: `name` is NUL-terminated and lives across the interface-index lookup.
        let interface_index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        assert_ne!(interface_index, 0, "find capture interface {interface}");
        // SAFETY: zero is a valid initial value for this address structure; the fields below are
        // filled before bind(2) reads it.
        let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        address.sll_family = libc::AF_PACKET as libc::c_ushort;
        address.sll_protocol = protocol;
        address.sll_ifindex = interface_index as libc::c_int;
        // SAFETY: `address` is a complete sockaddr_ll and `fd` is an AF_PACKET socket.
        let status = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&raw const address).cast(),
                std::mem::size_of_val(&address) as libc::socklen_t,
            )
        };
        assert_eq!(
            status,
            0,
            "bind AF_PACKET capture: {}",
            io::Error::last_os_error()
        );
        fd
    }

    /// Discard setup traffic and any packets left over from the previous forwarding case.
    fn drain_packet_capture(fd: libc::c_int) {
        let mut buffer = vec![0_u8; 70_000];
        loop {
            // SAFETY: `buffer` is writable and `fd` is the live capture socket.
            let length = unsafe {
                libc::recv(
                    fd,
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if length >= 0 {
                continue;
            }
            if io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock {
                break;
            }
            panic!("drain AF_PACKET capture: {}", io::Error::last_os_error());
        }
    }

    /// Capture forwarded IPv4/IPv6 TCP/UDP packets until the expected count arrives and goes quiet.
    fn capture_forwarded_packets(fd: libc::c_int, expected_count: usize) -> Vec<Vec<u8>> {
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut packets = Vec::with_capacity(expected_count);
        let mut buffer = vec![0_u8; 70_000];
        loop {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let wait = if packets.len() >= expected_count {
                100
            } else {
                500
            };
            let mut poll_fd = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: `poll_fd` points to one initialized descriptor and is valid for this call.
            let ready = unsafe { libc::poll(&mut poll_fd, 1, wait) };
            if ready < 0 {
                if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                panic!("poll AF_PACKET capture: {}", io::Error::last_os_error());
            }
            if ready == 0 {
                if packets.len() >= expected_count {
                    break;
                }
                continue;
            }

            // SAFETY: `buffer` is writable and `sender` is a sockaddr_ll-sized output buffer.
            let (length, sender) = unsafe {
                let mut sender: libc::sockaddr_ll = std::mem::zeroed();
                let mut sender_len = std::mem::size_of_val(&sender) as libc::socklen_t;
                let length = libc::recvfrom(
                    fd,
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    libc::MSG_DONTWAIT,
                    (&raw mut sender).cast(),
                    &mut sender_len,
                );
                (length, sender)
            };
            if length < 0 {
                if io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock {
                    continue;
                }
                panic!("read AF_PACKET capture: {}", io::Error::last_os_error());
            }
            if sender.sll_pkttype == libc::PACKET_OUTGOING as u8 || length < 14 {
                continue;
            }
            let frame = &buffer[..length as usize];
            let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
            if !matches!(ethertype, 0x0800 | 0x86dd) {
                continue;
            }
            let packet = &frame[14..];
            let (packet_length, protocol) = match packet.first().map(|byte| byte >> 4) {
                Some(4) if packet.len() >= 20 => (
                    usize::from(u16::from_be_bytes([packet[2], packet[3]])),
                    packet[9],
                ),
                Some(6) if packet.len() >= Ipv6Header::LEN => (
                    Ipv6Header::LEN + usize::from(u16::from_be_bytes([packet[4], packet[5]])),
                    packet[6],
                ),
                _ => continue,
            };
            if !matches!(protocol, 6 | 17) || packet_length > packet.len() {
                continue;
            }
            packets.push(packet[..packet_length].to_vec());
        }
        packets
    }

    /// Create distinct full and final-short payloads so segmentation order is observable.
    fn forwarding_payloads() -> Vec<Vec<u8>> {
        [1000, 1000, 1000, 400]
            .into_iter()
            .enumerate()
            .map(|(packet_index, length)| {
                (0..length)
                    .map(|byte_index| ((packet_index * 53 + byte_index * 17) % 251) as u8)
                    .collect()
            })
            .collect()
    }

    /// Return a direct TCP or UDP payload from a complete IPv4/IPv6 packet.
    fn wire_packet_payload(packet: &[u8]) -> Vec<u8> {
        let (ip_header_len, protocol, total_len) = match packet.first().map(|byte| byte >> 4) {
            Some(4) => (
                usize::from(packet[0] & 0x0f) * 4,
                packet[9],
                usize::from(u16::from_be_bytes([packet[2], packet[3]])),
            ),
            Some(6) => (
                Ipv6Header::LEN,
                packet[6],
                Ipv6Header::LEN + usize::from(u16::from_be_bytes([packet[4], packet[5]])),
            ),
            _ => panic!("unsupported forwarded IP packet"),
        };
        let transport = &packet[ip_header_len..total_len];
        let header_len = match protocol {
            6 => usize::from(transport[12] >> 4) * 4,
            17 => UdpHeader::LEN,
            other => panic!("unexpected forwarded IP protocol {other}"),
        };
        let payload_len = if protocol == 17 {
            usize::from(u16::from_be_bytes([transport[4], transport[5]])) - UdpHeader::LEN
        } else {
            transport.len() - header_len
        };
        transport[header_len..header_len + payload_len].to_vec()
    }

    /// Verify IPv4 header and TCP/UDP pseudo-header checksums independently of GotaTun's helpers.
    fn assert_forwarded_checksums(packet: &[u8], case: &str) {
        let version = packet[0] >> 4;
        let (ip_header_len, protocol, total_len) = match version {
            4 => (
                usize::from(packet[0] & 0x0f) * 4,
                packet[9],
                usize::from(u16::from_be_bytes([packet[2], packet[3]])),
            ),
            6 => (
                Ipv6Header::LEN,
                packet[6],
                Ipv6Header::LEN + usize::from(u16::from_be_bytes([packet[4], packet[5]])),
            ),
            _ => panic!("{case} emitted a non-IP packet"),
        };
        assert_eq!(total_len, packet.len(), "{case} IP length");
        if version == 4 {
            assert_eq!(
                folded_checksum_sum(&packet[..ip_header_len]),
                0xffff,
                "{case} IPv4 header checksum"
            );
        }
        assert!(matches!(protocol, 6 | 17), "{case} transport protocol");
        let transport = &packet[ip_header_len..total_len];
        let mut pseudo = Vec::new();
        if version == 4 {
            pseudo.extend_from_slice(&packet[12..20]);
            pseudo.extend_from_slice(&[0, protocol]);
            pseudo.extend_from_slice(&(transport.len() as u16).to_be_bytes());
        } else {
            pseudo.extend_from_slice(&packet[8..40]);
            pseudo.extend_from_slice(&(transport.len() as u32).to_be_bytes());
            pseudo.extend_from_slice(&[0, 0, 0, protocol]);
        }
        if protocol == 17 {
            assert_eq!(
                usize::from(u16::from_be_bytes([transport[4], transport[5]])),
                transport.len(),
                "{case} UDP length"
            );
            assert_ne!(
                u16::from_be_bytes([transport[6], transport[7]]),
                0,
                "{case} UDP checksum"
            );
        }
        pseudo.extend_from_slice(transport);
        assert_eq!(
            folded_checksum_sum(&pseudo),
            0xffff,
            "{case} transport checksum"
        );
    }

    /// Fold one's-complement 16-bit network words without applying the final complement.
    fn folded_checksum_sum(bytes: &[u8]) -> u16 {
        let mut sum = 0_u32;
        for word in bytes.chunks(2) {
            let value = if word.len() == 2 {
                u16::from_be_bytes([word[0], word[1]])
            } else {
                u16::from(word[0]) << 8
            };
            sum += u32::from(value);
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        sum as u16
    }
}
