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

//! Linux TUN TSO metadata validation and TCP segment reconstruction.

use crate::packet::{
    Ip, IpNextProtocol, Ipv4, Ipv4Header, Ipv4VersionIhl, Ipv6, Ipv6Header, Packet, Tcp, TcpHeader,
    Udp, UdpHeader,
    util::{
        PseudoHeaderV4, PseudoHeaderV6, checksum_ipv4_with_skip, checksum_tcp_with_skip,
        checksum_udp_with_skip,
    },
};
use crate::tun::tun_async_device::virtio::VirtioNetHeader;
use bytes::BytesMut;
use duplicate::duplicate_item;
use either::Either;
use libc::{TUN_F_CSUM, TUN_F_TSO4, TUN_F_TSO6, TUNSETOFFLOAD};
use std::mem::offset_of;
use std::{io, os::fd::AsRawFd};
use zerocopy::{FromBytes, IntoBytes};

/// Enable TCP offloading on the given tun device
///
/// Returns `EINVAL` if TSO is not supported (pre Linux 2.6)
///
/// <https://github.com/torvalds/linux/blob/f443e374ae131c168a065ea1748feac6b2e76613/drivers/net/tun.c#L2803>
pub fn try_enable_tso(tun: &impl AsRawFd) -> io::Result<()> {
    let offload_flags = TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6;
    let tun_fd = tun.as_raw_fd();

    // SAFETY: `TUNSETOFFLOAD` takes this integer bitmask, not a pointer. The ioctl validates
    // unsupported flags and reports them as an error for the caller's software fallback.
    let status = unsafe { libc::ioctl(tun_fd, TUNSETOFFLOAD, offload_flags as libc::c_ulong) };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

#[duplicate_item(
      new_tso_iter_ipvx   IpvX   IpvXHeader   CoalescedIpvX;
     [new_tso_iter_ipv4] [Ipv4] [Ipv4Header] [CoalescedIpv4];
     [new_tso_iter_ipv6] [Ipv6] [Ipv6Header] [CoalescedIpv6];
 )]
pub fn new_tso_iter_ipvx(ipvx_packet: Packet<IpvX>, gso_size: usize) -> io::Result<TsoIter> {
    match ipvx_packet.header.next_protocol() {
        IpNextProtocol::Tcp => {
            let mut tcp_packet = ipvx_packet
                .try_into_tcp()
                .map_err(|e| io::Error::other(e.to_string()))?;

            let tcp_options_len = tcp_packet
                .payload
                .options()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid TCP options"))?
                .len();
            let payload_len = tcp_packet
                .payload
                .payload()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid TCP payload"))?
                .len();

            // virtio_net_hdr.gso_size is the TCP payload MSS. It does not include IP or TCP
            // headers, including TCP options.
            if gso_size != 0 && gso_size < payload_len {
                let header_len = IpvXHeader::LEN + TcpHeader::LEN + tcp_options_len;

                let mut packet = tcp_packet.into_bytes();

                // Split the giant packet into IP/TCP header and giant payload. The payload
                // will be segmented, and the header will be prepended to each segment.
                let headers = packet.buf_mut().split_to(header_len);
                let payload = packet;
                let mut headers = Packet::from_bytes(headers);

                // Update IP header length field
                IpvX::<Tcp>::mut_from_bytes(headers.as_mut_bytes())
                    .expect("`headers` contains Ip/Tcp headers")
                    .try_update_ip_len()
                    .expect("IP packet is not too large");

                let headers = Packet::<IpvX>::try_from(headers)
                    .and_then(|headers| headers.try_into_tcp())
                    .expect("We're copying valid IP/TCP headers");

                let segment_payload_len = gso_size;
                let segment_count = payload_len.div_ceil(segment_payload_len);
                let capacity = header_len
                    .checked_mul(segment_count)
                    .and_then(|headers_len| headers_len.checked_add(payload_len))
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "TSO packet size overflow")
                    })?;

                // TODO: segmentation should not block the next tun.read
                return Ok(TsoIter::CoalescedIpvX {
                    // TODO: consider using a pool
                    buf: BytesMut::with_capacity(capacity),
                    segment_payload_len,
                    headers,
                    payload,
                    i: 0,
                });
            }

            tcp_packet.update_tcp_checksum();

            Ok(TsoIter::SinglePacket {
                packet: Some(tcp_packet.into()),
            })
        }
        _ => Ok(TsoIter::SinglePacket {
            packet: Some(ipvx_packet.into()),
        }),
    }
}

/// Parse one TUN frame with a virtio header and return its original IP packet boundaries.
pub(super) fn new_tso_iter_from_vnet(mut frame: Packet<[u8]>) -> io::Result<TsoIter> {
    if frame.len() < VirtioNetHeader::LEN {
        return Err(invalid_vnet("truncated virtio network header"));
    }

    let header_bytes = frame.buf_mut().split_to(VirtioNetHeader::LEN);
    let header = *VirtioNetHeader::ref_from_bytes(&header_bytes)
        .map_err(|_| invalid_vnet("malformed virtio network header"))?;
    let flags = header.flags;
    let raw_gso_type = header.gso_type.bits();
    let gso_type = raw_gso_type & !0x80;
    let gso_size = usize::from(header.gso_size);
    let header_len = usize::from(header.hdr_len);
    let csum_start = usize::from(header.csum_start);
    let csum_offset = usize::from(header.csum_offset);

    if !flags.reserved_bits_are_zero() || flags.rsc_info() {
        return Err(invalid_vnet("unsupported virtio network header flags"));
    }
    if flags.needs_csum() && flags.data_valid() {
        return Err(invalid_vnet("conflicting virtio checksum flags"));
    }

    let packet = frame;
    match gso_type {
        0 => {
            if raw_gso_type & 0x80 != 0 || gso_size != 0 {
                return Err(invalid_vnet("invalid metadata for a non-GSO packet"));
            }

            let packet = if flags.needs_csum() {
                complete_partial_checksum(packet, csum_start, csum_offset)?
            } else {
                packet
                    .try_into_ip()
                    .map_err(|e| invalid_vnet_owned(e.to_string()))?
            };
            Ok(TsoIter::SinglePacket {
                packet: Some(packet),
            })
        }
        1 => {
            if gso_size == 0 {
                return Err(invalid_vnet("TCPv4 GSO size must be nonzero"));
            }

            let (_, ip_header_len, _) = ipv4_header_and_lengths(packet.as_ref())?;
            if ip_header_len > Ipv4Header::LEN {
                return new_tso_iter_ipv4_with_options(
                    packet,
                    header_len,
                    gso_size,
                    flags.needs_csum(),
                    csum_start,
                    csum_offset,
                );
            }
            if flags.needs_csum()
                && (csum_start != ip_header_len || csum_offset != offset_of!(TcpHeader, checksum))
            {
                return Err(invalid_vnet("invalid TCPv4 checksum metadata"));
            }

            let ip = packet
                .try_into_ipvx()
                .map_err(|e| invalid_vnet_owned(e.to_string()))?;
            let Either::Left(ip) = ip else {
                return Err(invalid_vnet("TCPv4 GSO metadata on a non-IPv4 packet"));
            };
            let tcp = ip
                .try_into_tcp()
                .map_err(|e| invalid_vnet_owned(e.to_string()))?;
            let tcp_options_len = tcp
                .payload
                .options()
                .ok_or_else(|| invalid_vnet("invalid TCPv4 options"))?
                .len();
            let expected_header_len = Ipv4Header::LEN + TcpHeader::LEN + tcp_options_len;
            if header_len != expected_header_len {
                return Err(invalid_vnet("invalid TCPv4 header length"));
            }
            new_tso_iter_ipv4(tcp.into(), gso_size)
        }
        4 => {
            if gso_size == 0 {
                return Err(invalid_vnet("TCPv6 GSO size must be nonzero"));
            }
            if flags.needs_csum() && (csum_start != Ipv6Header::LEN || csum_offset != 16) {
                return Err(invalid_vnet("invalid TCPv6 checksum metadata"));
            }

            let ip = packet
                .try_into_ipvx()
                .map_err(|e| invalid_vnet_owned(e.to_string()))?;
            let Either::Right(ip) = ip else {
                return Err(invalid_vnet("TCPv6 GSO metadata on a non-IPv6 packet"));
            };
            let tcp = ip
                .try_into_tcp()
                .map_err(|e| invalid_vnet_owned(e.to_string()))?;
            let tcp_options_len = tcp
                .payload
                .options()
                .ok_or_else(|| invalid_vnet("invalid TCPv6 options"))?
                .len();
            let expected_header_len = Ipv6Header::LEN + TcpHeader::LEN + tcp_options_len;
            if header_len != expected_header_len {
                return Err(invalid_vnet("invalid TCPv6 header length"));
            }
            new_tso_iter_ipv6(tcp.into(), gso_size)
        }
        _ => Err(invalid_vnet("unsupported TUN GSO type")),
    }
}

fn new_tso_iter_ipv4_with_options(
    mut packet: Packet<[u8]>,
    header_len: usize,
    gso_size: usize,
    needs_csum: bool,
    csum_start: usize,
    csum_offset: usize,
) -> io::Result<TsoIter> {
    let (ip_header, ip_header_len, total_len) = ipv4_header_and_lengths(packet.as_ref())?;
    if ip_header.fragment_offset() != 0 || ip_header.more_fragments() {
        return Err(invalid_vnet("TCPv4 GSO metadata on a fragmented packet"));
    }
    if ip_header.next_protocol() != IpNextProtocol::Tcp {
        return Err(invalid_vnet("TCPv4 GSO metadata on a non-TCP packet"));
    }
    if needs_csum && (csum_start != ip_header_len || csum_offset != offset_of!(TcpHeader, checksum))
    {
        return Err(invalid_vnet("invalid TCPv4 checksum metadata"));
    }

    let tcp_bytes = &packet.as_ref()[ip_header_len..total_len];
    let tcp = Tcp::<[u8]>::ref_from_bytes(tcp_bytes)
        .map_err(|_| invalid_vnet("truncated TCPv4 packet"))?;
    let tcp_header_len = usize::from(tcp.header.data_offset()) * 4;
    if tcp_header_len < TcpHeader::LEN || tcp_header_len > tcp_bytes.len() {
        return Err(invalid_vnet("invalid TCPv4 data offset"));
    }
    if tcp.options().is_none() || tcp.payload().is_none() {
        return Err(invalid_vnet("invalid TCPv4 options or payload"));
    }

    let expected_header_len = ip_header_len + tcp_header_len;
    if header_len != expected_header_len {
        return Err(invalid_vnet("invalid TCPv4 header length"));
    }
    let payload_len = tcp_bytes.len() - tcp_header_len;
    packet.truncate(total_len);
    let headers = Packet::from_bytes(packet.buf_mut().split_to(expected_header_len));
    let payload = packet;

    if payload_len <= gso_size {
        let mut buf = BytesMut::with_capacity(expected_header_len + payload_len);
        let packet = build_ipv4_tcp_segment(
            &mut buf,
            headers.as_ref(),
            ip_header_len,
            payload.as_ref(),
            0,
            gso_size,
            true,
        );
        return Ok(TsoIter::SinglePacket {
            packet: Some(packet),
        });
    }

    let segment_count = payload_len.div_ceil(gso_size);
    let capacity = expected_header_len
        .checked_mul(segment_count)
        .and_then(|headers_len| headers_len.checked_add(payload_len))
        .ok_or_else(|| invalid_vnet("TCPv4 TSO packet size overflow"))?;

    Ok(TsoIter::CoalescedIpv4WithOptions {
        buf: BytesMut::with_capacity(capacity),
        i: 0,
        segment_payload_len: gso_size,
        headers,
        ip_header_len,
        payload,
    })
}

/// Rebuild a TCPv4 segment from the original variable-length IP and TCP headers.
fn build_ipv4_tcp_segment(
    buf: &mut BytesMut,
    headers: &[u8],
    ip_header_len: usize,
    payload: &[u8],
    segment_index: usize,
    segment_payload_len: usize,
    is_last_segment: bool,
) -> Packet<Ip> {
    let total_len = headers.len() + payload.len();
    let total_len = u16::try_from(total_len).expect("TSO segment fits in the input IPv4 length");
    buf.clear();
    buf.extend_from_slice(headers);
    buf.extend_from_slice(payload);

    let total_len_offset = offset_of!(Ipv4Header, total_len);
    buf[total_len_offset..total_len_offset + 2].copy_from_slice(&total_len.to_be_bytes());

    let identification_offset = offset_of!(Ipv4Header, identification);
    let identification = u16::from_be_bytes(
        buf[identification_offset..identification_offset + 2]
            .try_into()
            .expect("fixed IPv4 identification field"),
    );
    buf[identification_offset..identification_offset + 2].copy_from_slice(
        &identification
            .wrapping_add(segment_index as u16)
            .to_be_bytes(),
    );

    let tcp_seq_offset = ip_header_len + offset_of!(TcpHeader, seq_num);
    let sequence = u32::from_be_bytes(
        buf[tcp_seq_offset..tcp_seq_offset + 4]
            .try_into()
            .expect("fixed TCP sequence field"),
    );
    let sequence_delta = segment_payload_len.wrapping_mul(segment_index) as u32;
    buf[tcp_seq_offset..tcp_seq_offset + 4]
        .copy_from_slice(&sequence.wrapping_add(sequence_delta).to_be_bytes());

    if !is_last_segment {
        let flags_offset = ip_header_len + offset_of!(TcpHeader, flags);
        buf[flags_offset] &= !(0x01 | 0x08); // FIN and PSH belong only to the final segment.
    }

    let tcp_checksum_offset = ip_header_len + offset_of!(TcpHeader, checksum);
    buf[tcp_checksum_offset..tcp_checksum_offset + 2].fill(0);
    let ip_header = Ipv4Header::ref_from_bytes(&buf[..Ipv4Header::LEN])
        .expect("validated IPv4 header is present");
    let tcp = Tcp::<[u8]>::ref_from_bytes(&buf[ip_header_len..])
        .expect("validated TCP header and segment payload are present");
    let pseudo_header =
        PseudoHeaderV4::from_tcp(ip_header.source_address, ip_header.destination_address, tcp);
    let tcp_checksum = checksum_tcp_with_skip(pseudo_header, tcp);
    buf[tcp_checksum_offset..tcp_checksum_offset + 2].copy_from_slice(&tcp_checksum.to_be_bytes());

    let ip_checksum_offset = offset_of!(Ipv4Header, header_checksum);
    buf[ip_checksum_offset..ip_checksum_offset + 2].fill(0);
    let ip_checksum = checksum_ipv4_with_skip(&buf[..ip_header_len]);
    buf[ip_checksum_offset..ip_checksum_offset + 2].copy_from_slice(&ip_checksum.to_be_bytes());

    Packet::from_bytes(buf.split())
        .try_into_ip()
        .expect("a rebuilt IPv4 TCP segment is a valid IP packet")
}

pub(super) fn single_packet(packet: Packet<Ip>) -> TsoIter {
    TsoIter::SinglePacket {
        packet: Some(packet),
    }
}

fn invalid_vnet(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn invalid_vnet_owned(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn ipv4_header_and_lengths(bytes: &[u8]) -> io::Result<(Ipv4Header, usize, usize)> {
    let header_bytes = bytes
        .get(..Ipv4Header::LEN)
        .ok_or_else(|| invalid_vnet("truncated IPv4 header"))?;
    let header = *Ipv4Header::ref_from_bytes(header_bytes)
        .map_err(|_| invalid_vnet("malformed IPv4 header"))?;
    if header.version() != 4 {
        return Err(invalid_vnet("TCPv4 metadata on a non-IPv4 packet"));
    }

    let header_len = usize::from(header.ihl()) * 4;
    if header_len < Ipv4Header::LEN || header_len > bytes.len() {
        return Err(invalid_vnet("invalid IPv4 header length"));
    }

    let total_len = usize::from(header.total_len);
    if total_len < header_len || total_len > bytes.len() {
        return Err(invalid_vnet("invalid IPv4 total length"));
    }

    Ok((header, header_len, total_len))
}

fn complete_partial_checksum_ipv4(
    mut packet: Packet<[u8]>,
    csum_start: usize,
    csum_offset: usize,
) -> io::Result<Packet<Ip>> {
    let (header, ip_header_len, total_len) = ipv4_header_and_lengths(packet.as_ref())?;
    if header.fragment_offset() != 0 || header.more_fragments() {
        return Err(invalid_vnet("partial checksum on a fragmented IPv4 packet"));
    }
    if csum_start != ip_header_len {
        return Err(invalid_vnet("invalid IPv4 checksum start"));
    }

    let transport = &packet.as_ref()[ip_header_len..total_len];
    let (checksum_offset, checksum) = match header.next_protocol() {
        IpNextProtocol::Tcp => {
            let checksum_offset = offset_of!(TcpHeader, checksum);
            if csum_offset != checksum_offset {
                return Err(invalid_vnet("invalid TCPv4 checksum offset"));
            }
            let tcp = Tcp::<[u8]>::ref_from_bytes(transport)
                .map_err(|_| invalid_vnet("truncated TCPv4 packet"))?;
            if tcp.payload().is_none() {
                return Err(invalid_vnet("invalid TCPv4 data offset"));
            }
            let pseudo_header =
                PseudoHeaderV4::from_tcp(header.source_address, header.destination_address, tcp);
            (checksum_offset, checksum_tcp_with_skip(pseudo_header, tcp))
        }
        IpNextProtocol::Udp => {
            let checksum_offset = offset_of!(UdpHeader, checksum);
            if csum_offset != checksum_offset {
                return Err(invalid_vnet("invalid UDPv4 checksum offset"));
            }
            let udp = Udp::<[u8]>::ref_from_bytes(transport)
                .map_err(|_| invalid_vnet("truncated UDPv4 packet"))?;
            if usize::from(udp.header.length) != transport.len() {
                return Err(invalid_vnet("invalid UDPv4 length"));
            }
            let pseudo_header =
                PseudoHeaderV4::from_udp(header.source_address, header.destination_address, udp);
            (checksum_offset, checksum_udp_with_skip(pseudo_header, udp))
        }
        _ => return Err(invalid_vnet("unsupported IPv4 partial checksum protocol")),
    };

    packet.truncate(total_len);
    let checksum_start = csum_start + checksum_offset;
    packet.buf_mut()[checksum_start..checksum_start + 2].copy_from_slice(&checksum.to_be_bytes());
    packet.buf_mut()[10..12].fill(0);
    let ip_checksum = checksum_ipv4_with_skip(&packet.as_ref()[..ip_header_len]);
    packet.buf_mut()[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    packet
        .try_into_ip()
        .map_err(|e| invalid_vnet_owned(e.to_string()))
}

fn complete_partial_checksum(
    packet: Packet<[u8]>,
    csum_start: usize,
    csum_offset: usize,
) -> io::Result<Packet<Ip>> {
    if packet.as_ref().first().is_some_and(|byte| byte >> 4 == 4) {
        return complete_partial_checksum_ipv4(packet, csum_start, csum_offset);
    }

    match packet
        .try_into_ipvx()
        .map_err(|e| invalid_vnet_owned(e.to_string()))?
    {
        Either::Left(ip) => match ip.header.next_protocol() {
            IpNextProtocol::Tcp => {
                if csum_start != Ipv4Header::LEN
                    || csum_offset != offset_of!(crate::packet::TcpHeader, checksum)
                {
                    return Err(invalid_vnet("invalid TCPv4 checksum metadata"));
                }
                let mut tcp = ip
                    .try_into_tcp()
                    .map_err(|e| invalid_vnet_owned(e.to_string()))?;
                tcp.update_tcp_checksum();
                Ok(tcp.into())
            }
            IpNextProtocol::Udp => {
                if csum_start != Ipv4Header::LEN
                    || csum_offset != offset_of!(crate::packet::UdpHeader, checksum)
                {
                    return Err(invalid_vnet("invalid UDPv4 checksum metadata"));
                }
                let mut udp = ip
                    .try_into_udp()
                    .map_err(|e| invalid_vnet_owned(e.to_string()))?;
                let pseudo_header = PseudoHeaderV4::from_udp(
                    udp.header.source_address,
                    udp.header.destination_address,
                    &udp.payload,
                );
                udp.payload.header.checksum =
                    checksum_udp_with_skip(pseudo_header, &udp.payload).into();
                Ok(udp.into())
            }
            _ => Err(invalid_vnet("unsupported IPv4 partial checksum protocol")),
        },
        Either::Right(ip) => match ip.header.next_protocol() {
            IpNextProtocol::Tcp => {
                if csum_start != Ipv6Header::LEN
                    || csum_offset != offset_of!(crate::packet::TcpHeader, checksum)
                {
                    return Err(invalid_vnet("invalid TCPv6 checksum metadata"));
                }
                let mut tcp = ip
                    .try_into_tcp()
                    .map_err(|e| invalid_vnet_owned(e.to_string()))?;
                tcp.update_tcp_checksum();
                Ok(tcp.into())
            }
            IpNextProtocol::Udp => {
                if csum_start != Ipv6Header::LEN
                    || csum_offset != offset_of!(crate::packet::UdpHeader, checksum)
                {
                    return Err(invalid_vnet("invalid UDPv6 checksum metadata"));
                }
                let mut udp = ip
                    .try_into_udp()
                    .map_err(|e| invalid_vnet_owned(e.to_string()))?;
                let pseudo_header = PseudoHeaderV6::from_udp(
                    udp.header.source_address,
                    udp.header.destination_address,
                    &udp.payload,
                );
                udp.payload.header.checksum =
                    checksum_udp_with_skip(pseudo_header, &udp.payload).into();
                Ok(udp.into())
            }
            _ => Err(invalid_vnet("unsupported IPv6 partial checksum protocol")),
        },
    }
}

/// An iterator that segments a large TCP packet into smaller TCP packets.
pub enum TsoIter {
    SinglePacket {
        packet: Option<Packet<Ip>>,
    },
    CoalescedIpv4WithOptions {
        buf: BytesMut,
        i: usize,
        segment_payload_len: usize,
        headers: Packet<[u8]>,
        ip_header_len: usize,
        payload: Packet<[u8]>,
    },
    CoalescedIpv4 {
        buf: BytesMut,

        i: usize,
        segment_payload_len: usize,

        headers: Packet<Ipv4<Tcp>>,
        payload: Packet<[u8]>,
    },
    CoalescedIpv6 {
        buf: BytesMut,

        i: usize,
        segment_payload_len: usize,

        headers: Packet<Ipv6<Tcp>>,
        payload: Packet<[u8]>,
    },
}

impl Iterator for TsoIter {
    type Item = Packet<Ip>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            TsoIter::SinglePacket { packet } => packet.take(),

            TsoIter::CoalescedIpv4WithOptions {
                buf,
                i,
                segment_payload_len,
                headers,
                ip_header_len,
                payload,
            } => {
                if payload.is_empty() {
                    return None;
                }

                let len = payload.len().min(*segment_payload_len);
                let segment_payload = payload.buf_mut().split_to(len).freeze();
                let is_last_segment = payload.is_empty();
                let packet = build_ipv4_tcp_segment(
                    buf,
                    headers.as_ref(),
                    *ip_header_len,
                    &segment_payload,
                    *i,
                    *segment_payload_len,
                    is_last_segment,
                );
                *i += 1;
                Some(packet)
            }

            TsoIter::CoalescedIpv4 {
                buf,
                i,
                segment_payload_len,
                headers,
                payload,
            } => {
                if payload.is_empty() {
                    return None;
                }

                let len = payload.len().min(*segment_payload_len);
                let segment_payload = payload.buf_mut().split_to(len).freeze();

                let is_last_segment = payload.is_empty();

                // Headers from the original TSO packet
                let ipv4_header = &headers.header;
                let tcp_header = &headers.payload.header;
                let tcp_options = headers.payload.options();
                let tcp_options = tcp_options.expect("We've validated the TCP header");

                let seq_num = (*segment_payload_len).wrapping_mul(*i) as u32;
                let seq_num = seq_num.wrapping_add(tcp_header.seq_num.get());

                // Give each emitted IPv4 datagram a distinct ID in case a segment is fragmented
                // downstream and needs reassembly.
                let identification = ipv4_header.identification.get();
                let identification = identification.wrapping_add(*i as u16);

                let total_len = (const { Ipv4Header::LEN + TcpHeader::LEN }
                    + tcp_options.len()
                    + segment_payload.len()) as u16;

                // Use them to construct the headers for this segment
                let mut segment_headers = Ipv4 {
                    header: Ipv4Header {
                        version_and_ihl: Ipv4VersionIhl::new().with_version(4).with_ihl(5),
                        dscp_and_ecn: ipv4_header.dscp_and_ecn,
                        total_len: total_len.into(),

                        identification: identification.into(),

                        // TODO: handle this field
                        // we should never receive fragmented ip packets, i *think*.
                        flags_and_fragment_offset: ipv4_header.flags_and_fragment_offset,

                        time_to_live: ipv4_header.time_to_live,

                        protocol: IpNextProtocol::Tcp,
                        header_checksum: 0.into(),

                        source_address: ipv4_header.source_address,
                        destination_address: ipv4_header.destination_address,
                    },
                    payload: TcpHeader {
                        source_port: tcp_header.source_port,
                        destination_port: tcp_header.destination_port,

                        seq_num: seq_num.into(),
                        ack_num: tcp_header.ack_num,

                        data_offset: tcp_header.data_offset,
                        flags: tcp_header.flags,
                        window: tcp_header.window,
                        checksum: 0.into(),
                        urgent_pointer: tcp_header.urgent_pointer,
                    },
                };

                if !is_last_segment {
                    segment_headers.payload.set_fin(false);
                    segment_headers.payload.set_psh(false);
                }

                // Copy the data into the large `buf` allocation and split it off into Packet.
                buf.extend_from_slice(segment_headers.as_bytes());
                buf.extend_from_slice(tcp_options);
                buf.extend_from_slice(&segment_payload);
                let packet = Packet::from_bytes(buf.split());

                let mut packet = packet
                    .try_into_ipvx()
                    .map(|either| either.expect_left("The packet is IPv4"))
                    .and_then(|packet| packet.try_into_tcp())
                    .expect("we've correctly initialized the packet");

                packet.update_tcp_checksum();
                let ip_checksum = packet.header.compute_checksum();
                packet.header.header_checksum.set(ip_checksum);

                *i += 1;

                Some(packet.into())
            }

            TsoIter::CoalescedIpv6 {
                buf,
                i,
                segment_payload_len,
                headers,
                payload,
            } => {
                if payload.is_empty() {
                    return None;
                }

                let len = payload.len().min(*segment_payload_len);
                let segment_payload = payload.buf_mut().split_to(len).freeze();

                let is_last_segment = payload.is_empty();

                // Headers from the original TSO packet
                let ipv6_header = &headers.header;
                let tcp_header = &headers.payload.header;
                let tcp_options = headers.payload.options().unwrap_or_default();

                let seq_num = (*segment_payload_len).wrapping_mul(*i) as u32;
                let seq_num = seq_num.wrapping_add(tcp_header.seq_num.get());

                // Use them to construct the headers for this segment
                let mut segment_headers = Ipv6 {
                    header: Ipv6Header {
                        version_traffic_flow: headers.header.version_traffic_flow,
                        payload_length: (TcpHeader::LEN
                            + tcp_options.len()
                            + segment_payload.len())
                        .try_into()
                        .unwrap(),

                        next_header: IpNextProtocol::Tcp,
                        hop_limit: headers.header.hop_limit,

                        source_address: ipv6_header.source_address,
                        destination_address: ipv6_header.destination_address,
                    },

                    // TODO: deduplicate with CoalescedIpv4
                    payload: TcpHeader {
                        source_port: tcp_header.source_port,
                        destination_port: tcp_header.destination_port,

                        seq_num: seq_num.into(),
                        ack_num: tcp_header.ack_num,

                        data_offset: tcp_header.data_offset,
                        flags: tcp_header.flags,
                        window: tcp_header.window,
                        checksum: 0.into(),
                        urgent_pointer: tcp_header.urgent_pointer,
                    },
                };

                if !is_last_segment {
                    segment_headers.payload.set_fin(false);
                    segment_headers.payload.set_psh(false);
                }

                // Copy the data into the large `buf` allocation and split it off into Packet.
                buf.extend_from_slice(segment_headers.as_bytes());
                buf.extend_from_slice(tcp_options);
                buf.extend_from_slice(&segment_payload);
                let packet = Packet::from_bytes(buf.split());

                let mut packet = packet
                    .try_into_ipvx()
                    .map(|either| either.expect_right("The packet is IPv6"))
                    .and_then(|packet| packet.try_into_tcp())
                    .expect("we've correctly initialized the packet");

                packet.update_tcp_checksum();

                *i += 1;

                Some(packet.into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{
        Decoder, Ipv4Decoder, Ipv4Options, Ipv6VersionTrafficFlow, UdpHeader,
        util::{checksum_ipv4_with_skip, checksum_tcp_with_skip},
    };
    use crate::tun::tun_async_device::virtio::{Flags, GsoType, VirtioNetHeader};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use zerocopy::big_endian;

    fn ipv4_tcp_packet(payload: &[u8], tcp_options: &[u8]) -> Packet<Ipv4<Tcp>> {
        assert_eq!(tcp_options.len() % 4, 0);

        let tcp_header = TcpHeader {
            source_port: 111.into(),
            destination_port: 222.into(),
            seq_num: 1000.into(),
            ack_num: 444.into(),
            data_offset: crate::packet::TcpDataOffset::new()
                .with_data_offset((5 + tcp_options.len() / 4) as u8),
            flags: crate::packet::TcpFlags::new()
                .with_ack(true)
                .with_fin(true)
                .with_psh(true),
            window: 555.into(),
            checksum: 0.into(),
            urgent_pointer: 0.into(),
        };
        let payload_len = TcpHeader::LEN + tcp_options.len() + payload.len();
        let ip_header = Ipv4Header::new_for_length(
            Ipv4Addr::new(1, 2, 3, 4),
            Ipv4Addr::new(4, 3, 2, 1),
            IpNextProtocol::Tcp,
            payload_len.try_into().unwrap(),
        );

        let mut bytes = BytesMut::with_capacity(Ipv4Header::LEN + payload_len);
        bytes.extend_from_slice(ip_header.as_bytes());
        bytes.extend_from_slice(tcp_header.as_bytes());
        bytes.extend_from_slice(tcp_options);
        bytes.extend_from_slice(payload);

        Packet::from_bytes(bytes)
            .try_into_ipvx()
            .unwrap()
            .unwrap_left()
            .try_into_tcp()
            .unwrap()
    }

    fn ipv4_packet_with_ip_options(packet: &[u8], ip_options: &[u8]) -> Packet<[u8]> {
        assert_eq!(ip_options.len() % 4, 0);
        let original_header = *Ipv4Header::ref_from_bytes(&packet[..Ipv4Header::LEN]).unwrap();
        assert_eq!(original_header.ihl(), 5);
        let ip_header_len = Ipv4Header::LEN + ip_options.len();
        let mut ip_header = original_header;
        ip_header.version_and_ihl = Ipv4VersionIhl::new()
            .with_version(4)
            .with_ihl((ip_header_len / 4) as u8);
        ip_header.total_len = (ip_header_len + packet.len() - Ipv4Header::LEN)
            .try_into()
            .unwrap();
        ip_header.header_checksum = 0.into();

        let mut bytes = BytesMut::with_capacity(ip_header_len + packet.len() - Ipv4Header::LEN);
        bytes.extend_from_slice(ip_header.as_bytes());
        bytes.extend_from_slice(ip_options);
        bytes.extend_from_slice(&packet[Ipv4Header::LEN..]);
        let checksum = checksum_ipv4_with_skip(&bytes[..ip_header_len]);
        bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
        Packet::from_bytes(bytes)
    }

    fn ipv4_tcp_packet_with_ip_options(payload: &[u8], ip_options: &[u8]) -> Packet<[u8]> {
        let packet = ipv4_tcp_packet(payload, &[]);
        ipv4_packet_with_ip_options(packet.as_bytes(), ip_options)
    }

    fn vnet_header(gso_type: GsoType, gso_size: u16, hdr_len: u16) -> VirtioNetHeader {
        VirtioNetHeader {
            flags: Flags::new(),
            gso_type,
            hdr_len,
            gso_size,
            csum_start: 0,
            csum_offset: 0,
        }
    }

    fn vnet_frame(header: VirtioNetHeader, packet: &[u8]) -> Packet<[u8]> {
        let mut frame = BytesMut::with_capacity(header.as_bytes().len() + packet.len());
        frame.extend_from_slice(header.as_bytes());
        frame.extend_from_slice(packet);
        Packet::from_bytes(frame)
    }

    fn ipv6_tcp_packet(payload: &[u8], tcp_options: &[u8]) -> Packet<Ipv6<Tcp>> {
        assert_eq!(tcp_options.len() % 4, 0);

        let tcp_header = TcpHeader {
            source_port: 111.into(),
            destination_port: 222.into(),
            seq_num: 2000.into(),
            ack_num: 444.into(),
            data_offset: crate::packet::TcpDataOffset::new()
                .with_data_offset((5 + tcp_options.len() / 4) as u8),
            flags: crate::packet::TcpFlags::new()
                .with_ack(true)
                .with_fin(true)
                .with_psh(true),
            window: 555.into(),
            checksum: 0.into(),
            urgent_pointer: 0.into(),
        };
        let payload_len = TcpHeader::LEN + tcp_options.len() + payload.len();
        let ip_header = Ipv6Header {
            version_traffic_flow: Ipv6VersionTrafficFlow::new().with_version(6),
            payload_length: payload_len.try_into().unwrap(),
            next_header: IpNextProtocol::Tcp,
            hop_limit: 42,
            source_address: big_endian::U128::new(u128::from(Ipv6Addr::LOCALHOST)),
            destination_address: big_endian::U128::new(u128::from(Ipv6Addr::UNSPECIFIED)),
        };

        let mut bytes = BytesMut::with_capacity(Ipv6Header::LEN + payload_len);
        bytes.extend_from_slice(ip_header.as_bytes());
        bytes.extend_from_slice(tcp_header.as_bytes());
        bytes.extend_from_slice(tcp_options);
        bytes.extend_from_slice(payload);

        Packet::from_bytes(bytes)
            .try_into_ipvx()
            .unwrap()
            .unwrap_right()
            .try_into_tcp()
            .unwrap()
    }

    fn ipv4_udp_packet(payload: &[u8], partial_checksum: u16) -> Packet<[u8]> {
        let udp_len = UdpHeader::LEN + payload.len();
        let udp_header = UdpHeader::new(123, 456, udp_len.try_into().unwrap(), partial_checksum);
        let ip_header = Ipv4Header::new_for_length(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            IpNextProtocol::Udp,
            udp_len.try_into().unwrap(),
        );
        let mut bytes = BytesMut::with_capacity(Ipv4Header::LEN + udp_len);
        bytes.extend_from_slice(ip_header.as_bytes());
        bytes.extend_from_slice(udp_header.as_bytes());
        bytes.extend_from_slice(payload);
        Packet::from_bytes(bytes)
    }

    #[test]
    fn tso_gso_size_is_tcp_payload_mss_and_checksums_are_valid() {
        let input_payload = b"abcdefghijklmnopqrstuvwxyz";
        let tcp_options = [1, 1, 1, 1];
        let packet = ipv4_tcp_packet(input_payload, &tcp_options);

        let header = vnet_header(
            GsoType::VIRTIO_NET_HDR_GSO_TCPV4,
            10,
            (Ipv4Header::LEN + TcpHeader::LEN + tcp_options.len()) as u16,
        );
        let mut header = header;
        header.flags = Flags::new().with_needs_csum(true);
        header.csum_start = Ipv4Header::LEN as u16;
        header.csum_offset = 16;
        let segments: Vec<_> = new_tso_iter_from_vnet(vnet_frame(header, packet.as_bytes()))
            .unwrap()
            .map(|packet| {
                packet
                    .try_into_ipvx()
                    .unwrap()
                    .unwrap_left()
                    .try_into_tcp()
                    .unwrap()
            })
            .collect();

        assert_eq!(segments.len(), 3);
        assert_eq!(
            segments
                .iter()
                .map(|packet| packet.payload.payload().unwrap())
                .collect::<Vec<_>>(),
            [b"abcdefghij".as_slice(), b"klmnopqrst", b"uvwxyz"]
        );
        assert_eq!(
            segments
                .iter()
                .map(|packet| packet.payload.header.seq_num.get())
                .collect::<Vec<_>>(),
            [1000, 1010, 1020]
        );
        assert!(segments.iter().all(|packet| {
            packet.payload.options().unwrap() == tcp_options
                && packet.calculate_tcp_checksum() == packet.payload.header.checksum.get()
                && packet.header.compute_checksum() == packet.header.header_checksum.get()
        }));
        assert!(
            segments[..2]
                .iter()
                .all(|packet| { !packet.payload.header.fin() && !packet.payload.header.psh() })
        );
        assert!(segments[2].payload.header.fin() && segments[2].payload.header.psh());
    }

    #[test]
    fn tso_ipv6_rebuilds_lengths_sequences_and_checksums() {
        let input_payload = b"abcdefghijklmnopq";
        let tcp_options = [1, 1, 1, 1];
        let packet = ipv6_tcp_packet(input_payload, &tcp_options);
        let mut header = vnet_header(
            GsoType::VIRTIO_NET_HDR_GSO_TCPV6,
            8,
            (Ipv6Header::LEN + TcpHeader::LEN + tcp_options.len()) as u16,
        );
        header.flags = Flags::new().with_needs_csum(true);
        header.csum_start = Ipv6Header::LEN as u16;
        header.csum_offset = 16;

        let segments: Vec<_> = new_tso_iter_from_vnet(vnet_frame(header, packet.as_bytes()))
            .unwrap()
            .map(|packet| {
                packet
                    .try_into_ipvx()
                    .unwrap()
                    .unwrap_right()
                    .try_into_tcp()
                    .unwrap()
            })
            .collect();

        assert_eq!(segments.len(), 3);
        assert_eq!(
            segments
                .iter()
                .map(|packet| packet.payload.payload().unwrap())
                .collect::<Vec<_>>(),
            [b"abcdefgh".as_slice(), b"ijklmnop", b"q"]
        );
        assert_eq!(
            segments
                .iter()
                .map(|packet| packet.payload.header.seq_num.get())
                .collect::<Vec<_>>(),
            [2000, 2008, 2016]
        );
        assert!(segments.iter().all(|packet| {
            packet.payload.options().unwrap() == tcp_options
                && packet.calculate_tcp_checksum() == packet.payload.header.checksum.get()
                && usize::from(packet.header.payload_length)
                    == packet.as_bytes().len() - Ipv6Header::LEN
                && packet.header.hop_limit == 42
        }));
        assert!(
            segments[..2]
                .iter()
                .all(|packet| { !packet.payload.header.fin() && !packet.payload.header.psh() })
        );
        assert!(segments[2].payload.header.fin() && segments[2].payload.header.psh());
    }

    #[test]
    fn tso_ipv4_options_are_preserved_and_checksums_rebuilt() {
        let input_payload = b"abcdefghijklmnopqrstuvwxyz";
        let ip_options = [1, 1, 1, 1];
        let packet = ipv4_tcp_packet_with_ip_options(input_payload, &ip_options);
        let ip_header_len = Ipv4Header::LEN + ip_options.len();
        let mut header = vnet_header(
            GsoType::VIRTIO_NET_HDR_GSO_TCPV4,
            10,
            (ip_header_len + TcpHeader::LEN) as u16,
        );
        header.flags = Flags::new().with_needs_csum(true);
        header.csum_start = ip_header_len as u16;
        header.csum_offset = 16;

        let segments: Vec<_> = new_tso_iter_from_vnet(vnet_frame(header, packet.as_ref()))
            .unwrap()
            .map(Packet::into_bytes)
            .collect();

        assert_eq!(segments.len(), 3);
        assert_eq!(
            segments
                .iter()
                .map(|packet| {
                    let bytes = packet.as_ref();
                    let tcp = Tcp::<[u8]>::ref_from_bytes(&bytes[ip_header_len..]).unwrap();
                    tcp.payload().unwrap().to_vec()
                })
                .collect::<Vec<_>>(),
            [
                b"abcdefghij".to_vec(),
                b"klmnopqrst".to_vec(),
                b"uvwxyz".to_vec()
            ]
        );

        for segment in &segments {
            let bytes = segment.as_ref();
            let ip: &Ipv4<Ipv4Options<[u8]>> = Ipv4Decoder::CHECK_ALL.decode_ref(bytes).unwrap();
            let tcp = Tcp::<[u8]>::ref_from_bytes(&bytes[ip_header_len..]).unwrap();
            let pseudo_header = PseudoHeaderV4::from_tcp(
                ip.header.source_address,
                ip.header.destination_address,
                tcp,
            );

            assert_eq!(ip.header.ihl(), 6);
            assert_eq!(&bytes[Ipv4Header::LEN..ip_header_len], &ip_options);
            assert_eq!(usize::from(ip.header.total_len), bytes.len());
            assert_eq!(
                tcp.header.checksum.get(),
                checksum_tcp_with_skip(pseudo_header, tcp)
            );
        }
    }

    #[test]
    fn tso_ipv4_options_at_max_packet_length_stays_within_mtu() {
        let input_payload = vec![0x5a; u16::MAX as usize - Ipv4Header::LEN - 4 - TcpHeader::LEN];
        let ip_options = [1, 1, 1, 1];
        let packet = ipv4_tcp_packet_with_ip_options(&input_payload, &ip_options);
        let ip_header_len = Ipv4Header::LEN + ip_options.len();
        let mss = 1500 - ip_header_len - TcpHeader::LEN;
        let mut header = vnet_header(
            GsoType::VIRTIO_NET_HDR_GSO_TCPV4,
            mss as u16,
            (ip_header_len + TcpHeader::LEN) as u16,
        );
        header.flags = Flags::new().with_needs_csum(true);
        header.csum_start = ip_header_len as u16;
        header.csum_offset = offset_of!(TcpHeader, checksum) as u16;

        let segments: Vec<_> = new_tso_iter_from_vnet(vnet_frame(header, packet.as_ref()))
            .unwrap()
            .collect();
        assert_eq!(segments.len(), input_payload.len().div_ceil(mss));

        let mut output_payload = Vec::with_capacity(input_payload.len());
        for segment in &segments {
            let bytes = segment.as_bytes();
            let ip: &Ipv4<Ipv4Options<[u8]>> = Ipv4Decoder::CHECK_ALL.decode_ref(bytes).unwrap();
            let tcp = Tcp::<[u8]>::ref_from_bytes(&bytes[ip_header_len..]).unwrap();
            let pseudo_header = PseudoHeaderV4::from_tcp(
                ip.header.source_address,
                ip.header.destination_address,
                tcp,
            );

            assert_eq!(bytes.len(), usize::from(ip.header.total_len));
            assert!(bytes.len() <= 1500);
            assert_eq!(&bytes[Ipv4Header::LEN..ip_header_len], &ip_options);
            assert_eq!(
                tcp.header.checksum.get(),
                checksum_tcp_with_skip(pseudo_header, tcp)
            );
            output_payload.extend_from_slice(tcp.payload().unwrap());
        }
        assert_eq!(output_payload, input_payload);
    }

    #[test]
    fn tso_ipv6_at_max_payload_length_stays_within_mtu() {
        let input_payload = vec![0xa5; u16::MAX as usize - TcpHeader::LEN];
        let packet = ipv6_tcp_packet(&input_payload, &[]);
        let mss = 1500 - Ipv6Header::LEN - TcpHeader::LEN;
        let mut header = vnet_header(
            GsoType::VIRTIO_NET_HDR_GSO_TCPV6,
            mss as u16,
            (Ipv6Header::LEN + TcpHeader::LEN) as u16,
        );
        header.flags = Flags::new().with_needs_csum(true);
        header.csum_start = Ipv6Header::LEN as u16;
        header.csum_offset = offset_of!(TcpHeader, checksum) as u16;

        let segments: Vec<_> = new_tso_iter_from_vnet(vnet_frame(header, packet.as_bytes()))
            .unwrap()
            .collect();
        assert_eq!(segments.len(), input_payload.len().div_ceil(mss));

        let mut output_payload = Vec::with_capacity(input_payload.len());
        for segment in segments {
            let tcp = segment
                .try_into_ipvx()
                .unwrap()
                .unwrap_right()
                .try_into_tcp()
                .unwrap();
            assert!(tcp.as_bytes().len() <= 1500);
            assert_eq!(
                usize::from(tcp.header.payload_length),
                tcp.as_bytes().len() - Ipv6Header::LEN
            );
            assert_eq!(
                tcp.calculate_tcp_checksum(),
                tcp.payload.header.checksum.get()
            );
            output_payload.extend_from_slice(tcp.payload.payload().unwrap());
        }
        assert_eq!(output_payload, input_payload);
    }

    #[test]
    fn vnet_header_without_gso_preserves_one_packet() {
        let packet = ipv4_tcp_packet(b"small payload", &[]);
        let header = vnet_header(GsoType::VIRTIO_NET_HDR_GSO_NONE, 0, 0);

        let packets: Vec<_> = new_tso_iter_from_vnet(vnet_frame(header, packet.as_bytes()))
            .unwrap()
            .collect();

        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].as_bytes(), packet.as_bytes());
    }

    #[test]
    fn vnet_header_completes_partial_udp_checksum_before_forwarding() {
        let packet = ipv4_udp_packet(b"odd length", 0x1234);
        let mut header = vnet_header(GsoType::VIRTIO_NET_HDR_GSO_NONE, 0, 0);
        header.flags = Flags::new().with_needs_csum(true);
        header.csum_start = Ipv4Header::LEN as u16;
        header.csum_offset = offset_of!(crate::packet::UdpHeader, checksum) as u16;

        let packets: Vec<_> = new_tso_iter_from_vnet(vnet_frame(header, packet.as_bytes()))
            .unwrap()
            .collect();
        let udp = packets
            .into_iter()
            .next()
            .unwrap()
            .try_into_ipvx()
            .unwrap()
            .unwrap_left()
            .try_into_udp()
            .unwrap();
        let pseudo_header = PseudoHeaderV4::from_udp(
            udp.header.source_address,
            udp.header.destination_address,
            &udp.payload,
        );

        assert_eq!(
            udp.payload.header.checksum.get(),
            checksum_udp_with_skip(pseudo_header, &udp.payload)
        );
    }

    #[test]
    fn vnet_header_completes_partial_udp_checksum_with_ipv4_options() {
        let ip_options = [1, 1, 1, 1];
        let base_packet = ipv4_udp_packet(b"odd length", 0x1234);
        let packet = ipv4_packet_with_ip_options(base_packet.as_ref(), &ip_options);
        let ip_header_len = Ipv4Header::LEN + ip_options.len();
        let mut header = vnet_header(GsoType::VIRTIO_NET_HDR_GSO_NONE, 0, 0);
        header.flags = Flags::new().with_needs_csum(true);
        header.csum_start = ip_header_len as u16;
        header.csum_offset = offset_of!(UdpHeader, checksum) as u16;

        let packets: Vec<_> = new_tso_iter_from_vnet(vnet_frame(header, packet.as_ref()))
            .unwrap()
            .collect();
        assert_eq!(packets.len(), 1);

        let bytes = packets[0].as_bytes();
        let ip: &Ipv4<Ipv4Options<[u8]>> = Ipv4Decoder::CHECK_ALL.decode_ref(bytes).unwrap();
        let udp = Udp::<[u8]>::ref_from_bytes(&bytes[ip_header_len..]).unwrap();
        let pseudo_header =
            PseudoHeaderV4::from_udp(ip.header.source_address, ip.header.destination_address, udp);

        assert_eq!(&bytes[Ipv4Header::LEN..ip_header_len], &ip_options);
        assert_eq!(
            udp.header.checksum.get(),
            checksum_udp_with_skip(pseudo_header, udp)
        );
    }

    #[test]
    fn vnet_header_rejects_truncated_metadata_without_panicking() {
        let err = new_tso_iter_from_vnet(Packet::copy_from(&[0u8; 9][..]))
            .err()
            .unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn vnet_header_rejects_invalid_mss_and_header_length() {
        let packet = ipv4_tcp_packet(b"payload is longer than the MSS", &[]);
        let invalid_mss = vnet_header(
            GsoType::VIRTIO_NET_HDR_GSO_TCPV4,
            0,
            (Ipv4Header::LEN + TcpHeader::LEN) as u16,
        );
        let err = new_tso_iter_from_vnet(vnet_frame(invalid_mss, packet.as_bytes()))
            .err()
            .unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        let invalid_header_len = vnet_header(
            GsoType::VIRTIO_NET_HDR_GSO_TCPV4,
            10,
            (Ipv4Header::LEN + TcpHeader::LEN + 4) as u16,
        );
        let err = new_tso_iter_from_vnet(vnet_frame(invalid_header_len, packet.as_bytes()))
            .err()
            .unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn vnet_header_rejects_invalid_ipv4_ihl_without_panicking() {
        let packet = ipv4_tcp_packet(b"payload is longer than the MSS", &[]);
        for ihl in [4, 15] {
            let mut bytes = BytesMut::from(packet.as_bytes());
            bytes[0] = 0x40 | ihl;
            let header = vnet_header(
                GsoType::VIRTIO_NET_HDR_GSO_TCPV4,
                8,
                (Ipv4Header::LEN + TcpHeader::LEN) as u16,
            );

            let err = new_tso_iter_from_vnet(vnet_frame(header, &bytes))
                .err()
                .unwrap();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        }
    }

    #[test]
    fn vnet_header_rejects_unsupported_udp_gso() {
        let packet = ipv4_tcp_packet(b"payload", &[]);
        let header = vnet_header(GsoType::VIRTIO_NET_HDR_GSO_UDP, 4, 28);

        let err = new_tso_iter_from_vnet(vnet_frame(header, packet.as_bytes()))
            .err()
            .unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn vnet_header_rejects_fragmented_tcp_gso() {
        let packet = ipv4_tcp_packet(b"payload is longer than the MSS", &[]);
        let mut bytes = BytesMut::from(packet.as_bytes());
        bytes[6] = 0x20;
        bytes[7] = 0;
        let mut header = vnet_header(
            GsoType::VIRTIO_NET_HDR_GSO_TCPV4,
            8,
            (Ipv4Header::LEN + TcpHeader::LEN) as u16,
        );
        header.flags = Flags::new().with_needs_csum(true);
        header.csum_start = Ipv4Header::LEN as u16;
        header.csum_offset = 16;

        let err = new_tso_iter_from_vnet(vnet_frame(header, &bytes))
            .err()
            .unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn vnet_header_rejects_conflicting_checksum_flags() {
        let packet = ipv4_tcp_packet(b"payload", &[]);
        let mut header = vnet_header(GsoType::VIRTIO_NET_HDR_GSO_NONE, 0, 0);
        header.flags = Flags::new().with_needs_csum(true).with_data_valid(true);

        let err = new_tso_iter_from_vnet(vnet_frame(header, packet.as_bytes()))
            .err()
            .unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
