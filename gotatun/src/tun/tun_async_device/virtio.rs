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

//! Implementation of the Virtio net header.
//!
//! The header can be enabled on TUN devices using the [libc::IFF_VNET_HDR]-flag,
//! or using [tun::PlatformConfig::vnet_hdr], and enables use of GSO.

use bitfield_struct::bitfield;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

/// See [module](self) docs.
///
/// Definition in linux include/uapi/linux/virtio_net.h
#[repr(C, packed)]
#[derive(
    Clone, Copy, Debug, FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable, PartialEq, Eq,
)]
pub struct VirtioNetHeader {
    pub flags: Flags,

    pub gso_type: GsoType,

    /// Ethernet + IP + tcp/udp headers
    pub hdr_len: u16,

    /// Bytes to append to `hdr_len` per frame
    pub gso_size: u16,

    /// Position to start checksumming from
    pub csum_start: u16,

    /// Offset after that to place checksum
    pub csum_offset: u16,
}

impl VirtioNetHeader {
    /// Size of the Linux TUN virtio network header.
    pub const LEN: usize = 10;
}

/// A field of [VirtioNetHeader].
#[repr(transparent)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable, PartialEq, Eq)]
pub struct GsoType(u8);

impl GsoType {
    /// Not a GSO frame
    pub const VIRTIO_NET_HDR_GSO_NONE: GsoType = GsoType(0);

    /// GSO frame, IPv4 TCP (TSO)
    pub const VIRTIO_NET_HDR_GSO_TCPV4: GsoType = GsoType(1);

    /// GSO frame, IPv4 UDP (UFO)
    pub const VIRTIO_NET_HDR_GSO_UDP: GsoType = GsoType(3);

    /// GSO frame, IPv6 TCP
    pub const VIRTIO_NET_HDR_GSO_TCPV6: GsoType = GsoType(4);

    /// GSO frame, IPv4& IPv6 UDP (USO)
    pub const VIRTIO_NET_HDR_GSO_UDP_L4: GsoType = GsoType(5);

    /// TCP has ECN set
    pub const VIRTIO_NET_HDR_GSO_ECN: GsoType = GsoType(0x80);

    /// Return the raw Linux UAPI value.
    pub const fn bits(self) -> u8 {
        self.0
    }
}

impl std::fmt::Debug for GsoType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match *self {
            GsoType::VIRTIO_NET_HDR_GSO_NONE => "VIRTIO_NET_HDR_GSO_NONE ",
            GsoType::VIRTIO_NET_HDR_GSO_TCPV4 => "VIRTIO_NET_HDR_GSO_TCPV4 ",
            GsoType::VIRTIO_NET_HDR_GSO_UDP => "VIRTIO_NET_HDR_GSO_UDP",
            GsoType::VIRTIO_NET_HDR_GSO_TCPV6 => "VIRTIO_NET_HDR_GSO_TCPV6",
            GsoType::VIRTIO_NET_HDR_GSO_UDP_L4 => "VIRTIO_NET_HDR_GSO_UDP_L4",
            GsoType::VIRTIO_NET_HDR_GSO_ECN => "VIRTIO_NET_HDR_GSO_ECN",
            GsoType(..) => "UNKNOWN_GSO_TYPE",
        };

        f.debug_tuple(name).field(&self.0).finish()
    }
}

/// A field of [VirtioNetHeader].
#[bitfield(u8)]
#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable, PartialEq, Eq)]
pub struct Flags {
    /// Use csum_start, csum_offset
    pub needs_csum: bool,
    /// Csum is valid
    pub data_valid: bool,
    /// rsc info in csum_ fields
    pub rsc_info: bool,

    #[bits(5)]
    _reserved: u8,
}

impl Flags {
    /// Check the reserved bits that this implementation does not support.
    pub fn reserved_bits_are_zero(&self) -> bool {
        self.as_bytes()[0] & 0b1111_1000 == 0
    }
}
