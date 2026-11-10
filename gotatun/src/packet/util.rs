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

use std::mem::offset_of;

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, big_endian};

use crate::packet::{IpNextProtocol, Tcp, TcpHeader, Udp, UdpHeader};

/// Check that the size of type `T` is `size`. If not, panic.
///
/// Returns `size` for convenience.
pub(crate) const fn size_must_be<T>(size: usize) -> usize {
    if size_of::<T>() == size {
        size
    } else {
        panic!("Size of T is wrong!")
    }
}

/// Pseudo-header used for computing UDP and TCP checksums.
#[repr(C)]
#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
pub struct PseudoHeaderV4 {
    /// Source IP address
    pub source: big_endian::U32,
    /// Destination IP address
    pub destination: big_endian::U32,
    _zero: u8,
    /// Transport protocol
    pub protocol: IpNextProtocol,
    /// Transport header and payload size
    pub length: big_endian::U16,
}

impl PseudoHeaderV4 {
    /// Create a new [`PseudoHeaderV4`] from a [`Udp`] datagram.
    pub fn from_udp(source: big_endian::U32, destination: big_endian::U32, udp: &Udp) -> Self {
        Self::from_bytes(source, destination, IpNextProtocol::Udp, udp.as_bytes())
    }

    /// Create a new [`PseudoHeaderV4`] from a [`Udp`] datagram.
    pub fn from_tcp(source: big_endian::U32, destination: big_endian::U32, tcp: &Tcp) -> Self {
        Self::from_bytes(source, destination, IpNextProtocol::Tcp, tcp.as_bytes())
    }

    /// Create a new [`PseudoHeaderV4`] from payload.
    ///
    /// # Panics
    ///
    /// This panics if `payload` is bigger than `u16::MAX`.
    pub fn from_bytes(
        source: big_endian::U32,
        destination: big_endian::U32,
        protocol: IpNextProtocol,
        payload: &[u8],
    ) -> Self {
        Self {
            source,
            destination,
            _zero: 0,
            protocol,
            length: payload.len().try_into().unwrap(),
        }
    }
}

/// Pseudo-header used for computing UDP and TCP checksums.
#[repr(C)]
#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
pub struct PseudoHeaderV6 {
    /// Source IP address
    pub source: big_endian::U128,
    /// Destination IP address
    pub destination: big_endian::U128,
    _zero: u8,
    /// Transport protocol
    pub protocol: IpNextProtocol,
    /// Transport header and payload size
    pub length: big_endian::U16,
}

impl PseudoHeaderV6 {
    /// Create a new [`PseudoHeaderV6`] from a [`Udp`] datagram.
    pub fn from_udp(source: big_endian::U128, destination: big_endian::U128, udp: &Udp) -> Self {
        Self::from_bytes(source, destination, IpNextProtocol::Udp, udp.as_bytes())
    }

    /// Create a new [`PseudoHeaderV6`] from a [`Tcp`] datagram.
    pub fn from_tcp(source: big_endian::U128, destination: big_endian::U128, tcp: &Tcp) -> Self {
        Self::from_bytes(source, destination, IpNextProtocol::Tcp, tcp.as_bytes())
    }

    /// Create a new [`PseudoHeaderV6`] from payload.
    ///
    /// # Panics
    ///
    /// This panics if `payload` is bigger than `u16::MAX`.
    pub fn from_bytes(
        source: big_endian::U128,
        destination: big_endian::U128,
        protocol: IpNextProtocol,
        payload: &[u8],
    ) -> Self {
        Self {
            source,
            destination,
            _zero: 0,
            protocol,
            length: payload.len().try_into().unwrap(),
        }
    }
}

/// Compute an "Internet checksum"
pub fn checksum(payload: &[&[u8]]) -> u16 {
    let mut sum = 0;
    for p in payload {
        sum += checksum_payload(p);
    }
    finalize_csum(sum)
}

/// Compute an "Internet checksum" for IPv4.
/// This skips the checksum field, so it works for even if non-zero.
pub fn checksum_ipv4_with_skip(payload: &[u8]) -> u16 {
    const SKIP_WORD: usize =
        offset_of!(crate::packet::Ipv4Header, header_checksum) / size_of::<u16>();
    let sum = checksum_payload_with_skip(payload, SKIP_WORD);
    finalize_csum(sum)
}

/// Compute an "Internet checksum" with an additional header and a final
/// inversion of all bits if the checksum is all zeros. This is used for UDP checksums
/// because 0 means "no checksum" in UDP + IPv4.
pub fn checksum_udp<H: IntoBytes + Immutable>(header: H, payload: &[u8]) -> u16 {
    let csum = checksum(&[header.as_bytes(), payload]);
    if csum == 0 {
        return !0;
    }
    csum
}

/// Compute an "Internet checksum" with an additional header and a final
/// inversion of all bits if the checksum is all zeros. This is used for UDP checksums
/// because 0 means "no checksum" in UDP + IPv4.
///
/// This also skips any existing checksum field.
pub fn checksum_udp_with_skip<H: IntoBytes + Immutable>(pseudo_header: H, udp: &Udp) -> u16 {
    const SKIP_INDEX: usize = offset_of!(UdpHeader, checksum) / size_of::<u16>();
    let mut sum = checksum_payload(pseudo_header.as_bytes());
    sum += checksum_payload_with_skip(udp.as_bytes(), SKIP_INDEX);
    let csum = finalize_csum(sum);
    if csum == 0 {
        return !0;
    }
    csum
}

/// Compute an "Internet checksum" with an additional header and a final
/// inversion of all bits if the checksum is all zeros. This is used for TCP checksums
/// because 0 means "no checksum" in TCP + IPv4.
///
/// This also skips any existing checksum field.
pub fn checksum_tcp_with_skip<H: IntoBytes + Immutable>(header: H, tcp: &Tcp) -> u16 {
    const SKIP_INDEX: usize = offset_of!(TcpHeader, checksum) / size_of::<u16>();
    let mut sum = checksum_payload(header.as_bytes());
    sum += checksum_payload_with_skip(tcp.as_bytes(), SKIP_INDEX);
    finalize_csum(sum)
}

/// One's-complement sum of `bytes` read as big-endian 16-bit words, folded to 16 bits.
///
/// A trailing odd byte is padded with a zero byte, as RFC 1071 asks. The result is returned as
/// a `u32` so callers can add several partial sums before [`finalize_csum`] folds them.
///
/// This runs for every segment of every TSO frame the TUN hands us, so it is on the sender's
/// hot path (#260: about 4% of the sending endpoint's CPU before this change). It adds 8-byte
/// chunks in native byte order into a 64-bit accumulator and swaps the bytes once at the end:
/// the one's-complement sum does not depend on byte order (RFC 1071 section 2(B)), so this
/// gives exactly the big-endian word sum. The plain chunk loop is safe code that the compiler
/// vectorises on its own; it needs no intrinsics and no `unsafe`.
///
/// Each chunk adds at most 2 × (2³² − 1), so the accumulator cannot overflow below 2³⁰ chunks
/// (8 GiB), far above the 64 KiB IP packet limit.
fn checksum_payload(bytes: &[u8]) -> u32 {
    let (chunks, tail) = bytes.as_chunks::<8>();
    let mut acc: u64 = 0;
    for chunk in chunks {
        let value = u64::from_ne_bytes(*chunk);
        acc += (value & 0xffff_ffff) + (value >> 32);
    }
    let (words, odd) = tail.as_chunks::<2>();
    for word in words {
        acc += u64::from(u16::from_ne_bytes(*word));
    }
    if let [b] = odd {
        // Zero-pad if odd number of bytes. Every word above started at an even offset, so this
        // byte is the high half of its big-endian word.
        acc += u64::from(u16::from_ne_bytes([*b, 0]));
    }

    // End-around carry folding keeps a nonzero sum nonzero, so folding early gives the same
    // 16-bit value as folding once at the end.
    let mut folded = (acc & 0xffff_ffff) + (acc >> 32);
    while folded >> 16 != 0 {
        folded = (folded & 0xffff) + (folded >> 16);
    }
    let folded = u16::try_from(folded).expect("folded to 16 bits");
    u32::from(if cfg!(target_endian = "little") {
        folded.swap_bytes()
    } else {
        folded
    })
}

/// Like [`checksum_payload`], but leaves out the 16-bit word at `skip_word_index`.
///
/// Used to sum a header whose checksum field still holds an old value. The two slices around the
/// skipped word both start at even offsets, so their sums add up to the sum without it. An index
/// past the last whole word skips nothing.
fn checksum_payload_with_skip(bytes: &[u8], skip_word_index: usize) -> u32 {
    let start = skip_word_index * 2;
    match bytes.get(start + 2..) {
        Some(after) => checksum_payload(&bytes[..start]) + checksum_payload(after),
        None => checksum_payload(bytes),
    }
}

fn finalize_csum(mut sum: u32) -> u16 {
    // Wrap overflowing bits and add back
    while sum >> 16 != 0 {
        sum = (sum >> 16) + (sum & 0xffff);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Ipv4Header;
    use std::net::Ipv4Addr;

    #[test]
    fn test_ipv4_header_checksum() {
        let src_ip = Ipv4Addr::new(10, 0, 0, 1);
        let dst_ip = Ipv4Addr::new(192, 168, 1, 1);
        let mut header = Ipv4Header::new_for_length(src_ip, dst_ip, IpNextProtocol::Udp, 23);
        header.header_checksum = checksum(&[header.as_bytes()]).into();
        assert_eq!(header.header_checksum.get(), 0xAF18);
        assert_eq!(checksum(&[header.as_bytes()]), 0);
    }

    /// The word-at-a-time sum this module used before the chunked version (#260); kept here
    /// as the reference the fast version must match exactly.
    fn reference_sum(bytes: &[u8], skip_word_index: Option<usize>) -> u32 {
        let mut sum = 0u32;
        let (words, odd) = bytes.as_chunks::<2>();
        for (i, w) in words.iter().enumerate() {
            if Some(i) != skip_word_index {
                sum += u32::from(u16::from_be_bytes(*w));
            }
        }
        if let [b] = odd {
            sum += u32::from(u16::from_be_bytes([*b, 0]));
        }
        sum
    }

    /// Deterministic test bytes; no extra dependency for randomness.
    fn pseudo_random_bytes(len: usize, seed: u64) -> Vec<u8> {
        let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect()
    }

    /// The chunked sum gives exactly the old checksum for every length, odd tails, the
    /// all-0xff and all-zero edge cases, and every skipped-word position.
    #[test]
    fn chunked_sum_matches_the_word_at_a_time_reference() {
        let mut inputs: Vec<Vec<u8>> = (0..300)
            .map(|len| pseudo_random_bytes(len, len as u64))
            .collect();
        inputs.push(pseudo_random_bytes(65_535, 7));
        inputs.push(pseudo_random_bytes(65_534, 8));
        inputs.push(vec![0xff; 65_535]);
        inputs.push(vec![0; 1500]);
        for bytes in &inputs {
            assert_eq!(
                finalize_csum(checksum_payload(bytes)),
                finalize_csum(reference_sum(bytes, None)),
                "length {}",
                bytes.len()
            );
            for skip in [0, 1, 5, 8, 9, bytes.len() / 2, bytes.len() / 2 + 3] {
                assert_eq!(
                    finalize_csum(checksum_payload_with_skip(bytes, skip)),
                    finalize_csum(reference_sum(bytes, Some(skip))),
                    "length {} skip {skip}",
                    bytes.len()
                );
            }
        }
    }

    /// J466 review: the pre-2ce84c1 implementation, verbatim from 1e3674b.
    fn j466_old_payload(bytes: &[u8]) -> u32 {
        let (words, rest) = <[big_endian::U16]>::ref_from_prefix(bytes).unwrap();

        let mut sum: u32 = words.iter().map(|w| u32::from(w.get())).sum();
        if let [b] = rest {
            // Zero-pad if odd number of bytes
            sum += u32::from(u16::from_be_bytes([*b, 0]));
        }

        sum
    }

    /// J466 review: the pre-2ce84c1 skip variant, verbatim from 1e3674b.
    fn j466_old_payload_with_skip(bytes: &[u8], skip_word_index: usize) -> u32 {
        let (words, rest) = <[big_endian::U16]>::ref_from_prefix(bytes).unwrap();

        let mut sum: u32 = words
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != skip_word_index)
            .map(|(_, w)| u32::from(w.get()))
            .sum();
        if let [b] = rest {
            // Zero-pad if odd number of bytes
            sum += u32::from(u16::from_be_bytes([*b, 0]));
        }

        sum
    }

    /// J466 review: random differential fuzz of old vs new (lengths, alignment, skip, slice
    /// composition, carry-heavy fills). `J466_CSUM_ITERS` (default 1,000,000), `J466_CSUM_SEED`.
    #[test]
    #[ignore = "J466 fuzz: run with --release"]
    fn j466_checksum_differential_fuzz() {
        let iters: u64 = std::env::var("J466_CSUM_ITERS").ok().and_then(|v| v.parse().ok()).unwrap_or(1_000_000);
        let mut st: u64 = std::env::var("J466_CSUM_SEED").ok().and_then(|v| v.parse().ok()).unwrap_or(0x5eed_1234_abcd_0466);
        let mut rnd = move || { st ^= st << 13; st ^= st >> 7; st ^= st << 17; st };
        let mut buf = vec![0u8; 65_535 + 16];
        let (mut odd, mut multi, mut bytes_total) = (0u64, 0u64, 0u64);
        // Exhaustive: every 1- and 2-byte input, every 3-byte input with a fixed middle byte set.
        for a in 0..=255u8 {
            assert_eq!(finalize_csum(checksum_payload(&[a])), finalize_csum(j466_old_payload(&[a])));
            for b in 0..=255u8 {
                let x = [a, b];
                assert_eq!(finalize_csum(checksum_payload(&x)), finalize_csum(j466_old_payload(&x)));
                for c in [0u8, 1, 0x7f, 0x80, 0xfe, 0xff] {
                    let y = [a, c, b];
                    assert_eq!(finalize_csum(checksum_payload(&y)), finalize_csum(j466_old_payload(&y)));
                }
            }
        }
        for it in 0..iters {
            let r = rnd();
            let len = match r % 100 {
                0..=49 => (rnd() % 65) as usize,
                50..=79 => (rnd() % 1601) as usize,
                80..=94 => (rnd() % 9001) as usize,
                _ => (rnd() % 65_536) as usize,
            };
            let off = (rnd() % 8) as usize;
            let fill = rnd() % 6;
            for (i, byte) in buf[off..off + len].iter_mut().enumerate() {
                *byte = match fill {
                    0 => 0xff,
                    1 => 0x00,
                    2 => if i % 2 == 0 { 0xff } else { 0x00 },
                    3 => if rnd() % 16 == 0 { rnd() as u8 } else { 0xff },
                    _ => rnd() as u8,
                };
            }
            let b = &buf[off..off + len];
            bytes_total += len as u64;
            odd += (len % 2) as u64;
            assert_eq!(finalize_csum(checksum_payload(b)), finalize_csum(j466_old_payload(b)),
                "iter {it} len {len} off {off} fill {fill}");
            let skip = (rnd() % (len as u64 / 2 + 3)) as usize;
            assert_eq!(finalize_csum(checksum_payload_with_skip(b, skip)),
                finalize_csum(j466_old_payload_with_skip(b, skip)),
                "iter {it} len {len} off {off} skip {skip}");
            // Callers add several partial sums (pseudo-header + segment, `checksum(&[..])`).
            if len > 0 && it % 4 == 0 {
                multi += 1;
                let cut1 = (rnd() % (len as u64 + 1)) as usize;
                let cut2 = cut1 + (rnd() % ((len - cut1) as u64 + 1)) as usize;
                let parts = [&b[..cut1], &b[cut1..cut2], &b[cut2..]];
                let old: u32 = parts.iter().map(|p| j466_old_payload(p)).sum();
                assert_eq!(checksum(&parts), finalize_csum(old), "iter {it} cuts {cut1}/{cut2}");
            }
        }
        eprintln!("J466 checksum fuzz: iters={iters} odd_len={odd} multi_slice={multi} bytes={bytes_total} mismatches=0");
    }
}
