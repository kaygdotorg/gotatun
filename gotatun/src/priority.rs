// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

//! Replies jump ahead of bulk data in the packet task's queues (#260, J720).
//!
//! A bulk transfer fills GotaTun's own FIFOs (the TUN read-ahead and, on macOS, the buffered UDP
//! receive queue). A probe reply or a TCP ACK that lands behind them waits for every bulk packet
//! ahead of it, although it carries no data and delays the sender's clock. The kernel's own
//! interface queue (fq_codel) already serves such sparse flows first; once packets move into
//! GotaTun's FIFOs that ordering is lost. This module restores it:
//!
//! - [`ip_is_reply`] picks inner IP packets that may overtake bulk data: pure TCP ACKs (no
//!   payload, no SYN, FIN or RST, so the TCP state machine never sees a reordered control
//!   segment) and non-TCP packets of at most [`REPLY_MAX`] bytes (pings, small UDP, ICMPv6).
//! - [`datagram_is_reply`] picks small encrypted datagrams (WireGuard data with a small inner
//!   packet, handshakes, cookies, keepalives).
//! - [`replies_first`] moves those to the front of a batch, keeping order inside each class.
//!
//! Reordering limits: a pure ACK overtaking data of its own connection is harmless (ACKs carry
//! no sequence space). A small UDP datagram can overtake a large one of the same flow; UDP
//! promises no order. A small encrypted datagram can overtake up to one receive queue of bulk
//! datagrams of the same session, far inside WireGuard's replay window.
//!
//! Bench switch: `GOTATUN_BENCH_REPLIES_FIRST` = `tun`, `udp` or `both`. Unset, nothing moves.

use std::sync::OnceLock;

/// Largest packet (inner IP or encrypted datagram) that counts as a reply.
///
/// A pure ACK is 40-72 bytes of inner IP, and a WireGuard data message adds 32 bytes plus
/// padding to 16, so 256 covers ACKs and small probes on both families while every bulk
/// segment (MTU-sized) stays in the bulk class.
pub(crate) const REPLY_MAX: usize = 256;

const TCP: u8 = 6;
const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;

/// Which queues let replies jump ahead, read once from `GOTATUN_BENCH_REPLIES_FIRST`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Mode {
    /// Reorder the TUN read-ahead batch (the send path).
    pub(crate) tun: bool,
    /// Give small received datagrams their own lane (the receive path, non-Linux only).
    pub(crate) udp: bool,
}

impl Mode {
    /// Parse the switch value; anything unknown leaves both queues as they are.
    pub(crate) fn parse(value: Option<&str>) -> Self {
        match value {
            Some("tun") => Self {
                tun: true,
                udp: false,
            },
            Some("udp") => Self {
                tun: false,
                udp: true,
            },
            Some("both") => Self {
                tun: true,
                udp: true,
            },
            _ => Self::default(),
        }
    }
}

/// The process-wide mode, read from the environment on first use.
pub(crate) fn mode() -> Mode {
    static MODE: OnceLock<Mode> = OnceLock::new();
    *MODE.get_or_init(|| {
        let value = std::env::var("GOTATUN_BENCH_REPLIES_FIRST").ok();
        let mode = Mode::parse(value.as_deref());
        if mode != Mode::default() {
            eprintln!("diag replies_first tun={} udp={}", mode.tun, mode.udp);
        }
        mode
    })
}

/// Whether an inner IP packet may overtake bulk data (see the module docs).
pub(crate) fn ip_is_reply(packet: &[u8]) -> bool {
    let Some(&first) = packet.first() else {
        return false;
    };
    let (protocol, transport, total) = match first >> 4 {
        4 => {
            if packet.len() < 20 {
                return false;
            }
            let header = usize::from(first & 0x0f) * 4;
            let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
            (packet[9], header, total)
        }
        6 => {
            if packet.len() < 40 {
                return false;
            }
            let payload = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
            (packet[6], 40, 40 + payload)
        }
        _ => return false,
    };
    if protocol != TCP {
        return total <= REPLY_MAX;
    }
    let Some(tcp) = packet.get(transport..) else {
        return false;
    };
    if tcp.len() < 20 {
        return false;
    }
    let tcp_header = usize::from(tcp[12] >> 4) * 4;
    let flags = tcp[13];
    total == transport + tcp_header && flags & (TCP_FIN | TCP_SYN | TCP_RST) == 0
}

/// Whether an encrypted datagram of `len` bytes may overtake bulk datagrams.
pub(crate) fn datagram_is_reply(len: usize) -> bool {
    len <= REPLY_MAX
}

/// Move every item `is_reply` picks to the front of `items`, keeping order inside each class.
///
/// Allocates only when the batch mixes both classes, which is exactly when it helps.
pub(crate) fn replies_first<T>(items: &mut Vec<T>, is_reply: impl Fn(&T) -> bool) {
    let Some(first_bulk) = items.iter().position(|item| !is_reply(item)) else {
        return;
    };
    if !items[first_bulk..].iter().any(&is_reply) {
        return;
    }
    let rest = items.split_off(first_bulk);
    let mut bulk = Vec::with_capacity(rest.len());
    for item in rest {
        if is_reply(&item) {
            items.push(item);
        } else {
            bulk.push(item);
        }
    }
    items.append(&mut bulk);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// IPv4 TCP segment with `payload` bytes and `flags`.
    fn tcp4(payload: usize, flags: u8) -> Vec<u8> {
        let total = 20 + 32 + payload;
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[9] = TCP;
        p[20 + 12] = 8 << 4; // 32-byte TCP header (timestamps)
        p[20 + 13] = flags;
        p
    }

    /// IPv6 packet with `next` header and `payload` bytes after the fixed header.
    fn ip6(next: u8, payload: usize, tcp_flags: u8) -> Vec<u8> {
        let mut p = vec![0u8; 40 + payload];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&(payload as u16).to_be_bytes());
        p[6] = next;
        if next == TCP {
            p[40 + 12] = 5 << 4;
            p[40 + 13] = tcp_flags;
        }
        p
    }

    fn udp4(total: usize) -> Vec<u8> {
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[9] = 17;
        p
    }

    #[test]
    fn pure_acks_and_small_packets_are_replies() {
        assert!(ip_is_reply(&tcp4(0, 0x10)));
        assert!(
            ip_is_reply(&tcp4(0, 0x18)),
            "PSH+ACK without data is still a pure ACK"
        );
        assert!(ip_is_reply(&ip6(TCP, 20, 0x10)));
        assert!(ip_is_reply(&udp4(124)));
        assert!(ip_is_reply(&ip6(58, 64, 0)), "ICMPv6 echo");
    }

    #[test]
    fn data_and_control_segments_stay_in_order() {
        assert!(
            !ip_is_reply(&tcp4(1, 0x18)),
            "any TCP payload keeps its place"
        );
        assert!(!ip_is_reply(&tcp4(1348, 0x10)));
        assert!(!ip_is_reply(&tcp4(0, 0x11)), "FIN");
        assert!(!ip_is_reply(&tcp4(0, 0x12)), "SYN+ACK");
        assert!(!ip_is_reply(&tcp4(0, 0x14)), "RST+ACK");
        assert!(!ip_is_reply(&ip6(TCP, 20 + 1200, 0x10)));
        assert!(!ip_is_reply(&udp4(1400)));
        assert!(!ip_is_reply(&[]));
        assert!(!ip_is_reply(&[0x45; 10]), "truncated header");
    }

    #[test]
    fn small_datagrams_are_replies() {
        assert!(datagram_is_reply(32), "keepalive");
        assert!(datagram_is_reply(148), "handshake initiation");
        assert!(!datagram_is_reply(1452));
    }

    #[test]
    fn replies_move_ahead_in_a_stable_order() {
        let mut items = vec![1000, 1, 1001, 2, 1002, 3];
        replies_first(&mut items, |&x| x < 100);
        assert_eq!(items, [1, 2, 3, 1000, 1001, 1002]);

        let mut sorted = vec![1, 2, 1000];
        replies_first(&mut sorted, |&x| x < 100);
        assert_eq!(sorted, [1, 2, 1000]);

        let mut bulk = vec![1000, 1001];
        replies_first(&mut bulk, |&x| x < 100);
        assert_eq!(bulk, [1000, 1001]);
    }

    #[test]
    fn the_switch_is_off_unless_named() {
        assert_eq!(Mode::parse(None), Mode::default());
        assert_eq!(Mode::parse(Some("yes")), Mode::default());
        assert!(Mode::parse(Some("tun")).tun && !Mode::parse(Some("tun")).udp);
        assert!(Mode::parse(Some("udp")).udp && !Mode::parse(Some("udp")).tun);
        assert_eq!(
            Mode::parse(Some("both")),
            Mode {
                tun: true,
                udp: true
            }
        );
    }
}
