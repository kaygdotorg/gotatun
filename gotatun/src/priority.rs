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
//! On by default for the send path (#260, J1143): the TUN read-ahead (`tun`) and the UDP send
//! queue (`tx`). Three paired cross-VM holds (equal rate 2.0 Gbit/s and full speed, CUBIC and
//! BBR, 1 and 8 flows) kept throughput within 1% and lowered the loaded median of both an ICMP
//! probe and a keystroke-sized TCP request/response. The receive lane (`udp`, non-Linux only)
//! was not measured there, so it stays opt-in.
//!
//! Switch: `GOTATUN_REPLIES_FIRST` = `off` (every queue stays a FIFO), or a comma list of
//! `tun`, `udp` and `tx`, or `both` (`tun,udp`) or `all`. Unset or empty means the default.
//! A value it does not understand turns every lane off, so a mistyped "no" never leaves the
//! reordering on.

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

/// Which queues let replies jump ahead, read once from `GOTATUN_REPLIES_FIRST`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Mode {
    /// Reorder the TUN read-ahead batch (the send path).
    pub(crate) tun: bool,
    /// Give small received datagrams their own lane (the receive path, non-Linux only).
    pub(crate) udp: bool,
    /// Give small encrypted datagrams their own lane in the UDP send queue (the send path).
    pub(crate) tx: bool,
}

impl Mode {
    /// Every lane off: each queue is a plain FIFO.
    pub(crate) const OFF: Self = Self {
        tun: false,
        udp: false,
        tx: false,
    };

    /// The default when the switch is unset: both send-path lanes, measured in #260 (J1143).
    pub(crate) const DEFAULT: Self = Self {
        tun: true,
        udp: false,
        tx: true,
    };

    /// Parse the switch value: unset or empty gives [`Self::DEFAULT`]; `off` gives
    /// [`Self::OFF`]; otherwise a comma list of `tun`, `udp` and `tx`, or `both` (`tun,udp`) or
    /// `all`. Anything unknown gives [`Self::OFF`], the behaviour before the lanes existed.
    pub(crate) fn parse(value: Option<&str>) -> Self {
        let value = value.unwrap_or_default().trim();
        if value.is_empty() {
            return Self::DEFAULT;
        }
        let mut mode = Self::OFF;
        for part in value.split(',') {
            match part {
                "tun" => mode.tun = true,
                "udp" => mode.udp = true,
                "tx" => mode.tx = true,
                "both" => (mode.tun, mode.udp) = (true, true),
                "all" => (mode.tun, mode.udp, mode.tx) = (true, true, true),
                _ => return Self::OFF,
            }
        }
        mode
    }
}

/// The process-wide mode, read from the environment on first use.
///
/// Prints one `diag replies_first` line when the result differs from [`Mode::DEFAULT`], so a
/// run that turned the lanes off (or changed them) says so in its log.
pub(crate) fn mode() -> Mode {
    static MODE: OnceLock<Mode> = OnceLock::new();
    *MODE.get_or_init(|| {
        let value = std::env::var("GOTATUN_REPLIES_FIRST").ok();
        let mode = Mode::parse(value.as_deref());
        if mode != Mode::DEFAULT {
            eprintln!(
                "diag replies_first tun={} udp={} tx={}",
                mode.tun, mode.udp, mode.tx
            );
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
    fn the_send_lanes_are_on_unless_turned_off() {
        let on = |tun, udp, tx| Mode { tun, udp, tx };
        assert_eq!(Mode::parse(None), on(true, false, true), "unset = default");
        assert_eq!(Mode::parse(Some("")), Mode::DEFAULT);
        assert_eq!(Mode::parse(Some(" ")), Mode::DEFAULT);
        assert_eq!(Mode::parse(Some("off")), Mode::OFF);
        assert_eq!(Mode::parse(Some("yes")), Mode::OFF, "unknown = off");
        assert_eq!(Mode::parse(Some("0")), Mode::OFF);
        assert_eq!(Mode::parse(Some("tun,nope")), Mode::OFF);
        assert_eq!(Mode::parse(Some("tun")), on(true, false, false));
        assert_eq!(Mode::parse(Some("udp")), on(false, true, false));
        assert_eq!(Mode::parse(Some("tx")), on(false, false, true));
        assert_eq!(Mode::parse(Some("both")), on(true, true, false));
        assert_eq!(Mode::parse(Some("tun,tx")), on(true, false, true));
        assert_eq!(Mode::parse(Some("all")), on(true, true, true));
    }
}
