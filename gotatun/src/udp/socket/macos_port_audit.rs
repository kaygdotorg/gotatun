// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

//! Who holds a UDP port, from the kernel's list of UDP sockets (`net.inet.udp.pcblist_n`, the
//! list `netstat` reads; any user may read it).
//!
//! The kernel builds the list while holding the UDP socket table's lock, the same lock every
//! `bind` takes, so a bind that has returned is in the list (J815, xnu `get_pcblist_n`). Closed
//! sockets are left out.
//!
//! [`ensure_alone`] uses it right after a single WireGuard socket binds with connected sends off:
//! xnu can let that exclusive bind succeed beside a socket another user bound to the port earlier
//! with `SO_REUSEPORT` (J827 measured `0.0.0.0:<port>` beside a dual-stack `[::]:<port>`, and `::1`
//! beside an IPv4-only `0.0.0.0:<port>`) (#260, J815, J827). The product's dual-stack bind is a
//! per-family pair instead (`UdpSocket::bind_split`, J834), which the kernel alone keeps closed,
//! so it does not use this check. The reader and parser are J815's, shared
//! with the connected-send pool's audit (`j815-mac-socket-pool`), so one review covers both.
//!
//! **macOS 27 hides other processes' sockets (J1108).** On macOS 27.2.1 the list a program of
//! ours reads holds only its own sockets: before our bind it is just the header and trailer,
//! after it one record, ours, while a socket another process holds on the same port (same user)
//! is missing. Developer ID signing does not change that. Apple's own tools (`netstat`, Apple's
//! `python3` and `perl`) still read every socket, and macOS 26.5.2 shows every socket to us too.
//! A list like that proves nothing about other processes, yet it still shows our own socket, so
//! the layout check below would let it through. [`PortUsers::sees_other_processes`] tells the
//! two apart: every real Mac has UDP sockets of other processes (at least the DNS responder's),
//! so a list with none of them is a filtered one. Each user decides what that means for its
//! own claim: [`ensure_alone`] here, and the connected-send pool's audit, which then opens no
//! window.
//!
//! **Private layout.** The record offsets below are xnu's `xinpcb_n`/`xsocket_n` layout, which is
//! not public API. [`ensure_alone`] therefore fails closed: if our own bound socket is not in the
//! list, the layout is not recognised and the bind is refused, never let through unchecked. The
//! tests check the offsets against our own sockets on every run, so a macOS that moves them fails
//! the suite before it fails a user.

use std::{ffi::CStr, io};

/// Refuse a WireGuard socket bound **without** `SO_REUSEPORT` (connected sends off) if any other
/// socket is on its port: such a socket was there before us, on an address the kernel let us bind
/// beside, and would receive some of the port's datagrams.
///
/// One read of the kernel's socket list per bind (median 20 µs on the Mac VM, J827). It
/// fails closed: `EADDRINUSE` when someone else is on the port, `InvalidData` when our own socket
/// is not in the list (the private record layout is not recognised), and the read's own error
/// when the list cannot be read.
///
/// It checks the port once, at bind time, and nothing later. That covers the sockets that
/// were there before us. It does **not** cover the whole socket life: xnu lets another user
/// bind an AF_INET6 socket to `::ffff:0.0.0.0:<port>` beside our dual-stack `[::]:<port>` at
/// any time (both are PF_INET6 wildcards, which `in_pcbbind` exempts from its conflict
/// check), and after that a `SO_REUSEADDR` bind of `::ffff:<host address>:<port>` by the same
/// user passes the different-user check against its own socket and takes every IPv4 datagram
/// sent to that address (J826, #260). A dual-stack bind on macOS is therefore an AF_INET socket
/// plus an `IPV6_V6ONLY` one (`UdpSocket::bind_split`, J834), which closes that by the kernel's
/// own rule and needs no audit at all.
pub(crate) fn ensure_alone(socket: &socket2::Socket) -> io::Result<()> {
    let local = socket
        .local_addr()?
        .as_socket()
        .ok_or_else(|| io::Error::other("UDP socket has no IP address"))?;
    let port = local.port();
    let users = port_users(port).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("cannot check who else holds UDP port {port}: {error}"),
        )
    })?;
    let only_v6 = local.is_ipv6() && socket.only_v6()?;
    alone(&users, port, single_family_wildcard(local, only_v6))
}

/// Whether a socket bound to `local` (IPv6-only when `only_v6`) is a wildcard of one family:
/// `0.0.0.0`, or `[::]` with `IPV6_V6ONLY`. A dual-stack `[::]` is not: an IPv4 squatter can
/// share its port (J815).
fn single_family_wildcard(local: std::net::SocketAddr, only_v6: bool) -> bool {
    local.ip().is_unspecified() && (local.is_ipv4() || only_v6)
}

/// The verdict of [`ensure_alone`] on a parsed list: exactly one socket on the port, and it is
/// this process's.
///
/// A list that shows no other process's socket at all (macOS 27, see the module docs) cannot
/// rule anyone out. For a single-family `wildcard` bind (`0.0.0.0`, or `[::]` with
/// `IPV6_V6ONLY`; never a dual-stack `[::]`, which an IPv4 squatter can share, J815) that is
/// accepted, because there the kernel's own rule already refuses every socket of the same family
/// on the port, before us or after us, and a socket of the other family gets none of our
/// datagrams. J1108 measured it on macOS 26.5.2 and 27.2.1 alike: every same-family squatter
/// (`0.0.0.0`, `127.0.0.1`, a dual-stack `[::]`, and for an IPv6-only bind an IPv6-only `[::]`
/// and `[::1]`) was refused, and the only squatters that bound beside us were of the other
/// family, receiving only their own family's datagrams. Any other bind fails closed.
fn alone(users: &PortUsers, port: u16, wildcard: bool) -> io::Result<()> {
    if users.total > 0 && !users.sees_other_processes() {
        if wildcard && users.total == 1 {
            tracing::debug!(
                "UDP port {port}: the socket list shows only this process's sockets; the kernel \
                 keeps an exclusive wildcard bind's family to itself"
            );
            return Ok(());
        }
        if !wildcard {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "cannot check who else holds UDP port {port}: the kernel's socket list shows \
                     only this process's sockets"
                ),
            ));
        }
    }
    match users.total {
        0 => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "our socket on UDP port {port} is not in net.inet.udp.pcblist_n: its record \
                 layout is not recognised, so nobody can be ruled out"
            ),
        )),
        1 if users.others.is_empty() => Ok(()),
        total => Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            format!(
                "UDP port {port} is already held by another socket ({total} sockets on it; \
                 others (uid, pid): {:?})",
                users.others
            ),
        )),
    }
}

/// The sockets on one port.
#[derive(Debug, Default)]
pub(crate) struct PortUsers {
    /// How many sockets are bound to the port, any address, either family.
    pub(crate) total: usize,
    /// `(uid, last pid)` of each socket that is not this process's (for the log only).
    pub(crate) others: Vec<(u32, i32)>,
    /// How many sockets in the whole list, on any port, are not this process's.
    pub(crate) visible_others: usize,
}

impl PortUsers {
    /// Whether the list shows any other process's socket at all. When it does not, it has been
    /// filtered for us (macOS 27, see the module docs) and cannot show who else is on the port.
    pub(crate) fn sees_other_processes(&self) -> bool {
        self.visible_others > 0
    }
}

/// The sockets on UDP `port` right now.
pub(crate) fn port_users(port: u16) -> io::Result<PortUsers> {
    let list = read_sysctl(c"net.inet.udp.pcblist_n")?;
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    let uid = unsafe { libc::geteuid() };
    let pid = i32::try_from(std::process::id()).unwrap_or(-1);
    parse(&list, port, uid, pid)
}

/// Read a variable-size sysctl, retrying while it grows between the size query and the read.
fn read_sysctl(name: &CStr) -> io::Result<Vec<u8>> {
    for _ in 0..8 {
        let mut len = 0usize;
        // SAFETY: a size query: no output buffer, `len` is a valid out-pointer.
        let rc = unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                std::ptr::null_mut(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        len += len / 4 + 4096;
        let mut buf = vec![0u8; len];
        // SAFETY: `buf` is `len` bytes long; the kernel writes at most `len` bytes and
        // stores the written length back into `len`.
        let rc = unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                buf.as_mut_ptr().cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc == 0 {
            buf.truncate(len);
            return Ok(buf);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ENOMEM) {
            return Err(error);
        }
    }
    Err(io::Error::other("the UDP socket list kept growing"))
}

/// `struct xinpgen`: the list's header and trailer.
const GEN_LEN: usize = 24;
/// Record kinds (`xso_kind`/`xi_kind`).
const XSO_SOCKET: u32 = 0x001;
const XSO_INPCB: u32 = 0x010;
/// `struct xinpcb_n` (packed to 4): `inp_lport`, network order.
const INPCB_LPORT: usize = 18;
/// `struct xsocket_n` (packed to 4): `so_uid` and `so_last_pid`.
const SOCKET_UID: usize = 64;
const SOCKET_LAST_PID: usize = 68;

/// Count the sockets on `port` in a `pcblist_n` buffer. Each socket is a run of records
/// (`xinpcb_n` first, then `xsocket_n`, buffers, stats), each starting with its length and
/// kind and padded to 8 bytes, between a leading and a trailing `xinpgen`.
pub(crate) fn parse(list: &[u8], port: u16, uid: u32, pid: i32) -> io::Result<PortUsers> {
    let malformed = || io::Error::new(io::ErrorKind::InvalidData, "malformed pcblist_n");
    let u32_at = |offset: usize| -> io::Result<u32> {
        list.get(offset..offset + 4)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u32::from_ne_bytes)
            .ok_or_else(malformed)
    };
    if list.len() < 2 * GEN_LEN || u32_at(0)? as usize != GEN_LEN {
        return Err(malformed());
    }
    let end = list.len() - GEN_LEN;
    let mut users = PortUsers::default();
    let mut on_port = false;
    let mut offset = GEN_LEN.next_multiple_of(8);
    while offset < end {
        let len = u32_at(offset)? as usize;
        let kind = u32_at(offset + 4)?;
        if len < 8 || offset + len > end {
            return Err(malformed());
        }
        match kind {
            XSO_INPCB => {
                let lport = list
                    .get(offset + INPCB_LPORT..offset + INPCB_LPORT + 2)
                    .ok_or_else(malformed)?;
                on_port = u16::from_be_bytes([lport[0], lport[1]]) == port;
                users.total += usize::from(on_port);
            }
            XSO_SOCKET => {
                if len < SOCKET_LAST_PID + 4 {
                    return Err(malformed());
                }
                let so_uid = u32_at(offset + SOCKET_UID)?;
                let last_pid = u32_at(offset + SOCKET_LAST_PID)? as i32;
                if (so_uid, last_pid) != (uid, pid) {
                    users.visible_others += 1;
                    if on_port {
                        users.others.push((so_uid, last_pid));
                    }
                }
            }
            _ => {}
        }
        offset += len.next_multiple_of(8);
    }
    Ok(users)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    /// Bind `address` with `SO_REUSEPORT`, so several sockets of this test can share a port.
    fn shared(address: SocketAddr) -> socket2::Socket {
        let socket = socket2::Socket::new(
            socket2::Domain::for_address(address),
            socket2::Type::DGRAM,
            None,
        )
        .expect("socket");
        socket.set_reuse_port(true).expect("SO_REUSEPORT");
        socket.bind(&address.into()).expect("bind");
        socket
    }

    /// Every socket on the port is counted, IPv4 and IPv6 alike, and each is attributed to this
    /// process: that checks the `xsocket_n` offsets the log relies on, and that the IPv6 and
    /// IPv4 sockets come from the one list. Sockets on other ports are not counted, and a closed
    /// one leaves the count at once.
    #[test]
    fn our_sockets_on_a_port_are_counted_and_attributed() {
        let first = shared((Ipv6Addr::UNSPECIFIED, 0).into());
        let port = first
            .local_addr()
            .expect("local")
            .as_socket()
            .expect("ip")
            .port();
        let second = shared((Ipv4Addr::LOCALHOST, port).into());
        let third = shared((Ipv4Addr::UNSPECIFIED, port).into());
        let _elsewhere = shared((Ipv4Addr::LOCALHOST, 0).into());

        let users = super::port_users(port).expect("read the list");
        assert_eq!(users.total, 3);
        assert!(users.others.is_empty(), "{:?}", users.others);

        drop(second);
        assert_eq!(super::port_users(port).expect("read the list").total, 2);
        drop((first, third));
        assert_eq!(super::port_users(port).expect("read the list").total, 0);
    }

    /// The S-off verdict: our socket alone passes; anyone else on the port is `EADDRINUSE`; a
    /// list without our own socket means the layout is not recognised, and that fails closed too.
    #[test]
    fn the_verdict_fails_closed() {
        let alone = |total, others: Vec<(u32, i32)>| {
            let users = super::PortUsers {
                total,
                others,
                visible_others: 5,
            };
            super::alone(&users, 9, true).map_err(|error| error.kind())
        };
        assert_eq!(alone(1, vec![]), Ok(()));
        assert_eq!(
            alone(2, vec![(501, 77)]),
            Err(std::io::ErrorKind::AddrInUse)
        );
        assert_eq!(
            alone(2, vec![]),
            Err(std::io::ErrorKind::AddrInUse),
            "two of ours"
        );
        assert_eq!(
            alone(1, vec![(501, 77)]),
            Err(std::io::ErrorKind::AddrInUse)
        );
        assert_eq!(alone(0, vec![]), Err(std::io::ErrorKind::InvalidData));
    }

    /// A list that shows no other process's socket (macOS 27, J1108) cannot rule anyone out: a
    /// wildcard bind, which the kernel keeps to itself per family, is accepted with only our own
    /// socket on the port; a specific address fails closed; two of ours and an empty list are
    /// refused as before.
    #[test]
    fn a_list_without_other_processes_is_trusted_only_for_wildcards() {
        let verdict = |total, wildcard| {
            let users = super::PortUsers {
                total,
                others: Vec::new(),
                visible_others: 0,
            };
            super::alone(&users, 9, wildcard).map_err(|error| error.kind())
        };
        assert_eq!(verdict(1, true), Ok(()));
        assert_eq!(verdict(1, false), Err(std::io::ErrorKind::InvalidData));
        assert_eq!(verdict(2, true), Err(std::io::ErrorKind::AddrInUse));
        assert_eq!(verdict(0, true), Err(std::io::ErrorKind::InvalidData));
    }

    /// Only `0.0.0.0` and an IPv6-only `[::]` are trusted on a filtered list; a dual-stack `[::]`
    /// and specific addresses are not.
    #[test]
    fn only_single_family_wildcards_are_trusted() {
        let at = |address: &str| address.parse::<std::net::SocketAddr>().expect("address");
        assert!(super::single_family_wildcard(at("0.0.0.0:9"), false));
        assert!(super::single_family_wildcard(at("[::]:9"), true));
        assert!(
            !super::single_family_wildcard(at("[::]:9"), false),
            "dual-stack"
        );
        assert!(!super::single_family_wildcard(at("127.0.0.1:9"), false));
        assert!(!super::single_family_wildcard(at("[::1]:9"), true));
    }

    /// This test process sees other processes' sockets on macOS 26 (the Mac VM), not on macOS 27
    /// (J1108); either way the count is consistent with what it reports.
    #[test]
    fn the_list_says_whether_it_shows_other_processes() {
        let users = super::port_users(9).expect("read the list");
        eprintln!(
            "pcblist_n: {} sockets of other processes visible (filtered: {})",
            users.visible_others,
            !users.sees_other_processes()
        );
        assert_eq!(users.sees_other_processes(), users.visible_others > 0);
    }

    /// A socket bound without `SO_REUSEPORT` passes the check on a real list. Also prints what
    /// one check costs (the median of 200), the price every S-off bind pays once.
    #[test]
    fn an_exclusive_socket_is_alone() {
        let socket = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None)
            .expect("socket");
        socket.set_only_v6(false).expect("dual-stack");
        socket
            .bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)).into())
            .expect("bind [::]:0");
        if !super::port_users(9).expect("list").sees_other_processes() {
            // macOS 27 (J1108): the filtered list cannot clear a dual-stack bind, which an IPv4
            // squatter could share (J815); it must fail closed.
            let refused = super::ensure_alone(&socket).expect_err("a dual-stack bind fails closed");
            assert_eq!(refused.kind(), std::io::ErrorKind::InvalidData, "{refused}");
            return;
        }
        super::ensure_alone(&socket).expect("alone on its port");

        let mut took: Vec<_> = (0..200)
            .map(|_| {
                let start = std::time::Instant::now();
                super::ensure_alone(&socket).expect("alone on its port");
                start.elapsed()
            })
            .collect();
        took.sort();
        eprintln!(
            "ensure_alone: median {:?}, max {:?} over 200 checks",
            took[100], took[199]
        );
    }

    /// A list that is cut short or whose records do not add up is refused, never half-counted.
    #[test]
    fn a_malformed_list_is_refused() {
        let mut list = vec![0u8; 2 * super::GEN_LEN];
        list[..4].copy_from_slice(&(super::GEN_LEN as u32).to_ne_bytes());
        assert_eq!(super::parse(&list, 9, 0, 0).expect("empty list").total, 0);

        // One record that claims to run past the trailer.
        let mut list = vec![0u8; 2 * super::GEN_LEN + 16];
        list[..4].copy_from_slice(&(super::GEN_LEN as u32).to_ne_bytes());
        list[24..28].copy_from_slice(&64u32.to_ne_bytes());
        list[28..32].copy_from_slice(&super::XSO_INPCB.to_ne_bytes());
        assert!(super::parse(&list, 9, 0, 0).is_err());

        assert!(
            super::parse(&[0u8; 8], 9, 0, 0).is_err(),
            "shorter than the header"
        );
    }
}
