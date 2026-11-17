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
//! [`ensure_alone`] uses it right after the WireGuard socket binds with connected sends off: xnu
//! lets that exclusive bind succeed beside a socket another user bound to the port earlier with
//! `SO_REUSEPORT` (`0.0.0.0:<port>` beside our `[::]:<port>`), and that socket would then
//! receive the port's IPv4 datagrams (#260, J815, J827). The reader and parser are J815's, shared
//! with the connected-send pool's audit (`j815-mac-socket-pool`), so one review covers both.
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
/// sent to that address (J826, #260). A dual-stack bind is therefore split into an AF_INET
/// socket plus an `IPV6_V6ONLY` one (`UdpSocket::bind_split`, J834), which the kernel's own
/// rule keeps closed for the socket's whole life. This check stays on top of that.
///
/// `ours` is how many sockets this bind put on the port: 1 for a single socket, 2 for a macOS
/// split pair (AF_INET plus `IPV6_V6ONLY`, J834), whose sockets must both be in the list.
pub(crate) fn ensure_alone(socket: &socket2::Socket, ours: usize) -> io::Result<()> {
    let port = socket
        .local_addr()?
        .as_socket()
        .ok_or_else(|| io::Error::other("UDP socket has no IP address"))?
        .port();
    let users = port_users(port).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("cannot check who else holds UDP port {port}: {error}"),
        )
    })?;
    alone(&users, port, ours)
}

/// The verdict of [`ensure_alone`] on a parsed list: exactly `ours` sockets on the port, all of
/// them this process's. Fewer than `ours`, with nobody else there, means some of ours are missing
/// from the list, so the layout is not recognised either.
fn alone(users: &PortUsers, port: u16, ours: usize) -> io::Result<()> {
    match users.total {
        total if total < ours && users.others.is_empty() => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "our socket on UDP port {port} is not in net.inet.udp.pcblist_n: its record \
                 layout is not recognised, so nobody can be ruled out"
            ),
        )),
        total if total == ours && users.others.is_empty() => Ok(()),
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
            XSO_SOCKET if on_port => {
                if len < SOCKET_LAST_PID + 4 {
                    return Err(malformed());
                }
                let so_uid = u32_at(offset + SOCKET_UID)?;
                let last_pid = u32_at(offset + SOCKET_LAST_PID)? as i32;
                if (so_uid, last_pid) != (uid, pid) {
                    users.others.push((so_uid, last_pid));
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
            super::alone(&super::PortUsers { total, others }, 9, 1).map_err(|error| error.kind())
        };
        let pair = |total, others: Vec<(u32, i32)>| {
            super::alone(&super::PortUsers { total, others }, 9, 2).map_err(|error| error.kind())
        };
        assert_eq!(pair(2, vec![]), Ok(()), "a split pair");
        assert_eq!(
            pair(1, vec![]),
            Err(std::io::ErrorKind::InvalidData),
            "one of ours missing"
        );
        assert_eq!(pair(0, vec![]), Err(std::io::ErrorKind::InvalidData));
        assert_eq!(pair(3, vec![]), Err(std::io::ErrorKind::AddrInUse));
        assert_eq!(
            pair(2, vec![(501, 77)]),
            Err(std::io::ErrorKind::AddrInUse),
            "one of ours plus someone else"
        );
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
        super::ensure_alone(&socket, 1).expect("alone on its port");

        let mut took: Vec<_> = (0..200)
            .map(|_| {
                let start = std::time::Instant::now();
                super::ensure_alone(&socket, 1).expect("alone on its port");
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
