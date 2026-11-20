// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

//! **Measurement prototype (#554, #260, J1023), not for shipping as is:** batched UDP send and
//! receive on macOS through xnu's private `sendmsg_x` and `recvmsg_x`.
//!
//! **Why.** On macOS every WireGuard datagram costs one `sendto` or `recvfrom`, because the
//! public API has no `sendmmsg`/`recvmmsg` and no UDP GSO/GRO. xnu has private batch calls that
//! move many datagrams per syscall. J1023 measures whether they pay for themselves on real
//! hardware, alone and on top of connected sends ([`super::macos_connected`]).
//!
//! **How it is switched.** Nothing changes unless `GOTATUN_J1023_BATCH` is `send`, `recv` or
//! `both`. Both symbols are resolved once with `dlsym`. If either is missing, the switch is
//! ignored and today's one-datagram path runs. `GOTATUN_J1023_BATCH_N` (1..=256, default 64)
//! caps the datagrams per call.
//!
//! **Semantics that callers rely on** (measured by J434 on macOS 26 and kept here):
//! - `sendmsg_x` returns how many datagrams it queued. A short count means "the socket is
//!   full", and the next call resumes at the first unsent datagram. `-1` with `EWOULDBLOCK` or
//!   `ENOBUFS` means nothing left on this call.
//! - Any other `-1` may come *after* earlier datagrams of the same call were sent (J434: an
//!   unsendable datagram at index 3 of 8). The caller then sends the rest one at a time, so a
//!   few datagrams can leave twice. WireGuard's replay window drops the duplicates.
//! - `recvmsg_x` reports neither `MSG_TRUNC` nor the real length of a datagram larger than its
//!   buffer. The pool's buffers are far larger than any WireGuard datagram on our MTUs, so a
//!   datagram that fills its buffer is dropped as truncated.
//!
//! [`stats`] counts calls and datagrams, so a bench can report datagrams per syscall.

#![allow(unsafe_code)]

use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    os::fd::RawFd,
    sync::{
        OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};

use crate::packet::{Packet, PacketBufPool};

/// Darwin's private `struct msghdr_x` (xnu `bsd/sys/socket_private.h`): a `msghdr` plus
/// `msg_datalen`, the byte count of that one datagram.
#[repr(C)]
struct MsghdrX {
    msg_name: *mut libc::c_void,
    msg_namelen: libc::socklen_t,
    msg_iov: *mut libc::iovec,
    msg_iovlen: libc::c_int,
    msg_control: *mut libc::c_void,
    msg_controllen: libc::socklen_t,
    msg_flags: libc::c_int,
    msg_datalen: libc::size_t,
}

/// `ssize_t sendmsg_x(int, const struct msghdr_x *, u_int, int)` and the same shape for
/// `recvmsg_x` (its array is written to).
type MsgX = unsafe extern "C" fn(libc::c_int, *mut MsghdrX, libc::c_uint, libc::c_int) -> isize;

/// The two private calls, if this macOS exports them.
struct Calls {
    send: MsgX,
    recv: MsgX,
}

/// Resolve both calls once per process. `None` when either symbol is missing.
fn calls() -> Option<&'static Calls> {
    static CALLS: OnceLock<Option<Calls>> = OnceLock::new();
    CALLS
        .get_or_init(|| {
            // SAFETY: dlsym with a NUL-terminated name only looks the symbol up.
            let send = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"sendmsg_x".as_ptr()) };
            // SAFETY: as above.
            let recv = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"recvmsg_x".as_ptr()) };
            if send.is_null() || recv.is_null() {
                return None;
            }
            // SAFETY: both symbols are xnu's syscall wrappers with the `MsgX` signature.
            Some(unsafe {
                Calls {
                    send: std::mem::transmute::<*mut libc::c_void, MsgX>(send),
                    recv: std::mem::transmute::<*mut libc::c_void, MsgX>(recv),
                }
            })
        })
        .as_ref()
}

/// Which directions batch, read once from `GOTATUN_J1023_BATCH`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Mode {
    /// Sends go out through `sendmsg_x`.
    pub(crate) send: bool,
    /// Receives come in through `recvmsg_x`.
    pub(crate) recv: bool,
    /// Most datagrams per call.
    pub(crate) batch: usize,
}

/// The batching mode of this process (off unless asked for, and only if both calls resolve).
pub(crate) fn mode() -> Mode {
    static MODE: OnceLock<Mode> = OnceLock::new();
    *MODE.get_or_init(|| {
        let value = std::env::var("GOTATUN_J1023_BATCH").unwrap_or_default();
        let (mut send, mut recv) = match value.as_str() {
            "send" => (true, false),
            "recv" => (false, true),
            "both" => (true, true),
            _ => (false, false),
        };
        if (send || recv) && calls().is_none() {
            eprintln!("j1023 batch: sendmsg_x/recvmsg_x not found; one datagram per call");
            (send, recv) = (false, false);
        }
        let batch = std::env::var("GOTATUN_J1023_BATCH_N")
            .ok()
            .and_then(|n| n.parse().ok())
            .unwrap_or(64usize)
            .clamp(1, 256);
        if send || recv {
            eprintln!("j1023 batch: send={send} recv={recv} batch={batch}");
        }
        Mode { send, recv, batch }
    })
}

/// Calls and datagrams through the batch calls: send calls, send datagrams, receive calls,
/// receive datagrams.
static STATS: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];

/// Snapshot of [`STATS`]: `[send_calls, send_datagrams, recv_calls, recv_datagrams]`.
pub fn stats() -> [u64; 4] {
    STATS.each_ref().map(|count| count.load(Ordering::Relaxed))
}

/// One `sendmsg_x` call for `items` on `fd`: each item is a payload and, on an unconnected
/// socket, its destination. Returns how many datagrams the kernel took (at least 1), or the
/// call's error. `EWOULDBLOCK`/`ENOBUFS` mean none were taken.
pub(crate) fn send_x(fd: RawFd, items: &[(&[u8], Option<SocketAddr>)]) -> io::Result<usize> {
    let calls = calls().ok_or(io::ErrorKind::Unsupported)?;
    let count = items.len().min(mode().batch);
    let names: Vec<Option<socket2::SockAddr>> = items[..count]
        .iter()
        .map(|(_, destination)| destination.map(socket2::SockAddr::from))
        .collect();
    let mut iov: Vec<libc::iovec> = items[..count]
        .iter()
        .map(|(payload, _)| libc::iovec {
            iov_base: payload.as_ptr() as *mut libc::c_void,
            iov_len: payload.len(),
        })
        .collect();
    let mut headers: Vec<MsghdrX> = iov
        .iter_mut()
        .zip(&names)
        .map(|(iov, name)| MsghdrX {
            msg_name: name
                .as_ref()
                .map_or(std::ptr::null_mut(), |n| n.as_ptr() as *mut libc::c_void),
            msg_namelen: name.as_ref().map_or(0, socket2::SockAddr::len),
            msg_iov: iov,
            msg_iovlen: 1,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
            msg_datalen: 0,
        })
        .collect();
    // SAFETY: `headers`, `iov` and `names` outlive the call and describe valid buffers.
    let sent = unsafe { (calls.send)(fd, headers.as_mut_ptr(), count as libc::c_uint, 0) };
    STATS[0].fetch_add(1, Ordering::Relaxed);
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    let sent = sent as usize;
    STATS[1].fetch_add(sent as u64, Ordering::Relaxed);
    if sent == 0 {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    Ok(sent)
}

/// Spare receive buffers kept between [`recv_x`] calls, so a call that gets few datagrams does
/// not hand the rest back to the pool and take them again next time.
#[derive(Default)]
pub struct RecvBuf {
    /// Buffers from the pool, full length, not yet filled.
    spare: Vec<Packet>,
}

/// One `recvmsg_x` call on `fd`: appends every datagram it returns to `packets` with its source
/// (mapped by `map_src`), and returns how many. `EWOULDBLOCK` when nothing was queued.
pub(crate) fn recv_x(
    fd: RawFd,
    buf: &mut RecvBuf,
    pool: &mut PacketBufPool,
    packets: &mut Vec<(Packet, SocketAddr)>,
    map_src: impl Fn(SocketAddr) -> SocketAddr,
) -> io::Result<usize> {
    let calls = calls().ok_or(io::ErrorKind::Unsupported)?;
    let count = mode().batch;
    while buf.spare.len() < count {
        buf.spare.push(pool.get());
    }
    // SAFETY: an all-zero sockaddr_storage is a valid (empty) value.
    let mut names: Vec<libc::sockaddr_storage> = vec![unsafe { std::mem::zeroed() }; count];
    let mut iov: Vec<libc::iovec> = buf.spare[..count]
        .iter_mut()
        .map(|packet| libc::iovec {
            iov_base: packet.as_mut_ptr() as *mut libc::c_void,
            iov_len: packet.len(),
        })
        .collect();
    let mut headers: Vec<MsghdrX> = iov
        .iter_mut()
        .zip(names.iter_mut())
        .map(|(iov, name)| MsghdrX {
            msg_name: (name as *mut libc::sockaddr_storage).cast(),
            msg_namelen: size_of::<libc::sockaddr_storage>() as libc::socklen_t,
            msg_iov: iov,
            msg_iovlen: 1,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
            msg_datalen: 0,
        })
        .collect();
    // SAFETY: every header points at a live, writable buffer and name of the stated length.
    let got = unsafe { (calls.recv)(fd, headers.as_mut_ptr(), count as libc::c_uint, 0) };
    STATS[2].fetch_add(1, Ordering::Relaxed);
    if got < 0 {
        return Err(io::Error::last_os_error());
    }
    let got = got as usize;
    if got == 0 {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    STATS[3].fetch_add(got as u64, Ordering::Relaxed);
    let lengths: Vec<(usize, Option<SocketAddr>)> = headers[..got]
        .iter()
        .zip(&names)
        .map(|(header, name)| (header.msg_datalen, parse(name)))
        .collect();
    let rest = buf.spare.split_off(got);
    let filled = std::mem::replace(&mut buf.spare, rest);
    let mut delivered = 0;
    for (mut packet, (len, source)) in filled.into_iter().zip(lengths) {
        // A datagram that fills its buffer may have been cut short; recvmsg_x does not say.
        let Some(source) = source else { continue };
        if len >= packet.len() {
            continue;
        }
        packet.truncate(len);
        packets.push((packet, map_src(source)));
        delivered += 1;
    }
    Ok(delivered)
}

/// The IPv4 or IPv6 address in a `sockaddr_storage` the kernel filled in.
fn parse(name: &libc::sockaddr_storage) -> Option<SocketAddr> {
    match libc::c_int::from(name.ss_family) {
        libc::AF_INET => {
            // SAFETY: the family says this storage holds a sockaddr_in.
            let a = unsafe { &*(name as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>() };
            Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr)),
                u16::from_be(a.sin_port),
            )))
        }
        libc::AF_INET6 => {
            // SAFETY: the family says this storage holds a sockaddr_in6.
            let a = unsafe { &*(name as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>() };
            Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(a.sin6_addr.s6_addr),
                u16::from_be(a.sin6_port),
                a.sin6_flowinfo,
                a.sin6_scope_id,
            )))
        }
        _ => None,
    }
}

/// Send every item on `socket` through `sendmsg_x`, waiting while the socket is full. Returns
/// how many were sent before a hard error (see the module docs), or `Ok(items.len())`.
/// `ENOBUFS` drops the datagram at the head, as a `sendto` would.
pub(crate) async fn send_all(
    socket: &tokio::net::UdpSocket,
    items: &[(&[u8], Option<SocketAddr>)],
) -> Result<usize, (usize, io::Error)> {
    use std::os::fd::AsRawFd;
    let mut done = 0;
    while done < items.len() {
        match socket.try_io(tokio::io::Interest::WRITABLE, || {
            send_x(socket.as_raw_fd(), &items[done..])
        }) {
            Ok(sent) => done += sent,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if let Err(error) = socket.writable().await {
                    return Err((done, error));
                }
            }
            Err(error) if error.raw_os_error() == Some(libc::ENOBUFS) => done += 1,
            Err(error) => return Err((done, error)),
        }
    }
    Ok(done)
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;

    use super::*;

    /// `send_x` then `recv_x` move 100 datagrams in order between two loopback sockets, in
    /// calls of more than one datagram, with the right source address (layout and semantics).
    #[test]
    fn a_batch_round_trip_keeps_order_and_source() {
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
        receiver.set_nonblocking(true).expect("nonblocking");
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind sender");
        let to = receiver.local_addr().expect("receiver address");
        let payloads: Vec<Vec<u8>> = (0..100u8).map(|i| vec![i; 100 + usize::from(i)]).collect();
        let items: Vec<(&[u8], Option<SocketAddr>)> =
            payloads.iter().map(|p| (&p[..], Some(to))).collect();
        let mut done = 0;
        while done < items.len() {
            done += send_x(sender.as_raw_fd(), &items[done..]).expect("sendmsg_x");
        }
        let mut pool = PacketBufPool::new(256);
        let mut buf = RecvBuf::default();
        let mut packets = Vec::new();
        let mut calls = 0;
        while packets.len() < 100 && calls < 1000 {
            calls += 1;
            match recv_x(receiver.as_raw_fd(), &mut buf, &mut pool, &mut packets, |s| s) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => std::thread::yield_now(),
                Err(e) => panic!("recvmsg_x: {e}"),
            }
        }
        assert_eq!(packets.len(), 100);
        assert!(calls < 100, "recvmsg_x returned one datagram per call ({calls} calls)");
        for (i, (packet, source)) in packets.iter().enumerate() {
            assert_eq!(&packet[..], &payloads[i][..]);
            assert_eq!(*source, sender.local_addr().expect("sender address"));
        }
    }
}
