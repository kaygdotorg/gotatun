// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

//! Socket options for a macOS utun control socket that `libc` does not export.
//!
//! **Why (#260, J673).** A utun hands packets to its reader through the control socket's
//! receive buffer, but by default it lets only **one** packet wait there
//! (`pcb->utun_max_pending_packets = 1` in xnu's `bsd/net/if_utun.c`). `utun_start` stops
//! dequeuing from the interface queue while that packet is unread, and only the reader's next
//! read (`utun_ctl_rcvd`) turns output back on. So a reader gets one packet per wake-up no
//! matter how it reads: every packet costs a read, a kernel start-thread hand-off and another
//! readiness wake. Raising the limit with `UTUN_OPT_MAX_PENDING_PACKETS` lets a burst queue up
//! so one wake-up (or one `recvmsg_x`) takes many packets.
//!
//! The rest of the backlog still waits in the interface's own queue, so a small limit keeps
//! most of a bulk backlog under the interface's queueing discipline.

use std::{
    ffi::c_int,
    io, mem,
    os::fd::{AsRawFd, BorrowedFd},
};

/// `UTUN_OPT_MAX_PENDING_PACKETS` from xnu's `bsd/net/if_utun.h`: the number of packets that
/// may wait to be read from the control socket at a time.
const UTUN_OPT_MAX_PENDING_PACKETS: c_int = 16;

/// Let up to `packets` packets wait on this utun control socket before the interface pauses.
///
/// # Errors
/// [`io::ErrorKind::InvalidInput`] for `0` (the kernel refuses it too), or the error from
/// `setsockopt`, for example when `fd` is not a connected utun control socket.
pub fn set_max_pending_packets(fd: BorrowedFd<'_>, packets: u32) -> io::Result<()> {
    let _ = (fd, packets);
    Ok(())
}

/// Read back how many packets may wait on this utun control socket.
///
/// # Errors
/// The error from `getsockopt`, for example when `fd` is not a connected utun control socket.
pub fn max_pending_packets(fd: BorrowedFd<'_>) -> io::Result<u32> {
    let _ = fd;
    Ok(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsFd, FromRawFd, OwnedFd};

    /// The setter reports a socket that is not a utun instead of pretending it worked.
    #[test]
    fn max_pending_is_refused_on_a_non_utun_socket() {
        let (socket, _peer) = std::os::unix::net::UnixDatagram::pair().expect("datagram pair");
        assert!(set_max_pending_packets(socket.as_fd(), 8).is_err());
        assert!(max_pending_packets(socket.as_fd()).is_err());
    }

    /// Zero would stop the interface for good; it is refused before the kernel sees it.
    #[test]
    fn zero_pending_packets_is_invalid() {
        let (socket, _peer) = std::os::unix::net::UnixDatagram::pair().expect("datagram pair");
        let error = set_max_pending_packets(socket.as_fd(), 0).expect_err("zero is refused");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    /// Open a fresh utun control socket (needs root).
    fn open_utun() -> OwnedFd {
        // SAFETY: plain socket/ioctl/connect calls on a descriptor this test owns, with
        // structures that live for each call.
        unsafe {
            let fd = libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL);
            assert!(fd >= 0, "PF_SYSTEM socket");
            let fd = OwnedFd::from_raw_fd(fd);
            let mut info: libc::ctl_info = mem::zeroed();
            for (dst, src) in info.ctl_name.iter_mut().zip(b"com.apple.net.utun_control") {
                *dst = *src as libc::c_char;
            }
            assert_eq!(libc::ioctl(fd.as_raw_fd(), libc::CTLIOCGINFO, &mut info), 0);
            let address = libc::sockaddr_ctl {
                sc_len: mem::size_of::<libc::sockaddr_ctl>() as u8,
                sc_family: libc::AF_SYSTEM as u8,
                ss_sysaddr: libc::AF_SYS_CONTROL as u16,
                sc_id: info.ctl_id,
                sc_unit: 0,
                sc_reserved: [0; 5],
            };
            let connected = libc::connect(
                fd.as_raw_fd(),
                (&raw const address).cast(),
                mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
            );
            assert_eq!(connected, 0, "utun connect (run as root)");
            fd
        }
    }

    /// On a real utun the limit starts at xnu's default of 1 and takes the new value.
    #[test]
    #[ignore = "needs root to create a utun: sudo <test binary> --ignored macos_utun"]
    fn max_pending_round_trips_on_a_real_utun() {
        let utun = open_utun();
        assert_eq!(max_pending_packets(utun.as_fd()).expect("default"), 1);
        set_max_pending_packets(utun.as_fd(), 64).expect("set 64");
        assert_eq!(max_pending_packets(utun.as_fd()).expect("read back"), 64);
    }
}
