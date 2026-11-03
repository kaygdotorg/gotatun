// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

//! Linux-specific TUN setup and software fallback policy.

use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

pub(super) fn create_tun_with_vnet_fallback(
    config: &mut tun::Configuration,
) -> Result<(tun::AsyncDevice, bool), tun::Error> {
    open_with_vnet_fallback(|vnet_header| {
        config.platform_config(|platform| {
            platform.vnet_hdr(vnet_header);
        });
        tun::create_as_async(config)
    })
}

pub(super) fn enable_tso_with_fallback(tun: &impl AsRawFd) -> bool {
    match super::tso::try_enable_tso(tun) {
        Ok(()) => true,
        Err(error) => {
            tracing::debug!(%error, "TUN TSO unavailable; using software packet handling");
            false
        }
    }
}

fn open_with_vnet_fallback<T, E>(
    mut create: impl FnMut(bool) -> Result<T, E>,
) -> Result<(T, bool), E> {
    match create(true) {
        Ok(device) => Ok((device, true)),
        Err(vnet_error) => match create(false) {
            Ok(device) => Ok((device, false)),
            Err(_) => Err(vnet_error),
        },
    }
}

/// Packets the kernel may hold on the TUN transmit ring while our reader is not running.
///
/// The ring sits between the host stack and [`super::TunDevice`]'s reader: every packet the
/// host routes into the tunnel waits there. The kernel sizes it at 500 for a new TUN device,
/// and when it is full the kernel drops the packet without pushing back on the sender (the
/// qdisc above it never holds anything). Under load the reader shares the CPUs with
/// decryption and TUN writes, so a short scheduling gap overflowed the ring on the side that
/// mostly sends ACKs and small replies (#260). Each drop there is a lost reply or a lost
/// latency probe.
///
/// Raising the bound turns those drops into a short wait. It cannot reorder: the device is
/// single-queue (the `tun` crate rejects more queues), so there is one FIFO ring, and its
/// size only decides whether a packet is kept or dropped, never when it leaves relative to
/// the others. The ring stores pointers; memory is only used by packets actually waiting.
///
/// 1,024 is the smallest size that removed every ring drop at 1 and 8 TCP flows on the #260
/// benchmark host (500 dropped up to 1.5% on the reply side; 4,096 measured the same as
/// 1,024). The smaller bound keeps the worst-case wait in the ring short.
pub(super) const TUN_TX_QUEUE_LEN: u32 = 1024;

/// Raise the transmit ring of TUN device `name` to [`TUN_TX_QUEUE_LEN`] packets.
///
/// Only raises: a ring already at least that long (set by an administrator, or by a previous
/// run on a persistent device) is left alone. Failure is not fatal; the device then keeps
/// the kernel's default and works as before.
pub(super) fn raise_tx_queue_len(name: &str) {
    match set_tx_queue_len_at_least(name, TUN_TX_QUEUE_LEN) {
        Ok(len) => tracing::debug!(%name, len, "TUN transmit queue length"),
        Err(error) => {
            tracing::debug!(%name, %error, "TUN transmit queue length left at its default")
        }
    }
}

/// The length to set, or `None` to keep `current`.
fn tx_queue_len_target(current: u32, wanted: u32) -> Option<u32> {
    (current < wanted).then_some(wanted)
}

/// Read the transmit queue length of interface `name`.
fn tx_queue_len(name: &str) -> io::Result<u32> {
    let socket = control_socket()?;
    let mut request = interface_request(name)?;
    // SAFETY: `SIOCGIFTXQLEN` reads `ifr_name` and writes the length into the union's integer
    // member; `request` is a valid, initialised `ifreq` for the duration of the call.
    if unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCGIFTXQLEN as _, &raw mut request) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the kernel wrote the integer member (`ifr_qlen` is `ifru_ivalue`, which libc
    // names `ifru_ifindex`).
    let len = unsafe { request.ifr_ifru.ifru_ifindex };
    u32::try_from(len).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "negative qlen"))
}

/// Set the transmit queue length of `name` to at least `wanted`; returns the length in effect.
fn set_tx_queue_len_at_least(name: &str, wanted: u32) -> io::Result<u32> {
    let current = tx_queue_len(name)?;
    let Some(target) = tx_queue_len_target(current, wanted) else {
        return Ok(current);
    };
    let socket = control_socket()?;
    let mut request = interface_request(name)?;
    request.ifr_ifru.ifru_ifindex = libc::c_int::try_from(target)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "qlen too large"))?;
    // SAFETY: `SIOCSIFTXQLEN` reads `ifr_name` and the integer member of a valid `ifreq`.
    if unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCSIFTXQLEN as _, &raw mut request) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(target)
}

fn control_socket() -> io::Result<OwnedFd> {
    // SAFETY: plain socket(2) call; the result is checked before it is wrapped.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a freshly opened descriptor that nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn interface_request(name: &str) -> io::Result<libc::ifreq> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() >= libc::IFNAMSIZ || bytes.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid interface name",
        ));
    }
    // SAFETY: `ifreq` is plain old data; all-zero is a valid value (empty name, zero union).
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    for (dst, src) in request.ifr_name.iter_mut().zip(bytes) {
        *dst = *src as libc::c_char;
    }
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::open_with_vnet_fallback;
    use std::fs::File;

    #[test]
    fn tx_queue_len_only_ever_grows() {
        assert_eq!(super::tx_queue_len_target(500, 1024), Some(1024));
        assert_eq!(super::tx_queue_len_target(1024, 1024), None);
        assert_eq!(super::tx_queue_len_target(10_000, 1024), None);
    }

    #[test]
    fn tx_queue_len_reads_a_real_interface_and_rejects_bad_names() {
        // Every network namespace has a loopback device; reading needs no privilege.
        assert!(super::tx_queue_len("lo").is_ok());
        assert!(super::tx_queue_len("").is_err());
        assert!(super::tx_queue_len("a-name-longer-than-ifnamsiz").is_err());
        assert!(super::tx_queue_len("gotatun-none0").is_err());
    }

    #[test]
    fn raising_an_unknown_interface_fails_without_panicking() {
        assert!(super::set_tx_queue_len_at_least("gotatun-none0", 1024).is_err());
        super::raise_tx_queue_len("gotatun-none0");
    }

    #[test]
    fn unsupported_vnet_header_retries_without_the_header() {
        let mut requests = Vec::new();
        let (device, vnet_header) = open_with_vnet_fallback(|requested| {
            requests.push(requested);
            if requested {
                Err("IFF_VNET_HDR unsupported")
            } else {
                Ok("plain TUN")
            }
        })
        .unwrap();

        assert_eq!(device, "plain TUN");
        assert!(!vnet_header);
        assert_eq!(requests, [true, false]);
    }

    #[test]
    fn failure_of_both_open_modes_returns_the_original_error() {
        let mut requests = Vec::new();
        let result: Result<(&str, bool), &str> = open_with_vnet_fallback(|requested| {
            requests.push(requested);
            Err(if requested {
                "vnet failure"
            } else {
                "plain failure"
            })
        });

        assert_eq!(result, Err("vnet failure"));
        assert_eq!(requests, [true, false]);
    }

    #[test]
    fn unsupported_tun_tso_ioctl_keeps_the_software_path_available() {
        let file = File::open("/dev/null").unwrap();

        assert!(!super::enable_tso_with_fallback(&file));
    }
}
