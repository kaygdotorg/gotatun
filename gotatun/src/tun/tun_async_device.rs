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

//! Implementations of [`IpSend`] and [`IpRecv`] for the [`tun`] crate.

#[cfg(target_os = "linux")]
mod gso;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
mod tso;
#[cfg(target_os = "linux")]
mod virtio;

#[cfg(target_os = "linux")]
use bytes::BytesMut;
use tokio::{sync::watch, time::sleep};
use tun::AbstractDevice;
use zerocopy::IntoBytes;

use crate::{
    packet::{Ip, Packet, PacketBufPool},
    task::Task,
    tun::{IpRecv, IpSend, MtuWatcher, is_fatal_tun_error},
};

#[cfg(not(target_os = "linux"))]
use std::iter;
#[cfg(target_os = "linux")]
use std::ops::Deref;
use std::{io, sync::Arc, time::Duration};

#[cfg(target_os = "linux")]
const MAX_TUN_PACKET_LEN: usize = 40 + u16::MAX as usize;

#[cfg(target_os = "linux")]
const MAX_TUN_FRAME_LEN: usize = virtio::VirtioNetHeader::LEN + MAX_TUN_PACKET_LEN;

/// Error from [`TunDevice`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Failed to open TUN device
    #[error("Failed to open TUN device: {0}")]
    OpenTun(#[source] tun::Error),

    /// Failed to get TUN device name
    #[error("Failed to get TUN device name: {0}")]
    GetTunName(#[source] tun::Error),

    /// Unsupported TUN feature
    #[error("Unsupported TUN feature: {0}")]
    UnsupportedFeature(String),

    /// Failed to get TUN device MTU
    #[error("Failed to get TUN device MTU: {0}")]
    GetMtu(#[source] tun::Error),
}

/// A kernel virtual network device; a TUN device.
///
/// Implements [`IpSend`] and [`IpRecv`].
#[derive(Clone)]
pub struct TunDevice {
    tun: Arc<tun::AsyncDevice>,
    state: Arc<TunDeviceState>,
}

struct TunDeviceState {
    mtu: MtuWatcher,

    /// Task which monitors TUN device MTU. Aborted when dropped.
    _mtu_monitor: Task,

    /// Whether this descriptor carries virtio-net headers (Linux offload path only).
    #[cfg(target_os = "linux")]
    vnet_header: bool,

    #[cfg(target_os = "linux")]
    offloads: linux::TunOffloadState,

    #[cfg(target_os = "linux")]
    read_buf: tokio::sync::Mutex<BytesMut>,
}

impl TunDevice {
    /// Construct from a name.
    ///
    /// # Warning
    ///
    /// If this is used on Windows, you are recommended to enable the `verify_binary_signature`
    /// feature for the `tun` crate. By default, `tun` will load `wintun.dll` using the
    /// [default search order], which includes the `PATH` environment variable.
    ///
    /// [default search order]: <https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order>
    pub fn from_name(name: &str) -> Result<Self, Error> {
        let mut tun_config = tun::Configuration::default();
        if cfg!(not(target_os = "macos")) || name != "utun" {
            // If the name is 'utun', automatically assign a name
            tun_config.tun_name(name);
        }
        #[cfg(target_os = "macos")]
        tun_config.platform_config(|p| {
            p.enable_routing(false);
        });

        #[cfg(target_os = "linux")]
        {
            let (tun, vnet_header) =
                linux::create_tun_with_vnet_fallback(&mut tun_config).map_err(Error::OpenTun)?;
            let offloads = if vnet_header {
                linux::enable_tun_offloads_with_fallback(tun.deref())
            } else {
                tracing::debug!(
                    "TUN virtio network header unavailable; using software packet handling"
                );
                linux::TunOffloadState::default()
            };
            tracing::info!(
                vnet_header,
                tcp_tso = offloads.tcp_tso,
                udp_uso = offloads.udp_uso,
                "Linux TUN offload setup"
            );
            // Only a device we created here: one handed to us via `from_tun_device` keeps
            // whatever its owner configured.
            if let Ok(name) = tun.tun_name() {
                linux::raise_tx_queue_len(&name);
            }
            TunDevice::from_tun_device_with_vnet_header(tun, vnet_header, offloads)
        }

        #[cfg(not(target_os = "linux"))]
        {
            // TODO: for wintun, must set path or enable signature check
            // we should upstream to `tun`
            let tun = tun::create_as_async(&tun_config).map_err(Error::OpenTun)?;
            TunDevice::from_tun_device(tun)
        }
    }

    /// Construct from a name with an explicit path to `wintun.dll`.
    ///
    /// Use this on Windows when `wintun.dll` is not on `PATH` or in the executable directory.
    #[cfg(windows)]
    pub fn from_name_with_wintun_path(
        name: &str,
        wintun_path: &std::path::Path,
    ) -> Result<Self, Error> {
        let mut tun_config = tun::Configuration::default();
        tun_config.tun_name(name);
        tun_config.platform_config(|p| {
            p.wintun_file(wintun_path.as_os_str());
        });
        let tun = tun::create_as_async(&tun_config).map_err(Error::OpenTun)?;
        TunDevice::from_tun_device(tun)
    }

    /// Construct from a [`tun::AsyncDevice`].
    pub fn from_tun_device(tun: tun::AsyncDevice) -> Result<Self, Error> {
        #[cfg(target_os = "linux")]
        {
            Self::from_tun_device_with_vnet_header(tun, false, linux::TunOffloadState::default())
        }
        #[cfg(not(target_os = "linux"))]
        {
            Self::from_tun_device_with_vnet_header(tun)
        }
    }

    /// Construct with the virtio-header and offload capabilities known for this descriptor.
    fn from_tun_device_with_vnet_header(
        tun: tun::AsyncDevice,
        #[cfg(target_os = "linux")] vnet_header: bool,
        #[cfg(target_os = "linux")] offloads: linux::TunOffloadState,
    ) -> Result<Self, Error> {
        #[cfg(target_os = "linux")]
        if tun.packet_information() {
            return Err(Error::UnsupportedFeature("packet_information".to_string()));
        }

        let mtu = tun.mtu().map_err(Error::GetMtu)?;
        let (tx, rx) = watch::channel(mtu);

        let tun = Arc::new(tun);
        let tun_weak = Arc::downgrade(&tun);

        // Watch for changes to the MTU of the TUN device.
        // On Linux, subscribe to `NETLINK_ROUTE` `RTMGRP_LINK` events so an idle device wakes
        // zero times (#260, J1150) and learns MTU changes immediately; fall back to a 3 s poll
        // on other platforms or if opening the netlink socket fails.
        let mtu_monitor = Task::spawn("tun_mtu_monitor", async move {
            #[cfg(target_os = "linux")]
            if watch_mtu_netlink(&tun_weak, mtu, &tx).await {
                return;
            }
            let mut mtu = mtu;
            loop {
                sleep(Duration::from_secs(3)).await;
                let Some(tun) = tun_weak.upgrade() else {
                    break;
                };
                let Ok(new) = tun.mtu() else {
                    break;
                };
                if new != mtu {
                    mtu = new;
                    if tx.send(mtu).is_err() {
                        break;
                    }
                }
            }
        });

        Ok(Self {
            tun,
            state: Arc::new(TunDeviceState {
                mtu: rx.into(),
                _mtu_monitor: mtu_monitor,
                #[cfg(target_os = "linux")]
                vnet_header,
                #[cfg(target_os = "linux")]
                offloads,
                #[cfg(target_os = "linux")]
                read_buf: tokio::sync::Mutex::new(BytesMut::zeroed(MAX_TUN_FRAME_LEN)),
            }),
        })
    }

    /// Write one raw IP packet when the descriptor does not use virtio headers.
    async fn write_ip_packet(&self, packet: Packet<Ip>) -> io::Result<()> {
        self.tun.send(packet.as_bytes()).await?;
        Ok(())
    }

    /// Get the name of the TUN device.
    pub fn name(&self) -> Result<String, Error> {
        self.tun.tun_name().map_err(Error::GetTunName)
    }
}

/// Watch for Linux link-layer changes over a `NETLINK_ROUTE` (`RTMGRP_LINK`) socket and re-read
/// the TUN device MTU whenever a link event arrives (#260, J1150).
///
/// Returns `true` when the watcher ran until the TUN device or watch channel closed, or `false`
/// if opening/binding the netlink socket failed so the caller should fall back to polling.
#[cfg(target_os = "linux")]
async fn watch_mtu_netlink(
    tun_weak: &std::sync::Weak<tun::AsyncDevice>,
    mut mtu: u16,
    tx: &watch::Sender<u16>,
) -> bool {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    // SAFETY: socket() takes only integer constants and returns a new owned fd or -1.
    let raw_fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if raw_fd < 0 {
        return false;
    }
    // SAFETY: `raw_fd` is a valid, freshly created descriptor owned exclusively here.
    let owned_fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

    // SAFETY: zero-initializing a C POD sockaddr_nl struct is valid.
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    addr.nl_groups = libc::RTMGRP_LINK as u32;

    // SAFETY: binding our owned netlink socket to a valid sockaddr_nl.
    let bound = unsafe {
        libc::bind(
            owned_fd.as_raw_fd(),
            (&raw const addr).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if bound < 0 {
        return false;
    }

    let Ok(async_fd) = tokio::io::unix::AsyncFd::new(owned_fd) else {
        return false;
    };

    let mut scratch = [0_u8; 4096];
    loop {
        let Ok(mut guard) = async_fd.readable().await else {
            return true;
        };
        // Drain every queued netlink message before checking MTU so a burst of link events
        // collapses into one ioctl.
        loop {
            // SAFETY: receiving into our stack scratch buffer from our own non-blocking socket.
            let n = unsafe {
                libc::recv(
                    async_fd.as_raw_fd(),
                    scratch.as_mut_ptr().cast::<libc::c_void>(),
                    scratch.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if n > 0 {
                continue;
            }
            if n == 0 {
                return true;
            }
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                guard.clear_ready();
                break;
            }
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            // ENOBUFS means the kernel dropped some netlink messages; still re-check MTU below.
            if err.raw_os_error() == Some(libc::ENOBUFS) {
                continue;
            }
            return false;
        }

        let Some(tun) = tun_weak.upgrade() else {
            return true;
        };
        let Ok(new) = tun.mtu() else {
            return true;
        };
        if new != mtu {
            mtu = new;
            if tx.send(mtu).is_err() {
                return true;
            }
        }
    }
}

impl IpSend for TunDevice {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        if self.state.vnet_header {
            let mut packets = vec![packet];
            return self.send_many(&mut packets).await;
        }
        self.write_ip_packet(packet).await
    }

    async fn send_many(&mut self, packets: &mut Vec<Packet<Ip>>) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        if self.state.vnet_header {
            let disable_gso = std::env::var_os("GOTATUN_DIAG_DISABLE_TUN_GSO").is_some();
            let frames = gso::coalesce_packets(
                std::mem::take(packets),
                self.state.offloads.tcp_tso && !disable_gso,
                self.state.offloads.udp_uso && !disable_gso,
            );
            let mut first_error = None;
            let tun = self.tun.as_ref();
            for frame in frames {
                let result = gso::write_frame_with_fallback(frame, |frame_bytes| async move {
                    tun.send(frame_bytes.as_bytes()).await.map(|_| ())
                })
                .await;
                match result {
                    Ok(()) => {}
                    Err(error) => {
                        let fatal = is_fatal_tun_error(&error);
                        if fatal {
                            return Err(error);
                        }
                        if first_error.is_none() {
                            first_error = Some(error);
                        }
                    }
                }
            }
            return first_error.map_or(Ok(()), Err);
        }

        let mut first_error = None;
        for packet in packets.drain(..) {
            if let Err(error) = self.write_ip_packet(packet).await {
                if is_fatal_tun_error(&error) {
                    return Err(error);
                }
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

#[cfg(not(target_os = "linux"))]
impl IpRecv for TunDevice {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + 'a> {
        let mut packet = pool.get();
        let n = self.tun.recv(&mut packet).await?;
        packet.truncate(n);
        match packet.try_into_ip() {
            Ok(packet) => Ok(iter::once(packet)),
            Err(e) => Err(io::Error::other(e.to_string())),
        }
    }

    fn mtu(&self) -> MtuWatcher {
        self.state.mtu.clone()
    }
}

#[cfg(target_os = "linux")]
impl IpRecv for TunDevice {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + 'a> {
        let mut read_buf = self.state.read_buf.lock().await;
        let n = self.tun.recv(&mut read_buf).await?;
        if n > read_buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TUN read exceeded the receive buffer",
            ));
        }

        // Keep one oversized scratch allocation per TUN device. The packet pool still owns the
        // returned packet, so its lifetime is independent of the next read into this buffer.
        let mut packet = pool.get();
        packet.buf_mut().clear();
        packet.buf_mut().extend_from_slice(&read_buf[..n]);
        drop(read_buf);

        if self.state.vnet_header {
            tso::new_tso_iter_from_vnet(packet)
        } else {
            let packet = packet
                .try_into_ip()
                .map_err(|e| io::Error::other(e.to_string()))?;
            Ok(tso::single_packet(packet))
        }
    }

    fn mtu(&self) -> MtuWatcher {
        self.state.mtu.clone()
    }
}
