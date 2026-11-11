// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

//! Linux-specific TUN setup and software fallback policy.

use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    io,
    net::IpAddr,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

use crate::packet::{Ip, Packet};
use crate::task::Task;
use crate::tun::is_fatal_tun_error;
use tokio::sync::{mpsc, oneshot};
use zerocopy::IntoBytes;

/// Number of writers used to measure concurrent TUN injection without changing the interface.
const TUN_WRITE_WORKERS: usize = 2;

/// Bounds batch descriptors waiting at each TUN writer; packet buffers remain bounded upstream.
const TUN_WRITE_QUEUE_CAPACITY: usize = 8;

/// A flow identity that stays constant for packets that must retain FIFO order in one TUN lane.
#[derive(Debug, Hash, PartialEq, Eq)]
enum TunFlowPart {
    /// The transport ports distinguish TCP and UDP flows sharing the same IP addresses.
    Ports(u16, u16),
    /// IPv4 fragments use their datagram identifier because later fragments have no ports.
    Fragment(u16),
    /// Other protocols and IPv6 packets with extension headers share a network-protocol lane.
    Protocol,
}

/// The fields used to route an inner IP flow to one writer without reading packet payloads.
#[derive(Debug, Hash, PartialEq, Eq)]
struct TunFlowKey {
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    part: TunFlowPart,
}

/// Read a stable flow key from a validated IP packet without allocating.
fn flow_key(packet: &Packet<Ip>) -> Option<TunFlowKey> {
    let bytes = packet.as_bytes();
    let source = packet.source()?;
    let destination = packet.destination()?;
    let version = packet.header.version();

    let (protocol, transport_offset, fragment) = match version {
        4 => {
            let protocol = *bytes.get(9)?;
            let identification = u16::from_be_bytes(bytes.get(4..6)?.try_into().ok()?);
            let fragment = u16::from_be_bytes(bytes.get(6..8)?.try_into().ok()?);
            let is_fragment = fragment & 0x3fff != 0;
            let transport_offset = usize::from(bytes[0] & 0x0f) * 4;
            (
                protocol,
                Some(transport_offset),
                is_fragment.then_some(identification),
            )
        }
        6 => (*bytes.get(6)?, Some(40), None),
        _ => return None,
    };

    let part = if let Some(identification) = fragment {
        TunFlowPart::Fragment(identification)
    } else if matches!(protocol, 6 | 17) {
        transport_offset
            .and_then(|offset| bytes.get(offset..offset.saturating_add(4)))
            .map(|ports| {
                TunFlowPart::Ports(
                    u16::from_be_bytes([ports[0], ports[1]]),
                    u16::from_be_bytes([ports[2], ports[3]]),
                )
            })
            .unwrap_or(TunFlowPart::Protocol)
    } else {
        TunFlowPart::Protocol
    };

    Some(TunFlowKey {
        source,
        destination,
        protocol,
        part,
    })
}

/// Select one writer lane for a flow; one lane always receives its packets in input order.
fn flow_shard(packet: &Packet<Ip>, worker_count: usize) -> usize {
    if worker_count <= 1 {
        return 0;
    }
    let Some(key) = flow_key(packet) else {
        return 0;
    };
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    hasher.finish() as usize % worker_count
}

/// Partition packets by stable flow while keeping each lane's original packet order.
fn partition_packets(packets: Vec<Packet<Ip>>, worker_count: usize) -> Vec<Vec<Packet<Ip>>> {
    let worker_count = worker_count.max(1);
    let mut shards = (0..worker_count).map(|_| Vec::new()).collect::<Vec<_>>();
    for packet in packets {
        let shard = flow_shard(&packet, worker_count);
        shards[shard].push(packet);
    }
    shards
}

/// One ordered batch and its completion result for a TUN writer.
struct TunWriteRequest {
    packets: Vec<Packet<Ip>>,
    completion: oneshot::Sender<io::Result<()>>,
}

/// Fixed writer lanes that send different inner flows through the same Linux TUN descriptor.
pub(super) struct TunWriteWorkers {
    senders: Vec<mpsc::Sender<TunWriteRequest>>,
    /// Aborted when the last `TunDevice` owner drops its state.
    _tasks: Vec<Task>,
}

impl TunWriteWorkers {
    /// Start two FIFO writer tasks sharing `tun`; each flow stays assigned to one task.
    pub(super) fn new(
        tun: std::sync::Arc<tun::AsyncDevice>,
        vnet_header: bool,
        offloads: TunOffloadState,
    ) -> Self {
        let mut senders = Vec::with_capacity(TUN_WRITE_WORKERS);
        let mut tasks = Vec::with_capacity(TUN_WRITE_WORKERS);
        for _ in 0..TUN_WRITE_WORKERS {
            let (sender, mut receiver) = mpsc::channel::<TunWriteRequest>(TUN_WRITE_QUEUE_CAPACITY);
            let tun = std::sync::Arc::clone(&tun);
            let task = Task::spawn("tun write worker", async move {
                while let Some(request) = receiver.recv().await {
                    let mut packets = request.packets;
                    let result =
                        super::write_tun_packets(&tun, vnet_header, offloads, &mut packets).await;
                    let _ = request.completion.send(result);
                }
            });
            senders.push(sender);
            tasks.push(task);
        }
        Self {
            senders,
            _tasks: tasks,
        }
    }

    /// Send a run and wait until every selected writer has finished it.
    pub(super) async fn send_many(&self, packets: &mut Vec<Packet<Ip>>) -> io::Result<()> {
        if packets.is_empty() {
            return Ok(());
        }
        send_partitioned(&self.senders, std::mem::take(packets)).await
    }
}

/// Dispatch a packet run and await every lane so upstream bounds cover queued and active writes.
async fn send_partitioned(
    senders: &[mpsc::Sender<TunWriteRequest>],
    packets: Vec<Packet<Ip>>,
) -> io::Result<()> {
    if senders.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "no TUN write workers are available",
        ));
    }

    let mut pending = Vec::with_capacity(senders.len());
    let mut first_error = None;
    for (sender, packets) in senders
        .iter()
        .zip(partition_packets(packets, senders.len()))
    {
        if packets.is_empty() {
            continue;
        }
        let (completion, result) = oneshot::channel();
        if sender
            .send(TunWriteRequest {
                packets,
                completion,
            })
            .await
            .is_ok()
        {
            pending.push(result);
        } else if first_error.is_none() {
            first_error = Some(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "TUN write worker stopped",
            ));
        }
    }

    let mut fatal_error = None;
    for result in pending {
        let result = match result.await {
            Ok(result) => result,
            Err(_) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "TUN write worker stopped before completing its batch",
            )),
        };
        if let Err(error) = result {
            if is_fatal_tun_error(&error) {
                if fatal_error.is_none() {
                    fatal_error = Some(error);
                }
            } else if first_error.is_none() {
                first_error = Some(error);
            }
        }
    }

    fatal_error.or(first_error).map_or(Ok(()), Err)
}

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

/// Offloads successfully enabled on the TUN descriptor.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct TunOffloadState {
    pub(super) tcp_tso: bool,
    pub(super) udp_uso: bool,
}

/// Enable TCP TSO first, then add UDP USO when the running kernel supports it.
///
/// The second ioctl repeats the TCP flags because `TUNSETOFFLOAD` replaces the descriptor's full
/// offload mask. A kernel that rejects USO therefore keeps the first, TCP-only mask.
pub(super) fn enable_tun_offloads_with_fallback(tun: &impl AsRawFd) -> TunOffloadState {
    enable_offloads_with_fallback(
        || super::tso::try_enable_tso(tun),
        || super::tso::try_enable_udp_segmentation(tun),
    )
}

/// Convert ordered TUN offload requests into the capabilities that remain available.
///
/// UDP USO is attempted only after TCP TSO succeeds. A rejected USO request must preserve the
/// earlier TCP-only mask and leave the software UDP segmentation path available.
fn enable_offloads_with_fallback(
    enable_tcp_tso: impl FnOnce() -> io::Result<()>,
    enable_udp_uso: impl FnOnce() -> io::Result<()>,
) -> TunOffloadState {
    match enable_tcp_tso() {
        Ok(()) => match enable_udp_uso() {
            Ok(()) => TunOffloadState {
                tcp_tso: true,
                udp_uso: true,
            },
            Err(error) => {
                tracing::debug!(%error, "TUN UDP segmentation unavailable; continuing with TCP TSO");
                TunOffloadState {
                    tcp_tso: true,
                    udp_uso: false,
                }
            }
        },
        Err(error) => {
            tracing::debug!(%error, "TUN TSO unavailable; using software packet handling");
            TunOffloadState::default()
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
    let fd = socket.as_raw_fd();
    // SAFETY: `SIOCGIFTXQLEN` reads `ifr_name` and writes the length into the union's integer
    // member; `request` is a valid, initialised `ifreq` for the duration of the call.
    let status = unsafe { libc::ioctl(fd, libc::SIOCGIFTXQLEN as _, &raw mut request) };
    if status < 0 {
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
    let fd = socket.as_raw_fd();
    // SAFETY: `SIOCSIFTXQLEN` reads `ifr_name` and the integer member of a valid `ifreq`.
    let status = unsafe { libc::ioctl(fd, libc::SIOCSIFTXQLEN as _, &raw mut request) };
    if status < 0 {
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
    use crate::packet::{Ip, Packet};
    use bytes::BytesMut;
    use std::fs::File;
    use zerocopy::IntoBytes;

    /// Build a small IPv4 UDP packet whose source port identifies its inner flow.
    fn udp_packet(source_port: u16, identification: u16, marker: u8) -> Packet<Ip> {
        let mut bytes = BytesMut::zeroed(36);
        bytes[0] = 0x45;
        let total_len = bytes.len() as u16;
        bytes[2..4].copy_from_slice(&total_len.to_be_bytes());
        bytes[4..6].copy_from_slice(&identification.to_be_bytes());
        bytes[9] = 17;
        bytes[12..16].copy_from_slice(&[10, 0, 0, 1]);
        bytes[16..20].copy_from_slice(&[10, 0, 0, 2]);
        bytes[20..22].copy_from_slice(&source_port.to_be_bytes());
        bytes[22..24].copy_from_slice(&53_u16.to_be_bytes());
        bytes[24..26].copy_from_slice(&16_u16.to_be_bytes());
        bytes[28] = marker;
        Packet::from_bytes(bytes)
            .try_into_ip()
            .expect("the test packet has an IPv4 header")
    }

    /// Build a fragment with the same IPv4 identification and endpoints.
    fn ipv4_fragment(offset: u16, more_fragments: bool, identification: u16) -> Packet<Ip> {
        let mut bytes: Packet<[u8]> = udp_packet(9000, identification, 0).into();
        {
            let bytes = bytes.buf_mut();
            let flags = offset | if more_fragments { 0x2000 } else { 0 };
            bytes[6..8].copy_from_slice(&flags.to_be_bytes());
            if offset != 0 {
                bytes[20..24].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
            }
        }
        bytes
            .try_into_ip()
            .expect("the fragment still has an IPv4 header")
    }

    /// `id` remains a test-only marker after packets are split into writer lanes.
    fn packet_id(packet: &Packet<Ip>) -> u16 {
        let bytes = packet.as_bytes();
        u16::from_be_bytes([bytes[4], bytes[5]])
    }

    #[test]
    fn tun_writer_shard_uses_the_full_udp_flow_and_ignores_packet_contents() {
        let first = udp_packet(12_000, 1, 0x11);
        let later = udp_packet(12_000, 2, 0x22);
        let other_flow = udp_packet(12_001, 3, 0x33);

        assert_eq!(super::flow_key(&first), super::flow_key(&later));
        assert_ne!(super::flow_key(&first), super::flow_key(&other_flow));
        assert_eq!(super::flow_shard(&first, 4), super::flow_shard(&later, 4));
    }

    #[test]
    fn tun_writer_partition_keeps_each_flow_in_fifo_order() {
        let first = udp_packet(12_000, 1, 0x11);
        let other_source_port = (12_001..13_000)
            .find(|port| {
                let packet = udp_packet(*port, 2, 0x22);
                super::flow_shard(&packet, 2) != super::flow_shard(&first, 2)
            })
            .expect("the deterministic flow hash distributes the test ports");
        let later = udp_packet(12_000, 3, 0x33);
        let packets = vec![first, udp_packet(other_source_port, 2, 0x22), later];

        let shards = super::partition_packets(packets, 2);
        let first_lane = super::flow_shard(&udp_packet(12_000, 4, 0x44), 2);
        let ids = shards[first_lane].iter().map(packet_id).collect::<Vec<_>>();

        assert_eq!(ids, [1, 3]);
    }

    #[test]
    fn tun_writer_keeps_all_ipv4_fragments_in_one_lane() {
        let first = ipv4_fragment(0, true, 7);
        let later = ipv4_fragment(1, false, 7);

        assert_eq!(super::flow_key(&first), super::flow_key(&later));
        assert_eq!(super::flow_shard(&first, 4), super::flow_shard(&later, 4));
    }

    #[tokio::test]
    async fn tun_writer_dispatch_waits_for_the_selected_lane_to_finish() {
        use tokio::sync::{mpsc, oneshot};

        let packet = udp_packet(12_000, 1, 0x11);
        let lane = super::flow_shard(&packet, 2);
        let (first_tx, first_rx) = mpsc::channel::<super::TunWriteRequest>(1);
        let (second_tx, second_rx) = mpsc::channel::<super::TunWriteRequest>(1);
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let mut selected_rx = if lane == 0 { first_rx } else { second_rx };
        let worker = tokio::spawn(async move {
            let request = selected_rx
                .recv()
                .await
                .expect("the selected lane receives the packet");
            let ids = request.packets.iter().map(packet_id).collect::<Vec<_>>();
            started_tx
                .send(ids)
                .expect("the test is waiting for this lane");
            release_rx.await.expect("the test releases the writer");
            request
                .completion
                .send(Ok(()))
                .expect("the dispatch waits for the writer result");
        });
        let senders = [first_tx, second_tx];
        let dispatch =
            tokio::spawn(async move { super::send_partitioned(&senders, vec![packet]).await });

        assert_eq!(started_rx.await.unwrap(), [1]);
        assert!(!dispatch.is_finished());
        release_tx.send(()).unwrap();
        dispatch.await.unwrap().unwrap();
        worker.await.unwrap();
    }

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

        assert_eq!(
            super::enable_tun_offloads_with_fallback(&file),
            super::TunOffloadState::default()
        );
    }

    /// Keeps TCP TSO active when a kernel rejects the later UDP USO request.
    #[test]
    fn unsupported_udp_segmentation_keeps_tcp_tso_enabled() {
        let calls = std::cell::RefCell::new(Vec::new());
        let state = super::enable_offloads_with_fallback(
            || {
                calls.borrow_mut().push("tcp");
                Ok(())
            },
            || {
                calls.borrow_mut().push("udp");
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "UDP USO unavailable",
                ))
            },
        );

        assert_eq!(
            state,
            super::TunOffloadState {
                tcp_tso: true,
                udp_uso: false,
            }
        );
        assert_eq!(calls.into_inner(), ["tcp", "udp"]);
    }
}
