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

//! Linux UDP send and receive batching, including optional GSO and GRO offloads.

#[cfg(target_os = "linux")]
use nix::sys::socket::ControlMessage;
use nix::sys::socket::{MsgFlags, MultiHeaders, SockaddrStorage};
#[cfg(target_os = "linux")]
use nix::sys::socket::{setsockopt, sockopt};
use std::{
    io::{self, IoSlice},
    net::SocketAddr,
    os::fd::{AsRawFd, RawFd},
};

use super::read_watched::ReadWatchedSocket;
use crate::{
    packet::Packet,
    udp::{
        UdpSend,
        socket::{UdpSocket, check_send_max_number_of_packets},
    },
};

/// Max number of packets/messages for sendmmsg/recvmmsg.
///
/// Each GRO slot reserves 256 KiB, so matching the 64-segment UDP GSO limit bounds the receive
/// reserve to 16 MiB instead of reserving 25 MiB for 100 messages.
#[cfg(target_os = "linux")]
const MAX_PACKET_COUNT: usize = UDP_SEGMENT_MAX_DATAGRAMS;

/// Max number of packets/messages for sendmmsg on Android.
///
/// This file also builds for Android, which has neither the GSO segment limit nor the GRO
/// receive reserve that the Linux cap is sized for, so it keeps the previous batch size.
#[cfg(target_os = "android")]
const MAX_PACKET_COUNT: usize = 100;

/// Maximum UDP payload length for one IPv4 datagram, accounting for IPv4 and UDP headers.
#[cfg(target_os = "linux")]
const MAX_IPV4_PAYLOAD_LEN: usize = (1 << 16) - 1 - 20 - 8;

/// Maximum UDP payload length for one IPv6 datagram, accounting for the UDP header.
#[cfg(target_os = "linux")]
const MAX_IPV6_PAYLOAD_LEN: usize = (1 << 16) - 1 - 8;

/// Kernel-imposed limit for UDP_SEGMENT datagrams in one coalesced message.
#[cfg(target_os = "linux")]
const UDP_SEGMENT_MAX_DATAGRAMS: usize = 64;

#[derive(Default)]
pub struct SendmmsgBuf {
    targets: Vec<Option<SockaddrStorage>>,
    #[cfg(target_os = "linux")]
    gso_batches: Vec<UdpGsoBatch>,
}

#[cfg(all(test, target_os = "linux"))]
impl SendmmsgBuf {
    fn gso_batches(&self) -> &[UdpGsoBatch] {
        &self.gso_batches
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UdpGsoBatch {
    start: usize,
    datagrams: usize,
    target: SocketAddr,
    segment_size: usize,
    payload_len: usize,
}

#[cfg(target_os = "linux")]
fn plan_udp_gso_batches<I>(packets: I, batches: &mut Vec<UdpGsoBatch>)
where
    I: IntoIterator<Item = (usize, SocketAddr)>,
{
    batches.clear();
    let mut end_batch = false;

    for (packet_index, (packet_len, target)) in packets.into_iter().enumerate() {
        if let Some(batch) = batches.last_mut() {
            let max_payload_len = if batch.target.is_ipv6() {
                MAX_IPV6_PAYLOAD_LEN
            } else {
                MAX_IPV4_PAYLOAD_LEN
            };
            let can_coalesce = batch.payload_len + packet_len <= max_payload_len
                && batch.segment_size != 0
                && packet_len != 0
                && packet_len <= batch.segment_size
                && batch.datagrams < UDP_SEGMENT_MAX_DATAGRAMS
                && target == batch.target
                && !end_batch;

            if can_coalesce {
                batch.payload_len += packet_len;
                batch.datagrams += 1;
                if packet_len < batch.segment_size {
                    end_batch = true;
                }
                continue;
            }
        }

        end_batch = false;
        batches.push(UdpGsoBatch {
            start: packet_index,
            datagrams: 1,
            target,
            segment_size: packet_len,
            payload_len: packet_len,
        });
    }
}

#[cfg(target_os = "linux")]
fn udp_gso_segment_size(batch: &UdpGsoBatch) -> Option<u16> {
    if batch.datagrams <= 1 || batch.segment_size == 0 {
        return None;
    }

    u16::try_from(batch.segment_size).ok()
}

#[cfg(target_os = "linux")]
fn udp_gso_control_messages(segment_size: &u16) -> [ControlMessage<'_>; 1] {
    [ControlMessage::UdpGsoSegments(segment_size)]
}

#[cfg(target_os = "linux")]
fn should_disable_udp_gso(err: &io::Error) -> bool {
    err.raw_os_error() == Some(libc::EIO)
}

struct SendBatch<'a, 'p> {
    socket: &'a ReadWatchedSocket,
    fd: RawFd,
    pkts: &'a [[IoSlice<'p>; 1]],
    targets: &'a [Option<SockaddrStorage>],
}

async fn send_plain_range(
    batch: &SendBatch<'_, '_>,
    mut packet_buf_start: usize,
    packet_buf_end: usize,
) -> io::Result<()> {
    while packet_buf_start < packet_buf_end {
        let result = batch
            .socket
            .send(|| {
                let mut multiheaders =
                    MultiHeaders::preallocate(packet_buf_end - packet_buf_start, None);
                let multiresult = nix::sys::socket::sendmmsg(
                    batch.fd,
                    &mut multiheaders,
                    &batch.pkts[packet_buf_start..packet_buf_end],
                    &batch.targets[packet_buf_start..packet_buf_end],
                    [],
                    MsgFlags::MSG_DONTWAIT,
                )?;
                Ok(multiresult.count())
            })
            .await;
        let n = result?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "sendmmsg sent zero UDP datagrams",
            ));
        }
        packet_buf_start += n;
    }

    Ok(())
}

#[cfg(target_os = "linux")]
async fn send_gso_segment(
    udp_socket: &super::UdpSocket,
    batch: &SendBatch<'_, '_>,
    start: usize,
    datagrams: usize,
    segment_size: u16,
) -> io::Result<()> {
    let end = start + datagrams;
    let mut segment_iovs = [IoSlice::new(&[]); UDP_SEGMENT_MAX_DATAGRAMS];
    for (dst, packet_iov) in segment_iovs.iter_mut().zip(&batch.pkts[start..end]) {
        *dst = packet_iov[0];
    }
    let segment_iovs = &segment_iovs[..datagrams];
    let cmsgs = udp_gso_control_messages(&segment_size);

    let result = batch
        .socket
        .send(|| {
            let mut multiheaders = MultiHeaders::preallocate(1, Some(nix::cmsg_space!(u16)));
            let multiresult = nix::sys::socket::sendmmsg(
                batch.fd,
                &mut multiheaders,
                [&segment_iovs],
                &batch.targets[start..start + 1],
                cmsgs,
                MsgFlags::MSG_DONTWAIT,
            )?;
            Ok(multiresult.count())
        })
        .await;

    match result {
        Ok(1) => Ok(()),
        Ok(0) => Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "sendmmsg sent zero UDP GSO segments",
        )),
        Ok(_) => unreachable!("one UDP GSO message was submitted"),
        Err(err) if should_disable_udp_gso(&err) => {
            udp_socket.disable_udp_gso();
            send_plain_range(batch, start, end).await
        }
        Err(err) => Err(err),
    }
}

#[cfg(all(test, target_os = "linux"))]
mod gso_tests {
    use super::{
        MAX_IPV4_PAYLOAD_LEN, MAX_IPV6_PAYLOAD_LEN, MAX_PACKET_COUNT, UDP_SEGMENT_MAX_DATAGRAMS,
        UdpGsoBatch, plan_udp_gso_batches, udp_gso_control_messages, udp_gso_segment_size,
    };
    use nix::sys::socket::ControlMessage;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    /// Keep each Linux UDP batch within the segment limit that also bounds GRO buffer memory.
    #[test]
    fn message_batch_capacity_matches_udp_segment_limit() {
        assert_eq!(MAX_PACKET_COUNT, UDP_SEGMENT_MAX_DATAGRAMS);
    }

    fn target(port: u16) -> SocketAddr {
        (Ipv4Addr::LOCALHOST, port).into()
    }

    fn target_v6(port: u16) -> SocketAddr {
        (Ipv6Addr::LOCALHOST, port).into()
    }

    fn plan(packet_lens: &[usize], packet_targets: &[SocketAddr], batches: &mut Vec<UdpGsoBatch>) {
        plan_udp_gso_batches(
            packet_lens
                .iter()
                .copied()
                .zip(packet_targets.iter().copied()),
            batches,
        );
    }

    #[test]
    fn gso_plan_coalesces_equal_datagrams() {
        let mut batches = Vec::new();
        plan(
            &[1200, 1200, 1200],
            &[target(1000), target(1000), target(1000)],
            &mut batches,
        );

        assert_eq!(
            batches,
            vec![UdpGsoBatch {
                start: 0,
                datagrams: 3,
                target: target(1000),
                segment_size: 1200,
                payload_len: 3600,
            }]
        );
    }

    #[test]
    fn gso_plan_allows_short_tail_then_starts_new_batch() {
        let mut batches = Vec::new();
        plan(
            &[1200, 800, 1200],
            &[target(1000), target(1000), target(1000)],
            &mut batches,
        );

        assert_eq!(
            batches,
            vec![
                UdpGsoBatch {
                    start: 0,
                    datagrams: 2,
                    target: target(1000),
                    segment_size: 1200,
                    payload_len: 2000,
                },
                UdpGsoBatch {
                    start: 2,
                    datagrams: 1,
                    target: target(1000),
                    segment_size: 1200,
                    payload_len: 1200,
                },
            ]
        );
    }

    #[test]
    fn gso_plan_splits_at_segment_count_limit() {
        let packets = vec![1000; UDP_SEGMENT_MAX_DATAGRAMS + 1];
        let targets = vec![target(1000); packets.len()];
        let mut batches = Vec::new();
        plan(&packets, &targets, &mut batches);

        assert_eq!(
            batches,
            vec![
                UdpGsoBatch {
                    start: 0,
                    datagrams: UDP_SEGMENT_MAX_DATAGRAMS,
                    target: target(1000),
                    segment_size: 1000,
                    payload_len: 1000 * UDP_SEGMENT_MAX_DATAGRAMS,
                },
                UdpGsoBatch {
                    start: UDP_SEGMENT_MAX_DATAGRAMS,
                    datagrams: 1,
                    target: target(1000),
                    segment_size: 1000,
                    payload_len: 1000,
                },
            ]
        );
    }

    #[test]
    fn gso_plan_splits_at_ipv4_payload_limit() {
        let segment_size = MAX_IPV4_PAYLOAD_LEN / 2 + 1;
        let mut batches = Vec::new();
        plan(
            &[segment_size, segment_size],
            &[target(1000), target(1000)],
            &mut batches,
        );

        assert_eq!(
            batches,
            vec![
                UdpGsoBatch {
                    start: 0,
                    datagrams: 1,
                    target: target(1000),
                    segment_size,
                    payload_len: segment_size,
                },
                UdpGsoBatch {
                    start: 1,
                    datagrams: 1,
                    target: target(1000),
                    segment_size,
                    payload_len: segment_size,
                },
            ]
        );
    }

    #[test]
    fn gso_plan_uses_ipv6_payload_limit() {
        let segment_size = MAX_IPV6_PAYLOAD_LEN / 2;
        let packet_lens = [segment_size, segment_size, 2];
        let packet_targets = [target_v6(1000), target_v6(1000), target_v6(1000)];
        let mut batches = Vec::new();

        plan(&packet_lens, &packet_targets, &mut batches);

        assert_eq!(
            batches,
            vec![
                UdpGsoBatch {
                    start: 0,
                    datagrams: 2,
                    target: target_v6(1000),
                    segment_size,
                    payload_len: segment_size * 2,
                },
                UdpGsoBatch {
                    start: 2,
                    datagrams: 1,
                    target: target_v6(1000),
                    segment_size: 2,
                    payload_len: 2,
                },
            ]
        );
    }

    #[test]
    fn gso_plan_splits_at_destination_changes() {
        let mut batches = Vec::new();
        plan(
            &[1200, 1200, 1200],
            &[target(1000), target(2000), target(2000)],
            &mut batches,
        );

        assert_eq!(
            batches,
            vec![
                UdpGsoBatch {
                    start: 0,
                    datagrams: 1,
                    target: target(1000),
                    segment_size: 1200,
                    payload_len: 1200,
                },
                UdpGsoBatch {
                    start: 1,
                    datagrams: 2,
                    target: target(2000),
                    segment_size: 1200,
                    payload_len: 2400,
                },
            ]
        );
    }

    #[test]
    fn gso_plan_does_not_coalesce_zero_length_datagrams() {
        let mut batches = Vec::new();
        plan(
            &[1200, 0, 1200, 0],
            &[target(1000), target(1000), target(1000), target(1000)],
            &mut batches,
        );

        assert_eq!(
            batches,
            vec![
                UdpGsoBatch {
                    start: 0,
                    datagrams: 1,
                    target: target(1000),
                    segment_size: 1200,
                    payload_len: 1200,
                },
                UdpGsoBatch {
                    start: 1,
                    datagrams: 1,
                    target: target(1000),
                    segment_size: 0,
                    payload_len: 0,
                },
                UdpGsoBatch {
                    start: 2,
                    datagrams: 1,
                    target: target(1000),
                    segment_size: 1200,
                    payload_len: 1200,
                },
                UdpGsoBatch {
                    start: 3,
                    datagrams: 1,
                    target: target(1000),
                    segment_size: 0,
                    payload_len: 0,
                },
            ]
        );
    }

    #[test]
    fn gso_plan_splits_at_address_family_changes() {
        let mut batches = Vec::new();
        plan(
            &[1200, 1200, 1200, 1200],
            &[target(1000), target(1000), target_v6(1000), target_v6(1000)],
            &mut batches,
        );

        assert_eq!(
            batches,
            vec![
                UdpGsoBatch {
                    start: 0,
                    datagrams: 2,
                    target: target(1000),
                    segment_size: 1200,
                    payload_len: 2400,
                },
                UdpGsoBatch {
                    start: 2,
                    datagrams: 2,
                    target: target_v6(1000),
                    segment_size: 1200,
                    payload_len: 2400,
                },
            ]
        );
    }

    #[test]
    fn gso_segment_size_only_emits_for_coalesced_batches() {
        assert_eq!(
            udp_gso_segment_size(&UdpGsoBatch {
                start: 0,
                datagrams: 3,
                target: target(1000),
                segment_size: 1200,
                payload_len: 3200,
            }),
            Some(1200)
        );
        assert_eq!(
            udp_gso_segment_size(&UdpGsoBatch {
                start: 3,
                datagrams: 1,
                target: target(1000),
                segment_size: 1200,
                payload_len: 1200,
            }),
            None
        );
        assert_eq!(
            udp_gso_segment_size(&UdpGsoBatch {
                start: 4,
                datagrams: 2,
                target: target(1000),
                segment_size: 0,
                payload_len: 0,
            }),
            None
        );
    }

    #[test]
    fn gso_segment_size_rejects_oversized_segment() {
        assert_eq!(
            udp_gso_segment_size(&UdpGsoBatch {
                start: 0,
                datagrams: 2,
                target: target(1000),
                segment_size: usize::from(u16::MAX) + 1,
                payload_len: (usize::from(u16::MAX) + 1) * 2,
            }),
            None
        );
    }

    #[test]
    fn udp_gso_control_message_uses_udp_segment_size() {
        let segment_size = 1200;
        let [cmsg] = udp_gso_control_messages(&segment_size);

        assert_eq!(cmsg, ControlMessage::UdpGsoSegments(&segment_size));
    }

    #[test]
    fn eio_disables_udp_gso() {
        let error = std::io::Error::from_raw_os_error(libc::EIO);
        assert!(super::should_disable_udp_gso(&error));

        let error = std::io::Error::from_raw_os_error(libc::ECONNREFUSED);
        assert!(!super::should_disable_udp_gso(&error));
    }

    #[tokio::test]
    async fn send_many_to_records_reusable_gso_plan() {
        use crate::packet::PacketBufPool;
        use crate::udp::UdpSend;
        use crate::udp::socket::SockOpt;
        use std::net::{Ipv4Addr, SocketAddr};
        use std::time::Duration;

        let socket = crate::udp::socket::UdpSocket::bind(
            (Ipv4Addr::LOCALHOST, 0).into(),
            SockOpt::default(),
        )
        .unwrap();
        let receiver = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let target: SocketAddr = receiver.local_addr().unwrap();
        let pool = PacketBufPool::<4096>::new(4);
        let mut send_buf = super::SendmmsgBuf::default();
        let mut packets = [(1200usize, 0x11), (1200, 0x22), (800, 0x33)]
            .into_iter()
            .map(|(len, contents)| {
                let mut packet = pool.get();
                packet.truncate(len);
                packet.fill(contents);
                (packet, target)
            })
            .collect();

        socket
            .send_many_to(&mut send_buf, &mut packets)
            .await
            .unwrap();

        assert!(packets.is_empty());
        assert_eq!(
            send_buf.gso_batches(),
            &[UdpGsoBatch {
                start: 0,
                datagrams: 3,
                target,
                segment_size: 1200,
                payload_len: 3200,
            }]
        );

        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut recv_buf = vec![0u8; 1200];
        for (expected_len, expected_contents) in [(1200, 0x11), (1200, 0x22), (800, 0x33)] {
            let (len, from) = receiver.recv_from(&mut recv_buf).unwrap();
            assert_eq!(from, socket.local_addr().unwrap());
            assert_eq!(len, expected_len);
            assert!(
                recv_buf[..len]
                    .iter()
                    .all(|contents| *contents == expected_contents)
            );
        }
    }

    #[tokio::test]
    async fn send_many_to_preserves_datagrams_when_gso_is_disabled() {
        use crate::packet::PacketBufPool;
        use crate::udp::UdpSend;
        use crate::udp::socket::SockOpt;
        use std::net::{Ipv4Addr, SocketAddr};
        use std::time::Duration;

        let socket = crate::udp::socket::UdpSocket::bind(
            (Ipv4Addr::LOCALHOST, 0).into(),
            SockOpt::default(),
        )
        .unwrap();
        socket.disable_udp_gso();
        let receiver = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let target: SocketAddr = receiver.local_addr().unwrap();
        let pool = PacketBufPool::<4096>::new(3);
        let mut packets = [(3usize, 0x11), (0, 0x22), (5, 0x33)]
            .into_iter()
            .map(|(len, contents)| {
                let mut packet = pool.get();
                packet.truncate(len);
                packet.fill(contents);
                (packet, target)
            })
            .collect();

        socket
            .send_many_to(&mut super::SendmmsgBuf::default(), &mut packets)
            .await
            .unwrap();

        assert!(packets.is_empty());
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut recv_buf = [0u8; 8];
        for (expected_len, expected_contents) in [(3, 0x11), (0, 0x22), (5, 0x33)] {
            let (len, from) = receiver.recv_from(&mut recv_buf).unwrap();
            assert_eq!(from, socket.local_addr().unwrap());
            assert_eq!(len, expected_len);
            assert!(
                recv_buf[..len]
                    .iter()
                    .all(|contents| *contents == expected_contents)
            );
        }
    }

    #[tokio::test]
    async fn send_many_to_records_ipv6_gso_plan() {
        use crate::packet::PacketBufPool;
        use crate::udp::UdpSend;
        use crate::udp::socket::SockOpt;
        use std::time::Duration;

        let socket = crate::udp::socket::UdpSocket::bind(
            (Ipv6Addr::LOCALHOST, 0).into(),
            SockOpt::default(),
        )
        .unwrap();
        let receiver = std::net::UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).unwrap();
        let target: SocketAddr = receiver.local_addr().unwrap();
        let pool = PacketBufPool::<4096>::new(4);
        let mut send_buf = super::SendmmsgBuf::default();
        let mut packets = [900usize, 900, 700]
            .into_iter()
            .map(|len| {
                let mut packet = pool.get();
                packet.truncate(len);
                packet.fill(0x24);
                (packet, target)
            })
            .collect();

        socket
            .send_many_to(&mut send_buf, &mut packets)
            .await
            .unwrap();

        assert!(packets.is_empty());
        assert_eq!(
            send_buf.gso_batches(),
            &[UdpGsoBatch {
                start: 0,
                datagrams: 3,
                target,
                segment_size: 900,
                payload_len: 2500,
            }]
        );

        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut received_lens = Vec::new();
        let mut recv_buf = vec![0u8; 900];
        for _ in 0..3 {
            let (len, from) = receiver.recv_from(&mut recv_buf).unwrap();
            assert_eq!(from, socket.local_addr().unwrap());
            received_lens.push(len);
        }
        assert_eq!(received_lens, vec![900, 900, 700]);
    }
}

impl UdpSend for super::UdpSocket {
    type SendManyBuf = SendmmsgBuf;

    async fn send_to(&self, packet: Packet, target: SocketAddr) -> io::Result<()> {
        let socket = self.socket();
        self.inner
            .socket
            .send(|| socket.send_to(&packet, target))
            .await?;
        Ok(())
    }

    async fn send_many_to(
        &self,
        buf: &mut SendmmsgBuf,
        packets: &mut Vec<(Packet, SocketAddr)>,
    ) -> io::Result<()> {
        check_send_max_number_of_packets(MAX_PACKET_COUNT, packets)?;

        let fd = self.socket().as_raw_fd();

        buf.targets.clear();

        // This allocation can't be put in the struct because of lifetimes.
        // So we allocate it on the stack instead.
        let mut packets_buf = [[IoSlice::new(&[])]; MAX_PACKET_COUNT];
        for ((packet, target), packets_buf) in packets.iter().zip(&mut packets_buf) {
            buf.targets.push(Some(SockaddrStorage::from(*target)));
            *packets_buf = [IoSlice::new(&packet[..])];
        }

        let pkts = &packets_buf[..buf.targets.len()];
        let batch = SendBatch {
            socket: &self.inner.socket,
            fd,
            pkts,
            targets: &buf.targets,
        };

        #[cfg(target_os = "linux")]
        {
            plan_udp_gso_batches(
                packets
                    .iter()
                    .map(|(packet, target)| (packet.len(), *target)),
                &mut buf.gso_batches,
            );

            if self.udp_gso_supported() && !self.udp_gso_disabled() {
                let mut plain_start = None;

                for gso_batch in &buf.gso_batches {
                    let Some(segment_size) = udp_gso_segment_size(gso_batch) else {
                        plain_start.get_or_insert(gso_batch.start);
                        continue;
                    };

                    if let Some(start) = plain_start.take() {
                        send_plain_range(&batch, start, gso_batch.start).await?;
                    }

                    if self.udp_gso_disabled() {
                        send_plain_range(
                            &batch,
                            gso_batch.start,
                            gso_batch.start + gso_batch.datagrams,
                        )
                        .await?;
                    } else {
                        send_gso_segment(
                            self,
                            &batch,
                            gso_batch.start,
                            gso_batch.datagrams,
                            segment_size,
                        )
                        .await?;
                    }
                }

                if let Some(start) = plain_start {
                    send_plain_range(&batch, start, buf.targets.len()).await?;
                }
            } else {
                send_plain_range(&batch, 0, buf.targets.len()).await?;
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            send_plain_range(&batch, 0, buf.targets.len()).await?;
        }
        packets.clear();

        Ok(())
    }

    fn max_number_of_packets_to_send(&self) -> usize {
        MAX_PACKET_COUNT
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        UdpSocket::local_addr(self).map(Some)
    }

    /// Bind the side socket (#260, J1159): port 0 on this socket's address, dual-stack when this
    /// one is, with this socket's fwmark so policy routing treats both alike. Buffer sizes stay
    /// at the system default: it only carries datagrams of at most 256 bytes.
    fn bind_side(&self) -> io::Result<Option<Self>> {
        let local = UdpSocket::local_addr(self)?;
        let only_v6 = match local {
            SocketAddr::V6(_) => Some(!self.map_ipv4_to_ipv6),
            SocketAddr::V4(_) => None,
        };
        #[cfg(target_os = "linux")]
        let fwmark = nix::sys::socket::getsockopt(self.socket(), sockopt::Mark)
            .ok()
            .filter(|mark| *mark != 0);
        let opts = super::SockOpt {
            #[cfg(target_os = "linux")]
            fwmark,
            only_v6,
            ..super::SockOpt::default()
        };
        UdpSocket::bind(SocketAddr::new(local.ip(), 0), opts).map(Some)
    }

    #[cfg(target_os = "linux")]
    fn set_fwmark(&self, mark: u32) -> io::Result<()> {
        setsockopt(self.socket(), sockopt::Mark, &mark)?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod gro {
    /// Most bytes one received message carries. The kernel builds UDP GRO packets only below
    /// 64 KiB (larger GRO packets are for TCP alone), and a UDP datagram's 16-bit length caps
    /// an unsegmented or locally sent GSO datagram the same way.
    const MAX_MESSAGE_LEN: usize = 1 << 16;
    /// One allocation that receive slots are cut from. A slot keeps receiving into the rest of
    /// its chunk while at least [`MAX_MESSAGE_LEN`] bytes are left, so a chunk serves one
    /// full-size message or several typical ones before the slot takes another.
    const CHUNK_LEN: usize = 2 * MAX_MESSAGE_LEN;
    /// Most chunks kept for reuse after their slot moved on. A chunk can only be reused once
    /// every packet cut from it is gone; beyond this many, the oldest is let go and its memory
    /// is freed when its last packet is dropped.
    const MAX_RETIRED_CHUNKS: usize = 2 * MAX_PACKET_COUNT;

    use super::MAX_PACKET_COUNT;
    use crate::packet::{Packet, PacketBufPool};
    use crate::udp::socket::map_src_addr;
    use crate::udp::{UdpRecv, socket::UdpSocket};
    use bytes::BytesMut;
    use nix::cmsg_space;
    use nix::sys::socket::{ControlMessageOwned, MsgFlags, MultiHeaders, SockaddrStorage};
    use std::collections::VecDeque;
    use std::hint::cold_path;
    use std::io::{self, IoSliceMut};
    use std::net::SocketAddr;
    use std::os::fd::AsRawFd;
    use tokio::io::Interest;

    /// Cut the `received` bytes of one message into packets without copying them (#260, J1129).
    ///
    /// Each packet is a view of its own bytes in the receive chunk, so decryption runs in
    /// place there and the decrypted packet is written to the TUN from there. With GRO the
    /// message holds `gro_size`-byte datagrams back to back, the last one possibly shorter.
    fn append_received_packets(
        mut received: BytesMut,
        gro_size: Option<usize>,
        source_addr: SocketAddr,
        packets: &mut Vec<(Packet, SocketAddr)>,
    ) -> io::Result<()> {
        if let Some(gro_size) = gro_size {
            if gro_size == 0 || received.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid empty UDP GRO datagram",
                ));
            }
            while !received.is_empty() {
                let segment = received.split_to(gro_size.min(received.len()));
                packets.push((Packet::from_bytes(segment), source_addr));
            }
        } else {
            packets.push((Packet::from_bytes(received), source_addr));
        }
        Ok(())
    }

    /// The receive slots of one `recvmmsg` call and the chunks their packets are cut from.
    ///
    /// INVARIANT: `gro_bufs[i]` is the unreceived rest of the chunk that `starts[i]` points to
    /// the start of, holds at least [`MAX_MESSAGE_LEN`] bytes before every receive, and is the
    /// only handle to those bytes; every byte of a chunk is initialised (chunks are allocated
    /// zeroed and only ever written).
    pub struct RecvManyBuf {
        pub(crate) gro_bufs: Box<[BytesMut; MAX_PACKET_COUNT]>,
        /// A zero-length handle at the start of each slot's chunk; once it is the chunk's only
        /// handle, no packet of the chunk is alive and the whole chunk can be reclaimed.
        starts: Box<[BytesMut; MAX_PACKET_COUNT]>,
        /// Start handles of chunks whose slot moved on, oldest first.
        retired: VecDeque<BytesMut>,
        /// Kernel receive timestamps (`SO_TIMESTAMPNS`, ns), one per output packet index of the
        /// last call; empty when the receive-side queue bound is off.
        pub(crate) rx_stamps: Vec<u64>,
    }

    /// A fresh zeroed chunk: its start handle and its writable bytes.
    fn new_chunk() -> (BytesMut, BytesMut) {
        let mut chunk = BytesMut::zeroed(CHUNK_LEN);
        let start = chunk.split_to(0);
        (start, chunk)
    }

    impl Default for RecvManyBuf {
        fn default() -> Self {
            let mut starts = Vec::with_capacity(MAX_PACKET_COUNT);
            let mut gro_bufs = Vec::with_capacity(MAX_PACKET_COUNT);
            for _ in 0..MAX_PACKET_COUNT {
                let (start, chunk) = new_chunk();
                starts.push(start);
                gro_bufs.push(chunk);
            }
            let to_slots = |slots: Vec<BytesMut>| -> Box<[BytesMut; MAX_PACKET_COUNT]> {
                slots
                    .into_boxed_slice()
                    .try_into()
                    .unwrap_or_else(|_| unreachable!("one buffer per slot"))
            };
            Self {
                gro_bufs: to_slots(gro_bufs),
                starts: to_slots(starts),
                retired: VecDeque::new(),
                rx_stamps: Vec::new(),
            }
        }
    }

    impl RecvManyBuf {
        /// Hand the first `len` bytes received into `slot` out as their own buffer, and give
        /// the slot a new chunk when too little of its chunk is left for another message.
        ///
        /// # Errors
        /// A length beyond the slot, which only a broken kernel reply can report.
        fn take_received(&mut self, slot: usize, len: usize) -> io::Result<BytesMut> {
            if len > self.gro_bufs[slot].len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "UDP receive length exceeded its buffer",
                ));
            }
            let received = self.gro_bufs[slot].split_to(len);
            if self.gro_bufs[slot].len() < MAX_MESSAGE_LEN {
                let (start, chunk) = self.reuse_chunk().unwrap_or_else(new_chunk);
                let old = std::mem::replace(&mut self.starts[slot], start);
                self.gro_bufs[slot] = chunk;
                if self.retired.len() == MAX_RETIRED_CHUNKS {
                    self.retired.pop_front();
                }
                self.retired.push_back(old);
            }
            Ok(received)
        }

        /// The oldest retired chunk none of whose packets is alive any more, taken back whole.
        fn reuse_chunk(&mut self) -> Option<(BytesMut, BytesMut)> {
            let index = self
                .retired
                .iter_mut()
                .position(|start| start.try_reclaim(CHUNK_LEN))?;
            let mut start = self.retired.remove(index)?;
            let mut chunk = start.split_off(0);
            debug_assert!(chunk.capacity() >= CHUNK_LEN);
            // SAFETY: `try_reclaim` succeeded, so `start` was the chunk's only handle and the
            // capacity covers the whole chunk again; the chunk was allocated zeroed and only
            // ever written, so all `CHUNK_LEN` bytes are initialised (see the type invariant).
            unsafe { chunk.set_len(CHUNK_LEN) };
            Some((start, chunk))
        }

        /// Discard the pages the kernel wrote into, keeping the active slot mappings, and
        /// drop retired chunks so idle RSS returns to the pre-load floor (#260, J1150).
        ///
        /// Over a burst, every slot's chunk (both its consumed prefix and its unreceived tail)
        /// and the retired chunks get written through, so several MiB stay resident. For each
        /// active slot, we drop the tail handle and try to reclaim the whole 128 KiB chunk via
        /// `starts[i]` so `MADV_DONTNEED` discards the consumed prefix too (not only the
        /// unreceived tail). If a packet cut from that slot is still in flight, the slot gets a
        /// fresh demand-zeroed chunk and the old chunk frees when that packet drops. Retired
        /// chunks are cleared outright instead of retaining up to 128 chunks and their
        /// page-alignment edges across idle periods.
        pub(crate) fn release_pages(&mut self) {
            for (start, buf) in self.starts.iter_mut().zip(self.gro_bufs.iter_mut()) {
                if buf.len() == CHUNK_LEN {
                    discard_pages(buf.as_mut_ptr() as usize, buf.len());
                    continue;
                }
                drop(std::mem::take(buf));
                if start.try_reclaim(CHUNK_LEN) {
                    let spare = start.spare_capacity_mut();
                    discard_pages(spare.as_mut_ptr() as usize, spare.len());
                    let mut chunk = start.split_off(0);
                    debug_assert!(chunk.capacity() >= CHUNK_LEN);
                    // SAFETY: `try_reclaim` succeeded, so `start` was the chunk's only handle
                    // and the capacity covers the whole chunk again; `MADV_DONTNEED` on
                    // private anonymous memory yields zero bytes, so all `CHUNK_LEN` bytes
                    // remain initialised (see the type invariant).
                    unsafe { chunk.set_len(CHUNK_LEN) };
                    *buf = chunk;
                } else {
                    // A packet cut from this chunk is still alive; give the slot a fresh
                    // demand-zeroed chunk and let the old one drop with its last packet.
                    let (new_start, new_buf) = new_chunk();
                    *start = new_start;
                    *buf = new_buf;
                }
            }
            self.retired.clear();
            self.retired.shrink_to_fit();
            self.rx_stamps.clear();
            self.rx_stamps.shrink_to_fit();
        }
    }

    /// Discard the whole pages inside the `len` bytes at `start`, which no other handle may
    /// reach: the unreceived rest of a slot, or a retired chunk with no packet alive.
    fn discard_pages(start: usize, len: usize) {
        // SAFETY: sysconf has no preconditions.
        let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
            .ok()
            .filter(|&page| page > 0)
            .unwrap_or(4096);
        let first = start.next_multiple_of(page);
        let end = (start + len) / page * page;
        if end <= first {
            return;
        }
        // SAFETY: [first, end) lies inside the caller's exclusive range and covers whole pages
        // only, so no allocator metadata, live packet or neighbouring allocation shares them.
        // MADV_DONTNEED on private anonymous memory makes the range read back as zeros, which
        // keeps every byte initialised. Failure only means the pages stay resident.
        unsafe {
            libc::madvise(first as *mut libc::c_void, end - first, libc::MADV_DONTNEED);
        }
    }

    impl UdpRecv for UdpSocket {
        type RecvManyBuf = RecvManyBuf;

        async fn recv_from(
            &mut self,
            pool: &mut PacketBufPool,
        ) -> io::Result<(Packet, SocketAddr)> {
            let mut buf = pool.get();
            let (n, src) = self.inner.socket.receive_from(&mut buf).await?;
            buf.truncate(n);
            let src = self.map_src(src);
            Ok((buf, src))
        }

        async fn recv_many_from(
            &mut self,
            recv_many_bufs: &mut Self::RecvManyBuf,
            pool: &mut PacketBufPool,
            packets: &mut Vec<(Packet, SocketAddr)>,
        ) -> io::Result<()> {
            let fd = self.socket().as_raw_fd();
            let map_ipv4_to_ipv6 = self.map_ipv4_to_ipv6;
            let stamp = crate::aqm::enabled();
            if stamp {
                // Keep one entry per already-buffered packet so indices stay aligned.
                recv_many_bufs.rx_stamps.resize(packets.len(), 0);
            }

            self.inner
                .socket
                .receive(Interest::READABLE, move || {
                    // TODO: the CMSG space cannot be reused, so we must allocate new headers each
                    // time [ControlMessageOwned::UdpGroSegments(i32)] contains
                    // the size of all smaller packets/segments
                    // Use a generic sockaddr storage here because this path serves both the IPv4
                    // and IPv6 UDP sockets. Using `SockaddrIn` corrupts IPv6 source addresses and
                    // can poison the peer runtime endpoint with an unspecified IPv4 address.
                    let headers = &mut MultiHeaders::<SockaddrStorage>::preallocate(
                        MAX_PACKET_COUNT,
                        Some(cmsg_space!(i32, libc::timespec)),
                    );

                    let mut io_slices: [[IoSliceMut; 1]; MAX_PACKET_COUNT] =
                        std::array::from_fn(|_| [IoSliceMut::new(&mut [])]);

                    for (i, buf) in recv_many_bufs.gro_bufs.iter_mut().enumerate() {
                        io_slices[i] = [IoSliceMut::new(&mut buf[..])];
                    }

                    let buffered = packets.len();
                    // Each message's slot, length, source, GRO size and timestamp. The packets
                    // are cut out of the slots only after the iovecs' borrow of them ends.
                    let mut received: Vec<(usize, usize, SocketAddr, Option<usize>, u64)> =
                        Vec::new();
                    let results = nix::sys::socket::recvmmsg(
                        fd,
                        headers,
                        &mut io_slices[..MAX_PACKET_COUNT],
                        MsgFlags::MSG_DONTWAIT,
                        None,
                    )?;

                    // `recvmmsg` fills the slots in order, so result `slot` used `gro_bufs[slot]`.
                    for (slot, result) in results.enumerate() {
                        if result.iovs().next().is_none() {
                            cold_path();
                            if cfg!(debug_assertions) {
                                tracing::trace!("Received empty datagram from IoSlice");
                            }
                            continue;
                        }

                        if result
                            .flags
                            .intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC)
                        {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "truncated UDP GRO receive",
                            ));
                        }

                        let Some(source_addr) = result.address.as_ref().and_then(|addr| {
                            addr.as_sockaddr_in()
                                .map(|&addr| SocketAddr::from(addr))
                                .or_else(|| addr.as_sockaddr_in6().map(|addr| (*addr).into()))
                        }) else {
                            if cfg!(debug_assertions) {
                                tracing::debug!("recvmmsg returned packet without source");
                            }
                            continue;
                        };

                        let source_addr = map_src_addr(map_ipv4_to_ipv6, source_addr);

                        // TODO: is this true? Under what circumstance can the cmsg buffer overflow?
                        let cmsgs = result.cmsgs().expect("we have allocated enough memory");

                        let mut gro_size = None;
                        let mut rx_ns = 0_u64;
                        for cmsg in cmsgs {
                            match cmsg {
                                ControlMessageOwned::UdpGroSegments(size) => gro_size = Some(size),
                                ControlMessageOwned::ScmTimestampns(time) => {
                                    rx_ns = u64::try_from(time.tv_sec())
                                        .unwrap_or(0)
                                        .saturating_mul(1_000_000_000)
                                        .saturating_add(u64::try_from(time.tv_nsec()).unwrap_or(0));
                                }
                                _ => {}
                            }
                        }
                        let gro_size = gro_size
                            .and_then(|gro_size| usize::try_from(gro_size).ok())
                            .filter(|&gro_size| gro_size > 0);
                        received.push((slot, result.bytes, source_addr, gro_size, rx_ns));
                    }

                    for (slot, len, source_addr, gro_size, rx_ns) in received {
                        let bytes = recv_many_bufs.take_received(slot, len)?;
                        append_received_packets(bytes, gro_size, source_addr, packets)?;
                        if stamp {
                            // Every segment of a GRO batch shares its head skb's timestamp.
                            recv_many_bufs.rx_stamps.resize(packets.len(), rx_ns);
                        }
                    }
                    // The pool's use count tells the idle release that the link is busy; these
                    // packets no longer come from the pool, so count them there (J1129).
                    pool.count_taken(packets.len() - buffered);

                    Ok(())
                })
                .await?;

            Ok(())
        }

        fn release_recv_buf(&self, recv_buf: &mut Self::RecvManyBuf) {
            recv_buf.release_pages();
        }

        fn rx_timestamp_ns(recv_buf: &Self::RecvManyBuf, index: usize) -> u64 {
            recv_buf.rx_stamps.get(index).copied().unwrap_or(0)
        }

        fn enable_udp_gro(&self) -> io::Result<()> {
            // TODO: missing constants on Android
            use std::os::fd::AsFd;
            nix::sys::socket::setsockopt(
                &self.as_fd(),
                nix::sys::socket::sockopt::UdpGroSegment,
                &true,
            )?;
            if crate::aqm::enabled() {
                // The receive-side queue bound measures sojourn from the kernel's receive time.
                nix::sys::socket::setsockopt(
                    &self.as_fd(),
                    nix::sys::socket::sockopt::ReceiveTimestampns,
                    &true,
                )?;
            }
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{RecvManyBuf, UdpSocket, append_received_packets};
        use crate::packet::{Packet, PacketBufPool};
        use crate::udp::socket::SockOpt;
        use crate::udp::{UdpRecv, UdpSend};
        use bytes::BytesMut;
        use std::net::{Ipv6Addr, SocketAddr};
        use std::time::Duration;
        #[cfg(feature = "device")]
        use {super::MAX_PACKET_COUNT, crate::udp::buffer::BufferedUdpSend, std::net::Ipv4Addr};

        /// A received GRO message is cut into its datagrams in place: each packet is a view of
        /// the slot's chunk, and only the bytes `recvmmsg` reported become packets (J1129).
        #[test]
        fn gro_receive_cuts_only_the_reported_bytes_without_copying() {
            let source: SocketAddr = (Ipv6Addr::LOCALHOST, 51820).into();
            let mut bufs = RecvManyBuf::default();
            bufs.gro_bufs[0][..12].copy_from_slice(b"abcdefghXXXX");
            let start = bufs.gro_bufs[0].as_ptr();
            let mut packets = Vec::new();

            let bytes = bufs.take_received(0, 8).unwrap();
            append_received_packets(bytes, Some(3), source, &mut packets).unwrap();

            assert_eq!(
                packets
                    .iter()
                    .map(|(packet, _)| packet.as_ref())
                    .collect::<Vec<_>>(),
                [b"abc".as_slice(), b"def", b"gh"]
            );
            assert!(packets.iter().all(|(_, addr)| *addr == source));
            assert_eq!(packets[0].0.as_ref().as_ptr(), start, "no copy");
            assert_eq!(
                bufs.gro_bufs[0][..4],
                *b"XXXX",
                "the slot keeps receiving after the packets"
            );
        }

        #[test]
        fn gro_receive_rejects_a_length_larger_than_its_iovec() {
            let mut bufs = RecvManyBuf::default();
            let len = bufs.gro_bufs[0].len();

            let err = bufs.take_received(0, len + 1).unwrap_err();

            assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
            assert_eq!(bufs.gro_bufs[0].len(), len, "the slot is unchanged");
        }

        /// Fill slot 0 with full-size messages until it moves to another chunk, keeping the
        /// packets; returns them and the start of the chunk they were cut from.
        fn fill_one_chunk(bufs: &mut RecvManyBuf) -> (Vec<BytesMut>, *const u8) {
            let first = bufs.gro_bufs[0].as_ptr();
            let mut kept = Vec::new();
            while bufs.gro_bufs[0].as_ptr() >= first
                && bufs.gro_bufs[0].as_ptr() < first.wrapping_add(super::CHUNK_LEN)
            {
                kept.push(bufs.take_received(0, super::MAX_MESSAGE_LEN).unwrap());
            }
            (kept, first)
        }

        /// A slot moves on to a fresh chunk while packets of its old chunk are alive, and takes
        /// the old chunk back whole once they are all gone, so steady receiving allocates and
        /// faults in nothing new.
        #[test]
        fn a_chunk_is_reused_only_after_its_last_packet_is_dropped() {
            let mut bufs = RecvManyBuf::default();
            let (kept, first) = fill_one_chunk(&mut bufs);
            assert!(!kept.is_empty());
            let (second_kept, second) = fill_one_chunk(&mut bufs);
            assert_ne!(second, first, "a live packet keeps its chunk out of reuse");
            assert_ne!(bufs.gro_bufs[0].as_ptr(), first);
            drop(kept);
            drop(second_kept);
            // The slot is on a third chunk now; when that one is used up, it takes back one of
            // the two retired chunks instead of allocating.
            let (_third, _) = fill_one_chunk(&mut bufs);
            let next = bufs.gro_bufs[0].as_ptr();
            assert!(
                next == first || next == second,
                "a chunk with no live packet is reused"
            );
            assert!(bufs.gro_bufs[0].len() >= super::MAX_MESSAGE_LEN);
        }

        /// Bytes of a packet that outlives its slot's move to another chunk stay intact while
        /// the slot keeps receiving.
        #[test]
        fn a_live_packet_keeps_its_bytes_while_the_slot_receives_on() {
            let mut bufs = RecvManyBuf::default();
            bufs.gro_bufs[0][..5].copy_from_slice(b"hello");
            let packet = bufs.take_received(0, 5).unwrap();
            for _ in 0..8 {
                bufs.gro_bufs[0].fill(0xEE);
                drop(bufs.take_received(0, super::MAX_MESSAGE_LEN).unwrap());
            }
            assert_eq!(&packet[..], b"hello");
        }

        /// Releasing an idle receive buffer drops its touched pages (they read back as zeros,
        /// which only happens if the kernel discarded them) and leaves every buffer at full
        /// length and writable.
        #[test]
        fn release_pages_drops_touched_pages_and_keeps_buffers_usable() {
            // SAFETY: sysconf has no preconditions.
            let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap();
            let mut bufs = RecvManyBuf::default();
            let lens: Vec<usize> = bufs.gro_bufs.iter().map(|b| b.len()).collect();
            for buf in bufs.gro_bufs.iter_mut() {
                buf[..64 * 1024].fill(0xAA);
            }

            bufs.release_pages();

            for (buf, len) in bufs.gro_bufs.iter_mut().zip(lens) {
                assert_eq!(buf.len(), len);
                let start = buf.as_ptr() as usize;
                let first_page = start.next_multiple_of(page) - start;
                let interior = &buf[first_page..64 * 1024 - page];
                assert!(
                    interior.iter().all(|&b| b == 0),
                    "page-aligned interior must be discarded"
                );
                buf[..64 * 1024].fill(0x55);
                assert!(buf[..64 * 1024].iter().all(|&b| b == 0x55));
            }
        }

        /// After a burst, `release_pages` reclaims active slots' consumed prefixes back to full
        /// `CHUNK_LEN`, clears retired chunks, and leaves any slot with a live packet intact.
        #[test]
        fn release_pages_reclaims_consumed_prefixes_and_clears_retired() {
            let mut bufs = RecvManyBuf::default();
            // Slot 0: consume 32 KiB and drop the packet so the whole chunk is reclaimable.
            bufs.gro_bufs[0][..32 * 1024].fill(0xAA);
            drop(bufs.take_received(0, 32 * 1024).unwrap());
            assert_eq!(bufs.gro_bufs[0].len(), super::CHUNK_LEN - 32 * 1024);

            // Slot 1: keep a live packet in flight so slot 1 must swap to a fresh chunk.
            bufs.gro_bufs[1][..5].copy_from_slice(b"alive");
            let live = bufs.take_received(1, 5).unwrap();

            // Slot 2: fill enough to push a chunk onto `retired`.
            bufs.gro_bufs[2][..super::MAX_MESSAGE_LEN].fill(0xBB);
            drop(bufs.take_received(2, super::MAX_MESSAGE_LEN).unwrap());
            bufs.gro_bufs[2][..1024].fill(0xCC);
            drop(bufs.take_received(2, 1024).unwrap());
            assert!(!bufs.retired.is_empty());

            bufs.release_pages();

            assert_eq!(bufs.gro_bufs[0].len(), super::CHUNK_LEN);
            assert_eq!(bufs.gro_bufs[1].len(), super::CHUNK_LEN);
            assert_eq!(bufs.gro_bufs[2].len(), super::CHUNK_LEN);
            assert!(bufs.retired.is_empty());
            assert_eq!(&live[..], b"alive");
        }

        #[tokio::test]
        async fn recv_many_from_preserves_ipv6_source_addr() {
            let mut receiver =
                UdpSocket::bind((Ipv6Addr::LOCALHOST, 0).into(), SockOpt::default()).unwrap();
            receiver.enable_udp_gro().ok();
            let sender =
                UdpSocket::bind((Ipv6Addr::LOCALHOST, 0).into(), SockOpt::default()).unwrap();

            let recv_addr = receiver.local_addr().unwrap();
            let sender_addr = sender.local_addr().unwrap();

            let send_pool = PacketBufPool::<4096>::new(1);
            let mut packet = send_pool.get();
            packet.truncate(5);
            packet.copy_from_slice(b"hello");
            sender.send_to(packet, recv_addr).await.unwrap();

            let mut recv_pool = PacketBufPool::<4096>::new(1);
            let mut recv_many_buf = <UdpSocket as UdpRecv>::RecvManyBuf::default();
            let mut packets = vec![];

            tokio::time::timeout(
                Duration::from_secs(1),
                receiver.recv_many_from(&mut recv_many_buf, &mut recv_pool, &mut packets),
            )
            .await
            .unwrap()
            .unwrap();

            assert!(!packets.is_empty(), "expected at least one IPv6 packet");
            assert_eq!(packets[0].1, sender_addr);
        }

        /// A burst of more than two batches crosses the message cap on both sides of a real
        /// socket pair. The buffered sender splits it into `sendmmsg` calls of at most
        /// `MAX_PACKET_COUNT` messages. Each `recvmmsg` returns at most `MAX_PACKET_COUNT`
        /// messages and leaves the rest queued in the kernel for the next call. Every datagram
        /// must arrive exactly once and in send order.
        ///
        /// GRO stays off on the receiver, so each message is one datagram and the per-call
        /// count is the message count. Loopback would not coalesce anyway.
        #[cfg(feature = "device")]
        #[tokio::test]
        async fn a_burst_larger_than_one_batch_arrives_whole_and_in_order() {
            const BURST: usize = 2 * MAX_PACKET_COUNT + 5;
            let opts = SockOpt {
                recv_buffer_size: Some(4 << 20),
                ..SockOpt::default()
            };
            let mut receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0).into(), opts).unwrap();
            let recv_addr = receiver.local_addr().unwrap();
            let sender =
                UdpSocket::bind((Ipv4Addr::LOCALHOST, 0).into(), SockOpt::default()).unwrap();
            let send = BufferedUdpSend::new(4 * BURST, sender);

            let mut packets = (0..BURST as u32)
                .map(|i| (Packet::from_bytes(i.to_be_bytes()[..].into()), recv_addr))
                .collect::<Vec<_>>();
            send.send_many_to(&mut (), &mut packets).await.unwrap();

            let mut recv_pool = PacketBufPool::<4096>::new(BURST);
            let mut recv_many_buf = RecvManyBuf::default();
            let mut received = Vec::with_capacity(BURST);
            let mut calls = 0;
            while received.len() < BURST {
                let mut batch = Vec::new();
                tokio::time::timeout(
                    Duration::from_secs(2),
                    receiver.recv_many_from(&mut recv_many_buf, &mut recv_pool, &mut batch),
                )
                .await
                .expect("the burst stalled: a datagram was lost")
                .unwrap();
                assert!(
                    batch.len() <= MAX_PACKET_COUNT,
                    "one recvmmsg returned {} messages, more than the cap of {MAX_PACKET_COUNT}",
                    batch.len()
                );
                calls += 1;
                received.extend(batch.into_iter().map(|(packet, _)| {
                    u32::from_be_bytes(packet[..].try_into().expect("4-byte payload"))
                }));
            }

            assert_eq!(received, (0..BURST as u32).collect::<Vec<_>>());
            assert!(
                calls >= 3,
                "{BURST} datagrams need at least 3 receive calls"
            );
        }

        // A datagram larger than the pool buffer must be received in full by growing
        // the target buffer, not dropped or truncated.
        //
        // Note: a single datagram is not GRO-coalesced, so this exercises the non-GRO
        // receive branch. The GRO branch (segments larger than the buffer) is not
        // covered here - UDP GRO does not engage on loopback.
        #[tokio::test]
        async fn recv_many_from_grows_for_oversized_datagram() {
            let mut receiver =
                UdpSocket::bind((Ipv6Addr::LOCALHOST, 0).into(), SockOpt::default()).unwrap();
            receiver.enable_udp_gro().ok();
            let recv_addr = receiver.local_addr().unwrap();

            // 10000 bytes is larger than the 4096-byte pool buffer.
            let payload = vec![0xABu8; 10_000];
            let sender = std::net::UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).unwrap();
            sender.send_to(&payload, recv_addr).unwrap();

            let mut recv_pool = PacketBufPool::<4096>::new(1);
            let mut recv_many_buf = <UdpSocket as UdpRecv>::RecvManyBuf::default();
            let mut packets: Vec<(Packet, SocketAddr)> = Vec::new();

            // The datagram is already buffered, so a single read returns it.
            tokio::time::timeout(
                Duration::from_secs(1),
                receiver.recv_many_from(&mut recv_many_buf, &mut recv_pool, &mut packets),
            )
            .await
            .unwrap()
            .unwrap();

            assert_eq!(packets.len(), 1, "expected exactly one packet");
            let (packet, _) = &packets[0];
            assert_eq!(
                packet.len(),
                payload.len(),
                "oversized datagram must be received in full, not dropped or truncated"
            );
            assert_eq!(
                &packet[..],
                &payload[..],
                "datagram must retain same content"
            );
        }
    }
}

#[cfg(target_os = "android")]
mod android {
    use crate::packet::{Packet, PacketBufPool};
    use crate::udp::UdpRecv;
    use std::io;
    use std::net::SocketAddr;

    impl UdpRecv for super::UdpSocket {
        type RecvManyBuf = ();

        async fn recv_from(
            &mut self,
            pool: &mut PacketBufPool,
        ) -> io::Result<(Packet, SocketAddr)> {
            let mut buf = pool.get();
            let (n, src) = self.inner.socket.receive_from(&mut buf).await?;
            buf.truncate(n);
            let src = self.map_src(src);
            Ok((buf, src))
        }
    }
}
