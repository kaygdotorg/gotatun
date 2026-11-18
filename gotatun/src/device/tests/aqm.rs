// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Exercise the real UDP receive stamps through ordered crypto and a backpressured TUN.

use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use ipnetwork::Ipv4Network;
use tokio::sync::{Semaphore, mpsc};
use x25519_dalek::{PublicKey, StaticSecret};
use zerocopy::IntoBytes;

use super::{super::PIPELINE_BUFS, mock};
use crate::{
    device::{DeviceBuilder, Peer},
    packet::{Ip, Packet, PacketBufPool},
    tun::IpSend,
    udp::{
        UdpRecv, UdpTransportFactory, UdpTransportFactoryParams,
        socket::{UdpSocket, UdpSocketFactory},
    },
};

/// Report the kernel stamps of the fixture's large data datagrams before crypto can dequeue them.
struct ObservedSocket {
    socket: UdpSocket,
    stamps: mpsc::Sender<u64>,
}

impl UdpRecv for ObservedSocket {
    type RecvManyBuf = <UdpSocket as UdpRecv>::RecvManyBuf;

    async fn recv_from(&mut self, pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        self.socket.recv_from(pool).await
    }

    async fn recv_many_from(
        &mut self,
        buf: &mut Self::RecvManyBuf,
        pool: &mut PacketBufPool,
        packets: &mut Vec<(Packet, SocketAddr)>,
    ) -> io::Result<()> {
        let first = packets.len();
        self.socket.recv_many_from(buf, pool, packets).await?;
        for (i, (packet, _)) in packets.iter().enumerate().skip(first) {
            if packet.len() > 1_000 {
                self.stamps.try_send(Self::rx_timestamp_ns(buf, i)).unwrap();
            }
        }
        Ok(())
    }

    fn rx_timestamp_ns(buf: &Self::RecvManyBuf, index: usize) -> u64 {
        UdpSocket::rx_timestamp_ns(buf, index)
    }
}

/// Use the real socket factory while making stamp collection observable to the fixture.
struct ObservedUdp(mpsc::Sender<u64>);

impl UdpTransportFactory for ObservedUdp {
    type Send = UdpSocket;
    type Recv = ObservedSocket;

    async fn bind(
        &mut self,
        params: &UdpTransportFactoryParams,
    ) -> io::Result<(Self::Send, Self::Recv)> {
        let (send, socket) = UdpSocketFactory::default().bind(params).await?;
        Ok((
            send,
            ObservedSocket {
                socket,
                stamps: self.0.clone(),
            },
        ))
    }
}

/// Report each ordered delivery before waiting for the fixture's TUN permit.
#[derive(Clone)]
struct GatedTun {
    delivered: mpsc::Sender<Packet<Ip>>,
    permits: Arc<Semaphore>,
}

impl IpSend for GatedTun {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        self.delivered.send(packet).await.unwrap();
        self.permits.acquire().await.unwrap().forget();
        Ok(())
    }
}

/// A packet behind backpressure keeps its real receive stamp and ages until its own dequeue.
#[tokio::test]
async fn blocked_tun_keeps_kernel_age_until_ordered_dequeue() {
    const CHILD: &str = "GOTATUN_TEST_AQM_TUN_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "device::tests::aqm::blocked_tun_keeps_kernel_age_until_ordered_dequeue",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("GOTATUN_AQM", "ecn")
            .env("GOTATUN_AQM_TARGET_US", "10000")
            .env("GOTATUN_AQM_INTERVAL_US", "10000000")
            .status();
        assert!(status.unwrap().success());
        return;
    }

    tokio::time::timeout(Duration::from_secs(10), async {
        let (a_tun, a_app, _a_rx) = mock::mock_tun();
        let (b_tun, _b_app, _b_rx) = mock::mock_tun();
        let (deliver, mut delivered) = mpsc::channel(2);
        let (stamp, mut stamped) = mpsc::channel(2);
        let permits = Arc::new(Semaphore::new(0));
        let a_key = StaticSecret::random();
        let b_key = StaticSecret::random();
        let allowed = Ipv4Network::new(Ipv4Addr::UNSPECIFIED, 0).unwrap().into();
        let b = DeviceBuilder::new()
            .with_private_key(b_key.clone())
            .with_ip_pair(
                GatedTun {
                    delivered: deliver,
                    permits: permits.clone(),
                },
                b_tun,
            )
            .with_udp(ObservedUdp(stamp))
            .with_peer(Peer::new(PublicKey::from(&a_key)).with_allowed_ip(allowed))
            .build()
            .await
            .unwrap();
        let port = b.read(async |state| state.listen_port()).await;
        let a = DeviceBuilder::new()
            .with_private_key(a_key)
            .with_ip(a_tun)
            .with_default_udp()
            .with_peer(
                Peer::new(PublicKey::from(&b_key))
                    .with_endpoint((Ipv4Addr::LOCALHOST, port).into())
                    .with_allowed_ip(allowed),
            )
            .build()
            .await
            .unwrap();

        a_app.send(mock::packet([1; 1_200])).await;
        stamped.recv().await.unwrap();
        assert_eq!(delivered.recv().await.unwrap().as_bytes().last(), Some(&1));

        // Fill the TUN writer's upstream buffer, including one run waiting to enqueue.
        // A larger-than-target age by itself cannot drop any packet in this fixture.
        for _ in 0..PIPELINE_BUFS {
            a_app.send(mock::packet([1; 1_200])).await;
            assert_ne!(stamped.recv().await.unwrap(), 0);
        }
        a_app.send(mock::packet([2; 1_200])).await;
        let queued_stamp = stamped.recv().await.unwrap();
        assert_ne!(queued_stamp, 0);
        // sleep: age the queued packet past the target after the socket confirms receipt.
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(
            delivered.try_recv().is_err(),
            "the second delivery must wait for the first"
        );
        permits.add_permits(PIPELINE_BUFS + 2);
        for _ in 0..PIPELINE_BUFS {
            assert_eq!(delivered.recv().await.unwrap().as_bytes().last(), Some(&1));
        }
        assert_eq!(delivered.recv().await.unwrap().as_bytes().last(), Some(&2));

        let peer = b.inner.read().await.peers.values().next().unwrap().clone();
        let dequeue = peer.lock().await.aqm.above_target_wall_ns().unwrap();
        let age = dequeue.checked_sub(queued_stamp).unwrap();
        assert!(age >= 30_000_000, "queued packet age was {age} ns");
        eprintln!("J888 real UDP ordered TUN backlog: age_ns={age}");
        a.stop().await;
        b.stop().await;
    })
    .await
    .expect("both loopback packets traverse the real engine");
}
