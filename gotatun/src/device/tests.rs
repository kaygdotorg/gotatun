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

use std::{
    future::ready,
    io,
    net::{Ipv4Addr, Ipv6Addr},
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

use futures::{FutureExt, StreamExt, future::pending};
use mock::MockEavesdropper;
use rand::{SeedableRng, rngs::StdRng};
use tokio::{
    join, select,
    sync::{Mutex, mpsc, oneshot},
    time::{sleep, timeout},
};
use zerocopy::IntoBytes;

use super::{PendingCompletions, PendingIncoming, PendingOutgoing, await_while_completing};

use crate::noise::TimerParams;
use crate::noise::index_table::IndexTable;
use crate::packet::{Ip, Packet, PacketBufPool};
use crate::tun::{IpRecv, IpSend, MtuWatcher};

pub mod mock;

/// A TUN test double that drains each immediately ready run in packet order.
#[derive(Clone)]
struct BatchedTun {
    app_to_tun_rx: Arc<Mutex<mpsc::UnboundedReceiver<Packet<Ip>>>>,
    tun_to_app_tx: mpsc::UnboundedSender<Packet<Ip>>,
    observed_input: Arc<StdMutex<Vec<Vec<u8>>>>,
}

/// Test endpoints for a pair of devices whose TUN reads return bounded runs.
struct BatchedDevice {
    _device: crate::device::Device<(
        crate::udp::channel::UdpChannelFactory,
        BatchedTun,
        BatchedTun,
    )>,
    app_tx: mpsc::UnboundedSender<Packet<Ip>>,
    app_rx: mpsc::UnboundedReceiver<Packet<Ip>>,
    observed_input: Arc<StdMutex<Vec<Vec<u8>>>>,
}

/// Packet channels and the observed input record returned by a fake TUN endpoint.
type BatchedTunChannels = (
    BatchedTun,
    mpsc::UnboundedSender<Packet<Ip>>,
    mpsc::UnboundedReceiver<Packet<Ip>>,
    Arc<StdMutex<Vec<Vec<u8>>>>,
);

/// Create the two packet channels and an order record for one test TUN endpoint.
fn batched_tun() -> BatchedTunChannels {
    let (app_to_tun_tx, app_to_tun_rx) = mpsc::unbounded_channel();
    let (tun_to_app_tx, tun_to_app_rx) = mpsc::unbounded_channel();
    let observed_input = Arc::new(StdMutex::new(Vec::new()));
    let tun = BatchedTun {
        app_to_tun_rx: Arc::new(Mutex::new(app_to_tun_rx)),
        tun_to_app_tx,
        observed_input: Arc::clone(&observed_input),
    };
    (tun, app_to_tun_tx, tun_to_app_rx, observed_input)
}

impl IpSend for BatchedTun {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        self.tun_to_app_tx
            .send(packet)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "test TUN receiver closed"))
    }
}

impl IpRecv for BatchedTun {
    async fn recv<'a>(
        &'a mut self,
        _pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        let mut app_to_tun_rx = self.app_to_tun_rx.lock().await;
        let first = app_to_tun_rx
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "test TUN closed"))?;
        let mut packets = vec![first];
        while packets.len() < 64 {
            match app_to_tun_rx.try_recv() {
                Ok(packet) => packets.push(packet),
                Err(_) => break,
            }
        }
        self.observed_input
            .lock()
            .expect("the input-order record is not poisoned")
            .extend(packets.iter().map(|packet| packet.as_bytes().to_vec()));
        Ok(packets.into_iter())
    }

    fn mtu(&self) -> MtuWatcher {
        MtuWatcher::new(mock::TUN_MTU)
    }
}

/// Build two real devices over bounded in-memory TUN and UDP transports.
async fn batched_device_pair() -> (BatchedDevice, BatchedDevice) {
    use crate::device::{DeviceBuilder, Peer};
    use crate::udp::channel::{UdpChannelFactory, UdpChannelV4, UdpChannelV6};
    use ipnetwork::Ipv4Network;
    use rand::{SeedableRng, rngs::StdRng};
    use x25519_dalek::{PublicKey, StaticSecret};

    let (tun_a, app_tx_a, app_rx_a, observed_a) = batched_tun();
    let (tun_b, app_tx_b, app_rx_b, observed_b) = batched_tun();
    let port = 51820;
    let endpoint_a = Ipv4Addr::new(10, 0, 0, 1);
    let endpoint_b = Ipv4Addr::new(10, 0, 0, 2);

    let (udp_a_v4, bridge_a_v4) = UdpChannelV4::new_pair(128);
    let (udp_b_v4, bridge_b_v4) = UdpChannelV4::new_pair(128);
    let (udp_a_v6, bridge_a_v6) = UdpChannelV6::new_pair(128);
    let (udp_b_v6, bridge_b_v6) = UdpChannelV6::new_pair(128);
    let (bridge_a_v4_rx, bridge_a_v4_tx) = (bridge_a_v4.rx, bridge_a_v4.tx);
    let (bridge_b_v4_rx, bridge_b_v4_tx) = (bridge_b_v4.rx, bridge_b_v4.tx);
    let (bridge_a_v6_rx, bridge_a_v6_tx) = (bridge_a_v6.rx, bridge_a_v6.tx);
    let (bridge_b_v6_rx, bridge_b_v6_tx) = (bridge_b_v6.rx, bridge_b_v6.tx);
    tokio::spawn(async move {
        let mut rx = bridge_a_v4_rx;
        let tx = bridge_b_v4_tx;
        while let Some(packet) = rx.recv().await {
            if tx.send(packet).await.is_err() {
                break;
            }
        }
    });
    tokio::spawn(async move {
        let mut rx = bridge_b_v4_rx;
        let tx = bridge_a_v4_tx;
        while let Some(packet) = rx.recv().await {
            if tx.send(packet).await.is_err() {
                break;
            }
        }
    });
    tokio::spawn(async move {
        let mut rx = bridge_a_v6_rx;
        let tx = bridge_b_v6_tx;
        while let Some(packet) = rx.recv().await {
            if tx.send(packet).await.is_err() {
                break;
            }
        }
    });
    tokio::spawn(async move {
        let mut rx = bridge_b_v6_rx;
        let tx = bridge_a_v6_tx;
        while let Some(packet) = rx.recv().await {
            if tx.send(packet).await.is_err() {
                break;
            }
        }
    });

    let udp_a = UdpChannelFactory::new(endpoint_a, udp_a_v4, Ipv6Addr::UNSPECIFIED, udp_a_v6);
    let udp_b = UdpChannelFactory::new(endpoint_b, udp_b_v4, Ipv6Addr::UNSPECIFIED, udp_b_v6);
    let private_a = StaticSecret::random();
    let private_b = StaticSecret::random();
    let public_a = PublicKey::from(&private_a);
    let public_b = PublicKey::from(&private_b);
    let allowed = Ipv4Network::new(Ipv4Addr::UNSPECIFIED, 0)
        .expect("the catch-all test route is valid")
        .into();

    let device_a = DeviceBuilder::new()
        .with_private_key(private_a)
        .with_ip(tun_a)
        .with_udp(udp_a)
        .with_listen_port(port)
        .with_peer(
            Peer::new(public_b)
                .with_endpoint((endpoint_b, port).into())
                .with_allowed_ip(allowed),
        )
        .with_index_table(IndexTable::from_rng(StdRng::seed_from_u64(
            mock::ALICE_INDEX_SEED,
        )))
        .build()
        .await
        .expect("the first test device builds");
    let device_b = DeviceBuilder::new()
        .with_private_key(private_b)
        .with_ip(tun_b)
        .with_udp(udp_b)
        .with_listen_port(port)
        .with_peer(
            Peer::new(public_a)
                .with_endpoint((endpoint_a, port).into())
                .with_allowed_ip(allowed),
        )
        .with_index_table(IndexTable::from_rng(StdRng::seed_from_u64(
            mock::BOB_INDEX_SEED,
        )))
        .build()
        .await
        .expect("the second test device builds");

    (
        BatchedDevice {
            _device: device_a,
            app_tx: app_tx_a,
            app_rx: app_rx_a,
            observed_input: observed_a,
        },
        BatchedDevice {
            _device: device_b,
            app_tx: app_tx_b,
            app_rx: app_rx_b,
            observed_input: observed_b,
        },
    )
}

/// Compare complete packet bytes while keeping an ordering failure concise.
fn assert_packet_order(label: &str, input: &[Vec<u8>], received: &[Vec<u8>]) {
    assert_eq!(input.len(), received.len(), "{label} packet count differs");
    let mismatch = input
        .iter()
        .zip(received)
        .position(|(expected, actual)| expected != actual);
    if let Some(slot) = mismatch {
        let sequence = |bytes: &[u8]| {
            let payload = &bytes[crate::packet::Ipv4Header::LEN..];
            (
                u64::from_be_bytes(payload[..8].try_into().expect("producer id fits")),
                u64::from_be_bytes(payload[8..16].try_into().expect("sequence fits")),
            )
        };
        panic!(
            "{label} order changed at slot {slot}: expected {:?}, received {:?}",
            sequence(&input[slot]),
            sequence(&received[slot])
        );
    }
}

/// Verify a queued same-task completion progresses before its parent acquires the peer lock.
///
/// This small regression pins the scheduler behavior that can stop the duplex path: a child
/// completion is first in Tokio's mutex queue, but it only runs when its parent polls the pending
/// completion stream. The parent must keep polling that stream while waiting for the same mutex.
#[tokio::test]
async fn peer_lock_wait_polls_the_completion_queued_ahead_of_it() {
    let peer = Arc::new(Mutex::new(()));
    let holder = peer.lock().await;
    let (completion_tx, completion_rx) = oneshot::channel();
    let completion_peer = Arc::clone(&peer);
    let mut incoming = PendingIncoming::new();
    incoming.push(
        async move {
            let _peer = completion_peer.lock().await;
            completion_tx
                .send(())
                .expect("the regression test still observes its completion");
            Ok(())
        }
        .boxed(),
    );

    assert!(
        incoming.next().now_or_never().is_none(),
        "the queued completion waits behind the holder"
    );

    let mut outgoing = PendingOutgoing::new();
    let mut pending = PendingCompletions::Incoming(&mut incoming, &mut outgoing);
    let mut acquire = Box::pin(await_while_completing(peer.lock(), &mut pending));
    assert!(futures::poll!(acquire.as_mut()).is_pending());
    drop(holder);

    let _peer = timeout(Duration::from_secs(1), acquire)
        .await
        .expect("the peer lock becomes available after its queued completion runs")
        .expect("the completion stream has no error");
    completion_rx
        .await
        .expect("the queued completion ran before the parent acquired the lock");
}

/// A control drain polls earlier delivery work without retaining the async device lock.
#[tokio::test]
async fn j369_control_drain_progresses_with_a_queued_device_writer() {
    use super::parallel_crypto::OrderedCompletions;
    let (alice, bob, _eve) = mock::device_pair().await;
    alice.device.suspend().await;
    bob.device.suspend().await;
    let device = Arc::clone(&alice.device.inner);
    let (peer, packet_lookup, task_liveness) = {
        let state = device.read().await;
        (
            state.peers.values().next().unwrap().clone(),
            Arc::clone(&state.packet_lookup),
            Arc::clone(&state.task_liveness),
        )
    };
    let held_peer = peer.lock().await;
    let lane = Arc::new(OrderedCompletions::default());
    let slot = lane.reserve_run(1).unwrap();
    let (tun, _tx, _rx) = mock::mock_tun();
    let delivery_device = Arc::downgrade(&task_liveness);
    let completion_peer = Arc::clone(&peer);
    let completion_lookup = Arc::clone(&packet_lookup);
    let mut incoming = PendingIncoming::new();
    let completion_lane = Arc::clone(&lane);
    incoming.push(
        async move {
            completion_lane
                .complete_run(slot, vec![None], |completions| {
                    super::DeviceState::<mock::MockDeviceTransports>::deliver_incoming_run(
                        slot,
                        delivery_device.clone(),
                        completion_lookup.clone(),
                        completion_peer.clone(),
                        completions,
                        tun.clone(),
                    )
                })
                .await
        }
        .boxed(),
    );
    let mut drain = Box::pin(super::drain_incoming_before_control(
        Some(Arc::clone(&lane)),
        &mut incoming,
    ));
    assert!(futures::poll!(drain.as_mut()).is_pending());
    let writer_device = Arc::clone(&device);
    let writer_peer = Arc::clone(&peer);
    let mut writer = Box::pin(async move {
        let _device_guard = writer_device.write().await;
        let _peer_guard = writer_peer.lock().await;
    });
    assert!(futures::poll!(writer.as_mut()).is_pending());
    drop(held_peer);
    drain
        .await
        .expect("delivery completes after peer state is released");
    writer.await;
    alice.device.stop().await;
    bob.device.stop().await;
    assert!(
        lane.is_idle(),
        "the control drain must poll its owned completion"
    );
}

/// Timer output is deferred instead of panicking while the peer's bounded order window is full.
#[tokio::test]
async fn j369_timer_output_survives_a_full_peer_window() {
    use super::parallel_crypto::{CryptoWorkers, MAX_PEER_CRYPTO_IN_FLIGHT, OrderStore};
    let (alice, bob, _eve) = mock::device_pair().await;
    let (udp, packet_lookup, index_table, rate_limiter, task_liveness) = {
        let state = alice.device.inner.read().await;
        (
            state.connection.as_ref().unwrap().udp.clone(),
            Arc::clone(&state.packet_lookup),
            state.index_table.clone(),
            Arc::clone(state.rate_limiter.as_ref().unwrap()),
            Arc::clone(&state.task_liveness),
        )
    };
    alice.device.suspend().await;
    bob.device.suspend().await;
    let peer = alice
        .device
        .inner
        .read()
        .await
        .peers
        .values()
        .next()
        .unwrap()
        .clone();
    peer.lock().await.tunnel.set_persistent_keepalive(Some(1));
    let order = Arc::new(OrderStore::default());
    order
        .reserve_run(super::peer_order_key(&peer), MAX_PEER_CRYPTO_IN_FLIGHT)
        .unwrap();
    let workers = CryptoWorkers::with_worker_count(2).unwrap();
    let timers = super::DeviceState::<mock::MockDeviceTransports>::handle_timers(
        super::PacketTaskHandles {
            liveness: Arc::downgrade(&task_liveness),
            lookup: packet_lookup,
            flush_requests: Arc::default(),
        },
        index_table,
        rate_limiter,
        udp,
        workers.handle(),
        order,
    );
    let outcome = std::panic::AssertUnwindSafe(timers)
        .catch_unwind()
        .now_or_never();
    workers.stop().await;
    alice.device.stop().await;
    bob.device.stop().await;
    assert!(
        outcome.is_none(),
        "timer task panicked at the bounded lane's normal full state"
    );
}

/// Keep the data path moving and ordered while a reverse producer sends ACK-sized packets.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn threaded_reverse_traffic_preserves_order_and_progress() {
    const DATA_PACKET_COUNT: usize = 4000;
    const DATA_PAYLOAD_LEN: usize = 1200;
    const ACK_EVERY: usize = 2;
    const ACK_PACKET_COUNT: usize = DATA_PACKET_COUNT / ACK_EVERY;
    const ACK_PAYLOAD_LEN: usize = 32;
    let (alice, bob) = batched_device_pair().await;
    let BatchedDevice {
        _device: _alice_device,
        app_tx: alice_tx,
        app_rx: mut alice_rx,
        observed_input: alice_input,
    } = alice;
    let BatchedDevice {
        _device: _bob_device,
        app_tx: bob_tx,
        app_rx: mut bob_rx,
        observed_input: bob_input,
    } = bob;
    let received_data_progress = Arc::new(AtomicUsize::new(0));
    // Keep both TUN inputs open until in-flight completions have reached the opposite endpoint.
    let tun_input_guards = (alice_tx.clone(), bob_tx.clone());

    // Establish both peer sessions before the flood so the bounded handshake queue does not
    // discard setup traffic and masquerade as an ordered-lane stall.
    let alice_seed = mock::packet(b"duplex warm-up from Alice");
    alice_tx
        .send(alice_seed.clone())
        .expect("the first endpoint accepts its warm-up packet");
    let received_alice_seed = timeout(Duration::from_secs(2), bob_rx.recv())
        .await
        .expect("the first endpoint's warm-up packet reaches the second endpoint")
        .expect("the second endpoint remains open during setup");
    assert_eq!(received_alice_seed.as_bytes(), alice_seed.as_bytes());

    let bob_seed = mock::packet(b"duplex warm-up from Bob");
    bob_tx
        .send(bob_seed.clone())
        .expect("the second endpoint accepts its warm-up packet");
    let received_bob_seed = timeout(Duration::from_secs(2), alice_rx.recv())
        .await
        .expect("the second endpoint's warm-up packet reaches the first endpoint")
        .expect("the first endpoint remains open during setup");
    assert_eq!(received_bob_seed.as_bytes(), bob_seed.as_bytes());

    alice_input
        .lock()
        .expect("the first endpoint's input-order record is not poisoned")
        .clear();
    bob_input
        .lock()
        .expect("the second endpoint's input-order record is not poisoned")
        .clear();

    let alice_producer = thread::Builder::new()
        .name("data-packet-producer".into())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("data producer runtime builds");
            runtime.block_on(async move {
                for sequence in 0..DATA_PACKET_COUNT {
                    let mut payload = vec![0; DATA_PAYLOAD_LEN];
                    payload[..8].copy_from_slice(&0_u64.to_be_bytes());
                    let sequence = u64::try_from(sequence).expect("test packet ids fit in u64");
                    payload[8..16].copy_from_slice(&sequence.to_be_bytes());
                    alice_tx
                        .send(mock::packet(payload))
                        .expect("the data endpoint keeps reading TUN packets");
                    if sequence % 16 == 0 {
                        tokio::task::yield_now().await;
                    }
                }
            });
        })
        .expect("data producer thread starts");

    let reverse_producer = thread::Builder::new()
        .name("reverse-ack-producer".into())
        .spawn(move || {
            let received_data_progress = Arc::clone(&received_data_progress);
            let timeout_progress = Arc::clone(&received_data_progress);
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("reverse producer runtime builds");
            runtime.block_on(async move {
                timeout(Duration::from_secs(45), async move {
                    let mut received_data = Vec::with_capacity(DATA_PACKET_COUNT);
                    let mut ack_sequence = 0_usize;
                    for received_count in 1..=DATA_PACKET_COUNT {
                        let packet = bob_rx
                            .recv()
                            .await
                            .expect("the reverse endpoint returns each data packet");
                        received_data.push(packet.as_bytes().to_vec());
                        received_data_progress.store(received_count, Ordering::Relaxed);
                        if received_count.is_multiple_of(ACK_EVERY) {
                            let mut payload = vec![0; ACK_PAYLOAD_LEN];
                            payload[..8].copy_from_slice(&1_u64.to_be_bytes());
                            let sequence = u64::try_from(ack_sequence)
                                .expect("test acknowledgement ids fit in u64");
                            payload[8..16].copy_from_slice(&sequence.to_be_bytes());
                            let acknowledged =
                                u64::try_from(received_count).expect("test packet ids fit in u64");
                            payload[16..24].copy_from_slice(&acknowledged.to_be_bytes());
                            bob_tx
                                .send(mock::packet(payload))
                                .expect("the data endpoint keeps reading reverse packets");
                            ack_sequence += 1;
                            tokio::task::yield_now().await;
                        }
                    }
                    received_data
                })
                .await
                .map_err(|_| timeout_progress.load(Ordering::Relaxed))
            })
        })
        .expect("reverse producer thread starts");

    let received_acks = timeout(Duration::from_secs(50), async {
        let mut packets = Vec::with_capacity(ACK_PACKET_COUNT);
        for _ in 0..ACK_PACKET_COUNT {
            let Some(packet) = alice_rx.recv().await else {
                return Err("the data endpoint closed before all acknowledgements arrived");
            };
            packets.push(packet.as_bytes().to_vec());
        }
        Ok::<_, &'static str>(packets)
    })
    .await;

    alice_producer
        .join()
        .expect("data producer thread completes");
    let received_data = reverse_producer
        .join()
        .expect("reverse producer thread completes")
        .unwrap_or_else(|received| {
            panic!(
                "reverse path stopped after receiving {received}/{DATA_PACKET_COUNT} data packets"
            )
        });
    let received_acks = received_acks
        .expect("the reverse acknowledgements reach the data endpoint")
        .expect("the data endpoint stays open until the final acknowledgement");

    let alice_input = alice_input
        .lock()
        .expect("the data input-order record is not poisoned");
    let bob_input = bob_input
        .lock()
        .expect("the reverse input-order record is not poisoned");
    assert_packet_order("data", &alice_input, &received_data);
    assert_packet_order("reverse acknowledgements", &bob_input, &received_acks);
    drop(tun_input_guards);
}

/// A rekey under sustained traffic must not stall either receive path (#260 round 2).
///
/// Alice floods Bob with batched data, keeping up to [`IN_FLIGHT`] packets outstanding the way a
/// TCP sender keeps its window full, while Bob sends a small reverse packet every few
/// milliseconds. Alice's sessions rekey every 200 ms. Each rekey ends with a control packet from
/// Alice's UDP receive task (the keepalive after the handshake response). The bug: that receive
/// task then drained the handshake queue itself, and the TUN task diverted the whole flood into
/// that queue for as long as the drain ran, so the drain rarely finished. Meanwhile Bob's reverse
/// packets were not received, and diverted packets beyond the 256-packet queue were dropped.
///
/// Whether the in-memory transports reach that livelock depends on relative speeds, so the test
/// also asserts the invariant itself: across every rekey, the receive task never runs a drain.
/// The perf-VM rekey test on #260 measures the real-rate effect. Skipped under `mock_instant`,
/// which freezes the timers that trigger rekeys.
#[cfg(not(feature = "mock_instant"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rekey_under_sustained_traffic_keeps_both_receive_paths_moving() {
    use std::sync::atomic::AtomicBool;
    use std::time::Instant;

    /// Session age after which Alice, the initiator, starts the next handshake.
    const REKEY_AFTER: Duration = Duration::from_millis(200);
    /// Rekeys the flood must cross before the test stops.
    const MIN_REKEYS: usize = 3;
    /// Upper bound on the flood's duration. A loaded debug build can need far longer than the
    /// 600 ms or so that three rekeys take on a quiet host, so the test waits for rekeys, not time.
    const RUN_AT_MOST: Duration = Duration::from_secs(30);
    /// Spacing of Bob's reverse packets.
    const REVERSE_INTERVAL: Duration = Duration::from_millis(5);
    /// Longest gap between consecutive arrivals in either direction that still counts as moving.
    /// A hang check, not a speed check: in a loaded parallel suite on compute01 the gaps reached
    /// 194 ms with no fault. The structural assertions below (no receive-task drain, no queue
    /// drop) are what pin the round-2 fix; the measured gaps are printed for the record.
    const MAX_GAP: Duration = Duration::from_secs(5);
    /// Data packets Alice may have sent that Bob has not yet received.
    const IN_FLIGHT: usize = 1024;

    let (alice, bob) = batched_device_pair().await;
    let BatchedDevice {
        _device: mut alice_device,
        app_tx: alice_tx,
        app_rx: mut alice_rx,
        ..
    } = alice;
    let BatchedDevice {
        _device: bob_device,
        app_tx: bob_tx,
        app_rx: mut bob_rx,
        ..
    } = bob;

    // Short sessions apply from the first handshake on, so set them before any traffic.
    let bob_key = alice_device.peers().await[0].peer.public_key;
    let short_rekey = TimerParams {
        rekey_after_time: REKEY_AFTER..=REKEY_AFTER,
        ..TimerParams::default()
    };
    assert!(
        alice_device
            .modify_peer(&bob_key, |peer| {
                peer.dangerously_set_timer_params(Some(short_rekey.clone()));
            })
            .await
            .expect("the timer update reaches Alice's peer")
    );

    // Warm up both directions so the flood starts on an established session.
    alice_tx
        .send(mock::packet(b"rekey warm-up from Alice"))
        .unwrap();
    timeout(Duration::from_secs(5), bob_rx.recv())
        .await
        .expect("Alice's warm-up packet reaches Bob")
        .expect("Bob's TUN stays open");
    bob_tx
        .send(mock::packet(b"rekey warm-up from Bob"))
        .unwrap();
    timeout(Duration::from_secs(5), alice_rx.recv())
        .await
        .expect("Bob's warm-up packet reaches Alice")
        .expect("Alice's TUN stays open");

    let stop = Arc::new(AtomicBool::new(false));
    let forward_received = Arc::new(AtomicUsize::new(0));

    let data_producer = {
        let stop = Arc::clone(&stop);
        let forward_received = Arc::clone(&forward_received);
        let alice_tx = alice_tx.clone();
        thread::Builder::new()
            .name("rekey-flood".into())
            .spawn(move || {
                let mut sent = 0_usize;
                while !stop.load(Ordering::Relaxed) {
                    if sent - forward_received.load(Ordering::Relaxed) >= IN_FLIGHT {
                        thread::yield_now();
                        continue;
                    }
                    let mut payload = vec![0; 1200];
                    payload[..8].copy_from_slice(&(sent as u64).to_be_bytes());
                    if alice_tx.send(mock::packet(payload)).is_err() {
                        break;
                    }
                    sent += 1;
                }
                sent
            })
            .expect("the flood thread starts")
    };
    let reverse_producer = {
        let stop = Arc::clone(&stop);
        let bob_tx = bob_tx.clone();
        thread::Builder::new()
            .name("rekey-reverse".into())
            .spawn(move || {
                let mut sent = 0_usize;
                while !stop.load(Ordering::Relaxed) {
                    if bob_tx.send(mock::packet(b"reverse probe")).is_err() {
                        break;
                    }
                    sent += 1;
                    // sleep: paces Bob's reverse probes at a fixed interval.
                    thread::sleep(REVERSE_INTERVAL);
                }
                sent
            })
            .expect("the reverse thread starts")
    };

    let drains_before = super::RECEIVE_TASK_DRAINS.load(Ordering::Relaxed);
    let started = Instant::now();
    let mut forward_last = started;
    let mut reverse_last = started;
    let mut forward_gap = Duration::ZERO;
    let mut reverse_gap = Duration::ZERO;
    let mut reverse_received = 0_usize;
    let mut rekeys = 0_usize;
    let mut last_handshake = None;
    let mut poll_stats = tokio::time::interval(Duration::from_millis(20));
    while rekeys < MIN_REKEYS && started.elapsed() < RUN_AT_MOST {
        select! {
            packet = bob_rx.recv() => {
                packet.expect("Bob's TUN stays open during the flood");
                forward_received.fetch_add(1, Ordering::Relaxed);
                forward_gap = forward_gap.max(forward_last.elapsed());
                forward_last = Instant::now();
            }
            packet = alice_rx.recv() => {
                packet.expect("Alice's TUN stays open during the flood");
                reverse_received += 1;
                reverse_gap = reverse_gap.max(reverse_last.elapsed());
                reverse_last = Instant::now();
            }
            _ = poll_stats.tick() => {
                let age = alice_device.peers().await[0].stats.last_handshake;
                if let (Some(previous), Some(age)) = (last_handshake, age)
                    && age < previous
                {
                    rekeys += 1;
                }
                last_handshake = age;
            }
        }
    }
    forward_gap = forward_gap.max(forward_last.elapsed());
    reverse_gap = reverse_gap.max(reverse_last.elapsed());
    stop.store(true, Ordering::Relaxed);
    let sent = data_producer.join().expect("the flood thread completes");
    let reverse_sent = reverse_producer
        .join()
        .expect("the reverse thread completes");
    let forward = forward_received.load(Ordering::Relaxed);
    let receive_task_drains = super::RECEIVE_TASK_DRAINS.load(Ordering::Relaxed) - drains_before;
    let mut queue_drops = 0;
    for device in [&alice_device.inner, &bob_device.inner] {
        let peer = device.read().await.peers.values().next().unwrap().clone();
        queue_drops += peer.lock().await.tunnel.queue_drops();
    }
    eprintln!(
        "rekey flood: rekeys={rekeys} forward={forward}/{sent} reverse={reverse_received}/{reverse_sent} \
         forward_gap={forward_gap:?} reverse_gap={reverse_gap:?} receive_task_drains={receive_task_drains} \
         queue_drops={queue_drops}"
    );

    assert!(
        rekeys >= MIN_REKEYS,
        "the flood must cross {MIN_REKEYS} rekeys within {RUN_AT_MOST:?}, saw {rekeys}"
    );
    assert_eq!(
        queue_drops, 0,
        "packets were dropped at the 256-packet handshake queue bound across {rekeys} rekeys"
    );
    assert_eq!(
        receive_task_drains, 0,
        "the UDP receive task drained the handshake queue {receive_task_drains} times across \
         {rekeys} rekeys; a drain there blocks datagram processing"
    );
    assert!(
        reverse_gap <= MAX_GAP,
        "Alice's receive path stalled for {reverse_gap:?} across a rekey (limit {MAX_GAP:?})"
    );
    assert!(
        forward_gap <= MAX_GAP,
        "Bob stopped receiving the flood for {forward_gap:?} across a rekey (limit {MAX_GAP:?})"
    );
    drop((alice_tx, bob_tx, bob_device));
}

/// Assert that the expected number of packets is sent.
/// We expect there to be [`packet_count`] data packets, one handshake init,
/// one handshake resp, and one keepalive.
#[tokio::test]
#[test_log::test]
async fn number_of_packets() {
    test_device_pair(async |eve| {
        let expected_count = packet_count() + 2 + 1;
        let ipv4_count = eve.ipv4().count().await;
        assert_eq!(ipv4_count, expected_count);
    })
    .await
}

/// Assert that IPv6 is not used.
#[tokio::test]
#[test_log::test]
async fn ipv6_isnt_used() {
    test_device_pair(async |eve| {
        let ipv6_count = eve.ipv6().count().await;
        assert_eq!(dbg!(ipv6_count), 0);
    })
    .await
}

/// Assert that exactly one handshake is performed.
/// This test does not run for long enough to trigger a second handshake.
#[tokio::test]
#[test_log::test]
async fn one_handshake() {
    test_device_pair(async |eve| {
        let handshake_inits = async {
            assert_eq!(eve.wg_handshake_init().count().await, 1);
        };
        let handshake_resps = async {
            assert_eq!(eve.wg_handshake_resp().count().await, 1);
        };
        join! { handshake_inits, handshake_resps };
    })
    .await
}

// TODO: is this according to spec?
/// Assert that exactly one keepalive is sent.
/// The keepalive should be sent after the handshake is completed.
#[tokio::test]
#[test_log::test]
async fn one_keepalive() {
    test_device_pair(async |eve| {
        let keepalive_count = eve
            .wg_data()
            .filter(|wg_data| ready(wg_data.is_keepalive()))
            .count()
            .await;

        assert_eq!(keepalive_count, 1);
    })
    .await
}

/// Assert that all WgData packets lenghts are a multiple of 16.
#[tokio::test]
#[test_log::test]
async fn wg_data_length_is_x16() {
    test_device_pair(async |eve| {
        let wg_data_count = eve
            .wg_data()
            .map(|wg| {
                let payload_len = wg.encrypted_encapsulated_packet().len();
                assert!(
                    payload_len.is_multiple_of(16),
                    "wireguard data length must be a multiple of 16, but was {payload_len}"
                );
            })
            .count()
            .await;

        assert!(dbg!(wg_data_count) >= packet_count());
    })
    .await
}

/// Test that indices work as expected.
#[tokio::test]
#[test_log::test]
async fn test_indices() {
    // Compute the expected first index from each seeded RNG.
    let expected_alice_idx =
        IndexTable::next_id(&mut StdRng::seed_from_u64(mock::ALICE_INDEX_SEED));
    let expected_bob_idx = IndexTable::next_id(&mut StdRng::seed_from_u64(mock::BOB_INDEX_SEED));

    test_device_pair(async |eve| {
        let check_init = eve.wg_handshake_init().for_each(async |p| {
            assert_eq!(p.sender_idx.get(), expected_alice_idx);
        });
        let check_alice_data = eve.wg_data().for_each(async |p| {
            // Every data packet is sent to Bob
            assert_eq!(p.header.receiver_idx, expected_bob_idx);
        });
        let check_resp = eve.wg_handshake_resp().for_each(async |p| {
            assert_eq!(p.sender_idx.get(), expected_bob_idx);
        });
        join!(check_init, check_resp, check_alice_data);
    })
    .await;
}

/// Test that device handles roaming (changes to endpoint) for data packets.
#[tokio::test]
#[test_log::test]
async fn test_endpoint_roaming() {
    let (mut alice, mut bob, eve) = mock::device_pair().await;
    let packet = mock::packet(b"Hello!");

    let mut ping_pong = async |alice_ip| {
        *alice.source_ipv4_override.lock().await = Some(alice_ip);

        alice.app_tx.send(packet.clone()).await;
        assert_eq!(bob.app_rx.recv().await.as_bytes(), packet.as_bytes());

        let peers = bob.device.peers().await;
        assert_eq!(peers.len(), 1);
        let stats = &peers[0];

        // Bob's device's peer should point to Alice's last known endpoint
        assert_eq!(
            stats.peer.endpoint.map(|addr| addr.ip()),
            Some(alice_ip.into()),
        );

        // Bob's sent packets should use the new endpoint
        let ip_stream = eve.ip();
        tokio::pin!(ip_stream);

        let next_packet = async {
            tokio::time::timeout(Duration::from_secs(5), ip_stream.next())
                .await
                .expect("did not see sent packet")
        };

        let (_, sniffed_packet) = join! {
            bob.app_tx.send(packet.clone()),
            next_packet,
        };
        alice.app_rx.recv().await;

        assert_eq!(
            sniffed_packet.and_then(|ip| ip.destination()),
            Some(alice_ip.into())
        );
    };

    // Simulate roaming by changing Alice's source IP
    ping_pong("1.2.3.4".parse().unwrap()).await;
    ping_pong("1.3.3.7".parse().unwrap()).await;
    ping_pong("1.2.3.4".parse().unwrap()).await;
}

/// Adding peers is atomic, including when a public key is duplicated within the batch.
#[tokio::test]
#[test_log::test]
async fn add_peers_rejects_duplicate_public_keys() {
    use crate::device::Peer;
    use ipnetwork::Ipv4Network;
    use std::{net::Ipv4Addr, sync::Arc};
    use x25519_dalek::{PublicKey, StaticSecret};

    let (_alice, bob, _eve) = mock::device_pair().await;
    let initial_peers = bob.device.peers().await.len();
    let public_key = PublicKey::from(&StaticSecret::random());
    let peer_a = Peer::new(public_key).with_allowed_ip(
        Ipv4Network::new(Ipv4Addr::new(10, 0, 0, 1), 32)
            .unwrap()
            .into(),
    );
    let peer_b = Peer::new(public_key).with_allowed_ip(
        Ipv4Network::new(Ipv4Addr::new(10, 0, 0, 2), 32)
            .unwrap()
            .into(),
    );

    let added = bob
        .device
        .add_peers([peer_a, peer_b])
        .await
        .expect("device reconfiguration should not fail");

    assert!(!added, "duplicate public keys must reject the entire batch");
    assert_eq!(bob.device.peers().await.len(), initial_peers);

    let state = bob.device.inner.read().await;
    assert!(
        state
            .packet_lookup
            .state
            .read()
            .peers_by_ip
            .iter()
            .all(|(routed_peer, _)| {
                state
                    .peers
                    .values()
                    .any(|peer| Arc::ptr_eq(peer, routed_peer))
            })
    );
}

/// Replacing a peer's routes keeps canonical IPv4/IPv6 entries in its listing and the device trie.
#[tokio::test]
#[test_log::test]
async fn allowed_ip_updates_preserve_v4_v6_listing_and_routes() {
    use ipnetwork::IpNetwork;
    use std::{net::IpAddr, sync::Arc};

    let (_alice, mut bob, _eve) = mock::device_pair().await;
    let peer_key = get_first_and_only_peer(&bob).await.public_key;
    let v4_with_host_bits: IpNetwork = "192.0.2.7/24".parse().unwrap();
    let v4_canonical: IpNetwork = "192.0.2.0/24".parse().unwrap();
    let v6_with_host_bits: IpNetwork = "2001:db8:1::abcd/64".parse().unwrap();
    let v6_canonical: IpNetwork = "2001:db8:1::/64".parse().unwrap();

    let updated = bob
        .device
        .modify_peer(&peer_key, |peer_mut| {
            peer_mut.clear_allowed_ips();
            peer_mut.add_allowed_ips([v4_with_host_bits, v4_canonical, v6_with_host_bits]);
        })
        .await
        .expect("device reconfiguration should not fail");
    assert!(updated, "existing peer should be updated");

    let listed = get_first_and_only_peer(&bob).await;
    assert_eq!(listed.allowed_ips.len(), 2);
    assert!(listed.allowed_ips.contains(&v4_canonical));
    assert!(listed.allowed_ips.contains(&v6_canonical));

    let state = bob.device.inner.read().await;
    let peer = state
        .peers
        .get(&peer_key)
        .expect("configured peer should remain");
    for address in ["192.0.2.123", "2001:db8:1::1"] {
        let address: IpAddr = address.parse().unwrap();
        let route_owner = state
            .packet_lookup
            .peer_by_ip(address)
            .expect("updated address should remain routable");
        assert!(Arc::ptr_eq(peer, &route_owner));
    }
    assert!(
        state
            .packet_lookup
            .peer_by_ip("198.51.100.1".parse().unwrap())
            .is_none()
    );
}

/// A peer must not inject a packet whose inner source IP belongs
/// (by longest-prefix match) to a *different* peer, even when the
/// sending peer's own allowed-ips would cover it. The most specific
/// allowed IP on the device for the source address of incoming
/// packets must belong to the peer.
#[tokio::test]
#[test_log::test]
async fn reverse_path_rejects_source_owned_by_another_peer() {
    use crate::device::Peer;
    use ipnetwork::Ipv4Network;
    use std::net::Ipv4Addr;
    use x25519_dalek::{PublicKey, StaticSecret};

    // Alice has 0.0.0.0/0 as it's allowed IP range
    let (alice, mut bob, _eve) = mock::device_pair().await;

    // Set up a third peer "Carol" with 10.0.0.5/32 on Bob's device
    let carol_pub = PublicKey::from(&StaticSecret::random());
    let added = bob
        .device
        .add_peer(
            Peer::new(carol_pub).with_allowed_ip(
                Ipv4Network::new(Ipv4Addr::new(10, 0, 0, 5), 32)
                    .unwrap()
                    .into(),
            ),
        )
        .await
        .unwrap();
    assert!(added);

    // Sanity: a legitimately-sourced packet (within Alice's 0.0.0.0/0) is delivered
    let legit = mock::packet_from(Ipv4Addr::new(192, 168, 0, 1), b"hi");
    alice.app_tx.send(legit.clone()).await;
    let got = tokio::time::timeout(Duration::from_secs(2), bob.app_rx.recv())
        .await
        .expect("legit packet must be delivered");
    assert_eq!(got.as_bytes(), legit.as_bytes());

    // Alice spoofs source 10.0.0.5, which on Bob's device belongs to Carol. Bob must drop it.
    let spoofed = mock::packet_from(Ipv4Addr::new(10, 0, 0, 5), b"spoofed");
    alice.app_tx.send(spoofed).await;
    let result = tokio::time::timeout(Duration::from_secs(1), bob.app_rx.recv()).await;
    assert!(
        result.is_err(),
        "Bob delivered a packet whose source 10.0.0.5 is owned by a different peer"
    );
}

/// Ensures setting a peer's preshared key via Device::modify_peer propagates into its noise state
#[tokio::test]
#[test_log::test]
async fn modify_peer_preshared_key_reaches_tunnel() {
    assert_peer_psk_update_reaches_tunnel(async |device: &mut mock::MockDevice, preshared_key| {
        let peer = get_first_and_only_peer(device).await;
        let updated = device
            .device
            .modify_peer(&peer.public_key, |peer_mut| {
                peer_mut.set_preshared_key(Some(preshared_key));
            })
            .await
            .expect("modify_peer should succeed");
        assert!(updated, "peer update should affect an existing peer");
        advance_mock_clock();
    })
    .await;
}

/// Ensures setting a peer's preshared key via Device::update_peer propagates into its noise state
#[tokio::test]
#[test_log::test]
async fn update_peer_preshared_key_reaches_tunnel() {
    assert_peer_psk_update_reaches_tunnel(async |device: &mut mock::MockDevice, preshared_key| {
        let mut peer = get_first_and_only_peer(device).await;
        peer.preshared_key = Some(preshared_key);
        let updated = device
            .device
            .update_peer(peer)
            .await
            .expect("update_peer should succeed");
        assert!(updated, "peer update should affect an existing peer");
        advance_mock_clock();
    })
    .await;
}

/// Ensures setting a peer's timer params via Device::modify_peer propagates into its noise state,
/// and that clearing them restores the defaults
#[tokio::test]
#[test_log::test]
async fn modify_peer_timer_params_reach_tunnel() {
    let (_alice, mut bob, _eve) = mock::device_pair().await;
    let peer = get_first_and_only_peer(&bob).await;
    assert_eq!(peer.danger_timer_params, Some(TimerParams::default()));

    let timer_params = TimerParams {
        keepalive_timeout: Duration::from_secs(3)..=Duration::from_secs(5),
        ..TimerParams::default()
    };
    for expected in [Some(timer_params.clone()), None] {
        let updated = bob
            .device
            .modify_peer(&peer.public_key, |peer_mut| {
                peer_mut.dangerously_set_timer_params(expected.clone());
            })
            .await
            .expect("modify_peer should succeed");
        assert!(updated, "peer update should affect an existing peer");

        let peer = get_first_and_only_peer(&bob).await;
        assert_eq!(peer.danger_timer_params, Some(expected.unwrap_or_default()),);
    }
}

/// The number of packets we send through the tunnel
fn packet_count() -> usize {
    mock::packets_of_every_size().len()
}

/// Setting a peer's preshared key must propagate into its noise state, and must
/// not tear down a live session. `set_preshared_key` applies the change through
/// one of the device's configuration APIs.
async fn assert_peer_psk_update_reaches_tunnel(
    set_preshared_key: impl AsyncFn(&mut mock::MockDevice, [u8; 32]),
) {
    let packet = mock::packet(b"Hello!");
    let preshared_key = [0xA5; 32];

    // One side changes its PSK: the peers disagree and the handshake fails.
    {
        let (mut alice, mut bob, _eve) = mock::device_pair().await;
        set_preshared_key(&mut alice, preshared_key).await;
        send_and_expect_blocked(&alice, &mut bob, &packet).await;
    }

    // Both sides set the same PSK: traffic flows.
    {
        let (mut alice, mut bob, _eve) = mock::device_pair().await;
        set_preshared_key(&mut alice, preshared_key).await;
        set_preshared_key(&mut bob, preshared_key).await;
        send_and_expect_delivery(&alice, &mut bob, &packet).await;
    }

    // Updating an established peer keeps the live session working.
    {
        let (mut alice, mut bob, _eve) = mock::device_pair().await;
        send_and_expect_delivery(&alice, &mut bob, &packet).await;
        set_preshared_key(&mut alice, preshared_key).await;
        send_and_expect_delivery(&alice, &mut bob, &packet).await;
    }
}

/// Return the device's single configured peer, asserting there is exactly one.
async fn get_first_and_only_peer(device: &mock::MockDevice) -> crate::device::Peer {
    let peers = device.device.peers().await;
    let [stats] = <[_; 1]>::try_from(peers).expect("expected exactly one peer");
    stats.peer
}

/// Advance the mock clock so consecutive handshakes get distinct timestamps.
fn advance_mock_clock() {
    #[cfg(feature = "mock_instant")]
    mock_instant::thread_local::MockClock::advance(Duration::from_micros(1));
}

async fn send_and_expect_blocked(
    sender: &mock::MockDevice,
    receiver: &mut mock::MockDevice,
    packet: &Packet<Ip>,
) {
    sender.app_tx.send(packet.clone()).await;
    assert!(
        timeout(Duration::from_millis(500), receiver.app_rx.recv())
            .await
            .is_err(),
        "packet should not be delivered while peers disagree on the live PSK"
    );
}

async fn send_and_expect_delivery(
    sender: &mock::MockDevice,
    receiver: &mut mock::MockDevice,
    packet: &Packet<Ip>,
) {
    sender.app_tx.send(packet.clone()).await;
    let received = timeout(Duration::from_secs(1), receiver.app_rx.recv())
        .await
        .expect("expected packet delivery once both live PSKs match");
    assert_eq!(received.as_bytes(), packet.as_bytes());
}

/// [`Device::suspend`] stops all traffic; [`Device::resume`] restores it with a fresh handshake.
#[tokio::test]
#[test_log::test]
async fn suspend_and_resume() {
    use tokio::time::timeout;

    let (alice, mut bob, eve) = mock::device_pair().await;

    // Sniff handshake initiations across the whole test.
    let mut inits = std::pin::pin!(eve.wg_handshake_init());

    // 1. Establish the tunnel: a packet from alice must reach bob.
    let before = b"before suspend";
    alice.app_tx.send(mock::packet(before)).await;
    let received = timeout(Duration::from_secs(1), bob.app_rx.recv())
        .await
        .expect("bob should receive alice's packet before suspend");
    assert_eq!(received.as_bytes(), mock::packet(before).as_bytes());

    // The initial handshake should have happened.
    let first_init = timeout(Duration::from_secs(1), inits.next())
        .await
        .expect("a handshake init should be observed");
    assert!(first_init.is_some());

    // 2. Suspend alice. All of its tasks (timers, inbound, outbound) are now stopped.
    alice.device.suspend().await;
    // Suspending again is a no-op.
    alice.device.suspend().await;

    // 3. While suspended, a packet from alice must NOT reach bob.
    let during = b"during suspend";
    alice.app_tx.send(mock::packet(during)).await;
    let no_delivery = timeout(Duration::from_millis(300), bob.app_rx.recv()).await;
    assert!(
        no_delivery.is_err(),
        "no traffic should flow while suspended"
    );

    // Time passes while the host process is suspended. Advancing the mock clock
    // (a no-op without the `mock_instant` feature) ensures the fresh handshake
    // sent after resume carries a strictly later TAI64N timestamp than the first,
    // so the peer does not reject it as a replay.
    advance_mock_clock();

    // 4. Resume alice. The buffered packet should now flow, via a fresh handshake.
    alice.device.resume().await.expect("resume should succeed");
    // Resuming again is a no-op.
    alice
        .device
        .resume()
        .await
        .expect("resume should be idempotent");

    let received = timeout(Duration::from_secs(2), bob.app_rx.recv())
        .await
        .expect("bob should receive alice's packet after resume");
    assert_eq!(received.as_bytes(), mock::packet(during).as_bytes());

    // Resume cleared alice's sessions, so a second handshake init must be observed.
    let second_init = timeout(Duration::from_secs(2), inits.next())
        .await
        .expect("a fresh handshake init should be observed after resume");
    assert!(second_init.is_some());

    drop((alice, bob));
}

/// Binding to port 0 reports the actual port, and keeps it across rebinds.
#[tokio::test]
#[test_log::test]
async fn listen_port_zero_reports_bound_port() {
    use crate::device::{DeviceBuilder, Peer};
    use x25519_dalek::{PublicKey, StaticSecret};

    let (tun, _app_tx, _app_rx) = mock::mock_tun();
    let peer = Peer::new(PublicKey::from(&StaticSecret::random()));

    let device = DeviceBuilder::new()
        .with_private_key(StaticSecret::random())
        .with_ip(tun)
        .with_default_udp()
        .with_listen_port(0)
        .with_peer(peer)
        .build()
        .await
        .expect("create device");

    let port = device.read(async |d| d.listen_port()).await;
    assert_ne!(port, 0);

    device.suspend().await;
    device.resume().await.expect("resume should succeed");

    let port_after_resume = device.read(async |d| d.listen_port()).await;
    assert_eq!(port, port_after_resume);

    device.stop().await;
}

/// A reconfiguration that would normally rebuild the connection must not
/// silently un-suspend the device: the change is applied to `DeviceState` but
/// the connection stays down until [`Device::resume`].
#[tokio::test]
#[test_log::test]
async fn reconfigure_while_suspended_stays_down() {
    use tokio::time::timeout;

    let (alice, mut bob, _eve) = mock::device_pair().await;

    // Establish the tunnel.
    alice.app_tx.send(mock::packet(b"before")).await;
    timeout(Duration::from_secs(1), bob.app_rx.recv())
        .await
        .expect("tunnel should establish before suspend");

    alice.device.suspend().await;

    // A config change that internally calls `Connection::set_up`. Reuse the same
    // listen port so the mock's source-port addressing stays intact on resume.
    alice
        .device
        .set_listen_port(1)
        .await
        .expect("reconfigure should succeed while suspended");

    // The connection must stay down: reconfiguring did not resume the tunnel.
    let during = b"during suspend";
    alice.app_tx.send(mock::packet(during)).await;
    let no_delivery = timeout(Duration::from_millis(300), bob.app_rx.recv()).await;
    assert!(
        no_delivery.is_err(),
        "reconfiguring while suspended must not bring the connection up"
    );

    // Resume brings the connection up with the applied config; traffic flows.
    advance_mock_clock();
    alice.device.resume().await.expect("resume should succeed");
    let received = timeout(Duration::from_secs(2), bob.app_rx.recv())
        .await
        .expect("traffic should flow after resume");
    assert_eq!(received.as_bytes(), mock::packet(during).as_bytes());

    drop((alice, bob));
}

/// [`Device::force_handshake`] performs a single handshake, and nothing once a session exists.
#[tokio::test]
#[test_log::test]
async fn force_handshake() {
    use crate::device::Error;
    use x25519_dalek::{PublicKey, StaticSecret};

    let (alice, _bob, eve) = mock::device_pair().await;
    let mut inits = std::pin::pin!(eve.wg_handshake_init());
    let bob_public_key = get_first_and_only_peer(&alice).await.public_key;

    // Concurrent callers share a single handshake.
    let (first, second) = timeout(Duration::from_secs(2), async {
        join!(
            alice.device.force_handshake(&bob_public_key),
            alice.device.force_handshake(&bob_public_key),
        )
    })
    .await
    .expect("session should be established");
    first.expect("first wait should succeed");
    second.expect("second wait should succeed");

    let first_init = timeout(Duration::from_secs(1), inits.next())
        .await
        .expect("a handshake init should be observed");
    assert!(first_init.is_some());

    assert!(
        timeout(Duration::from_millis(500), inits.next())
            .await
            .is_err(),
        "no additional handshake init should be sent"
    );

    // With an active WireGuard session, no handshake is initiated.
    alice
        .device
        .force_handshake(&bob_public_key)
        .await
        .expect("wait with a fresh session should succeed");

    assert!(
        timeout(Duration::from_millis(500), inits.next())
            .await
            .is_err(),
        "no additional handshake init should be sent"
    );

    let unknown_peer = PublicKey::from(&StaticSecret::random());
    assert!(matches!(
        alice.device.force_handshake(&unknown_peer).await,
        Err(Error::PeerNotFound)
    ));

    alice.device.suspend().await;
    assert!(matches!(
        alice.device.force_handshake(&bob_public_key).await,
        Err(Error::NotConnected)
    ));
}

/// Deadline for one device-pair exchange in [`test_device_pair`]: the handshake, every packet
/// from [`mock::packets_of_every_size`], and shutdown.
///
/// This catches a hang, not a slow run. A quiet host needs about 0.15–0.5 s in a debug build, but
/// on a loaded build VM even the unmodified base needed over 1 s, so the old 1 s deadline failed
/// both base and candidate there (#260 comments 88702 and 88507). The tests' assertions on packet
/// contents, indices, counts and sizes don't depend on this value.
const DEVICE_PAIR_DEADLINE: Duration = Duration::from_secs(10);

/// Helper method to test that packets can be sent from one [`Device`] to another.
/// Use `eavesdrop` to sniff wireguard packets and assert things about the connection.
async fn test_device_pair(eavesdrop: impl AsyncFnOnce(MockEavesdropper) + Send) {
    let (mut alice, mut bob, eve) = mock::device_pair().await;

    // Create a future to eavesdrop on alice and bob.
    let eavesdrop = async {
        select! {
            _ = eavesdrop(eve) => {}
            // sleep: bounds the eavesdropper until both devices shut down; see DEVICE_PAIR_DEADLINE.
            _ = sleep(DEVICE_PAIR_DEADLINE) => panic!("eavesdrop timeout"),
        }
    };

    // Create a future to drive alice and bob.
    let drive_connection = async move {
        let packets_to_send = mock::packets_of_every_size();
        let packets_to_recv = packets_to_send.clone();

        // Send a bunch of packets from alice to bob.
        let send_packets = async {
            for packet in packets_to_send {
                alice.app_tx.send(packet).await;
            }
            pending().await
        };

        // Receive expected packets to bob from alice.
        let wait_for_packets = async {
            for expected_packet in packets_to_recv {
                let p = bob.app_rx.recv().await;
                assert_eq!(p.as_bytes(), expected_packet.as_bytes());
            }
        };

        select! {
            _ = wait_for_packets => {},
            _ = send_packets => unreachable!(),
            _ = alice.app_rx.recv() => panic!("no data is sent from bob to alice"),
            // sleep: bounds delivery of every test packet; see DEVICE_PAIR_DEADLINE.
            _ = sleep(DEVICE_PAIR_DEADLINE) => panic!("timeout"),
        }

        // Shut down alice and bob after `wait_for_packets`
        drop((alice, bob));
    };

    // Drive the connection, and eavesdrop it at the same time.
    join! {
        drive_connection,
        eavesdrop
    };
}

/// Packet lookup progresses while configuration owns the device write lock and waits for a peer.
#[tokio::test]
async fn j380_packet_lookup_progresses_with_a_pending_delivery_reader() {
    use super::parallel_crypto::OrderedCompletions;
    let (alice, bob, _eve) = mock::device_pair().await;
    alice.device.suspend().await;
    bob.device.suspend().await;
    let device = Arc::clone(&alice.device.inner);
    let (peer, packet_lookup, task_liveness) = {
        let state = device.read().await;
        (
            state.peers.values().next().unwrap().clone(),
            Arc::clone(&state.packet_lookup),
            Arc::clone(&state.task_liveness),
        )
    };
    let held_peer = peer.lock().await;
    let lane = Arc::new(OrderedCompletions::default());
    let slot = lane.reserve_run(1).unwrap();
    let (tun, _tx, _rx) = mock::mock_tun();
    let delivery_device = Arc::downgrade(&task_liveness);
    let completion_peer = peer.clone();
    let completion_lookup = Arc::clone(&packet_lookup);
    let mut incoming = PendingIncoming::new();
    incoming.push(
        async move {
            lane.complete_run(slot, vec![None], |completions| {
                super::DeviceState::<mock::MockDeviceTransports>::deliver_incoming_run(
                    slot,
                    delivery_device.clone(),
                    completion_lookup.clone(),
                    completion_peer.clone(),
                    completions,
                    tun.clone(),
                )
            })
            .await
        }
        .boxed(),
    );
    // The receive owner polls this callback while it waits for peer state.
    assert!(futures::poll!(incoming.next()).is_pending());
    let writer_device = Arc::clone(&device);
    let writer_peer = Arc::clone(&peer);
    let (writer_locked_tx, mut writer_locked_rx) = oneshot::channel();
    let mut writer = Box::pin(async move {
        let _device_guard = writer_device.write().await;
        writer_locked_tx
            .send(())
            .expect("the test still observes the writer lock");
        let _peer_guard = writer_peer.lock().await;
    });
    // The configuration writer owns the device lock while it queues on the peer mutex.
    assert!(futures::poll!(writer.as_mut()).is_pending());
    let writer_owns_device = writer_locked_rx.try_recv().is_ok();
    let route: std::net::IpAddr = "203.0.113.1".parse().unwrap();
    let lookup_progressed = packet_lookup
        .peer_by_ip(route)
        .is_some_and(|current| Arc::ptr_eq(&current, &peer));
    drop(held_peer);
    incoming.next().await.unwrap().unwrap();
    writer.await;
    alice.device.stop().await;
    bob.device.stop().await;
    assert!(
        writer_owns_device && lookup_progressed,
        "packet lookup must progress while a writer holds the device lock and waits on the peer mutex"
    );
}

/// J433 review (#260): a handshake that reaches the receive task while the send task is draining
/// the same peer's handshake queue must not stop the receive task.
///
/// `handle_outgoing` sets the peer's flush marker when it prepares a handshake initiation and keeps
/// it across the awaits in `flush_handshake_queue`, with the peer mutex released. A handshake
/// initiation (or response) from the peer handled by `handle_incoming` in that window calls
/// `begin_flush` again for the same peer without checking `is_flushing`, and `begin_flush` asserts.
/// This holds the marker the way the send task does, then delivers one valid initiation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn j433_incoming_handshake_during_an_outgoing_flush_keeps_receiving() {
    use super::parallel_crypto::{CryptoWorkers, OrderStore};
    use crate::packet::WgKind;
    use crate::udp::UdpSend;

    let (alice, bob, _eve) = mock::device_pair().await;
    alice.device.suspend().await;
    bob.device.suspend().await;
    let (peer, lookup, liveness, key_pair, rate_limiter, (udp_tx, udp_rx)) = {
        let mut state = alice.device.inner.write().await;
        let socket = state.open_listen_socket().await.unwrap();
        (
            state.peers.values().next().unwrap().clone(),
            Arc::clone(&state.packet_lookup),
            Arc::clone(&state.task_liveness),
            state.key_pair.clone().unwrap(),
            Arc::clone(state.rate_limiter.as_ref().unwrap()),
            socket,
        )
    };
    let (bob_udp_tx, _bob_udp_rx, init) = {
        let mut state = bob.device.inner.write().await;
        let (tx, rx) = state.open_listen_socket().await.unwrap();
        let bob_peer = state.peers.values().next().unwrap().clone();
        let init = bob_peer
            .lock()
            .await
            .tunnel
            .format_handshake_initiation(false)
            .expect("a fresh peer can initiate");
        (tx, rx, init)
    };

    let outgoing_order = Arc::new(OrderStore::default());
    // The send task is inside `flush_handshake_queue` for this peer.
    let _send_task_flush = outgoing_order
        .try_begin_flush(super::peer_order_key(&peer))
        .expect("no drain is marked yet");
    let workers = CryptoWorkers::with_worker_count(2).unwrap();
    let (tun, _app_tx, _app_rx) = mock::mock_tun();
    let incoming = tokio::spawn(
        super::DeviceState::<mock::MockDeviceTransports>::handle_incoming(
            super::PacketTaskHandles {
                liveness: Arc::downgrade(&liveness),
                lookup,
                flush_requests: Arc::default(),
            },
            super::HandshakeResponder {
                private_key: key_pair.0,
                public_key: key_pair.1,
                rate_limiter,
            },
            tun,
            udp_tx,
            udp_rx,
            PacketBufPool::new_lazy(64),
            super::CryptoOrderContext {
                crypto: workers.handle(),
                incoming: Arc::new(OrderStore::default()),
                outgoing: Arc::clone(&outgoing_order),
            },
        ),
    );
    bob_udp_tx
        .send_to(
            WgKind::from(init).into(),
            (Ipv4Addr::new(10, 0, 0, 1), 51820).into(),
        )
        .await
        .unwrap();

    let outcome = timeout(Duration::from_secs(2), incoming).await;
    let panicked = match outcome {
        Ok(Err(error)) if error.is_panic() => {
            let payload = error.into_panic();
            let message = payload
                .downcast_ref::<&str>()
                .map(|m| m.to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_default();
            eprintln!("J433 receive task panicked: {message}");
            true
        }
        Ok(other) => {
            eprintln!("J433 receive task ended: {other:?}");
            false
        }
        Err(_) => {
            eprintln!("J433 receive task still running after the handshake (expected)");
            false
        }
    };
    workers.stop().await;
    assert!(
        !panicked,
        "the receive task must survive a peer handshake during the send task's queue flush"
    );
}

/// J433 review (#260): both peers start sending at once, so both prepare a handshake
/// initiation on the send path while the other side's initiation arrives. Counts rounds in which
/// either direction does not deliver and any task panic. Run alone (`--ignored --exact`) because
/// it installs a process-wide panic hook. `J433_ROUNDS` sets the round count (default 300).
#[test]
#[ignore = "J433 stress: run alone"]
fn j433_simultaneous_first_traffic_stress() {
    let panics: Arc<StdMutex<Vec<String>>> = Arc::default();
    let hook_panics = Arc::clone(&panics);
    std::panic::set_hook(Box::new(move |info| {
        hook_panics.lock().unwrap().push(info.to_string());
    }));
    let rounds: usize = std::env::var("J433_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let mut stalled = 0;
    for round in 0..rounds {
        let ok = runtime.block_on(async {
            let (mut alice, mut bob, _eve) = mock::device_pair().await;
            let a = mock::packet(b"alice-to-bob");
            let b = mock::packet(b"bob-to-alice");
            let (alice_tx, bob_tx) = (alice.app_tx.clone(), bob.app_tx.clone());
            let send_a = tokio::spawn(async move { alice_tx.send(a).await });
            let send_b = tokio::spawn(async move { bob_tx.send(b).await });
            let _ = join!(send_a, send_b);
            let got_b = timeout(Duration::from_secs(3), bob.app_rx.recv())
                .await
                .is_ok();
            let got_a = timeout(Duration::from_secs(3), alice.app_rx.recv())
                .await
                .is_ok();
            // Second exchange after the handshake settles: a dead receive task shows up here.
            alice.app_tx.send(mock::packet(b"again-ab")).await;
            bob.app_tx.send(mock::packet(b"again-ba")).await;
            let again_b = timeout(Duration::from_secs(3), bob.app_rx.recv())
                .await
                .is_ok();
            let again_a = timeout(Duration::from_secs(3), alice.app_rx.recv())
                .await
                .is_ok();
            alice.device.stop().await;
            bob.device.stop().await;
            got_a && got_b && again_a && again_b
        });
        if !ok {
            stalled += 1;
            eprintln!("J433 round {round}: a direction did not deliver");
        }
    }
    let panics = panics.lock().unwrap().clone();
    let _ = std::panic::take_hook();
    eprintln!(
        "J433 stress: rounds={rounds} stalled={stalled} panics={}",
        panics.len()
    );
    for p in panics.iter().take(5) {
        eprintln!("J433 panic: {p}");
    }
    assert!(
        stalled == 0 && panics.is_empty(),
        "stalled={stalled} panics={}",
        panics.len()
    );
}

/// A panicking packet task becomes a fatal device error instead of ending quietly (J433 P2-1).
#[tokio::test]
async fn a_panicking_packet_task_reports_a_fatal_error() {
    let outcome = super::fatal_on_panic("handle_incoming", async {
        panic!("peer input broke an invariant");
    })
    .await;
    match outcome {
        Err(super::Error::TaskPanicked { task, message }) => {
            assert_eq!(task, "handle_incoming");
            assert!(
                message.contains("peer input broke an invariant"),
                "{message}"
            );
        }
        other => panic!("expected TaskPanicked, got {other:?}"),
    }
    assert!(
        super::fatal_on_panic("handle_outgoing", async { Ok(()) })
            .await
            .is_ok(),
        "a task that ends normally stays Ok"
    );
}

/// A completion's fatal failure wakes the packet tasks, and the first reason wins (J433 P2-1).
#[tokio::test]
async fn a_pipeline_failure_wakes_waiters_with_the_first_reason() {
    use super::parallel_crypto::OrderStore;
    use crate::packet::WgKind;

    let order = Arc::new(OrderStore::<WgKind>::default());
    let waiter = {
        let order = Arc::clone(&order);
        tokio::spawn(async move { order.failed().await })
    };
    tokio::task::yield_now().await;
    order.fail("UDP send failed: first".into());
    order.fail("UDP send failed: second".into());
    let reason = timeout(Duration::from_secs(5), waiter)
        .await
        .expect("a waiting task wakes on failure")
        .expect("the waiter does not panic");
    assert_eq!(reason, "UDP send failed: first");
    // A task that starts waiting after the failure sees it at once.
    assert_eq!(
        timeout(Duration::from_secs(1), order.failed())
            .await
            .expect("a late waiter sees the recorded failure"),
        "UDP send failed: first"
    );
}
