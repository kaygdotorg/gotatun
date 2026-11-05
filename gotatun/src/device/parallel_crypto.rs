// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//   Copyright (c) Mullvad VPN AB. All rights reserved.
//   Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
//
// SPDX-License-Identifier: MPL-2.0

//! Bounded packet-crypto workers and per-peer ordered completion stages.

use std::collections::BTreeMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex as StdMutex};
use std::thread::{self, JoinHandle};

use parking_lot::Mutex;
use tokio::sync::{Mutex as AsyncMutex, Notify, mpsc, oneshot};

use crate::noise::errors::WireGuardError;
use crate::noise::{PreparedDecryption, PreparedEncryption, VerifiedDecryption};
use crate::packet::WgKind;

/// Packets a device direction may submit before it drains that chunk's completions.
///
/// A received or TUN packet is processed immediately when it arrives; this is only a scheduling
/// bound and never a target batch size.
pub(crate) const CRYPTO_CHUNK_SIZE: usize = 32;

/// Maximum outstanding completion slots for one peer and one direction.
pub(crate) const MAX_PEER_CRYPTO_IN_FLIGHT: usize = 128;

/// Bound on jobs waiting for a worker. A worker removes one job at a time and never waits to fill
/// a batch, so a short packet cannot be held behind a packet-count target.
pub(crate) const MAX_QUEUED_CRYPTO_JOBS: usize = 128;

/// A decrypted packet and the session metadata applied at its ordered release point.
pub(crate) struct IncomingCompletion {
    /// The verified AEAD result whose replay update waits for ordered release.
    pub(crate) result: Result<VerifiedDecryption, WireGuardError>,
    /// The address that authenticated this packet if replay validation succeeds.
    pub(crate) addr: SocketAddr,
}

/// Tracks reserved sequence positions and completed packets for one peer direction.
struct CompletionState<T> {
    next_slot: u64,
    next_release: u64,
    next_delivered: u64,
    in_flight: usize,
    pending: BTreeMap<u64, Option<T>>,
}

/// Assigns peer-local slots and releases completed results only in slot order.
///
/// Producers reserve while holding their peer's state lock. Workers may finish in any order.
/// `complete_with` serializes delivery as well as extraction, so an async send for an earlier
/// result cannot be overtaken by a later completion.
pub(crate) struct OrderedCompletions<T> {
    state: Mutex<CompletionState<T>>,
    delivery: AsyncMutex<()>,
    progress: Notify,
}

impl<T> Default for OrderedCompletions<T> {
    /// Create a lane with no reserved peer sequence slots.
    fn default() -> Self {
        Self {
            state: Mutex::new(CompletionState {
                next_slot: 0,
                next_release: 0,
                next_delivered: 0,
                in_flight: 0,
                pending: BTreeMap::new(),
            }),
            delivery: AsyncMutex::new(()),
            progress: Notify::new(),
        }
    }
}

impl<T> OrderedCompletions<T> {
    /// Reserve a slot, returning `None` when the bounded per-peer window is full.
    pub(crate) fn reserve(&self) -> Option<u64> {
        let mut state = self.state.lock();
        if state.in_flight == MAX_PEER_CRYPTO_IN_FLIGHT {
            return None;
        }

        let slot = state.next_slot;
        state.next_slot = state
            .next_slot
            .checked_add(1)
            .expect("a peer crypto sequence cannot wrap");
        state.in_flight += 1;
        Some(slot)
    }

    /// Store a completion and deliver each newly contiguous result in order.
    ///
    /// `None` marks a slot that completed without a packet, such as an invalid receive packet.
    pub(crate) async fn complete_with<F, Fut, E>(
        &self,
        slot: u64,
        result: Option<T>,
        mut deliver: F,
    ) -> Result<(), E>
    where
        F: FnMut(T) -> Fut,
        Fut: Future<Output = Result<(), E>>,
    {
        let delivery = self.delivery.lock().await;
        let ready = {
            let mut state = self.state.lock();
            assert!(
                slot >= state.next_release && slot < state.next_slot,
                "completion slot {slot} was not outstanding"
            );
            assert!(
                state.pending.insert(slot, result).is_none(),
                "completion slot {slot} was completed twice"
            );

            let mut ready = Vec::new();
            loop {
                let slot = state.next_release;
                let Some(result) = state.pending.remove(&slot) else {
                    break;
                };
                ready.push((slot, result));
                state.next_release = state
                    .next_release
                    .checked_add(1)
                    .expect("a peer crypto sequence cannot wrap");
            }
            ready
        };

        let mut first_error = None;
        for (slot, result) in ready {
            if let Some(result) = result
                && first_error.is_none()
                && let Err(error) = deliver(result).await
            {
                first_error = Some(error);
            }
            {
                let mut state = self.state.lock();
                assert_eq!(
                    state.next_delivered, slot,
                    "ordered completion delivery advanced out of sequence"
                );
                state.next_delivered += 1;
                state.in_flight -= 1;
            }
            self.progress.notify_waiters();
        }
        drop(delivery);

        // Keep this completion in its producer's bounded window until it is actually released.
        // Otherwise later slots could finish quickly, leave the window, and let an arbitrarily
        // large backlog accumulate behind one slow earlier packet.
        loop {
            let notified = self.progress.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.state.lock().next_delivered > slot {
                break;
            }
            notified.await;
        }

        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Whether every reserved slot has been delivered.
    pub(crate) fn is_idle(&self) -> bool {
        let state = self.state.lock();
        state.in_flight == 0 && state.pending.is_empty()
    }

    /// Wait until this slot and every earlier slot have been delivered in order.
    ///
    /// Queue drains wait for their last reserved slot rather than lane idleness, because newer
    /// peer traffic may reserve later slots before the drain returns.
    pub(crate) async fn wait_delivered(&self, slot: u64) {
        assert!(
            slot < self.state.lock().next_slot,
            "a completion slot must be reserved before it is awaited"
        );

        loop {
            let notified = self.progress.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.state.lock().next_delivered > slot {
                return;
            }
            notified.await;
        }
    }
}

/// Keeps ordered completion state only while a peer has outstanding work.
pub(crate) struct OrderStore<T> {
    lanes: Mutex<BTreeMap<usize, Arc<OrderedCompletions<T>>>>,
    flushing: Mutex<std::collections::BTreeSet<usize>>,
}

impl<T> Default for OrderStore<T> {
    /// Create a store without any per-peer lanes or active queue drains.
    fn default() -> Self {
        Self {
            lanes: Mutex::new(BTreeMap::new()),
            flushing: Mutex::new(std::collections::BTreeSet::new()),
        }
    }
}

impl<T> OrderStore<T> {
    /// Reserve a slot in this peer's lane, creating the lane only when traffic needs it.
    pub(crate) fn reserve(&self, peer: usize) -> Option<(Arc<OrderedCompletions<T>>, u64)> {
        let mut lanes = self.lanes.lock();
        let lane = lanes
            .entry(peer)
            .or_insert_with(|| Arc::new(OrderedCompletions::default()));
        let slot = lane.reserve()?;
        Some((Arc::clone(lane), slot))
    }

    /// Return the active lane for a peer when it has outstanding ordered work.
    pub(crate) fn lane(&self, peer: usize) -> Option<Arc<OrderedCompletions<T>>> {
        self.lanes.lock().get(&peer).cloned()
    }

    /// Mark the short handshake queue drain that keeps newer tunnel packets behind it.
    pub(crate) fn begin_flush(self: &Arc<Self>, peer: usize) -> FlushGuard<T> {
        let inserted = self.flushing.lock().insert(peer);
        assert!(inserted, "a peer's outgoing queue is already being drained");
        FlushGuard {
            store: Arc::clone(self),
            peer,
        }
    }

    /// Whether outgoing data for this peer must wait behind its handshake queue.
    pub(crate) fn is_flushing(&self, peer: usize) -> bool {
        self.flushing.lock().contains(&peer)
    }

    /// Remove a lane as soon as all its results have been delivered.
    pub(crate) fn release_if_idle(&self, peer: usize, lane: &Arc<OrderedCompletions<T>>) {
        let mut lanes = self.lanes.lock();
        if lanes
            .get(&peer)
            .is_some_and(|current| Arc::ptr_eq(current, lane) && current.is_idle())
        {
            lanes.remove(&peer);
        }
    }
}

/// Clears the temporary queue-drain marker when a handshake queue finishes or its task stops.
pub(crate) struct FlushGuard<T> {
    store: Arc<OrderStore<T>>,
    peer: usize,
}

impl<T> Drop for FlushGuard<T> {
    /// Remove the marker so future packets can use the regular outgoing path.
    fn drop(&mut self) {
        self.store.flushing.lock().remove(&self.peer);
    }
}

/// One packet operation sent to a process-wide worker.
enum CryptoJob {
    Encrypt(PreparedEncryption, oneshot::Sender<WgKind>),
    Decrypt(
        PreparedDecryption,
        oneshot::Sender<Result<VerifiedDecryption, WireGuardError>>,
    ),
}

/// Cloneable asynchronous handle for submitting one packet at a time.
#[derive(Clone)]
pub(crate) struct CryptoHandle {
    sender: mpsc::Sender<CryptoJob>,
}

impl CryptoHandle {
    /// Submit one prepared encryption job to the bounded worker queue.
    pub(crate) async fn submit_encryption(
        &self,
        packet: PreparedEncryption,
    ) -> Option<oneshot::Receiver<WgKind>> {
        let (result_tx, result_rx) = oneshot::channel();
        self.sender
            .send(CryptoJob::Encrypt(packet, result_tx))
            .await
            .ok()?;
        Some(result_rx)
    }

    /// Submit one prepared decryption job to the bounded worker queue.
    pub(crate) async fn submit_decryption(
        &self,
        packet: PreparedDecryption,
    ) -> Option<oneshot::Receiver<Result<VerifiedDecryption, WireGuardError>>> {
        let (result_tx, result_rx) = oneshot::channel();
        self.sender
            .send(CryptoJob::Decrypt(packet, result_tx))
            .await
            .ok()?;
        Some(result_rx)
    }
}

/// Fixed process-local pool of blocking crypto workers.
///
/// Each worker receives exactly one packet, performs its AEAD operation, and immediately returns
/// to the queue. The queue is bounded; the owning connection drops its senders before joining the
/// workers during shutdown.
pub(crate) struct CryptoWorkers {
    handle: CryptoHandle,
    threads: Vec<JoinHandle<()>>,
    #[cfg(test)]
    worker_count: usize,
}

impl CryptoWorkers {
    /// Start one worker for every CPU available to this process.
    pub(crate) fn new() -> io::Result<Self> {
        let worker_count = thread::available_parallelism()
            .map(NonZeroUsize::get)
            .unwrap_or(1);
        Self::with_worker_count(worker_count)
    }

    /// Start a fixed pool with an explicit size for focused measurements.
    pub(crate) fn with_worker_count(worker_count: usize) -> io::Result<Self> {
        assert!(
            worker_count > 0,
            "the crypto pool needs at least one worker"
        );

        let (sender, receiver) = mpsc::channel(MAX_QUEUED_CRYPTO_JOBS);
        let receiver = Arc::new(StdMutex::new(receiver));
        let mut threads = Vec::with_capacity(worker_count);

        for worker_index in 0..worker_count {
            let worker_receiver = Arc::clone(&receiver);
            let thread = thread::Builder::new()
                .name(format!("gotatun-crypto-{worker_index}"))
                .spawn(move || {
                    loop {
                        let job = {
                            let mut receiver = worker_receiver
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            receiver.blocking_recv()
                        };
                        let Some(job) = job else {
                            break;
                        };

                        match job {
                            CryptoJob::Encrypt(packet, result_tx) => {
                                let _ = result_tx.send(packet.encrypt());
                            }
                            CryptoJob::Decrypt(packet, result_tx) => {
                                let _ = result_tx.send(packet.decrypt());
                            }
                        }
                    }
                });

            match thread {
                Ok(thread) => threads.push(thread),
                Err(error) => {
                    drop(sender);
                    drop(receiver);
                    for thread in threads {
                        let _ = thread.join();
                    }
                    return Err(error);
                }
            }
        }

        Ok(Self {
            handle: CryptoHandle { sender },
            threads,
            #[cfg(test)]
            worker_count,
        })
    }

    /// Return a cloneable handle for device tasks.
    pub(crate) fn handle(&self) -> CryptoHandle {
        self.handle.clone()
    }

    /// Worker count used for the pool.
    #[cfg(test)]
    pub(crate) fn worker_count(&self) -> usize {
        self.worker_count
    }

    /// Close the job queue and join every worker.
    pub(crate) async fn stop(self) {
        let Self {
            handle, threads, ..
        } = self;
        let CryptoHandle { sender } = handle;
        drop(sender);

        let join = tokio::task::spawn_blocking(move || {
            for thread in threads {
                if thread.join().is_err() {
                    tracing::error!("packet crypto worker panicked");
                }
            }
        });
        if let Err(error) = join.await {
            tracing::error!("failed to join packet crypto workers: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    //! Exercise cross-thread ordering and provide the manual crypto-stage profile.

    use std::hint::black_box;
    use std::sync::{Arc, Mutex, mpsc};
    use std::thread;
    use std::time::{Duration, Instant};

    use bytes::BytesMut;
    use futures::{StreamExt, stream::FuturesUnordered};

    use super::{CRYPTO_CHUNK_SIZE, CryptoWorkers, OrderedCompletions};
    use crate::noise::index_table::IndexTable;
    use crate::noise::rate_limiter::RateLimiter;
    use crate::noise::{
        PreparedDecryption, PreparedEncryption, PreparedIncoming, PreparedOutgoing, Tunn,
        TunnResult, VerifiedDecryption,
    };
    use crate::packet::{Packet, WgKind};
    use crate::x25519;

    /// Size of each inner packet used by the crypto-stage profile.
    const PROFILE_PACKET_BYTES: usize = 1380;

    /// Number of samples used to calculate throughput and the p99 stage latency.
    const PROFILE_PACKET_COUNT: usize = 20_000;

    /// Separate runtimes can finish later slots first without exposing them to the consumer.
    #[test]
    fn concurrent_producers_release_each_peers_completions_in_slot_order() {
        let completions = Arc::new(OrderedCompletions::default());
        let delivered = Arc::new(Mutex::new(Vec::new()));
        let (first_slot_tx, first_slot_rx) = mpsc::sync_channel(1);
        let (release_first_tx, release_first_rx) = tokio::sync::oneshot::channel();

        let first_completions = Arc::clone(&completions);
        let first_delivered = Arc::clone(&delivered);
        let first = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let slot = first_completions.reserve().unwrap();
                first_slot_tx.send(slot).unwrap();
                release_first_rx.await.unwrap();
                first_completions
                    .complete_with(slot, Some(slot), |value| {
                        let delivered = Arc::clone(&first_delivered);
                        async move {
                            delivered.lock().unwrap().push(value);
                            Ok::<_, ()>(())
                        }
                    })
                    .await
                    .unwrap();
            });
        });

        assert_eq!(first_slot_rx.recv().unwrap(), 0);

        let (later_tx, later_rx) = mpsc::channel();
        let mut producers = Vec::new();
        for _ in 0..3 {
            let completions = Arc::clone(&completions);
            let delivered = Arc::clone(&delivered);
            let later_tx = later_tx.clone();
            producers.push(thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .build()
                    .unwrap();
                runtime.block_on(async move {
                    let slot = completions.reserve().unwrap();
                    later_tx.send(slot).unwrap();
                    completions
                        .complete_with(slot, Some(slot), |value| {
                            let delivered = Arc::clone(&delivered);
                            async move {
                                delivered.lock().unwrap().push(value);
                                Ok::<_, ()>(())
                            }
                        })
                        .await
                        .unwrap();
                });
            }));
        }

        let mut later_slots = Vec::new();
        for _ in 0..3 {
            later_slots.push(later_rx.recv().unwrap());
        }
        later_slots.sort_unstable();
        assert_eq!(later_slots, vec![1, 2, 3]);
        assert!(delivered.lock().unwrap().is_empty());

        release_first_tx.send(()).unwrap();
        first.join().unwrap();
        for producer in producers {
            producer.join().unwrap();
        }

        assert_eq!(*delivered.lock().unwrap(), vec![0, 1, 2, 3]);
        assert!(completions.is_idle());
    }

    /// A test-first control confirms why an append-on-completion stage is unsafe.
    #[test]
    fn naive_parallel_completion_reorders_a_peers_packets() {
        let next_slot = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let naive = Arc::new(Mutex::new(Vec::new()));
        let (first_slot_tx, first_slot_rx) = mpsc::sync_channel(1);
        let (release_first_tx, release_first_rx) = tokio::sync::oneshot::channel();

        let first_next_slot = Arc::clone(&next_slot);
        let first_naive = Arc::clone(&naive);
        let first = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let slot = first_next_slot.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                first_slot_tx.send(slot).unwrap();
                release_first_rx.await.unwrap();
                first_naive.lock().unwrap().push(slot);
            });
        });

        assert_eq!(first_slot_rx.recv().unwrap(), 0);
        for expected_slot in 1..=3 {
            let next_slot = Arc::clone(&next_slot);
            let naive = Arc::clone(&naive);
            let producer = thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .build()
                    .unwrap();
                runtime.block_on(async move {
                    let slot = next_slot.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    assert_eq!(slot, expected_slot);
                    naive.lock().unwrap().push(slot);
                });
            });
            producer.join().unwrap();
        }

        release_first_tx.send(()).unwrap();
        first.join().unwrap();

        assert_eq!(*naive.lock().unwrap(), vec![1, 2, 3, 0]);
    }

    /// The number of outstanding slots remains fixed even when completions are delayed.
    #[test]
    fn completion_window_is_bounded_per_peer() {
        let completions = OrderedCompletions::<()>::default();
        for expected in 0..super::MAX_PEER_CRYPTO_IN_FLIGHT {
            assert_eq!(completions.reserve(), Some(expected as u64));
        }
        assert_eq!(completions.reserve(), None);
    }

    /// A queue drain can finish without waiting for newer peer traffic.
    #[tokio::test]
    async fn wait_for_slot_does_not_wait_for_later_peer_work() {
        let completions = OrderedCompletions::<u8>::default();
        let first_slot = completions.reserve().unwrap();
        let later_slot = completions.reserve().unwrap();
        let mut waiter = Box::pin(completions.wait_delivered(first_slot));
        assert!(futures::poll!(&mut waiter).is_pending());

        completions
            .complete_with(first_slot, Some(1), |_| async { Ok::<_, ()>(()) })
            .await
            .unwrap();

        assert!(futures::poll!(&mut waiter).is_ready());
        assert!(!completions.is_idle());
        completions
            .complete_with(later_slot, Some(2), |_| async { Ok::<_, ()>(()) })
            .await
            .unwrap();
        assert!(completions.is_idle());
    }

    /// Size the production pool from the CPU count visible to this process.
    #[test]
    fn default_worker_pool_uses_available_cpu_count() {
        let expected = thread::available_parallelism()
            .map(std::num::NonZeroUsize::get)
            .unwrap_or(1);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("the pool test runtime starts");
        runtime.block_on(async {
            let workers = CryptoWorkers::new().expect("the default worker pool starts");
            assert_eq!(workers.worker_count(), expected);
            workers.stop().await;
        });
    }

    /// Build two tunnels with an established session for deterministic packet preparation.
    fn established_tunnels() -> (Tunn, Tunn) {
        let left_private = x25519::StaticSecret::from([11; 32]);
        let left_public = x25519::PublicKey::from(&left_private);
        let right_private = x25519::StaticSecret::from([29; 32]);
        let right_public = x25519::PublicKey::from(&right_private);

        let mut left = Tunn::new(
            left_private,
            right_public,
            None,
            None,
            IndexTable::from_os_rng(),
            Arc::new(RateLimiter::new(&left_public, 100)),
        );
        let mut right = Tunn::new(
            right_private,
            left_public,
            None,
            None,
            IndexTable::from_os_rng(),
            Arc::new(RateLimiter::new(&right_public, 100)),
        );

        let initiation = left
            .format_handshake_initiation(false)
            .expect("the initial handshake is available");
        let TunnResult::WriteToNetwork(response) =
            right.handle_incoming_packet(WgKind::HandshakeInit(initiation))
        else {
            panic!("the receiver should prepare a handshake response");
        };
        let WgKind::HandshakeResp(response) = response else {
            panic!("the receiver should produce a handshake response");
        };
        let _ = left.handle_incoming_packet(WgKind::HandshakeResp(response));

        (left, right)
    }

    /// Reserve `count` outgoing AEAD operations without including packet preparation in timing.
    fn prepared_encryptions(tunnel: &mut Tunn, count: usize) -> Vec<PreparedEncryption> {
        (0..count)
            .map(|_| {
                let packet = Packet::from_bytes(BytesMut::zeroed(PROFILE_PACKET_BYTES));
                match tunnel.prepare_outgoing_packet(packet, None) {
                    Some(PreparedOutgoing::Encrypt(packet)) => packet,
                    Some(PreparedOutgoing::Ready(_)) => {
                        panic!("an established session should produce data encryption work")
                    }
                    None => panic!("an established session should prepare every packet"),
                }
            })
            .collect()
    }

    /// Prepare valid incoming AEAD operations before timing their worker stage.
    fn prepared_decryptions(
        sender: &mut Tunn,
        receiver: &mut Tunn,
        count: usize,
    ) -> Vec<PreparedDecryption> {
        (0..count)
            .map(|_| {
                let packet = Packet::from_bytes(BytesMut::zeroed(PROFILE_PACKET_BYTES));
                let Some(WgKind::Data(packet)) = sender.handle_outgoing_packet(packet, None) else {
                    panic!("an established session should encrypt each profile packet");
                };
                match receiver.prepare_incoming_packet(WgKind::Data(packet)) {
                    PreparedIncoming::Decrypt { packet } => packet,
                    PreparedIncoming::Immediate(_) => {
                        panic!("the established receiver should select its session")
                    }
                }
            })
            .collect()
    }

    /// Return the nearest-rank p99 from a non-empty set of packet stage durations.
    fn p99_duration(samples: &mut [Duration]) -> Duration {
        samples.sort_unstable();
        samples[(samples.len() * 99).div_ceil(100) - 1]
    }

    /// Print packets per second and nearest-rank p99 for one measured packet stage.
    fn report_stage(label: &str, elapsed: Duration, samples: &mut [Duration]) {
        let packets_per_second = samples.len() as f64 / elapsed.as_secs_f64();
        let p99_us = p99_duration(samples).as_secs_f64() * 1_000_000.0;
        println!("{label}: packets/s={packets_per_second:.0} p99_stage_us={p99_us:.3}");
    }

    /// Measure serial AEAD and the ordered worker stage at one, two, and four workers.
    ///
    /// Run with `cargo test -p gotatun --no-default-features --features device,ring --lib
    /// crypto_stage_microbenchmark -- --ignored --nocapture` on a quiet compute host. Packet
    /// preparation is outside the timed interval. Worker measurements include queueing and
    /// in-order release, using the same bounded chunk size as the live device path.
    #[test]
    #[ignore = "manual crypto-stage measurement on compute01"]
    fn crypto_stage_microbenchmark() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("the profile runtime starts");
        runtime.block_on(async {
            let available_cpus = thread::available_parallelism()
                .map(std::num::NonZeroUsize::get)
                .unwrap_or(1);
            println!(
                "crypto stage profile: packets={PROFILE_PACKET_COUNT} packet_bytes={PROFILE_PACKET_BYTES} chunk={CRYPTO_CHUNK_SIZE} available_cpus={available_cpus}"
            );
            let (mut sender, _) = established_tunnels();
            let encryptions = prepared_encryptions(&mut sender, PROFILE_PACKET_COUNT);
            let mut serial_latencies = Vec::with_capacity(PROFILE_PACKET_COUNT);
            let serial_started = Instant::now();
            for packet in encryptions {
                let packet_started = Instant::now();
                black_box(packet.encrypt());
                serial_latencies.push(packet_started.elapsed());
            }
            let serial_elapsed = serial_started.elapsed();
            report_stage(
                "before serial encrypt",
                serial_elapsed,
                &mut serial_latencies,
            );

            for worker_count in [1, 2, 4] {
                let encryptions = prepared_encryptions(&mut sender, PROFILE_PACKET_COUNT);
                let (elapsed, mut latencies) =
                    measure_parallel_encryptions(encryptions, worker_count).await;
                report_stage(
                    &format!("after encrypt workers={worker_count}"),
                    elapsed,
                    &mut latencies,
                );
            }

            let (mut sender, mut receiver) = established_tunnels();
            let decryptions =
                prepared_decryptions(&mut sender, &mut receiver, PROFILE_PACKET_COUNT);
            let mut serial_latencies = Vec::with_capacity(PROFILE_PACKET_COUNT);
            let serial_started = Instant::now();
            for packet in decryptions {
                let packet_started = Instant::now();
                let verified = packet.decrypt().expect("the profile packet authenticates");
                black_box(
                    verified
                        .complete()
                        .expect("the ordered profile counter is accepted"),
                );
                serial_latencies.push(packet_started.elapsed());
            }
            let serial_elapsed = serial_started.elapsed();
            report_stage(
                "before serial decrypt",
                serial_elapsed,
                &mut serial_latencies,
            );

            for worker_count in [1, 2, 4] {
                let (mut sender, mut receiver) = established_tunnels();
                let decryptions =
                    prepared_decryptions(&mut sender, &mut receiver, PROFILE_PACKET_COUNT);
                let (elapsed, mut latencies) =
                    measure_parallel_decryptions(decryptions, worker_count).await;
                report_stage(
                    &format!("after decrypt workers={worker_count}"),
                    elapsed,
                    &mut latencies,
                );
            }
        });
    }

    /// Measure encryption worker throughput and time from submission through ordered release.
    async fn measure_parallel_encryptions(
        encryptions: Vec<PreparedEncryption>,
        worker_count: usize,
    ) -> (Duration, Vec<Duration>) {
        let workers = CryptoWorkers::with_worker_count(worker_count)
            .expect("the requested worker pool starts");
        assert_eq!(workers.worker_count(), worker_count);
        let crypto = workers.handle();
        let lane = Arc::new(OrderedCompletions::<WgKind>::default());
        let mut encryptions = encryptions.into_iter();
        let mut latencies = Vec::with_capacity(PROFILE_PACKET_COUNT);
        let started = Instant::now();

        loop {
            let batch = encryptions
                .by_ref()
                .take(CRYPTO_CHUNK_SIZE)
                .collect::<Vec<_>>();
            if batch.is_empty() {
                break;
            }

            let mut pending = FuturesUnordered::new();
            for packet in batch {
                let slot = lane
                    .reserve()
                    .expect("the bounded chunk fits the peer window");
                let crypto = crypto.clone();
                let lane = Arc::clone(&lane);
                let packet_started = Instant::now();
                pending.push(async move {
                    let result = crypto
                        .submit_encryption(packet)
                        .await
                        .expect("the worker queue remains open");
                    let packet = result.await.expect("the worker returns its result");
                    lane.complete_with(slot, Some(packet), |packet| async move {
                        black_box(packet);
                        Ok::<_, ()>(())
                    })
                    .await
                    .expect("ordered delivery succeeds");
                    packet_started.elapsed()
                });
            }

            while let Some(latency) = pending.next().await {
                latencies.push(latency);
            }
        }

        let elapsed = started.elapsed();
        assert!(lane.is_idle());
        drop(crypto);
        workers.stop().await;
        (elapsed, latencies)
    }

    /// Measure decryption worker throughput and time through ordered replay marking.
    async fn measure_parallel_decryptions(
        decryptions: Vec<PreparedDecryption>,
        worker_count: usize,
    ) -> (Duration, Vec<Duration>) {
        let workers = CryptoWorkers::with_worker_count(worker_count)
            .expect("the requested worker pool starts");
        assert_eq!(workers.worker_count(), worker_count);
        let crypto = workers.handle();
        let lane = Arc::new(OrderedCompletions::<VerifiedDecryption>::default());
        let mut decryptions = decryptions.into_iter();
        let mut latencies = Vec::with_capacity(PROFILE_PACKET_COUNT);
        let started = Instant::now();

        loop {
            let batch = decryptions
                .by_ref()
                .take(CRYPTO_CHUNK_SIZE)
                .collect::<Vec<_>>();
            if batch.is_empty() {
                break;
            }

            let mut pending = FuturesUnordered::new();
            for packet in batch {
                let slot = lane
                    .reserve()
                    .expect("the bounded chunk fits the peer window");
                let crypto = crypto.clone();
                let lane = Arc::clone(&lane);
                let packet_started = Instant::now();
                pending.push(async move {
                    let result = crypto
                        .submit_decryption(packet)
                        .await
                        .expect("the worker queue remains open");
                    let packet = result
                        .await
                        .expect("the worker returns its result")
                        .expect("the profile packet authenticates");
                    lane.complete_with(slot, Some(packet), |packet| async move {
                        black_box(
                            packet
                                .complete()
                                .expect("the ordered profile counter is accepted"),
                        );
                        Ok::<_, ()>(())
                    })
                    .await
                    .expect("ordered delivery succeeds");
                    packet_started.elapsed()
                });
            }

            while let Some(latency) = pending.next().await {
                latencies.push(latency);
            }
        }

        let elapsed = started.elapsed();
        assert!(lane.is_idle());
        drop(crypto);
        workers.stop().await;
        (elapsed, latencies)
    }
}
