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

use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::thread::{self, JoinHandle};

use parking_lot::{Condvar, Mutex};
use tokio::sync::{Mutex as AsyncMutex, Notify, OwnedSemaphorePermit, Semaphore, oneshot};

use crate::noise::errors::WireGuardError;
use crate::noise::{PreparedDecryption, PreparedOutgoing, VerifiedDecryption};
use crate::packet::WgKind;

/// Maximum number of consecutive packets reserved together from one producer batch.
///
/// A TUN or UDP read is processed as soon as it returns. This is a scheduling bound, never a
/// target batch size.
pub(crate) const CRYPTO_CHUNK_SIZE: usize = 64;

/// Maximum packets released together for one peer in a ready read run.
///
/// Runs are ready when the producer read returns; workers never wait to fill one. The fixed cap
/// bounds how long the last packet waits behind its run mates.
pub(crate) const CRYPTO_BATCH_SIZE: usize = CRYPTO_WORKER_BATCH_SIZE;

/// Maximum contiguous packet count a worker accepts for one chunk.
pub(crate) const CRYPTO_WORKER_BATCH_SIZE: usize = CRYPTO_CHUNK_SIZE;

/// Smallest ready single-peer run that is worth handing to the worker pool.
pub(crate) const MIN_PARALLEL_RUN_SIZE: usize = 8;

/// Maximum outstanding completion slots for one peer and one direction.
pub(crate) const MAX_PEER_CRYPTO_IN_FLIGHT: usize = 128;

/// Bound on worker runs waiting in the shared queue. Every run is already full when submitted;
/// workers never wait to fill it, so a short packet cannot be held behind a packet-count target.
pub(crate) const MAX_QUEUED_CRYPTO_JOBS: usize = 128;

/// Number of lock-free checks a worker makes for newly queued chunks before it parks.
const WORKER_SPIN_COUNT: usize = 128;

/// Whether a ready run is large enough, or has enough other work, to justify a worker handoff.
///
/// Small single-peer runs stay inline so sparse traffic avoids queue latency. A substantial run,
/// a producer-split read, or another active peer can use the pool to expose parallel work.
pub(crate) const fn should_force_worker(packet_count: usize, other_peer_runs: bool) -> bool {
    packet_count >= MIN_PARALLEL_RUN_SIZE || (other_peer_runs && packet_count > 1)
}

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
    pending: BTreeMap<u64, Vec<Option<T>>>,
}

/// Assigns peer-local slots and releases completed results only in slot order.
///
/// Producers reserve while holding their peer's state lock. Workers may finish in any order.
/// `complete_run` serializes delivery as well as extraction, so an async send for an earlier run
/// cannot be overtaken by a later completion.
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
    /// Reserve one contiguous range, returning `None` when the bounded per-peer window is full.
    #[cfg(test)]
    pub(crate) fn reserve(&self) -> Option<u64> {
        self.reserve_run(1)
    }

    /// Reserve `count` consecutive slots with one peer-lane lock acquisition.
    pub(crate) fn reserve_run(&self, count: usize) -> Option<u64> {
        if count == 0 || count > MAX_PEER_CRYPTO_IN_FLIGHT {
            return None;
        }
        let mut state = self.state.lock();
        if count > MAX_PEER_CRYPTO_IN_FLIGHT - state.in_flight {
            return None;
        }

        let first_slot = state.next_slot;
        state.next_slot = state
            .next_slot
            .checked_add(count as u64)
            .expect("a peer crypto sequence cannot wrap");
        state.in_flight += count;
        Some(first_slot)
    }

    /// Store a completed run and deliver newly contiguous runs in slot order.
    ///
    /// `None` marks a slot that completed without a packet, such as an invalid receive packet.
    pub(crate) async fn complete_run<F, Fut, E>(
        &self,
        first_slot: u64,
        results: Vec<Option<T>>,
        mut deliver: F,
    ) -> Result<(), E>
    where
        F: FnMut(Vec<Option<T>>) -> Fut,
        Fut: Future<Output = Result<(), E>>,
    {
        assert!(!results.is_empty(), "a completion run cannot be empty");
        let run_len = results.len();
        let end_slot = first_slot
            .checked_add(run_len as u64)
            .expect("a peer crypto sequence cannot wrap");
        let delivery = self.delivery.lock().await;
        let ready = {
            let mut state = self.state.lock();
            assert!(
                first_slot >= state.next_release && end_slot <= state.next_slot,
                "completion run {first_slot}..{end_slot} was not outstanding"
            );
            assert!(
                state.pending.insert(first_slot, results).is_none(),
                "completion run beginning at slot {first_slot} was completed twice"
            );

            let mut ready = Vec::new();
            loop {
                let first_slot = state.next_release;
                let Some(results) = state.pending.remove(&first_slot) else {
                    break;
                };
                let run_len = results.len();
                ready.push((first_slot, run_len, results));
                state.next_release = state
                    .next_release
                    .checked_add(run_len as u64)
                    .expect("a peer crypto sequence cannot wrap");
            }
            ready
        };

        let mut first_error = None;
        for (first_slot, run_len, results) in ready {
            if first_error.is_none()
                && let Err(error) = deliver(results).await
            {
                first_error = Some(error);
            }
            {
                let mut state = self.state.lock();
                assert_eq!(
                    state.next_delivered, first_slot,
                    "ordered completion delivery advanced out of sequence"
                );
                state.next_delivered += run_len as u64;
                state.in_flight -= run_len;
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
            if self.state.lock().next_delivered >= end_slot {
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

    /// Remaining sequence slots before this peer reaches its in-flight bound.
    pub(crate) fn available(&self) -> usize {
        MAX_PEER_CRYPTO_IN_FLIGHT - self.state.lock().in_flight
    }

    /// Wait until an ordered completion releases at least one slot in this peer's window.
    pub(crate) async fn wait_for_capacity(&self) {
        loop {
            let notified = self.progress.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.available() > 0 {
                return;
            }
            notified.await;
        }
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
        self.reserve_run(peer, 1)
    }

    /// Reserve a contiguous range in a peer's lane, creating the lane only for active work.
    pub(crate) fn reserve_run(
        &self,
        peer: usize,
        count: usize,
    ) -> Option<(Arc<OrderedCompletions<T>>, u64)> {
        let mut lanes = self.lanes.lock();
        let lane = lanes
            .entry(peer)
            .or_insert_with(|| Arc::new(OrderedCompletions::default()));
        let first_slot = lane.reserve_run(count)?;
        Some((Arc::clone(lane), first_slot))
    }

    /// Return the active lane for a peer when it has outstanding ordered work.
    pub(crate) fn lane(&self, peer: usize) -> Option<Arc<OrderedCompletions<T>>> {
        self.lanes.lock().get(&peer).cloned()
    }

    /// Remaining range capacity, treating a peer without an active lane as empty.
    pub(crate) fn available(&self, peer: usize) -> usize {
        self.lanes
            .lock()
            .get(&peer)
            .map_or(MAX_PEER_CRYPTO_IN_FLIGHT, |lane| lane.available())
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

/// One contiguous packet run assigned to a worker and returned with one wakeup.
enum CryptoJob {
    Encrypt(
        Vec<Option<PreparedOutgoing>>,
        oneshot::Sender<Vec<Option<WgKind>>>,
        ActiveBatch,
    ),
    Decrypt(
        Vec<(PreparedDecryption, SocketAddr)>,
        oneshot::Sender<Vec<IncomingCompletion>>,
        ActiveBatch,
    ),
}

/// Bounded work queue shared by the fixed crypto worker set.
///
/// Workers park on the condition variable while the queue is empty. The mutex protects only the
/// queue metadata; a worker releases it before processing a run.
struct CryptoQueue {
    state: Mutex<CryptoQueueState>,
    ready: Condvar,
    queued_slots: Arc<Semaphore>,
    queued_jobs: AtomicUsize,
}

/// Queue metadata protected only while runs are added, removed, or the pool closes.
struct CryptoQueueState {
    jobs: VecDeque<QueuedCryptoJob>,
    closed: bool,
}

/// One bounded run and the permit that accounts for its place in the queue.
struct QueuedCryptoJob {
    job: CryptoJob,
    _permit: OwnedSemaphorePermit,
}

impl CryptoQueue {
    /// Create an empty queue with a fixed number of pending worker-run slots.
    fn new(capacity: usize) -> Self {
        Self {
            state: Mutex::new(CryptoQueueState {
                jobs: VecDeque::with_capacity(capacity),
                closed: false,
            }),
            ready: Condvar::new(),
            queued_slots: Arc::new(Semaphore::new(capacity)),
            queued_jobs: AtomicUsize::new(0),
        }
    }

    /// Enqueue one complete run under one queue lock and wake one parked worker.
    async fn push(&self, job: CryptoJob) -> Result<(), ()> {
        let permit = Arc::clone(&self.queued_slots)
            .acquire_owned()
            .await
            .map_err(|_| ())?;
        let mut state = self.state.lock();
        if state.closed {
            return Err(());
        }
        state.jobs.push_back(QueuedCryptoJob {
            job,
            _permit: permit,
        });
        self.queued_jobs.fetch_add(1, Ordering::Release);
        self.ready.notify_one();
        Ok(())
    }

    /// Take one worker chunk, briefly spinning before parking when the queue remains empty.
    fn pop(&self) -> Option<CryptoJob> {
        let mut state = self.state.lock();
        loop {
            if let Some(QueuedCryptoJob { job, _permit }) = state.jobs.pop_front() {
                self.queued_jobs.fetch_sub(1, Ordering::Relaxed);
                drop(state);
                drop(_permit);
                return Some(job);
            }
            if state.closed {
                return None;
            }

            drop(state);
            for _ in 0..WORKER_SPIN_COUNT {
                if self.queued_jobs.load(Ordering::Acquire) > 0 {
                    break;
                }
                std::hint::spin_loop();
            }

            state = self.state.lock();
            if state.jobs.is_empty() && !state.closed {
                self.ready.wait(&mut state);
            }
        }
    }

    /// Stop accepting work and wake parked workers so they can drain and exit.
    fn close(&self) {
        self.state.lock().closed = true;
        self.ready.notify_all();
    }
}

/// Cloneable handle for inline or batched crypto work.
#[derive(Clone)]
pub(crate) struct CryptoHandle {
    queue: Arc<CryptoQueue>,
    worker_count: usize,
    active_batches: Arc<AtomicUsize>,
    serial: Arc<Mutex<()>>,
    #[cfg(test)]
    handoff_count: Arc<AtomicUsize>,
    #[cfg(test)]
    worker_run_count: Arc<AtomicUsize>,
}

impl CryptoHandle {
    /// Encrypt one ready run, using the caller as a serial fast path when the pool is otherwise idle.
    pub(crate) async fn encrypt_run(
        &self,
        run: Vec<Option<PreparedOutgoing>>,
        force_worker: bool,
    ) -> Option<Vec<Option<WgKind>>> {
        assert!(!run.is_empty() && run.len() <= CRYPTO_WORKER_BATCH_SIZE);

        if !run
            .iter()
            .any(|prepared| matches!(prepared, Some(PreparedOutgoing::Encrypt(_))))
        {
            return Some(encrypt_run(run));
        }

        if self.worker_count == 1 {
            let _serial = self.serial.lock();
            return Some(encrypt_run(run));
        }

        if let Some(_active) = ActiveBatch::try_enter_inline(&self.active_batches, force_worker) {
            return Some(encrypt_run(run));
        }

        let (result_tx, result_rx) = oneshot::channel();
        let active = ActiveBatch::enter_queued(&self.active_batches);
        self.queue
            .push(CryptoJob::Encrypt(run, result_tx, active))
            .await
            .ok()?;
        #[cfg(test)]
        self.handoff_count.fetch_add(1, Ordering::Relaxed);
        result_rx.await.ok()
    }

    /// Decrypt one ready run, using the caller as a serial fast path when the pool is otherwise idle.
    pub(crate) async fn decrypt_run(
        &self,
        run: Vec<(PreparedDecryption, SocketAddr)>,
        force_worker: bool,
    ) -> Option<Vec<IncomingCompletion>> {
        assert!(!run.is_empty() && run.len() <= CRYPTO_WORKER_BATCH_SIZE);

        if self.worker_count == 1 {
            let _serial = self.serial.lock();
            return Some(decrypt_run(run));
        }

        if let Some(_active) = ActiveBatch::try_enter_inline(&self.active_batches, force_worker) {
            return Some(decrypt_run(run));
        }

        let (result_tx, result_rx) = oneshot::channel();
        let active = ActiveBatch::enter_queued(&self.active_batches);
        self.queue
            .push(CryptoJob::Decrypt(run, result_tx, active))
            .await
            .ok()?;
        #[cfg(test)]
        self.handoff_count.fetch_add(1, Ordering::Relaxed);
        result_rx.await.ok()
    }

    /// Count batch handoffs in tests without adding metadata to production handles.
    #[cfg(test)]
    fn handoff_count(&self) -> usize {
        self.handoff_count.load(Ordering::Relaxed)
    }

    /// Count how many bounded worker runs have completed in tests.
    #[cfg(test)]
    fn worker_run_count(&self) -> usize {
        self.worker_run_count.load(Ordering::Relaxed)
    }
}

/// Releases one active-batch count even when a submitting future is cancelled.
struct ActiveBatch(Arc<AtomicUsize>);

impl ActiveBatch {
    /// Claim the caller-side fast path only while no batch is active.
    fn try_enter_inline(active_batches: &Arc<AtomicUsize>, force_worker: bool) -> Option<Self> {
        if force_worker
            || active_batches
                .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
        {
            return None;
        }
        Some(Self(Arc::clone(active_batches)))
    }

    /// Count a batch before it waits in the bounded worker queue.
    fn enter_queued(active_batches: &Arc<AtomicUsize>) -> Self {
        active_batches.fetch_add(1, Ordering::AcqRel);
        Self(Arc::clone(active_batches))
    }
}

impl Drop for ActiveBatch {
    /// Return the batch slot to the inline-path scheduler.
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Release);
    }
}

/// Encrypt one contiguous worker chunk without making per-packet handoffs.
///
/// `PreparedEncryption::encrypt` seals each packet in its existing writable network buffer; only
/// the chunk's result vector is collected here.
fn encrypt_run(run: Vec<Option<PreparedOutgoing>>) -> Vec<Option<WgKind>> {
    run.into_iter()
        .map(|prepared| {
            prepared.map(|prepared| match prepared {
                PreparedOutgoing::Encrypt(packet) => packet.encrypt(),
                PreparedOutgoing::Ready(packet) => packet,
            })
        })
        .collect()
}

/// Authenticate all items in a batch while retaining their source addresses for ordered release.
fn decrypt_run(run: Vec<(PreparedDecryption, SocketAddr)>) -> Vec<IncomingCompletion> {
    run.into_iter()
        .map(|(packet, addr)| IncomingCompletion {
            result: packet.decrypt(),
            addr,
        })
        .collect()
}

/// Fixed process-local pool of blocking crypto workers.
///
/// Each worker removes one complete contiguous run from the queue, performs its AEAD operations
/// without per-packet handoffs, and immediately returns to the queue. The queue is bounded, and
/// shutdown closes it before joining workers so cloned handles cannot keep parked threads alive.
pub(crate) struct CryptoWorkers {
    handle: CryptoHandle,
    queue: Arc<CryptoQueue>,
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

        let queue = Arc::new(CryptoQueue::new(MAX_QUEUED_CRYPTO_JOBS));
        let active_batches = Arc::new(AtomicUsize::new(0));
        #[cfg(test)]
        let worker_run_count = Arc::new(AtomicUsize::new(0));
        let mut threads = Vec::with_capacity(worker_count);

        for worker_index in 0..worker_count {
            let worker_queue = Arc::clone(&queue);
            #[cfg(test)]
            let completed_runs = Arc::clone(&worker_run_count);
            let thread = thread::Builder::new()
                .name(format!("gotatun-crypto-{worker_index}"))
                .spawn(move || {
                    while let Some(job) = worker_queue.pop() {
                        #[cfg(test)]
                        completed_runs.fetch_add(1, Ordering::Relaxed);
                        match job {
                            CryptoJob::Encrypt(run, result_sender, active) => {
                                let _ = result_sender.send(encrypt_run(run));
                                drop(active);
                            }
                            CryptoJob::Decrypt(run, result_sender, active) => {
                                let _ = result_sender.send(decrypt_run(run));
                                drop(active);
                            }
                        }
                    }
                });

            match thread {
                Ok(thread) => threads.push(thread),
                Err(error) => {
                    queue.close();
                    for thread in threads {
                        let _ = thread.join();
                    }
                    return Err(error);
                }
            }
        }

        #[cfg(test)]
        let handoff_count = Arc::new(AtomicUsize::new(0));

        Ok(Self {
            handle: CryptoHandle {
                queue: Arc::clone(&queue),
                worker_count,
                active_batches,
                serial: Arc::new(Mutex::new(())),
                #[cfg(test)]
                handoff_count,
                #[cfg(test)]
                worker_run_count,
            },
            queue,
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
            handle,
            queue,
            threads,
            ..
        } = self;
        queue.close();
        drop(handle);

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
    use futures::{FutureExt, StreamExt, stream::FuturesUnordered};
    use zerocopy::IntoBytes;

    use super::{
        CRYPTO_BATCH_SIZE, CRYPTO_CHUNK_SIZE, CRYPTO_WORKER_BATCH_SIZE, CryptoWorkers,
        IncomingCompletion, MIN_PARALLEL_RUN_SIZE, OrderedCompletions,
    };
    use crate::noise::index_table::IndexTable;
    use crate::noise::rate_limiter::RateLimiter;
    use crate::noise::{
        PreparedDecryption, PreparedEncryption, PreparedIncoming, PreparedOutgoing, Tunn,
        TunnResult,
    };
    use crate::packet::{Packet, WgKind};
    use crate::x25519;

    /// Size of each inner packet used by the crypto-stage profile.
    const PROFILE_PACKET_BYTES: usize = 1380;

    /// Number of samples used to calculate throughput and the p99 stage latency.
    const PROFILE_PACKET_COUNT: usize = 20_000;

    /// Number of singleton reads used to measure the low-rate serial fast path.
    const PROFILE_SPARSE_PACKET_COUNT: usize = 2_000;

    /// Inner IP flows carried by one peer in the loaded stage profile.
    const PROFILE_INNER_FLOW_COUNT: usize = 8;

    /// The profile uses one peer so a read produces one contiguous, order-sensitive run.
    const PROFILE_PEER_COUNT: usize = 1;

    /// Packets per peer in one ready read from the profile.
    const PROFILE_READ_PACKETS_PER_PEER: usize = CRYPTO_CHUNK_SIZE;

    /// Keep a small fixed input window ready so the workers do not go idle between reads.
    const PROFILE_READS_IN_FLIGHT: usize = 2;

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
                let slot = first_completions.reserve_run(2).unwrap();
                first_slot_tx.send(slot).unwrap();
                release_first_rx.await.unwrap();
                first_completions
                    .complete_run(slot, vec![Some(slot), Some(slot + 1)], |values| {
                        let delivered = Arc::clone(&first_delivered);
                        async move {
                            delivered
                                .lock()
                                .unwrap()
                                .extend(values.into_iter().flatten());
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
                    let slot = completions.reserve_run(2).unwrap();
                    later_tx.send(slot).unwrap();
                    completions
                        .complete_run(slot, vec![Some(slot), Some(slot + 1)], |values| {
                            let delivered = Arc::clone(&delivered);
                            async move {
                                delivered
                                    .lock()
                                    .unwrap()
                                    .extend(values.into_iter().flatten());
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
        assert_eq!(later_slots, vec![2, 4, 6]);
        assert!(delivered.lock().unwrap().is_empty());

        release_first_tx.send(()).unwrap();
        first.join().unwrap();
        for producer in producers {
            producer.join().unwrap();
        }

        assert_eq!(*delivered.lock().unwrap(), vec![0, 1, 2, 3, 4, 5, 6, 7]);
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

    /// Keep sparse traffic inline and dispatch substantial or concurrent ready work.
    #[test]
    fn worker_dispatch_preserves_single_run_fast_path_and_parallelizes_ready_runs() {
        assert!(!super::should_force_worker(1, false));
        assert!(!super::should_force_worker(
            MIN_PARALLEL_RUN_SIZE - 1,
            false
        ));
        assert!(super::should_force_worker(MIN_PARALLEL_RUN_SIZE, false));
        assert!(!super::should_force_worker(1, true));
        assert!(super::should_force_worker(2, true));
    }

    /// Keep a ready read run contiguous through one worker handoff and ordered release.
    #[test]
    fn ordered_run_uses_the_full_worker_batch_bound() {
        assert_eq!(super::CRYPTO_BATCH_SIZE, super::CRYPTO_WORKER_BATCH_SIZE);
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

    /// A producer can wait for space even when another task owns the pending completion.
    #[tokio::test]
    async fn wait_for_capacity_wakes_when_an_inflight_run_releases() {
        let completions = OrderedCompletions::<()>::default();
        let first_slot = completions
            .reserve_run(super::MAX_PEER_CRYPTO_IN_FLIGHT)
            .unwrap();
        let mut waiter = Box::pin(completions.wait_for_capacity());
        assert!(futures::poll!(&mut waiter).is_pending());

        completions
            .complete_run(
                first_slot,
                std::iter::repeat_with(|| None)
                    .take(super::MAX_PEER_CRYPTO_IN_FLIGHT)
                    .collect(),
                |_| async { Ok::<_, ()>(()) },
            )
            .await
            .unwrap();

        assert!(futures::poll!(&mut waiter).is_ready());
    }

    /// A worker should receive one handoff for a contiguous crypto run.
    #[tokio::test]
    async fn one_worker_handoff_covers_a_contiguous_encryption_run() {
        let (mut sender, _) = established_tunnels();
        let packets = prepared_encryptions(&mut sender, super::CRYPTO_BATCH_SIZE);
        let workers = CryptoWorkers::with_worker_count(2).expect("the worker pool starts");
        let crypto = workers.handle();
        let run = packets
            .into_iter()
            .map(|packet| Some(PreparedOutgoing::Encrypt(packet)))
            .collect();
        let results = crypto
            .encrypt_run(run, true)
            .await
            .expect("the worker queue stays open");
        black_box(results);

        assert_eq!(crypto.handoff_count(), 1);
        workers.stop().await;
    }

    /// A worker takes one bounded contiguous run without packet-level queue jobs.
    #[tokio::test]
    async fn grouped_encryption_uses_one_bounded_worker_run() {
        let packet_count = super::CRYPTO_WORKER_BATCH_SIZE;
        let (mut sender, _) = established_tunnels();
        let packets = prepared_encryptions(&mut sender, packet_count);
        let workers = CryptoWorkers::with_worker_count(2).expect("the worker pool starts");
        let crypto = workers.handle();
        let run = packets
            .into_iter()
            .map(|packet| Some(PreparedOutgoing::Encrypt(packet)))
            .collect();

        let results = std::panic::AssertUnwindSafe(crypto.encrypt_run(run, true))
            .catch_unwind()
            .await;
        let handoffs = crypto.handoff_count();
        let worker_runs = crypto.worker_run_count();
        drop(crypto);
        workers.stop().await;

        let results = results
            .expect("the grouped run is accepted")
            .expect("the worker queue remains open");
        assert_eq!(results.len(), packet_count);
        assert_eq!(handoffs, 1);
        assert_eq!(worker_runs, 1);
    }

    /// A grouped decryption keeps replay counters in order within one worker run.
    #[tokio::test]
    async fn grouped_decryption_preserves_replay_order_in_one_worker_run() {
        let packet_count = super::CRYPTO_WORKER_BATCH_SIZE;
        let (mut sender, mut receiver) = established_tunnels();
        let decryptions = prepared_decryptions(&mut sender, &mut receiver, packet_count);
        let address = "127.0.0.1:51820"
            .parse()
            .expect("the profile peer address is valid");
        let run = decryptions
            .into_iter()
            .map(|packet| (packet, address))
            .collect();
        let workers = CryptoWorkers::with_worker_count(2).expect("the worker pool starts");
        let crypto = workers.handle();

        let completions = std::panic::AssertUnwindSafe(crypto.decrypt_run(run, true))
            .catch_unwind()
            .await;
        let worker_runs = crypto.worker_run_count();
        drop(crypto);
        workers.stop().await;

        let completions = completions
            .expect("the grouped run is accepted")
            .expect("the worker queue remains open");
        assert_eq!(completions.len(), packet_count);
        assert_eq!(worker_runs, 1);
        for completion in completions {
            black_box(
                completion
                    .result
                    .expect("the prepared packet authenticates")
                    .complete()
                    .expect("replay completion follows the packet's input order"),
            );
        }
    }

    /// AEAD reuses every packet's writable backing bytes across a grouped worker run.
    #[tokio::test]
    async fn grouped_encryption_reuses_packet_backing_allocations() {
        let (mut sender, _) = established_tunnels();
        let run = prepared_encryptions(&mut sender, 4)
            .into_iter()
            .map(|packet| Some(PreparedOutgoing::Encrypt(packet)))
            .collect::<Vec<_>>();
        let input_packet_pointers = run
            .iter()
            .map(
                |prepared| match prepared.as_ref().expect("a prepared packet exists") {
                    PreparedOutgoing::Encrypt(packet) => packet.packet_buffer_ptr() as usize,
                    PreparedOutgoing::Ready(_) => panic!("the packet uses transport encryption"),
                },
            )
            .collect::<Vec<_>>();
        let workers = CryptoWorkers::with_worker_count(2).expect("the worker pool starts");
        let crypto = workers.handle();

        let results = crypto
            .encrypt_run(run, true)
            .await
            .expect("the worker queue stays open");
        let output_packet_pointers = results
            .iter()
            .map(
                |result| match result.as_ref().expect("encryption returns a packet") {
                    WgKind::Data(packet) => packet.as_bytes().as_ptr() as usize,
                    _ => panic!("the encrypted packet is data"),
                },
            )
            .collect::<Vec<_>>();
        workers.stop().await;

        assert_eq!(
            output_packet_pointers, input_packet_pointers,
            "AEAD writes into each packet's existing network buffer"
        );
    }

    /// Sparse single-packet traffic stays on the caller while no other work needs a worker.
    #[tokio::test]
    async fn a_lone_encryption_run_uses_the_serial_fast_path() {
        let (mut sender, _) = established_tunnels();
        let packets = prepared_encryptions(&mut sender, 1);
        let workers = CryptoWorkers::with_worker_count(2).expect("the worker pool starts");
        let crypto = workers.handle();
        let run = packets
            .into_iter()
            .map(|packet| Some(PreparedOutgoing::Encrypt(packet)))
            .collect();

        black_box(
            crypto
                .encrypt_run(run, false)
                .await
                .expect("the serial fast path returns the packet"),
        );

        assert_eq!(crypto.handoff_count(), 0);
        workers.stop().await;
    }

    /// Stopping the pool must not depend on every clone dropping its queue handle first.
    #[tokio::test]
    async fn stopping_workers_closes_the_queue_while_a_handle_is_live() {
        let workers = CryptoWorkers::with_worker_count(2).expect("the worker pool starts");
        let crypto = workers.handle();

        let stopped = tokio::time::timeout(Duration::from_secs(2), workers.stop()).await;
        drop(crypto);
        assert!(
            stopped.is_ok(),
            "worker shutdown must close the shared queue"
        );
    }

    /// Finishing an inline run must not clear an overlapping worker run from the active count.
    #[test]
    fn inline_run_completion_preserves_other_active_batches() {
        let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let inline = super::ActiveBatch::try_enter_inline(&active, false).unwrap();
        let queued = super::ActiveBatch::enter_queued(&active);

        drop(inline);
        assert_eq!(active.load(std::sync::atomic::Ordering::Acquire), 1);

        drop(queued);
        assert_eq!(active.load(std::sync::atomic::Ordering::Acquire), 0);
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
            .complete_run(first_slot, vec![Some(1)], |_| async { Ok::<_, ()>(()) })
            .await
            .unwrap();

        assert!(futures::poll!(&mut waiter).is_ready());
        assert!(!completions.is_idle());
        completions
            .complete_run(later_slot, vec![Some(2)], |_| async { Ok::<_, ()>(()) })
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

    /// Prepare one bounded packet stream for each peer in the stage profile.
    fn prepared_encryption_peers() -> Vec<Vec<PreparedEncryption>> {
        assert!(PROFILE_PACKET_COUNT.is_multiple_of(PROFILE_PEER_COUNT));
        (0..PROFILE_PEER_COUNT)
            .map(|_| {
                let (mut sender, _) = established_tunnels();
                prepared_encryptions(&mut sender, PROFILE_PACKET_COUNT / PROFILE_PEER_COUNT)
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

    /// Prepare valid incoming packets for each peer in the stage profile.
    fn prepared_decryption_peers() -> Vec<Vec<PreparedDecryption>> {
        assert!(PROFILE_PACKET_COUNT.is_multiple_of(PROFILE_PEER_COUNT));
        (0..PROFILE_PEER_COUNT)
            .map(|_| {
                let (mut sender, mut receiver) = established_tunnels();
                prepared_decryptions(
                    &mut sender,
                    &mut receiver,
                    PROFILE_PACKET_COUNT / PROFILE_PEER_COUNT,
                )
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

    /// Measure serial AEAD and the ordered stage at one, two, and four workers.
    ///
    /// Run with `cargo test -p gotatun --no-default-features --features device,ring,tun --lib
    /// crypto_stage_microbenchmark -- --ignored --nocapture` on a quiet compute host. Packet
    /// preparation is outside the timed interval. The ordered-stage profile places eight inner IP
    /// flows on one peer, so a read becomes one contiguous 64-packet run. Its latency runs from
    /// read readiness through in-order release, including queueing and the bounded worker batch.
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
                "crypto stage profile: packets={PROFILE_PACKET_COUNT} inner_flows={PROFILE_INNER_FLOW_COUNT} peers={PROFILE_PEER_COUNT} read_packets_per_peer={PROFILE_READ_PACKETS_PER_PEER} packet_bytes={PROFILE_PACKET_BYTES} max_read_run={CRYPTO_CHUNK_SIZE} ordered_run={CRYPTO_BATCH_SIZE} max_worker_batch={CRYPTO_WORKER_BATCH_SIZE} available_cpus={available_cpus}"
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
                let (mut sender, _) = established_tunnels();
                let packets = prepared_encryptions(&mut sender, PROFILE_SPARSE_PACKET_COUNT);
                let (elapsed, mut latencies) =
                    measure_sparse_encryptions(packets, worker_count).await;
                report_stage(
                    &format!("sparse ordered encrypt workers={worker_count}"),
                    elapsed,
                    &mut latencies,
                );
            }

            for worker_count in [1, 2, 4] {
                let encryptions = prepared_encryption_peers();
                let (elapsed, mut latencies) =
                    measure_parallel_encryptions(encryptions, worker_count).await;
                report_stage(
                    &format!("ordered encrypt workers={worker_count}"),
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
                let decryptions = prepared_decryptions(
                    &mut sender,
                    &mut receiver,
                    PROFILE_SPARSE_PACKET_COUNT,
                );
                let (elapsed, mut latencies) =
                    measure_sparse_decryptions(decryptions, worker_count).await;
                report_stage(
                    &format!("sparse ordered decrypt workers={worker_count}"),
                    elapsed,
                    &mut latencies,
                );
            }

            for worker_count in [1, 2, 4] {
                let decryptions = prepared_decryption_peers();
                let (elapsed, mut latencies) =
                    measure_parallel_decryptions(decryptions, worker_count).await;
                report_stage(
                    &format!("ordered decrypt workers={worker_count}"),
                    elapsed,
                    &mut latencies,
                );
            }
        });
    }

    /// Measure singleton reads through the in-order stage while keeping the worker pool idle.
    async fn measure_sparse_encryptions(
        packets: Vec<PreparedEncryption>,
        worker_count: usize,
    ) -> (Duration, Vec<Duration>) {
        let workers = CryptoWorkers::with_worker_count(worker_count)
            .expect("the requested worker pool starts");
        let crypto = workers.handle();
        let lane = OrderedCompletions::<WgKind>::default();
        let mut latencies = Vec::with_capacity(packets.len());
        let started = Instant::now();

        for packet in packets {
            let packet_started = Instant::now();
            let slot = lane.reserve_run(1).expect("the sparse slot is available");
            let results = crypto
                .encrypt_run(vec![Some(PreparedOutgoing::Encrypt(packet))], false)
                .await
                .expect("the serial fast path returns its packet");
            lane.complete_run(slot, results, |mut results| async move {
                black_box(results.pop().flatten());
                Ok::<_, ()>(())
            })
            .await
            .expect("ordered sparse delivery succeeds");
            latencies.push(packet_started.elapsed());
        }

        let elapsed = started.elapsed();
        drop(crypto);
        workers.stop().await;
        (elapsed, latencies)
    }

    /// Measure singleton receives through ordered replay marking with no worker handoff.
    async fn measure_sparse_decryptions(
        packets: Vec<PreparedDecryption>,
        worker_count: usize,
    ) -> (Duration, Vec<Duration>) {
        let workers = CryptoWorkers::with_worker_count(worker_count)
            .expect("the requested worker pool starts");
        let crypto = workers.handle();
        let lane = OrderedCompletions::<IncomingCompletion>::default();
        let mut latencies = Vec::with_capacity(packets.len());
        let started = Instant::now();
        let addr = "127.0.0.1:51820"
            .parse()
            .expect("the profile peer address is valid");

        for packet in packets {
            let packet_started = Instant::now();
            let slot = lane.reserve_run(1).expect("the sparse slot is available");
            let mut results = crypto
                .decrypt_run(vec![(packet, addr)], false)
                .await
                .expect("the serial fast path returns its packet");
            let completion = results.pop().expect("one packet was decrypted");
            lane.complete_run(slot, vec![Some(completion)], |mut results| async move {
                let completion = results
                    .pop()
                    .flatten()
                    .expect("the sparse completion exists");
                black_box(
                    completion
                        .result
                        .expect("the sparse packet authenticates")
                        .complete()
                        .expect("the sparse replay counter is accepted"),
                );
                Ok::<_, ()>(())
            })
            .await
            .expect("ordered replay marking succeeds");
            latencies.push(packet_started.elapsed());
        }

        let elapsed = started.elapsed();
        drop(crypto);
        workers.stop().await;
        (elapsed, latencies)
    }

    /// Measure encryption throughput and time from read readiness through ordered release.
    async fn measure_parallel_encryptions(
        peers: Vec<Vec<PreparedEncryption>>,
        worker_count: usize,
    ) -> (Duration, Vec<Duration>) {
        let workers = CryptoWorkers::with_worker_count(worker_count)
            .expect("the requested worker pool starts");
        assert_eq!(workers.worker_count(), worker_count);
        let crypto = workers.handle();
        let lanes = (0..peers.len())
            .map(|_| Arc::new(OrderedCompletions::<WgKind>::default()))
            .collect::<Vec<_>>();
        let mut peers = peers.into_iter().map(Vec::into_iter).collect::<Vec<_>>();
        let mut latencies = Vec::with_capacity(PROFILE_PACKET_COUNT);
        let started = Instant::now();

        loop {
            let mut pending = FuturesUnordered::new();
            for _ in 0..PROFILE_READS_IN_FLIGHT {
                let read_started = Instant::now();
                let mut read_has_packets = false;
                for (peer_index, packets) in peers.iter_mut().enumerate() {
                    let batch = packets
                        .by_ref()
                        .take(PROFILE_READ_PACKETS_PER_PEER)
                        .map(|packet| Some(PreparedOutgoing::Encrypt(packet)))
                        .collect::<Vec<_>>();
                    if batch.is_empty() {
                        continue;
                    }
                    read_has_packets = true;
                    let batch_len = batch.len();
                    let lane = Arc::clone(&lanes[peer_index]);
                    let first_slot = lane
                        .reserve_run(batch_len)
                        .expect("ready peer runs fit the in-flight window");
                    let crypto = crypto.clone();
                    pending.push(async move {
                        let results = crypto
                            .encrypt_run(batch, worker_count > 1 && batch_len > 1)
                            .await
                            .expect("the worker queue remains open");
                        lane.complete_run(first_slot, results, |results| async move {
                            black_box(results);
                            Ok::<_, ()>(())
                        })
                        .await
                        .expect("ordered delivery succeeds");
                        (batch_len, read_started.elapsed())
                    });
                }
                if !read_has_packets {
                    break;
                }
            }
            if pending.is_empty() {
                break;
            }
            while let Some((batch_len, latency)) = pending.next().await {
                latencies.resize(latencies.len() + batch_len, latency);
            }
        }

        let elapsed = started.elapsed();
        assert!(lanes.iter().all(|lane| lane.is_idle()));
        drop(crypto);
        workers.stop().await;
        (elapsed, latencies)
    }

    /// Measure decryption worker throughput and time through ordered replay marking.
    async fn measure_parallel_decryptions(
        peers: Vec<Vec<PreparedDecryption>>,
        worker_count: usize,
    ) -> (Duration, Vec<Duration>) {
        let workers = CryptoWorkers::with_worker_count(worker_count)
            .expect("the requested worker pool starts");
        assert_eq!(workers.worker_count(), worker_count);
        let crypto = workers.handle();
        let lanes = (0..peers.len())
            .map(|_| Arc::new(OrderedCompletions::<IncomingCompletion>::default()))
            .collect::<Vec<_>>();
        let mut peers = peers.into_iter().map(Vec::into_iter).collect::<Vec<_>>();
        let mut latencies = Vec::with_capacity(PROFILE_PACKET_COUNT);
        let started = Instant::now();
        let addr = "127.0.0.1:51820"
            .parse()
            .expect("the profile peer address is valid");

        loop {
            let mut pending = FuturesUnordered::new();
            for _ in 0..PROFILE_READS_IN_FLIGHT {
                let read_started = Instant::now();
                let mut read_has_packets = false;
                for (peer_index, decryptions) in peers.iter_mut().enumerate() {
                    let batch = decryptions
                        .by_ref()
                        .take(PROFILE_READ_PACKETS_PER_PEER)
                        .map(|packet| (packet, addr))
                        .collect::<Vec<_>>();
                    if batch.is_empty() {
                        continue;
                    }
                    read_has_packets = true;
                    let batch_len = batch.len();
                    let lane = Arc::clone(&lanes[peer_index]);
                    let first_slot = lane
                        .reserve_run(batch_len)
                        .expect("ready peer runs fit the in-flight window");
                    let crypto = crypto.clone();
                    pending.push(async move {
                        let completions = crypto
                            .decrypt_run(batch, worker_count > 1 && batch_len > 1)
                            .await
                            .expect("the worker queue remains open");
                        let results = completions.into_iter().map(Some).collect();
                        lane.complete_run(first_slot, results, |completions| async move {
                            for completion in completions.into_iter().flatten() {
                                black_box(
                                    completion
                                        .result
                                        .expect("the profile packet authenticates")
                                        .complete()
                                        .expect("the ordered profile counter is accepted"),
                                );
                            }
                            Ok::<_, ()>(())
                        })
                        .await
                        .expect("ordered replay marking succeeds");
                        (batch_len, read_started.elapsed())
                    });
                }
                if !read_has_packets {
                    break;
                }
            }
            if pending.is_empty() {
                break;
            }
            while let Some((batch_len, latency)) = pending.next().await {
                latencies.resize(latencies.len() + batch_len, latency);
            }
        }

        let elapsed = started.elapsed();
        assert!(lanes.iter().all(|lane| lane.is_idle()));
        drop(crypto);
        workers.stop().await;
        (elapsed, latencies)
    }
}
