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
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
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

/// Smallest ready peer run worth offloading when another run can execute concurrently.
pub(crate) const MIN_PARALLEL_RUN_SIZE: usize = 8;

/// Start parallel dispatch after half a worker chunk of older packets is queued for this peer.
pub(crate) const PARALLEL_DISPATCH_HIGH_WATER: usize = CRYPTO_CHUNK_SIZE / 2;

/// Return to inline dispatch after this peer's older backlog drains below one minimum run.
pub(crate) const PARALLEL_DISPATCH_LOW_WATER: usize = MIN_PARALLEL_RUN_SIZE;

/// Maximum outstanding completion slots for one peer and one direction.
pub(crate) const MAX_PEER_CRYPTO_IN_FLIGHT: usize = 128;

/// Bound on worker runs waiting in the shared queue. Every run is already full when submitted;
/// workers never wait to fill it, so a short packet cannot be held behind a packet-count target.
pub(crate) const MAX_QUEUED_CRYPTO_JOBS: usize = 128;

/// Number of lock-free checks a worker makes for newly queued chunks before it parks.
const WORKER_SPIN_COUNT: usize = 128;

/// Whether a ready run has enough queued work behind it to justify entering parallel dispatch.
///
/// The backlog is measured in older reserved packet slots for this peer. A large lone run cannot
/// benefit from a worker handoff, and another peer's activity must not make this peer leave its
/// shallow-queue fast path.
pub(crate) const fn should_force_worker(packet_count: usize, peer_backlog_packets: usize) -> bool {
    packet_count >= MIN_PARALLEL_RUN_SIZE && peer_backlog_packets >= PARALLEL_DISPATCH_HIGH_WATER
}

/// A decrypted packet and the session metadata applied at its ordered release point.
pub(crate) struct IncomingCompletion {
    /// The verified AEAD result whose replay update waits for ordered release.
    pub(crate) result: Result<VerifiedDecryption, WireGuardError>,
    /// The address that authenticated this packet if replay validation succeeds.
    pub(crate) addr: SocketAddr,
}

/// Tracks reserved sequence positions and completed packets for one peer direction.
struct CompletionState {
    next_slot: u64,
    /// First slot that has not yet claimed the ordered delivery turn.
    next_release: u64,
    /// First slot whose delivery callback has not finished.
    next_delivered: u64,
    in_flight: usize,
    /// Reserved packets whose AEAD work has not completed; ordered delivery is tracked separately.
    crypto_pending: usize,
    /// AEAD-complete runs waiting for their turn; each future retains its results and callback.
    completed: BTreeMap<u64, usize>,
    /// Adaptive dispatch exists only while this ordered lane has in-flight slots.
    dispatch: AdaptiveDispatch,
}

/// Per-peer high and low water marks for handing bounded runs to crypto workers.
///
/// This latch lives inside the ordered lane, which is removed as soon as its peer drains. No idle
/// peer keeps a timer or adaptive-dispatch state alive.
#[derive(Default)]
struct AdaptiveDispatch {
    parallel: bool,
}

impl AdaptiveDispatch {
    /// Update this peer's hysteresis latch and select a worker only for useful batch sizes.
    fn should_force_worker(&mut self, packet_count: usize, peer_backlog_packets: usize) -> bool {
        if self.parallel {
            if peer_backlog_packets <= PARALLEL_DISPATCH_LOW_WATER {
                self.parallel = false;
            }
        } else if should_force_worker(packet_count, peer_backlog_packets) {
            self.parallel = true;
        }

        self.parallel && packet_count >= MIN_PARALLEL_RUN_SIZE
    }
}

/// Assigns peer-local slots and releases completed results only in slot order.
///
/// Producers reserve while holding their peer's state lock. Workers may finish in any order, but
/// each completion keeps its own result and delivery callback while waiting for its sequence turn.
/// Completed crypto leaves the dispatch backlog before the serialized delivery lock is acquired.
pub(crate) struct OrderedCompletions<T> {
    state: Mutex<CompletionState>,
    delivery: AsyncMutex<()>,
    progress: Notify,
    _result_type: PhantomData<fn() -> T>,
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
                crypto_pending: 0,
                completed: BTreeMap::new(),
                dispatch: AdaptiveDispatch::default(),
            }),
            delivery: AsyncMutex::new(()),
            progress: Notify::new(),
            _result_type: PhantomData,
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
        state.crypto_pending += count;
        Some(first_slot)
    }

    /// Decide whether this bounded run should join the peer's active parallel phase.
    ///
    /// Call after reserving the run so `crypto_pending` includes it. The backlog counts older
    /// packets that have not finished AEAD, excluding completed work waiting for ordered I/O. The
    /// lane's separate high and low water marks prevent mode flapping.
    pub(crate) fn should_force_worker(&self, packet_count: usize) -> bool {
        assert!(packet_count > 0, "a crypto dispatch run cannot be empty");
        if std::env::var_os("GOTATUN_DIAG_FORCE_INLINE").is_some() {
            return false;
        }
        if std::env::var_os("GOTATUN_DIAG_FORCE_WORKERS").is_some() {
            return true;
        }
        let mut state = self.state.lock();
        assert!(
            packet_count <= state.crypto_pending,
            "dispatch can only inspect slots already reserved by this peer"
        );
        let peer_backlog_packets = state.crypto_pending - packet_count;
        state
            .dispatch
            .should_force_worker(packet_count, peer_backlog_packets)
    }

    /// Record AEAD completion and deliver this run when its slot range reaches the front.
    ///
    /// `None` marks a slot that completed without a packet, such as an invalid receive packet.
    pub(crate) async fn complete_run<F, Fut, E>(
        &self,
        first_slot: u64,
        results: Vec<Option<T>>,
        deliver: F,
    ) -> Result<(), E>
    where
        F: FnMut(Vec<Option<T>>) -> Fut,
        Fut: Future<Output = Result<(), E>>,
    {
        self.complete_run_inner(None, first_slot, results, deliver)
            .await
    }

    /// Complete a run with the peer and direction attached to its diagnostics.
    pub(crate) async fn complete_run_traced<F, Fut, E>(
        &self,
        direction: &'static str,
        peer_key: usize,
        first_slot: u64,
        results: Vec<Option<T>>,
        deliver: F,
    ) -> Result<(), E>
    where
        F: FnMut(Vec<Option<T>>) -> Fut,
        Fut: Future<Output = Result<(), E>>,
    {
        self.complete_run_inner(Some((direction, peer_key)), first_slot, results, deliver)
            .await
    }

    async fn complete_run_inner<F, Fut, E>(
        &self,
        diagnostic_lane: Option<(&'static str, usize)>,
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
        let diagnostic = std::env::var_os("GOTATUN_DIAG_PIPELINE").is_some()
            || std::env::var_os("GOTATUN_DIAG_SEND_QUEUE").is_some();
        {
            let mut state = self.state.lock();
            assert!(
                first_slot >= state.next_release && end_slot <= state.next_slot,
                "completion run {first_slot}..{end_slot} was not outstanding"
            );
            assert!(
                run_len <= state.crypto_pending,
                "completion run {first_slot}..{end_slot} finished more crypto slots than remain"
            );
            assert!(
                state.completed.insert(first_slot, run_len).is_none(),
                "completion run beginning at slot {first_slot} was completed twice"
            );
            state.crypto_pending -= run_len;
        }
        if diagnostic {
            if let Some((direction, peer_key)) = diagnostic_lane {
                eprintln!(
                    "pipeline stage=ordered_completion_ready direction={direction} peer={peer_key} first_slot={first_slot} packets={run_len}"
                );
            } else {
                eprintln!(
                    "pipeline stage=ordered_completion_ready first_slot={first_slot} packets={run_len}"
                );
            }
        }

        loop {
            let notified = self.progress.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            if diagnostic {
                if let Some((direction, peer_key)) = diagnostic_lane {
                    eprintln!(
                        "pipeline stage=ordered_delivery_lock_wait direction={direction} peer={peer_key} first_slot={first_slot}"
                    );
                } else {
                    eprintln!("pipeline stage=ordered_delivery_lock_wait first_slot={first_slot}");
                }
            }
            let delivery = self.delivery.lock().await;
            if diagnostic {
                if let Some((direction, peer_key)) = diagnostic_lane {
                    eprintln!(
                        "pipeline stage=ordered_delivery_lock_acquired direction={direction} peer={peer_key} first_slot={first_slot}"
                    );
                } else {
                    eprintln!(
                        "pipeline stage=ordered_delivery_lock_acquired first_slot={first_slot}"
                    );
                }
            }
            let (is_next_run, next_release, wait_snapshot) = {
                let mut state = self.state.lock();
                assert!(
                    first_slot >= state.next_release && end_slot <= state.next_slot,
                    "completion run {first_slot}..{end_slot} was not outstanding"
                );
                if first_slot == state.next_release {
                    assert_eq!(
                        state.completed.remove(&first_slot),
                        Some(run_len),
                        "the next ordered run must have completed crypto"
                    );
                    // Claim the ordered turn before awaiting I/O; `next_delivered` advances later.
                    state.next_release = end_slot;
                    (true, state.next_release, None)
                } else {
                    let snapshot = diagnostic.then(|| {
                        (
                            state.next_slot,
                            state.next_delivered,
                            state.in_flight,
                            state.crypto_pending,
                            state.completed.keys().copied().collect::<Vec<_>>(),
                        )
                    });
                    (false, state.next_release, snapshot)
                }
            };

            if !is_next_run {
                if diagnostic {
                    let (next_slot, next_delivered, in_flight, crypto_pending, completed) =
                        wait_snapshot.expect("diagnostics capture an ordered wait snapshot");
                    if let Some((direction, peer_key)) = diagnostic_lane {
                        eprintln!(
                            "pipeline stage=ordered_wait_predecessor direction={direction} peer={peer_key} first_slot={first_slot} next_release={next_release} next_slot={next_slot} next_delivered={next_delivered} in_flight={in_flight} crypto_pending={crypto_pending} completed={completed:?}"
                        );
                    } else {
                        eprintln!(
                            "pipeline stage=ordered_wait_predecessor first_slot={first_slot} next_release={next_release} next_slot={next_slot} next_delivered={next_delivered} in_flight={in_flight} crypto_pending={crypto_pending} completed={completed:?}"
                        );
                    }
                }
                drop(delivery);
                notified.await;
                continue;
            }

            if diagnostic {
                if let Some((direction, peer_key)) = diagnostic_lane {
                    eprintln!(
                        "pipeline stage=ordered_delivery_start direction={direction} peer={peer_key} first_slot={first_slot}"
                    );
                } else {
                    eprintln!("pipeline stage=ordered_delivery_start first_slot={first_slot}");
                }
            }
            let result = deliver(results).await;
            if diagnostic {
                if let Some((direction, peer_key)) = diagnostic_lane {
                    eprintln!(
                        "pipeline stage=ordered_delivery_done direction={direction} peer={peer_key} first_slot={first_slot} success={}",
                        result.is_ok()
                    );
                } else {
                    eprintln!(
                        "pipeline stage=ordered_delivery_done first_slot={first_slot} success={}",
                        result.is_ok()
                    );
                }
            }
            {
                let mut state = self.state.lock();
                assert_eq!(
                    state.next_delivered, first_slot,
                    "ordered completion delivery advanced out of sequence"
                );
                state.next_delivered = end_slot;
                state.in_flight -= run_len;
            }
            self.progress.notify_waiters();
            drop(delivery);
            return result;
        }
    }

    /// Whether every reserved slot has been delivered.
    pub(crate) fn is_idle(&self) -> bool {
        let state = self.state.lock();
        state.in_flight == 0 && state.crypto_pending == 0 && state.completed.is_empty()
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
        static REPORTED_ENCRYPT_HANDOFF: AtomicBool = AtomicBool::new(false);
        if std::env::var_os("GOTATUN_DIAG_FORCE_WORKERS").is_some()
            && !REPORTED_ENCRYPT_HANDOFF.swap(true, Ordering::Relaxed)
        {
            eprintln!("diagnostic: encrypt run handed to crypto worker");
        }
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
        static REPORTED_DECRYPT_HANDOFF: AtomicBool = AtomicBool::new(false);
        if std::env::var_os("GOTATUN_DIAG_FORCE_WORKERS").is_some()
            && !REPORTED_DECRYPT_HANDOFF.swap(true, Ordering::Relaxed)
        {
            eprintln!("diagnostic: decrypt run handed to crypto worker");
        }
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
    /// Keep a shallow peer run on its caller even while unrelated crypto work is active.
    ///
    /// The peer-local adaptive latch already decides whether a run needs a worker handoff. A
    /// global active count must not put an interactive peer behind another peer's queued work.
    fn try_enter_inline(active_batches: &Arc<AtomicUsize>, force_worker: bool) -> Option<Self> {
        if force_worker {
            return None;
        }

        active_batches.fetch_add(1, Ordering::AcqRel);
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

    use std::collections::VecDeque;
    use std::future::Future;
    use std::hint::black_box;
    use std::sync::{Arc, Mutex, mpsc};
    use std::thread;
    use std::time::{Duration, Instant};

    use bytes::BytesMut;
    use futures::{FutureExt, StreamExt, stream::FuturesUnordered};
    use zerocopy::IntoBytes;

    use super::{
        CRYPTO_BATCH_SIZE, CRYPTO_CHUNK_SIZE, CRYPTO_WORKER_BATCH_SIZE, CryptoWorkers,
        IncomingCompletion, MAX_PEER_CRYPTO_IN_FLIGHT, MIN_PARALLEL_RUN_SIZE, OrderedCompletions,
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

    /// Inner IP flows carried by each peer in the loaded stage profile.
    const PROFILE_INNER_FLOW_COUNT: usize = 8;

    /// Two peers let four workers run without exceeding either peer's slot window.
    const PROFILE_PEER_COUNT: usize = 2;

    /// Keep one extra ready run per worker so the loaded profile crosses the peer backlog mark.
    const PROFILE_READY_RUNS_PER_WORKER: usize = 2;

    /// Packets per peer in one ready read from the profile.
    const PROFILE_READ_PACKETS_PER_PEER: usize = CRYPTO_CHUNK_SIZE;

    /// Select one worker count for affinity-specific runs, or keep the full default sweep.
    fn profile_worker_counts() -> Vec<usize> {
        match std::env::var("GOTATUN_PROFILE_WORKERS") {
            Ok(value) => {
                let worker_count = value
                    .parse::<usize>()
                    .expect("the profile worker count is an integer");
                assert!(
                    [1, 2, 4].contains(&worker_count),
                    "the profile worker count must be 1, 2 or 4"
                );
                vec![worker_count]
            }
            Err(std::env::VarError::NotPresent) => vec![1, 2, 4],
            Err(std::env::VarError::NotUnicode(_)) => {
                panic!("the profile worker count is valid text")
            }
        }
    }

    /// One peer's ready packet run and its arrival time at the crypto stage.
    struct ProfilePeerRead<T> {
        /// The peer whose sequence lane owns this run.
        peer_index: usize,
        /// When the complete read run became available to the stage.
        ready_at: Instant,
        /// The contiguous packets from this read.
        packets: Vec<T>,
    }

    /// Keep one lazy packet stream per peer for fair ready-read scheduling.
    fn profile_peer_streams<T>(peers: Vec<Vec<T>>) -> VecDeque<(usize, std::vec::IntoIter<T>)> {
        peers
            .into_iter()
            .enumerate()
            .map(|(peer_index, packets)| (peer_index, packets.into_iter()))
            .collect::<VecDeque<_>>()
    }

    /// Keep a bounded set of ready reads active, replacing each completed run immediately.
    async fn run_profile_window<R, T, I, F, Fut>(
        reads: I,
        max_in_flight: usize,
        mut process: F,
    ) -> Vec<T>
    where
        I: IntoIterator<Item = R>,
        F: FnMut(R) -> Fut,
        Fut: Future<Output = T> + 'static,
    {
        assert!(max_in_flight > 0, "the profile window must be non-empty");
        let mut reads = reads.into_iter();
        let mut pending = FuturesUnordered::<Fut>::new();
        let mut completed = Vec::new();

        while pending.len() < max_in_flight {
            let Some(read) = reads.next() else {
                break;
            };
            pending.push(process(read));
        }

        while let Some(result) = pending.next().await {
            completed.push(result);
            if let Some(read) = reads.next() {
                pending.push(process(read));
            }
        }

        completed
    }

    /// Take one fitting run without materializing batches for peers whose slot windows are full.
    fn next_profile_peer_read<T>(
        streams: &mut VecDeque<(usize, std::vec::IntoIter<T>)>,
        peer_in_flight: &[usize],
        peer_capacity: usize,
    ) -> Option<ProfilePeerRead<T>> {
        let peers_to_check = streams.len();
        for _ in 0..peers_to_check {
            let (peer_index, mut packets) =
                streams.pop_front().expect("the peer stream remains queued");
            let Some(run_len) = (!packets.as_slice().is_empty())
                .then_some(packets.as_slice().len().min(PROFILE_READ_PACKETS_PER_PEER))
            else {
                continue;
            };
            let in_flight = peer_in_flight[peer_index];
            assert!(
                in_flight <= peer_capacity,
                "a peer stays within its slot bound"
            );
            if run_len > peer_capacity - in_flight {
                streams.push_back((peer_index, packets));
                continue;
            }

            let batch = packets.by_ref().take(run_len).collect();
            if !packets.as_slice().is_empty() {
                streams.push_back((peer_index, packets));
            }
            return Some(ProfilePeerRead {
                peer_index,
                ready_at: Instant::now(),
                packets: batch,
            });
        }
        None
    }

    /// Keep a global worker window while respecting each peer's ordered slot capacity.
    async fn run_profile_peer_window<T, R, F, Fut>(
        peers: Vec<Vec<T>>,
        max_in_flight: usize,
        mut process: F,
    ) -> Vec<R>
    where
        F: FnMut(ProfilePeerRead<T>) -> Fut,
        Fut: Future<Output = R> + 'static,
    {
        assert!(max_in_flight > 0, "the profile window must be non-empty");
        let peer_count = peers.len();
        assert!(peer_count > 0, "the profile must contain at least one peer");

        let mut streams = profile_peer_streams(peers);
        let mut peer_in_flight = vec![0usize; peer_count];
        let mut pending = FuturesUnordered::new();
        let mut completed = Vec::new();

        loop {
            while pending.len() < max_in_flight {
                let Some(read) = next_profile_peer_read(
                    &mut streams,
                    &peer_in_flight,
                    MAX_PEER_CRYPTO_IN_FLIGHT,
                ) else {
                    break;
                };
                let peer_index = read.peer_index;
                assert!(
                    peer_index < peer_count,
                    "each profile read belongs to a configured peer"
                );
                let run_len = read.packets.len();
                peer_in_flight[peer_index] += run_len;
                let run = process(read);
                pending.push(async move { (peer_index, run_len, run.await) });
            }

            let Some((peer_index, run_len, result)) = pending.next().await else {
                assert!(streams.is_empty(), "all profile peer streams are drained");
                break;
            };
            peer_in_flight[peer_index] -= run_len;
            completed.push(result);
        }

        completed
    }

    /// Refill the bounded read window when one run finishes, even if another remains pending.
    #[tokio::test]
    async fn profile_window_refills_before_the_previous_window_drains() {
        let (release_first_tx, release_first_rx) = tokio::sync::oneshot::channel();
        let (release_second_tx, release_second_rx) = tokio::sync::oneshot::channel();
        let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut gates = VecDeque::from([Some(release_first_rx), Some(release_second_rx), None]);

        let task = tokio::spawn(run_profile_window(vec![0, 1, 2], 2, move |run| {
            let gate = gates.pop_front().expect("each run gets one gate");
            let started = started_tx.clone();
            async move {
                started.send(run).expect("the scheduler test is listening");
                if let Some(gate) = gate {
                    gate.await.expect("the scheduler test releases the run");
                }
                run
            }
        }));

        let mut first_window = vec![
            started_rx.recv().await.expect("the first run starts"),
            started_rx.recv().await.expect("the second run starts"),
        ];
        first_window.sort_unstable();
        assert_eq!(first_window, vec![0, 1]);
        assert!(started_rx.try_recv().is_err(), "the window holds two runs");

        release_first_tx
            .send(())
            .expect("the first run is still waiting");
        let mut refilled = None;
        for _ in 0..8 {
            tokio::task::yield_now().await;
            if let Ok(run) = started_rx.try_recv() {
                refilled = Some(run);
                break;
            }
        }
        release_second_tx
            .send(())
            .expect("the second run is still waiting");

        assert_eq!(refilled, Some(2));
        assert_eq!(
            task.await.expect("the profile scheduler completes"),
            vec![0, 2, 1]
        );
    }

    /// Keep four ready worker runs inside each peer's bounded completion window.
    #[tokio::test]
    async fn profile_four_worker_window_respects_each_peer_capacity() {
        let peers = vec![
            vec![(); PROFILE_READ_PACKETS_PER_PEER * 4],
            vec![(); PROFILE_READ_PACKETS_PER_PEER * 4],
        ];
        let lanes = (0..peers.len())
            .map(|_| Arc::new(OrderedCompletions::<()>::default()))
            .collect::<Vec<_>>();

        let completed = run_profile_peer_window(peers, 4, |read| {
            let lane = Arc::clone(&lanes[read.peer_index]);
            let run_len = read.packets.len();
            let first_slot = lane
                .reserve_run(run_len)
                .expect("the ready profile window fits each peer's slot bound");
            async move {
                lane.complete_run(first_slot, vec![Some(()); run_len], |_| async {
                    Ok::<_, ()>(())
                })
                .await
                .expect("the profile run completes in order");
            }
        })
        .await;

        assert_eq!(completed.len(), 8);
    }

    /// Keep another peer moving while a slow peer has filled its ordered slot window.
    #[tokio::test]
    async fn profile_window_does_not_overfill_a_slow_peers_slot_capacity() {
        let peers = vec![
            vec![(); PROFILE_READ_PACKETS_PER_PEER * 4],
            vec![(); PROFILE_READ_PACKETS_PER_PEER * 4],
        ];
        let lanes = (0..peers.len())
            .map(|_| Arc::new(OrderedCompletions::<()>::default()))
            .collect::<Vec<_>>();
        let (release_slow_peer_tx, release_slow_peer_rx) = tokio::sync::oneshot::channel();
        let mut slow_peer_gate = Some(release_slow_peer_rx);
        let (fast_peer_done_tx, mut fast_peer_done_rx) = tokio::sync::mpsc::unbounded_channel();

        let mut task = tokio::spawn(run_profile_peer_window(peers, 4, move |read| {
            let lane = Arc::clone(&lanes[read.peer_index]);
            let run_len = read.packets.len();
            let first_slot = lane
                .reserve_run(run_len)
                .expect("the profile scheduler stays within each peer's slot window");
            let gate = (read.peer_index == 0 && first_slot == 0).then(|| {
                slow_peer_gate
                    .take()
                    .expect("the first slow run has a gate")
            });
            let fast_peer_done = fast_peer_done_tx.clone();

            async move {
                if let Some(gate) = gate {
                    gate.await.expect("the slow peer is eventually released");
                }
                lane.complete_run(first_slot, vec![Some(()); run_len], |_| async {
                    Ok::<_, ()>(())
                })
                .await
                .expect("the profile run completes in order");
                if read.peer_index == 1 {
                    fast_peer_done
                        .send(())
                        .expect("the test is listening for the fast peer");
                }
            }
        }));

        for _ in 0..4 {
            tokio::select! {
                result = &mut task => panic!("the profile scheduler failed before the fast peer drained: {result:?}"),
                completed = fast_peer_done_rx.recv() => {
                    assert!(completed.is_some(), "the fast peer completion channel stays open");
                }
            }
        }

        release_slow_peer_tx
            .send(())
            .expect("the slow peer is still waiting");
        assert_eq!(
            task.await.expect("the profile scheduler completes"),
            vec![(), (), (), (), (), (), (), ()]
        );
    }

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

    /// A later batch must run its own delivery callback after an earlier packet closes the gap.
    #[test]
    fn concurrent_producers_keep_each_runs_delivery_callback() {
        let completions = Arc::new(OrderedCompletions::<u64>::default());
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
                let slot = first_completions.reserve_run(1).unwrap();
                first_slot_tx.send(slot).unwrap();
                release_first_rx.await.unwrap();
                first_completions
                    .complete_run(slot, vec![Some(0)], |values| {
                        let delivered = Arc::clone(&first_delivered);
                        async move {
                            delivered
                                .lock()
                                .unwrap()
                                .push((slot, values.into_iter().flatten().collect::<Vec<_>>()));
                            Ok::<_, ()>(())
                        }
                    })
                    .await
                    .unwrap();
            });
        });

        assert_eq!(first_slot_rx.recv().unwrap(), 0);

        let (later_ready_tx, later_ready_rx) = mpsc::sync_channel(1);
        let (later_waiting_tx, later_waiting_rx) = mpsc::sync_channel(1);
        let later_completions = Arc::clone(&completions);
        let later_delivered = Arc::clone(&delivered);
        let later = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let slot = later_completions.reserve_run(2).unwrap();
                later_ready_tx.send(slot).unwrap();
                let mut completion = Box::pin(later_completions.complete_run(
                    slot,
                    vec![Some(1), Some(2)],
                    |values| {
                        let delivered = Arc::clone(&later_delivered);
                        async move {
                            delivered
                                .lock()
                                .unwrap()
                                .push((slot, values.into_iter().flatten().collect::<Vec<_>>()));
                            Ok::<_, ()>(())
                        }
                    },
                ));
                assert!(futures::poll!(&mut completion).is_pending());
                later_waiting_tx.send(()).unwrap();
                completion.await.unwrap();
            });
        });

        assert_eq!(later_ready_rx.recv().unwrap(), 1);
        later_waiting_rx.recv().unwrap();
        assert!(delivered.lock().unwrap().is_empty());

        release_first_tx.send(()).unwrap();
        first.join().unwrap();
        later.join().unwrap();

        assert_eq!(
            *delivered.lock().unwrap(),
            vec![(0, vec![0]), (1, vec![1, 2])]
        );
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

    /// Keep a lone ready run inline and dispatch substantial work only when another run exists.
    #[test]
    fn worker_dispatch_requires_a_useful_run_and_peer_backlog() {
        assert!(!super::should_force_worker(
            1,
            super::PARALLEL_DISPATCH_HIGH_WATER
        ));
        assert!(!super::should_force_worker(
            MIN_PARALLEL_RUN_SIZE - 1,
            super::PARALLEL_DISPATCH_HIGH_WATER
        ));
        assert!(!super::should_force_worker(
            MIN_PARALLEL_RUN_SIZE,
            super::PARALLEL_DISPATCH_HIGH_WATER - 1
        ));
        assert!(super::should_force_worker(
            MIN_PARALLEL_RUN_SIZE,
            super::PARALLEL_DISPATCH_HIGH_WATER
        ));
    }

    /// Keep parallel dispatch active in the hysteresis band, then collapse near an empty queue.
    #[test]
    fn adaptive_dispatch_uses_distinct_high_and_low_watermarks() {
        let mut dispatch = super::AdaptiveDispatch::default();
        assert!(!dispatch.should_force_worker(CRYPTO_CHUNK_SIZE, 0));
        assert!(!dispatch.should_force_worker(
            MIN_PARALLEL_RUN_SIZE,
            super::PARALLEL_DISPATCH_HIGH_WATER - 1
        ));
        assert!(
            dispatch
                .should_force_worker(MIN_PARALLEL_RUN_SIZE, super::PARALLEL_DISPATCH_HIGH_WATER)
        );
        assert!(dispatch.should_force_worker(
            MIN_PARALLEL_RUN_SIZE,
            super::PARALLEL_DISPATCH_LOW_WATER + 1
        ));
        assert!(
            !dispatch
                .should_force_worker(MIN_PARALLEL_RUN_SIZE, super::PARALLEL_DISPATCH_LOW_WATER)
        );
        assert!(!dispatch.should_force_worker(
            MIN_PARALLEL_RUN_SIZE,
            super::PARALLEL_DISPATCH_HIGH_WATER - 1
        ));
    }

    /// Backlog on one peer must not force a shallow peer out of its inline fast path.
    #[test]
    fn adaptive_dispatch_uses_each_peers_own_ordered_backlog() {
        let bulk_peer = OrderedCompletions::<()>::default();
        let interactive_peer = OrderedCompletions::<()>::default();
        bulk_peer
            .reserve_run(super::PARALLEL_DISPATCH_HIGH_WATER)
            .expect("the bulk peer has bounded backlog capacity");
        bulk_peer
            .reserve_run(MIN_PARALLEL_RUN_SIZE)
            .expect("the current bulk run fits in its lane");
        interactive_peer
            .reserve_run(MIN_PARALLEL_RUN_SIZE)
            .expect("the interactive run fits in its lane");

        assert!(bulk_peer.should_force_worker(MIN_PARALLEL_RUN_SIZE));
        assert!(!interactive_peer.should_force_worker(MIN_PARALLEL_RUN_SIZE));
    }

    /// A shallow peer keeps its caller-side path while another peer has worker work active.
    #[tokio::test]
    async fn shallow_peer_run_stays_inline_while_another_batch_is_active() {
        let (mut sender, _) = established_tunnels();
        let packets = prepared_encryptions(&mut sender, MIN_PARALLEL_RUN_SIZE);
        let workers = CryptoWorkers::with_worker_count(2).expect("the worker pool starts");
        let crypto = workers.handle();
        let other_peer_batch = super::ActiveBatch::enter_queued(&crypto.active_batches);
        let lane = OrderedCompletions::<WgKind>::default();
        let first_slot = lane
            .reserve_run(MIN_PARALLEL_RUN_SIZE)
            .expect("the interactive run fits the peer's ordered window");
        let run = packets
            .into_iter()
            .map(|packet| Some(PreparedOutgoing::Encrypt(packet)))
            .collect();
        let force_worker = lane.should_force_worker(MIN_PARALLEL_RUN_SIZE);
        assert!(!force_worker, "the interactive peer's queue stays shallow");

        let results = crypto
            .encrypt_run(run, force_worker)
            .await
            .expect("the shallow run completes while bulk work is active");
        lane.complete_run(first_slot, results, |results| async move {
            black_box(results);
            Ok::<_, ()>(())
        })
        .await
        .expect("the interactive run is released in its peer order");

        assert_eq!(
            crypto.handoff_count(),
            0,
            "a shallow peer must not be queued behind another peer's work"
        );
        assert!(lane.is_idle());
        drop(other_peer_batch);
        workers.stop().await;
    }

    /// Completed crypto waiting for ordered output must not keep another run on a worker.
    #[tokio::test]
    async fn adaptive_dispatch_ignores_backlog_after_crypto_completes() {
        let lane = Arc::new(OrderedCompletions::<()>::default());
        let first_slot = lane
            .reserve_run(super::PARALLEL_DISPATCH_HIGH_WATER)
            .expect("the first run fits the peer's window");
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let release_rx = Arc::new(tokio::sync::Mutex::new(Some(release_rx)));
        let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
        let first_lane = Arc::clone(&lane);
        let first_release_rx = Arc::clone(&release_rx);
        let first_completion = tokio::spawn(async move {
            first_lane
                .complete_run(
                    first_slot,
                    vec![Some(()); super::PARALLEL_DISPATCH_HIGH_WATER],
                    move |_| {
                        let release_rx = Arc::clone(&first_release_rx);
                        let started_tx = started_tx.clone();
                        async move {
                            started_tx
                                .send(())
                                .expect("the test is waiting for ordered delivery");
                            let release_rx = release_rx
                                .lock()
                                .await
                                .take()
                                .expect("the ordered release receiver is taken once");
                            release_rx.await.expect("the test releases ordered output");
                            Ok::<_, ()>(())
                        }
                    },
                )
                .await
        });
        started_rx
            .recv()
            .await
            .expect("the first result reached ordered output");

        let next_slot = lane
            .reserve_run(MIN_PARALLEL_RUN_SIZE)
            .expect("the next run fits behind completed output");
        assert!(!lane.should_force_worker(MIN_PARALLEL_RUN_SIZE));

        release_tx
            .send(())
            .expect("ordered output is still waiting");
        first_completion
            .await
            .expect("the first completion task succeeds")
            .expect("the first delivery succeeds");
        lane.complete_run(
            next_slot,
            vec![Some(()); MIN_PARALLEL_RUN_SIZE],
            |_| async { Ok::<_, ()>(()) },
        )
        .await
        .expect("the next delivery succeeds");
        assert!(lane.is_idle());
    }

    /// A completed run waiting for the delivery lock must not count as unfinished AEAD work.
    #[tokio::test]
    async fn adaptive_dispatch_ignores_completed_crypto_waiting_for_delivery_lock() {
        let lane = Arc::new(OrderedCompletions::<()>::default());
        let first_slot = lane
            .reserve_run(super::PARALLEL_DISPATCH_HIGH_WATER)
            .expect("the first run fits the peer's window");
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let release_rx = Arc::new(tokio::sync::Mutex::new(Some(release_rx)));
        let (delivering_tx, mut delivering_rx) = tokio::sync::mpsc::unbounded_channel();
        let first_lane = Arc::clone(&lane);
        let first_release_rx = Arc::clone(&release_rx);
        let first_completion = tokio::spawn(async move {
            first_lane
                .complete_run(
                    first_slot,
                    vec![Some(()); super::PARALLEL_DISPATCH_HIGH_WATER],
                    move |_| {
                        let release_rx = Arc::clone(&first_release_rx);
                        let delivering_tx = delivering_tx.clone();
                        async move {
                            delivering_tx
                                .send(())
                                .expect("the test is waiting for ordered delivery");
                            let release_rx = release_rx
                                .lock()
                                .await
                                .take()
                                .expect("the earlier ordered send waits once");
                            release_rx
                                .await
                                .expect("the test releases the earlier ordered send");
                            Ok::<_, ()>(())
                        }
                    },
                )
                .await
        });
        delivering_rx
            .recv()
            .await
            .expect("the earlier run reached ordered output");

        let completed_slot = lane
            .reserve_run(super::PARALLEL_DISPATCH_HIGH_WATER)
            .expect("the next run fits behind the earlier ordered send");
        let (waiting_tx, mut waiting_rx) = tokio::sync::mpsc::unbounded_channel();
        let completed_lane = Arc::clone(&lane);
        let completed_run = tokio::spawn(async move {
            let mut completion = Box::pin(completed_lane.complete_run(
                completed_slot,
                vec![Some(()); super::PARALLEL_DISPATCH_HIGH_WATER],
                |_| async { Ok::<_, ()>(()) },
            ));
            assert!(futures::poll!(&mut completion).is_pending());
            waiting_tx
                .send(())
                .expect("the test is waiting for the blocked completion");
            completion.await
        });
        waiting_rx
            .recv()
            .await
            .expect("the completed run is waiting for ordered delivery");

        let next_slot = lane
            .reserve_run(MIN_PARALLEL_RUN_SIZE)
            .expect("the next dispatch decision fits the peer's window");
        assert!(
            !lane.should_force_worker(MIN_PARALLEL_RUN_SIZE),
            "delivery-lock wait must not look like outstanding AEAD work"
        );

        release_tx
            .send(())
            .expect("the earlier ordered send is still waiting");
        first_completion
            .await
            .expect("the earlier completion task succeeds")
            .expect("the earlier delivery succeeds");
        completed_run
            .await
            .expect("the later completion task succeeds")
            .expect("the later delivery succeeds");
        lane.complete_run(
            next_slot,
            vec![Some(()); MIN_PARALLEL_RUN_SIZE],
            |_| async { Ok::<_, ()>(()) },
        )
        .await
        .expect("the next ordered delivery succeeds");
        assert!(lane.is_idle());
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

    /// A lone full worker-sized run stays on the caller when no other run is ready.
    #[tokio::test]
    async fn a_lone_encryption_run_uses_the_serial_fast_path() {
        let (mut sender, _) = established_tunnels();
        let packet_count = super::CRYPTO_WORKER_BATCH_SIZE;
        let packets = prepared_encryptions(&mut sender, packet_count);
        let workers = CryptoWorkers::with_worker_count(2).expect("the worker pool starts");
        let crypto = workers.handle();
        let lane = OrderedCompletions::<WgKind>::default();
        let first_slot = lane
            .reserve_run(packet_count)
            .expect("the lone run fits the peer's ordered window");
        let run = packets
            .into_iter()
            .map(|packet| Some(PreparedOutgoing::Encrypt(packet)))
            .collect();
        let force_worker = lane.should_force_worker(packet_count);

        let results = crypto
            .encrypt_run(run, force_worker)
            .await
            .expect("the serial fast path returns the packet");
        lane.complete_run(first_slot, results, |results| async move {
            black_box(results);
            Ok::<_, ()>(())
        })
        .await
        .expect("the ordered lane releases the lone run");

        assert_eq!(crypto.handoff_count(), 0);
        assert!(lane.is_idle());
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

    /// Print packets per second and nearest-rank p99 for one measured path.
    fn report_measurement(label: &str, elapsed: Duration, samples: &mut [Duration]) {
        let packets_per_second = samples.len() as f64 / elapsed.as_secs_f64();
        let p99_us = p99_duration(samples).as_secs_f64() * 1_000_000.0;
        println!("{label}: packets/s={packets_per_second:.0} p99_us={p99_us:.3}");
    }

    /// Measure raw serial AEAD, then the ordered stage at one, two, and four workers.
    ///
    /// Build this test in release mode on compute01, then run its binary on the pinned performance
    /// host with the shared benchmark lock and `taskset`. Set `GOTATUN_PROFILE_WORKERS` to run one
    /// worker count at a time so its affinity can match the pool size. Packet preparation is outside
    /// the timed interval. The ordered-stage profile places eight inner IP flows on each of two
    /// peers, and schedules their contiguous reads only when each run fits in that peer's 128-slot
    /// window. A full peer stream does not occupy the shared worker window. Its latency runs from
    /// read readiness through in-order release, including worker queueing and the bounded batch.
    /// The loaded stage keeps twice as many bounded reads ready as workers so dispatch observes
    /// real per-peer backlog; compare worker counts with the one-worker stage row, not the raw
    /// per-packet AEAD row, because those rows time different work units.
    #[test]
    #[ignore = "manual crypto-stage measurement on the pinned performance VM"]
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
            report_measurement(
                "serial AEAD encrypt per packet",
                serial_elapsed,
                &mut serial_latencies,
            );

            for worker_count in profile_worker_counts() {
                let (mut sender, _) = established_tunnels();
                let packets = prepared_encryptions(&mut sender, PROFILE_SPARSE_PACKET_COUNT);
                let (elapsed, mut latencies) =
                    measure_sparse_encryptions(packets, worker_count).await;
                report_measurement(
                    &format!("sparse ordered encrypt workers={worker_count}"),
                    elapsed,
                    &mut latencies,
                );
            }

            for worker_count in profile_worker_counts() {
                let encryptions = prepared_encryption_peers();
                let (elapsed, mut latencies) =
                    measure_parallel_encryptions(encryptions, worker_count).await;
                report_measurement(
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
            report_measurement(
                "serial AEAD decrypt per packet",
                serial_elapsed,
                &mut serial_latencies,
            );

            for worker_count in profile_worker_counts() {
                let (mut sender, mut receiver) = established_tunnels();
                let decryptions = prepared_decryptions(
                    &mut sender,
                    &mut receiver,
                    PROFILE_SPARSE_PACKET_COUNT,
                );
                let (elapsed, mut latencies) =
                    measure_sparse_decryptions(decryptions, worker_count).await;
                report_measurement(
                    &format!("sparse ordered decrypt workers={worker_count}"),
                    elapsed,
                    &mut latencies,
                );
            }

            for worker_count in profile_worker_counts() {
                let decryptions = prepared_decryption_peers();
                let (elapsed, mut latencies) =
                    measure_parallel_decryptions(decryptions, worker_count).await;
                report_measurement(
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
        let peer_count = peers.len();
        let lanes = (0..peer_count)
            .map(|_| Arc::new(OrderedCompletions::<WgKind>::default()))
            .collect::<Vec<_>>();
        let mut latencies = Vec::with_capacity(PROFILE_PACKET_COUNT);
        let started = Instant::now();
        let completed = run_profile_peer_window(
            peers,
            worker_count.saturating_mul(PROFILE_READY_RUNS_PER_WORKER),
            |read| {
                let read_started = read.ready_at;
                let peer_index = read.peer_index;
                let batch_len = read.packets.len();
                let batch = read
                    .packets
                    .into_iter()
                    .map(|packet| Some(PreparedOutgoing::Encrypt(packet)))
                    .collect::<Vec<_>>();
                let lane = Arc::clone(&lanes[peer_index]);
                let first_slot = lane
                    .reserve_run(batch_len)
                    .expect("ready peer runs fit the in-flight window");
                let force_worker = lane.should_force_worker(batch_len);
                let crypto = crypto.clone();
                async move {
                    let results = crypto
                        .encrypt_run(batch, force_worker)
                        .await
                        .expect("the worker queue remains open");
                    lane.complete_run(first_slot, results, |results| async move {
                        black_box(results);
                        Ok::<_, ()>(())
                    })
                    .await
                    .expect("ordered delivery succeeds");
                    lane.wait_delivered(first_slot + batch_len as u64 - 1).await;
                    (batch_len, read_started.elapsed())
                }
            },
        )
        .await;
        for (batch_len, latency) in completed {
            latencies.resize(latencies.len() + batch_len, latency);
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
        let peer_count = peers.len();
        let lanes = (0..peer_count)
            .map(|_| Arc::new(OrderedCompletions::<IncomingCompletion>::default()))
            .collect::<Vec<_>>();
        let mut latencies = Vec::with_capacity(PROFILE_PACKET_COUNT);
        let started = Instant::now();
        let addr = "127.0.0.1:51820"
            .parse()
            .expect("the profile peer address is valid");
        let completed = run_profile_peer_window(
            peers,
            worker_count.saturating_mul(PROFILE_READY_RUNS_PER_WORKER),
            |read| {
                let read_started = read.ready_at;
                let peer_index = read.peer_index;
                let batch_len = read.packets.len();
                let batch = read
                    .packets
                    .into_iter()
                    .map(|packet| (packet, addr))
                    .collect::<Vec<_>>();
                let lane = Arc::clone(&lanes[peer_index]);
                let first_slot = lane
                    .reserve_run(batch_len)
                    .expect("ready peer runs fit the in-flight window");
                let force_worker = lane.should_force_worker(batch_len);
                let crypto = crypto.clone();
                async move {
                    let completions = crypto
                        .decrypt_run(batch, force_worker)
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
                    lane.wait_delivered(first_slot + batch_len as u64 - 1).await;
                    (batch_len, read_started.elapsed())
                }
            },
        )
        .await;
        for (batch_len, latency) in completed {
            latencies.resize(latencies.len() + batch_len, latency);
        }

        let elapsed = started.elapsed();
        assert!(lanes.iter().all(|lane| lane.is_idle()));
        drop(crypto);
        workers.stop().await;
        (elapsed, latencies)
    }
}
