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

//! Generic buffered IP send and receive implementations.

use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};

use crate::{
    packet::{Ip, Packet, PacketBufPool},
    task::Task,
    tun::{IpRecv, IpSend, MtuWatcher},
};
use tokio::{
    sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc},
    time::timeout,
};
use tokio_util::sync::CancellationToken;
use zerocopy::IntoBytes;

/// Limit the number of TUN packets handed to the serial encryption task in one receive batch.
const ENCRYPTION_BATCH_LIMIT: usize = 64;

/// Flow buckets used to decide whether a queued packet can use the sparse lane.
const FLOW_BUCKETS: usize = 1024;

/// The sparse lane stays bounded; when full, an idle packet falls back to the FIFO bulk lane.
const SPARSE_LANE: usize = 256;

/// A queued packet retains the flow bucket whose outstanding count protects its order.
type Queued = (u16, Packet<Ip>);

/// Create a pair of [`BufferedIpSend`] and [`BufferedIpRecv`] with `capacity`.
///
/// This takes an `Arc<Mutex<S>>` and `Arc<Mutex<R>>` because the inner `S` and `R` will be re-used
/// after [BufferedIpSend] or [BufferedIpRecv] is dropped. We will take the mutex lock when this
/// function is called, and hold onto it for the lifetime of the sender or receiver.
///
/// # Panics
/// Panics if one of the locks is already taken.
pub async fn channel<S: IpSend, R: IpRecv>(
    capacity: usize,
    pool: PacketBufPool,
    send: Arc<Mutex<S>>,
    recv: Arc<Mutex<R>>,
) -> (BufferedIpSend, BufferedIpRecv<R>) {
    let token = CancellationToken::new();
    let buffer_send = BufferedIpSend::new(capacity, send, token.clone());
    let buffer_recv = BufferedIpRecv::new(capacity, pool, recv, token).await;
    (buffer_send, buffer_recv)
}

/// An [`IpSend`] that wraps another [`IpSend`] to provide buffering.
///
/// Packets sent on this [`IpSend::send`] will be buffered on a channel, and asynchronously
/// processed on another task. This means [`IpSend::send`] won't block unless the channel is full.
#[derive(Clone)]
pub struct BufferedIpSend {
    tx: mpsc::Sender<BufferedIpMessage>,
    packet_slots: Arc<Semaphore>,
    packet_capacity: usize,
    _task: Arc<Task>,
}

/// A single packet or a run passed through the buffered TUN boundary.
enum BufferedIpMessage {
    Single(Packet<Ip>, OwnedSemaphorePermit),
    Batch(Vec<Packet<Ip>>, OwnedSemaphorePermit),
}

impl BufferedIpSend {
    /// Create a [`BufferedIpSend`] with `capacity`.
    ///
    /// This takes an `Arc<Mutex<I>>` because the inner `I` will be re-used after [Self] is
    /// dropped. We will take the mutex lock when this function is called, and hold onto it for the
    /// lifetime of [Self].
    ///
    /// # Panics
    /// Panics if the lock is already taken.
    fn new<I: IpSend>(capacity: usize, inner: Arc<Mutex<I>>, token: CancellationToken) -> Self {
        let (tx, mut rx) = mpsc::channel::<BufferedIpMessage>(capacity);
        let packet_slots = Arc::new(Semaphore::new(capacity));

        let drop_guard = token.clone().drop_guard();

        let task = async move {
            let mut inner = timeout(Duration::from_secs(5), inner.lock())
                .await
                .expect("Deadlock on IpSend. There must be no more than one IpSend active at any given time.");

            let mut refused: u64 = 0;
            while let Some(message) = rx.recv().await {
                let result = match message {
                    BufferedIpMessage::Single(packet, _permit) => inner.send(packet).await,
                    BufferedIpMessage::Batch(mut packets, _permit) => {
                        let batch_len = packets.len();
                        match inner.send_many(&mut packets).await {
                            Ok(()) => continue,
                            Err(error) => {
                                refused = refused.saturating_add(batch_len as u64);
                                Err(error)
                            }
                        }
                    }
                };

                if let Err(e) = result {
                    if is_fatal_tun_error(&e) {
                        tracing::error!("TUN device was deleted: {e}");
                        break;
                    }
                    // The next packet may be accepted after a device refusal.
                    refused += 1;
                    if refused.is_power_of_two() {
                        tracing::warn!(
                            "Dropped IP packet the TUN device refused ({refused} so far): {e}"
                        );
                    }
                }
            }

            drop(drop_guard);
        };

        let task = Task::spawn("buffered IP send", async move {
            token.run_until_cancelled_owned(task).await;
        });

        Self {
            tx,
            packet_slots,
            packet_capacity: capacity,
            _task: Arc::new(task),
        }
    }
}

impl IpSend for BufferedIpSend {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        let permit = Arc::clone(&self.packet_slots)
            .acquire_owned()
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))?;
        self.tx
            .send(BufferedIpMessage::Single(packet, permit))
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))?;
        Ok(())
    }

    async fn send_many(&mut self, packets: &mut Vec<Packet<Ip>>) -> io::Result<()> {
        while !packets.is_empty() {
            let count = packets.len().min(self.packet_capacity);
            let permit_count = u32::try_from(count).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("TUN batch is too large: {e}"),
                )
            })?;
            let permit = Arc::clone(&self.packet_slots)
                .acquire_many_owned(permit_count)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))?;
            let batch = if count == packets.len() {
                std::mem::take(packets)
            } else {
                packets.drain(..count).collect()
            };
            if let Err(error) = self.tx.send(BufferedIpMessage::Batch(batch, permit)).await {
                let mut unsent = match error.0 {
                    BufferedIpMessage::Batch(batch, _) => batch,
                    BufferedIpMessage::Single(..) => unreachable!("send_many queues a batch"),
                };
                unsent.append(packets);
                *packets = unsent;
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "TUN send task stopped",
                ));
            }
        }
        Ok(())
    }
}

/// An [`IpRecv`] that wraps another [`IpRecv`] to provide buffering.
///
/// This will spawn a background task that continuously calls [`IpRecv::recv`] until the buffer is
/// full. Any call to [`IpRecv::recv`] on _this_ object will not block unless the lanes are empty.
/// Each returned batch is bounded so the encryption task cannot hold a deep TUN backlog at once.
///
/// A packet whose flow has no queued work may pass packets from other flows through the sparse
/// lane. Its flow count is raised before enqueue and stays raised while packets wait in either
/// lane or in the consumer's spill buffer. Before returning a bulk batch, the consumer drains
/// earlier sparse packets in front of it. This closes the race where the producer fills the
/// sparse lane after the consumer's initial lane check but before it takes bulk work.
///
/// The consumer lowers counts only after assembling a complete returned batch, then handles that
/// batch before asking for another. Packets from one flow therefore keep FIFO order even when
/// sparse packets pass other flows. A sparse backlog can take several bounded batches to drain;
/// while it does, older bulk spill stays pending so a bulk successor cannot overtake its sparse
/// head. Every returned batch remains within `ENCRYPTION_BATCH_LIMIT`.
pub struct BufferedIpRecv<I> {
    lanes: LaneReceiver,
    _task: Arc<Task>,
    _phantom: std::marker::PhantomData<I>,
    mtu: MtuWatcher,
}

/// The producer side of [`BufferedIpRecv`]'s sparse and bulk lanes.
struct Lanes {
    sparse_tx: mpsc::Sender<Queued>,
    tx: mpsc::Sender<Queued>,
    flows: Arc<FlowCounts>,
}

/// The consumer side of [`BufferedIpRecv`]'s lanes. `spill` holds bounded bulk work not returned
/// with an earlier sparse batch.
struct LaneReceiver {
    sparse_rx: mpsc::Receiver<Queued>,
    rx: mpsc::Receiver<Queued>,
    flows: Arc<FlowCounts>,
    batch: Vec<Queued>,
    spill: Vec<Queued>,
}

/// Queued packet counts per flow bucket, shared by the producer and consumer tasks.
struct FlowCounts([AtomicU32; FLOW_BUCKETS]);

impl FlowCounts {
    /// Create an empty set of flow-bucket counts.
    fn new() -> Self {
        Self(std::array::from_fn(|_| AtomicU32::new(0)))
    }

    /// Count one queued packet and report whether `bucket` was empty before it arrived.
    fn enqueue(&self, bucket: u16) -> bool {
        self.0[usize::from(bucket)].fetch_add(1, Ordering::AcqRel) == 0
    }

    /// Remove one packet from the count held for `bucket`.
    fn dequeue(&self, bucket: u16) {
        self.0[usize::from(bucket)].fetch_sub(1, Ordering::AcqRel);
    }
}

/// Compute an order-preserving flow bucket from IP addresses, protocol and transport ports.
///
/// IPv4 fragments omit ports from the hash so every fragment of a datagram uses one bucket.
/// IPv6 extension headers are not walked; those packets use addresses and the first next-header
/// value, which can merge buckets but cannot split one flow across them.
fn flow_bucket(packet: &[u8]) -> u16 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut mix = |bytes: &[u8]| {
        for &byte in bytes {
            hash = (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3);
        }
    };
    match packet.first().map(|byte| byte >> 4) {
        Some(4) if packet.len() >= 20 => {
            let header_len = usize::from(packet[0] & 0x0f) * 4;
            let protocol = packet[9];
            mix(&packet[12..20]);
            mix(&[protocol]);
            let is_fragment = u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff != 0;
            if !is_fragment
                && matches!(protocol, 6 | 17)
                && let Some(ports) = packet.get(header_len..header_len + 4)
            {
                mix(ports);
            }
        }
        Some(6) if packet.len() >= 40 => {
            let next_header = packet[6];
            mix(&packet[8..40]);
            mix(&[next_header]);
            if matches!(next_header, 6 | 17) {
                mix(&packet[40..packet.len().min(44)]);
            }
        }
        _ => mix(packet.get(..1).unwrap_or_default()),
    }
    // FLOW_BUCKETS is a power of two that fits in u16.
    (hash as usize % FLOW_BUCKETS) as u16
}

/// Create the producer and consumer halves of two bounded packet lanes.
fn lanes(capacity: usize) -> (Lanes, LaneReceiver) {
    let (tx, rx) = mpsc::channel::<Queued>(capacity);
    let (sparse_tx, sparse_rx) = mpsc::channel::<Queued>(SPARSE_LANE);
    let flows = Arc::new(FlowCounts::new());
    let receiver = LaneReceiver {
        sparse_rx,
        rx,
        flows: Arc::clone(&flows),
        batch: Vec::new(),
        spill: Vec::new(),
    };
    (
        Lanes {
            sparse_tx,
            tx,
            flows,
        },
        receiver,
    )
}

impl Lanes {
    /// Put a packet in the sparse lane when no earlier packet from its flow is pending.
    async fn queue(&self, packet: Packet<Ip>) -> bool {
        let bucket = flow_bucket(packet.as_bytes());
        let queued = if self.flows.enqueue(bucket) {
            match self.sparse_tx.try_send((bucket, packet)) {
                Ok(()) => return true,
                // No packet from this flow is queued, so using the bulk lane is order-safe.
                Err(mpsc::error::TrySendError::Full(queued)) => queued,
                Err(mpsc::error::TrySendError::Closed(_)) => return false,
            }
        } else {
            (bucket, packet)
        };
        self.tx.send(queued).await.is_ok()
    }
}

impl LaneReceiver {
    /// Assemble one bounded batch, placing already queued sparse packets before bulk work.
    async fn take(&mut self) -> usize {
        enum Lane {
            Sparse(Option<Queued>),
            Bulk,
            ExistingSpill,
        }

        self.batch.clear();
        let max_n = self.rx.max_capacity().min(ENCRYPTION_BATCH_LIMIT);
        let lane = if self.spill.is_empty() {
            let LaneReceiver {
                sparse_rx,
                rx,
                spill,
                ..
            } = self;
            tokio::select! {
                biased;
                queued = sparse_rx.recv() => Lane::Sparse(queued),
                _ = rx.recv_many(spill, max_n) => Lane::Bulk,
            }
        } else {
            Lane::ExistingSpill
        };

        match lane {
            Lane::Sparse(Some(queued)) => {
                self.batch.push(queued);
                let bulk_limit = ENCRYPTION_BATCH_LIMIT - self.batch.len();
                while self.spill.len() < bulk_limit {
                    match self.rx.try_recv() {
                        Ok(queued) => self.spill.push(queued),
                        Err(_) => break,
                    }
                }
            }
            Lane::Sparse(None) => {
                self.rx.recv_many(&mut self.spill, max_n).await;
            }
            Lane::Bulk | Lane::ExistingSpill => {}
        }

        // Do not read more bulk packets after this drain. A sparse head and its bulk successor
        // can be queued while a batch is assembled, so the drain must be the final lane check.
        self.drain_sparse_into_batch(ENCRYPTION_BATCH_LIMIT);

        let bulk_capacity = ENCRYPTION_BATCH_LIMIT - self.batch.len();
        let from_spill = bulk_capacity.min(self.spill.len());
        self.batch.extend(self.spill.drain(..from_spill));

        for (bucket, _) in &self.batch {
            self.flows.dequeue(*bucket);
        }
        self.batch.len()
    }

    /// Add sparse packets up to `limit`, keeping the returned batch within its encryption cap.
    fn drain_sparse_into_batch(&mut self, limit: usize) {
        while self.batch.len() < limit {
            match self.sparse_rx.try_recv() {
                Ok(queued) => self.batch.push(queued),
                Err(_) => break,
            }
        }
    }
}

impl<I: IpRecv> BufferedIpRecv<I> {
    /// Create a new [`BufferedIpRecv`] with `capacity`.
    ///
    /// This takes an `Arc<Mutex<I>>` because the inner `I` will be re-used after [Self] is
    /// dropped. We will take the mutex lock when this function is called, and hold onto it for the
    /// lifetime of [Self]. Will panic if the lock is already taken.
    async fn new(
        capacity: usize,
        mut pool: PacketBufPool,
        inner: Arc<Mutex<I>>,
        token: CancellationToken,
    ) -> Self {
        let (queue, lanes) = lanes(capacity);

        // We use a timeout instead of a try_lock().expect() because there may still be an old
        // BufferedIpRecv that is in the process of being dropped. Otherwise, there would be a
        // race condition between the old `task` dropping, and us taking the lock again.
        let mut inner = timeout(Duration::from_secs(5), inner.lock_owned())
            .await
            .expect("Deadlock on IpRecv. There must be no more than one IpRecv active at any given time.");

        let mtu = inner.mtu();

        let drop_guard = token.clone().drop_guard();

        let task = async move {
            let mut dropped: u64 = 0;
            loop {
                match inner.recv(&mut pool).await {
                    Ok(packets) => {
                        for packet in packets {
                            if !queue.queue(packet).await {
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        if is_fatal_tun_error(&e) {
                            tracing::error!("TUN device was deleted: {e}");
                            break;
                        }
                        // One frame we could not decode: drop it and read the next. Yield so
                        // a device that keeps failing cannot spin this worker.
                        dropped += 1;
                        if dropped.is_power_of_two() {
                            tracing::warn!("Dropped undecodable IP packet ({dropped} so far): {e}");
                        }
                        tokio::task::yield_now().await;
                    }
                }
            }
            drop(drop_guard);
        };
        let task = Task::spawn("buffered IP recv", async move {
            token.run_until_cancelled_owned(task).await;
        });

        Self {
            lanes,
            _task: Arc::new(task),
            _phantom: std::marker::PhantomData,
            mtu,
        }
    }
}

impl<I: IpRecv> IpRecv for BufferedIpRecv<I> {
    /// Return the next capped batch from the sparse/bulk scheduler.
    async fn recv<'a>(
        &'a mut self,
        _pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + 'a> {
        if self.lanes.take().await == 0 {
            // Channel is closed
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "channel closed",
            ));
        }
        Ok(self.lanes.batch.drain(..).map(|(_, packet)| packet))
    }

    fn mtu(&self) -> MtuWatcher {
        self.mtu.clone()
    }
}

/// Checks if an I/O error indicates the TUN device has been deleted or is unusable.
///
/// Only a gone device counts. `InvalidData` and `InvalidInput` describe one frame (a malformed
/// header we refuse to decode, a packet the device refuses to take) and are not fatal: anything
/// on the host able to send a raw packet could otherwise stop a whole direction of traffic
/// with one bad frame (#260).
fn is_fatal_tun_error(err: &io::Error) -> bool {
    #[cfg(target_os = "linux")]
    if matches!(
        err.raw_os_error(),
        Some(libc::EBADF) | Some(libc::EBADFD) | Some(libc::ENODEV)
    ) {
        return true;
    }

    #[cfg(windows)]
    {
        const ERROR_HANDLE_EOF: i32 = windows_sys::Win32::Foundation::ERROR_HANDLE_EOF as i32;

        if err.raw_os_error() == Some(ERROR_HANDLE_EOF) {
            return true;
        }

        // TODO: Propagate the underlying error from tun/wintun-bindings and remove this
        #[cfg(feature = "tun")]
        if let Some(ERROR_HANDLE_EOF) = err
            .get_ref()
            .and_then(|e| e.downcast_ref::<wintun_bindings::Error>())
            .and_then(|e| match e {
                wintun_bindings::Error::Io(io_err) => io_err.raw_os_error(),
                _ => None,
            })
        {
            return true;
        }
    }

    matches!(
        err.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::UnexpectedEof | io::ErrorKind::BrokenPipe
    )
}

#[cfg(test)]
mod tests {
    use super::{BufferedIpRecv, BufferedIpSend};
    use crate::{
        packet::{Ip, Packet, PacketBufPool},
        tun::{IpRecv, IpSend, MtuWatcher},
    };
    use bytes::BytesMut;
    use std::{collections::VecDeque, io, sync::Arc, time::Duration};
    use tokio::sync::{Mutex, mpsc};
    use tokio_util::sync::CancellationToken;
    use zerocopy::IntoBytes;

    /// Hands out scripted receive results, then waits forever.
    struct Script(VecDeque<io::Result<Vec<Packet<Ip>>>>);

    impl IpRecv for Script {
        async fn recv<'a>(
            &'a mut self,
            _pool: &mut PacketBufPool,
        ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
            match self.0.pop_front() {
                Some(result) => result.map(Vec::into_iter),
                None => std::future::pending().await,
            }
        }

        fn mtu(&self) -> MtuWatcher {
            MtuWatcher::new(1420)
        }
    }

    /// An IP packet of `len` bytes, identified by `id` in bytes 4..6 (the IPv4 identification).
    fn packet(len: usize, id: u16) -> Packet<Ip> {
        let mut bytes = BytesMut::zeroed(len);
        bytes[0] = 0x45;
        bytes[4..6].copy_from_slice(&id.to_be_bytes());
        Packet::from_bytes(bytes).try_into_ip().unwrap()
    }

    /// An IPv4 packet of protocol `protocol` from source port `port`, carrying `sequence` in its
    /// identification field so the scheduler tests can inspect per-flow order.
    fn flow_packet(protocol: u8, port: u16, sequence: u16) -> Packet<Ip> {
        let mut bytes = BytesMut::zeroed(60);
        bytes[0] = 0x45;
        bytes[4..6].copy_from_slice(&sequence.to_be_bytes());
        bytes[9] = protocol;
        bytes[12..16].copy_from_slice(&[10, 0, 0, 1]);
        bytes[16..20].copy_from_slice(&[10, 0, 0, 2]);
        bytes[20..22].copy_from_slice(&port.to_be_bytes());
        bytes[22..24].copy_from_slice(&5201u16.to_be_bytes());
        Packet::from_bytes(bytes).try_into_ip().unwrap()
    }

    /// Read protocol, source port and synthetic sequence from a test packet.
    fn flow_key_and_sequence(packet: &Packet<Ip>) -> (u8, u16, u16) {
        let bytes = packet.as_bytes();
        (
            bytes[9],
            u16::from_be_bytes([bytes[20], bytes[21]]),
            u16::from_be_bytes([bytes[4], bytes[5]]),
        )
    }

    /// Records each packet that crosses the buffered send boundary.
    struct RecordingIpSend(mpsc::UnboundedSender<u16>);

    impl IpSend for RecordingIpSend {
        async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
            let bytes = packet.as_bytes();
            self.0
                .send(u16::from_be_bytes([bytes[4], bytes[5]]))
                .expect("the test receiver remains open");
            Ok(())
        }

        async fn send_many(&mut self, packets: &mut Vec<Packet<Ip>>) -> io::Result<()> {
            for packet in packets.drain(..) {
                self.send(packet).await?;
            }
            Ok(())
        }
    }

    /// Make a buffered receiver with a chosen capacity for deterministic batch tests.
    async fn scripted_recv_with_capacity(
        capacity: usize,
        script: Vec<io::Result<Vec<Packet<Ip>>>>,
    ) -> BufferedIpRecv<Script> {
        let inner = Arc::new(Mutex::new(Script(VecDeque::from(script))));
        BufferedIpRecv::new(
            capacity,
            PacketBufPool::new(1),
            inner,
            CancellationToken::new(),
        )
        .await
    }

    /// Use the usual small capacity for tests that do not inspect batching.
    async fn scripted_recv(script: Vec<io::Result<Vec<Packet<Ip>>>>) -> BufferedIpRecv<Script> {
        scripted_recv_with_capacity(64, script).await
    }

    /// One frame the TUN reader refuses (malformed headers) is dropped; the next frame still
    /// reaches encryption. Before #260 it was taken for a deleted device and stopped the whole
    /// outbound direction.
    #[tokio::test]
    async fn bad_frame_is_dropped_and_the_next_one_passes() {
        let mut recv = scripted_recv(vec![
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid IPv6 extension length",
            )),
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "bad virtio header",
            )),
            Ok(vec![packet(1400, 7)]),
        ])
        .await;
        let mut pool = PacketBufPool::new(1);

        let ids: Vec<u16> = tokio::time::timeout(Duration::from_secs(5), recv.recv(&mut pool))
            .await
            .expect("the valid frame must arrive")
            .expect("a bad frame must not stop the reader")
            .map(|p| {
                let bytes = p.as_bytes();
                u16::from_be_bytes([bytes[4], bytes[5]])
            })
            .collect();
        assert_eq!(ids, [7]);
    }

    /// A gone device still ends the reader, so the device can report it.
    #[tokio::test]
    async fn device_gone_still_stops_the_reader() {
        let mut recv = scripted_recv(vec![Err(io::Error::from_raw_os_error(libc::EBADF))]).await;
        let mut pool = PacketBufPool::new(1);

        let result = tokio::time::timeout(Duration::from_secs(5), recv.recv(&mut pool))
            .await
            .expect("the reader must stop promptly");
        assert_eq!(
            result.err().map(|e| e.kind()),
            Some(io::ErrorKind::UnexpectedEof)
        );
    }

    /// Keep each TUN batch handed to encryption within the configured packet cap.
    #[tokio::test]
    async fn encryption_batches_respect_the_configured_limit() {
        const BATCH_CAP: usize = super::ENCRYPTION_BATCH_LIMIT;
        const PACKETS: usize = BATCH_CAP * 2;

        let packets = (0..PACKETS)
            .map(|id| packet(64, id as u16))
            .collect::<Vec<_>>();
        let mut recv = scripted_recv_with_capacity(4000, vec![Ok(packets)]).await;
        let mut pool = PacketBufPool::new(1);
        tokio::time::timeout(Duration::from_secs(5), async {
            while recv.lanes.sparse_rx.len() + recv.lanes.rx.len() < PACKETS {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the full scripted batch must reach the queues before reading");

        let mut observed = 0;
        while observed < PACKETS {
            let batch = tokio::time::timeout(Duration::from_secs(5), recv.recv(&mut pool))
                .await
                .expect("queued packets must arrive")
                .expect("the reader must remain open")
                .collect::<Vec<_>>();
            assert!(!batch.is_empty(), "a queued packet must be returned");
            assert!(
                batch.len() <= BATCH_CAP,
                "an encrypt batch exceeded {BATCH_CAP} packets: {}",
                batch.len()
            );
            observed += batch.len();
        }
        assert_eq!(observed, PACKETS, "batching must not lose packets");
    }

    /// A packet on a new flow should pass a queued bulk backlog while the bulk flow keeps FIFO.
    #[tokio::test]
    async fn sparse_packet_overtakes_backlog_without_reordering_bulk_flow() {
        const BULK_PACKETS: u16 = 40;
        let mut packets = (0..BULK_PACKETS)
            .map(|sequence| flow_packet(6, 40000, sequence))
            .collect::<Vec<_>>();
        packets.push(flow_packet(1, 0, 0));

        let mut recv = scripted_recv_with_capacity(4000, vec![Ok(packets)]).await;
        let mut pool = PacketBufPool::new(1);
        tokio::time::timeout(Duration::from_secs(5), async {
            while recv.lanes.sparse_rx.len() + recv.lanes.rx.len() < usize::from(BULK_PACKETS) + 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the full scripted backlog must reach the queue before reading");

        let mut order = Vec::new();
        while order.len() < usize::from(BULK_PACKETS) + 1 {
            let batch = tokio::time::timeout(Duration::from_secs(5), recv.recv(&mut pool))
                .await
                .expect("queued packets must arrive")
                .expect("the reader must remain open");
            order.extend(batch.map(|packet| flow_key_and_sequence(&packet)));
        }

        let probe = order
            .iter()
            .position(|&(protocol, _, _)| protocol == 1)
            .expect("the sparse probe must be delivered");
        assert!(probe <= 1, "the probe waited behind {probe} packets");
        let bulk: Vec<u16> = order
            .iter()
            .filter(|&&(protocol, _, _)| protocol == 6)
            .map(|&(_, _, sequence)| sequence)
            .collect();
        assert_eq!(bulk, (0..BULK_PACKETS).collect::<Vec<_>>());
    }

    /// Older bulk spill must finish before newer packets leave the bulk channel.
    #[tokio::test]
    async fn older_bulk_spill_precedes_newer_bulk_packets() {
        const SPILL_PACKETS: u16 = 64;
        const NEW_BULK_PACKETS: u16 = 64;
        const SPARSE_PACKETS: u16 = 32;

        let (queue, mut receiver) = super::lanes(4000);
        let mut bulk_bucket = None;
        for sequence in 0..SPILL_PACKETS {
            let packet = flow_packet(17, 40000, sequence);
            let bucket = super::flow_bucket(packet.as_bytes());
            bulk_bucket = Some(bucket);
            assert_eq!(queue.flows.enqueue(bucket), sequence == 0);
            receiver.spill.push((bucket, packet));
        }
        let bulk_bucket = bulk_bucket.expect("the spill has one bulk flow");

        for sequence in SPILL_PACKETS..SPILL_PACKETS + NEW_BULK_PACKETS {
            let packet = flow_packet(17, 40000, sequence);
            let bucket = super::flow_bucket(packet.as_bytes());
            assert_eq!(bucket, bulk_bucket);
            assert!(!queue.flows.enqueue(bucket));
            assert!(queue.tx.send((bucket, packet)).await.is_ok());
        }

        for sequence in 0..SPARSE_PACKETS {
            let packet = flow_packet(1, 0, sequence);
            let bucket = super::flow_bucket(packet.as_bytes());
            assert_ne!(bucket, bulk_bucket);
            assert_eq!(queue.flows.enqueue(bucket), sequence == 0);
            assert!(queue.sparse_tx.send((bucket, packet)).await.is_ok());
        }

        assert_eq!(receiver.take().await, super::ENCRYPTION_BATCH_LIMIT);
        let bulk_sequences = receiver
            .batch
            .iter()
            .filter_map(|(_, packet)| {
                let (protocol, port, sequence) = flow_key_and_sequence(packet);
                (protocol == 17 && port == 40000).then_some(sequence)
            })
            .collect::<Vec<_>>();
        assert_eq!(bulk_sequences, (0..32).collect::<Vec<_>>());
    }

    /// A late sparse head must precede its bulk successor even beyond the scheduler's old quota.
    #[tokio::test]
    async fn sparse_heads_beyond_the_batch_quota_stay_ahead_of_bulk_successors() {
        const SPARSE_FLOWS: usize = 32;
        let (queue, mut receiver) = super::lanes(4000);
        let mut buckets = Vec::new();
        let mut port = 10000u16;
        while buckets.len() < SPARSE_FLOWS {
            let packet = flow_packet(6, port, 0);
            let bucket = super::flow_bucket(packet.as_bytes());
            if !buckets.contains(&bucket) {
                assert!(queue.queue(packet).await);
                buckets.push(bucket);
            }
            port += 1;
        }

        assert!(queue.queue(flow_packet(17, 50000, 0)).await);
        assert!(queue.queue(flow_packet(17, 50000, 1)).await);
        assert_eq!(receiver.sparse_rx.len(), SPARSE_FLOWS + 1);
        assert_eq!(receiver.rx.len(), 1);

        let count = receiver.take().await;
        assert!(count <= super::ENCRYPTION_BATCH_LIMIT);
        let flow_sequences = receiver
            .batch
            .iter()
            .filter_map(|(_, packet)| {
                let (protocol, port, sequence) = flow_key_and_sequence(packet);
                (protocol == 17 && port == 50000).then_some(sequence)
            })
            .collect::<Vec<_>>();
        assert_eq!(flow_sequences, [0, 1]);
    }

    /// Per-flow order holds when producer and consumer run on separate OS threads.
    #[test]
    fn per_flow_order_holds_across_threads() {
        const FLOWS: usize = 4;
        const PACKETS: u32 = 200_000;
        let (queue, mut receiver) = super::lanes(64);
        let producer = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let mut next = [0u16; FLOWS];
                let mut state = 0x9e37_79b9_u32;
                let mut sent = 0;
                while sent < PACKETS {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    let flow = state as usize % FLOWS;
                    for _ in 0..1 + (state >> 8) % 6 {
                        let packet = flow_packet(17, 30000 + flow as u16, next[flow]);
                        assert!(queue.queue(packet).await, "the consumer is gone");
                        next[flow] = next[flow].wrapping_add(1);
                        sent += 1;
                    }
                }
            });
        });

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let total = runtime.block_on(async {
            let mut seen = [0u16; FLOWS];
            let mut total = 0u32;
            loop {
                let count = tokio::time::timeout(Duration::from_secs(10), receiver.take())
                    .await
                    .expect("the lanes must keep delivering");
                if count == 0 {
                    break total;
                }
                let batch = receiver.batch.drain(..).collect::<Vec<_>>();
                for (_, packet) in &batch {
                    let (_, port, sequence) = flow_key_and_sequence(packet);
                    let flow = usize::from(port - 30000);
                    let batch_sequences = batch
                        .iter()
                        .filter_map(|(_, packet)| {
                            let (_, packet_port, packet_sequence) = flow_key_and_sequence(packet);
                            (usize::from(packet_port - 30000) == flow).then_some(packet_sequence)
                        })
                        .collect::<Vec<_>>();
                    let spill_sequences = receiver
                        .spill
                        .iter()
                        .filter_map(|(_, packet)| {
                            let (_, packet_port, packet_sequence) = flow_key_and_sequence(packet);
                            (usize::from(packet_port - 30000) == flow).then_some(packet_sequence)
                        })
                        .collect::<Vec<_>>();
                    assert_eq!(
                        sequence,
                        seen[flow],
                        "flow {flow} reordered after {total} packets; batch={batch_sequences:?}, \
                         spill={spill_sequences:?}, bulk_len={}, sparse_len={}",
                        receiver.rx.len(),
                        receiver.sparse_rx.len(),
                    );
                    seen[flow] = seen[flow].wrapping_add(1);
                    total += 1;
                }
            }
        });
        producer.join().unwrap();
        assert!(total >= PACKETS);
    }

    /// IPv4 fragments of one datagram use the same bucket even when later fragments lack ports.
    #[test]
    fn fragments_share_their_datagrams_bucket() {
        let first = flow_packet(17, 30000, 1);
        let mut later = BytesMut::from(first.as_bytes());
        later[6..8].copy_from_slice(&0x00b9u16.to_be_bytes()); // fragment offset only
        later[20..24].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // payload, not ports
        let mut first_bytes = BytesMut::from(first.as_bytes());
        first_bytes[6..8].copy_from_slice(&0x2000u16.to_be_bytes()); // more fragments
        assert_eq!(super::flow_bucket(&first_bytes), super::flow_bucket(&later));
    }

    /// A run larger than the buffer capacity is split without waiting for impossible permits.
    #[tokio::test]
    async fn send_many_splits_runs_larger_than_the_buffer_capacity() {
        let (sent_tx, mut sent_rx) = mpsc::unbounded_channel();
        let inner = Arc::new(Mutex::new(RecordingIpSend(sent_tx)));
        let token = CancellationToken::new();
        let mut send = BufferedIpSend::new(1, inner, token);
        let mut packets = vec![packet(64, 1), packet(64, 2), packet(64, 3)];

        tokio::time::timeout(Duration::from_secs(1), send.send_many(&mut packets))
            .await
            .expect("an oversized run must not wait for impossible capacity")
            .expect("the buffered send task must accept each chunk");
        assert!(packets.is_empty());

        for expected in [1, 2, 3] {
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), sent_rx.recv())
                    .await
                    .expect("the packet must cross the buffer")
                    .expect("the send task remains open"),
                expected
            );
        }
    }
}
