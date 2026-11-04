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
    sync::{Mutex, mpsc},
    time::timeout,
};
use tokio_util::sync::CancellationToken;
use zerocopy::IntoBytes;

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
    tx: mpsc::Sender<Packet<Ip>>,
    _task: Arc<Task>,
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
        let (tx, mut rx) = mpsc::channel::<Packet<Ip>>(capacity);

        let drop_guard = token.clone().drop_guard();

        let task = async move {
            let mut inner = timeout(Duration::from_secs(5), inner.lock())
                .await
                .expect("Deadlock on IpSend. There must be no more than one IpSend active at any given time.");

            let mut refused: u64 = 0;
            while let Some(packet) = rx.recv().await {
                if let Err(e) = inner.send(packet).await {
                    if is_fatal_tun_error(&e) {
                        tracing::error!("TUN device was deleted: {e}");
                        break;
                    }
                    // The device refused this one packet; the next one may be fine.
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
            _task: Arc::new(task),
        }
    }
}

impl IpSend for BufferedIpSend {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        self.tx
            .send(packet)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))?;
        Ok(())
    }
}

/// Flow buckets for [`BufferedIpRecv`]'s queued-packet counts. Two flows sharing a bucket are
/// only ever treated as one busier flow, which costs priority, never order.
const FLOW_BUCKETS: usize = 1024;

/// Slots in the sparse lane. When it is full, a sparse packet joins the bulk lane, which is
/// always order-safe (see [`BufferedIpRecv`]).
const SPARSE_LANE: usize = 256;

/// A packet queued in [`BufferedIpRecv`], with the flow bucket it was counted in.
type Queued = (u16, Packet<Ip>);

/// An [`IpRecv`] that wraps another [`IpRecv`] to provide buffering.
///
/// This will spawn a background task that continuously calls [`IpRecv::recv`] until the buffer is
/// full. Any call to [`IpRecv::recv`] on _this_ object will not block unless the buffer is empty.
///
/// # Sparse flows first
///
/// Under load the buffer holds a standing queue of bulk packets (#260 traces: hundreds deep, the
/// largest queue residence on the path). A packet of a flow that has nothing queued, such as an
/// interactive keystroke, an ICMP probe or a TCP ACK, would otherwise wait behind all of it. So
/// the buffer keeps a count of queued packets per flow bucket and has two lanes. A packet whose
/// bucket count is zero when it arrives goes to the sparse lane; every other packet goes to the
/// bulk lane. [`IpRecv::recv`] serves the sparse lane first.
///
/// **Per-flow order holds.** A count is raised before its packet is queued, and lowered only once
/// the consumer has taken the packet and everything it puts in the same batch. So a zero count
/// means no earlier packet of that flow is queued in either lane or sits in the batch being
/// assembled. A sparse packet can therefore only overtake other flows' packets. Every later
/// packet of its flow sees a non-zero count and queues behind it in the bulk lane, or arrives
/// after the consumer has taken it. The consumer handles each returned batch fully before it asks
/// for the next, so a packet taken in an earlier batch is always handled first. Order across
/// flows is not kept, as with any per-flow queueing. This happens before encryption, so the
/// session counters still go out in sequence.
///
/// The two lanes are separate channels, so the consumer cannot check both at one instant. It can
/// find the sparse lane empty, and then take a bulk batch that holds a packet the producer queued
/// after a sparse packet of the same flow. So after every bulk batch, the consumer drains the
/// sparse lane and puts those packets first ([`LaneReceiver::take`]). That is always safe: when a
/// sparse packet was queued, its flow had nothing counted, and the bulk batch's counts are still
/// held, so any packet of its flow in that batch was queued after it. #260's 1 h soak found the
/// reordering without this step (90,299 out-of-order segments at the receiver).
pub struct BufferedIpRecv<I> {
    lanes: LaneReceiver,
    _task: Arc<Task>,
    _phantom: std::marker::PhantomData<I>,
    mtu: MtuWatcher,
}

/// The producer side of [`BufferedIpRecv`]'s two lanes.
struct Lanes {
    sparse_tx: mpsc::Sender<Queued>,
    tx: mpsc::Sender<Queued>,
    flows: Arc<FlowCounts>,
}

/// The consumer side of [`BufferedIpRecv`]'s two lanes. `batch` holds the batch last taken.
struct LaneReceiver {
    sparse_rx: mpsc::Receiver<Queued>,
    rx: mpsc::Receiver<Queued>,
    flows: Arc<FlowCounts>,
    batch: Vec<Queued>,
    spill: Vec<Queued>,
}

/// Two lanes in front of one consumer; the bulk lane holds `capacity` packets.
fn lanes(capacity: usize) -> (Lanes, LaneReceiver) {
    let (tx, rx) = mpsc::channel::<Queued>(capacity);
    let (sparse_tx, sparse_rx) = mpsc::channel::<Queued>(SPARSE_LANE);
    let flows = Arc::new(FlowCounts::new());
    let receiver = LaneReceiver {
        sparse_rx,
        rx,
        flows: Arc::clone(&flows),
        batch: vec![],
        spill: vec![],
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
    /// Queue one packet in its lane. Returns `false` once the consumer is gone.
    async fn queue(&self, packet: Packet<Ip>) -> bool {
        let bucket = flow_bucket(packet.as_bytes());
        let queued = if self.flows.enqueue(bucket) {
            match self.sparse_tx.try_send((bucket, packet)) {
                Ok(()) => return true,
                // Nothing of this flow is queued, so the bulk lane is order-safe too.
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
    /// Take the next batch into `self.batch` and return its length; 0 once both lanes are closed
    /// and empty. A batch is whatever the sparse lane holds, or a bulk batch as before, with any
    /// sparse packets that arrived meanwhile in front (see [`BufferedIpRecv`]).
    async fn take(&mut self) -> usize {
        enum Lane {
            Sparse(Option<Queued>),
            Bulk(usize),
        }
        let max_n = self.rx.max_capacity();
        self.batch.clear();
        // Both receive futures are cancel-safe, so the losing branch loses nothing.
        let lane = tokio::select! {
            biased;
            queued = self.sparse_rx.recv() => Lane::Sparse(queued),
            n = self.rx.recv_many(&mut self.batch, max_n) => Lane::Bulk(n),
        };
        match lane {
            Lane::Sparse(Some(queued)) => {
                self.batch.push(queued);
                self.drain_sparse_into_batch();
            }
            // The producer is gone; the bulk lane may still hold packets.
            Lane::Sparse(None) => {
                self.rx.recv_many(&mut self.batch, max_n).await;
            }
            Lane::Bulk(_) => {
                // Sparse packets queued before this batch's packets of the same flow must go
                // first. The batch's counts are still held, so nothing queued from here on can
                // belong before it.
                std::mem::swap(&mut self.batch, &mut self.spill);
                self.drain_sparse_into_batch();
                self.batch.append(&mut self.spill);
            }
        }
        // Only now may later packets of these flows take the sparse lane.
        for (bucket, _) in &self.batch {
            self.flows.dequeue(*bucket);
        }
        self.batch.len()
    }

    /// Move up to [`SPARSE_LANE`] sparse packets to the end of `self.batch`. The lane holds at
    /// most that many at once, and it is FIFO, so every packet already queued when a bulk batch
    /// was taken is among them; the cap only stops a stream of new arrivals from holding up the
    /// batch.
    fn drain_sparse_into_batch(&mut self) {
        for _ in 0..SPARSE_LANE {
            let Ok(queued) = self.sparse_rx.try_recv() else {
                break;
            };
            self.batch.push(queued);
        }
    }
}

/// Queued packets per flow bucket, shared by the producer task and the consumer.
struct FlowCounts([AtomicU32; FLOW_BUCKETS]);

impl FlowCounts {
    fn new() -> Self {
        Self(std::array::from_fn(|_| AtomicU32::new(0)))
    }

    /// Count one more queued packet in `bucket`; returns whether the bucket was empty.
    fn enqueue(&self, bucket: u16) -> bool {
        self.0[usize::from(bucket)].fetch_add(1, Ordering::AcqRel) == 0
    }

    fn dequeue(&self, bucket: u16) {
        self.0[usize::from(bucket)].fetch_sub(1, Ordering::AcqRel);
    }
}

/// The flow bucket of an IP packet: addresses and protocol, plus ports for TCP and UDP. IPv4
/// fragments after the first carry no ports, so every fragment hashes without them, keeping a
/// fragmented datagram in one bucket. IPv6 extension headers are not walked: such packets hash
/// by addresses and next header only, which is coarser but still one bucket per flow.
fn flow_bucket(packet: &[u8]) -> u16 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut mix = |bytes: &[u8]| {
        for &byte in bytes {
            hash = (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3);
        }
    };
    match packet.first().map(|b| b >> 4) {
        Some(4) if packet.len() >= 20 => {
            let header_len = usize::from(packet[0] & 0x0f) * 4;
            let protocol = packet[9];
            mix(&packet[12..20]);
            mix(&[protocol]);
            // More-fragments flag or a fragment offset: leave the ports out.
            let fragment = u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff != 0;
            if !fragment
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
    /// The next batch from [`LaneReceiver::take`]. Its flow counts are already released; that is
    /// safe because the caller handles the whole batch before it calls again (see the type docs).
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
    use super::BufferedIpRecv;
    use crate::{
        packet::{Ip, Packet, PacketBufPool},
        tun::{IpRecv, MtuWatcher},
    };
    use bytes::BytesMut;
    use std::{collections::VecDeque, io, sync::Arc, time::Duration};
    use tokio::sync::Mutex;
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

    async fn scripted_recv(script: Vec<io::Result<Vec<Packet<Ip>>>>) -> BufferedIpRecv<Script> {
        let inner = Arc::new(Mutex::new(Script(VecDeque::from(script))));
        BufferedIpRecv::new(64, PacketBufPool::new(1), inner, CancellationToken::new()).await
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

    /// An IPv4 packet of protocol `proto` from source port `port`, carrying `seq` in its
    /// identification field.
    fn flow_packet(proto: u8, port: u16, seq: u16) -> Packet<Ip> {
        let mut bytes = BytesMut::zeroed(60);
        bytes[0] = 0x45;
        bytes[4..6].copy_from_slice(&seq.to_be_bytes());
        bytes[9] = proto;
        bytes[12..16].copy_from_slice(&[10, 0, 0, 1]);
        bytes[16..20].copy_from_slice(&[10, 0, 0, 2]);
        bytes[20..22].copy_from_slice(&port.to_be_bytes());
        bytes[22..24].copy_from_slice(&5201u16.to_be_bytes());
        Packet::from_bytes(bytes).try_into_ip().unwrap()
    }

    fn port_and_seq(packet: &Packet<Ip>) -> (u8, u16, u16) {
        let b = packet.as_bytes();
        (
            b[9],
            u16::from_be_bytes([b[20], b[21]]),
            u16::from_be_bytes([b[4], b[5]]),
        )
    }

    /// A probe from an idle flow is served before a bulk flow's backlog, and the bulk flow keeps
    /// its order across the two lanes (its first packet found its flow idle, too).
    #[tokio::test]
    async fn sparse_packet_overtakes_a_backlog_and_flows_keep_order() {
        let mut batch: Vec<Packet<Ip>> = (0..40).map(|seq| flow_packet(6, 40000, seq)).collect();
        batch.push(flow_packet(1, 0, 0));
        let mut recv = scripted_recv(vec![Ok(batch)]).await;
        let mut pool = PacketBufPool::new(1);
        // Let the producer queue the whole read before the consumer takes anything.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut order = vec![];
        while order.len() < 41 {
            let batch = tokio::time::timeout(Duration::from_secs(5), recv.recv(&mut pool))
                .await
                .expect("queued packets must arrive")
                .expect("the reader keeps running");
            order.extend(batch.map(|p| port_and_seq(&p)));
        }
        let probe = order.iter().position(|&(proto, ..)| proto == 1).unwrap();
        assert!(probe <= 1, "the probe waited behind the backlog: {probe}");
        let bulk: Vec<u16> = order
            .iter()
            .filter(|&&(proto, ..)| proto == 6)
            .map(|&(.., seq)| seq)
            .collect();
        assert_eq!(bulk, (0..40).collect::<Vec<_>>());
    }

    /// Per-flow order holds while the producer and the consumer interleave at many points: the
    /// 64-slot bulk lane blocks the producer mid-read, the consumer yields at varying batch
    /// counts, and flows go idle and busy many times, so packets keep switching lanes.
    #[tokio::test]
    async fn per_flow_order_holds_under_interleaving() {
        const FLOWS: u16 = 6;
        const PER_FLOW: u16 = 3000;
        let mut script = vec![];
        let mut next = [0u16; FLOWS as usize];
        let mut state = 0x2545_f491_u32;
        while next.iter().any(|&n| n < PER_FLOW) {
            // Batches of 1..=48 packets from a pseudo-random mix of flows.
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            let len = 1 + (state % 48) as usize;
            let mut batch = vec![];
            for i in 0..len {
                let flow = ((state as usize >> 8) + i * (1 + i % 3)) % usize::from(FLOWS);
                if next[flow] < PER_FLOW {
                    batch.push(flow_packet(17, 30000 + flow as u16, next[flow]));
                    next[flow] += 1;
                }
            }
            script.push(Ok(batch));
        }
        let mut recv = scripted_recv(script).await;
        let mut pool = PacketBufPool::new(1);

        let mut seen = [0u16; FLOWS as usize];
        let mut total = 0usize;
        while total < usize::from(FLOWS) * usize::from(PER_FLOW) {
            let batch = tokio::time::timeout(Duration::from_secs(10), recv.recv(&mut pool))
                .await
                .expect("queued packets must arrive")
                .expect("the reader keeps running");
            for packet in batch {
                let (_, port, seq) = port_and_seq(&packet);
                let flow = usize::from(port - 30000);
                assert_eq!(seq, seen[flow], "flow {flow} reordered");
                seen[flow] += 1;
                total += 1;
            }
            for _ in 0..total % 3 {
                tokio::task::yield_now().await;
            }
        }
    }

    /// Per-flow order holds with the producer on another OS thread. Short bursts from few flows
    /// make flows go idle and busy constantly, so a sparse packet and the next packet of its flow
    /// often land in different lanes while the consumer is between its two lane checks: the
    /// race the #260 soak found as TCP reordering.
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
            // Dropping `queue` closes both lanes, which ends the consumer below.
        });
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let total = runtime.block_on(async {
            let mut seen = [0u16; FLOWS];
            let mut total = 0u32;
            loop {
                let n = tokio::time::timeout(Duration::from_secs(10), receiver.take())
                    .await
                    .expect("the lanes must keep delivering");
                if n == 0 {
                    break total;
                }
                for (_, packet) in receiver.batch.drain(..) {
                    let (_, port, seq) = port_and_seq(&packet);
                    let flow = usize::from(port - 30000);
                    assert_eq!(
                        seq, seen[flow],
                        "flow {flow} reordered after {total} packets"
                    );
                    seen[flow] = seen[flow].wrapping_add(1);
                    total += 1;
                }
            }
        });
        producer.join().unwrap();
        assert!(total >= PACKETS);
    }

    /// Fragments of one IPv4 datagram share a bucket even though only the first carries ports.
    #[test]
    fn fragments_share_their_datagrams_bucket() {
        let first = flow_packet(17, 30000, 1);
        let mut later = BytesMut::from(first.as_bytes());
        later[6..8].copy_from_slice(&0x00b9u16.to_be_bytes()); // offset only
        later[20..24].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // payload, not ports
        let mut first_bytes = BytesMut::from(first.as_bytes());
        first_bytes[6..8].copy_from_slice(&0x2000u16.to_be_bytes()); // more fragments
        assert_eq!(super::flow_bucket(&first_bytes), super::flow_bucket(&later));
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
}
