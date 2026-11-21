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
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use futures::future::BoxFuture;

use crate::{
    packet::{Ip, Packet, PacketBufPool},
    task::Task,
    tun::{IpRecv, IpSend, MtuWatcher, is_fatal_tun_error},
};
use tokio::{
    sync::{Mutex, OwnedMutexGuard, OwnedSemaphorePermit, Semaphore, mpsc},
    time::timeout,
};
use tokio_util::sync::{CancellationToken, DropGuard};

/// Identifies buffered TUN runs only when GOTATUN_DIAG_SEND_QUEUE is enabled.
static NEXT_DIAGNOSTIC_RUN_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Create a pair of [`BufferedIpSend`] and [`BufferedIpRecv`] with `capacity`.
///
/// This takes an `Arc<Mutex<S>>` and `Arc<Mutex<R>>` because the inner `S` and `R` will be re-used
/// after [BufferedIpSend] or [BufferedIpRecv] is dropped. We will take the mutex lock when this
/// function is called, and hold onto it for the lifetime of the sender or receiver.
///
/// # Panics
/// Panics if one of the locks is already taken.
///
/// Which side reads and writes the device directly instead of through a task (#260, J1122) is
/// this platform's [`crate::diag::run_to_completion`] default; see [`channel_with`].
pub async fn channel<S: IpSend, R: IpRecv>(
    capacity: usize,
    recv_capacity: usize,
    pool: PacketBufPool,
    send: Arc<Mutex<S>>,
    recv: Arc<Mutex<R>>,
) -> (BufferedIpSend, BufferedIpRecv<R>) {
    channel_with(
        capacity,
        recv_capacity,
        pool,
        send,
        recv,
        crate::diag::run_to_completion(),
    )
    .await
}

/// Like [`channel`], with the run-to-completion stages chosen by the caller (#260, J1122).
///
/// With `stages.tun_rx` the receiver reads the device in the caller's task ([`BufferedIpRecv`]
/// has no read-ahead task then). With `stages.tun_tx` the sender writes a run itself when its
/// queue is idle ([`BufferedIpSend`]).
pub(crate) async fn channel_with<S: IpSend, R: IpRecv>(
    capacity: usize,
    recv_capacity: usize,
    pool: PacketBufPool,
    send: Arc<Mutex<S>>,
    recv: Arc<Mutex<R>>,
    stages: crate::diag::RunToCompletion,
) -> (BufferedIpSend, BufferedIpRecv<R>) {
    let token = CancellationToken::new();
    let buffer_send = BufferedIpSend::new(capacity, send, token.clone(), stages.tun_tx).await;
    let buffer_recv = BufferedIpRecv::new(recv_capacity, pool, recv, token, stages.tun_rx).await;
    (buffer_send, buffer_recv)
}

/// An [`IpSend`] that wraps another [`IpSend`] to provide buffering.
///
/// Packets sent on this [`IpSend::send`] will be buffered on a channel, and asynchronously
/// processed on another task. This means [`IpSend::send`] won't block unless the channel is full.
///
/// With a direct path (the Linux default, #260 J1122) a run skips the channel when the channel
/// is empty and the send task is not writing: the caller writes it to the device itself. The
/// decrypting task then goes from the UDP read to the TUN write without waking the send task,
/// which J1120 counted among the per-Gbit wakes where we trail wireguard-go. Order holds because
/// a run only skips the queue when no earlier run can still wait in it (see [`DirectIpWrite`]).
#[derive(Clone)]
pub struct BufferedIpSend {
    tx: mpsc::Sender<BufferedIpMessage>,
    /// Bounds queued and in-service packets when one channel message carries a run.
    packet_slots: Arc<Semaphore>,
    packet_capacity: usize,
    /// The device, shared by the send task and the direct path; `None` writes only through
    /// the queue.
    direct: Option<Arc<dyn DirectIpWrite>>,
    _task: Arc<Task>,
}

/// A single packet or an ordered run crossing the buffered TUN boundary.
/// A batch id is present only for opt-in send-queue diagnostics.
enum BufferedIpMessage {
    Single(Packet<Ip>, OwnedSemaphorePermit),
    Batch(Vec<Packet<Ip>>, OwnedSemaphorePermit, Option<u64>),
}

/// The locked TUN writer, shared by the send task and the callers' direct writes.
///
/// The send task locks [`Self::device`] for each queued message it writes; a direct write takes
/// it only with `try_lock`, never waiting. `None` once the send task has ended: the device lock
/// (the outer `Arc<Mutex<I>>`) is released then, as before, so a rebuilt connection can take it.
struct SharedIpSend<I> {
    device: Mutex<Option<OwnedMutexGuard<I>>>,
    /// Packets the device refused so far, by either path; logged on powers of two.
    refused: AtomicU64,
}

impl<I: IpSend> SharedIpSend<I> {
    /// Write `packets` (one packet when `single`) and apply the TUN error rules: a refused
    /// packet or run is dropped and counted, as a congested link drops it; a gone device is
    /// returned as an error.
    async fn write(
        &self,
        device: &mut I,
        packets: &mut Vec<Packet<Ip>>,
        single: bool,
    ) -> io::Result<()> {
        let count = packets.len() as u64;
        let result = if single && packets.len() == 1 {
            let packet = packets.pop().expect("one packet was counted");
            device.send(packet).await
        } else {
            device.send_many(packets).await
        };
        packets.clear();
        if crate::diag::PIPELINE.on() {
            eprintln!(
                "pipeline stage=tun_device_write packets={count} success={}",
                result.is_ok()
            );
        }
        match result {
            Ok(()) => Ok(()),
            Err(e) if is_fatal_tun_error(&e) => Err(e),
            Err(e) => {
                // The device refused this packet or run; the next send may be fine.
                let refused = self.refused.fetch_add(count, Ordering::Relaxed) + count;
                if refused.is_power_of_two() {
                    tracing::warn!(
                        "Dropped IP packet(s) the TUN device refused ({refused} so far): {e}"
                    );
                }
                Ok(())
            }
        }
    }
}

/// A caller-side write that only happens when it cannot overtake queued work (#260, J1122).
trait DirectIpWrite: Send + Sync {
    /// Start writing `packets` now if the device is free, or return `None` to queue them.
    ///
    /// The caller checks first that the queue holds no packet ([`BufferedIpSend`]'s permits
    /// all free: queued and in-service packets both hold one). This then takes the device only
    /// if nobody is writing. Together that means no run handed over earlier can still be
    /// waiting, so writing now keeps every producer's order. On success `packets` is empty; a
    /// refused write is dropped and counted like a queued one; a gone device is an error.
    fn try_write<'a>(
        &'a self,
        packets: &'a mut Vec<Packet<Ip>>,
        single: bool,
    ) -> Option<BoxFuture<'a, io::Result<()>>>;
}

impl<I: IpSend> DirectIpWrite for SharedIpSend<I> {
    fn try_write<'a>(
        &'a self,
        packets: &'a mut Vec<Packet<Ip>>,
        single: bool,
    ) -> Option<BoxFuture<'a, io::Result<()>>> {
        let mut device = self.device.try_lock().ok()?;
        device.as_ref()?;
        Some(Box::pin(async move {
            let device = device.as_mut().expect("checked above under the same guard");
            self.write(device, packets, single).await.map_err(|e| {
                tracing::error!("TUN device was deleted: {e}");
                io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    format!("TUN device was deleted: {e}"),
                )
            })
        }))
    }
}

impl BufferedIpSend {
    /// Create a [`BufferedIpSend`] with `capacity`; `direct` lets callers write an idle
    /// device themselves (see the type docs).
    ///
    /// This takes an `Arc<Mutex<I>>` because the inner `I` will be re-used after [Self] is
    /// dropped. We will take the mutex lock when this function is called, and hold onto it until
    /// the send task ends.
    ///
    /// # Panics
    /// Panics if the lock is still taken after five seconds.
    async fn new<I: IpSend>(
        capacity: usize,
        inner: Arc<Mutex<I>>,
        token: CancellationToken,
        direct: bool,
    ) -> Self {
        let (tx, mut rx) = mpsc::channel::<BufferedIpMessage>(capacity);
        let packet_slots = Arc::new(Semaphore::new(capacity));

        let device = timeout(Duration::from_secs(5), inner.lock_owned())
            .await
            .expect("Deadlock on IpSend. There must be no more than one IpSend active at any given time.");
        let shared = Arc::new(SharedIpSend {
            device: Mutex::new(Some(device)),
            refused: AtomicU64::new(0),
        });

        let drop_guard = token.clone().drop_guard();

        let task_shared = Arc::clone(&shared);
        let task = async move {
            while let Some(message) = rx.recv().await {
                let diagnostic = crate::diag::PIPELINE.on();
                let mut device = task_shared.device.lock().await;
                let Some(device) = device.as_mut() else {
                    break;
                };
                let result = match message {
                    BufferedIpMessage::Single(packet, _permit) => {
                        if diagnostic {
                            eprintln!("pipeline stage=tun_buffer_dequeue mode=single packets=1");
                        }
                        task_shared.write(device, &mut vec![packet], true).await
                    }
                    BufferedIpMessage::Batch(mut packets, _permit, sequence) => {
                        let batch_len = packets.len() as u64;
                        if let Some(sequence) = sequence {
                            eprintln!(
                                "send_many dequeue direction=tun sequence={sequence} packets={batch_len}"
                            );
                        }
                        if diagnostic {
                            eprintln!(
                                "pipeline stage=tun_buffer_dequeue mode=batch packets={batch_len}"
                            );
                        }
                        let result = task_shared.write(device, &mut packets, false).await;
                        if let Some(sequence) = sequence {
                            eprintln!(
                                "send_many complete direction=tun sequence={sequence} packets={batch_len} success={}",
                                result.is_ok()
                            );
                        }
                        result
                    }
                };
                if let Err(e) = result {
                    tracing::error!("TUN device was deleted: {e}");
                    break;
                }
            }

            drop(drop_guard);
        };

        let ended_shared = Arc::clone(&shared);
        let task = Task::spawn("buffered IP send", async move {
            token.run_until_cancelled_owned(task).await;
            // Release the device lock however the task ended, so a rebuilt connection can take
            // it while callers still hold clones of this sender.
            ended_shared.device.lock().await.take();
        });

        Self {
            tx,
            packet_slots,
            packet_capacity: capacity,
            direct: direct.then_some(shared as Arc<dyn DirectIpWrite>),
            _task: Arc::new(task),
        }
    }

    /// The direct path, when it may write now: the queue holds no packet, queued or in service.
    fn idle_direct(&self) -> Option<&Arc<dyn DirectIpWrite>> {
        let direct = self.direct.as_ref()?;
        (self.packet_slots.available_permits() == self.packet_capacity).then_some(direct)
    }
}

impl BufferedIpSend {
    /// Bench diagnostic (#260, J687): packets waiting to be written to the TUN device.
    pub(crate) fn depth_probe(&self) -> crate::diag::DepthProbe {
        let tx = self.tx.downgrade();
        let slots = Arc::clone(&self.packet_slots);
        let capacity = self.packet_capacity;
        Box::new(move || {
            tx.upgrade()?;
            Some(capacity - slots.available_permits())
        })
    }
}

impl IpSend for BufferedIpSend {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        let mut packet = Some(packet);
        if let Some(direct) = self.idle_direct() {
            let mut packets = vec![packet.take().expect("set above")];
            if let Some(write) = direct.try_write(&mut packets, true) {
                return write.await;
            }
            packet = packets.pop();
        }
        let packet = packet.expect("the direct path returns a packet it did not take");
        let diagnostic = crate::diag::PIPELINE.on();
        if diagnostic {
            eprintln!(
                "pipeline stage=tun_buffer_permit_wait packets=1 available={} mode=single",
                self.packet_slots.available_permits()
            );
        }
        let permit = Arc::clone(&self.packet_slots)
            .acquire_owned()
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))?;
        if diagnostic {
            eprintln!("pipeline stage=tun_buffer_permit_acquired packets=1 mode=single");
        }
        self.tx
            .send(BufferedIpMessage::Single(packet, permit))
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))?;
        if diagnostic {
            eprintln!("pipeline stage=tun_buffer_channel_sent packets=1 mode=single");
        }
        Ok(())
    }

    async fn send_many(&mut self, packets: &mut Vec<Packet<Ip>>) -> io::Result<()> {
        if crate::diag::TUN_SINGLE_SENDS.on() {
            for packet in std::mem::take(packets) {
                self.send(packet).await?;
            }
            return Ok(());
        }

        if !packets.is_empty()
            && let Some(direct) = self.idle_direct()
            && let Some(write) = direct.try_write(packets, false)
        {
            return write.await;
        }

        while !packets.is_empty() {
            let count = packets.len().min(self.packet_capacity);
            let sequence_diagnostic = crate::diag::SEND_QUEUE.on();
            let sequence = sequence_diagnostic
                .then(|| NEXT_DIAGNOSTIC_RUN_SEQUENCE.fetch_add(1, Ordering::Relaxed));
            if let Some(sequence) = sequence {
                eprintln!(
                    "send_many enqueue_wait direction=tun sequence={sequence} packets={count} available={}",
                    self.packet_slots.available_permits()
                );
            }
            let diagnostic = crate::diag::PIPELINE.on();
            if diagnostic {
                eprintln!(
                    "pipeline stage=tun_buffer_permit_wait packets={count} available={} mode=batch",
                    self.packet_slots.available_permits()
                );
            }
            let permit_count = u32::try_from(count).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("TUN run is too large: {e}"),
                )
            })?;
            let permit = Arc::clone(&self.packet_slots)
                .acquire_many_owned(permit_count)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))?;
            if let Some(sequence) = sequence {
                eprintln!(
                    "send_many permit_acquired direction=tun sequence={sequence} packets={count}"
                );
            }
            if diagnostic {
                eprintln!("pipeline stage=tun_buffer_permit_acquired packets={count} mode=batch");
            }
            let batch = if count == packets.len() {
                std::mem::take(packets)
            } else {
                packets.drain(..count).collect()
            };
            if let Err(error) = self
                .tx
                .send(BufferedIpMessage::Batch(batch, permit, sequence))
                .await
            {
                let mut unsent = match error.0 {
                    BufferedIpMessage::Batch(batch, _, _) => batch,
                    BufferedIpMessage::Single(..) => unreachable!("send_many queues a batch"),
                };
                if let Some(sequence) = sequence {
                    eprintln!(
                        "send_many enqueue_failed direction=tun sequence={sequence} packets={count}"
                    );
                }
                unsent.append(packets);
                *packets = unsent;
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "TUN send task stopped",
                ));
            }
            if let Some(sequence) = sequence {
                eprintln!("send_many enqueued direction=tun sequence={sequence} packets={count}");
            }
            if diagnostic {
                eprintln!("pipeline stage=tun_buffer_channel_sent packets={count} mode=batch");
            }
        }
        Ok(())
    }
}

/// An [`IpRecv`] that wraps another [`IpRecv`] to provide buffering.
///
/// Queued (the default off Linux), this spawns a background task that continuously calls
/// [`IpRecv::recv`] until the buffer is full, and a call to [`IpRecv::recv`] on _this_ object
/// does not block unless the buffer is empty.
///
/// Direct (the Linux default, #260 J1122), there is no task: [`IpRecv::recv`] reads the device in
/// the caller's task. The outgoing packet task then reads, groups, encrypts and sends a TUN frame
/// without a cross-thread wake between the read and the encryption. J1120 measured that handoff
/// among the ~9,200 engine thread wakes per Gbit (wireguard-go: ~4,700): the reader sent every
/// segment of a TSO frame through the channel on its own, and each send could wake the consumer
/// on another worker. The device's own receive queue now holds what the read-ahead channel held,
/// so a sender that outruns the tunnel meets the kernel's backpressure instead of a 4,000-packet
/// queue in the engine.
pub struct BufferedIpRecv<I> {
    source: RecvSource<I>,
    rx_packet_buf: Vec<Packet<Ip>>,
    mtu: MtuWatcher,
    /// Move replies ahead of bulk data in each batch (#260, J720; see [`crate::priority`]).
    replies_first: bool,
}

/// Where [`BufferedIpRecv`] takes packets from.
enum RecvSource<I> {
    /// A read-ahead task fills a bounded channel.
    Queued {
        rx: mpsc::Receiver<Packet<Ip>>,
        /// Bench diagnostic handle on the read-ahead channel (#260, J687); never keeps it open.
        depth_tx: mpsc::WeakSender<Packet<Ip>>,
        _task: Arc<Task>,
    },
    /// The caller's task reads the device itself.
    Direct(DirectRead<I>),
}

/// The device side of a direct [`BufferedIpRecv`]: the locked device and the reader's state.
struct DirectRead<I> {
    /// Held for the receiver's lifetime, like the read-ahead task holds it when queued.
    inner: OwnedMutexGuard<I>,
    pool: PacketBufPool,
    /// Frames the device refused so far; logged on powers of two.
    dropped: u64,
    /// Cancels the shared token when the receiver goes, which stops the buffered sender's task
    /// exactly as the read-ahead task's end does when queued.
    _stop_sender: DropGuard,
}

impl<I: IpRecv> DirectRead<I> {
    /// Read the next frame that holds at least one packet and append its packets to `out`.
    ///
    /// Handles errors as the read-ahead task does: a refused frame is dropped and counted, and
    /// the reader yields before it reads again, so a device that keeps failing cannot spin the
    /// worker; a gone device ends the receiver with [`io::ErrorKind::UnexpectedEof`].
    ///
    /// Cancel safety: the caller polls this inside `select!`. The only awaits are the device
    /// read (readiness-based for the TUN devices we ship: no frame is consumed before it
    /// returns) and the yield, and packets are appended only after the read has returned, so
    /// cancelling loses no packet.
    async fn read_into(&mut self, out: &mut Vec<Packet<Ip>>) -> io::Result<usize> {
        loop {
            match self.inner.recv(&mut self.pool).await {
                Ok(packets) => {
                    let before = out.len();
                    out.extend(packets);
                    let read = out.len() - before;
                    if read > 0 {
                        return Ok(read);
                    }
                    // The device's own filter dropped the whole frame: read the next one.
                }
                Err(e) if is_fatal_tun_error(&e) => {
                    tracing::error!("TUN device was deleted: {e}");
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!("TUN device was deleted: {e}"),
                    ));
                }
                Err(e) => {
                    self.dropped += 1;
                    if self.dropped.is_power_of_two() {
                        tracing::warn!(
                            "Dropped undecodable IP packet ({} so far): {e}",
                            self.dropped
                        );
                    }
                    tokio::task::yield_now().await;
                }
            }
        }
    }
}

impl<I: IpRecv> BufferedIpRecv<I> {
    /// Create a new [`BufferedIpRecv`] with `capacity`; `direct` reads in the caller's task
    /// instead (no read-ahead task, `capacity` unused).
    ///
    /// This takes an `Arc<Mutex<I>>` because the inner `I` will be re-used after [Self] is
    /// dropped. We will take the mutex lock when this function is called, and hold onto it for the
    /// lifetime of [Self]. Will panic if the lock is already taken.
    async fn new(
        capacity: usize,
        mut pool: PacketBufPool,
        inner: Arc<Mutex<I>>,
        token: CancellationToken,
        direct: bool,
    ) -> Self {
        // We use a timeout instead of a try_lock().expect() because there may still be an old
        // BufferedIpRecv that is in the process of being dropped. Otherwise, there would be a
        // race condition between the old `task` dropping, and us taking the lock again.
        let mut inner = timeout(Duration::from_secs(5), inner.lock_owned())
            .await
            .expect("Deadlock on IpRecv. There must be no more than one IpRecv active at any given time.");

        let mtu = inner.mtu();
        let replies_first = crate::priority::mode().tun;

        let drop_guard = token.clone().drop_guard();

        if direct {
            return Self {
                source: RecvSource::Direct(DirectRead {
                    inner,
                    pool,
                    dropped: 0,
                    _stop_sender: drop_guard,
                }),
                rx_packet_buf: vec![],
                mtu,
                replies_first,
            };
        }

        let (tx, rx) = mpsc::channel::<Packet<Ip>>(capacity);
        let depth_tx = tx.downgrade();

        let task = async move {
            let mut dropped: u64 = 0;
            loop {
                match inner.recv(&mut pool).await {
                    Ok(packets) => {
                        for packet in packets {
                            if tx.send(packet).await.is_err() {
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
            source: RecvSource::Queued {
                rx,
                depth_tx,
                _task: Arc::new(task),
            },
            rx_packet_buf: vec![],
            mtu,
            replies_first,
        }
    }
}

impl<I> BufferedIpRecv<I> {
    /// Bench diagnostic (#260, J687): packets read from the TUN device and not yet taken by
    /// the outgoing packet task.
    ///
    /// A direct receiver has no read-ahead queue, so its probe always reports it gone.
    pub(crate) fn depth_probe(&self) -> crate::diag::DepthProbe {
        let RecvSource::Queued { depth_tx, .. } = &self.source else {
            return Box::new(|| None);
        };
        let tx = depth_tx.clone();
        Box::new(move || {
            let tx = tx.upgrade()?;
            Some(tx.max_capacity() - tx.capacity())
        })
    }
}

impl<I: IpRecv> IpRecv for BufferedIpRecv<I> {
    async fn recv<'a>(
        &'a mut self,
        _pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + 'a> {
        let n = match &mut self.source {
            RecvSource::Queued { rx, .. } => {
                let max_n = rx.max_capacity();
                let n = rx.recv_many(&mut self.rx_packet_buf, max_n).await;
                if n == 0 {
                    // Channel is closed
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "channel closed",
                    ));
                }
                n
            }
            RecvSource::Direct(read) => read.read_into(&mut self.rx_packet_buf).await?,
        };
        if self.replies_first {
            crate::priority::replies_first(&mut self.rx_packet_buf, |packet| {
                crate::priority::ip_is_reply(zerocopy::IntoBytes::as_bytes(&**packet))
            });
        }
        Ok(self.rx_packet_buf.drain(..n))
    }

    fn mtu(&self) -> MtuWatcher {
        self.mtu.clone()
    }
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

    /// Records whether the buffered sender forwards a whole run across its task boundary.
    struct RecordingIpSend {
        singles: mpsc::UnboundedSender<u16>,
        batches: mpsc::UnboundedSender<Vec<u16>>,
    }

    impl IpSend for RecordingIpSend {
        async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
            self.singles
                .send(packet_id(&packet))
                .expect("the test receiver remains open");
            Ok(())
        }

        async fn send_many(&mut self, packets: &mut Vec<Packet<Ip>>) -> io::Result<()> {
            let ids = packets.iter().map(packet_id).collect();
            self.batches
                .send(ids)
                .expect("the test receiver remains open");
            packets.clear();
            Ok(())
        }
    }

    fn packet_id(packet: &Packet<Ip>) -> u16 {
        let bytes = packet.as_bytes();
        u16::from_be_bytes([bytes[4], bytes[5]])
    }

    /// Send completed packets as one run instead of one task handoff per packet.
    #[tokio::test]
    async fn buffered_send_many_forwards_one_batch() {
        let (single_tx, mut single_rx) = mpsc::unbounded_channel();
        let (batch_tx, mut batch_rx) = mpsc::unbounded_channel();
        let inner = Arc::new(Mutex::new(RecordingIpSend {
            singles: single_tx,
            batches: batch_tx,
        }));
        let mut send = BufferedIpSend::new(3, inner, CancellationToken::new(), false).await;
        let mut packets = vec![packet(64, 1), packet(64, 2), packet(64, 3)];

        send.send_many(&mut packets).await.unwrap();
        assert!(packets.is_empty());
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), batch_rx.recv())
                .await
                .expect("the batch must cross the buffered sender")
                .expect("the send task remains open"),
            [1, 2, 3]
        );
        assert!(single_rx.try_recv().is_err());
    }

    /// A run larger than the packet budget is split without waiting for impossible permits.
    #[tokio::test]
    async fn send_many_splits_runs_larger_than_the_packet_budget() {
        let (single_tx, mut single_rx) = mpsc::unbounded_channel();
        let (batch_tx, mut batch_rx) = mpsc::unbounded_channel();
        let inner = Arc::new(Mutex::new(RecordingIpSend {
            singles: single_tx,
            batches: batch_tx,
        }));
        let mut send = BufferedIpSend::new(1, inner, CancellationToken::new(), false).await;
        let mut packets = vec![packet(64, 1), packet(64, 2), packet(64, 3)];

        tokio::time::timeout(Duration::from_secs(1), send.send_many(&mut packets))
            .await
            .expect("a run larger than capacity must not wait for impossible permits")
            .expect("the buffered sender must accept every run chunk");
        assert!(packets.is_empty());

        for expected in [[1], [2], [3]] {
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), batch_rx.recv())
                    .await
                    .expect("each run chunk must cross the buffered sender")
                    .expect("the send task remains open"),
                expected
            );
        }
        assert!(single_rx.try_recv().is_err());
    }

    /// A queued receiver (read-ahead task) over `script`.
    async fn scripted_recv(script: Vec<io::Result<Vec<Packet<Ip>>>>) -> BufferedIpRecv<Script> {
        scripted_recv_with(script, false).await
    }

    /// A receiver over `script`, reading in the caller's task when `direct` (#260, J1122).
    async fn scripted_recv_with(
        script: Vec<io::Result<Vec<Packet<Ip>>>>,
        direct: bool,
    ) -> BufferedIpRecv<Script> {
        let inner = Arc::new(Mutex::new(Script(VecDeque::from(script))));
        BufferedIpRecv::new(
            64,
            PacketBufPool::new(1),
            inner,
            CancellationToken::new(),
            direct,
        )
        .await
    }

    /// Packet ids of the next receive, waiting at most five seconds.
    async fn next_ids(recv: &mut BufferedIpRecv<Script>) -> io::Result<Vec<u16>> {
        let mut pool = PacketBufPool::new(1);
        let packets = tokio::time::timeout(Duration::from_secs(5), recv.recv(&mut pool))
            .await
            .expect("the receive must finish promptly")?;
        Ok(packets.map(|p| packet_id(&p)).collect())
    }

    /// An IPv4 pure ACK (no payload), identified like [`packet`].
    fn ack(id: u16) -> Packet<Ip> {
        let mut bytes = BytesMut::zeroed(52);
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&52u16.to_be_bytes());
        bytes[4..6].copy_from_slice(&id.to_be_bytes());
        bytes[9] = 6;
        bytes[20 + 12] = 8 << 4;
        bytes[20 + 13] = 0x10;
        Packet::from_bytes(bytes).try_into_ip().unwrap()
    }

    /// Bulk TCP data of `len` bytes, identified like [`packet`].
    fn data(len: u16, id: u16) -> Packet<Ip> {
        let mut bytes = BytesMut::zeroed(usize::from(len));
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&len.to_be_bytes());
        bytes[4..6].copy_from_slice(&id.to_be_bytes());
        bytes[9] = 6;
        bytes[20 + 12] = 8 << 4;
        bytes[20 + 13] = 0x10;
        Packet::from_bytes(bytes).try_into_ip().unwrap()
    }

    /// With replies first on, a pure ACK read behind bulk data leaves the read-ahead first, and
    /// each class keeps its order (#260, J720). Off, the batch is a FIFO.
    #[tokio::test]
    async fn replies_leave_the_read_ahead_before_bulk_data() {
        let batch = || vec![data(1400, 1), data(1400, 2), ack(3), data(1400, 4), ack(5)];
        for (on, expected) in [(false, [1, 2, 3, 4, 5]), (true, [3, 5, 1, 2, 4])] {
            let mut recv = scripted_recv(vec![Ok(batch())]).await;
            recv.replies_first = on;
            let mut pool = PacketBufPool::new(1);
            // The reader task forwards packet by packet; wait until all five are queued.
            for _ in 0..100 {
                let super::RecvSource::Queued { rx, .. } = &recv.source else {
                    unreachable!("scripted_recv builds a queued receiver");
                };
                if rx.len() == 5 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            let ids: Vec<u16> = recv
                .recv(&mut pool)
                .await
                .expect("the scripted batch")
                .map(|p| packet_id(&p))
                .collect();
            assert_eq!(ids, expected, "replies_first={on}");
        }
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

    /// A direct receiver hands over a whole frame from one read, in order, with no read-ahead
    /// task (#260, J1122), and replies still go first when that mode is on.
    #[tokio::test]
    async fn direct_receive_returns_each_frame_in_order() {
        let mut recv = scripted_recv_with(
            vec![
                Ok(vec![data(1400, 1), data(1400, 2), ack(3)]),
                Ok(vec![]),
                Ok(vec![data(1400, 4)]),
            ],
            true,
        )
        .await;
        assert!(matches!(recv.source, super::RecvSource::Direct(_)));
        assert_eq!(next_ids(&mut recv).await.unwrap(), [1, 2, 3]);
        // The empty frame (everything filtered) is skipped, not returned as an empty batch.
        assert_eq!(next_ids(&mut recv).await.unwrap(), [4]);

        let mut recv = scripted_recv_with(vec![Ok(vec![data(1400, 1), ack(2)])], true).await;
        recv.replies_first = true;
        assert_eq!(next_ids(&mut recv).await.unwrap(), [2, 1]);
    }

    /// Bad frames and a gone device behave the same whether the receiver is queued or direct.
    #[tokio::test]
    async fn direct_receive_keeps_the_error_rules() {
        for direct in [false, true] {
            let mut recv = scripted_recv_with(
                vec![
                    Err(io::Error::new(io::ErrorKind::InvalidData, "bad frame")),
                    Ok(vec![packet(1400, 7)]),
                    Err(io::Error::from_raw_os_error(libc::EBADF)),
                ],
                direct,
            )
            .await;
            assert_eq!(next_ids(&mut recv).await.unwrap(), [7], "direct={direct}");
            assert_eq!(
                next_ids(&mut recv).await.err().map(|e| e.kind()),
                Some(io::ErrorKind::UnexpectedEof),
                "direct={direct}"
            );
        }
    }

    /// Dropping a direct receiver stops the buffered sender's task, as the end of the read-ahead
    /// task does when queued, so a gone TUN reader never leaves a writer behind.
    #[tokio::test]
    async fn dropping_a_direct_receiver_cancels_the_shared_token() {
        let token = CancellationToken::new();
        let inner = Arc::new(Mutex::new(Script(VecDeque::new())));
        let recv = BufferedIpRecv::new(64, PacketBufPool::new(1), inner, token.clone(), true).await;
        assert!(!token.is_cancelled());
        drop(recv);
        assert!(token.is_cancelled());
    }

    /// Records each written run after waiting for one `gate` permit, so a test can hold the
    /// device mid-write.
    struct GatedIpSend {
        gate: Arc<tokio::sync::Semaphore>,
        batches: mpsc::UnboundedSender<Vec<u16>>,
    }

    impl IpSend for GatedIpSend {
        async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
            self.send_many(&mut vec![packet]).await
        }

        async fn send_many(&mut self, packets: &mut Vec<Packet<Ip>>) -> io::Result<()> {
            self.gate
                .acquire()
                .await
                .expect("the gate stays open")
                .forget();
            let ids = packets.drain(..).map(|p| packet_id(&p)).collect();
            self.batches
                .send(ids)
                .expect("the test receiver remains open");
            Ok(())
        }
    }

    /// With the direct path, a run sent to an idle sender is written before `send_many`
    /// returns, in the caller's task, as one run (#260, J1122).
    #[tokio::test]
    async fn idle_direct_sender_writes_in_the_callers_task() {
        let (single_tx, mut single_rx) = mpsc::unbounded_channel();
        let (batch_tx, mut batch_rx) = mpsc::unbounded_channel();
        let inner = Arc::new(Mutex::new(RecordingIpSend {
            singles: single_tx,
            batches: batch_tx,
        }));
        let mut send = BufferedIpSend::new(8, inner, CancellationToken::new(), true).await;

        send.send_many(&mut vec![packet(64, 1), packet(64, 2)])
            .await
            .unwrap();
        assert_eq!(batch_rx.try_recv().ok(), Some(vec![1, 2]));
        send.send(packet(64, 3)).await.unwrap();
        assert_eq!(single_rx.try_recv().ok(), Some(3));
    }

    /// While one run is being written, later runs queue behind it and none overtakes another:
    /// the device sees 1, 2, 3 in order (#260, J1122).
    #[tokio::test]
    async fn busy_direct_sender_queues_in_order() {
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let (batch_tx, mut batch_rx) = mpsc::unbounded_channel();
        let inner = Arc::new(Mutex::new(GatedIpSend {
            gate: Arc::clone(&gate),
            batches: batch_tx,
        }));
        let send = BufferedIpSend::new(8, inner, CancellationToken::new(), true).await;

        let mut first = send.clone();
        let first = tokio::spawn(async move { first.send_many(&mut vec![packet(64, 1)]).await });
        // Wait until the first run holds the device, mid-write.
        for _ in 0..200 {
            if send
                .direct
                .as_ref()
                .is_some_and(|direct| direct.try_write(&mut Vec::new(), false).is_none())
            {
                break;
            }
            tokio::task::yield_now().await;
        }
        let mut later = send.clone();
        tokio::time::timeout(
            Duration::from_secs(1),
            later.send_many(&mut vec![packet(64, 2)]),
        )
        .await
        .expect("a busy device must queue the run, not wait for it")
        .unwrap();
        tokio::time::timeout(Duration::from_secs(1), later.send(packet(64, 3)))
            .await
            .expect("a non-empty queue takes the next packet too")
            .unwrap();

        gate.add_permits(3);
        first.await.unwrap().unwrap();
        let mut seen = Vec::new();
        while seen.len() < 3 {
            let batch = tokio::time::timeout(Duration::from_secs(1), batch_rx.recv())
                .await
                .expect("every run reaches the device")
                .expect("the device stays open");
            seen.extend(batch);
        }
        assert_eq!(seen, [1, 2, 3]);
    }
}
