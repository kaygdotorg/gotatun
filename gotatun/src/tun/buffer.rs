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

use crate::{
    packet::{Ip, Packet, PacketBufPool},
    task::Task,
    tun::{IpRecv, IpSend, MtuWatcher, is_fatal_tun_error},
};
use tokio::{
    sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc},
    time::timeout,
};
use tokio_util::sync::CancellationToken;

/// Identifies buffered TUN runs only when GOTATUN_DIAG_SEND_QUEUE is enabled.
static NEXT_DIAGNOSTIC_RUN_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Create a pair of [`BufferedIpSend`] holding up to `send_capacity` packets and
/// [`BufferedIpRecv`] holding up to `recv_capacity` packets.
///
/// This takes an `Arc<Mutex<S>>` and `Arc<Mutex<R>>` because the inner `S` and `R` will be re-used
/// after [BufferedIpSend] or [BufferedIpRecv] is dropped. We will take the mutex lock when this
/// function is called, and hold onto it for the lifetime of the sender or receiver.
///
/// # Panics
/// Panics if one of the locks is already taken.
pub async fn channel<S: IpSend, R: IpRecv>(
    send_capacity: usize,
    recv_capacity: usize,
    pool: PacketBufPool,
    send: Arc<Mutex<S>>,
    recv: Arc<Mutex<R>>,
) -> (BufferedIpSend, BufferedIpRecv<R>) {
    let token = CancellationToken::new();
    let buffer_send = BufferedIpSend::new(send_capacity, send, token.clone());
    let buffer_recv = BufferedIpRecv::new(recv_capacity, pool, recv, token).await;
    (buffer_send, buffer_recv)
}

/// An [`IpSend`] that wraps another [`IpSend`] to provide buffering.
///
/// Packets sent on this [`IpSend::send`] will be buffered on a channel, and asynchronously
/// processed on another task. This means [`IpSend::send`] won't block unless the channel is full.
#[derive(Clone)]
pub struct BufferedIpSend {
    tx: mpsc::Sender<BufferedIpMessage>,
    /// Bounds queued and in-service packets when one channel message carries a run.
    packet_slots: Arc<Semaphore>,
    packet_capacity: usize,
    _task: Arc<Task>,
}

/// A single packet or an ordered run crossing the buffered TUN boundary.
/// A batch id is present only for opt-in send-queue diagnostics.
enum BufferedIpMessage {
    Single(Packet<Ip>, OwnedSemaphorePermit),
    Batch(Vec<Packet<Ip>>, OwnedSemaphorePermit, Option<u64>),
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
                let diagnostic = crate::diag::PIPELINE.on();
                let (result, refused_packets) = match message {
                    BufferedIpMessage::Single(packet, _permit) => {
                        if diagnostic {
                            eprintln!("pipeline stage=tun_buffer_dequeue mode=single packets=1");
                        }
                        (inner.send(packet).await, 1)
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
                        let result = inner.send_many(&mut packets).await;
                        if let Some(sequence) = sequence {
                            eprintln!(
                                "send_many complete direction=tun sequence={sequence} packets={batch_len} success={}",
                                result.is_ok()
                            );
                        }
                        (result, batch_len)
                    }
                };
                if diagnostic {
                    eprintln!(
                        "pipeline stage=tun_device_write packets={refused_packets} success={}",
                        result.is_ok()
                    );
                }
                if let Err(e) = result {
                    if is_fatal_tun_error(&e) {
                        tracing::error!("TUN device was deleted: {e}");
                        break;
                    }
                    // The device refused this packet or run; the next send may be fine.
                    refused = refused.saturating_add(refused_packets);
                    if refused.is_power_of_two() {
                        tracing::warn!(
                            "Dropped IP packet(s) the TUN device refused ({refused} so far): {e}"
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
            crate::diag::TUN_WRITE_OCCUPANCY
                .record(self.packet_capacity - self.packet_slots.available_permits());
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
/// This will spawn a background task that continuously calls [`IpRecv::recv`] until the buffer is
/// full. Any call to [`IpRecv::recv`] on _this_ object will not block unless the buffer is empty.
pub struct BufferedIpRecv<I> {
    rx: mpsc::Receiver<Packet<Ip>>,
    rx_packet_buf: Vec<Packet<Ip>>,
    _task: Arc<Task>,
    _phantom: std::marker::PhantomData<I>,
    mtu: MtuWatcher,
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
        let (tx, rx) = mpsc::channel::<Packet<Ip>>(capacity);

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
                        let mut read = 0;
                        for packet in packets {
                            if tx.send(packet).await.is_err() {
                                return;
                            }
                            read += 1;
                        }
                        crate::diag::TUN_READ_BATCH.record(read);
                        crate::diag::TUN_READ_OCCUPANCY
                            .record(tx.max_capacity() - tx.capacity());
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
            rx,
            rx_packet_buf: vec![],
            _task: Arc::new(task),
            _phantom: std::marker::PhantomData,
            mtu,
        }
    }
}

impl<I: IpRecv> IpRecv for BufferedIpRecv<I> {
    async fn recv<'a>(
        &'a mut self,
        _pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + 'a> {
        let max_n = self.rx.max_capacity();
        let n = self.rx.recv_many(&mut self.rx_packet_buf, max_n).await;
        crate::diag::OUTGOING_TAKE.record(n);
        if n == 0 {
            // Channel is closed
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "channel closed",
            ));
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
        let mut send = BufferedIpSend::new(3, inner, CancellationToken::new());
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
        let mut send = BufferedIpSend::new(1, inner, CancellationToken::new());
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
