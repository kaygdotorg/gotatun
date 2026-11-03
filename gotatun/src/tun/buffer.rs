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

use std::{io, sync::Arc, time::Duration};

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

/// IP packets up to this length take the small lane of [`BufferedIpRecv`]: TCP ACKs,
/// keystrokes, DNS, probes and other interactive traffic. Full-size segments do not.
const SMALL_PACKET_MAX_LEN: usize = 256;

/// Bound of the small lane. When it is full, small packets queue on the bulk lane instead.
const SMALL_LANE_CAPACITY: usize = 1024;

/// Most packets one [`BufferedIpRecv::recv`] call takes from each lane.
///
/// This bounds how long a small packet waits behind bulk that was already handed out: one
/// quantum of full-size packets, about 0.25 ms of encryption at 3 Gbit/s, instead of up to the
/// whole 4,000-packet queue.
const LANE_QUANTUM: usize = 64;

/// An [`IpRecv`] that wraps another [`IpRecv`] to provide buffering.
///
/// This will spawn a background task that continuously calls [`IpRecv::recv`] until the buffer is
/// full. Any call to [`IpRecv::recv`] on _this_ object will not block unless the buffer is empty.
///
/// Packets queue on two lanes. Small ones (see [`SMALL_PACKET_MAX_LEN`]) are handed out before
/// queued bulk, so interactive traffic does not wait behind a standing queue of full-size
/// segments under load (#260). Each call takes up to [`LANE_QUANTUM`] packets from each lane, so
/// a flood of small packets cannot starve bulk. Each lane keeps its own order; a small packet
/// can overtake bulk queued before it, which TCP and QUIC tolerate as reordering. WireGuard
/// assigns nonces after this queue, so the tunnel's own counters stay in order.
pub struct BufferedIpRecv<I> {
    rx: mpsc::Receiver<Packet<Ip>>,
    small_rx: mpsc::Receiver<Packet<Ip>>,
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
        let (small_tx, small_rx) =
            mpsc::channel::<Packet<Ip>>(SMALL_LANE_CAPACITY.min(capacity).max(1));

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
                            let packet = if packet.as_bytes().len() <= SMALL_PACKET_MAX_LEN {
                                match small_tx.try_send(packet) {
                                    Ok(()) => continue,
                                    Err(mpsc::error::TrySendError::Full(packet)) => packet,
                                    Err(mpsc::error::TrySendError::Closed(_)) => return,
                                }
                            } else {
                                packet
                            };
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
            rx,
            small_rx,
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
        let Self {
            rx,
            small_rx,
            rx_packet_buf: buf,
            ..
        } = self;
        debug_assert!(buf.is_empty());

        take_ready(small_rx, buf);
        take_ready(rx, buf);
        if buf.is_empty() {
            // Nothing queued: wait for the first packet on either lane, then take what else
            // arrived with it. A lane only closes when the worker stops, which closes both.
            let first = tokio::select! {
                biased;
                Some(packet) = small_rx.recv() => Some(packet),
                Some(packet) = rx.recv() => Some(packet),
                else => None,
            };
            let Some(first) = first else {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "channel closed",
                ));
            };
            buf.push(first);
            take_ready(small_rx, buf);
            take_ready(rx, buf);
        }
        Ok(buf.drain(..))
    }

    fn mtu(&self) -> MtuWatcher {
        self.mtu.clone()
    }
}

/// Move up to [`LANE_QUANTUM`] already-queued packets from `rx` to `buf` without waiting.
fn take_ready(rx: &mut mpsc::Receiver<Packet<Ip>>, buf: &mut Vec<Packet<Ip>>) {
    for _ in 0..LANE_QUANTUM {
        match rx.try_recv() {
            Ok(packet) => buf.push(packet),
            Err(_) => break,
        }
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
    use super::{BufferedIpRecv, LANE_QUANTUM};
    use crate::{
        packet::{Ip, Packet, PacketBufPool},
        tun::{IpRecv, MtuWatcher},
    };
    use bytes::BytesMut;
    use std::{collections::VecDeque, io, sync::Arc, time::Duration};
    use tokio::sync::Mutex;
    use tokio_util::sync::CancellationToken;
    use zerocopy::IntoBytes;

    /// Hands out pre-built batches, then waits forever.
    struct Batches(VecDeque<Vec<Packet<Ip>>>);

    impl IpRecv for Batches {
        async fn recv<'a>(
            &'a mut self,
            _pool: &mut PacketBufPool,
        ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
            match self.0.pop_front() {
                Some(batch) => Ok(batch.into_iter()),
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

    fn id(packet: &Packet<Ip>) -> u16 {
        let bytes = packet.as_bytes();
        u16::from_be_bytes([bytes[4], bytes[5]])
    }

    async fn queued_recv(batch: Vec<Packet<Ip>>) -> BufferedIpRecv<Batches> {
        let total = batch.len();
        let inner = Arc::new(Mutex::new(Batches(VecDeque::from([batch]))));
        let recv =
            BufferedIpRecv::new(4000, PacketBufPool::new(1), inner, CancellationToken::new()).await;
        tokio::time::timeout(Duration::from_secs(5), async {
            while recv.small_rx.len() + recv.rx.len() < total {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the worker must queue the whole batch");
        recv
    }

    async fn next_ids<I: IpRecv>(recv: &mut BufferedIpRecv<I>) -> Vec<u16> {
        let mut pool = PacketBufPool::new(1);
        recv.recv(&mut pool)
            .await
            .unwrap()
            .map(|p| id(&p))
            .collect()
    }

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

        let ids = tokio::time::timeout(Duration::from_secs(5), next_ids(&mut recv))
            .await
            .expect("the valid frame must arrive");
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

    /// A small packet queued behind bulk is handed out first, and each lane keeps its order.
    #[tokio::test]
    async fn small_packets_overtake_queued_bulk() {
        let mut batch: Vec<_> = (0..200).map(|i| packet(1400, i)).collect();
        batch.insert(150, packet(92, 1000));
        batch.push(packet(52, 1001));
        let mut recv = queued_recv(batch).await;

        let first = next_ids(&mut recv).await;
        let expected: Vec<u16> = [1000, 1001]
            .into_iter()
            .chain(0..LANE_QUANTUM as u16)
            .collect();
        assert_eq!(first, expected);

        let second = next_ids(&mut recv).await;
        assert_eq!(second[0], LANE_QUANTUM as u16, "bulk resumes in order");
    }

    /// A steady stream of small packets cannot starve bulk: every call that finds bulk
    /// queued hands some of it out.
    #[tokio::test]
    async fn bulk_is_not_starved_by_small_packets() {
        let mut batch: Vec<_> = (0..300).map(|i| packet(64, i)).collect();
        batch.extend((1000..1010).map(|i| packet(1400, i)));
        let mut recv = queued_recv(batch).await;

        let first = next_ids(&mut recv).await;
        let expected: Vec<u16> = (0..LANE_QUANTUM as u16).chain(1000..1010).collect();
        assert_eq!(first, expected);
    }
}
