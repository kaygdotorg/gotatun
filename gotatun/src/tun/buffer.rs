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

    /// Keep each TUN batch handed to encryption at or below the experimental 64-packet cap.
    #[tokio::test]
    async fn encryption_batches_are_capped_at_sixty_four_packets() {
        const BATCH_CAP: usize = 64;
        const PACKETS: usize = BATCH_CAP * 2;

        let packets = (0..PACKETS)
            .map(|id| packet(64, id as u16))
            .collect::<Vec<_>>();
        let mut recv = scripted_recv_with_capacity(4000, vec![Ok(packets)]).await;
        let mut pool = PacketBufPool::new(1);
        tokio::time::sleep(Duration::from_millis(50)).await;

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
}
