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

//! IP send and receive wrappers for the device's TUN side.
//!
//! The read side is buffered: a task reads the device and hands packets to encryption over a
//! channel. The write side is not (#260): the task that decrypts a packet writes it to the device
//! itself through [`DirectIpSend`]. A channel there cost one task wake-up per packet, and on a
//! loaded host the woken worker waited for a CPU about as long as it ran, which showed up as
//! tail latency on every probe and ACK.

use std::{io, sync::Arc, time::Duration};

use crate::{
    packet::{Ip, Packet, PacketBufPool},
    task::Task,
    tun::{IpRecv, IpSend, MtuWatcher},
};
use tokio::{
    sync::{Mutex, OwnedMutexGuard, mpsc},
    time::timeout,
};
use tokio_util::sync::CancellationToken;

/// Create a [`BufferedIpRecv`] with `capacity` over the device reader `recv`.
///
/// This takes an `Arc<Mutex<R>>` because the inner `R` will be re-used after the
/// [BufferedIpRecv] is dropped. We will take the mutex lock when this function is called, and
/// hold onto it for the lifetime of the receiver.
///
/// # Panics
/// Panics if the lock is not released within 5 seconds.
pub async fn buffered_recv<R: IpRecv>(
    capacity: usize,
    pool: PacketBufPool,
    recv: Arc<Mutex<R>>,
) -> BufferedIpRecv<R> {
    BufferedIpRecv::new(capacity, pool, recv, CancellationToken::new()).await
}

/// An [`IpSend`] that writes to the device from the calling task, with no channel or worker.
///
/// It holds the device writer's lock for its whole lifetime, so it is the only writer: packets
/// reach the device in exactly the order [`IpSend::send`] is called. The decrypting task is the
/// one caller, so per-flow order is the order of decryption, as it was through the channel.
///
/// A packet the device refuses is dropped and counted, and the next one is still written. Only a
/// device that is gone returns an error.
pub struct DirectIpSend<I: IpSend> {
    inner: OwnedMutexGuard<I>,
    refused: u64,
}

impl<I: IpSend> DirectIpSend<I> {
    /// Take the device writer's lock.
    ///
    /// # Panics
    /// Panics if the lock is not released within 5 seconds. A previous connection's writer
    /// releases it when its task is stopped.
    pub async fn new(inner: Arc<Mutex<I>>) -> Self {
        let inner = timeout(Duration::from_secs(5), inner.lock_owned())
            .await
            .expect("Deadlock on IpSend. There must be no more than one IpSend active at any given time.");
        Self { inner, refused: 0 }
    }
}

impl<I: IpSend> IpSend for DirectIpSend<I> {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        match self.inner.send(packet).await {
            Ok(()) => Ok(()),
            Err(e) if is_fatal_tun_error(&e) => {
                tracing::error!("TUN device was deleted: {e}");
                Err(e)
            }
            Err(e) => {
                // The device refused this one packet; the next one may be fine.
                self.refused += 1;
                if self.refused.is_power_of_two() {
                    tracing::warn!(
                        "Dropped IP packet the TUN device refused ({} so far): {e}",
                        self.refused
                    );
                }
                Ok(())
            }
        }
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
    use super::{BufferedIpRecv, DirectIpSend};
    use crate::{
        packet::{Ip, Packet, PacketBufPool},
        tun::{IpRecv, IpSend, MtuWatcher},
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

    /// Records what reaches the device; refuses the packets whose id is in `refuse` and reports
    /// the device gone for id `gone`.
    #[derive(Default)]
    struct Sink {
        written: Vec<u16>,
        refuse: Vec<u16>,
        gone: Option<u16>,
    }

    impl IpSend for Sink {
        async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
            let bytes = packet.as_bytes();
            let id = u16::from_be_bytes([bytes[4], bytes[5]]);
            if self.gone == Some(id) {
                return Err(io::Error::from_raw_os_error(libc::EBADF));
            }
            if self.refuse.contains(&id) {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "refused"));
            }
            self.written.push(id);
            Ok(())
        }
    }

    /// The direct writer passes packets through in call order, and a refused packet does not
    /// stop the ones after it (#260).
    #[tokio::test]
    async fn direct_send_keeps_order_and_skips_a_refused_packet() {
        let sink = Arc::new(Mutex::new(Sink {
            refuse: vec![2],
            ..Sink::default()
        }));
        let mut send = DirectIpSend::new(Arc::clone(&sink)).await;
        for id in 0..5 {
            send.send(packet(64, id)).await.expect("not fatal");
        }
        drop(send);
        assert_eq!(sink.lock().await.written, [0, 1, 3, 4]);
    }

    /// A gone device is reported to the caller, which stops the receive direction.
    #[tokio::test]
    async fn direct_send_reports_a_gone_device() {
        let sink = Arc::new(Mutex::new(Sink {
            gone: Some(1),
            ..Sink::default()
        }));
        let mut send = DirectIpSend::new(sink).await;
        send.send(packet(64, 0)).await.expect("written");
        assert!(send.send(packet(64, 1)).await.is_err());
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
