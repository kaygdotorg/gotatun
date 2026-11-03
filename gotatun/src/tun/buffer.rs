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

//! Buffered IP sending and platform-specific receive adapters.

#[cfg(not(target_os = "linux"))]
use std::marker::PhantomData;
use std::{io, sync::Arc, time::Duration};

use crate::{
    packet::{Ip, Packet, PacketBufPool},
    task::Task,
    tun::{IpRecv, IpSend, MtuWatcher},
};
#[cfg(target_os = "linux")]
use tokio::sync::OwnedMutexGuard;
use tokio::{
    sync::{Mutex, mpsc},
    time::timeout,
};
use tokio_util::sync::CancellationToken;

/// Create a buffered sender and receive adapter with `capacity`.
///
/// This takes an `Arc<Mutex<S>>` and `Arc<Mutex<R>>` because the inner `S` and `R` will be re-used
/// after [BufferedIpSend] or [IpRecvAdapter] is dropped. The adapter holds the receive lock for its
/// lifetime. On Linux it reads on demand in the device task, avoiding a receive worker and channel;
/// other platforms keep the buffered receive worker.
///
/// # Panics
/// Panics if one of the locks is already taken.
pub async fn channel<S: IpSend, R: IpRecv>(
    capacity: usize,
    pool: PacketBufPool,
    send: Arc<Mutex<S>>,
    recv: Arc<Mutex<R>>,
) -> (BufferedIpSend, IpRecvAdapter<R>) {
    let token = CancellationToken::new();
    let buffer_send = BufferedIpSend::new(capacity, send, token.clone());
    #[cfg(target_os = "linux")]
    let buffer_recv = {
        drop(pool);
        IpRecvAdapter::new_direct(recv, token).await
    };
    #[cfg(not(target_os = "linux"))]
    let buffer_recv = IpRecvAdapter::new_buffered(capacity, pool, recv, token).await;
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

            while let Some(packet) = rx.recv().await {
                if let Err(e) = inner.send(packet).await {
                    if is_fatal_tun_error(&e) {
                        tracing::error!("TUN device was deleted: {e}");
                        break;
                    }
                    tracing::error!("Error sending IP packet: {e}");
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

/// An [`IpRecv`] adapter that maintains exclusive ownership of the underlying reader.
///
/// Linux reads happen in the calling task without a worker-to-device queue. Other platforms use a
/// background reader and bounded channel so reads stay decoupled from packet processing.
pub struct IpRecvAdapter<I> {
    mode: IpRecvMode<I>,
    rx_packet_buf: Vec<Packet<Ip>>,
    mtu: MtuWatcher,
}

enum IpRecvMode<I> {
    #[cfg(not(target_os = "linux"))]
    Buffered {
        rx: mpsc::Receiver<Packet<Ip>>,
        _task: Arc<Task>,
        _phantom: PhantomData<I>,
    },
    #[cfg(target_os = "linux")]
    Direct {
        inner: OwnedMutexGuard<I>,
        token: CancellationToken,
    },
}

impl<I: IpRecv> IpRecvAdapter<I> {
    #[cfg(not(target_os = "linux"))]
    /// Create a buffered adapter with `capacity`.
    ///
    /// This takes an `Arc<Mutex<I>>` because the inner `I` will be re-used after [Self] is
    /// dropped. We will take the mutex lock when this function is called, and hold onto it for the
    /// lifetime of [Self]. Will panic if the lock is already taken.
    async fn new_buffered(
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
                        tracing::error!("Error receiving IP packet: {e}");
                    }
                }
            }
            drop(drop_guard);
        };
        let task = Task::spawn("buffered IP recv", async move {
            token.run_until_cancelled_owned(task).await;
        });

        Self {
            mode: IpRecvMode::Buffered {
                rx,
                _task: Arc::new(task),
                _phantom: PhantomData,
            },
            rx_packet_buf: vec![],
            mtu,
        }
    }

    #[cfg(target_os = "linux")]
    /// Create a direct adapter that holds the reader lock until it is dropped.
    async fn new_direct(inner: Arc<Mutex<I>>, token: CancellationToken) -> Self {
        // An older connection can still be releasing its reader after cancellation. Wait for
        // that release before starting the replacement connection.
        let inner = timeout(Duration::from_secs(5), inner.lock_owned())
            .await
            .expect("Deadlock on IpRecv. There must be no more than one IpRecv active at any given time.");
        let mtu = inner.mtu();

        Self {
            mode: IpRecvMode::Direct { inner, token },
            rx_packet_buf: Vec::new(),
            mtu,
        }
    }
}

impl<I: IpRecv> IpRecv for IpRecvAdapter<I> {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + 'a> {
        #[cfg(target_os = "linux")]
        {
            let Self {
                mode: IpRecvMode::Direct { inner, token },
                rx_packet_buf,
                ..
            } = self;

            loop {
                let result = tokio::select! {
                    biased;
                    _ = token.cancelled() => {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "TUN receive cancelled",
                        ));
                    }
                    result = inner.recv(pool) => result,
                };
                match result {
                    Ok(packets) => {
                        // Move packet handles into a reusable vector so the iterator keeps the
                        // same concrete type as the channel-backed implementation.
                        rx_packet_buf.clear();
                        rx_packet_buf.extend(packets);
                        return Ok(rx_packet_buf.drain(..));
                    }
                    Err(e) if is_fatal_tun_error(&e) => return Err(e),
                    Err(e) => tracing::error!("Error receiving IP packet: {e}"),
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            let Self {
                mode: IpRecvMode::Buffered { rx, .. },
                rx_packet_buf,
                ..
            } = self
            else {
                unreachable!("non-Linux receive adapter must use buffered mode");
            };
            let max_n = rx.max_capacity();
            let n = rx.recv_many(rx_packet_buf, max_n).await;
            if n == 0 {
                // Channel is closed
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "channel closed",
                ));
            }
            Ok(rx_packet_buf.drain(..n))
        }
    }

    fn mtu(&self) -> MtuWatcher {
        self.mtu.clone()
    }
}

#[cfg(target_os = "linux")]
impl<I> Drop for IpRecvAdapter<I> {
    fn drop(&mut self) {
        let IpRecvMode::Direct { token, .. } = &self.mode;
        token.cancel();
    }
}

/// Checks if an I/O error indicates the TUN device has been deleted or is unusable.
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
        io::ErrorKind::NotFound
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::InvalidData
            | io::ErrorKind::InvalidInput
    )
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct FakeSend;

    impl IpSend for FakeSend {
        async fn send(&mut self, _packet: Packet<Ip>) -> io::Result<()> {
            Ok(())
        }
    }

    struct FakeReceive {
        events: VecDeque<io::Result<Vec<Packet<Ip>>>>,
        calls: Arc<AtomicUsize>,
    }

    impl IpRecv for FakeReceive {
        async fn recv<'a>(
            &'a mut self,
            _pool: &mut PacketBufPool,
        ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            match self.events.pop_front() {
                Some(Ok(packets)) => Ok(packets.into_iter()),
                Some(Err(error)) => Err(error),
                None => std::future::pending().await,
            }
        }

        fn mtu(&self) -> MtuWatcher {
            MtuWatcher::new(1420)
        }
    }

    fn packet_with_id(id: u16) -> Packet<Ip> {
        let mut bytes = [0_u8; 20];
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&20_u16.to_be_bytes());
        bytes[4..6].copy_from_slice(&id.to_be_bytes());
        bytes[8] = 64;
        bytes[9] = 1;
        bytes[12..16].copy_from_slice(&[192, 0, 2, 1]);
        bytes[16..20].copy_from_slice(&[192, 0, 2, 2]);
        Packet::copy_from(&bytes[..]).try_into_ip().unwrap()
    }

    fn packet_id(packet: Packet<Ip>) -> u16 {
        let bytes = packet.into_bytes();
        u16::from_be_bytes(bytes.as_ref()[4..6].try_into().unwrap())
    }

    #[tokio::test]
    async fn linux_tun_receive_is_demand_driven_and_preserves_batch_order() {
        let calls = Arc::new(AtomicUsize::new(0));
        let recv = FakeReceive {
            events: VecDeque::from([
                Err(io::Error::from(io::ErrorKind::WouldBlock)),
                Ok(vec![
                    packet_with_id(17),
                    packet_with_id(18),
                    packet_with_id(19),
                ]),
            ]),
            calls: Arc::clone(&calls),
        };
        let (_send, mut recv) = channel(
            4,
            PacketBufPool::new_lazy(4),
            Arc::new(Mutex::new(FakeSend)),
            Arc::new(Mutex::new(recv)),
        )
        .await;

        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::Relaxed), 0);

        let mut pool = PacketBufPool::new_lazy(4);
        let packet_ids = recv
            .recv(&mut pool)
            .await
            .unwrap()
            .map(packet_id)
            .collect::<Vec<_>>();

        assert_eq!(packet_ids, [17, 18, 19]);
        assert_eq!(calls.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn linux_tun_receive_returns_fatal_error_without_retrying() {
        let calls = Arc::new(AtomicUsize::new(0));
        let recv = FakeReceive {
            events: VecDeque::from([
                Err(io::Error::from(io::ErrorKind::BrokenPipe)),
                Ok(vec![packet_with_id(20)]),
            ]),
            calls: Arc::clone(&calls),
        };
        let (_send, mut recv) = channel(
            4,
            PacketBufPool::new_lazy(4),
            Arc::new(Mutex::new(FakeSend)),
            Arc::new(Mutex::new(recv)),
        )
        .await;

        let mut pool = PacketBufPool::new_lazy(4);
        let error_kind = match recv.recv(&mut pool).await {
            Ok(_) => panic!("fatal TUN receive error was not returned"),
            Err(error) => error.kind(),
        };

        assert_eq!(error_kind, io::ErrorKind::BrokenPipe);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn linux_tun_receive_cancellation_releases_reader_and_send_queue() {
        let calls = Arc::new(AtomicUsize::new(0));
        let reader = Arc::new(Mutex::new(FakeReceive {
            events: VecDeque::new(),
            calls,
        }));
        let (mut send, recv) = channel(
            4,
            PacketBufPool::new_lazy(4),
            Arc::new(Mutex::new(FakeSend)),
            Arc::clone(&reader),
        )
        .await;

        assert!(reader.try_lock().is_err());
        drop(recv);
        assert!(reader.try_lock().is_ok());

        tokio::task::yield_now().await;
        let error = send.send(packet_with_id(21)).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    }
}
