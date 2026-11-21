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

//! Generic buffered `UdpTransport` implementation.

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use futures::future::BoxFuture;
use tokio::{
    io,
    sync::{Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore, mpsc},
};

use crate::packet::Packet;
#[cfg(any(not(target_os = "linux"), test))]
use crate::packet::PacketBufPool;
use crate::task::Task;
#[cfg(any(not(target_os = "linux"), test))]
use crate::udp::UdpRecv;
use crate::udp::UdpSend;

/// Identifies buffered UDP runs only when GOTATUN_DIAG_SEND_QUEUE is enabled.
static NEXT_DIAGNOSTIC_RUN_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// A [`UdpSend`] that wraps another [`UdpSend`] to provide buffering.
///
/// Packets sent on this [`UdpSend::send_to`] will be buffered on a channel, and asynchronously
/// processed on another task. This means [`UdpSend::send_to`] won't block unless the channel is
/// full.
///
/// With a direct path (the Linux default, #260 J1122) a datagram or run skips the channel when
/// no datagram is queued or being sent: the caller sends it itself. The task that finished
/// encrypting a run then also sends it, without waking the send task on another worker; J1120
/// counted that wake among the per-Gbit wakes where we trail wireguard-go. When the socket is
/// busy (a run in flight, or a queue), the run is queued as before, behind everything queued
/// earlier, so no run overtakes another.
#[derive(Clone)]
pub struct BufferedUdpSend {
    _send_task: Arc<Task>,
    /// The direct path; `None` sends only through the queue.
    direct: Option<Arc<dyn DirectUdpWrite>>,

    /// One FIFO keeps packets ordered when a peer's endpoint changes address family.
    send_tx: mpsc::Sender<BufferedUdpMessage>,
    packet_slots: Arc<Semaphore>,
    packet_capacity: usize,
    /// Small datagrams, sent before the next queued run (#260, J720); `None` without the lane.
    reply_tx: Option<mpsc::Sender<(Packet, SocketAddr)>>,
}

/// A caller-side send that only happens when it cannot overtake queued work (#260, J1122).
trait DirectUdpWrite: Send + Sync {
    /// Start sending `packets` now if no other direct send holds the socket's send buffer, or
    /// return `None` to queue them.
    ///
    /// The caller checks first that no datagram is queued or in service ([`BufferedUdpSend`]'s
    /// permits all free: the send task holds a datagram's permit until the socket took it), and
    /// this takes the send turn only if nobody holds it ([`SharedUdpSend`]). Together that means
    /// no run handed over earlier can still be waiting. On success `packets` is empty. Like a
    /// queued send, an error from the socket drops the datagrams concerned and is only traced.
    fn try_write<'a>(
        &'a self,
        packets: &'a mut Vec<(Packet, SocketAddr)>,
    ) -> Option<BoxFuture<'a, ()>>;
}

/// The socket's send turn, shared by the send task and the direct path.
///
/// Whoever holds [`Self::send_many_buf`] is the only one sending: the send task locks it for each
/// batch of messages it takes from the queue, and the direct path only with `try_lock`. So a run
/// never reaches the socket while an earlier one is still being sent, whichever path each took.
struct SharedUdpSend<U: UdpSend> {
    udp_tx: U,
    /// The send turn, and the transport's reusable send buffer that comes with it.
    send_many_buf: AsyncMutex<U::SendManyBuf>,
    /// Most datagrams one transport call takes.
    max_packet_count: usize,
}

impl<U: UdpSend + 'static> DirectUdpWrite for SharedUdpSend<U> {
    fn try_write<'a>(
        &'a self,
        packets: &'a mut Vec<(Packet, SocketAddr)>,
    ) -> Option<BoxFuture<'a, ()>> {
        let mut send_many_buf = self.send_many_buf.try_lock().ok()?;
        Some(Box::pin(async move {
            let run = std::mem::take(packets);
            // No send-turn budget here: the caller is the packet task itself, so yielding would
            // only delay its own next read (the budget exists for the send task, J728).
            let mut budget = SendTurnBudget { every: 0, sent: 0 };
            flush_udp_run(
                &self.udp_tx,
                &mut send_many_buf,
                run,
                self.max_packet_count,
                &mut budget,
            )
            .await;
        }))
    }
}

/// One queued datagram or one ordered run of datagrams.
/// A batch id is present only for opt-in send-queue diagnostics.
enum BufferedUdpMessage {
    Single(Packet, SocketAddr, OwnedSemaphorePermit),
    Batch(Vec<(Packet, SocketAddr)>, OwnedSemaphorePermit, Option<u64>),
}

/// The send task's poll point (#260, J728).
///
/// On a current-thread runtime the send task, the receive task and the TUN reader share one
/// thread. A socket send that never blocks never yields, so one queued run of N datagrams keeps
/// the thread for N socket calls (about 25 us each on the macOS VM), and a reply that arrived
/// meanwhile waits for the whole run. After `every` datagrams this budget yields: Tokio defers a
/// yielded task until it has polled I/O, so the woken receive task runs first. `every == 0`
/// never yields (the default).
struct SendTurnBudget {
    every: usize,
    sent: usize,
}

impl SendTurnBudget {
    /// Count `datagrams` handed to the socket and yield once the budget is spent.
    async fn charge(&mut self, datagrams: usize) {
        if self.every == 0 || datagrams == 0 {
            return;
        }
        self.sent += datagrams;
        if self.sent >= self.every {
            self.sent = 0;
            tokio::task::yield_now().await;
        }
    }

    /// The largest run to hand to the socket in one call: at most the budget when it is on.
    fn chunk(&self, max_packet_count: usize) -> usize {
        if self.every == 0 {
            max_packet_count
        } else {
            max_packet_count.min(self.every)
        }
    }
}

/// Bench switch (#260, J728): `GOTATUN_BENCH_SEND_YIELD=<n>` turns on the send-turn budget
/// ([`SendTurnBudget`]) with `n` datagrams per turn. Read once; unset or 0 leaves it off.
fn send_yield_every() -> usize {
    static EVERY: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *EVERY.get_or_init(|| {
        let every = std::env::var("GOTATUN_BENCH_SEND_YIELD")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        if every > 0 {
            eprintln!("diag send_yield every={every}");
        }
        every
    })
}

/// Send one same-family UDP run through the transport's reusable send buffer.
async fn flush_udp_packets<U: UdpSend>(
    udp_tx: &U,
    send_buf: &mut U::SendManyBuf,
    packets: &mut Vec<(Packet, SocketAddr)>,
) {
    let diagnostic = crate::diag::PIPELINE.on();
    let packet_count = packets.len();
    if crate::diag::UDP_SINGLE_SENDS.on() {
        let mut sent = 0;
        for (packet, address) in packets.drain(..) {
            match udp_tx.send_to(packet, address).await {
                Ok(()) => sent += 1,
                Err(error) => tracing::trace!("send_to_err: {error:#}"),
            }
        }
        if diagnostic {
            eprintln!("pipeline stage=udp_socket_send packets={sent}/{packet_count} mode=single");
        }
        return;
    }

    match packets.len() {
        0 => {}
        1 => {
            let (packet, addr) = packets.pop().expect("one packet was counted");
            let result = udp_tx.send_to(packet, addr).await;
            if diagnostic {
                eprintln!(
                    "pipeline stage=udp_socket_send packets={} mode=single success={}",
                    u8::from(result.is_ok()),
                    result.is_ok()
                );
            }
            if let Err(error) = result {
                tracing::trace!("send_to_err: {error:#}");
            }
        }
        _ => {
            let result = udp_tx.send_many_to(send_buf, packets).await;
            if diagnostic {
                eprintln!(
                    "pipeline stage=udp_socket_send packets={} mode=batch success={}",
                    if result.is_ok() {
                        packet_count
                    } else {
                        packet_count - packets.len()
                    },
                    result.is_ok()
                );
            }
            if let Err(error) = result {
                tracing::trace!("send_to_many_err: {error:#}");
                packets.clear();
            }
        }
    }
}

/// Send a bounded run in as few transport calls as its maximum batch size allows.
///
/// `budget` is charged after every socket call, so a long run yields between calls.
async fn flush_udp_run<U: UdpSend>(
    udp_tx: &U,
    send_buf: &mut U::SendManyBuf,
    packets: Vec<(Packet, SocketAddr)>,
    max_packet_count: usize,
    budget: &mut SendTurnBudget,
) {
    let chunk = budget.chunk(max_packet_count);
    if packets.len() <= chunk {
        let mut packets = packets;
        let count = packets.len();
        flush_udp_packets(udp_tx, send_buf, &mut packets).await;
        budget.charge(count).await;
        return;
    }

    let mut packets = packets.into_iter();
    while packets.len() > 0 {
        let mut batch = packets.by_ref().take(chunk).collect::<Vec<_>>();
        let count = batch.len();
        flush_udp_packets(udp_tx, send_buf, &mut batch).await;
        budget.charge(count).await;
    }
}

/// Send `replies` and every reply already queued on `reply_rx`, one address family per call.
async fn flush_replies<U: UdpSend>(
    reply_rx: &mut mpsc::Receiver<(Packet, SocketAddr)>,
    udp_tx: &U,
    send_buf: &mut U::SendManyBuf,
    replies: &mut Vec<(Packet, SocketAddr)>,
    max_packet_count: usize,
) {
    while let Ok(reply) = reply_rx.try_recv() {
        let other_family = replies.first().is_some_and(|(_, first)| {
            matches!(first, SocketAddr::V4(..)) != matches!(reply.1, SocketAddr::V4(..))
        });
        if other_family || replies.len() == max_packet_count {
            flush_udp_packets(udp_tx, send_buf, replies).await;
        }
        replies.push(reply);
    }
    flush_udp_packets(udp_tx, send_buf, replies).await;
}

impl BufferedUdpSend {
    /// Wrap a [`UdpSend`] into a [`BufferedUdpSend`] with `capacity`.
    ///
    /// Small datagrams get their own lane when `GOTATUN_BENCH_REPLIES_FIRST` names `tx`
    /// (#260, J720; see [`crate::priority`]).
    pub fn new(capacity: usize, udp_tx: impl UdpSend + 'static) -> Self {
        Self::with_reply_lane(capacity, udp_tx, crate::priority::mode().tx)
    }

    /// Like [`Self::new`], with the reply lane chosen by the caller (`reply_lane`).
    ///
    /// With the lane, a datagram of at most [`crate::priority::REPLY_MAX`] bytes skips the
    /// queued runs: the send task sends every queued reply before its next queued run, so a
    /// probe or ACK no longer waits behind a full send queue of bulk datagrams.
    pub(crate) fn with_reply_lane(
        capacity: usize,
        udp_tx: impl UdpSend + 'static,
        reply_lane: bool,
    ) -> Self {
        Self::with_send_turn(
            capacity,
            udp_tx,
            reply_lane,
            send_yield_every(),
            crate::diag::run_to_completion().udp_tx,
        )
    }

    /// Like [`Self::with_reply_lane`], plus a send-turn budget (#260, J728): after
    /// `yield_every` datagrams reach the socket, the send task yields so the runtime polls I/O
    /// before it sends more. `0` turns the budget off. `direct` lets callers send to an idle
    /// socket themselves (see the type docs).
    pub(crate) fn with_send_turn<U: UdpSend + 'static>(
        capacity: usize,
        udp_tx: U,
        reply_lane: bool,
        yield_every: usize,
        direct: bool,
    ) -> Self {
        let shared = Arc::new(SharedUdpSend {
            max_packet_count: udp_tx.max_number_of_packets_to_send().max(1),
            udp_tx: udp_tx.clone(),
            send_many_buf: AsyncMutex::new(U::SendManyBuf::default()),
        });
        let direct = direct.then(|| Arc::clone(&shared) as Arc<dyn DirectUdpWrite>);
        let (send_tx, mut send_rx) = mpsc::channel::<BufferedUdpMessage>(capacity);
        let packet_slots = Arc::new(Semaphore::new(capacity));
        let (reply_tx, mut reply_rx) = if reply_lane {
            let (tx, rx) = mpsc::channel(capacity);
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };

        let send_task = Task::spawn("buffered UDP send", async move {
            let mut buf = vec![];
            let max_packet_count = udp_tx.max_number_of_packets_to_send().max(1);
            let mut singles = Vec::with_capacity(max_packet_count);
            let mut single_permits = Vec::with_capacity(max_packet_count);
            let mut replies = Vec::with_capacity(max_packet_count);
            let mut budget = SendTurnBudget {
                every: yield_every,
                sent: 0,
            };

            loop {
                let count = match &mut reply_rx {
                    Some(reply_rx) => tokio::select! {
                        biased;
                        Some(reply) = reply_rx.recv() => {
                            replies.push(reply);
                            let mut send_many_buf = shared.send_many_buf.lock().await;
                            flush_replies(reply_rx, &udp_tx, &mut send_many_buf, &mut replies, max_packet_count).await;
                            continue;
                        }
                        count = send_rx.recv_many(&mut buf, max_packet_count) => count,
                    },
                    None => send_rx.recv_many(&mut buf, max_packet_count).await,
                };
                if count == 0 {
                    break;
                }

                // Hold the send turn for this batch, so no direct send interleaves with it.
                let mut send_many_buf = shared.send_many_buf.lock().await;
                for message in buf.drain(..) {
                    // Replies queued since the last run leave before the next one.
                    if let Some(reply_rx) = &mut reply_rx {
                        flush_replies(
                            reply_rx,
                            &udp_tx,
                            &mut send_many_buf,
                            &mut replies,
                            max_packet_count,
                        )
                        .await;
                    }
                    match message {
                        BufferedUdpMessage::Single(packet, addr, permit) => {
                            if singles.first().is_some_and(|(_, first_addr)| {
                                matches!(first_addr, SocketAddr::V4(..))
                                    != matches!(addr, SocketAddr::V4(..))
                            }) {
                                flush_udp_packets(&udp_tx, &mut send_many_buf, &mut singles).await;
                                single_permits.clear();
                            }
                            singles.push((packet, addr));
                            single_permits.push(permit);
                            if singles.len() == budget.chunk(max_packet_count) {
                                let count = singles.len();
                                flush_udp_packets(&udp_tx, &mut send_many_buf, &mut singles).await;
                                single_permits.clear();
                                budget.charge(count).await;
                            }
                        }
                        BufferedUdpMessage::Batch(packets, permit, sequence) => {
                            let packet_count = packets.len();
                            if let Some(sequence) = sequence {
                                eprintln!(
                                    "send_many dequeue direction=udp sequence={sequence} packets={packet_count}"
                                );
                            }
                            flush_udp_packets(&udp_tx, &mut send_many_buf, &mut singles).await;
                            single_permits.clear();
                            flush_udp_run(
                                &udp_tx,
                                &mut send_many_buf,
                                packets,
                                max_packet_count,
                                &mut budget,
                            )
                            .await;
                            if let Some(sequence) = sequence {
                                eprintln!(
                                    "send_many complete direction=udp sequence={sequence} packets={packet_count}"
                                );
                            }
                            drop(permit);
                        }
                    }
                }

                flush_udp_packets(&udp_tx, &mut send_many_buf, &mut singles).await;
                single_permits.clear();
            }
        });

        Self {
            _send_task: Arc::new(send_task),
            direct,
            send_tx,
            packet_slots,
            packet_capacity: capacity,
            reply_tx,
        }
    }
}

impl BufferedUdpSend {
    /// The direct path, when it may send now: no datagram is queued or in service.
    fn idle_direct(&self) -> Option<&Arc<dyn DirectUdpWrite>> {
        let direct = self.direct.as_ref()?;
        (self.packet_slots.available_permits() == self.packet_capacity).then_some(direct)
    }

    /// Bench diagnostic (#260, J687): datagrams queued for the UDP socket and not yet sent.
    pub(crate) fn depth_probe(&self) -> crate::diag::DepthProbe {
        let tx = self.send_tx.downgrade();
        let slots = Arc::clone(&self.packet_slots);
        let capacity = self.packet_capacity;
        Box::new(move || {
            tx.upgrade()?;
            Some(capacity - slots.available_permits())
        })
    }
}

impl UdpSend for BufferedUdpSend {
    type SendManyBuf = ();

    async fn send_to(&self, packet: Packet, destination: SocketAddr) -> io::Result<()> {
        if let Some(reply_tx) = &self.reply_tx
            && crate::priority::datagram_is_reply(packet.len())
        {
            return reply_tx
                .send((packet, destination))
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e));
        }
        let mut packet = Some(packet);
        if let Some(direct) = self.idle_direct() {
            let mut run = vec![(packet.take().expect("set above"), destination)];
            if let Some(send) = direct.try_write(&mut run) {
                send.await;
                return Ok(());
            }
            packet = run.pop().map(|(packet, _)| packet);
        }
        let packet = packet.expect("the direct path returns a datagram it did not take");
        let permit = Arc::clone(&self.packet_slots)
            .acquire_owned()
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))?;
        self.send_tx
            .send(BufferedUdpMessage::Single(packet, destination, permit))
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))?;
        Ok(())
    }

    async fn send_many_to(
        &self,
        _send_buf: &mut Self::SendManyBuf,
        packets: &mut Vec<(Packet, SocketAddr)>,
    ) -> io::Result<()> {
        if packets.is_empty() {
            return Ok(());
        }
        let is_v4 = matches!(packets[0].1, SocketAddr::V4(..));
        if packets
            .iter()
            .any(|(_, addr)| matches!(addr, SocketAddr::V4(..)) != is_v4)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a UDP run cannot mix address families",
            ));
        }
        if let Some(reply_tx) = &self.reply_tx
            && packets
                .iter()
                .any(|(packet, _)| crate::priority::datagram_is_reply(packet.len()))
        {
            let mut bulk = Vec::with_capacity(packets.len());
            for (packet, address) in packets.drain(..) {
                if crate::priority::datagram_is_reply(packet.len()) {
                    reply_tx
                        .send((packet, address))
                        .await
                        .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))?;
                } else {
                    bulk.push((packet, address));
                }
            }
            *packets = bulk;
        }
        if !packets.is_empty()
            && let Some(direct) = self.idle_direct()
            && let Some(send) = direct.try_write(packets)
        {
            send.await;
            return Ok(());
        }
        while !packets.is_empty() {
            let count = packets.len().min(self.packet_capacity);
            let sequence_diagnostic = crate::diag::SEND_QUEUE.on();
            let sequence = sequence_diagnostic
                .then(|| NEXT_DIAGNOSTIC_RUN_SEQUENCE.fetch_add(1, Ordering::Relaxed));
            if let Some(sequence) = sequence {
                eprintln!(
                    "send_many enqueue_wait direction=udp sequence={sequence} packets={count} available={}",
                    self.packet_slots.available_permits()
                );
            }
            let permit_count = u32::try_from(count).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("UDP run is too large: {e}"),
                )
            })?;
            let permit = Arc::clone(&self.packet_slots)
                .acquire_many_owned(permit_count)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))?;
            if let Some(sequence) = sequence {
                eprintln!(
                    "send_many permit_acquired direction=udp sequence={sequence} packets={count}"
                );
            }
            let batch = if count == packets.len() {
                std::mem::take(packets)
            } else {
                packets.drain(..count).collect()
            };
            if let Err(error) = self
                .send_tx
                .send(BufferedUdpMessage::Batch(batch, permit, sequence))
                .await
            {
                let mut unsent = match error.0 {
                    BufferedUdpMessage::Batch(batch, _, _) => batch,
                    BufferedUdpMessage::Single(..) => unreachable!("send_many_to queues a batch"),
                };
                if let Some(sequence) = sequence {
                    eprintln!(
                        "send_many enqueue_failed direction=udp sequence={sequence} packets={count}"
                    );
                }
                unsent.append(packets);
                *packets = unsent;
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "UDP send task stopped",
                ));
            }
            if let Some(sequence) = sequence {
                eprintln!("send_many enqueued direction=udp sequence={sequence} packets={count}");
            }
        }
        Ok(())
    }

    fn max_number_of_packets_to_send(&self) -> usize {
        self.send_tx.max_capacity()
    }
}

/// A [`UdpRecv`] that wraps another [`UdpRecv`] to provide buffering.
///
/// This will spawn a background task that continuously calls [`UdpRecv::recv_from`] until the
/// buffer is full. Any call to [`UdpRecv::recv_from`] on _this_ object will not block unless the
/// buffer is empty.
#[cfg(any(not(target_os = "linux"), test))]
pub struct BufferedUdpReceive {
    _recv_task: Arc<Task>,
    /// Bench diagnostic handle on the receive queue (#260, J687); never keeps it open. Linux
    /// builds this type only for tests, which never sample it.
    #[cfg(not(target_os = "linux"))]
    depth_tx: mpsc::WeakSender<io::Result<(Packet, SocketAddr)>>,
    recv_rx: mpsc::Receiver<io::Result<(Packet, SocketAddr)>>,
    /// Small datagrams, taken before `recv_rx` (#260, J720); `None` without the reply lane.
    reply_rx: Option<mpsc::Receiver<(Packet, SocketAddr)>>,
}

#[cfg(any(not(target_os = "linux"), test))]
impl BufferedUdpReceive {
    /// Wrap a [`UdpRecv`] into a [`BufferedUdpReceive`] with `capacity`.
    ///
    /// Small datagrams get their own lane when `GOTATUN_BENCH_REPLIES_FIRST` names `udp`
    /// (#260, J720; see [`crate::priority`]).
    pub fn new(capacity: usize, udp_rx: impl UdpRecv + 'static, recv_pool: PacketBufPool) -> Self {
        Self::with_reply_lane(capacity, udp_rx, recv_pool, crate::priority::mode().udp)
    }

    /// Like [`Self::new`], with the reply lane chosen by the caller (`reply_lane`).
    ///
    /// With the lane, a datagram of at most [`crate::priority::REPLY_MAX`] bytes waits in its
    /// own queue of `capacity`, and every receive call takes that queue first. A probe reply or
    /// ACK then no longer waits behind a full queue of bulk datagrams.
    pub(crate) fn with_reply_lane(
        capacity: usize,
        mut udp_rx: impl UdpRecv + 'static,
        mut recv_pool: PacketBufPool,
        reply_lane: bool,
    ) -> Self {
        let (recv_tx, recv_rx) = mpsc::channel(capacity);
        let (reply_tx, reply_rx) = if reply_lane {
            let (tx, rx) = mpsc::channel(capacity);
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };
        #[cfg(not(target_os = "linux"))]
        let depth_tx = recv_tx.downgrade();

        let recv_task = Task::spawn("buffered UDP receive", async move {
            let mut recv_many_buf = Default::default();
            let mut packet_bufs = vec![];
            let mut dropped: u64 = 0;

            loop {
                // Read packets from the socket. Only a gone socket ends this task; a bad
                // datagram is dropped, and what the batch delivered before it is forwarded.
                if let Err(err) = udp_rx
                    .recv_many_from(&mut recv_many_buf, &mut recv_pool, &mut packet_bufs)
                    .await
                {
                    if crate::udp::is_fatal_udp_error(&err) {
                        let _ = recv_tx.send(Err(err)).await;
                        return;
                    }
                    dropped += 1;
                    if dropped.is_power_of_two() {
                        tracing::warn!(
                            "Dropped undecodable UDP datagram ({dropped} so far): {err}"
                        );
                    }
                    tokio::task::yield_now().await;
                }

                for (packet_buf, src) in packet_bufs.drain(..) {
                    if let Some(reply_tx) = &reply_tx
                        && crate::priority::datagram_is_reply(packet_buf.len())
                    {
                        if reply_tx.send((packet_buf, src)).await.is_err() {
                            return;
                        }
                        continue;
                    }
                    match recv_tx.try_send(Ok((packet_buf, src))) {
                        Ok(()) => (),
                        Err(mpsc::error::TrySendError::Full(packet)) => {
                            if recv_tx.send(packet).await.is_err() {
                                // Buffer dropped
                                return;
                            }
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => return,
                    }
                }
            }
        });

        Self {
            _recv_task: Arc::new(recv_task),
            #[cfg(not(target_os = "linux"))]
            depth_tx,
            recv_rx,
            reply_rx,
        }
    }

    /// Bench diagnostic (#260, J687): received datagrams waiting for the packet task.
    #[cfg(not(target_os = "linux"))]
    pub(crate) fn depth_probe(&self) -> crate::diag::DepthProbe {
        let tx = self.depth_tx.clone();
        Box::new(move || {
            let tx = tx.upgrade()?;
            Some(tx.max_capacity() - tx.capacity())
        })
    }
}

/// Most datagrams one [`BufferedUdpReceive::recv_many_from`] call hands to the packet task.
///
/// Taking every queued datagram in one call lets the packet task decrypt them as one run and
/// write them to the TUN together, the way Linux handles a `recvmmsg` batch, instead of paying
/// a loop turn per datagram (#260, J582). 64 matches the macOS socket read and send batches;
/// the bound keeps one call from holding the first datagram's TUN write behind the decryption
/// of a whole deep queue.
#[cfg(any(not(target_os = "linux"), test))]
const RECV_BATCH: usize = 64;

#[cfg(any(not(target_os = "linux"), test))]
impl UdpRecv for BufferedUdpReceive {
    type RecvManyBuf = ();

    async fn recv_from(&mut self, _pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        if let Some(reply_rx) = &mut self.reply_rx {
            // Replies first; a closed lane only means the receive task is gone, and the bulk
            // queue then reports how it ended.
            tokio::select! {
                biased;
                Some(reply) = reply_rx.recv() => return Ok(reply),
                packet = self.recv_rx.recv() => {
                    return packet.unwrap_or_else(|| {
                        Err(io::Error::new(io::ErrorKind::BrokenPipe, "UDP receive task stopped"))
                    });
                }
            }
        }
        let Some(packet) = self.recv_rx.recv().await else {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "UDP receive task stopped",
            ));
        };
        packet
    }

    /// Wait for one datagram, then add every datagram already queued, up to [`RECV_BATCH`].
    ///
    /// Never waits for a second datagram, so a lone reply is not delayed. The receive task only
    /// queues an error when the socket is gone, so an error ends the batch and is returned.
    async fn recv_many_from(
        &mut self,
        _recv_buf: &mut Self::RecvManyBuf,
        pool: &mut PacketBufPool,
        packets: &mut Vec<(Packet, SocketAddr)>,
    ) -> io::Result<()> {
        packets.push(self.recv_from(pool).await?);
        // Bench override (#260, J687): GOTATUN_BENCH_UDP_RX_BATCH=1 restores one datagram per call.
        static BATCH: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let batch =
            *BATCH.get_or_init(|| crate::diag::capacity("GOTATUN_BENCH_UDP_RX_BATCH", RECV_BATCH));
        for _ in 1..batch {
            if let Some(reply) = self.reply_rx.as_mut().and_then(|rx| rx.try_recv().ok()) {
                packets.push(reply);
                continue;
            }
            let Ok(item) = self.recv_rx.try_recv() else {
                break;
            };
            packets.push(item?);
        }
        Ok(())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod test {
    use super::*;
    use crate::udp::{
        UdpSend,
        socket::{SockOpt, UdpSocket},
    };
    use std::time::Duration;
    use tokio::sync::mpsc;
    use zerocopy::IntoBytes;

    /// Records datagrams that cross the buffered send boundary.
    #[derive(Clone)]
    struct RecordingUdpSend(mpsc::UnboundedSender<(Vec<u8>, SocketAddr)>);

    impl UdpSend for RecordingUdpSend {
        type SendManyBuf = ();

        async fn send_to(&self, packet: Packet, destination: SocketAddr) -> io::Result<()> {
            self.0
                .send((packet.as_bytes().to_vec(), destination))
                .expect("the test receiver remains open");
            Ok(())
        }
    }

    /// Hands out scripted receive results, then waits forever.
    struct Script(std::collections::VecDeque<io::Result<(Packet, SocketAddr)>>);

    impl UdpRecv for Script {
        type RecvManyBuf = ();

        async fn recv_from(
            &mut self,
            _pool: &mut PacketBufPool,
        ) -> io::Result<(Packet, SocketAddr)> {
            match self.0.pop_front() {
                Some(result) => result,
                None => std::future::pending().await,
            }
        }
    }

    fn datagram(payload: &[u8]) -> (Packet, SocketAddr) {
        (
            Packet::from_bytes(bytes::BytesMut::from(payload)),
            "127.0.0.1:51820".parse().unwrap(),
        )
    }

    /// A run larger than the buffer capacity is split without waiting for impossible permits.
    #[tokio::test]
    async fn send_many_splits_runs_larger_than_the_buffer_capacity() {
        let (sent_tx, mut sent_rx) = mpsc::unbounded_channel();
        let send = BufferedUdpSend::new(1, RecordingUdpSend(sent_tx));
        let address = "127.0.0.1:51820".parse().unwrap();
        let mut packets = vec![
            (
                Packet::from_bytes(bytes::BytesMut::from(&b"first"[..])),
                address,
            ),
            (
                Packet::from_bytes(bytes::BytesMut::from(&b"second"[..])),
                address,
            ),
            (
                Packet::from_bytes(bytes::BytesMut::from(&b"third"[..])),
                address,
            ),
        ];
        let mut send_buf = ();

        tokio::time::timeout(
            Duration::from_secs(1),
            send.send_many_to(&mut send_buf, &mut packets),
        )
        .await
        .expect("an oversized run must not wait for impossible capacity")
        .expect("the buffered send task must accept each chunk");
        assert!(packets.is_empty());

        for expected in [b"first".as_slice(), b"second", b"third"] {
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), sent_rx.recv())
                    .await
                    .expect("the packet must cross the buffer")
                    .expect("the send task remains open")
                    .0,
                expected
            );
        }
    }

    /// A peer that changes address family still sends its queued packets in slot order.
    #[tokio::test]
    async fn send_many_preserves_order_across_address_families() {
        let (sent_tx, mut sent_rx) = mpsc::unbounded_channel();
        let send = BufferedUdpSend::new(4, RecordingUdpSend(sent_tx));
        let address_v6 = "[::1]:51820".parse().unwrap();
        let address_v4 = "127.0.0.1:51820".parse().unwrap();
        let mut send_buf = ();
        let mut first = vec![(
            Packet::from_bytes(bytes::BytesMut::from(&b"first"[..])),
            address_v6,
        )];
        let mut second = vec![(
            Packet::from_bytes(bytes::BytesMut::from(&b"second"[..])),
            address_v4,
        )];

        send.send_many_to(&mut send_buf, &mut first)
            .await
            .expect("the first peer run is queued");
        send.send_many_to(&mut send_buf, &mut second)
            .await
            .expect("the next peer run is queued");

        for expected in [b"first".as_slice(), b"second"] {
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), sent_rx.recv())
                    .await
                    .expect("both peer runs must be sent")
                    .expect("the UDP send task remains open")
                    .0,
                expected,
            );
        }
    }

    /// A datagram the socket layer refuses (e.g. truncated) is dropped and the next one is
    /// still delivered; before #260 the first error stopped the receive task for good.
    #[tokio::test]
    async fn bad_datagram_is_dropped_and_the_next_one_passes() {
        let script = Script(
            [
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated UDP GRO receive",
                )),
                Ok(datagram(b"after-bad")),
            ]
            .into(),
        );
        let mut receiver = BufferedUdpReceive::new(16, script, PacketBufPool::new(4));

        let (packet, _) = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            receiver.recv_from(&mut PacketBufPool::new(1)),
        )
        .await
        .expect("the valid datagram must arrive")
        .expect("a bad datagram must not be reported as a receive failure");
        assert_eq!(&packet[..], b"after-bad");
    }

    /// One receive call hands the packet task every datagram already queued, up to a batch of
    /// 64, in arrival order (#260, J582). With one datagram per call, the macOS packet task
    /// paid a full loop turn per returning ACK while it also encrypted the bulk send, so the
    /// receive queue sat full and probe replies waited 5–15 ms (p99) in Mac-send with 8 flows.
    #[tokio::test]
    async fn one_receive_call_drains_the_queued_datagrams_in_order() {
        let script = Script((0..100_u8).map(|i| Ok(datagram(&[i]))).collect());
        let mut receiver = BufferedUdpReceive::new(128, script, PacketBufPool::new(128));
        for _ in 0..10_000 {
            if receiver.recv_rx.len() == 100 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(
            receiver.recv_rx.len(),
            100,
            "the receive task queues all 100"
        );

        let mut pool = PacketBufPool::new(1);
        let mut packets = Vec::new();
        receiver
            .recv_many_from(&mut (), &mut pool, &mut packets)
            .await
            .expect("queued datagrams");
        let first: Vec<u8> = packets.drain(..).map(|(p, _)| p[0]).collect();
        assert_eq!(
            first,
            (0..64).collect::<Vec<u8>>(),
            "a full batch, in order"
        );

        receiver
            .recv_many_from(&mut (), &mut pool, &mut packets)
            .await
            .expect("queued datagrams");
        let rest: Vec<u8> = packets.drain(..).map(|(p, _)| p[0]).collect();
        assert_eq!(
            rest,
            (64..100).collect::<Vec<u8>>(),
            "the rest, without waiting"
        );
    }

    /// A gone socket is still reported, and the receive task then stops.
    #[tokio::test]
    async fn closed_socket_still_stops_the_receiver() {
        let script = Script([Err(io::Error::from_raw_os_error(libc::EBADF))].into());
        let mut receiver = BufferedUdpReceive::new(16, script, PacketBufPool::new(4));
        let mut pool = PacketBufPool::new(1);

        let first = receiver.recv_from(&mut pool).await;
        assert_eq!(
            first.err().and_then(|e| e.raw_os_error()),
            Some(libc::EBADF)
        );
        let second = receiver.recv_from(&mut pool).await;
        assert_eq!(
            second.err().map(|e| e.kind()),
            Some(io::ErrorKind::BrokenPipe)
        );
    }

    #[test]
    fn only_a_gone_socket_is_fatal() {
        use crate::udp::is_fatal_udp_error;
        for kind in [
            io::ErrorKind::InvalidData,
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::WouldBlock,
        ] {
            assert!(!is_fatal_udp_error(&io::Error::from(kind)), "{kind:?}");
        }
        for err in [
            io::Error::from_raw_os_error(libc::EBADF),
            io::Error::from_raw_os_error(libc::ENOTSOCK),
            io::Error::from(io::ErrorKind::UnexpectedEof),
            io::Error::from(io::ErrorKind::BrokenPipe),
        ] {
            assert!(is_fatal_udp_error(&err), "{err:?}");
        }
    }

    #[tokio::test]
    /// Regression test for security advisory GHSA-6gxq-8xp9-742r.
    async fn empty_loopback_datagram_mustnt_stop_buffered_udp_receive() {
        let socket = UdpSocket::bind("127.0.0.1:0".parse().unwrap(), SockOpt::default()).unwrap();
        let addr = socket.local_addr().unwrap();
        let mut receiver = BufferedUdpReceive::new(16, socket, PacketBufPool::new(16));
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();

        sender.send_to(&[], addr).unwrap();
        sender.send_to(b"after-empty", addr).unwrap();

        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            receiver.recv_from(&mut PacketBufPool::new(1)),
        )
        .await
        .expect("the receive task must stop promptly")
        .expect("the panicked receive task must not close its channel");
    }
}

/// Reply lane tests (#260, J720). These run on every target, the Mac included.
#[cfg(test)]
mod reply_lane_test {
    use super::*;

    /// Hands out scripted datagrams, then waits forever.
    struct Script(std::collections::VecDeque<(Packet, SocketAddr)>);

    impl UdpRecv for Script {
        type RecvManyBuf = ();

        async fn recv_from(
            &mut self,
            _pool: &mut PacketBufPool,
        ) -> io::Result<(Packet, SocketAddr)> {
            match self.0.pop_front() {
                Some(item) => Ok(item),
                None => std::future::pending().await,
            }
        }
    }

    /// A datagram of `len` bytes whose first byte is `id`.
    fn datagram(len: usize, id: u8) -> (Packet, SocketAddr) {
        let mut bytes = bytes::BytesMut::zeroed(len);
        bytes[0] = id;
        (
            Packet::from_bytes(bytes),
            "192.0.2.1:51820".parse().unwrap(),
        )
    }

    async fn drained(lane: bool) -> Vec<u8> {
        let script = [
            datagram(1452, 1),
            datagram(1452, 2),
            datagram(96, 3),
            datagram(1452, 4),
            datagram(156, 5),
        ];
        let mut receiver = BufferedUdpReceive::with_reply_lane(
            16,
            Script(script.into()),
            PacketBufPool::new(8),
            lane,
        );
        // The receive task queues all five before the first call takes them.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let mut pool = PacketBufPool::new(1);
        let mut packets = Vec::new();
        let mut ids = Vec::new();
        while ids.len() < 5 {
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                receiver.recv_many_from(&mut (), &mut pool, &mut packets),
            )
            .await
            .expect("queued datagrams")
            .expect("the script never fails");
            ids.extend(packets.drain(..).map(|(p, _)| p[0]));
        }
        ids
    }

    /// Records the first byte of every datagram that reaches the socket. Each send call first
    /// takes a permit from `gate`, so the test can hold the first run in flight while more queue.
    #[derive(Clone)]
    struct GatedSend {
        gate: Arc<Semaphore>,
        sent: mpsc::UnboundedSender<u8>,
    }

    impl UdpSend for GatedSend {
        type SendManyBuf = ();

        async fn send_to(&self, packet: Packet, _destination: SocketAddr) -> io::Result<()> {
            self.gate.acquire().await.expect("open gate").forget();
            self.sent.send(packet[0]).expect("the test listens");
            Ok(())
        }
    }

    async fn sent_order(lane: bool) -> Vec<u8> {
        let gate = Arc::new(Semaphore::new(0));
        let (sent_tx, mut sent_rx) = mpsc::unbounded_channel();
        // Queued only: this test holds the send task at the gate (the direct path would hold
        // the caller there instead).
        let send = BufferedUdpSend::with_send_turn(
            64,
            GatedSend {
                gate: Arc::clone(&gate),
                sent: sent_tx,
            },
            lane,
            0,
            false,
        );
        let mut buf = ();
        // A bulk run the send task takes and holds at the gate.
        send.send_many_to(&mut buf, &mut vec![datagram(1452, 1), datagram(1452, 2)])
            .await
            .expect("queued");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        // Queued while it waits: another bulk run, then a run with a probe reply.
        send.send_many_to(&mut buf, &mut vec![datagram(1452, 3), datagram(1452, 4)])
            .await
            .expect("queued");
        send.send_many_to(&mut buf, &mut vec![datagram(1452, 5), datagram(124, 6)])
            .await
            .expect("queued");
        gate.add_permits(16);
        let mut order = Vec::new();
        while order.len() < 6 {
            order.push(
                tokio::time::timeout(std::time::Duration::from_secs(2), sent_rx.recv())
                    .await
                    .expect("all six are sent")
                    .expect("the send task holds the sender"),
            );
        }
        order
    }

    /// With the lane, a small datagram queued behind bulk runs is sent before them (the run in
    /// flight finishes first). Without it, the send queue is a FIFO.
    #[tokio::test]
    async fn small_datagrams_overtake_queued_send_runs() {
        assert_eq!(sent_order(false).await, [1, 2, 3, 4, 5, 6]);
        assert_eq!(sent_order(true).await, [1, 2, 6, 3, 4, 5]);
    }

    /// Logs `s` for every datagram that reaches the socket.
    #[derive(Clone)]
    struct LoggingSend(Arc<std::sync::Mutex<String>>);

    impl UdpSend for LoggingSend {
        type SendManyBuf = ();

        async fn send_to(&self, _packet: Packet, _destination: SocketAddr) -> io::Result<()> {
            self.0.lock().expect("log").push('s');
            Ok(())
        }
    }

    /// The longest unbroken run of sends while a competing task (`o`, standing in for the
    /// receive task a reply wakes) wants the same current-thread runtime.
    async fn longest_send_run(yield_every: usize) -> (usize, String) {
        let log = Arc::new(std::sync::Mutex::new(String::new()));
        let send = BufferedUdpSend::with_send_turn(
            64,
            LoggingSend(Arc::clone(&log)),
            false,
            yield_every,
            false,
        );
        let mut run = (1..=8).map(|id| datagram(1452, id)).collect::<Vec<_>>();
        send.send_many_to(&mut (), &mut run).await.expect("queued");
        let competitor_log = Arc::clone(&log);
        let competitor = tokio::spawn(async move {
            while competitor_log.lock().expect("log").matches('s').count() < 8 {
                competitor_log.lock().expect("log").push('o');
                tokio::task::yield_now().await;
            }
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), competitor)
            .await
            .expect("all eight are sent")
            .expect("the competitor never panics");
        let log = log.lock().expect("log").clone();
        (log.split('o').map(str::len).max().unwrap_or(0), log)
    }

    /// With a send-turn budget, the send task gives the runtime back after that many datagrams,
    /// so a ready receive runs between them. Without it, one queued run leaves in one turn.
    /// Tokio wakes the tasks deferred by a yield as one batch, so two budgets may still run back
    /// to back (the Mac VM logged `ssoossssooss`); the bound is therefore twice the budget.
    #[tokio::test]
    async fn send_turn_budget_lets_other_tasks_run_between_datagrams() {
        let (off, log) = longest_send_run(0).await;
        assert_eq!(off, 8, "{log}");
        let (on, log) = longest_send_run(2).await;
        assert!(on <= 4, "{log}");
    }

    /// With the lane, small datagrams queued behind bulk ones are handed over first, each class
    /// in arrival order. Without it, the queue is a FIFO.
    #[tokio::test]
    async fn small_datagrams_overtake_queued_bulk() {
        assert_eq!(drained(false).await, [1, 2, 3, 4, 5]);
        assert_eq!(drained(true).await, [3, 5, 1, 2, 4]);
    }

    /// With the direct path, a run sent while the socket is idle leaves in the caller's task:
    /// it has reached the socket when `send_many_to` returns (#260, J1122).
    #[tokio::test]
    async fn idle_direct_sender_sends_in_the_callers_task() {
        let gate = Arc::new(Semaphore::new(16));
        let (sent_tx, mut sent_rx) = mpsc::unbounded_channel();
        let send = BufferedUdpSend::with_send_turn(
            8,
            GatedSend {
                gate,
                sent: sent_tx,
            },
            false,
            0,
            true,
        );
        let mut run = vec![datagram(1452, 1), datagram(1452, 2)];
        send.send_many_to(&mut (), &mut run).await.unwrap();
        assert!(run.is_empty());
        let (packet, address) = datagram(1452, 3);
        send.send_to(packet, address).await.unwrap();
        let sent: Vec<u8> = std::iter::from_fn(|| sent_rx.try_recv().ok()).collect();
        assert_eq!(sent, [1, 2, 3]);
    }

    /// While a direct send holds the socket, later runs queue, and the queue keeps going to
    /// the send task until it is empty again: the socket sees 1..=6 in order (#260, J1122).
    #[tokio::test]
    async fn busy_direct_sender_queues_in_order() {
        let gate = Arc::new(Semaphore::new(0));
        let (sent_tx, mut sent_rx) = mpsc::unbounded_channel();
        let send = BufferedUdpSend::with_send_turn(
            64,
            GatedSend {
                gate: Arc::clone(&gate),
                sent: sent_tx,
            },
            false,
            0,
            true,
        );
        let first = send.clone();
        let first = tokio::spawn(async move {
            first
                .send_many_to(&mut (), &mut vec![datagram(1452, 1), datagram(1452, 2)])
                .await
        });
        // Wait until the first run holds the direct path, mid-send.
        for _ in 0..200 {
            if send
                .direct
                .as_ref()
                .is_some_and(|direct| direct.try_write(&mut Vec::new()).is_none())
            {
                break;
            }
            tokio::task::yield_now().await;
        }
        for run in [[3, 4], [5, 6]] {
            let mut run = run.map(|id| datagram(1452, id)).to_vec();
            tokio::time::timeout(
                std::time::Duration::from_secs(1),
                send.send_many_to(&mut (), &mut run),
            )
            .await
            .expect("a busy socket queues the run instead of waiting")
            .unwrap();
        }
        gate.add_permits(16);
        first.await.unwrap().unwrap();
        let mut order = Vec::new();
        while order.len() < 6 {
            order.push(
                tokio::time::timeout(std::time::Duration::from_secs(2), sent_rx.recv())
                    .await
                    .expect("all six are sent")
                    .expect("the send task holds the sender"),
            );
        }
        assert_eq!(order, [1, 2, 3, 4, 5, 6]);
    }
}
