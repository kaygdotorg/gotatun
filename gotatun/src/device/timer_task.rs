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

//! The device's timer task: it runs each peer's WireGuard timers when they are due and sends
//! what they produce (keepalives, handshake initiations) in the peer's output order.
//!
//! The packets one pass over the due peers produces are held until the pass ends (or the batch
//! is full) and then handed to the UDP writer back to back ([`PassOutbox`]), so thousands of
//! idle peers' keepalives and retries wake the writer once per batch, not once each
//! (infraternal #260, J1253).
//!
//! The task sleeps until the earliest deadline in the device's [`TimerQueue`] and visits only the
//! peers that are due. What one visit does is unchanged from the old 250 ms poll over every peer
//! (infraternal #260, J1111): run `update_timers` under the peer lock, then hand its packet to
//! the peer's ordered output lane. After the visit the tunnel reports its next deadline, at
//! least one tick away. See `timer_queue` for the timing rules and `noise::timers::deadline` for
//! how a tunnel computes its deadline.
//!
//! When no peer has a pending deadline, the task sleeps indefinitely on [`TimerQueue::notified`]
//! (zero idle wakeups; #260, J1150). On Linux, timed waits use a `CLOCK_BOOTTIME` `timerfd` so
//! the sleep tracks the same clock as `sleepyinstant` across system suspend without periodic
//! polling. The first pass after start or resume visits every peer once so no initial deadline
//! can be missed.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;

use super::parallel_crypto::{CryptoHandle, OrderStore};
use super::peer_state::PeerState;
use super::timer_queue::TimerQueue;
use super::{
    OutgoingPeerContext, PacketLookup, PacketTaskHandles, PeerLockDiagnostic,
    complete_outgoing_packet, lock_peer_state, peer_order_key,
};
use crate::noise::errors::WireGuardError;
use crate::noise::index_table::IndexTable;
use crate::noise::{PreparedOutgoing, TIMER_TICK};
use crate::packet::{Packet, WgKind};
use crate::udp::UdpSend;

/// The most packets a pass holds before it sends them, one UDP batch's worth.
const OUTBOX_PACKETS: usize = 64;

/// The packets a timer pass has produced but not yet sent.
///
/// A UDP writer in front of the device's writer: while a batch is open, [`UdpSend::send_to`]
/// holds the packet and returns; [`PassOutbox::flush`] sends the held ones back to back. With no
/// batch open it sends at once, so a packet whose ordered output slot is released after its
/// pass ended is not held back. Clones share the batch.
#[derive(Clone)]
struct PassOutbox<U> {
    /// The device's UDP writer.
    udp: U,
    /// `Some` while a pass is collecting; the lock is never held across an await.
    held: Held,
}

/// An outbox's shared batch.
type Held = Arc<parking_lot::Mutex<Option<Batch>>>;

/// Packets waiting to be sent, each with its destination.
type Batch = Vec<(Packet, SocketAddr)>;

impl<U: UdpSend> PassOutbox<U> {
    /// An outbox in front of `udp`, collecting nothing yet.
    fn new(udp: U) -> Self {
        Self {
            udp,
            held: Arc::default(),
        }
    }

    /// Start (or continue) collecting.
    fn open(&self) {
        self.held.lock().get_or_insert_with(Vec::new);
    }

    /// Whether the open batch has reached [`OUTBOX_PACKETS`].
    fn is_full(&self) -> bool {
        self.held
            .lock()
            .as_ref()
            .is_some_and(|batch| batch.len() >= OUTBOX_PACKETS)
    }

    /// Close the batch and send what it holds, in order. A fatal socket error stops the device
    /// through `failures`, as it would have for a packet sent at once; other errors drop that
    /// packet only.
    async fn flush(&self, failures: &OrderStore<WgKind>) {
        let Some(batch) = self.held.lock().take() else {
            return;
        };
        for (packet, destination) in batch {
            match self.udp.send_to(packet, destination).await {
                Err(err) if crate::udp::is_fatal_udp_error(&err) => {
                    failures.fail(format!("UDP send failed: {err}"));
                }
                Err(_) => tracing::trace!("udp.send_to failed"),
                Ok(()) => {}
            }
        }
    }
}

impl<U: UdpSend> UdpSend for PassOutbox<U> {
    type SendManyBuf = U::SendManyBuf;

    /// Hold `packet` while a batch is open, else send it now.
    async fn send_to(&self, packet: Packet, destination: SocketAddr) -> io::Result<()> {
        let unsent = match self.held.lock().as_mut() {
            Some(batch) => {
                batch.push((packet, destination));
                None
            }
            None => Some(packet),
        };
        match unsent {
            Some(packet) => self.udp.send_to(packet, destination).await,
            None => Ok(()),
        }
    }
}

/// How often stale session indices are dropped from the packet lookup at most.
///
/// The old poll did it every 250 ms. It costs a pass over every live index, and a stale index
/// only maps a dead session to its peer (its packets are dropped there), so once a second while
/// timers are firing is enough.
const RETAIN_INDICES_EVERY: Duration = Duration::from_secs(1);

/// Sleeps until the next timer deadline on the same clock as [`TimerQueue`].
///
/// On Linux (outside `mock_instant` tests) this wraps a `CLOCK_BOOTTIME` `timerfd` in
/// [`tokio::io::unix::AsyncFd`], so the kernel wakes the task at the exact deadline even across
/// system suspend with zero intermediate wakeups (#260, J1150). On other platforms (where
/// `sleepyinstant` already shares Tokio's monotonic clock) or if `timerfd_create` fails, it falls
/// back to [`tokio::time::sleep`].
struct DeadlineSleeper {
    #[cfg(all(target_os = "linux", not(feature = "mock_instant")))]
    timerfd: Option<tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>>,
}

impl DeadlineSleeper {
    /// Create a sleeper, opening a `CLOCK_BOOTTIME` `timerfd` on Linux when available.
    fn new() -> Self {
        #[cfg(all(target_os = "linux", not(feature = "mock_instant")))]
        {
            use std::os::fd::{FromRawFd, OwnedFd};
            // SAFETY: timerfd_create takes only integer flags and returns a new owned fd or -1.
            let fd = unsafe {
                libc::timerfd_create(libc::CLOCK_BOOTTIME, libc::TFD_NONBLOCK | libc::TFD_CLOEXEC)
            };
            let timerfd = if fd >= 0 {
                // SAFETY: `fd` is a valid, freshly created descriptor owned exclusively here.
                let owned = unsafe { OwnedFd::from_raw_fd(fd) };
                tokio::io::unix::AsyncFd::new(owned).ok()
            } else {
                None
            };
            Self { timerfd }
        }
        #[cfg(not(all(target_os = "linux", not(feature = "mock_instant"))))]
        {
            Self {}
        }
    }

    /// Disarm any pending `timerfd` so an old deadline cannot fire while sleeping indefinitely.
    fn disarm(&self) {
        #[cfg(all(target_os = "linux", not(feature = "mock_instant")))]
        if let Some(timerfd) = &self.timerfd {
            use std::os::fd::AsRawFd;
            let zero = libc::itimerspec {
                it_interval: libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                },
                it_value: libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                },
            };
            // SAFETY: valid owned timerfd and properly initialized `itimerspec`.
            unsafe {
                libc::timerfd_settime(timerfd.as_raw_fd(), 0, &zero, std::ptr::null_mut());
            }
        }
    }

    /// Sleep for `duration` (must be non-zero).
    async fn sleep(&self, duration: Duration) {
        #[cfg(all(target_os = "linux", not(feature = "mock_instant")))]
        if let Some(timerfd) = &self.timerfd {
            use std::os::fd::AsRawFd;
            // Clamp to a safe positive `time_t` so extreme durations never overflow `tv_sec`.
            let secs = i64::try_from(duration.as_secs()).unwrap_or(i64::MAX / 2);
            let nsecs = i64::from(duration.subsec_nanos());
            // A zero `it_value` disarms a timerfd; ensure at least 1 ns for any non-zero sleep.
            let (tv_sec, tv_nsec) = if secs == 0 && nsecs == 0 {
                (0, 1)
            } else {
                (secs, nsecs)
            };
            let spec = libc::itimerspec {
                it_interval: libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                },
                it_value: libc::timespec { tv_sec, tv_nsec },
            };
            // SAFETY: valid owned timerfd and properly initialized `itimerspec`.
            let armed = unsafe {
                libc::timerfd_settime(timerfd.as_raw_fd(), 0, &spec, std::ptr::null_mut())
            };
            if armed == 0 {
                loop {
                    let Ok(mut guard) = timerfd.readable().await else {
                        break;
                    };
                    let mut expirations = 0_u64;
                    // SAFETY: reading an 8-byte expiration counter from our own timerfd.
                    let n = unsafe {
                        libc::read(
                            timerfd.as_raw_fd(),
                            (&raw mut expirations).cast::<libc::c_void>(),
                            std::mem::size_of::<u64>(),
                        )
                    };
                    if n == std::mem::size_of::<u64>() as isize {
                        return;
                    }
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::WouldBlock {
                        guard.clear_ready();
                        continue;
                    }
                    break;
                }
            }
        }
        tokio::time::sleep(duration).await;
    }
}

/// What a peer visit needs besides the peer: the shared packet and output state.
struct TimerContext<'a, U: UdpSend> {
    /// Peer and session-index maps; tells whether a peer is still configured.
    lookup: &'a PacketLookup,
    /// Per-peer ordered output lanes; a timer packet takes a slot like any other.
    outgoing_order: &'a Arc<OrderStore<WgKind>>,
    /// Worker pool handle for packet encryption.
    crypto: &'a CryptoHandle,
    /// UDP writer for the packets the timers produce, batching one pass's worth.
    udp: &'a PassOutbox<U>,
    /// The device's deadline queue.
    queue: &'a TimerQueue,
}

/// Run peers' timers when they are due until the device goes away.
///
/// `queue` must be the queue the device's peers report to (`DeviceState::timer_queue`). The
/// first pass visits every peer, as after a start or a resume nothing is known to be current.
pub(super) async fn run(
    handles: PacketTaskHandles,
    queue: Arc<TimerQueue>,
    index_table: IndexTable,
    udp: impl UdpSend,
    crypto: CryptoHandle,
    outgoing_order: Arc<OrderStore<WgKind>>,
) {
    let PacketTaskHandles {
        liveness: device,
        lookup: packet_lookup,
        flush_requests: _,
    } = handles;
    let outbox = PassOutbox::new(udp);
    let context = TimerContext {
        lookup: &packet_lookup,
        outgoing_order: &outgoing_order,
        crypto: &crypto,
        udp: &outbox,
        queue: &queue,
    };
    let sleeper = DeadlineSleeper::new();
    let mut initial_pass = true;
    let mut last_retain: Option<Duration> = None;
    loop {
        if device.upgrade().is_none() {
            break;
        }
        let now = queue.now();
        let due = if initial_pass {
            // First pass after start or resume visits every peer once so no initial deadline
            // can be missed.
            initial_pass = false;
            queue.take_due(now);
            packet_lookup.peers()
        } else {
            queue.take_due(now)
        };

        if !due.is_empty() {
            // Remove stale session indices. Once a session is stale it is dropped by
            // `update_session_timers`, and its associated index is freed from the table.
            if last_retain.is_none_or(|at| now >= at + RETAIN_INDICES_EVERY) {
                packet_lookup.retain_live_indices(&index_table);
                last_retain = Some(now);
            }
        }

        // This snapshot owns peer handles and does not retain lookup state during timer work.
        for peer in due {
            outbox.open();
            visit_peer(peer, &context).await;
            if outbox.is_full() {
                outbox.flush(&outgoing_order).await;
            }
        }
        outbox.flush(&outgoing_order).await;

        let now = queue.now();
        match queue.sleep_for(now) {
            Some(sleep) if sleep.is_zero() => {
                // Something is due already; yield so other tasks run between passes.
                tokio::task::yield_now().await;
            }
            Some(sleep) => {
                tokio::select! {
                    () = sleeper.sleep(sleep) => {}
                    () = queue.notified() => {}
                }
            }
            None => {
                sleeper.disarm();
                queue.notified().await;
            }
        }
    }
}

/// Run one peer's due timers and send what they produce, then report its next deadline.
async fn visit_peer<U: UdpSend>(peer: Arc<Mutex<PeerState>>, context: &TimerContext<'_, U>) {
    let TimerContext {
        lookup: packet_lookup,
        outgoing_order,
        crypto,
        udp,
        queue,
    } = context;
    let peer_key = peer_order_key(&peer);
    if outgoing_order.is_flushing(peer_key) {
        // A control flush owns the lane; try again on the next tick, as the old poll did.
        queue.set(&Arc::downgrade(&peer), Some(TIMER_TICK));
        return;
    }
    let mut peer_trace = PeerLockDiagnostic::waiting("timer", peer_key);
    let mut p = lock_peer_state(&peer, "timer", peer_key, &mut peer_trace).await;
    if !packet_lookup.contains_peer(&peer) {
        // Removed while we waited: nothing to run and nothing to schedule.
        return;
    }
    let endpoint_addr = match p.endpoint().addr {
        Some(addr) => addr,
        None => {
            // Nothing can be sent without an endpoint. The peer is scheduled again by any timer
            // its traffic arms or by a configured endpoint.
            p.tunnel.unschedule_timers();
            return;
        }
    };
    if outgoing_order.is_flushing(peer_key) || outgoing_order.available(peer_key) == 0 {
        // Leave due timers untouched until a bounded output slot is available, and look again
        // on the next tick.
        p.tunnel.reschedule_timers(TIMER_TICK);
        return;
    }

    let result = p.update_timers();
    // Whatever ran, the next visit is at least one tick away, as with the old poll.
    p.tunnel.reschedule_timers(TIMER_TICK);
    match result {
        Ok(Some(packet)) => {
            // All slot producers for this peer hold its state lock, except for a
            // control flush that is marked above. The free-slot check therefore
            // remains valid until this reservation.
            let Some((lane, slot)) = outgoing_order.reserve(peer_key) else {
                tracing::warn!("Deferring timer packet because the peer order window filled");
                return;
            };

            let registered = packet_lookup.register_handshake_idx(&packet, &peer);
            drop(p);
            drop(peer_trace);
            // NOTE: we don't bother with triggering TunnelRecv DAITA events here.
            complete_outgoing_packet(
                OutgoingPeerContext {
                    crypto: (*crypto).clone(),
                    ordered: Arc::clone(outgoing_order),
                    peer_arc: Arc::clone(&peer),
                    peer_key,
                    peer_addr: endpoint_addr,
                    udp: (*udp).clone(),
                },
                lane,
                slot,
                // A peer removed since the lock was taken gets its slot released, not filled.
                registered.then_some(PreparedOutgoing::Ready(packet)),
                false,
            )
            .await;
        }
        Ok(None) => {}
        Err(WireGuardError::ConnectionExpired) => {}
        Err(e) => tracing::error!("Timer error = {e:?}: {e:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::PacketBufPool;
    use std::net::Ipv4Addr;

    /// A UDP writer that records the length of every packet it is given.
    #[derive(Clone, Default)]
    struct Recording(Arc<parking_lot::Mutex<Vec<usize>>>);

    impl UdpSend for Recording {
        type SendManyBuf = ();

        /// Record the packet instead of sending it.
        async fn send_to(&self, packet: Packet, _: SocketAddr) -> io::Result<()> {
            self.0.lock().push(packet.len());
            Ok(())
        }
    }

    /// While a batch is open nothing is sent; the flush sends it all in order, and after it
    /// packets go out at once again.
    #[tokio::test]
    async fn a_pass_holds_its_packets_until_the_flush() {
        let recording = Recording::default();
        let outbox = PassOutbox::new(recording.clone());
        let pool = PacketBufPool::<4096>::new(8);
        let target: SocketAddr = (Ipv4Addr::LOCALHOST, 9).into();
        let packet = |len| {
            let mut packet = pool.get();
            packet.truncate(len);
            packet
        };

        outbox.open();
        for len in [32, 148, 32] {
            outbox.send_to(packet(len), target).await.unwrap();
        }
        assert!(recording.0.lock().is_empty(), "held while the pass runs");
        assert!(!outbox.is_full());

        let failures: OrderStore<WgKind> = OrderStore::default();
        outbox.flush(&failures).await;
        assert_eq!(*recording.0.lock(), vec![32, 148, 32]);

        outbox.send_to(packet(64), target).await.unwrap();
        assert_eq!(*recording.0.lock(), vec![32, 148, 32, 64]);
    }
}
