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
//! The task sleeps until the earliest deadline in the device's [`TimerQueue`] and visits only the
//! peers that are due. What one visit does is unchanged from the old 250 ms poll over every peer
//! (infraternal #260, J1111): run `update_timers` under the peer lock, then hand its packet to
//! the peer's ordered output lane. After the visit the tunnel reports its next deadline, at
//! least one tick away. See `timer_queue` for the timing rules and `noise::timers::deadline` for
//! how a tunnel computes its deadline.
//!
//! Every [`SAFETY_SWEEP`] the task also visits every peer, whatever its deadline. A visit is
//! always correct (it only does what is due), so a deadline report that went missing can delay a
//! timer by at most one sweep. Before each sweep visit the task checks that the peer's reported
//! deadline is no later than its real one, and counts the peers for which it is not
//! ([`TimerQueue::sweep_misses`], which must stay at zero).

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;

use super::parallel_crypto::{CryptoHandle, OrderStore};
use super::peer_state::PeerState;
use super::timer_queue::{MAX_SLEEP, SAFETY_SWEEP, TimerQueue};
use super::{
    OutgoingPeerContext, PacketLookup, PacketTaskHandles, PeerLockDiagnostic,
    complete_outgoing_packet, lock_peer_state, peer_order_key,
};
use crate::noise::errors::WireGuardError;
use crate::noise::index_table::IndexTable;
use crate::noise::{PreparedOutgoing, TIMER_TICK};
use crate::packet::WgKind;
use crate::udp::UdpSend;

/// How often stale session indices are dropped from the packet lookup at most.
///
/// The old poll did it every 250 ms. It costs a pass over every live index, and a stale index
/// only maps a dead session to its peer (its packets are dropped there), so once a second while
/// timers are firing, and on every sweep, is enough.
const RETAIN_INDICES_EVERY: Duration = Duration::from_secs(1);

/// What a peer visit needs besides the peer: the shared packet and output state.
struct TimerContext<'a, U: UdpSend> {
    /// Peer and session-index maps; tells whether a peer is still configured.
    lookup: &'a PacketLookup,
    /// Per-peer ordered output lanes; a timer packet takes a slot like any other.
    outgoing_order: &'a Arc<OrderStore<WgKind>>,
    /// Worker pool handle for packet encryption.
    crypto: &'a CryptoHandle,
    /// UDP writer for the packets the timers produce.
    udp: &'a U,
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
    let context = TimerContext {
        lookup: &packet_lookup,
        outgoing_order: &outgoing_order,
        crypto: &crypto,
        udp: &udp,
        queue: &queue,
    };
    let mut last_sweep: Option<Duration> = None;
    let mut last_retain: Option<Duration> = None;
    loop {
        if device.upgrade().is_none() {
            break;
        }
        let now = queue.now();
        let sweep = last_sweep.is_none_or(|at| now >= at + SAFETY_SWEEP);
        let due = if sweep {
            // The sweep visits everyone, so pending deadlines are served by it.
            queue.take_due(now);
            packet_lookup.peers()
        } else {
            queue.take_due(now)
        };

        if !due.is_empty() || sweep {
            // Remove stale session indices. Once a session is stale it is dropped by
            // `update_session_timers`, and its associated index is freed from the table.
            if sweep || last_retain.is_none_or(|at| now >= at + RETAIN_INDICES_EVERY) {
                packet_lookup.retain_live_indices(&index_table);
                last_retain = Some(now);
            }
        }

        // This snapshot owns peer handles and does not retain lookup state during timer work.
        for peer in due {
            visit_peer(peer, &context, sweep).await;
        }
        if sweep {
            last_sweep = Some(now);
        }

        let now = queue.now();
        let until_sweep =
            last_sweep.map_or(Duration::ZERO, |at| (at + SAFETY_SWEEP).saturating_sub(now));
        let sleep = queue.sleep_for(now, MAX_SLEEP.min(until_sweep));
        if sleep.is_zero() {
            // Something is due already; yield so other tasks run between passes.
            tokio::task::yield_now().await;
            continue;
        }
        tokio::select! {
            () = tokio::time::sleep(sleep) => {}
            () = queue.notified() => {}
        }
    }
}

/// Run one peer's due timers and send what they produce, then report its next deadline.
///
/// `check` asks for the sweep's consistency check first (see the module docs).
async fn visit_peer<U: UdpSend>(
    peer: Arc<Mutex<PeerState>>,
    context: &TimerContext<'_, U>,
    check: bool,
) {
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
            // its traffic arms, by a configured endpoint, or by the next sweep.
            p.tunnel.unschedule_timers();
            return;
        }
    };
    if check && !p.tunnel.timer_schedule_is_consistent() {
        queue.record_miss();
        tracing::warn!(
            misses = queue.sweep_misses(),
            "A peer's timer deadline was reported late; the sweep ran it"
        );
    }
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
