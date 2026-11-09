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

//! WireGuard device implementation with support for peers, handshakes, and packet routing.
pub(crate) mod allowed_ips;
mod builder;
pub mod configure;
#[cfg(feature = "daita")]
pub mod daita;
#[cfg(test)]
mod integration_tests;
mod parallel_crypto;
mod peer;
mod peer_state;
#[cfg(test)]
mod tests;
mod transports;
pub mod uapi;

use crate::noise::index_table::IndexTable;
use builder::Nul;
use futures::{FutureExt, StreamExt, TryFutureExt, future::BoxFuture, stream::FuturesUnordered};
use std::collections::HashMap;
use std::io::{self};
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::ops::BitOrAssign;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use std::time::Duration;
use tokio::join;
use tokio::sync::RwLock;
use tokio::sync::{Mutex, MutexGuard, watch};
use tracing::{Level, instrument};

use crate::noise::errors::WireGuardError;
use crate::noise::handshake::parse_handshake_anon;
use crate::noise::rate_limiter::RateLimiter;
use crate::noise::{PreparedDecryption, PreparedOutgoing, Tunn, TunnResult};
use crate::packet::{PacketBufPool, WgKind};
use crate::task::Task;
use crate::tun::{IpRecv, IpSend, MtuWatcher};
#[cfg(not(target_os = "linux"))]
use crate::udp::buffer::BufferedUdpReceive;
use crate::udp::buffer::BufferedUdpSend;
use crate::udp::{UdpRecv, UdpSend, UdpTransportFactory, UdpTransportFactoryParams};
use crate::x25519;
use allowed_ips::AllowedIps;
use parallel_crypto::{
    CRYPTO_BATCH_SIZE, CRYPTO_CHUNK_SIZE, CryptoHandle, CryptoWorkers, IncomingCompletion,
    OrderStore, OrderedCompletions,
};
use peer_state::{PeerState, PendingHandshake};

#[cfg(feature = "tun")]
pub use crate::device::transports::DefaultDeviceTransports;
pub use crate::device::transports::DeviceTransports;
pub use builder::DeviceBuilder;
pub use peer::Peer;

/// The number of handshakes per second to tolerate before using cookies
const HANDSHAKE_RATE_LIMIT: u64 = 100;

/// Maximum number of packet buffers that each channel may contain
const MAX_PACKET_BUFS: usize = 4000;

/// How often the receive task checks for an idle link.
///
/// After a load the packet pool, the allocator and the UDP receive buffers keep about
/// 7–22 MiB resident per endpoint (#260). Memory goes back to the OS at the end of the first
/// idle period after a busy one, so 5–10 s after traffic stops. A shorter pause keeps the
/// buffers warm. Coming back from idle costs a page fault per newly touched buffer page,
/// which is microseconds against a network round trip.
const IDLE_RELEASE_PERIOD: Duration = Duration::from_secs(5);

/// A period in which fewer packet buffers than this were taken counts as idle: under about
/// 13 packets/s, which covers keepalives (as often as every second) and other trickles that
/// need only a handful of buffers.
const IDLE_MAX_BUFFERS_PER_PERIOD: u32 = 64;

/// Whether this idle-check period ends a busy stretch, given the buffers taken in it.
///
/// `busy` remembers whether a busy period came since the last release, so a long quiet
/// stretch releases once rather than every period.
fn idle_release_due(busy: &mut bool, taken: u32) -> bool {
    if taken >= IDLE_MAX_BUFFERS_PER_PERIOD {
        *busy = true;
        false
    } else {
        std::mem::take(busy)
    }
}

/// Error of [`Device`]-related operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Multiple peers have the same public key
    #[error("Multiple peers have the same public key")]
    DuplicatePeer,

    /// I/O error
    #[error("i/o error: {0}")]
    IoError(#[from] io::Error),

    /// Failed to bind UDP sockets
    #[error("Failed to bind UDP sockets (params={1:?}): {0}")]
    Bind(#[source] io::Error, UdpTransportFactoryParams),

    /// TUN device error
    #[error("TUN device error: {0}")]
    #[cfg(feature = "tun")]
    TunDevice(#[from] crate::tun::tun_async_device::Error),

    /// Failed to initialize DAITA hooks
    #[error("Failed to initialize DAITA hooks")]
    #[cfg(feature = "daita")]
    DaitaHooks(#[from] daita::Error),

    /// No peer with the given public key exists
    #[error("No peer with the given public key exists")]
    PeerNotFound,

    /// The peer has no known endpoint
    #[error("The peer has no known endpoint")]
    NoEndpoint,

    /// The device has no active connection, e.g. because it is suspended
    #[error("The device has no active connection")]
    NotConnected,
}

/// Futures that finish one outgoing worker result and release it through the peer's order lane.
type PendingOutgoing = FuturesUnordered<BoxFuture<'static, ()>>;

/// Futures that finish one incoming worker result and release it toward the TUN in order.
type PendingIncoming = FuturesUnordered<BoxFuture<'static, Result<(), Error>>>;

/// Completion streams that a packet task must keep polling while it waits for peer state.
enum PendingCompletions<'a> {
    /// Receive-side completions can deliver packets and propagate device errors.
    Incoming(&'a mut PendingIncoming, &'a mut PendingOutgoing),
    /// A send-side task owns only its outgoing completion stream.
    Outgoing(&'a mut PendingOutgoing),
}

impl PendingCompletions<'_> {
    /// Report whether the owner task has any completion future that still needs polling.
    fn is_empty(&self) -> bool {
        match self {
            Self::Incoming(incoming, outgoing) => incoming.is_empty() && outgoing.is_empty(),
            Self::Outgoing(outgoing) => outgoing.is_empty(),
        }
    }

    /// Poll one completion so a queued mutex waiter can receive its granted permit.
    async fn next(&mut self) -> Result<(), Error> {
        match self {
            Self::Incoming(incoming, outgoing) => {
                tokio::select! {
                    completed = incoming.next(), if !incoming.is_empty() => {
                        completed.expect("a nonempty receive set has a completion future")
                    }
                    completed = outgoing.next(), if !outgoing.is_empty() => {
                        completed.expect("a nonempty send set has a completion future");
                        Ok(())
                    }
                }
            }
            Self::Outgoing(outgoing) => {
                outgoing
                    .next()
                    .await
                    .expect("a nonempty send set has a completion future");
                Ok(())
            }
        }
    }
}

/// Prepared authenticated work gathered from one peer in a receive batch.
struct PreparedIncomingRun {
    peer_key: usize,
    peer_arc: Arc<Mutex<PeerState>>,
    packets: Vec<(PreparedDecryption, std::net::SocketAddr)>,
}

/// Crypto stages and peer-order lanes shared by the UDP receive task.
struct CryptoOrderContext {
    /// Shared worker handle used by both packet directions.
    crypto: CryptoHandle,
    /// Per-peer receive lanes for ordered decryption and replay updates.
    incoming: Arc<OrderStore<IncomingCompletion>>,
    /// Per-peer send lanes for ordered UDP output.
    outgoing: Arc<OrderStore<WgKind>>,
}

/// Shared state needed to enqueue and release one bounded receive run.
struct IncomingRunContext<D, TunTx> {
    /// Shared worker handle used for each bounded run.
    crypto: CryptoHandle,
    /// Peer lanes that retain the receive sequence until TUN delivery.
    ordered: Arc<OrderStore<IncomingCompletion>>,
    /// Stable identity for this peer's lane.
    peer_key: usize,
    /// Ordered lane that owns the run's reserved sequence slots.
    lane: Arc<OrderedCompletions<IncomingCompletion>>,
    /// Peer state updated only after ordered replay validation.
    peer_arc: Arc<Mutex<PeerState>>,
    /// Device state accessed when delivering authenticated packets.
    device: Weak<RwLock<D>>,
    /// Tunnel writer cloned by each bounded delivery future.
    tun_tx: TunTx,
}

impl<D, TunTx: Clone> Clone for IncomingRunContext<D, TunTx> {
    /// Clone the shared handles needed by another run without cloning device state.
    fn clone(&self) -> Self {
        Self {
            crypto: self.crypto.clone(),
            ordered: Arc::clone(&self.ordered),
            peer_key: self.peer_key,
            lane: Arc::clone(&self.lane),
            peer_arc: Arc::clone(&self.peer_arc),
            device: self.device.clone(),
            tun_tx: self.tun_tx.clone(),
        }
    }
}

/// Shared peer and transport state for one outgoing packet sequence.
#[derive(Clone)]
struct OutgoingPeerContext<U: UdpSend> {
    /// Shared worker handle used for this packet sequence.
    crypto: CryptoHandle,
    /// Per-peer lane store used to retire the lane after ordered delivery.
    ordered: Arc<OrderStore<WgKind>>,
    /// Peer state used for DAITA send hooks when that feature is enabled.
    peer_arc: Arc<Mutex<PeerState>>,
    /// Stable identity for this peer's lane.
    peer_key: usize,
    /// Destination selected for this peer's encrypted packets.
    peer_addr: std::net::SocketAddr,
    /// UDP writer shared by each ordered completion.
    udp: U,
}

/// Batch-only resources for sending multiple ordered packets together.
struct OutgoingBatchContext<U: UdpSend> {
    /// Shared per-peer state for the encrypted packet run.
    peer: OutgoingPeerContext<U>,
    /// Reusable UDP batch buffer protected across send calls.
    send_many_buf: Arc<Mutex<U::SendManyBuf>>,
}

impl<U: UdpSend> Clone for OutgoingBatchContext<U> {
    /// Share the peer handles and reusable batch buffer with another outgoing chunk.
    fn clone(&self) -> Self {
        Self {
            peer: self.peer.clone(),
            send_many_buf: Arc::clone(&self.send_many_buf),
        }
    }
}

/// Stable key for a peer while its reference-counted state remains alive.
fn peer_order_key(peer: &Arc<Mutex<PeerState>>) -> usize {
    Arc::as_ptr(peer) as usize
}

/// Correlates peer-state lock waits and releases in an opt-in pipeline diagnostic run.
static NEXT_PEER_LOCK_DIAGNOSTIC_ID: AtomicU64 = AtomicU64::new(0);
static PEER_LOCK_DIAGNOSTICS_ENABLED: OnceLock<bool> = OnceLock::new();

/// Identifies the operation holding a peer-state lock when pipeline diagnostics are enabled.
///
/// Construct this before awaiting the mutex so its release log follows the guard's drop order.
struct PeerLockDiagnostic {
    id: u64,
    operation: &'static str,
    peer_key: usize,
    enabled: bool,
    acquired: bool,
}

impl PeerLockDiagnostic {
    /// Begin tracing one peer-state mutex wait.
    fn waiting(operation: &'static str, peer_key: usize) -> Self {
        let enabled = *PEER_LOCK_DIAGNOSTICS_ENABLED
            .get_or_init(|| crate::diag::pipeline() || crate::diag::send_queue());
        let id = NEXT_PEER_LOCK_DIAGNOSTIC_ID.fetch_add(1, Ordering::Relaxed);
        if enabled {
            eprintln!("peer_lock wait id={id} operation={operation} peer={peer_key}");
        }
        Self {
            id,
            operation,
            peer_key,
            enabled,
            acquired: false,
        }
    }

    /// Record that the mutex guard now belongs to this operation.
    fn acquired(&mut self) {
        self.acquired = true;
        if self.enabled {
            eprintln!(
                "peer_lock acquired id={} operation={} peer={}",
                self.id, self.operation, self.peer_key
            );
        }
    }
}

impl Drop for PeerLockDiagnostic {
    /// Log the scope ending after its mutex guard has been released.
    fn drop(&mut self) {
        if !self.enabled {
            return;
        }
        let stage = if self.acquired {
            "released"
        } else {
            "wait_cancelled"
        };
        eprintln!(
            "peer_lock {stage} id={} operation={} peer={}",
            self.id, self.operation, self.peer_key
        );
    }
}

/// Acquire one peer-state mutex while recording the operation that owns it.
async fn lock_peer_state<'a>(
    peer: &'a Arc<Mutex<PeerState>>,
    operation: &'static str,
    peer_key: usize,
    diagnostic: &mut PeerLockDiagnostic,
) -> MutexGuard<'a, PeerState> {
    debug_assert_eq!(diagnostic.operation, operation);
    debug_assert_eq!(diagnostic.peer_key, peer_key);
    let guard = peer.lock().await;
    diagnostic.acquired();
    guard
}

/// Wait for a peer lock while continuing to poll the completion futures owned by this task.
///
/// Completion futures are not spawned, so a child waiting ahead of its parent in Tokio's FIFO
/// mutex queue must be polled by the parent before the lock can make progress. Poll completions
/// first when work is pending, then keep the lock future pinned across completion polls. The empty
/// path awaits the lock directly so low-rate traffic pays no select-loop cost.
async fn await_while_completing<F, T>(
    future: F,
    pending: &mut PendingCompletions<'_>,
) -> Result<T, Error>
where
    F: std::future::Future<Output = T>,
{
    if pending.is_empty() {
        return Ok(future.await);
    }

    tokio::pin!(future);
    loop {
        tokio::select! {
            biased;
            completed = pending.next(), if !pending.is_empty() => completed?,
            output = &mut future => return Ok(output),
        }
    }
}

/// Acquire one peer-state mutex while its owner task continues draining earlier completions.
async fn lock_peer_state_while_completing<'a>(
    peer: &'a Arc<Mutex<PeerState>>,
    operation: &'static str,
    peer_key: usize,
    diagnostic: &mut PeerLockDiagnostic,
    pending: &mut PendingCompletions<'_>,
) -> Result<MutexGuard<'a, PeerState>, Error> {
    debug_assert_eq!(diagnostic.operation, operation);
    debug_assert_eq!(diagnostic.peer_key, peer_key);
    let guard = await_while_completing(peer.lock(), pending).await?;
    diagnostic.acquired();
    Ok(guard)
}

/// Group interleaved items by key while keeping each group's input order.
fn group_by_key<K, Metadata, Item>(
    items: impl IntoIterator<Item = (K, Metadata, Item)>,
) -> Vec<(K, Metadata, Vec<Item>)>
where
    K: Copy + Eq + std::hash::Hash,
{
    let mut indices = HashMap::new();
    let mut groups = Vec::new();
    for (key, metadata, item) in items {
        let index = if let Some(index) = indices.get(&key).copied() {
            index
        } else {
            let index = groups.len();
            groups.push((key, metadata, Vec::new()));
            indices.insert(key, index);
            index
        };
        groups[index].2.push(item);
    }
    groups
}

/// Drive local completions until this outgoing slot is delivered, even if later peer work remains.
async fn wait_for_outgoing_slot(
    lane: &OrderedCompletions<WgKind>,
    slot: u64,
    pending: &mut PendingOutgoing,
) {
    loop {
        tokio::select! {
            _ = lane.wait_delivered(slot) => return,
            _ = pending.next(), if !pending.is_empty() => {}
        }
    }
}

/// Apply one prepared outgoing packet and deliver newly ordered results to the peer's UDP path.
async fn complete_outgoing_packet<U: UdpSend>(
    context: OutgoingPeerContext<U>,
    lane: Arc<OrderedCompletions<WgKind>>,
    slot: u64,
    prepared: Option<PreparedOutgoing>,
    apply_daita: bool,
) {
    let OutgoingPeerContext {
        crypto,
        ordered,
        peer_arc,
        peer_key,
        peer_addr,
        udp,
    } = context;
    #[cfg(not(feature = "daita"))]
    let _ = apply_daita;
    #[cfg(not(feature = "daita"))]
    let _ = &peer_arc;

    let packets = crypto
        .encrypt_run(vec![prepared], false)
        .await
        .unwrap_or_else(|| vec![None]);

    let _ = lane
        .complete_run_traced("outgoing", peer_key, slot, packets, |mut packets| {
            #[cfg(feature = "daita")]
            let peer_arc = Arc::clone(&peer_arc);
            let udp = udp.clone();
            async move {
                let Some(packet) = packets.pop().flatten() else {
                    return Ok::<(), ()>(());
                };
                #[cfg(feature = "daita")]
                let packet = {
                    if apply_daita {
                        let peer_key = peer_order_key(&peer_arc);
                        let mut peer_trace =
                            PeerLockDiagnostic::waiting("outgoing_packet_daita", peer_key);
                        let mut peer = lock_peer_state(
                            &peer_arc,
                            "outgoing_packet_daita",
                            peer_key,
                            &mut peer_trace,
                        )
                        .await;
                        let packet = match peer.daita.as_mut() {
                            Some(daita) => daita.on_tunnel_sent(packet),
                            None => Some(packet),
                        };
                        drop(peer);
                        drop(peer_trace);
                        packet
                    } else {
                        Some(packet)
                    }
                };
                #[cfg(not(feature = "daita"))]
                let packet = Some(packet);

                if let Some(packet) = packet
                    && udp.send_to(packet.into(), peer_addr).await.is_err()
                {
                    tracing::trace!("udp.send_to failed");
                }
                Ok::<(), ()>(())
            }
        })
        .await;
    ordered.release_if_idle(peer_key, &lane);
}

/// Encrypt and release one peer's contiguous run through one worker handoff and UDP batch send.
async fn complete_outgoing_batch<U: UdpSend + 'static>(
    context: OutgoingBatchContext<U>,
    lane: Arc<OrderedCompletions<WgKind>>,
    first_slot: u64,
    prepared: Vec<Option<PreparedOutgoing>>,
    apply_daita: bool,
    force_worker: bool,
) {
    let OutgoingBatchContext {
        peer:
            OutgoingPeerContext {
                crypto,
                ordered,
                peer_arc,
                peer_key,
                peer_addr,
                udp,
            },
        send_many_buf,
    } = context;
    let count = prepared.len();
    let diagnostic = crate::diag::pipeline() || crate::diag::send_queue();
    if diagnostic {
        eprintln!(
            "pipeline stage=encrypt_start first_slot={first_slot} packets={count} dispatch={}",
            if force_worker { "worker" } else { "inline" }
        );
    }
    let packets = crypto
        .encrypt_run(prepared, force_worker)
        .await
        .unwrap_or_else(|| std::iter::repeat_with(|| None).take(count).collect());
    if diagnostic {
        let counters = packets.iter().filter_map(|packet| match packet {
            Some(WgKind::Data(packet)) => Some(packet.header.counter.get()),
            _ => None,
        });
        let (first_counter, last_counter) = {
            let mut counters = counters;
            let first = counters.next();
            let last = counters.next_back().or(first);
            (first, last)
        };
        eprintln!(
            "pipeline stage=encrypt_complete first_slot={first_slot} packets={count} counter_first={first_counter:?} counter_last={last_counter:?}"
        );
    }

    let _ = lane
        .complete_run_traced("outgoing", peer_key, first_slot, packets, |packets| {
            let peer_arc = Arc::clone(&peer_arc);
            let udp = udp.clone();
            let send_many_buf = Arc::clone(&send_many_buf);
            async move {
                let mut output = Vec::with_capacity(packets.len());
                #[cfg(feature = "daita")]
                let mut peer_trace = if apply_daita {
                    Some(PeerLockDiagnostic::waiting(
                        "outgoing_batch_daita",
                        peer_key,
                    ))
                } else {
                    None
                };
                #[cfg(feature = "daita")]
                let mut peer = if let Some(peer_trace) = peer_trace.as_mut() {
                    Some(
                        lock_peer_state(
                            &peer_arc,
                            "outgoing_batch_daita",
                            peer_key,
                            peer_trace,
                        )
                        .await,
                    )
                } else {
                    None
                };
                #[cfg(not(feature = "daita"))]
                let _ = (apply_daita, peer_arc);

                for packet in packets.into_iter().flatten() {
                    #[cfg(feature = "daita")]
                    let packet = if let Some(peer) = peer.as_mut() {
                        match peer.daita.as_mut() {
                            Some(daita) => daita.on_tunnel_sent(packet),
                            None => Some(packet),
                        }
                    } else {
                        Some(packet)
                    };
                    #[cfg(not(feature = "daita"))]
                    let packet = Some(packet);

                    if let Some(packet) = packet {
                        output.push((packet.into(), peer_addr));
                    }
                }

                #[cfg(feature = "daita")]
                drop(peer);
                #[cfg(feature = "daita")]
                drop(peer_trace);

                let output_count = output.len();
                if diagnostic {
                    eprintln!(
                        "pipeline stage=ordered_udp_release first_slot={first_slot} packets={output_count}"
                    );
                }
                match output.len() {
                    0 => {}
                    1 => {
                        let (packet, addr) = output.pop().expect("one packet was counted");
                        let result = udp.send_to(packet, addr).await;
                        if diagnostic {
                            eprintln!(
                                "pipeline stage=udp_queue_send first_slot={first_slot} packets=1 success={}",
                                result.is_ok()
                            );
                        }
                        if result.is_err() {
                            tracing::trace!("udp.send_to failed");
                        }
                    }
                    _ => {
                        let mut send_many_buf = send_many_buf.lock().await;
                        let result = udp.send_many_to(&mut send_many_buf, &mut output).await;
                        if diagnostic {
                            eprintln!(
                                "pipeline stage=udp_queue_send first_slot={first_slot} packets={output_count} success={}",
                                result.is_ok()
                            );
                        }
                        if result.is_err() {
                            tracing::trace!("udp.send_many_to failed");
                        }
                    }
                }
                Ok::<(), ()>(())
            }
        })
        .await;
    ordered.release_if_idle(peer_key, &lane);
}

/// A reference-counted handle to a WireGuard device.
pub struct Device<T: DeviceTransports> {
    inner: Arc<RwLock<DeviceState<T>>>,
    fatal_error: watch::Receiver<Option<Error>>,
}

/// Entry point for building a [`Device`].
///
/// See [`DeviceBuilder`] for options.
pub const fn build() -> DeviceBuilder<Nul, Nul, Nul> {
    DeviceBuilder::new()
}

pub(crate) struct DeviceState<T: DeviceTransports> {
    key_pair: Option<(x25519::StaticSecret, x25519::PublicKey)>,
    fwmark: Option<u32>,

    tun_tx: Arc<Mutex<T::IpSend>>,
    /// The tun device reader.
    ///
    /// This is `Arc<Mutex>`:ed because:
    /// - The task responsible from reading from the `tun_rx` must have ownership of it.
    /// - We must be able to claim the ownership after that task is stopped.
    ///
    /// This is implemented by the task taking the lock upon startup, and holding it until it is
    /// stopped.
    tun_rx: Arc<Mutex<T::IpRecv>>,

    /// MTU watcher of the TUN device.
    tun_rx_mtu: MtuWatcher,

    peers: HashMap<x25519::PublicKey, Arc<Mutex<PeerState>>>,
    peers_by_ip: AllowedIps<Arc<Mutex<PeerState>>>,
    peers_by_idx: parking_lot::Mutex<HashMap<u32, Arc<Mutex<PeerState>>>>,
    index_table: IndexTable,

    rate_limiter: Option<Arc<RateLimiter>>,

    port: u16,
    udp_factory: T::UdpTransportFactory,
    connection: Option<Connection<T>>,

    /// Whether the device has been suspended via [`Device::suspend`].
    ///
    /// While suspended, the [`Connection`] (and all its tasks) is torn down so no
    /// traffic flows, but peers, keys, and config are retained for [`Device::resume`].
    suspended: bool,

    /// The task that responds to API requests.
    api: Option<Task>,

    /// If an unrecoverable error occurs (such as the TUN device being deleted),
    /// it will be stored here and propagated to all [`Device`] handles.
    fatal_error: watch::Sender<Option<Error>>,
}

pub(crate) struct Connection<T: DeviceTransports> {
    udp: <T::UdpTransportFactory as UdpTransportFactory>::Send,

    /// Bounded workers shared by both packet directions for this connection.
    crypto_workers: CryptoWorkers,

    /// The task that reads IPv4 traffic from the UDP socket.
    incoming: Task,

    /// The task that handles keepalives/heartbeats/etc.
    timers: Task,

    /// The task that reads traffic from the TUN device.
    outgoing: Task,
}

impl<T: DeviceTransports> Connection<T> {
    #[instrument(level = Level::TRACE, skip_all, ret)]
    pub async fn set_up(device_arc: Arc<RwLock<DeviceState<T>>>) -> Result<(), Error> {
        let mut device = device_arc.write().await;

        // While suspended, no connection may be brought up: a reconfiguration
        // (adding a peer, changing the key/port, a UAPI `set=1`, ...) must not
        // silently resume the tunnel. The config change is still applied to
        // `DeviceState`; [`Device::resume`] brings the connection up afterwards
        // with the latest config.
        if device.suspended {
            return Ok(());
        }

        let pool = PacketBufPool::new_lazy(MAX_PACKET_BUFS);

        // clean up existing connection
        if let Some(conn) = device.connection.take() {
            conn.stop().await;
        }

        let (udp_tx, udp_rx) = device.open_listen_socket().await?;

        // Remember the bound port in case it was 0
        if let Some(addr) = udp_tx.local_addr()? {
            device.port = addr.port();
        }

        let (buffered_ip_tx, buffered_ip_rx) = crate::tun::buffer::channel(
            MAX_PACKET_BUFS,
            pool.clone(),
            Arc::clone(&device.tun_tx),
            Arc::clone(&device.tun_rx),
        )
        .await;

        let buffered_udp_tx = BufferedUdpSend::new(MAX_PACKET_BUFS, udp_tx.clone());

        // Linux sockets already return recvmmsg/GRO batches here. Avoid queueing them across a
        // second worker handoff before packet processing.
        #[cfg(target_os = "linux")]
        let incoming_udp_rx = udp_rx;
        #[cfg(not(target_os = "linux"))]
        let incoming_udp_rx = BufferedUdpReceive::new(MAX_PACKET_BUFS, udp_rx, pool.clone());

        // Start DAITA/hooks tasks
        #[cfg(feature = "daita")]
        for peer_arc in device.peers.values() {
            PeerState::maybe_start_daita(
                peer_arc,
                pool.clone(),
                device.tun_rx_mtu.clone(),
                buffered_udp_tx.clone(),
            )
            .await?;
        }

        let crypto_workers = CryptoWorkers::new()?;
        let crypto = crypto_workers.handle();
        let outgoing_order = Arc::new(OrderStore::default());
        let incoming_order = Arc::new(OrderStore::default());

        let fatal_error = device.fatal_error.clone();
        let register_fatal_error = move |e| {
            fatal_error.send_if_modified(|option| {
                let has_error = option.is_some();
                if !has_error {
                    *option = Some(e);
                }
                !has_error
            })
        };

        // Start device tasks
        let outgoing = Task::spawn(
            "handle_outgoing",
            DeviceState::handle_outgoing(
                Arc::downgrade(&device_arc),
                buffered_ip_rx,
                buffered_udp_tx.clone(),
                pool.clone(),
                crypto.clone(),
                Arc::clone(&outgoing_order),
            )
            .map_err(register_fatal_error.clone()),
        );
        let timers = Task::spawn(
            "handle_timers",
            DeviceState::handle_timers(
                Arc::downgrade(&device_arc),
                buffered_udp_tx.clone(),
                crypto.clone(),
                Arc::clone(&outgoing_order),
            ),
        );
        let incoming = Task::spawn(
            "handle_incoming",
            DeviceState::handle_incoming(
                Arc::downgrade(&device_arc),
                buffered_ip_tx.clone(),
                buffered_udp_tx,
                incoming_udp_rx,
                pool.clone(),
                CryptoOrderContext {
                    crypto,
                    incoming: incoming_order,
                    outgoing: Arc::clone(&outgoing_order),
                },
            )
            .map_err(register_fatal_error.clone()),
        );

        debug_assert!(device.connection.is_none());
        device.connection = Some(Connection {
            udp: udp_tx,
            crypto_workers,
            incoming,
            timers,
            outgoing,
        });

        Ok(())
    }
}

impl<T: DeviceTransports> Device<T> {
    /// Stop tunneling traffic and shut down the [`Device`].
    pub async fn stop(self) {
        Self::stop_inner(self.inner.clone()).await
    }

    async fn stop_inner(device: Arc<RwLock<DeviceState<T>>>) {
        tracing::debug!("Stopping device");

        let mut device = device.write().await;

        if let Some(api_task) = device.api.take() {
            api_task.stop().await;
        }

        if let Some(connection) = device.connection.take() {
            connection.stop().await;
        }
    }

    /// Suspend the device, stopping all tunnel activity.
    ///
    /// This tears down the connection and all its background tasks (timers,
    /// inbound, and outbound I/O), so no keepalives, handshakes, or data packets are
    /// sent or received. Peers, keys, and configuration are retained, and the device
    /// can be brought back with [`Device::resume`].
    ///
    /// This is primarily intended for platforms such as iOS, where the host process
    /// may be suspended by the system: an explicit suspend stops the timers (whose
    /// clock keeps advancing while suspended) from waking the process and flooding
    /// the link on resume.
    ///
    /// Calling this on an already-suspended device is a no-op.
    pub async fn suspend(&self) {
        tracing::debug!("Suspending device");

        let mut device = self.inner.write().await;

        if device.suspended {
            return;
        }

        if let Some(connection) = device.connection.take() {
            connection.stop().await;
        }

        device.suspended = true;
    }

    /// Resume a device that was suspended with [`Device::suspend`].
    ///
    /// This rebuilds the connection (rebinding sockets and respawning tasks).
    /// Existing sessions are cleared first, so the tunnel performs a fresh handshake
    /// rather than reusing a stale session.
    ///
    /// Calling this on a device that is not suspended is a no-op.
    pub async fn resume(&self) -> Result<(), Error> {
        tracing::debug!("Resuming device");

        {
            let mut device = self.inner.write().await;

            if !device.suspended {
                return Ok(());
            }

            // Force a fresh handshake on resume by dropping any existing sessions.
            for peer in device.peers.values() {
                let peer_key = peer_order_key(peer);
                let mut peer_trace = PeerLockDiagnostic::waiting("resume", peer_key);
                let mut peer = lock_peer_state(peer, "resume", peer_key, &mut peer_trace).await;
                peer.reset();
            }

            device.suspended = false;

            // Nothing to bring up if the device has no peers (and therefore no key).
            if device.peers.is_empty() {
                return Ok(());
            }
        }

        Connection::set_up(self.inner.clone()).await
    }

    /// Wait until there is a session with the peer with `public_key` that is not yet due for
    /// rekeying.
    ///
    /// Returns immediately if such a session exists. Otherwise, a handshake initiation is sent
    /// unless one is already in progress, and this waits until a handshake initiated by us
    /// completes. Note that this function never times out.
    ///
    /// Returns [`Error::PeerNotFound`] if the peer does not exist or is removed while waiting.
    pub async fn force_handshake(&self, public_key: &x25519::PublicKey) -> Result<(), Error> {
        let mut completed = {
            let device = self.inner.read().await;
            let connection = device.connection.as_ref().ok_or(Error::NotConnected)?;
            let peer_arc = device.peers.get(public_key).ok_or(Error::PeerNotFound)?;

            let peer_key = peer_order_key(peer_arc);
            let mut peer_trace = PeerLockDiagnostic::waiting("force_handshake", peer_key);
            let mut peer =
                lock_peer_state(peer_arc, "force_handshake", peer_key, &mut peer_trace).await;
            let Some(PendingHandshake {
                completed,
                initiation,
            }) = peer.force_handshake()?
            else {
                return Ok(());
            };

            if let Some((packet, endpoint_addr)) = initiation {
                let packet = WgKind::from(packet);
                DeviceState::<T>::register_handshake_idx(&device.peers_by_idx, &packet, peer_arc);
                drop(peer);
                drop(peer_trace);

                // NOTE: Like `handle_timers`, this does not trigger DAITA events.
                connection.udp.send_to(packet.into(), endpoint_addr).await?;
            }

            completed
        };

        // The sender is dropped along with the peer
        completed.changed().await.map_err(|_| Error::PeerNotFound)
    }

    /// Wait until an unrecoverable error occurs.
    pub async fn wait(&mut self) {
        self.fatal_error
            .wait_for(|err| err.is_some())
            .await
            .expect("Sender will not be dropped while Self exists");
    }
}

impl<T: DeviceTransports> Drop for Device<T> {
    fn drop(&mut self) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            tracing::warn!("Failed to get tokio runtime handle");
            return;
        };
        let device = self.inner.clone();
        handle.spawn(async move {
            Self::stop_inner(device).await;
        });
    }
}

/// Do we need to reconfigure the socket?
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reconfigure {
    Yes,
    No,
}

impl BitOrAssign for Reconfigure {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = match (*self, rhs) {
            (Reconfigure::No, Reconfigure::No) => Reconfigure::No,
            _ => Reconfigure::Yes,
        };
    }
}

impl<T: DeviceTransports> DeviceState<T> {
    async fn remove_peer(&mut self, pub_key: &x25519::PublicKey) -> Option<Arc<Mutex<PeerState>>> {
        if let Some(peer) = self.peers.remove(pub_key) {
            // Remove all session index entries that point to this peer
            self.peers_by_idx
                .lock()
                .retain(|_idx, p| !Arc::ptr_eq(&peer, p));
            self.peers_by_ip
                .remove(&|p: &Arc<Mutex<PeerState>>| Arc::ptr_eq(&peer, p));

            tracing::info!("Peer removed");

            Some(peer)
        } else {
            None
        }
    }

    fn add_peer(&mut self, peer_builder: Peer) {
        let pub_key = peer_builder.public_key;
        let allowed_ips = peer_builder.allowed_ips.clone();
        let peer = self.create_peer(peer_builder);
        let peer = Arc::new(Mutex::new(peer));

        self.peers.insert(pub_key, Arc::clone(&peer));

        for allowed_ip in allowed_ips {
            let addr = allowed_ip.network();
            let cidr = allowed_ip.prefix();
            self.peers_by_ip.insert(addr, cidr, Arc::clone(&peer));
        }

        tracing::info!("Peer added");
    }

    fn create_peer(&mut self, peer_builder: Peer) -> PeerState {
        let device_key_pair = self
            .key_pair
            .as_ref()
            .expect("Private key must be set first");
        let rate_limiter = self
            .rate_limiter
            .as_ref()
            .expect("Setting private key creates rate limiter")
            .clone();

        let mut tunn = Tunn::new(
            device_key_pair.0.clone(),
            peer_builder.public_key,
            peer_builder.preshared_key,
            peer_builder.keepalive,
            self.index_table.clone(),
            rate_limiter,
        );

        if let Some(timer_params) = peer_builder.danger_timer_params {
            tunn.dangerously_set_timer_params(timer_params);
        }

        PeerState::new(
            tunn,
            peer_builder.endpoint,
            peer_builder.allowed_ips.as_slice(),
            #[cfg(feature = "daita")]
            peer_builder.daita_settings,
        )
    }

    fn set_port(&mut self, port: u16) -> Reconfigure {
        if self.port == port {
            Reconfigure::No
        } else {
            self.port = port;
            Reconfigure::Yes
        }
    }

    /// Bind two UDP sockets. One for IPv4, one for IPv6.
    async fn open_listen_socket(
        &mut self,
    ) -> Result<
        (
            <T::UdpTransportFactory as UdpTransportFactory>::Send,
            <T::UdpTransportFactory as UdpTransportFactory>::Recv,
        ),
        Error,
    > {
        let params = UdpTransportFactoryParams {
            addr: None,
            port: self.port,
            #[cfg(target_os = "linux")]
            fwmark: self.fwmark,
        };
        let (udp_tx, udp_rx) = self
            .udp_factory
            .bind(&params)
            .await
            .map_err(|e| Error::Bind(e, params))?;
        Ok((udp_tx, udp_rx))
    }

    async fn set_key(&mut self, private_key: x25519::StaticSecret) -> Reconfigure {
        let public_key = x25519::PublicKey::from(&private_key);
        // x25519 (rightly) doesn't let us expose secret keys for comparison.
        // If the public keys are the same, then the private keys are the same.
        if let Some(key_pair) = self.key_pair.as_ref()
            && key_pair.1 == public_key
        {
            return Reconfigure::No;
        }

        let rate_limiter = Arc::new(RateLimiter::new(&public_key, HANDSHAKE_RATE_LIMIT));

        for peer in self.peers.values_mut() {
            let peer_key = peer_order_key(peer);
            let mut peer_trace = PeerLockDiagnostic::waiting("set_key", peer_key);
            let mut peer = lock_peer_state(peer, "set_key", peer_key, &mut peer_trace).await;
            peer.tunnel.set_static_private(
                private_key.clone(),
                public_key,
                Arc::clone(&rate_limiter),
            )
        }

        self.key_pair = Some((private_key, public_key));
        self.rate_limiter = Some(rate_limiter);

        Reconfigure::Yes
    }

    #[cfg(target_os = "linux")]
    fn set_fwmark(&mut self, mark: u32) -> Result<(), Error> {
        self.fwmark = Some(mark);

        if let Some(conn) = &mut self.connection {
            conn.udp.set_fwmark(mark)?;
        }

        // // Then on all currently connected sockets
        // for peer in self.peers.values() {
        //     if let Some(ref sock) = peer.delay_lock().endpoint().conn {
        //         sock.set_mark(mark)?
        //     }
        // }

        Ok(())
    }

    /// Remove all peers.
    ///
    /// # Returns
    /// Returns the number of peers removed.
    fn clear_peers(&mut self) -> usize {
        let n = self.peers.len();
        self.peers.clear();
        self.peers_by_idx.lock().clear();
        self.peers_by_ip.clear();
        // TODO: tear down connection?
        n
    }

    /// If `packet` is a handshake init or response, register its `sender_idx` in `peers_by_idx`.
    fn register_handshake_idx(
        peers_by_idx: &parking_lot::Mutex<HashMap<u32, Arc<Mutex<PeerState>>>>,
        packet: &WgKind,
        peer: &Arc<Mutex<PeerState>>,
    ) {
        let sender_idx = match packet {
            WgKind::HandshakeInit(p) => p.sender_idx.get(),
            WgKind::HandshakeResp(p) => p.sender_idx.get(),
            _ => return,
        };
        peers_by_idx.lock().insert(sender_idx, Arc::clone(peer));
    }

    /// Finish a contiguous receive run while holding peer state only once, retaining its first slot for diagnostics.
    async fn deliver_incoming_run(
        first_slot: u64,
        device: Weak<RwLock<Self>>,
        peer_arc: Arc<Mutex<PeerState>>,
        completions: Vec<Option<IncomingCompletion>>,
        mut tun_tx: impl IpSend,
    ) -> Result<(), Error> {
        let diagnostic = crate::diag::pipeline() || crate::diag::send_queue();
        let completion_count = completions.len();
        if diagnostic {
            eprintln!(
                "pipeline stage=incoming_delivery_callback_start completions={completion_count}"
            );
        }
        let Some(device_arc) = device.upgrade() else {
            return Ok(());
        };
        if diagnostic {
            eprintln!("pipeline stage=incoming_device_lock_wait");
        }
        let device_guard = device_arc.read().await;
        if diagnostic {
            eprintln!("pipeline stage=incoming_device_lock_acquired");
            eprintln!("pipeline stage=incoming_delivery_peer_lock_wait");
        }
        let peer_key = peer_order_key(&peer_arc);
        let mut peer_trace = PeerLockDiagnostic::waiting("incoming_delivery", peer_key);
        let mut peer =
            lock_peer_state(&peer_arc, "incoming_delivery", peer_key, &mut peer_trace).await;
        if diagnostic {
            eprintln!("pipeline stage=incoming_delivery_peer_lock_acquired");
        }
        let mut tunnel_result_count = 0;
        let mut empty_packet_count = 0;
        let mut malformed_packet_count = 0;
        let mut rejected_source_count = 0;
        let mut tun_packets = Vec::with_capacity(completions.len());

        for completion in completions.into_iter().flatten() {
            let result = peer.complete_incoming_data(completion.result, completion.addr);
            #[cfg_attr(not(feature = "daita"), expect(unused_mut))]
            let TunnResult::WriteToTunnel(mut packet) = result else {
                continue;
            };
            tunnel_result_count += 1;

            #[cfg(feature = "daita")]
            if let Some(daita) = peer.daita.as_mut() {
                match daita.on_data_recv(packet) {
                    Some(new) => packet = new,
                    None => continue,
                }
            }

            if packet.is_empty() {
                empty_packet_count += 1;
                continue;
            }
            let Ok(packet) = packet.try_into_ipvx() else {
                malformed_packet_count += 1;
                continue;
            };

            let (source, packet): (IpAddr, _) = packet.either(
                |ipv4| (ipv4.header.source().into(), ipv4.into()),
                |ipv6| (ipv6.header.source().into(), ipv6.into()),
            );
            let routed_to_this_peer = device_guard
                .peers_by_ip
                .find(source)
                .is_some_and(|owner| Arc::ptr_eq(owner, &peer_arc));
            if !routed_to_this_peer {
                if cfg!(debug_assertions) {
                    let unspecified = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into();
                    tracing::warn!(
                        "peer at {} is not allowed to send us packets from: {source}",
                        peer.endpoint().addr.unwrap_or(unspecified)
                    );
                }
                rejected_source_count += 1;
                continue;
            }
            tun_packets.push(packet);
        }

        drop(peer);
        drop(peer_trace);
        drop(device_guard);
        let tunnel_packet_count = tun_packets.len();
        if diagnostic {
            eprintln!(
                "pipeline stage=incoming_release completions={completion_count} tunnel_results={tunnel_result_count} empty={empty_packet_count} malformed={malformed_packet_count} rejected_source={rejected_source_count} queued={tunnel_packet_count}"
            );
            eprintln!("pipeline stage=tun_queue_send_start packets={tunnel_packet_count}");
        }
        let sequence_diagnostic = crate::diag::send_queue();
        if sequence_diagnostic && tunnel_packet_count > 1 {
            eprintln!(
                "ordered_tun_send_many_start slots={first_slot}..{} packets={tunnel_packet_count}",
                first_slot + completion_count as u64
            );
        }
        let result = match tunnel_packet_count {
            0 => Ok(()),
            1 => tun_tx
                .send(tun_packets.pop().expect("one packet was counted"))
                .await
                .map_err(Error::IoError),
            _ => tun_tx
                .send_many(&mut tun_packets)
                .await
                .map_err(Error::IoError),
        };
        if diagnostic {
            eprintln!(
                "pipeline stage=tun_queue_enqueue packets={tunnel_packet_count} success={}",
                result.is_ok()
            );
        }
        if sequence_diagnostic && tunnel_packet_count > 1 {
            eprintln!(
                "ordered_tun_send_many_done slots={first_slot}..{} packets={tunnel_packet_count} success={}",
                first_slot + completion_count as u64,
                result.is_ok()
            );
        }
        result
    }

    /// Queue each bounded receive run once and release it through its peer's ordered lane.
    ///
    /// The lane selects worker dispatch from its own outstanding-slot backlog, so unrelated peers
    /// do not move a shallow queue off the inline path.
    fn enqueue_incoming_run<TunTx: IpSend + Clone>(
        pending: &mut PendingIncoming,
        context: IncomingRunContext<Self, TunTx>,
        first_slot: u64,
        packets: Vec<(PreparedDecryption, std::net::SocketAddr)>,
    ) {
        let IncomingRunContext {
            crypto,
            ordered,
            peer_key,
            lane,
            peer_arc,
            device,
            tun_tx,
        } = context;
        assert!(!packets.is_empty());
        let mut packets = packets.into_iter();
        let mut remaining = packets.len();
        let mut offset = 0_u64;

        while remaining > 0 {
            let batch = packets.by_ref().take(CRYPTO_BATCH_SIZE).collect::<Vec<_>>();
            let batch_len = batch.len();
            let batch_first_slot = first_slot + offset;
            let force_worker = lane.should_force_worker(batch_len);
            let crypto = crypto.clone();
            let ordered = Arc::clone(&ordered);
            let lane = Arc::clone(&lane);
            let peer_arc = Arc::clone(&peer_arc);
            let device = device.clone();
            let tun_tx = tun_tx.clone();
            pending.push(
                async move {
                    if crate::diag::pipeline()
                        || crate::diag::send_queue()
                    {
                        eprintln!(
                            "pipeline stage=decrypt_start first_slot={batch_first_slot} packets={batch_len} worker={force_worker}"
                        );
                    }
                    let results = crypto.decrypt_run(batch, force_worker).await;
                    let verified_count = results
                        .as_ref()
                        .map(|completions| {
                            completions
                                .iter()
                                .filter(|completion| completion.result.is_ok())
                                .count()
                        })
                        .unwrap_or_default();
                    if crate::diag::pipeline()
                        || crate::diag::send_queue()
                    {
                        eprintln!(
                            "pipeline stage=decrypt_complete first_slot={batch_first_slot} packets={batch_len} verified={verified_count} worker={force_worker}"
                        );
                    }
                    let results = results
                        .map(|completions| completions.into_iter().map(Some).collect())
                        .unwrap_or_else(|| {
                            std::iter::repeat_with(|| None).take(batch_len).collect()
                        });

                    let result = lane
                        .complete_run_traced(
                            "incoming",
                            peer_key,
                            batch_first_slot,
                            results,
                            |completions| {
                            let device = device.clone();
                            let peer_arc = Arc::clone(&peer_arc);
                            let tun_tx = tun_tx.clone();
                            async move {
                                Self::deliver_incoming_run(
                                    batch_first_slot,
                                    device,
                                    peer_arc,
                                    completions,
                                    tun_tx,
                                )
                                .await
                            }
                            },
                        )
                        .await;
                    if crate::diag::pipeline()
                        || crate::diag::send_queue()
                    {
                        eprintln!(
                            "pipeline stage=ordered_complete first_slot={batch_first_slot} packets={batch_len} success={}",
                            result.is_ok()
                        );
                    }
                    ordered.release_if_idle(peer_key, &lane);
                    result
                }
                .boxed(),
            );
            remaining -= batch_len;
            offset += batch_len as u64;
        }
    }

    /// Reserve one contiguous receive range and add its batches to the bounded completion set.
    ///
    /// A shallow peer lane stays inline and avoids a worker wake for low-rate traffic.
    async fn flush_incoming_run(
        pending: &mut PendingIncoming,
        crypto: CryptoHandle,
        ordered: Arc<OrderStore<IncomingCompletion>>,
        device: Weak<RwLock<Self>>,
        tun_tx: impl IpSend + Clone,
        run: PreparedIncomingRun,
    ) -> Result<(), Error> {
        if run.packets.is_empty() {
            return Ok(());
        }
        let diagnostic = crate::diag::pipeline() || crate::diag::send_queue();
        let packet_count = run.packets.len();
        let batch_count = run.packets.len().div_ceil(CRYPTO_BATCH_SIZE);
        if diagnostic {
            eprintln!(
                "pipeline stage=incoming_flush_start peer={} packets={packet_count} pending_runs={} batches={batch_count}",
                run.peer_key,
                pending.len()
            );
        }
        while pending.len() + batch_count > CRYPTO_CHUNK_SIZE {
            if diagnostic {
                eprintln!(
                    "pipeline stage=incoming_flush_wait_pending peer={} pending_runs={} batches={batch_count}",
                    run.peer_key,
                    pending.len()
                );
            }
            pending
                .next()
                .await
                .expect("a full incoming run has a completion future")?;
        }

        let (lane, first_slot) = loop {
            if let Some(reserved) = ordered.reserve_run(run.peer_key, run.packets.len()) {
                if diagnostic {
                    eprintln!(
                        "pipeline stage=incoming_slots_reserved peer={} first_slot={} packets={packet_count}",
                        run.peer_key, reserved.1
                    );
                }
                break reserved;
            }
            if diagnostic {
                eprintln!(
                    "pipeline stage=incoming_flush_wait_peer_capacity peer={} pending_runs={}",
                    run.peer_key,
                    pending.len()
                );
            }
            pending
                .next()
                .await
                .expect("an in-flight peer run has a completion future")?;
        };
        Self::enqueue_incoming_run(
            pending,
            IncomingRunContext {
                crypto,
                ordered,
                peer_key: run.peer_key,
                lane,
                peer_arc: run.peer_arc,
                device,
                tun_tx,
            },
            first_slot,
            run.packets,
        );
        if diagnostic {
            eprintln!(
                "pipeline stage=incoming_crypto_enqueued peer={} first_slot={first_slot} packets={packet_count} pending_runs={}",
                run.peer_key,
                pending.len()
            );
        }
        Ok(())
    }

    /// Encrypt and send a bounded chunk of handshake-queued packets before newer TUN traffic.
    async fn flush_handshake_queue<U: UdpSend + 'static>(
        device: Weak<RwLock<Self>>,
        context: OutgoingBatchContext<U>,
        first_lane: Arc<OrderedCompletions<WgKind>>,
        first_slot: u64,
        pending: &mut PendingOutgoing,
        flush_guard: parallel_crypto::FlushGuard<WgKind>,
    ) -> Result<(), Error> {
        let OutgoingBatchContext {
            peer:
                OutgoingPeerContext {
                    crypto,
                    ordered,
                    peer_arc,
                    peer_key,
                    peer_addr,
                    udp,
                },
            send_many_buf,
        } = context;
        let mut flush_guard = Some(flush_guard);

        wait_for_outgoing_slot(&first_lane, first_slot, pending).await;

        loop {
            let Some(device_arc) = device.upgrade() else {
                return Ok(());
            };
            let device_guard = device_arc.read().await;
            let mut peer_trace = PeerLockDiagnostic::waiting("handshake_queue_flush", peer_key);
            let mut pending_completions = PendingCompletions::Outgoing(pending);
            let mut peer = lock_peer_state_while_completing(
                &peer_arc,
                "handshake_queue_flush",
                peer_key,
                &mut peer_trace,
                &mut pending_completions,
            )
            .await?;
            if !peer.tunnel.has_queued_packets() {
                drop(flush_guard.take());
                return Ok(());
            }

            let mut jobs = Vec::with_capacity(CRYPTO_CHUNK_SIZE);
            let mut stop_after_chunk = false;
            for _ in 0..CRYPTO_CHUNK_SIZE {
                let Some(packet) = peer.tunnel.take_queued_packet() else {
                    break;
                };
                let prepared = peer.tunnel.prepare_queued_packet(packet);
                if let Some(PreparedOutgoing::Ready(packet)) = prepared.as_ref() {
                    Self::register_handshake_idx(&device_guard.peers_by_idx, packet, &peer_arc);
                    stop_after_chunk = true;
                }
                if prepared.is_none() {
                    stop_after_chunk = true;
                }
                jobs.push(prepared);
                if stop_after_chunk {
                    break;
                }
            }

            if stop_after_chunk || !peer.tunnel.has_queued_packets() {
                // The queue's remaining packets already have a later handshake or lane ordering
                // point, so newer TUN packets may return to the regular path now.
                drop(flush_guard.take());
            }
            drop(peer);
            drop(peer_trace);
            drop(device_guard);

            if jobs.is_empty() {
                return Ok(());
            }
            let (chunk_lane, first_slot) = ordered
                .reserve_run(peer_key, jobs.len())
                .expect("the bounded queue drain fits within the peer order window");
            let chunk_last_slot = first_slot + jobs.len() as u64 - 1;
            let batch_count = jobs.len().div_ceil(CRYPTO_BATCH_SIZE);
            while pending.len() + batch_count > CRYPTO_CHUNK_SIZE {
                pending
                    .next()
                    .await
                    .expect("a full outgoing run has a completion future");
            }
            Self::enqueue_outgoing_run(
                pending,
                OutgoingBatchContext {
                    peer: OutgoingPeerContext {
                        crypto: crypto.clone(),
                        ordered: Arc::clone(&ordered),
                        peer_arc: Arc::clone(&peer_arc),
                        peer_key,
                        peer_addr,
                        udp: udp.clone(),
                    },
                    send_many_buf: Arc::clone(&send_many_buf),
                },
                chunk_lane.clone(),
                first_slot,
                jobs,
                true,
            );

            wait_for_outgoing_slot(&chunk_lane, chunk_last_slot, pending).await;
            if flush_guard.is_none() {
                return Ok(());
            }
        }
    }

    /// Add one outgoing packet to a bounded future set without waiting for a larger batch.
    fn enqueue_outgoing_packet<U: UdpSend + 'static>(
        pending: &mut PendingOutgoing,
        context: OutgoingPeerContext<U>,
        lane: Arc<OrderedCompletions<WgKind>>,
        slot: u64,
        prepared: Option<PreparedOutgoing>,
        apply_daita: bool,
    ) {
        pending.push(complete_outgoing_packet(context, lane, slot, prepared, apply_daita).boxed());
    }

    /// Split a peer's reserved range into bounded runs without creating per-packet futures.
    ///
    /// Each run consults its own lane's backlog, so shallow traffic stays inline while sustained
    /// queued work can use the bounded worker pool.
    fn enqueue_outgoing_run<U: UdpSend + 'static>(
        pending: &mut PendingOutgoing,
        context: OutgoingBatchContext<U>,
        lane: Arc<OrderedCompletions<WgKind>>,
        first_slot: u64,
        prepared: Vec<Option<PreparedOutgoing>>,
        apply_daita: bool,
    ) {
        assert!(!prepared.is_empty());
        let mut prepared = prepared.into_iter();
        let mut remaining = prepared.len();
        let mut offset = 0_u64;

        while remaining > 0 {
            let batch = prepared
                .by_ref()
                .take(CRYPTO_BATCH_SIZE)
                .collect::<Vec<_>>();
            let batch_len = batch.len();
            let force_worker = lane.should_force_worker(batch_len);
            pending.push(
                complete_outgoing_batch(
                    context.clone(),
                    Arc::clone(&lane),
                    first_slot + offset,
                    batch,
                    apply_daita,
                    force_worker,
                )
                .boxed(),
            );
            remaining -= batch_len;
            offset += batch_len as u64;
        }
    }

    /// Run periodic tunnel maintenance and send each peer's timer output in sequence.
    #[instrument(level = Level::TRACE, skip_all)]
    async fn handle_timers(
        device: Weak<RwLock<Self>>,
        udp: impl UdpSend,
        crypto: CryptoHandle,
        outgoing_order: Arc<OrderStore<WgKind>>,
    ) {
        loop {
            let Some(device) = device.upgrade() else {
                break;
            };
            let device = device.read().await;
            // Remove stale session indices.
            //
            // `device.index_table` is a singleton which identifies ongoing handshakes and active sessions.
            // Once a session is stale it is dropped (see `update_session_timers`), and its
            // associated index is freed from the table.
            device
                .peers_by_idx
                .lock()
                .retain(|idx, _| device.index_table.in_use(*idx));

            // NOTE: Try to reset the packet counts here in addition to inside of `PeerState::update_timers`.
            // Otherwise if the device has no peers, try_reset_count will never trigger, and packet
            // counts will accumulate indefinitely. Fixes GHSA-m2rr-7rr7-vmp7.
            if let Some(rate_limiter) = device.rate_limiter.as_ref() {
                rate_limiter.try_reset_count();
            }

            // TODO: pass in peers instead?
            let peer_map = &device.peers;

            // Go over each peer and invoke the timer function
            for peer in peer_map.values() {
                let peer_key = peer_order_key(peer);
                let mut peer_trace = PeerLockDiagnostic::waiting("timer", peer_key);
                let mut p = lock_peer_state(peer, "timer", peer_key, &mut peer_trace).await;
                if outgoing_order.is_flushing(peer_key) {
                    continue;
                }
                let endpoint_addr = match p.endpoint().addr {
                    Some(addr) => addr,
                    None => continue,
                };

                match p.update_timers() {
                    Ok(Some(packet)) => {
                        // Register sender_idx from outgoing handshake packets
                        Self::register_handshake_idx(&device.peers_by_idx, &packet, peer);

                        let (lane, slot) = outgoing_order
                            .reserve(peer_key)
                            .expect("timer output fits within the peer order window");

                        drop(p);
                        drop(peer_trace);

                        // NOTE: we don't bother with triggering TunnelRecv DAITA events here.
                        complete_outgoing_packet(
                            OutgoingPeerContext {
                                crypto: crypto.clone(),
                                ordered: Arc::clone(&outgoing_order),
                                peer_arc: Arc::clone(peer),
                                peer_key,
                                peer_addr: endpoint_addr,
                                udp: udp.clone(),
                            },
                            lane,
                            slot,
                            Some(PreparedOutgoing::Ready(packet)),
                            false,
                        )
                        .await;
                    }
                    Ok(None) => {}
                    Err(WireGuardError::ConnectionExpired) => {}
                    Err(e) => tracing::error!("Timer error = {e:?}: {e:?}"),
                }
            }

            drop(device);
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// Read from UDP socket, decapsulate, write to tunnel device
    #[instrument(level = Level::TRACE, skip_all)]
    async fn handle_incoming(
        device: Weak<RwLock<Self>>,
        mut tun_tx: impl IpSend + Clone,
        udp_tx: impl UdpSend + 'static,
        mut udp_rx: impl UdpRecv,
        mut packet_pool: PacketBufPool,
        crypto_order: CryptoOrderContext,
    ) -> Result<(), Error> {
        let CryptoOrderContext {
            crypto,
            incoming: incoming_order,
            outgoing: outgoing_order,
        } = crypto_order;
        let (private_key, public_key, rate_limiter) = {
            let Some(device) = device.upgrade() else {
                return Ok(());
            };
            let device = device.read().await;

            let (private_key, public_key) = device.key_pair.clone().expect("Key not set");
            let rate_limiter = device.rate_limiter.clone().unwrap();
            (private_key, public_key, rate_limiter)
        };

        let mut udp_recv_buf = Default::default();
        let mut received_packets = Vec::new();
        let mut incoming_pending = PendingIncoming::new();
        let mut outgoing_pending = PendingOutgoing::new();
        let send_many_buf = Arc::new(Mutex::new(Default::default()));

        // Idle memory release. One timer for the task's lifetime, re-armed once per period,
        // and polled only when the socket has nothing to read (`biased` polls the receive
        // first), so a busy link pays nothing per packet. Every receive is cancel-safe while
        // pending: nothing is consumed before its single await completes. Completion futures are
        // polled ahead of the socket when ready so a quiet peer does not wait for another datagram.
        let idle_check = tokio::time::sleep(IDLE_RELEASE_PERIOD);
        tokio::pin!(idle_check);
        let mut busy = false;
        let mut dropped_datagrams: u64 = 0;

        loop {
            received_packets.clear();
            tokio::select! {
                biased;
                completed = incoming_pending.next(), if !incoming_pending.is_empty() => {
                    if let Some(result) = completed {
                        result?;
                    }
                }
                completed = outgoing_pending.next(), if !outgoing_pending.is_empty() => {
                    let _ = completed;
                }
                received = udp_rx.recv_many_from(
                    &mut udp_recv_buf,
                    &mut packet_pool,
                    &mut received_packets,
                ) => {
                    if crate::diag::pipeline() {
                        eprintln!(
                            "pipeline stage=udp_receive packets={} error={}",
                            received_packets.len(),
                            received.is_err()
                        );
                    }
                    if let Err(err) = received {
                        if crate::udp::is_fatal_udp_error(&err) {
                            return Err(Error::IoError(err));
                        }
                        // One bad datagram (or batch tail) must not stop receiving. Packets
                        // the batch delivered before the error are still processed below.
                        dropped_datagrams += 1;
                        if dropped_datagrams.is_power_of_two() {
                            tracing::warn!(
                                "Dropped undecodable UDP datagram ({dropped_datagrams} so far): {err}"
                            );
                        }
                        tokio::task::yield_now().await;
                    }
                }
                () = &mut idle_check => {
                    idle_check
                        .as_mut()
                        .reset(tokio::time::Instant::now() + IDLE_RELEASE_PERIOD);
                    // The pool sees packets in both directions, so it decides idleness.
                    if idle_release_due(&mut busy, packet_pool.take_count()) {
                        packet_pool.release();
                        udp_rx.release_recv_buf(&mut udp_recv_buf);
                        crate::packet::return_freed_heap_to_os();
                        tracing::debug!("Link idle: released packet buffers to the OS");
                    }
                    continue;
                }
            }

            let mut incoming_runs = HashMap::<usize, PreparedIncomingRun>::new();
            for (src_buf, addr) in received_packets.drain(..) {
                let parsed_packet = match rate_limiter.verify_packet(addr, src_buf) {
                    Ok(packet) => packet,
                    Err(TunnResult::WriteToNetwork(WgKind::CookieReply(cookie))) => {
                        for run in std::mem::take(&mut incoming_runs).into_values() {
                            Self::flush_incoming_run(
                                &mut incoming_pending,
                                crypto.clone(),
                                Arc::clone(&incoming_order),
                                device.clone(),
                                tun_tx.clone(),
                                run,
                            )
                            .await?;
                        }
                        // Note: Cookies should not affect counters.
                        udp_tx
                            .send_to(cookie.into(), addr)
                            .await
                            .map_err(Error::IoError)?;
                        continue;
                    }
                    Err(_) => continue,
                };

                if !matches!(&parsed_packet, WgKind::Data(_)) && !incoming_runs.is_empty() {
                    for run in std::mem::take(&mut incoming_runs).into_values() {
                        Self::flush_incoming_run(
                            &mut incoming_pending,
                            crypto.clone(),
                            Arc::clone(&incoming_order),
                            device.clone(),
                            tun_tx.clone(),
                            run,
                        )
                        .await?;
                    }
                }

                let Some(device_arc) = device.upgrade() else {
                    return Ok(());
                };

                let device_guard = device_arc.read().await;
                let peers = &device_guard.peers;
                let peer = match &parsed_packet {
                    WgKind::HandshakeInit(p) => parse_handshake_anon(&private_key, &public_key, p)
                        .ok()
                        .and_then(|hh| peers.get(&x25519::PublicKey::from(hh.peer_static_public)))
                        .cloned(),
                    WgKind::HandshakeResp(p) => device_guard
                        .peers_by_idx
                        .lock()
                        .get(&p.receiver_idx.get())
                        .cloned(),
                    WgKind::CookieReply(p) => device_guard
                        .peers_by_idx
                        .lock()
                        .get(&p.receiver_idx.get())
                        .cloned(),
                    WgKind::Data(p) => device_guard
                        .peers_by_idx
                        .lock()
                        .get(&p.header.receiver_idx.get())
                        .cloned(),
                };
                let Some(peer_arc) = peer else { continue };
                let peer_key = peer_order_key(&peer_arc);

                match parsed_packet {
                    WgKind::Data(packet) => {
                        let counter = packet.header.counter.get();
                        if crate::diag::pipeline() {
                            eprintln!("pipeline stage=udp_data_arrival counter={counter}");
                            eprintln!("pipeline stage=incoming_peer_lock_wait counter={counter}");
                        }
                        drop(device_guard);
                        let mut peer_trace =
                            PeerLockDiagnostic::waiting("incoming_prepare", peer_key);
                        let mut pending_completions = PendingCompletions::Incoming(
                            &mut incoming_pending,
                            &mut outgoing_pending,
                        );
                        let mut peer = lock_peer_state_while_completing(
                            &peer_arc,
                            "incoming_prepare",
                            peer_key,
                            &mut peer_trace,
                            &mut pending_completions,
                        )
                        .await?;
                        if crate::diag::pipeline() {
                            eprintln!(
                                "pipeline stage=incoming_peer_lock_acquired counter={counter}"
                            );
                        }
                        match peer.prepare_incoming_data(packet) {
                            crate::noise::PreparedIncoming::Immediate(result) => {
                                // The serial data path also discarded packets without a session.
                                if crate::diag::pipeline() {
                                    eprintln!(
                                        "pipeline stage=incoming_prepare_immediate counter={counter}"
                                    );
                                }
                                drop(result);
                            }
                            crate::noise::PreparedIncoming::Decrypt { packet } => {
                                if crate::diag::pipeline() {
                                    eprintln!(
                                        "pipeline stage=incoming_prepare_decrypt counter={counter}"
                                    );
                                }
                                drop(peer);
                                drop(peer_trace);
                                let reached_limit = {
                                    let run = incoming_runs.entry(peer_key).or_insert_with(|| {
                                        PreparedIncomingRun {
                                            peer_key,
                                            peer_arc: Arc::clone(&peer_arc),
                                            packets: Vec::with_capacity(CRYPTO_CHUNK_SIZE),
                                        }
                                    });
                                    run.packets.push((packet, addr));
                                    run.packets.len() == CRYPTO_CHUNK_SIZE
                                };
                                if reached_limit {
                                    Self::flush_incoming_run(
                                        &mut incoming_pending,
                                        crypto.clone(),
                                        Arc::clone(&incoming_order),
                                        device.clone(),
                                        tun_tx.clone(),
                                        incoming_runs
                                            .remove(&peer_key)
                                            .expect("the receive run reached its bound"),
                                    )
                                    .await?;
                                }
                            }
                        }
                    }
                    packet => {
                        if let Some(lane) = incoming_order.lane(peer_key) {
                            while !lane.is_idle() {
                                incoming_pending
                                    .next()
                                    .await
                                    .expect("an incoming data slot has a completion future")?;
                            }
                        }

                        let mut peer_trace =
                            PeerLockDiagnostic::waiting("incoming_control", peer_key);
                        let mut pending_completions = PendingCompletions::Incoming(
                            &mut incoming_pending,
                            &mut outgoing_pending,
                        );
                        let mut peer = lock_peer_state_while_completing(
                            &peer_arc,
                            "incoming_control",
                            peer_key,
                            &mut peer_trace,
                            &mut pending_completions,
                        )
                        .await?;
                        let result = peer.handle_incoming_packet(packet, addr);
                        match result {
                            TunnResult::Done | TunnResult::Err(_) => {}
                            TunnResult::WriteToNetwork(packet) => {
                                Self::register_handshake_idx(
                                    &device_guard.peers_by_idx,
                                    &packet,
                                    &peer_arc,
                                );
                                let flush_guard = outgoing_order.begin_flush(peer_key);
                                // Keep later TUN packets behind this control packet while its
                                // bounded peer lane has no free sequence slot. Release peer and
                                // device locks so the pending completions can drain the lane.
                                drop(peer);
                                drop(peer_trace);
                                drop(device_guard);
                                let (lane, slot) = loop {
                                    if let Some(reserved) = outgoing_order.reserve(peer_key) {
                                        if crate::diag::pipeline() {
                                            eprintln!(
                                                "pipeline stage=control_slot_reserved peer={peer_key} slot={} pending={}",
                                                reserved.1,
                                                outgoing_pending.len()
                                            );
                                        }
                                        break reserved;
                                    }
                                    let Some(lane) = outgoing_order.lane(peer_key) else {
                                        continue;
                                    };
                                    if crate::diag::pipeline() {
                                        eprintln!(
                                            "pipeline stage=control_slot_wait peer={peer_key} available={} pending={}",
                                            lane.available(),
                                            outgoing_pending.len()
                                        );
                                    }
                                    tokio::select! {
                                        _ = lane.wait_for_capacity() => {
                                            if crate::diag::pipeline() {
                                                eprintln!(
                                                    "pipeline stage=control_slot_capacity_wake peer={peer_key} available={}",
                                                    lane.available()
                                                );
                                            }
                                        }
                                        _ = outgoing_pending.next(), if !outgoing_pending.is_empty() => {
                                            if crate::diag::pipeline() {
                                                eprintln!(
                                                    "pipeline stage=control_slot_pending_wake peer={peer_key} available={}",
                                                    lane.available()
                                                );
                                            }
                                        }
                                    }
                                };
                                let first_lane = Arc::clone(&lane);

                                while outgoing_pending.len() >= CRYPTO_CHUNK_SIZE {
                                    outgoing_pending
                                        .next()
                                        .await
                                        .expect("a full outgoing chunk has a completion future");
                                }
                                let peer_context = OutgoingPeerContext {
                                    crypto: crypto.clone(),
                                    ordered: Arc::clone(&outgoing_order),
                                    peer_arc: Arc::clone(&peer_arc),
                                    peer_key,
                                    peer_addr: addr,
                                    udp: udp_tx.clone(),
                                };
                                Self::enqueue_outgoing_packet(
                                    &mut outgoing_pending,
                                    peer_context.clone(),
                                    lane,
                                    slot,
                                    Some(PreparedOutgoing::Ready(packet)),
                                    true,
                                );
                                Self::flush_handshake_queue(
                                    device.clone(),
                                    OutgoingBatchContext {
                                        peer: peer_context,
                                        send_many_buf: Arc::clone(&send_many_buf),
                                    },
                                    first_lane,
                                    slot,
                                    &mut outgoing_pending,
                                    flush_guard,
                                )
                                .await?;
                            }
                            #[cfg_attr(not(feature = "daita"), expect(unused_mut))]
                            TunnResult::WriteToTunnel(mut packet) => {
                                #[cfg(feature = "daita")]
                                if let Some(daita) = peer.daita.as_mut() {
                                    match daita.on_data_recv(packet) {
                                        Some(new) => packet = new,
                                        None => continue,
                                    }
                                }

                                if packet.is_empty() {
                                    continue;
                                }
                                let Ok(packet) = packet.try_into_ipvx() else {
                                    continue;
                                };
                                let (source, packet): (IpAddr, _) = packet.either(
                                    |ipv4| (ipv4.header.source().into(), ipv4.into()),
                                    |ipv6| (ipv6.header.source().into(), ipv6.into()),
                                );
                                let routed_to_this_peer = device_guard
                                    .peers_by_ip
                                    .find(source)
                                    .is_some_and(|owner| Arc::ptr_eq(owner, &peer_arc));
                                if !routed_to_this_peer {
                                    if cfg!(debug_assertions) {
                                        let unspecified =
                                            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into();
                                        tracing::warn!(
                                            "peer at {} is not allowed to send us packets from: {source}",
                                            peer.endpoint().addr.unwrap_or(unspecified)
                                        );
                                    }
                                    continue;
                                }

                                if crate::diag::pipeline() {
                                    eprintln!("pipeline stage=incoming_control_tun_send_wait");
                                }
                                if let Err(e) = tun_tx.send(packet).await {
                                    tracing::trace!("buffered_tun_send.send failed");
                                    return Err(Error::IoError(e));
                                }
                                if crate::diag::pipeline() {
                                    eprintln!("pipeline stage=incoming_control_tun_send_done");
                                }
                            }
                        }
                    }
                }
            }
            for run in std::mem::take(&mut incoming_runs).into_values() {
                Self::flush_incoming_run(
                    &mut incoming_pending,
                    crypto.clone(),
                    Arc::clone(&incoming_order),
                    device.clone(),
                    tun_tx.clone(),
                    run,
                )
                .await?;
            }
        }
    }

    /// Read from tunnel device, encapsulate, and write to UDP socket for the corresponding peer
    #[instrument(level = Level::TRACE, skip_all)]
    async fn handle_outgoing(
        device: Weak<RwLock<Self>>,
        mut tun_rx: impl IpRecv,
        udp: impl UdpSend + 'static,
        mut packet_pool: PacketBufPool,
        crypto: CryptoHandle,
        outgoing_order: Arc<OrderStore<WgKind>>,
    ) -> Result<(), Error> {
        let mut tun_mtu = {
            let Some(device) = device.upgrade() else {
                return Ok(());
            };
            let device = device.read().await;
            device.tun_rx_mtu.clone()
        };

        let mut pending = PendingOutgoing::new();
        let send_many_buf = Arc::new(Mutex::new(Default::default()));
        loop {
            tokio::select! {
                completed = pending.next(), if !pending.is_empty() => {
                    let _ = completed;
                    if crate::diag::pipeline() {
                        eprintln!("pipeline stage=outgoing_pending_complete remaining={}", pending.len());
                    }
                }
                packets = tun_rx.recv(&mut packet_pool) => {
                    let packets = match packets {
                        Ok(packets) => packets,
                        Err(e) => {
                            tracing::error!("Unexpected error on tun interface: {e:?}");
                            return Err(Error::IoError(e));
                        }
                    };
                    let packets = packets.collect::<Vec<_>>();
                    if crate::diag::pipeline() {
                        eprintln!("pipeline stage=tun_receive packets={}", packets.len());
                    }

                    let Some(device_arc) = device.upgrade() else {
                        return Ok(());
                    };
                    let device_guard = device_arc.read().await;
                    let runs = group_by_key(packets.into_iter().filter_map(|packet| {
                        let dst_addr = packet.destination()?;
                        let Some(peer_arc) = device_guard.peers_by_ip.find(dst_addr).cloned()
                        else {
                            if cfg!(debug_assertions) {
                                tracing::trace!("Dropping packet with no routable peer");
                            }
                            return None;
                        };

                        Some((peer_order_key(&peer_arc), peer_arc, packet))
                    }));
                    drop(device_guard);

                    for (peer_key, peer_arc, packets) in runs {
                        let mut packets = packets.into_iter().peekable();
                        while packets.peek().is_some() {
                            let Some(device_arc) = device.upgrade() else {
                                return Ok(());
                            };
                            let device_guard = device_arc.read().await;
                            let mut peer_trace =
                                PeerLockDiagnostic::waiting("outgoing_prepare", peer_key);
                            let mut pending_completions =
                                PendingCompletions::Outgoing(&mut pending);
                            let mut peer = lock_peer_state_while_completing(
                                &peer_arc,
                                "outgoing_prepare",
                                peer_key,
                                &mut peer_trace,
                                &mut pending_completions,
                            )
                            .await?;
                            let Some(peer_addr) = peer.endpoint().addr else {
                                tracing::error!("No endpoint");
                                break;
                            };

                            if outgoing_order.is_flushing(peer_key) {
                                for packet in packets {
                                    #[cfg(feature = "daita")]
                                    let packet = match peer.daita.as_mut() {
                                        Some(daita) => daita.on_normal_sent(packet),
                                        None => packet.into(),
                                    };
                                    #[cfg(not(feature = "daita"))]
                                    let packet = packet.into();
                                    peer.tunnel
                                        .queue_outgoing_packet(packet, Some(&mut tun_mtu));
                                }
                                break;
                            }

                            let available = outgoing_order.available(peer_key);
                            if available == 0 {
                                let lane = outgoing_order.lane(peer_key);
                                drop(peer);
                                drop(peer_trace);
                                drop(device_guard);
                                if let Some(lane) = lane {
                                    if crate::diag::pipeline() {
                                        eprintln!(
                                            "pipeline stage=outgoing_slot_wait peer={peer_key} pending={}",
                                            pending.len()
                                        );
                                    }
                                    tokio::select! {
                                        _ = lane.wait_for_capacity() => {}
                                        _ = pending.next(), if !pending.is_empty() => {}
                                    }
                                }
                                continue;
                            }
                            let run_len = packets.len().min(CRYPTO_CHUNK_SIZE).min(available);
                            let mut prepared = Vec::with_capacity(run_len);
                            let mut handshake_offset = None;
                            let mut flush_guard = None;

                            for _ in 0..run_len {
                                let packet = packets.next().expect("the run length fits its input");
                                #[cfg(feature = "daita")]
                                let packet = match peer.daita.as_mut() {
                                    Some(daita) => daita.on_normal_sent(packet),
                                    None => packet.into(),
                                };
                                #[cfg(not(feature = "daita"))]
                                let packet = packet.into();

                                let Some(prepared_packet) = peer
                                    .tunnel
                                    .prepare_outgoing_packet(packet, Some(&mut tun_mtu))
                                else {
                                    prepared.push(None);
                                    continue;
                                };

                                if let PreparedOutgoing::Ready(packet) = &prepared_packet {
                                    Self::register_handshake_idx(
                                        &device_guard.peers_by_idx,
                                        packet,
                                        &peer_arc,
                                    );
                                    handshake_offset = Some(prepared.len());
                                    flush_guard = Some(outgoing_order.begin_flush(peer_key));
                                }
                                prepared.push(Some(prepared_packet));
                                if handshake_offset.is_some() {
                                    break;
                                }
                            }

                            let (lane, first_slot) = outgoing_order
                                .reserve_run(peer_key, prepared.len())
                                .expect("the prepared run fits in the peer order window");
                            drop(peer);
                            drop(peer_trace);
                            drop(device_guard);

                            let batch_count = prepared.len().div_ceil(CRYPTO_BATCH_SIZE);
                            while pending.len() + batch_count > CRYPTO_CHUNK_SIZE {
                                if crate::diag::pipeline() {
                                    eprintln!(
                                        "pipeline stage=outgoing_pending_wait peer={peer_key} pending={} batches={batch_count}",
                                        pending.len()
                                    );
                                }
                                pending
                                    .next()
                                    .await
                                    .expect("a full outgoing run has a completion future");
                                if crate::diag::pipeline() {
                                    eprintln!(
                                        "pipeline stage=outgoing_pending_wake peer={peer_key} pending={}",
                                        pending.len()
                                    );
                                }
                            }
                            let batch_context = OutgoingBatchContext {
                                peer: OutgoingPeerContext {
                                    crypto: crypto.clone(),
                                    ordered: Arc::clone(&outgoing_order),
                                    peer_arc: Arc::clone(&peer_arc),
                                    peer_key,
                                    peer_addr,
                                    udp: udp.clone(),
                                },
                                send_many_buf: Arc::clone(&send_many_buf),
                            };
                            Self::enqueue_outgoing_run(
                                &mut pending,
                                batch_context.clone(),
                                Arc::clone(&lane),
                                first_slot,
                                prepared,
                                true,
                            );

                            if let (Some(offset), Some(flush_guard)) =
                                (handshake_offset, flush_guard)
                            {
                                Self::flush_handshake_queue(
                                    device.clone(),
                                    batch_context,
                                    lane,
                                    first_slot + offset as u64,
                                    &mut pending,
                                    flush_guard,
                                )
                                .await?;
                            }
                        }
                    }
                }
            }
        }
    }
}

impl<T: DeviceTransports> Connection<T> {
    /// Stop connection tasks before closing and joining the shared crypto workers.
    async fn stop(self) {
        let Self {
            udp,
            crypto_workers,
            incoming,
            timers,
            outgoing,
        } = self;
        drop(udp);

        join!(incoming.stop(), timers.stop(), outgoing.stop(),);
        crypto_workers.stop().await;
    }
}

#[cfg(all(test, feature = "socket", target_os = "linux"))]
mod outgoing_context_clone_tests {
    //! Compile-time checks for shared outgoing-run context ownership.

    use super::OutgoingBatchContext;
    use crate::udp::socket::UdpSocket;

    /// Cloning an outgoing run shares its batch buffer without cloning that buffer.
    #[test]
    fn clones_context_with_non_cloneable_send_buffer() {
        /// Require the selected outgoing context to implement `Clone`.
        fn assert_clone<T: Clone>() {}

        assert_clone::<OutgoingBatchContext<UdpSocket>>();
    }
}

#[cfg(test)]
mod peer_run_tests {
    //! Tests for grouping packets into bounded per-peer runs.

    use super::group_by_key;

    /// Interleaved packets keep their per-peer order while sharing one peer-owned run.
    #[test]
    fn groups_interleaved_packets_by_peer_without_reordering_peer_packets() {
        let groups = group_by_key([
            (2_usize, (), 0_u8),
            (1_usize, (), 10_u8),
            (2_usize, (), 1_u8),
            (1_usize, (), 11_u8),
        ]);
        let mut groups = groups
            .into_iter()
            .map(|(peer, (), packets)| (peer, packets))
            .collect::<Vec<_>>();
        groups.sort_unstable_by_key(|(peer, _)| *peer);

        assert_eq!(groups, vec![(1, vec![10, 11]), (2, vec![0, 1])]);
    }
}

#[cfg(test)]
mod idle_release_tests {
    use super::{IDLE_MAX_BUFFERS_PER_PERIOD, idle_release_due};

    /// Memory is released once, at the first quiet period after a busy one. Trickles such as
    /// keepalives count as quiet, and a long quiet stretch does not release again.
    #[test]
    fn idle_release_fires_once_per_busy_to_quiet_transition() {
        let busy_period = IDLE_MAX_BUFFERS_PER_PERIOD;
        let keepalive_trickle = 10;
        let mut busy = false;

        assert!(
            !idle_release_due(&mut busy, 0),
            "nothing to release at start"
        );
        assert!(!idle_release_due(&mut busy, busy_period));
        assert!(!idle_release_due(&mut busy, busy_period * 100));
        assert!(idle_release_due(&mut busy, keepalive_trickle));
        assert!(!idle_release_due(&mut busy, keepalive_trickle));
        assert!(!idle_release_due(&mut busy, 0));
        assert!(!idle_release_due(&mut busy, busy_period));
        assert!(idle_release_due(&mut busy, 0));
    }
}
