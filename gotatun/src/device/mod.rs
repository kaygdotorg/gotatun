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
//!
//! # Lock order
//!
//! 1. Configuration takes the async device lock first. A peer update then takes that peer's
//!    mutex and briefly writes the synchronous packet lookup. Peer insertion/removal updates the
//!    lookup while holding the device lock. Packet tasks receive the lookup and a weak task-
//!    liveness token, never a device-lock handle, so they cannot reacquire the async device lock.
//! 2. Packet tasks snapshot a peer or route under packet lookup and release its synchronous
//!    read guard before awaiting the peer mutex. While holding a peer mutex they may briefly
//!    recheck packet lookup, read the flush marker, or reserve through the order-store map and
//!    lane state. These nested locks are taken in the order peer, lookup/flush marker/order store,
//!    then lane state. No synchronous lookup or lane guard crosses an await.
//! 3. Producers reserve while holding peer state. If capacity is unavailable, they release peer
//!    state and wait for delivery progress. Only the TUN task drains a peer's handshake queue: it
//!    drains before preparing any newer run for that peer, and when the UDP receive task posts a
//!    request (`FlushRequests`). The receive task never drains and never waits on a drain. A
//!    drain keeps its marker set and its peer mutex held through each run's reservation, then
//!    releases both before crypto dispatch or I/O. While it runs, the TUN task reads nothing,
//!    so the queue it empties cannot grow and the drain is bounded by the queue limit.
//! 4. Completion code releases lane state before waiting for the async delivery gate. The gate
//!    may then acquire peer state for replay or send delivery. A producer holding peer state only
//!    takes lane metadata synchronously and never waits for the delivery gate.
//! 5. Timers snapshot peers from packet lookup and release it before taking peer state. They
//!    reserve under that peer mutex, skip a peer with an active handshake flush, and hold no
//!    device, peer, or lane lock while sleeping or waiting for output.
//!
//! Connection setup snapshots the key pair, rate limiter, index table, MTU watcher, and lookup
//! handle before spawning tasks. Running packet and timer tasks never reacquire the async device
//! lock, so reconfiguration can hold its write guard while stopping and joining them.
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
use std::collections::{HashMap, HashSet};
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

/// How many packets the macOS TUN channels and inbound UDP queue may hold.
///
/// On macOS the utun write is the slowest stage when a fast peer sends to us (#260, J461). With
/// [`MAX_PACKET_BUFS`] there, one TCP flow kept ~4,000 packets waiting between the UDP socket and
/// utun, about 45 ms at 1 Gbit/s, and every packet of every flow waited behind them (loaded p99
/// 44 ms). 512 packets of 1280 B is ~5 ms at that rate: still enough to keep utun busy across
/// scheduling gaps (goodput unchanged at 512 and 1024; 256 lost 10-15%), while the inbound UDP
/// queue drops the excess early so TCP slows down instead of queueing. Outbound UDP uses a
/// separate, smaller bound because the Mac-send matrix still showed excess loaded latency at 512
/// queued packets (#260, J461b, J461c).
#[cfg(target_os = "macos")]
const MACOS_PIPELINE_BUFS: usize = 512;

/// Capacity for the buffered tunnel queues on this platform.
#[cfg(target_os = "macos")]
const PIPELINE_BUFS: usize = MACOS_PIPELINE_BUFS;
/// Capacity for the buffered tunnel queues on this platform.
#[cfg(not(target_os = "macos"))]
const PIPELINE_BUFS: usize = MAX_PACKET_BUFS;

/// Bound the macOS outbound UDP backlog to one 64-packet send batch.
///
/// At the measured 0.32 Gbit/s Mac-send goodput, 64 full-size packets hold about 2.3 ms of
/// payload. This cap targets the loaded p99 regression while the TUN and receive queues keep
/// their separately measured 512-packet burst capacity (#260, J461c).
#[cfg(target_os = "macos")]
const UDP_SEND_BUFS: usize = 64;

/// Keep the existing outbound UDP capacity on Linux and other non-macOS targets.
#[cfg(not(target_os = "macos"))]
const UDP_SEND_BUFS: usize = MAX_PACKET_BUFS;

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

    /// A packet or timer task panicked. The device no longer moves packets and must be rebuilt.
    #[error("device task {task} panicked: {message}")]
    TaskPanicked {
        /// Name of the task that panicked.
        task: &'static str,
        /// The panic message.
        message: String,
    },

    /// The packet pipeline hit a failure it cannot recover from, such as a stopped UDP send task
    /// or a broken slot-reservation invariant. The device must be rebuilt.
    #[error("packet pipeline failed: {0}")]
    PipelineFailed(String),
}

/// Run one packet or timer task, turning a panic into [`Error::TaskPanicked`].
///
/// Without this, a panicking task ends quietly: `Task` only logs it, and the device stays "up"
/// with no receive or send path (J433 P2-1 on #260). The error goes to the device's fatal-error
/// channel, so [`Device::wait`] returns it and the infraternal agent rebuilds the interface.
///
/// Unwind safety: after a panic the whole connection is treated as failed, and no state the task
/// held is used to move packets again.
async fn fatal_on_panic<F>(task: &'static str, future: F) -> Result<(), Error>
where
    F: std::future::Future<Output = Result<(), Error>>,
{
    match std::panic::AssertUnwindSafe(future).catch_unwind().await {
        Ok(result) => result,
        Err(payload) => {
            let message = crate::task::panic_message(&*payload);
            tracing::error!("device task {task} panicked: {message}");
            Err(Error::TaskPanicked { task, message })
        }
    }
}

/// Futures that finish one outgoing worker result and release it through the peer's order lane.
type PendingOutgoing = FuturesUnordered<BoxFuture<'static, ()>>;

/// Futures that finish one incoming worker result and release it toward the TUN in order.
type PendingIncoming = FuturesUnordered<BoxFuture<'static, Result<(), Error>>>;

/// Drain prior data completions before a control packet mutates the same peer tunnel state.
async fn drain_incoming_before_control(
    lane: Option<Arc<OrderedCompletions<IncomingCompletion>>>,
    incoming_pending: &mut PendingIncoming,
) -> Result<(), Error> {
    if let Some(lane) = lane {
        while !lane.is_idle() {
            incoming_pending
                .next()
                .await
                .expect("an incoming data slot has a completion future")?;
        }
    }
    Ok(())
}

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

/// Packet-facing peer maps that remain available while configuration owns the async device lock.
///
/// Each method returns cloned handles or updates one bounded map under a synchronous guard. A
/// guard is never returned to a caller, so packet tasks cannot await peer state while holding the
/// lookup lock.
#[derive(Default)]
struct PacketLookup {
    state: parking_lot::RwLock<PacketLookupState>,
}

/// All packet-facing indices protected by one short synchronous read/write lock.
struct PacketLookupState {
    peers_by_key: HashMap<x25519::PublicKey, Arc<Mutex<PeerState>>>,
    peer_ids: HashSet<usize>,
    peers_by_ip: AllowedIps<Arc<Mutex<PeerState>>>,
    peers_by_idx: HashMap<u32, Arc<Mutex<PeerState>>>,
}

/// Create empty packet indices without requiring the peer handle type to be defaultable.
impl Default for PacketLookupState {
    fn default() -> Self {
        Self {
            peers_by_key: HashMap::new(),
            peer_ids: HashSet::new(),
            peers_by_ip: AllowedIps::new(),
            peers_by_idx: HashMap::new(),
        }
    }
}

impl PacketLookup {
    /// Add a peer and its initial packet routes while configuration owns the device lock.
    fn insert_peer(
        &self,
        public_key: x25519::PublicKey,
        peer: Arc<Mutex<PeerState>>,
        allowed_ips: impl IntoIterator<Item = ipnetwork::IpNetwork>,
    ) {
        let mut state = self.state.write();
        state.peers_by_key.insert(public_key, Arc::clone(&peer));
        state.peer_ids.insert(peer_order_key(&peer));
        for allowed_ip in allowed_ips {
            state
                .peers_by_ip
                .insert(allowed_ip.network(), allowed_ip.prefix(), Arc::clone(&peer));
        }
    }

    /// Remove every packet index that points at a peer being removed.
    fn remove_peer(&self, public_key: &x25519::PublicKey, peer: &Arc<Mutex<PeerState>>) {
        let mut state = self.state.write();
        if state
            .peers_by_key
            .get(public_key)
            .is_some_and(|current| Arc::ptr_eq(current, peer))
        {
            state.peers_by_key.remove(public_key);
        }
        state.peer_ids.remove(&peer_order_key(peer));
        state
            .peers_by_idx
            .retain(|_, current| !Arc::ptr_eq(current, peer));
        state
            .peers_by_ip
            .remove(&|current: &Arc<Mutex<PeerState>>| Arc::ptr_eq(current, peer));
    }

    /// Replace the allowed-IP routes for a peer after its peer state has been updated.
    fn replace_allowed_ips(
        &self,
        peer: &Arc<Mutex<PeerState>>,
        allowed_ips: impl IntoIterator<Item = ipnetwork::IpNetwork>,
    ) {
        let mut state = self.state.write();
        state
            .peers_by_ip
            .remove(&|current: &Arc<Mutex<PeerState>>| Arc::ptr_eq(current, peer));
        for allowed_ip in allowed_ips {
            state
                .peers_by_ip
                .insert(allowed_ip.network(), allowed_ip.prefix(), Arc::clone(peer));
        }
    }

    /// Remove all packet-facing indices when the device clears its peer set.
    fn clear(&self) {
        *self.state.write() = PacketLookupState::default();
    }

    /// Clone the peer selected by an allowed source or destination address.
    fn peer_by_ip(&self, address: IpAddr) -> Option<Arc<Mutex<PeerState>>> {
        self.state.read().peers_by_ip.find(address).cloned()
    }

    /// Clone the configured peer with this static public key.
    fn peer_by_key(&self, public_key: &x25519::PublicKey) -> Option<Arc<Mutex<PeerState>>> {
        self.state.read().peers_by_key.get(public_key).cloned()
    }

    /// Clone the peer registered for a receiver index.
    fn peer_by_index(&self, index: u32) -> Option<Arc<Mutex<PeerState>>> {
        self.state.read().peers_by_idx.get(&index).cloned()
    }

    /// Snapshot peers for timer work without retaining lookup state.
    fn peers(&self) -> Vec<Arc<Mutex<PeerState>>> {
        self.state.read().peers_by_key.values().cloned().collect()
    }

    /// Whether this exact peer handle remains in the configured packet set.
    fn contains_peer(&self, peer: &Arc<Mutex<PeerState>>) -> bool {
        self.state.read().peer_ids.contains(&peer_order_key(peer))
    }

    /// Register a handshake sender index only while its peer is still configured.
    fn register_handshake_idx(&self, packet: &WgKind, peer: &Arc<Mutex<PeerState>>) -> bool {
        let sender_idx = match packet {
            WgKind::HandshakeInit(packet) => Some(packet.sender_idx.get()),
            WgKind::HandshakeResp(packet) => Some(packet.sender_idx.get()),
            _ => None,
        };
        let mut state = self.state.write();
        if !state.peer_ids.contains(&peer_order_key(peer)) {
            return false;
        }
        if let Some(sender_idx) = sender_idx {
            state.peers_by_idx.insert(sender_idx, Arc::clone(peer));
        }
        true
    }

    /// Drop session indices whose underlying index-table reservation has expired.
    fn retain_live_indices(&self, index_table: &IndexTable) {
        self.state
            .write()
            .peers_by_idx
            .retain(|index, _| index_table.in_use(*index));
    }
}

/// Prepared authenticated work gathered from one peer in a receive batch.
struct PreparedIncomingRun {
    peer_key: usize,
    peer_arc: Arc<Mutex<PeerState>>,
    packets: Vec<(PreparedDecryption, std::net::SocketAddr)>,
}

#[cfg(test)]
tokio::task_local! {
    /// Marks code running inside the UDP receive task, so tests can check what it never does.
    static RECEIVE_TASK: ();
}

/// Handshake-queue drains that ran inside a UDP receive task, summed over this test binary.
///
/// The receive task must never drain (#260 round 2): a drain there blocks datagram processing for
/// as long as it runs. Tests compare this counter before and after the traffic they drive.
#[cfg(test)]
static RECEIVE_TASK_DRAINS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Count a drain if it runs inside the UDP receive task (test builds only).
#[cfg(test)]
fn note_drain_task() {
    if RECEIVE_TASK.try_with(|()| ()).is_ok() {
        RECEIVE_TASK_DRAINS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Everything a running packet or timer task may use to reach shared device state.
///
/// This is the type-level form of lock-order rule 1 in the module docs. A task gets a weak
/// liveness token and the synchronous packet lookup, and nothing that can reach the async
/// device lock. Configuration can therefore hold the device write lock while it stops and joins
/// these tasks, and a task waiting on peer state can never sit behind a queued configuration
/// writer (J380 P1 on #260).
#[derive(Clone)]
struct PacketTaskHandles {
    /// Upgrades only while the device still exists. Tasks stop once this fails.
    liveness: Weak<()>,
    /// Peer, route and session-index maps. Never hold one of its guards across an await.
    lookup: Arc<PacketLookup>,
    /// Asks the TUN task to drain a peer's handshake queue. Only that task ever drains one.
    flush_requests: Arc<FlushRequests>,
}

/// Peers whose handshake queue the TUN task should drain, posted by the UDP receive task.
///
/// Draining belongs to the TUN task alone (lock-order rule 3 in the module docs). The task that
/// reads the TUN is the only one that adds data packets behind a drain, so while it drains,
/// nothing can grow the queue it is emptying: each drain is bounded by the tunnel's queue limit.
/// When the drain ran in the UDP receive task instead, the TUN task kept queueing a full-rate
/// flood behind it, and receive processing stopped until the flood paused (#260 round 2).
///
/// Posting never waits, so the receive path stays free of the drain. A peer appears at most once,
/// so the list is bounded by the peer count.
#[derive(Default)]
struct FlushRequests {
    /// Requested peers, each at most once, by lane key.
    peers: parking_lot::Mutex<Vec<(usize, Arc<Mutex<PeerState>>)>>,
    /// Wakes the TUN task. A wake sent while it is busy is kept for its next wait.
    wake: tokio::sync::Notify,
}

impl FlushRequests {
    /// Ask the TUN task to drain this peer's queue soon. Returns at once.
    fn request(&self, peer_key: usize, peer: &Arc<Mutex<PeerState>>) {
        {
            let mut peers = self.peers.lock();
            if !peers.iter().any(|(key, _)| *key == peer_key) {
                peers.push((peer_key, Arc::clone(peer)));
            }
        }
        self.wake.notify_one();
    }

    /// Take every pending request, leaving the list empty.
    fn take(&self) -> Vec<(usize, Arc<Mutex<PeerState>>)> {
        std::mem::take(&mut *self.peers.lock())
    }
}

/// Handles one TUN task shares across every peer's outgoing runs.
struct OutgoingShared<U: UdpSend> {
    /// Worker pool handle for packet encryption.
    crypto: CryptoHandle,
    /// Per-peer ordered lanes for outgoing packets.
    ordered: Arc<OrderStore<WgKind>>,
    /// UDP writer for encrypted packets.
    udp: U,
    /// Reusable UDP batch buffer.
    send_many_buf: Arc<Mutex<U::SendManyBuf>>,
}

impl<U: UdpSend + Clone> OutgoingShared<U> {
    /// Build the run context for one peer and destination.
    fn batch_context(
        &self,
        peer_key: usize,
        peer_arc: &Arc<Mutex<PeerState>>,
        peer_addr: std::net::SocketAddr,
    ) -> OutgoingBatchContext<U> {
        OutgoingBatchContext {
            peer: OutgoingPeerContext {
                crypto: self.crypto.clone(),
                ordered: Arc::clone(&self.ordered),
                peer_arc: Arc::clone(peer_arc),
                peer_key,
                peer_addr,
                udp: self.udp.clone(),
            },
            send_many_buf: Arc::clone(&self.send_many_buf),
        }
    }
}

/// Device identity used by the UDP receive task to answer handshakes and rate-limit them.
struct HandshakeResponder {
    /// The device's static private key.
    private_key: x25519::StaticSecret,
    /// The public key matching `private_key`.
    public_key: x25519::PublicKey,
    /// Shared handshake rate limiter. Timers reset its counters.
    rate_limiter: Arc<RateLimiter>,
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
struct IncomingRunContext<TunTx> {
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
    /// Weak lifetime check without giving a queued callback access to the device lock.
    device: Weak<()>,
    /// Packet routes and session indices used without taking the async device lock.
    lookup: Arc<PacketLookup>,
    /// Tunnel writer cloned by each bounded delivery future.
    tun_tx: TunTx,
}

impl<TunTx: Clone> Clone for IncomingRunContext<TunTx> {
    /// Clone the shared handles needed by another run without cloning device state.
    fn clone(&self) -> Self {
        Self {
            crypto: self.crypto.clone(),
            ordered: Arc::clone(&self.ordered),
            peer_key: self.peer_key,
            lane: Arc::clone(&self.lane),
            peer_arc: Arc::clone(&self.peer_arc),
            device: self.device.clone(),
            lookup: Arc::clone(&self.lookup),
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
            .get_or_init(|| crate::diag::PIPELINE.on() || crate::diag::SEND_QUEUE.on());
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
            let failure_store = Arc::clone(&ordered);
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

                if let Some(packet) = packet {
                    match udp.send_to(packet.into(), peer_addr).await {
                        Err(err) if crate::udp::is_fatal_udp_error(&err) => {
                            failure_store.fail(format!("UDP send failed: {err}"));
                        }
                        Err(_) => tracing::trace!("udp.send_to failed"),
                        Ok(()) => {}
                    }
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
    let diagnostic = crate::diag::PIPELINE.on() || crate::diag::SEND_QUEUE.on();
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
            let ordered = Arc::clone(&ordered);
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
                        match result {
                            Err(err) if crate::udp::is_fatal_udp_error(&err) => {
                                ordered.fail(format!("UDP send failed: {err}"));
                            }
                            Err(_) => tracing::trace!("udp.send_to failed"),
                            Ok(()) => {}
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
                        match result {
                            Err(err) if crate::udp::is_fatal_udp_error(&err) => {
                                ordered.fail(format!("UDP send failed: {err}"));
                            }
                            Err(_) => tracing::trace!("udp.send_many_to failed"),
                            Ok(()) => {}
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

    /// Strong token used by packet tasks for a lifetime check without access to this device lock.
    task_liveness: Arc<()>,

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
    packet_lookup: Arc<PacketLookup>,
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
            PIPELINE_BUFS,
            pool.clone(),
            Arc::clone(&device.tun_tx),
            Arc::clone(&device.tun_rx),
        )
        .await;

        let buffered_udp_tx = BufferedUdpSend::new(UDP_SEND_BUFS, udp_tx.clone());

        // Linux sockets already return recvmmsg/GRO batches here. Avoid queueing them across a
        // second worker handoff before packet processing.
        #[cfg(target_os = "linux")]
        let incoming_udp_rx = udp_rx;
        #[cfg(not(target_os = "linux"))]
        let incoming_udp_rx = BufferedUdpReceive::new(
            crate::diag::udp_rx_queue().unwrap_or(PIPELINE_BUFS),
            udp_rx,
            pool.clone(),
        );

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
        let (private_key, public_key) = device.key_pair.clone().expect("Key not set");
        let rate_limiter = device
            .rate_limiter
            .as_ref()
            .expect("Setting a private key creates a rate limiter")
            .clone();
        let index_table = device.index_table.clone();
        let tun_rx_mtu = device.tun_rx_mtu.clone();
        let handles = PacketTaskHandles {
            liveness: Arc::downgrade(&device.task_liveness),
            lookup: Arc::clone(&device.packet_lookup),
            flush_requests: Arc::default(),
        };

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
        // Each packet and timer task fails the device when it panics or errors (`fatal_on_panic`),
        // so `Device::wait` reports it and the owner can rebuild the interface.
        let outgoing = Task::spawn(
            "handle_outgoing",
            fatal_on_panic(
                "handle_outgoing",
                DeviceState::<T>::handle_outgoing(
                    handles.clone(),
                    tun_rx_mtu,
                    buffered_ip_rx,
                    buffered_udp_tx.clone(),
                    pool.clone(),
                    crypto.clone(),
                    Arc::clone(&outgoing_order),
                ),
            )
            .map_err(register_fatal_error.clone()),
        );
        let timers = Task::spawn(
            "handle_timers",
            fatal_on_panic(
                "handle_timers",
                DeviceState::<T>::handle_timers(
                    handles.clone(),
                    index_table,
                    rate_limiter.clone(),
                    buffered_udp_tx.clone(),
                    crypto.clone(),
                    Arc::clone(&outgoing_order),
                )
                .map(Ok::<(), Error>),
            )
            .map_err(register_fatal_error.clone()),
        );
        let incoming_task = fatal_on_panic(
            "handle_incoming",
            DeviceState::<T>::handle_incoming(
                handles,
                HandshakeResponder {
                    private_key,
                    public_key,
                    rate_limiter,
                },
                buffered_ip_tx.clone(),
                buffered_udp_tx,
                incoming_udp_rx,
                pool.clone(),
                CryptoOrderContext {
                    crypto,
                    incoming: incoming_order,
                    outgoing: Arc::clone(&outgoing_order),
                },
            ),
        )
        .map_err(register_fatal_error.clone());
        // Test builds tag the receive task so tests can assert it never drains a queue.
        #[cfg(test)]
        let incoming_task = RECEIVE_TASK.scope((), incoming_task);
        let incoming = Task::spawn("handle_incoming", incoming_task);

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
        let (peer_arc, udp, packet_lookup) = {
            let device = self.inner.read().await;
            let connection = device.connection.as_ref().ok_or(Error::NotConnected)?;
            let peer_arc = Arc::clone(device.peers.get(public_key).ok_or(Error::PeerNotFound)?);
            (
                peer_arc,
                connection.udp.clone(),
                Arc::clone(&device.packet_lookup),
            )
        };

        let peer_key = peer_order_key(&peer_arc);
        let mut peer_trace = PeerLockDiagnostic::waiting("force_handshake", peer_key);
        let mut peer =
            lock_peer_state(&peer_arc, "force_handshake", peer_key, &mut peer_trace).await;
        if !packet_lookup.contains_peer(&peer_arc) {
            return Err(Error::PeerNotFound);
        }
        let Some(PendingHandshake {
            mut completed,
            initiation,
        }) = peer.force_handshake()?
        else {
            return Ok(());
        };

        let initiation = if let Some((packet, endpoint_addr)) = initiation {
            let packet = WgKind::from(packet);
            if !packet_lookup.register_handshake_idx(&packet, &peer_arc) {
                return Err(Error::PeerNotFound);
            }
            Some((packet, endpoint_addr))
        } else {
            None
        };
        drop(peer);
        drop(peer_trace);

        if let Some((packet, endpoint_addr)) = initiation {
            // NOTE: Like `handle_timers`, this does not trigger DAITA events.
            udp.send_to(packet.into(), endpoint_addr).await?;
        }

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
            self.packet_lookup.remove_peer(pub_key, &peer);

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
        self.packet_lookup.insert_peer(pub_key, peer, allowed_ips);

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
        } else if let Some(rekey_after) = crate::diag::rekey_after() {
            // Diagnostic only: frequent rekeys for rekey-under-load tests (see `diag`).
            tunn.dangerously_set_timer_params(crate::noise::TimerParams {
                rekey_after_time: rekey_after..=rekey_after,
                ..Default::default()
            });
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
        self.packet_lookup.clear();
        // TODO: tear down connection?
        n
    }

    /// Finish a contiguous receive run while holding peer state only once, retaining its first slot for diagnostics.
    async fn deliver_incoming_run(
        first_slot: u64,
        device: Weak<()>,
        lookup: Arc<PacketLookup>,
        peer_arc: Arc<Mutex<PeerState>>,
        completions: Vec<Option<IncomingCompletion>>,
        mut tun_tx: impl IpSend,
    ) -> Result<(), Error> {
        let diagnostic = crate::diag::PIPELINE.on() || crate::diag::SEND_QUEUE.on();
        let completion_count = completions.len();
        if diagnostic {
            eprintln!(
                "pipeline stage=incoming_delivery_callback_start completions={completion_count}"
            );
        }
        if device.upgrade().is_none() {
            return Ok(());
        }
        if diagnostic {
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
            let routed_to_this_peer = lookup
                .peer_by_ip(source)
                .is_some_and(|owner| Arc::ptr_eq(&owner, &peer_arc));
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
        let tunnel_packet_count = tun_packets.len();
        if diagnostic {
            eprintln!(
                "pipeline stage=incoming_release completions={completion_count} tunnel_results={tunnel_result_count} empty={empty_packet_count} malformed={malformed_packet_count} rejected_source={rejected_source_count} queued={tunnel_packet_count}"
            );
            eprintln!("pipeline stage=tun_queue_send_start packets={tunnel_packet_count}");
        }
        let sequence_diagnostic = crate::diag::SEND_QUEUE.on();
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
        context: IncomingRunContext<TunTx>,
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
            lookup,
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
            let lookup = Arc::clone(&lookup);
            let tun_tx = tun_tx.clone();
            pending.push(
                async move {
                    if crate::diag::PIPELINE.on()
                        || crate::diag::SEND_QUEUE.on()
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
                    if crate::diag::PIPELINE.on()
                        || crate::diag::SEND_QUEUE.on()
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
                            let lookup = Arc::clone(&lookup);
                            let peer_arc = Arc::clone(&peer_arc);
                            let tun_tx = tun_tx.clone();
                            async move {
                                Self::deliver_incoming_run(
                                    batch_first_slot,
                                    device,
                                    lookup,
                                    peer_arc,
                                    completions,
                                    tun_tx,
                                )
                                .await
                            }
                            },
                        )
                        .await;
                    if crate::diag::PIPELINE.on()
                        || crate::diag::SEND_QUEUE.on()
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
        device: Weak<()>,
        lookup: Arc<PacketLookup>,
        tun_tx: impl IpSend + Clone,
        run: PreparedIncomingRun,
    ) -> Result<(), Error> {
        if run.packets.is_empty() {
            return Ok(());
        }
        let diagnostic = crate::diag::PIPELINE.on() || crate::diag::SEND_QUEUE.on();
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
                lookup,
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

    /// Encrypt and send handshake-queued packets, in bounded runs, before newer TUN traffic.
    ///
    /// Runs in the TUN task only (see `FlushRequests`). `first` names a control packet's slot to
    /// wait for before the first run, as when the TUN task itself has just sent a handshake
    /// initiation. `flush_guard` must already be held; it is released once the queue is empty, or
    /// once a run has to stop (no usable session).
    async fn flush_handshake_queue<U: UdpSend + 'static>(
        device: Weak<()>,
        packet_lookup: Arc<PacketLookup>,
        context: OutgoingBatchContext<U>,
        first: Option<(Arc<OrderedCompletions<WgKind>>, u64)>,
        pending: &mut PendingOutgoing,
        flush_guard: parallel_crypto::FlushGuard<WgKind>,
    ) -> Result<(), Error> {
        #[cfg(test)]
        note_drain_task();
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

        // A drain that follows a control packet starts after that packet has been delivered.
        if let Some((first_lane, first_slot)) = first {
            wait_for_outgoing_slot(&first_lane, first_slot, pending).await;
        }

        loop {
            if device.upgrade().is_none() {
                return Ok(());
            }
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
            // Each run rechecks under the peer lock, since this loop releases the peer between
            // runs and removal takes only the device lock: a peer removed mid-drain sends nothing
            // more (J466 P3-A). Its queue goes away with its state.
            if !peer.tunnel.has_queued_packets() || !packet_lookup.contains_peer(&peer_arc) {
                drop(flush_guard.take());
                return Ok(());
            }

            let queued_count = peer.tunnel.queued_packet_count();
            let available = ordered.available(peer_key);
            if available == 0 {
                let lane = ordered.lane(peer_key);
                drop(peer);
                drop(peer_trace);
                let Some(lane) = lane else {
                    // The final completion can retire its idle lane between the capacity check
                    // and this lookup. Recheck under peer state; the active flush marker remains.
                    continue;
                };
                tokio::select! {
                    _ = lane.wait_for_capacity() => {}
                    _ = pending.next(), if !pending.is_empty() => {}
                }
                continue;
            }

            // Limit preparation to slots that can fit now. The peer mutex excludes every other
            // slot producer until the exact prepared run is reserved below.
            let run_limit = queued_count.min(CRYPTO_CHUNK_SIZE).min(available);
            let mut jobs = Vec::with_capacity(run_limit);
            let mut stop_after_chunk = false;
            for _ in 0..run_limit {
                let packet = peer
                    .tunnel
                    .take_queued_packet()
                    .expect("the queued packet count remains stable while peer state is locked");
                let prepared = peer.tunnel.prepare_queued_packet(packet);
                if let Some(PreparedOutgoing::Ready(packet)) = prepared.as_ref() {
                    stop_after_chunk = true;
                    if !packet_lookup.register_handshake_idx(packet, &peer_arc) {
                        // The peer was removed: keep the slot, send nothing (J433 P3-1).
                        jobs.push(None);
                        break;
                    }
                }
                if prepared.is_none() {
                    stop_after_chunk = true;
                }
                jobs.push(prepared);
                if stop_after_chunk {
                    break;
                }
            }

            if jobs.is_empty() {
                return Ok(());
            }

            // Preparation assigns packet counters. Keep peer state and the flush marker until
            // these packets own the matching contiguous sequence range, so a newer producer can
            // neither take counters nor reserve earlier slots.
            // Every producer reserves under peer state (lock-order rule 3), so the capacity checked
            // above is still there. If that invariant ever breaks, fail the device visibly: these
            // packets already own counters and cannot be reordered or dropped silently.
            let (chunk_lane, first_slot) =
                ordered.reserve_run(peer_key, jobs.len()).ok_or_else(|| {
                    Error::PipelineFailed(
                        "a handshake-queue run lost its checked sequence capacity".into(),
                    )
                })?;

            if stop_after_chunk || !peer.tunnel.has_queued_packets() {
                // The current run already owns its slots, so newer TUN reservations can follow it.
                drop(flush_guard.take());
            }
            drop(peer);
            drop(peer_trace);

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

    /// Drain one peer's handshake queue from the TUN task, ahead of any newer TUN packet.
    ///
    /// Call only from the TUN task, the single drainer. Does nothing when the queue is empty, no
    /// session exists yet, or another drain holds the marker. Otherwise it marks the drain under
    /// peer state, then runs [`DeviceState::flush_handshake_queue`], which keeps peer state and
    /// the marker through each run's slot reservation.
    async fn drain_queued_packets<U: UdpSend + Clone + 'static>(
        device: Weak<()>,
        packet_lookup: Arc<PacketLookup>,
        shared: &OutgoingShared<U>,
        peer_key: usize,
        peer_arc: &Arc<Mutex<PeerState>>,
        pending: &mut PendingOutgoing,
    ) -> Result<(), Error> {
        let mut peer_trace = PeerLockDiagnostic::waiting("handshake_queue_drain", peer_key);
        let mut pending_completions = PendingCompletions::Outgoing(pending);
        let peer = lock_peer_state_while_completing(
            peer_arc,
            "handshake_queue_drain",
            peer_key,
            &mut peer_trace,
            &mut pending_completions,
        )
        .await?;
        if !peer.tunnel.has_queued_packets() || !peer.tunnel.has_current_session() {
            return Ok(());
        }
        // The receive task may have requested this drain before configuration removed the peer;
        // send nothing to a removed (possibly revoked) peer, as on the TUN run path (J466 P3-A).
        if !packet_lookup.contains_peer(peer_arc) {
            return Ok(());
        }
        let Some(peer_addr) = peer.endpoint().addr else {
            return Ok(());
        };
        let Some(flush_guard) = shared.ordered.try_begin_flush(peer_key) else {
            return Ok(());
        };
        drop(peer);
        drop(peer_trace);
        Self::flush_handshake_queue(
            device,
            packet_lookup,
            shared.batch_context(peer_key, peer_arc, peer_addr),
            None,
            pending,
            flush_guard,
        )
        .await
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
        handles: PacketTaskHandles,
        index_table: IndexTable,
        rate_limiter: Arc<RateLimiter>,
        udp: impl UdpSend,
        crypto: CryptoHandle,
        outgoing_order: Arc<OrderStore<WgKind>>,
    ) {
        let PacketTaskHandles {
            liveness: device,
            lookup: packet_lookup,
            flush_requests: _,
        } = handles;
        loop {
            if device.upgrade().is_none() {
                break;
            }
            // Remove stale session indices. Once a session is stale it is dropped by
            // `update_session_timers`, and its associated index is freed from the table.
            packet_lookup.retain_live_indices(&index_table);

            // Keep resetting counts when a device has no peers, where per-peer timer updates
            // would otherwise never run.
            rate_limiter.try_reset_count();
            let peers = packet_lookup.peers();

            // This snapshot owns peer handles and does not retain lookup state during timer work.
            for peer in peers {
                let peer_key = peer_order_key(&peer);
                if outgoing_order.is_flushing(peer_key) {
                    continue;
                }
                let mut peer_trace = PeerLockDiagnostic::waiting("timer", peer_key);
                let mut p = lock_peer_state(&peer, "timer", peer_key, &mut peer_trace).await;
                if !packet_lookup.contains_peer(&peer)
                    || outgoing_order.is_flushing(peer_key)
                    || outgoing_order.available(peer_key) == 0
                {
                    // Leave due timers untouched until a bounded output slot is available.
                    continue;
                }
                let endpoint_addr = match p.endpoint().addr {
                    Some(addr) => addr,
                    None => continue,
                };

                match p.update_timers() {
                    Ok(Some(packet)) => {
                        // All slot producers for this peer hold its state lock, except for a
                        // control flush that is marked above. The free-slot check therefore
                        // remains valid until this reservation.
                        let Some((lane, slot)) = outgoing_order.reserve(peer_key) else {
                            tracing::warn!(
                                "Deferring timer packet because the peer order window filled"
                            );
                            continue;
                        };

                        if !packet_lookup.register_handshake_idx(&packet, &peer) {
                            drop(p);
                            drop(peer_trace);
                            complete_outgoing_packet(
                                OutgoingPeerContext {
                                    crypto: crypto.clone(),
                                    ordered: Arc::clone(&outgoing_order),
                                    peer_arc: Arc::clone(&peer),
                                    peer_key,
                                    peer_addr: endpoint_addr,
                                    udp: udp.clone(),
                                },
                                lane,
                                slot,
                                None,
                                false,
                            )
                            .await;
                            continue;
                        }

                        drop(p);
                        drop(peer_trace);

                        // NOTE: we don't bother with triggering TunnelRecv DAITA events here.
                        complete_outgoing_packet(
                            OutgoingPeerContext {
                                crypto: crypto.clone(),
                                ordered: Arc::clone(&outgoing_order),
                                peer_arc: Arc::clone(&peer),
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

            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// Read from UDP socket, decapsulate, write to tunnel device
    #[instrument(level = Level::TRACE, skip_all)]
    async fn handle_incoming(
        handles: PacketTaskHandles,
        responder: HandshakeResponder,
        mut tun_tx: impl IpSend + Clone,
        udp_tx: impl UdpSend + 'static,
        mut udp_rx: impl UdpRecv,
        mut packet_pool: PacketBufPool,
        crypto_order: CryptoOrderContext,
    ) -> Result<(), Error> {
        let PacketTaskHandles {
            liveness: device,
            lookup: packet_lookup,
            flush_requests,
        } = handles;
        let HandshakeResponder {
            private_key,
            public_key,
            rate_limiter,
        } = responder;
        let CryptoOrderContext {
            crypto,
            incoming: incoming_order,
            outgoing: outgoing_order,
        } = crypto_order;

        let mut udp_recv_buf = Default::default();
        let mut received_packets = Vec::new();
        let mut incoming_pending = PendingIncoming::new();
        let mut outgoing_pending = PendingOutgoing::new();

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
                reason = outgoing_order.failed() => {
                    return Err(Error::PipelineFailed(reason));
                }
                completed = outgoing_pending.next(), if !outgoing_pending.is_empty() => {
                    let _ = completed;
                }
                received = udp_rx.recv_many_from(
                    &mut udp_recv_buf,
                    &mut packet_pool,
                    &mut received_packets,
                ) => {
                    if crate::diag::PIPELINE.on() {
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
                                Arc::clone(&packet_lookup),
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
                            Arc::clone(&packet_lookup),
                            tun_tx.clone(),
                            run,
                        )
                        .await?;
                    }
                }

                if device.upgrade().is_none() {
                    return Ok(());
                }

                let peer = match &parsed_packet {
                    WgKind::HandshakeInit(p) => parse_handshake_anon(&private_key, &public_key, p)
                        .ok()
                        .and_then(|hh| {
                            packet_lookup
                                .peer_by_key(&x25519::PublicKey::from(hh.peer_static_public))
                        }),
                    WgKind::HandshakeResp(p) => packet_lookup.peer_by_index(p.receiver_idx.get()),
                    WgKind::CookieReply(p) => packet_lookup.peer_by_index(p.receiver_idx.get()),
                    WgKind::Data(p) => packet_lookup.peer_by_index(p.header.receiver_idx.get()),
                };
                let Some(peer_arc) = peer else { continue };
                let peer_key = peer_order_key(&peer_arc);

                match parsed_packet {
                    WgKind::Data(packet) => {
                        let counter = packet.header.counter.get();
                        if crate::diag::PIPELINE.on() {
                            eprintln!("pipeline stage=udp_data_arrival counter={counter}");
                            eprintln!("pipeline stage=incoming_peer_lock_wait counter={counter}");
                        }
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
                        if !packet_lookup.contains_peer(&peer_arc) {
                            continue;
                        }
                        if crate::diag::PIPELINE.on() {
                            eprintln!(
                                "pipeline stage=incoming_peer_lock_acquired counter={counter}"
                            );
                        }
                        match peer.prepare_incoming_data(packet) {
                            crate::noise::PreparedIncoming::Immediate(result) => {
                                // The serial data path also discarded packets without a session.
                                if crate::diag::PIPELINE.on() {
                                    eprintln!(
                                        "pipeline stage=incoming_prepare_immediate counter={counter}"
                                    );
                                }
                                drop(result);
                            }
                            crate::noise::PreparedIncoming::Decrypt { packet } => {
                                if crate::diag::PIPELINE.on() {
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
                                        Arc::clone(&packet_lookup),
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
                        drain_incoming_before_control(
                            incoming_order.lane(peer_key),
                            &mut incoming_pending,
                        )
                        .await?;

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
                        if !packet_lookup.contains_peer(&peer_arc) {
                            continue;
                        }
                        let peer_endpoint = peer.endpoint().addr;
                        let result = peer.handle_incoming_packet(packet, addr);
                        match result {
                            TunnResult::Done | TunnResult::Err(_) => {
                                drop(peer);
                                drop(peer_trace);
                            }
                            TunnResult::WriteToNetwork(packet) => {
                                // A handshake message or the keepalive after one. If it made a
                                // session usable for packets queued during the handshake, the TUN
                                // task drains them. This task only asks, and never waits on that
                                // drain (see `FlushRequests`).
                                let drain_queue = peer.tunnel.has_queued_packets()
                                    && peer.tunnel.has_current_session();
                                if !packet_lookup.register_handshake_idx(&packet, &peer_arc) {
                                    continue;
                                }
                                // Reserve while peer state is held, as every slot producer does
                                // (lock-order rule 3): a producer that checked capacity under the
                                // peer mutex can then rely on it until its own reservation. J433
                                // P1 (#260 88824): this task reserving without peer state could
                                // take the last slot between another producer's check and its
                                // reservation.
                                let mut reserved = outgoing_order.reserve(peer_key);
                                drop(peer);
                                drop(peer_trace);
                                if device.upgrade().is_none() {
                                    return Ok(());
                                }
                                let (lane, slot) = loop {
                                    if let Some(reserved) = reserved.take() {
                                        if crate::diag::PIPELINE.on() {
                                            eprintln!(
                                                "pipeline stage=control_slot_reserved peer={peer_key} slot={} pending={}",
                                                reserved.1,
                                                outgoing_pending.len()
                                            );
                                        }
                                        break reserved;
                                    }
                                    // The window is full: wait for delivery progress without peer
                                    // state, then retry the reservation under it.
                                    if let Some(lane) = outgoing_order.lane(peer_key) {
                                        if crate::diag::PIPELINE.on() {
                                            eprintln!(
                                                "pipeline stage=control_slot_wait peer={peer_key} available={} pending={}",
                                                lane.available(),
                                                outgoing_pending.len()
                                            );
                                        }
                                        tokio::select! {
                                            _ = lane.wait_for_capacity() => {}
                                            _ = outgoing_pending.next(), if !outgoing_pending.is_empty() => {}
                                        }
                                    }
                                    let mut peer_trace = PeerLockDiagnostic::waiting(
                                        "incoming_control_reserve",
                                        peer_key,
                                    );
                                    let mut pending_completions = PendingCompletions::Incoming(
                                        &mut incoming_pending,
                                        &mut outgoing_pending,
                                    );
                                    let _peer = lock_peer_state_while_completing(
                                        &peer_arc,
                                        "incoming_control_reserve",
                                        peer_key,
                                        &mut peer_trace,
                                        &mut pending_completions,
                                    )
                                    .await?;
                                    reserved = outgoing_order.reserve(peer_key);
                                };

                                while outgoing_pending.len() >= CRYPTO_CHUNK_SIZE {
                                    outgoing_pending
                                        .next()
                                        .await
                                        .expect("a full outgoing chunk has a completion future");
                                }
                                Self::enqueue_outgoing_packet(
                                    &mut outgoing_pending,
                                    OutgoingPeerContext {
                                        crypto: crypto.clone(),
                                        ordered: Arc::clone(&outgoing_order),
                                        peer_arc: Arc::clone(&peer_arc),
                                        peer_key,
                                        peer_addr: addr,
                                        udp: udp_tx.clone(),
                                    },
                                    lane,
                                    slot,
                                    Some(PreparedOutgoing::Ready(packet)),
                                    true,
                                );
                                if drain_queue {
                                    flush_requests.request(peer_key, &peer_arc);
                                }
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
                                drop(peer);
                                drop(peer_trace);
                                if device.upgrade().is_none() {
                                    return Ok(());
                                }
                                let routed_to_this_peer = packet_lookup
                                    .peer_by_ip(source)
                                    .is_some_and(|owner| Arc::ptr_eq(&owner, &peer_arc));
                                if !routed_to_this_peer {
                                    if cfg!(debug_assertions) {
                                        let unspecified =
                                            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into();
                                        tracing::warn!(
                                            "peer at {} is not allowed to send us packets from: {source}",
                                            peer_endpoint.unwrap_or(unspecified)
                                        );
                                    }
                                    continue;
                                }

                                if crate::diag::PIPELINE.on() {
                                    eprintln!("pipeline stage=incoming_control_tun_send_wait");
                                }
                                if let Err(e) = tun_tx.send(packet).await {
                                    tracing::trace!("buffered_tun_send.send failed");
                                    return Err(Error::IoError(e));
                                }
                                if crate::diag::PIPELINE.on() {
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
                    Arc::clone(&packet_lookup),
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
        handles: PacketTaskHandles,
        mut tun_mtu: MtuWatcher,
        mut tun_rx: impl IpRecv,
        udp: impl UdpSend + 'static,
        mut packet_pool: PacketBufPool,
        crypto: CryptoHandle,
        outgoing_order: Arc<OrderStore<WgKind>>,
    ) -> Result<(), Error> {
        let PacketTaskHandles {
            liveness: device,
            lookup: packet_lookup,
            flush_requests,
        } = handles;
        let mut pending = PendingOutgoing::new();
        let send_many_buf = Arc::new(Mutex::new(Default::default()));
        let shared = OutgoingShared {
            crypto: crypto.clone(),
            ordered: Arc::clone(&outgoing_order),
            udp: udp.clone(),
            send_many_buf: Arc::clone(&send_many_buf),
        };
        loop {
            tokio::select! {
                completed = pending.next(), if !pending.is_empty() => {
                    let _ = completed;
                    if crate::diag::PIPELINE.on() {
                        eprintln!("pipeline stage=outgoing_pending_complete remaining={}", pending.len());
                    }
                }
                reason = outgoing_order.failed() => {
                    return Err(Error::PipelineFailed(reason));
                }
                () = flush_requests.wake.notified() => {
                    for (peer_key, peer_arc) in flush_requests.take() {
                        if device.upgrade().is_none() {
                            return Ok(());
                        }
                        Self::drain_queued_packets(
                            device.clone(),
                            Arc::clone(&packet_lookup),
                            &shared,
                            peer_key,
                            &peer_arc,
                            &mut pending,
                        )
                        .await?;
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
                    if crate::diag::PIPELINE.on() {
                        eprintln!("pipeline stage=tun_receive packets={}", packets.len());
                    }

                    if device.upgrade().is_none() {
                        return Ok(());
                    }
                    let runs = group_by_key(packets.into_iter().filter_map(|packet| {
                        let dst_addr = packet.destination()?;
                        let Some(peer_arc) = packet_lookup.peer_by_ip(dst_addr)
                        else {
                            if cfg!(debug_assertions) {
                                tracing::trace!("Dropping packet with no routable peer");
                            }
                            return None;
                        };

                        Some((peer_order_key(&peer_arc), peer_arc, packet))
                    }));

                    for (peer_key, peer_arc, packets) in runs {
                        let mut packets = packets.into_iter().peekable();
                        // Drain at most once per run, so a session that refuses queued packets
                        // sends this run through the normal queueing path instead of looping.
                        let mut drained_queue = false;
                        while packets.peek().is_some() {
                            if device.upgrade().is_none() {
                                return Ok(());
                            }
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
                            // The peer may have been removed between the route lookup and this
                            // lock; send nothing to a removed (possibly revoked) peer. J433 P3-1.
                            if !packet_lookup.contains_peer(&peer_arc) {
                                break;
                            }
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

                            // Packets queued during a handshake leave before this newer run. This
                            // task is the only drainer (see `FlushRequests`), so nothing grows
                            // the queue while the drain runs.
                            if !drained_queue
                                && peer.tunnel.has_queued_packets()
                                && peer.tunnel.has_current_session()
                            {
                                drained_queue = true;
                                drop(peer);
                                drop(peer_trace);
                                Self::drain_queued_packets(
                                    device.clone(),
                                    Arc::clone(&packet_lookup),
                                    &shared,
                                    peer_key,
                                    &peer_arc,
                                    &mut pending,
                                )
                                .await?;
                                continue;
                            }

                            let available = outgoing_order.available(peer_key);
                            if available == 0 {
                                let lane = outgoing_order.lane(peer_key);
                                drop(peer);
                                drop(peer_trace);
                                if let Some(lane) = lane {
                                    if crate::diag::PIPELINE.on() {
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
                                    if !packet_lookup.register_handshake_idx(packet, &peer_arc) {
                                        // Removed since the check above (removal holds the device
                                        // lock, not this mutex): its initiation is not sent.
                                        prepared.push(None);
                                        break;
                                    }
                                    handshake_offset = Some(prepared.len());
                                    // Peer state is held and this task is the only drainer, so
                                    // no other marker can exist for this peer.
                                    flush_guard = outgoing_order.try_begin_flush(peer_key);
                                }
                                prepared.push(Some(prepared_packet));
                                if handshake_offset.is_some() {
                                    break;
                                }
                            }

                            // Capacity was checked under this peer mutex and every producer reserves
                            // under it (lock-order rule 3). A broken invariant fails the device
                            // visibly instead of panicking the TUN task.
                            let (lane, first_slot) = outgoing_order
                                .reserve_run(peer_key, prepared.len())
                                .ok_or_else(|| {
                                    Error::PipelineFailed(
                                        "a TUN run lost its checked sequence capacity".into(),
                                    )
                                })?;
                            drop(peer);
                            drop(peer_trace);

                            let batch_count = prepared.len().div_ceil(CRYPTO_BATCH_SIZE);
                            while pending.len() + batch_count > CRYPTO_CHUNK_SIZE {
                                if crate::diag::PIPELINE.on() {
                                    eprintln!(
                                        "pipeline stage=outgoing_pending_wait peer={peer_key} pending={} batches={batch_count}",
                                        pending.len()
                                    );
                                }
                                pending
                                    .next()
                                    .await
                                    .expect("a full outgoing run has a completion future");
                                if crate::diag::PIPELINE.on() {
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
                                    Arc::clone(&packet_lookup),
                                    batch_context,
                                    Some((lane, first_slot + offset as u64)),
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
