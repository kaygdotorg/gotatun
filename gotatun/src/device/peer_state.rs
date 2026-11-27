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

//! Stores per-peer tunnel state and compact route metadata; packet routing uses the shared lookup trie.

use ipnetwork::IpNetwork;

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::{Notify, watch};

#[cfg(feature = "daita")]
use crate::device::daita::{DaitaHooks, DaitaSettings};
use crate::noise::errors::WireGuardError;
use crate::noise::{Tunn, TunnResult, VerifiedDecryption};
#[cfg(feature = "daita")]
use crate::packet;
use crate::packet::{Packet, WgData, WgHandshakeInit, WgKind};
#[cfg(feature = "daita")]
use crate::tun::MtuWatcher;
#[cfg(feature = "daita")]
use crate::udp::UdpSend;

#[derive(Default, Debug)]
pub struct Endpoint {
    /// Where packets for this peer are sent: the configured address, or the source of the latest
    /// accepted packet, including a handshake initiation that has not yet proven key possession.
    pub addr: Option<SocketAddr>,
    /// The source of the latest packet that proved the sender holds the peer's key: decrypted
    /// transport data (keepalives included), or the response to a handshake we initiated.
    ///
    /// Unlike `addr`, an initiation never moves it. An initiation can be replayed from any
    /// address before the sender proves anything, so a caller that derives routing state from a
    /// peer's path (for example its MTU) should read this field. It is unset until the first
    /// proof and is cleared when the tunnel loses its last session.
    pub confirmed: Option<SocketAddr>,
}

/// A handshake initiated by [`PeerState::force_handshake`].
pub struct PendingHandshake {
    /// Notified when a handshake initiated by us completes.
    pub completed: watch::Receiver<()>,
    /// The initiation to send and where to send it, or `None` if one is already in flight.
    pub initiation: Option<(Packet<WgHandshakeInit>, SocketAddr)>,
}

pub struct PeerState {
    /// The associated tunnel struct
    pub(crate) tunnel: Tunn,
    pub(crate) endpoint: Endpoint,
    pub(crate) allowed_ips: Vec<IpNetwork>,

    #[cfg(feature = "daita")]
    daita_settings: Option<DaitaSettings>,
    #[cfg(feature = "daita")]
    pub(crate) daita: Option<DaitaHooks>,

    /// Notified whenever a handshake that we initiated completes.
    handshake_completed: watch::Sender<()>,

    /// The device's "a confirmed endpoint changed" signal, set when the device adds the peer
    /// (infraternal #260, J1253; see [`crate::device::Device::confirmed_endpoint_changes`]).
    pub(crate) confirmed_changes: Option<Arc<Notify>>,

    /// CoDel state for this peer's receive path (idle when `GOTATUN_AQM=off` or off Linux).
    /// Lives here because in-order delivery already holds the peer lock.
    pub(crate) aqm: crate::aqm::Codel,
}

/// Canonicalizes and deduplicates route metadata while preserving the old trie iteration order.
fn normalize_allowed_ips(allowed_ips: &mut Vec<IpNetwork>) {
    for allowed_ip in allowed_ips.iter_mut() {
        *allowed_ip = IpNetwork::new(allowed_ip.network(), allowed_ip.prefix())
            .expect("an existing IP network has a valid prefix");
    }

    allowed_ips.sort_unstable_by_key(|allowed_ip| (allowed_ip.network(), allowed_ip.prefix()));
    allowed_ips.dedup_by_key(|allowed_ip| (allowed_ip.network(), allowed_ip.prefix()));
}

impl PeerState {
    pub fn new(
        tunnel: Tunn,
        endpoint: Option<SocketAddr>,
        allowed_ips: &[IpNetwork],
        #[cfg(feature = "daita")] daita_settings: Option<DaitaSettings>,
    ) -> PeerState {
        let mut allowed_ips = allowed_ips.to_vec();
        normalize_allowed_ips(&mut allowed_ips);

        // Side-port opt-in starts from the bench switch (#260, J1159); `PeerMut::set_side_port`
        // overrides it per peer.
        let mut tunnel = tunnel;
        tunnel.set_side_port(crate::side_port::wanted());
        Self {
            tunnel,
            endpoint: Endpoint {
                addr: endpoint,
                confirmed: None,
            },
            allowed_ips,
            #[cfg(feature = "daita")]
            daita_settings,
            #[cfg(feature = "daita")]
            daita: None,
            handshake_completed: watch::Sender::new(()),
            confirmed_changes: None,
            aqm: crate::aqm::Codel::default(),
        }
    }

    /// Process an incoming packet received from `addr`.
    ///
    /// Any accepted packet updates the peer endpoint to `addr`. Only transport data and the
    /// response to our own initiation also update the confirmed endpoint; an accepted initiation
    /// does not, because it proves nothing until its sender's first data packet. Waiters are
    /// notified if the packet completes a handshake that we initiated.
    ///
    /// A data packet with the side mark (#260, J1159, [`crate::side_port`]) is delivered but
    /// moves neither endpoint, as in [`Self::complete_incoming_data`].
    pub fn handle_incoming_packet(&mut self, packet: WgKind, addr: SocketAddr) -> TunnResult {
        let is_handshake_resp = matches!(packet, WgKind::HandshakeResp(_));
        let side_port = matches!(&packet, WgKind::Data(data)
            if crate::side_port::is_marked(zerocopy::IntoBytes::as_bytes(&**data)));
        let result = self.tunnel.handle_incoming_packet(packet);
        match result {
            TunnResult::WriteToTunnel(_) if side_port => {}
            TunnResult::WriteToNetwork(_) => {
                self.endpoint.addr = Some(addr);
                if is_handshake_resp {
                    self.confirm_endpoint(addr);
                    self.notify_handshake_completed();
                }
            }
            TunnResult::WriteToTunnel(_) => {
                self.endpoint.addr = Some(addr);
                self.confirm_endpoint(addr);
            }
            // Don't update the peer endpoint on cookie replies, for consistency
            // with both the Linux kernel and wireguard-go.
            TunnResult::Done | TunnResult::Err(_) => {}
        }
        result
    }

    /// Apply the tunnel bookkeeping after a worker decrypts an incoming data packet.
    ///
    /// A packet that proves key possession moves the endpoint to `addr`, unless it carried the
    /// side mark (#260, J1159, [`crate::side_port`]): it left the peer's second socket, whose
    /// port the peer never wants traffic on, so the endpoint stays on the peer's main port.
    pub(crate) fn complete_incoming_data(
        &mut self,
        result: Result<VerifiedDecryption, WireGuardError>,
        addr: SocketAddr,
    ) -> TunnResult {
        let side_port = result
            .as_ref()
            .is_ok_and(VerifiedDecryption::came_from_side_port);
        let result = self.tunnel.complete_incoming_packet(result);
        if !side_port && matches!(result, TunnResult::WriteToTunnel(_)) {
            self.endpoint.addr = Some(addr);
            self.confirm_endpoint(addr);
        }
        result
    }

    /// Record `addr` as the confirmed endpoint after a packet proved key possession.
    ///
    /// This runs on every decrypted packet under the peer lock the caller already holds. It is a
    /// compare and, only when the source moved, a store and the device's change signal: no
    /// allocation.
    #[inline]
    fn confirm_endpoint(&mut self, addr: SocketAddr) {
        if self.endpoint.confirmed != Some(addr) {
            self.endpoint.confirmed = Some(addr);
            if let Some(changes) = &self.confirmed_changes {
                changes.notify_one();
            }
        }
    }

    /// Withdraw the authenticated endpoint when its sessions are gone. Keep the send address
    /// so the next handshake can try the same path.
    pub(super) fn clear_confirmed_endpoint(&mut self) {
        if self.endpoint.confirmed.take().is_some()
            && let Some(changes) = &self.confirmed_changes
        {
            changes.notify_one();
        }
    }

    /// Prepare a data packet for parallel decryption under its selected session.
    pub(crate) fn prepare_incoming_data(
        &mut self,
        packet: Packet<WgData>,
    ) -> crate::noise::PreparedIncoming {
        self.tunnel.prepare_incoming_packet(WgKind::Data(packet))
    }

    /// Subscribe to completions of handshakes that we initiated.
    ///
    /// The receiver only sees completions that happen after this call.
    fn subscribe_handshake_completed(&self) -> watch::Receiver<()> {
        self.handshake_completed.subscribe()
    }

    /// Wake everyone waiting on [`Self::subscribe_handshake_completed`].
    fn notify_handshake_completed(&self) {
        self.handshake_completed.send_replace(());
    }

    #[cfg(feature = "daita")]
    pub(crate) async fn maybe_start_daita<US: UdpSend + Clone + 'static>(
        peer: &std::sync::Arc<tokio::sync::Mutex<PeerState>>,
        pool: packet::PacketBufPool,
        tun_rx_mtu: MtuWatcher,
        udp_tx: US,
    ) -> Result<(), super::Error> {
        let peer_key = super::peer_order_key(peer);
        let mut peer_trace = super::PeerLockDiagnostic::waiting("daita_setup", peer_key);
        let mut peer_g =
            super::lock_peer_state(peer, "daita_setup", peer_key, &mut peer_trace).await;
        let Some(daita_settings) = peer_g.daita_settings.clone() else {
            // No DAITA settings; disabled
            return Ok(());
        };

        peer_g.daita = Some(DaitaHooks::new(
            daita_settings,
            std::sync::Arc::downgrade(peer),
            tun_rx_mtu,
            udp_tx,
            pool,
        )?);

        Ok(())
    }

    /// Ask the next timer pass to send this peer one keepalive if it has a current session;
    /// see [`Tunn::request_keepalive`]. Returns whether the request was taken.
    pub fn request_keepalive(&mut self) -> bool {
        self.tunnel.request_keepalive()
    }

    /// Run the tunnel timers and withdraw confirmation when the final session expires.
    pub fn update_timers(&mut self) -> Result<Option<WgKind>, WireGuardError> {
        let result = self.tunnel.update_timers();
        if self.endpoint.confirmed.is_some() && !self.tunnel.has_session() {
            self.clear_confirmed_endpoint();
        }
        result
    }

    /// Drop all sessions and endpoint confirmation, forcing a fresh handshake.
    pub fn reset(&mut self) {
        self.tunnel.reset();
        self.clear_confirmed_endpoint();
    }

    /// Start a handshake unless there is an active session or our own initiation is in flight.
    ///
    /// Returns `None` if there is an active session.
    pub fn force_handshake(&mut self) -> Result<Option<PendingHandshake>, super::Error> {
        if self.tunnel.has_active_session() {
            return Ok(None);
        }
        self.start_handshake(false).map(Some)
    }

    /// Start a new handshake now, even while a session is active or our own initiation is in
    /// flight.
    ///
    /// This is the initiation the rekey timer sends when it retries (`force_resend`): a fresh
    /// one with a new sender index, which replaces any initiation still in flight. The current
    /// session is not touched and keeps carrying data until the new handshake completes, so a
    /// working session is never lost. Callers use it when the peer's endpoint has just changed,
    /// so the first packet to the new address leaves at once instead of at the next keepalive.
    pub fn rehandshake(&mut self) -> Result<PendingHandshake, super::Error> {
        self.start_handshake(true)
    }

    /// Subscribe to the next completed handshake and format an initiation to the endpoint.
    /// With `force_resend` false, the initiation is `None` while ours is already in flight.
    fn start_handshake(&mut self, force_resend: bool) -> Result<PendingHandshake, super::Error> {
        let endpoint_addr = self.endpoint.addr.ok_or(super::Error::NoEndpoint)?;

        // Subscribe before creating the initiation so that a fast response cannot be missed
        let completed = self.subscribe_handshake_completed();

        // `None` means that our own initiation is already in flight
        let initiation = self
            .tunnel
            .format_handshake_initiation(force_resend)
            .map(|packet| (packet, endpoint_addr));

        Ok(PendingHandshake {
            completed,
            initiation,
        })
    }

    #[cfg(feature = "daita")]
    pub fn daita_settings(&self) -> Option<&DaitaSettings> {
        self.daita_settings.as_ref()
    }

    #[cfg(feature = "daita")]
    pub fn daita(&self) -> Option<&DaitaHooks> {
        self.daita.as_ref()
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Update the compact UAPI route list; packet lookup remains owned by the device routing trie.
    pub(crate) fn update_allowed_ips(
        &mut self,
        clear: bool,
        added: impl IntoIterator<Item = IpNetwork>,
    ) {
        if clear {
            self.allowed_ips.clear();
        }
        self.allowed_ips.extend(added);
        normalize_allowed_ips(&mut self.allowed_ips);
    }

    pub fn allowed_ips(&self) -> impl Iterator<Item = IpNetwork> + '_ {
        self.allowed_ips.iter().copied()
    }

    pub fn time_since_last_handshake(&self) -> Option<std::time::Duration> {
        self.tunnel.time_since_last_handshake()
    }

    pub fn persistent_keepalive(&self) -> Option<u16> {
        self.tunnel.persistent_keepalive()
    }

    pub fn preshared_key(&self) -> Option<[u8; 32]> {
        self.tunnel.preshared_key()
    }
}

#[cfg(test)]
mod confirmed_endpoint_tests {
    //! The confirmed endpoint moves only on packets that prove the peer's key.

    use super::PeerState;
    use crate::noise::{Tunn, TunnResult, index_table::IndexTable, rate_limiter::RateLimiter};
    use crate::packet::{Packet, WgKind};
    use crate::x25519::{PublicKey, StaticSecret};
    use futures::FutureExt as _;
    use std::net::SocketAddr;
    use std::sync::Arc;

    /// Build one side of a tunnel between `local` and the peer `remote`.
    fn tunnel(local: &StaticSecret, remote: &StaticSecret) -> Tunn {
        let public = PublicKey::from(local);
        Tunn::new(
            local.clone(),
            PublicKey::from(remote),
            None,
            None,
            IndexTable::from_os_rng(),
            Arc::new(RateLimiter::new(&public, 100)),
        )
    }

    /// Return the network packet `result` asks the caller to send.
    fn network(result: TunnResult) -> WgKind {
        match result {
            TunnResult::WriteToNetwork(packet) => packet,
            other => panic!("expected a packet for the network, got {other:?}"),
        }
    }

    /// A replayed initiation from a new source moves `addr` but never `confirmed`;
    /// authenticated data, and the response to our own initiation, move both (#489 J549 P1).
    /// A reset withdraws confirmation and keeps the last send address (#260 J1297 P1).
    #[test]
    fn only_authenticated_packets_move_the_confirmed_endpoint() {
        let initiator_key = StaticSecret::random_from_rng(rand_core::OsRng);
        let responder_key = StaticSecret::random_from_rng(rand_core::OsRng);
        let mut initiator = PeerState::new(
            tunnel(&initiator_key, &responder_key),
            None,
            &[],
            #[cfg(feature = "daita")]
            None,
        );
        let mut responder = PeerState::new(
            tunnel(&responder_key, &initiator_key),
            None,
            &[],
            #[cfg(feature = "daita")]
            None,
        );
        let real: SocketAddr = "192.0.2.10:51820".parse().unwrap();
        let forged: SocketAddr = "203.0.113.66:40000".parse().unwrap();
        let responder_addr: SocketAddr = "198.51.100.1:51820".parse().unwrap();

        // A genuine initiation: valid MAC1, valid static and timestamp, but no proof yet.
        let init = initiator.tunnel.format_handshake_initiation(false).unwrap();
        let response = network(responder.handle_incoming_packet(WgKind::from(init), real));
        assert_eq!(responder.endpoint().addr, Some(real));
        assert_eq!(responder.endpoint().confirmed, None);

        // The device's change signal fires once per change of a confirmed endpoint.
        let changes = Arc::new(tokio::sync::Notify::new());
        responder.confirmed_changes = Some(Arc::clone(&changes));
        let signalled = |changes: &tokio::sync::Notify| changes.notified().now_or_never().is_some();

        // Our own completed handshake confirms the responder's address on the initiator.
        let keepalive = network(initiator.handle_incoming_packet(response, responder_addr));
        assert_eq!(initiator.endpoint().confirmed, Some(responder_addr));

        // The initiator's first data packet proves its key to the responder.
        assert!(matches!(
            responder.handle_incoming_packet(keepalive, real),
            TunnResult::WriteToTunnel(_)
        ));
        assert_eq!(responder.endpoint().confirmed, Some(real));
        assert!(signalled(&changes), "the first proof is a change");

        // A fresh initiation the responder has not seen, delivered from another source, as a
        // replay would be: GotaTun accepts it and moves `addr`, `confirmed` must stay put.
        // With the mocked clock, time stands still; a later initiation needs a later timestamp.
        #[cfg(feature = "mock_instant")]
        mock_instant::thread_local::MockClock::advance(std::time::Duration::from_secs(1));
        let replayed = initiator.tunnel.format_handshake_initiation(true).unwrap();
        let _ = network(responder.handle_incoming_packet(WgKind::from(replayed), forged));
        assert_eq!(responder.endpoint().addr, Some(forged));
        assert_eq!(responder.endpoint().confirmed, Some(real));
        assert!(!signalled(&changes), "an unproven source is no change");

        // Authenticated data from a new source is a real roam and moves the confirmed endpoint.
        let roamed: SocketAddr = "192.0.2.20:51820".parse().unwrap();
        let data = initiator
            .tunnel
            .handle_outgoing_packet(Packet::from_bytes(bytes::BytesMut::new()), None)
            .unwrap();
        assert!(matches!(
            responder.handle_incoming_packet(data, roamed),
            TunnResult::WriteToTunnel(_)
        ));
        assert_eq!(responder.endpoint().addr, Some(roamed));
        assert_eq!(responder.endpoint().confirmed, Some(roamed));
        assert!(signalled(&changes), "a roam is a change");
        let again = initiator
            .tunnel
            .handle_outgoing_packet(Packet::from_bytes(bytes::BytesMut::new()), None)
            .unwrap();
        let _ = responder.handle_incoming_packet(again, roamed);
        assert!(!signalled(&changes), "the same source again is no change");

        responder.reset();
        assert_eq!(responder.endpoint().confirmed, None);
        assert_eq!(responder.endpoint().addr, Some(roamed));
        assert!(signalled(&changes), "reset withdraws the proof");
        responder.reset();
        assert!(!signalled(&changes), "no proof remains to withdraw");
    }

    /// The endpoint stays confirmed before expiry and is withdrawn as soon as the last
    /// session expires. A subsequent handshake can still use the send address (#260 J1297 P1).
    #[cfg(feature = "mock_instant")]
    #[test]
    fn the_last_session_expiry_withdraws_endpoint_confirmation() {
        use mock_instant::thread_local::MockClock;
        use std::time::Duration;

        let initiator_key = StaticSecret::random_from_rng(rand_core::OsRng);
        let responder_key = StaticSecret::random_from_rng(rand_core::OsRng);
        let mut initiator = tunnel(&initiator_key, &responder_key);
        let mut responder = PeerState::new(
            tunnel(&responder_key, &initiator_key),
            None,
            &[],
            #[cfg(feature = "daita")]
            None,
        );
        let changes = Arc::new(tokio::sync::Notify::new());
        responder.confirmed_changes = Some(Arc::clone(&changes));
        let addr = "192.0.2.10:51820".parse().unwrap();
        let init = initiator.format_handshake_initiation(false).unwrap();
        let response = network(responder.handle_incoming_packet(WgKind::from(init), addr));
        let keepalive = network(initiator.handle_incoming_packet(response));
        let _ = responder.handle_incoming_packet(keepalive, addr);
        assert_eq!(responder.endpoint().confirmed, Some(addr));
        assert!(changes.notified().now_or_never().is_some());

        MockClock::advance(Duration::from_secs(179));
        let _ = responder.update_timers();
        assert_eq!(responder.endpoint().confirmed, Some(addr));
        assert!(changes.notified().now_or_never().is_none());

        MockClock::advance(Duration::from_secs(2));
        let _ = responder.update_timers();
        assert_eq!(responder.endpoint().confirmed, None);
        assert_eq!(responder.endpoint().addr, Some(addr));
        assert!(changes.notified().now_or_never().is_some());
    }

    /// Data from the peer's side socket (side mark, #260 J1159) is delivered but moves neither
    /// endpoint, on the parallel and the serial receive path. Keepalives are never marked, and the
    /// same peer's unmarked data still roams.
    #[test]
    fn side_port_data_is_delivered_without_roaming() {
        use zerocopy::IntoBytes;

        let initiator_key = StaticSecret::random_from_rng(rand_core::OsRng);
        let responder_key = StaticSecret::random_from_rng(rand_core::OsRng);
        let new_state = |local: &StaticSecret, remote: &StaticSecret| {
            PeerState::new(
                tunnel(local, remote),
                None,
                &[],
                #[cfg(feature = "daita")]
                None,
            )
        };
        let mut initiator = new_state(&initiator_key, &responder_key);
        let mut responder = new_state(&responder_key, &initiator_key);
        let main: SocketAddr = "192.0.2.10:51820".parse().unwrap();
        let side: SocketAddr = "192.0.2.10:40001".parse().unwrap();
        let responder_addr: SocketAddr = "198.51.100.1:51820".parse().unwrap();

        let init = initiator.tunnel.format_handshake_initiation(false).unwrap();
        let response = network(responder.handle_incoming_packet(WgKind::from(init), main));
        let keepalive = network(initiator.handle_incoming_packet(response, responder_addr));
        let _ = responder.handle_incoming_packet(keepalive, main);
        assert_eq!(responder.endpoint().confirmed, Some(main));

        initiator.tunnel.set_side_port(true);
        let small = |initiator: &mut PeerState, len: usize| {
            let packet = Packet::from_bytes(bytes::BytesMut::zeroed(len));
            match initiator.tunnel.handle_outgoing_packet(packet, None) {
                Some(WgKind::Data(data)) => data,
                other => panic!("expected a data packet, got {other:?}"),
            }
        };

        // Parallel path: prepare, decrypt on a worker, complete under the peer lock.
        let data = small(&mut initiator, 64);
        assert!(crate::side_port::is_marked(data.as_bytes()));
        let crate::noise::PreparedIncoming::Decrypt { packet } =
            responder.prepare_incoming_data(data)
        else {
            panic!("a data packet with a session is decrypted on a worker");
        };
        assert!(matches!(
            responder.complete_incoming_data(packet.decrypt(), side),
            TunnResult::WriteToTunnel(_)
        ));
        assert_eq!(responder.endpoint().addr, Some(main));
        assert_eq!(responder.endpoint().confirmed, Some(main));

        // Serial path.
        let data = small(&mut initiator, 64);
        assert!(matches!(
            responder.handle_incoming_packet(WgKind::Data(data), side),
            TunnResult::WriteToTunnel(_)
        ));
        assert_eq!(responder.endpoint().addr, Some(main));

        // A keepalive is never marked, so it roams, like any unmarked data.
        let keepalive = small(&mut initiator, 0);
        assert!(!crate::side_port::is_marked(keepalive.as_bytes()));
        let roamed: SocketAddr = "192.0.2.20:51820".parse().unwrap();
        assert!(matches!(
            responder.handle_incoming_packet(WgKind::Data(keepalive), roamed),
            TunnResult::WriteToTunnel(_)
        ));
        assert_eq!(responder.endpoint().addr, Some(roamed));
        assert_eq!(responder.endpoint().confirmed, Some(roamed));
    }
}

#[cfg(all(test, target_pointer_width = "64", not(feature = "daita")))]
mod tests {
    //! Guard the per-peer inline footprint against retaining the duplicate route trie.

    use super::PeerState;

    #[test]
    fn idle_peer_state_stays_below_two_kibibytes() {
        let size = std::mem::size_of::<PeerState>();
        assert!(
            size <= 2 * 1024,
            "PeerState keeps {size} inline bytes; the peer-local route trie must be removed"
        );
    }
}
