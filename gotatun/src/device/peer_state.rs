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

//! Stores per-peer tunnel state and compact route metadata; packet routing uses the device trie.

use ipnetwork::IpNetwork;

use std::net::SocketAddr;

use tokio::sync::watch;

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
    pub addr: Option<SocketAddr>,
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

        Self {
            tunnel,
            endpoint: Endpoint { addr: endpoint },
            allowed_ips,
            #[cfg(feature = "daita")]
            daita_settings,
            #[cfg(feature = "daita")]
            daita: None,
            handshake_completed: watch::Sender::new(()),
        }
    }

    /// Process an incoming packet received from `addr`.
    ///
    /// Any authenticated packet updates the peer endpoint to `addr`. Waiters are notified if the
    /// packet completes a handshake that we initiated.
    pub fn handle_incoming_packet(&mut self, packet: WgKind, addr: SocketAddr) -> TunnResult {
        let is_handshake_resp = matches!(packet, WgKind::HandshakeResp(_));
        let result = self.tunnel.handle_incoming_packet(packet);
        match result {
            TunnResult::WriteToNetwork(_) => {
                self.endpoint.addr = Some(addr);
                if is_handshake_resp {
                    self.notify_handshake_completed();
                }
            }
            TunnResult::WriteToTunnel(_) => self.endpoint.addr = Some(addr),
            // Don't update the peer endpoint on cookie replies, for consistency
            // with both the Linux kernel and wireguard-go.
            TunnResult::Done | TunnResult::Err(_) => {}
        }
        result
    }

    /// Apply the tunnel bookkeeping after a worker decrypts an incoming data packet.
    pub(crate) fn complete_incoming_data(
        &mut self,
        result: Result<VerifiedDecryption, WireGuardError>,
        addr: SocketAddr,
    ) -> TunnResult {
        let result = self.tunnel.complete_incoming_packet(result);
        if matches!(result, TunnResult::WriteToTunnel(_)) {
            self.endpoint.addr = Some(addr);
        }
        result
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

    pub fn update_timers(&mut self) -> Result<Option<WgKind>, WireGuardError> {
        self.tunnel.update_timers()
    }

    /// Drop all sessions and reset the tunnel, forcing a fresh handshake.
    pub fn reset(&mut self) {
        self.tunnel.reset();
    }

    /// Start a handshake unless there is an active session or our own initiation is in flight.
    ///
    /// Returns `None` if there is an active session.
    pub fn force_handshake(&mut self) -> Result<Option<PendingHandshake>, super::Error> {
        if self.tunnel.has_active_session() {
            return Ok(None);
        }
        let endpoint_addr = self.endpoint.addr.ok_or(super::Error::NoEndpoint)?;

        // Subscribe before creating the initiation so that a fast response cannot be missed
        let completed = self.subscribe_handshake_completed();

        // `None` means that our own initiation is already in flight
        let initiation = self
            .tunnel
            .format_handshake_initiation(false)
            .map(|packet| (packet, endpoint_addr));

        Ok(Some(PendingHandshake {
            completed,
            initiation,
        }))
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
