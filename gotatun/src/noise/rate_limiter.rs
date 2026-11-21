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

use super::handshake::{b2s_hash, b2s_keyed_mac_16, b2s_keyed_mac_16_2, b2s_mac_24};
use crate::noise::handshake::{LABEL_COOKIE, LABEL_MAC1};
use crate::noise::{TunnResult, WireGuardError};
use crate::packet::{Packet, WgCookieReply, WgHandshakeBase, WgKind};

use constant_time_eq::constant_time_eq;
use gotatun_crypto::x25519;
#[cfg(feature = "mock_instant")]
use mock_instant::thread_local::Instant;
#[cfg(not(target_has_atomic = "64"))]
use portable_atomic::AtomicU64;
use rand::TryRngCore;
use std::net::{IpAddr, SocketAddr};
#[cfg(target_has_atomic = "64")]
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;

#[cfg(not(feature = "mock_instant"))]
use crate::sleepyinstant::Instant;

use aead::generic_array::GenericArray;
use aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305};
use rand::rngs::OsRng;

const COOKIE_REFRESH: u64 = 128; // Use 128 and not 120 so the compiler can optimize out the division
const COOKIE_SIZE: usize = 16;
const COOKIE_NONCE_SIZE: usize = 24;

/// How long the device stays under load after its handshake backlog last reached the limit.
///
/// The same one second that kernel WireGuard and wireguard-go hold "under load" for. Without a
/// hold, a flood that the queue limit just trims would flip cookie mode on and off with every
/// served message, and a legitimate initiator would get a cookie or not by chance.
const UNDER_LOAD_HOLD: Duration = Duration::from_secs(1);

type Cookie = [u8; COOKIE_SIZE];

/// There are two places where WireGuard requires "randomness" for cookies
/// * The 24 byte nonce in the cookie massage - here the only goal is to avoid nonce reuse
/// * A secret value that changes every two minutes
///
/// Because the main goal of the cookie is simply for a party to prove ownership of an IP address
/// we can relax the randomness definition a bit, in order to avoid locking, because using less
/// resources is the main goal of any DoS prevention mechanism.
/// In order to avoid locking and calls to rand we derive pseudo random values using the AEAD and
/// some counters.
pub struct RateLimiter {
    /// The key we use to derive the nonce
    nonce_key: [u8; 32],
    /// The key we use to derive the cookie
    secret_key: [u8; 16],
    start_time: Instant,
    /// A single 64 bit counter (should suffice for many years)
    nonce_ctr: AtomicU64,
    mac1_key: [u8; 32],
    cookie_key: Key,
    /// How many handshake messages must be waiting (see
    /// [`note_handshake_backlog`](Self::note_handshake_backlog)) before the device is under load.
    limit: u64,
    /// Nanoseconds after `start_time` until which the device is under load; 0 means never yet.
    ///
    /// Only ever raised (`fetch_max`), so the receive tasks of both address families can report
    /// their backlog without a lock and the latest deadline wins.
    under_load_until: AtomicU64,
}

impl RateLimiter {
    /// Create a new rate limiter for handshake packets.
    ///
    /// "Under load" is decided by the handshake backlog, as the WireGuard paper describes and
    /// kernel WireGuard implements, not by how many messages one source sent (#260, J1112).
    /// The device's receive task reports how many handshake messages are waiting with
    /// [`note_handshake_backlog`](Self::note_handshake_backlog); while that reaches `limit`,
    /// and for one second after, every handshake message needs a valid MAC2 and one without
    /// it is answered with a cookie reply. A limiter nobody reports to is never under load, so
    /// `u64::MAX` gives a limiter that only checks MAC1.
    ///
    /// # Arguments
    ///
    /// * `public_key` - The device's public key, used for cookie generation
    /// * `limit` - Waiting handshake messages at which the device is under load
    pub fn new(public_key: &x25519::PublicKey, limit: u64) -> Self {
        let mut secret_key = [0u8; 16];
        OsRng.try_fill_bytes(&mut secret_key).unwrap();
        RateLimiter {
            nonce_key: Self::rand_bytes(),
            secret_key,
            start_time: Instant::now(),
            nonce_ctr: AtomicU64::new(0),
            mac1_key: b2s_hash(LABEL_MAC1, public_key.as_bytes()),
            cookie_key: b2s_hash(LABEL_COOKIE, public_key.as_bytes()).into(),
            limit,
            under_load_until: AtomicU64::new(0),
        }
    }

    fn rand_bytes() -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.try_fill_bytes(&mut key).unwrap();
        key
    }

    /// Report that `waiting` handshake messages are queued for their key agreement.
    ///
    /// At `limit` or more, the device is under load from now until [`UNDER_LOAD_HOLD`] later.
    /// Below it nothing changes, so a hold that is running ends on time. Call it each time a
    /// queued message is about to be verified, with the number waiting at that moment.
    pub fn note_handshake_backlog(&self, waiting: usize) {
        if u64::try_from(waiting).unwrap_or(u64::MAX) < self.limit {
            return;
        }
        let hold = u64::try_from(UNDER_LOAD_HOLD.as_nanos()).unwrap_or(u64::MAX);
        let until = self.elapsed_nanos().saturating_add(hold);
        self.under_load_until.fetch_max(until, Ordering::Relaxed);
    }

    /// Whether the device is under load now: its backlog reached `limit` within the last
    /// [`UNDER_LOAD_HOLD`].
    pub fn is_under_load(&self) -> bool {
        self.elapsed_nanos() < self.under_load_until.load(Ordering::Relaxed)
    }

    /// Nanoseconds since this limiter was created, on the same clock as the cookie secret.
    fn elapsed_nanos(&self) -> u64 {
        u64::try_from(Instant::now().duration_since(self.start_time).as_nanos()).unwrap_or(u64::MAX)
    }

    /// Compute the correct cookie value based on the current secret value and the source address
    fn current_cookie(&self, addr: SocketAddr) -> Cookie {
        let mut addr_bytes = [0u8; 18]; // 16 for IP + 2 for port

        match addr.ip() {
            IpAddr::V4(a) => addr_bytes[..4].copy_from_slice(&a.octets()),
            IpAddr::V6(a) => addr_bytes[..16].copy_from_slice(&a.octets()),
        }
        addr_bytes[16..18].copy_from_slice(&addr.port().to_be_bytes());

        // The current cookie for a given IP is the MAC(responder.changing_secret_every_two_minutes,
        // initiator.address) First we derive the secret from the current time, the value
        // of cur_counter would change with time.
        let cur_counter = Instant::now().duration_since(self.start_time).as_secs() / COOKIE_REFRESH;

        // Next we derive the cookie
        b2s_keyed_mac_16_2(&self.secret_key, &cur_counter.to_le_bytes(), &addr_bytes)
    }

    fn nonce(&self) -> [u8; COOKIE_NONCE_SIZE] {
        let ctr = self.nonce_ctr.fetch_add(1, Ordering::Relaxed);

        b2s_mac_24(&self.nonce_key, &ctr.to_le_bytes())
    }

    pub(crate) fn format_cookie_reply(
        &self,
        idx: u32,
        cookie: Cookie,
        mac1: &[u8],
    ) -> WgCookieReply {
        let mut wg_cookie_reply = WgCookieReply::new();

        // msg.message_type = 3
        // msg.reserved_zero = { 0, 0, 0 }
        // msg.receiver_index = little_endian(initiator.sender_index)
        wg_cookie_reply.receiver_idx.set(idx);
        wg_cookie_reply.nonce = self.nonce();

        let cipher = XChaCha20Poly1305::new(&self.cookie_key);

        let iv = GenericArray::from_slice(&wg_cookie_reply.nonce);

        wg_cookie_reply.encrypted_cookie.encrypted = cookie;
        let tag = cipher
            .encrypt_in_place_detached(iv, mac1, &mut wg_cookie_reply.encrypted_cookie.encrypted)
            .expect("wg_cookie_reply is large enough");

        wg_cookie_reply.encrypted_cookie.tag = tag.into();
        wg_cookie_reply
    }

    /// Decode the packet as wireguard packet.
    /// Then, verify the MAC fields on the packet (if any), and apply rate limiting if needed.
    pub fn verify_packet(
        &self,
        src_addr: SocketAddr,
        packet: Packet,
    ) -> Result<WgKind, TunnResult> {
        let packet = packet
            .try_into_wg()
            .map_err(|_err| TunnResult::Err(WireGuardError::InvalidPacket))?;

        // Verify and rate limit handshake messages only
        match packet {
            WgKind::HandshakeInit(packet) => self
                .verify_handshake(src_addr, packet)
                .map(WgKind::HandshakeInit),
            WgKind::HandshakeResp(packet) => self
                .verify_handshake(src_addr, packet)
                .map(WgKind::HandshakeResp),
            _ => Ok(packet),
        }
    }

    /// Whether a handshake message's MAC1 is valid for this device.
    ///
    /// The cheap check (one keyed BLAKE2s) that keeps forged messages out of the handshake
    /// queue; [`verify_handshake`](Self::verify_handshake) checks it again when the message is
    /// served, together with the cookie.
    pub(crate) fn mac1_valid<P: WgHandshakeBase>(&self, handshake: &Packet<P>) -> bool {
        let computed_mac1 = b2s_keyed_mac_16(&self.mac1_key, handshake.until_mac1());
        constant_time_eq(&computed_mac1, handshake.mac1())
    }

    /// Verify the MAC fields on the handshake, and apply rate limiting if needed.
    ///
    /// Under load (see [`is_under_load`](Self::is_under_load)) a message without a valid MAC2
    /// is answered with a cookie reply instead, whoever sent it: initiations and responses
    /// alike, as kernel WireGuard does. Not under load, nothing is counted, so a burst of
    /// responses to our own initiations from one address (many peers behind one NAT or relay)
    /// is never turned away.
    pub(crate) fn verify_handshake<P: WgHandshakeBase>(
        &self,
        src_addr: SocketAddr,
        handshake: Packet<P>,
    ) -> Result<Packet<P>, TunnResult> {
        let sender_idx = handshake.sender_idx();
        let mac1 = handshake.mac1();
        let mac2 = handshake.mac2();

        let computed_mac1 = b2s_keyed_mac_16(&self.mac1_key, handshake.until_mac1());
        if !constant_time_eq(&computed_mac1, mac1) {
            return Err(TunnResult::Err(WireGuardError::InvalidMac));
        }

        if self.is_under_load() {
            let cookie = self.current_cookie(src_addr);
            let computed_mac2 = b2s_keyed_mac_16_2(&cookie, handshake.until_mac1(), mac1);

            if !constant_time_eq(&computed_mac2, mac2) {
                let cookie_reply = self.format_cookie_reply(sender_idx, cookie, mac1);
                let packet = handshake.overwrite_with(&cookie_reply);
                return Err(TunnResult::WriteToNetwork(packet.into()));
            }

            // If under load but mac2 is valid, allow the handshake
            return Ok(handshake);
        }

        Ok(handshake)
    }
}
