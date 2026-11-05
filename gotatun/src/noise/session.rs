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

//! Session keys and counters for preparing and applying transport AEAD operations.

use crate::crypto::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use crate::{
    noise::errors::WireGuardError,
    noise::index_table::Index,
    packet::{Packet, WgData, WgDataHeader, WgKind},
};
use bytes::{Buf, BytesMut};
use parking_lot::Mutex;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use zerocopy::{FromBytes, IntoBytes};

/// The maximum number of transport data messages that may be sent or received under a single
/// session key, per section 6.2 of the [whitepaper](https://www.wireguard.com/papers/wireguard.pdf)
/// (`Reject-After-Messages = 2^64 - 2^13 - 1`).
/// Refusing to use a counter at or beyond this value guarantees the 64-bit AEAD nonce can never
/// wrap and reuse a nonce with the same key.
pub(super) const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);

/// Owns one pair of transport keys and their independent send and replay counters.
pub struct Session {
    pub(crate) receiving_index: Index,
    sending_index: u32,
    receiver: LessSafeKey,
    sender: LessSafeKey,
    sending_key_counter: AtomicU64,
    receiving_key_counter: Mutex<ReceivingKeyCounterValidator>,
}

/// A packet with its counter and header reserved, ready for worker encryption.
pub(crate) struct PreparedEncryption {
    session: Arc<Session>,
    packet: Packet<WgData>,
}

impl PreparedEncryption {
    /// Wire length reserved for tunnel statistics.
    pub(crate) fn packet_len(&self) -> usize {
        self.packet.as_bytes().len()
    }

    /// Whether the plaintext is a keepalive.
    pub(crate) fn is_keepalive(&self) -> bool {
        self.packet.is_keepalive()
    }

    /// Apply AEAD and return the encrypted packet.
    pub(crate) fn encrypt(self) -> WgKind {
        let packet = self.session.encrypt_packet_data(self.packet);
        packet.into()
    }
}

/// A received packet and session reference ready for worker decryption.
pub(crate) struct PreparedDecryption {
    session: Arc<Session>,
    session_slot: usize,
    packet: Packet<WgData>,
}

impl PreparedDecryption {
    /// Authenticate and decrypt a packet without advancing the replay window.
    pub(crate) fn decrypt(self) -> Result<VerifiedDecryption, WireGuardError> {
        let (counter, packet) = self.session.decrypt_packet_data(self.packet)?;
        Ok(VerifiedDecryption {
            session: self.session,
            session_slot: self.session_slot,
            counter,
            packet,
        })
    }
}

/// An authenticated plaintext whose replay counter is not committed until ordered release.
pub(crate) struct VerifiedDecryption {
    session: Arc<Session>,
    session_slot: usize,
    counter: u64,
    packet: Packet,
}

impl VerifiedDecryption {
    /// Commit the replay counter and retain session identity for tunnel bookkeeping.
    pub(crate) fn complete(self) -> Result<CompletedDecryption, WireGuardError> {
        self.session.receiving_counter_mark(self.counter)?;
        Ok(CompletedDecryption {
            session: self.session,
            session_slot: self.session_slot,
            packet: self.packet,
        })
    }
}

/// A replay-checked plaintext ready for the tunnel's receive counters and TUN path.
pub(crate) struct CompletedDecryption {
    session: Arc<Session>,
    session_slot: usize,
    packet: Packet,
}

impl CompletedDecryption {
    /// Whether this completion still points at the session stored in its original slot.
    pub(crate) fn belongs_to(&self, session: &Arc<Session>) -> bool {
        Arc::ptr_eq(&self.session, session)
    }

    /// Session slot selected when the incoming packet was prepared.
    pub(crate) fn session_slot(&self) -> usize {
        self.session_slot
    }

    /// Take the validated plaintext packet for tunnel accounting and routing.
    pub(crate) fn into_packet(self) -> Packet {
        self.packet
    }
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Session: {}<- ->{}",
            self.receiving_index, self.sending_index
        )
    }
}

// Receiving buffer constants
const WORD_SIZE: u64 = 64;
// 64*128 = 8192, matching the WireGuard replay window in both the Linux kernel and wireguard-go
const N_WORDS: u64 = 128;
const N_BITS: u64 = WORD_SIZE * N_WORDS;

#[derive(Debug, Clone)]
struct ReceivingKeyCounterValidator {
    /// In order to avoid replays while allowing for some reordering of the packets, we keep a
    /// bitmap of received packets, and the value of the highest counter
    next: u64,
    /// Used to estimate packet loss
    receive_cnt: u64,
    bitmap: [u64; N_WORDS as usize],
}

impl Default for ReceivingKeyCounterValidator {
    fn default() -> Self {
        // `derive(Default)` only covers arrays up to length 32, so implement it by hand.
        Self {
            next: 0,
            receive_cnt: 0,
            bitmap: [0u64; N_WORDS as usize],
        }
    }
}

impl ReceivingKeyCounterValidator {
    #[inline(always)]
    fn set_bit(&mut self, idx: u64) {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        self.bitmap[word] |= 1 << bit;
    }

    #[inline(always)]
    fn clear_bit(&mut self, idx: u64) {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        self.bitmap[word] &= !(1u64 << bit);
    }

    /// Clear the word that contains idx
    #[inline(always)]
    fn clear_word(&mut self, idx: u64) {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        self.bitmap[word] = 0;
    }

    /// Returns true if bit is set, false otherwise
    #[inline(always)]
    fn check_bit(&self, idx: u64) -> bool {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        ((self.bitmap[word] >> bit) & 1) == 1
    }

    /// Returns true if the counter was not yet received, and is not too far back
    #[inline(always)]
    fn will_accept(&self, counter: u64) -> Result<(), WireGuardError> {
        if counter >= self.next {
            // As long as the counter is growing no replay took place for sure
            return Ok(());
        }
        if counter + N_BITS < self.next {
            // Drop if too far back
            return Err(WireGuardError::InvalidCounter);
        }
        if self.check_bit(counter) {
            Err(WireGuardError::DuplicateCounter)
        } else {
            Ok(())
        }
    }

    /// Marks the counter as received, and returns true if it is still good (in case during
    /// decryption something changed)
    #[inline(always)]
    fn mark_did_receive(&mut self, counter: u64) -> Result<(), WireGuardError> {
        if counter + N_BITS < self.next {
            // Drop if too far back
            return Err(WireGuardError::InvalidCounter);
        }
        if counter == self.next {
            // Usually the packets arrive in order, in that case we simply mark the bit and
            // increment the counter
            self.set_bit(counter);
            self.next += 1;
            return Ok(());
        }
        if counter < self.next {
            // A packet arrived out of order, check if it is valid, and mark
            if self.check_bit(counter) {
                return Err(WireGuardError::InvalidCounter);
            }
            self.set_bit(counter);
            return Ok(());
        }
        // Packets where dropped, or maybe reordered, skip them and mark unused
        if counter - self.next >= N_BITS {
            // Too far ahead, clear all the bits
            for c in self.bitmap.iter_mut() {
                *c = 0;
            }
        } else {
            let mut i = self.next;
            while !i.is_multiple_of(WORD_SIZE) && i < counter {
                // Clear until i aligned to word size
                self.clear_bit(i);
                i += 1;
            }
            while i + WORD_SIZE < counter {
                // Clear whole word at a time
                self.clear_word(i);
                i = (i + WORD_SIZE) & 0u64.wrapping_sub(WORD_SIZE);
            }
            while i < counter {
                // Clear any remaining bits
                self.clear_bit(i);
                i += 1;
            }
        }
        self.set_bit(counter);
        self.next = counter + 1;
        Ok(())
    }
}

impl Session {
    pub(super) fn new(
        local_index: Index,
        sending_index: u32,
        receiving_key: [u8; 32],
        sending_key: [u8; 32],
    ) -> Session {
        Session {
            receiving_index: local_index,
            sending_index,
            receiver: LessSafeKey::new(
                UnboundKey::new(&CHACHA20_POLY1305, &receiving_key).unwrap(),
            ),
            sender: LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &sending_key).unwrap()),
            sending_key_counter: AtomicU64::new(0),
            receiving_key_counter: Mutex::new(Default::default()),
        }
    }

    /// Returns true if receiving counter is good to use
    fn receiving_counter_quick_check(&self, counter: u64) -> Result<(), WireGuardError> {
        let counter_validator = self.receiving_key_counter.lock();
        counter_validator.will_accept(counter)
    }

    /// Returns true if receiving counter is good to use, and marks it as used {
    fn receiving_counter_mark(&self, counter: u64) -> Result<(), WireGuardError> {
        let mut counter_validator = self.receiving_key_counter.lock();
        let ret = counter_validator.mark_did_receive(counter);
        if ret.is_ok() {
            counter_validator.receive_cnt += 1;
        }
        ret
    }

    /// Test-only: fast-forward the sending counter so the `REJECT_AFTER_MESSAGES` limit can be
    /// exercised without actually sending billions of packets.
    #[cfg(test)]
    pub(super) fn set_sending_key_counter(&self, value: u64) {
        self.sending_key_counter.store(value, Ordering::Relaxed);
    }

    /// Encapsulate `packet` into a [`WgData`].
    ///
    /// Returns `Err(packet)` (the original, un-encapsulated packet) once the sending counter has
    /// reached `REJECT_AFTER_MESSAGES`: the session must then be replaced by a fresh handshake
    /// before more transport data can be sent, so the AEAD nonce can never wrap.
    pub(super) fn format_packet_data(&self, packet: Packet) -> Result<Packet<WgData>, Packet> {
        // Check before incrementing so an exhausted counter is never advanced (and thus can never
        // wrap back around to a previously used value).
        if self.sending_key_counter.load(Ordering::Relaxed) >= REJECT_AFTER_MESSAGES {
            return Err(packet);
        }
        let sending_key_counter = self.sending_key_counter.fetch_add(1, Ordering::Relaxed);

        let packet = self.prepare_packet_data_with_counter(packet, sending_key_counter);
        Ok(self.encrypt_packet_data(packet))
    }

    /// Reserve a nonce and prepare a packet for encryption on a worker.
    pub(crate) fn prepare_packet_data(
        self: &Arc<Self>,
        packet: Packet,
    ) -> Result<PreparedEncryption, Packet> {
        if self.sending_key_counter.load(Ordering::Relaxed) >= REJECT_AFTER_MESSAGES {
            return Err(packet);
        }
        let sending_key_counter = self.sending_key_counter.fetch_add(1, Ordering::Relaxed);
        let packet = self.prepare_packet_data_with_counter(packet, sending_key_counter);
        Ok(PreparedEncryption {
            session: Arc::clone(self),
            packet,
        })
    }

    /// Reserve the header and plaintext bytes without touching the AEAD key.
    fn prepare_packet_data_with_counter(
        &self,
        packet: Packet,
        sending_key_counter: u64,
    ) -> Packet<WgData> {
        let len = WgData::OVERHEAD + packet.len();

        // Prepare a buffer to hold our the WgData packet and our encapsulated payload.
        // TODO: we can remove this allocation by pre-allocating some extra
        // space at the beginning of `packet`s allocation, and using that.
        let mut buf = Packet::from_bytes(BytesMut::zeroed(len));

        let data = WgData::mut_from_bytes(buf.buf_mut())
            .expect("buffer size is at least WgData::OVERHEAD");

        // Initialize wireguard header.
        data.header = WgDataHeader::new()
            .with_receiver_idx(self.sending_index)
            .with_counter(sending_key_counter);

        // Copy inner packet into place.
        debug_assert_eq!(packet.len(), data.encrypted_encapsulated_packet_mut().len());
        data.encrypted_encapsulated_packet_mut()
            .copy_from_slice(&packet);

        // Keep the reserved counter in the header until a worker applies AEAD.
        let packet = buf.try_into_wg().expect("is a wireguard packet");
        let WgKind::Data(packet) = packet else {
            unreachable!("is a wireguard data packet");
        };

        packet
    }

    /// Encrypt a packet whose counter was assigned on the serialized peer path.
    fn encrypt_packet_data(&self, mut packet: Packet<WgData>) -> Packet<WgData> {
        let sending_key_counter = packet.header.counter.get();
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&sending_key_counter.to_le_bytes());

        let tag = self
            .sender
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(&[]),
                packet.encrypted_encapsulated_packet_mut(),
            )
            .expect("encryption must succeed");

        packet.tag_mut().copy_from_slice(tag.as_ref());
        packet
    }

    /// Retain this session and slot so ordered completion can commit replay state later.
    pub(crate) fn prepare_receive_packet(
        self: &Arc<Self>,
        packet: Packet<WgData>,
        session_slot: usize,
    ) -> PreparedDecryption {
        PreparedDecryption {
            session: Arc::clone(self),
            session_slot,
            packet,
        }
    }

    /// Authenticate `packet` and return its counter without committing the replay window.
    fn decrypt_packet_data(
        &self,
        mut packet: Packet<WgData>,
    ) -> Result<(u64, Packet), WireGuardError> {
        if packet.header.receiver_idx.get() != self.receiving_index.value() {
            return Err(WireGuardError::WrongIndex);
        }

        let counter = packet.header.counter.get();

        if counter >= REJECT_AFTER_MESSAGES {
            return Err(WireGuardError::ConnectionExpired);
        }

        // This check avoids expensive AEAD work for counters already known to be replays. The
        // ordered completion stage checks again after authentication before setting the bitmap.
        self.receiving_counter_quick_check(counter)?;

        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&packet.header.counter.to_bytes());

        let decrypted_len = self
            .receiver
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(&[]),
                &mut packet.encrypted_encapsulated_packet_and_tag,
            )
            .map_err(|_| WireGuardError::InvalidAeadTag)?
            .len();

        let mut packet = packet.into_bytes();
        let buf = packet.buf_mut();
        buf.advance(WgDataHeader::LEN);
        buf.truncate(decrypted_len);
        Ok((counter, packet))
    }

    /// Decapsulate `packet`, then commit its replay counter on the synchronous tunnel path.
    pub(super) fn receive_packet_data(
        &self,
        packet: Packet<WgData>,
    ) -> Result<Packet, WireGuardError> {
        let (counter, packet) = self.decrypt_packet_data(packet)?;
        self.receiving_counter_mark(counter)?;
        Ok(packet)
    }

    /// Returns the estimated downstream packet loss for this session
    pub(super) fn current_packet_cnt(&self) -> (u64, u64) {
        let counter_validator = self.receiving_key_counter.lock();
        (counter_validator.next, counter_validator.receive_cnt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::index_table::IndexTable;

    /// Build a `Session` with throwaway keys and a real receiving index.
    fn test_session() -> Session {
        let table: IndexTable = IndexTable::from_os_rng();
        Session::new(table.new_index(), 0, [0u8; 32], [0u8; 32])
    }

    /// Craft a (cryptographically invalid) `WgData` packet with a chosen receiver index and
    /// counter, for exercising the receive-path checks that run before decryption.
    fn make_data_packet(receiver_idx: u32, counter: u64) -> Packet<WgData> {
        let mut buf = Packet::from_bytes(BytesMut::zeroed(WgData::OVERHEAD));
        let data = WgData::mut_from_bytes(buf.buf_mut()).expect("buffer is WgData::OVERHEAD");
        data.header = WgDataHeader::new()
            .with_receiver_idx(receiver_idx)
            .with_counter(counter);
        let WgKind::Data(packet) = buf.try_into_wg().expect("is a wireguard packet") else {
            unreachable!("is a wireguard data packet");
        };
        packet
    }

    /// The receive path must reject a counter at/beyond REJECT_AFTER_MESSAGES before decryption,
    /// while a counter just below the limit is allowed past that check (and fails later at AEAD).
    #[test]
    fn test_receive_rejects_counter_at_reject_after_messages() {
        let session = test_session();
        let recv_idx = session.receiving_index.value();

        let over_limit = make_data_packet(recv_idx, REJECT_AFTER_MESSAGES);
        assert!(matches!(
            session.receive_packet_data(over_limit),
            Err(WireGuardError::ConnectionExpired)
        ));

        let in_limit = make_data_packet(recv_idx, REJECT_AFTER_MESSAGES - 1);
        assert!(matches!(
            session.receive_packet_data(in_limit),
            Err(WireGuardError::InvalidAeadTag)
        ));
    }

    /// Worker decryption leaves replay state untouched until the packet reaches its ordered slot.
    #[test]
    fn prepared_decryption_defers_replay_update_until_ordered_completion() {
        let table: IndexTable = IndexTable::from_os_rng();
        let receiving_index = table.new_index();
        let receiver_index = receiving_index.value();
        let receiver = Arc::new(Session::new(receiving_index, 0, [7u8; 32], [9u8; 32]));
        let sender = Session::new(table.new_index(), receiver_index, [9u8; 32], [7u8; 32]);
        let plaintext = Packet::from_bytes(BytesMut::from(&[0u8; 20][..]));
        let encrypted = sender.format_packet_data(plaintext).unwrap();

        let decrypted = receiver
            .prepare_receive_packet(encrypted, 0)
            .decrypt()
            .unwrap();

        assert_eq!(receiver.current_packet_cnt().1, 0);
        let decrypted = decrypted.complete().unwrap().into_packet();
        assert_eq!(receiver.current_packet_cnt().1, 1);
        assert_eq!(decrypted.as_bytes(), &[0u8; 20]);
    }

    #[test]
    fn test_replay_counter() {
        let mut c: ReceivingKeyCounterValidator = Default::default();

        assert!(c.mark_did_receive(0).is_ok());
        assert!(c.mark_did_receive(0).is_err());
        assert!(c.mark_did_receive(1).is_ok());
        assert!(c.mark_did_receive(1).is_err());
        assert!(c.mark_did_receive(63).is_ok());
        assert!(c.mark_did_receive(63).is_err());
        assert!(c.mark_did_receive(15).is_ok());
        assert!(c.mark_did_receive(15).is_err());

        for i in 64..N_BITS + 128 {
            assert!(c.mark_did_receive(i).is_ok());
            assert!(c.mark_did_receive(i).is_err());
        }

        assert!(c.mark_did_receive(N_BITS * 3).is_ok());
        for i in 0..=N_BITS * 2 {
            assert!(matches!(
                c.will_accept(i),
                Err(WireGuardError::InvalidCounter)
            ));
            assert!(c.mark_did_receive(i).is_err());
        }
        for i in N_BITS * 2 + 1..N_BITS * 3 {
            assert!(c.will_accept(i).is_ok());
        }
        assert!(matches!(
            c.will_accept(N_BITS * 3),
            Err(WireGuardError::DuplicateCounter)
        ));

        for i in (N_BITS * 2 + 1..N_BITS * 3).rev() {
            assert!(c.mark_did_receive(i).is_ok());
            assert!(c.mark_did_receive(i).is_err());
        }

        assert!(c.mark_did_receive(N_BITS * 3 + 70).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 71).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 72).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 72 + 125).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 63).is_ok());

        assert!(c.mark_did_receive(N_BITS * 3 + 70).is_err());
        assert!(c.mark_did_receive(N_BITS * 3 + 71).is_err());
        assert!(c.mark_did_receive(N_BITS * 3 + 72).is_err());
    }
}
