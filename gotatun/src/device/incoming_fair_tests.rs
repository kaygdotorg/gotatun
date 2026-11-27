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

//! Receive-classification checks for the bounded pre-decryption fair queue.

use std::sync::Arc;

use bytes::BytesMut;
use zerocopy::{FromBytes, IntoBytes};

use super::{PacketLookup, QueuedIncomingData, classify_incoming_peer, queue_incoming_data};
use crate::{
    device::{IncomingFairQueue, tests::mock},
    packet::{Packet, WgData, WgDataHeader, WgKind},
};

/// Make an encrypted-data-shaped datagram with a selected visible receiver index.
fn forged_data_packet(receiver_index: u32) -> Packet<WgData> {
    let mut bytes = Packet::from_bytes(BytesMut::zeroed(WgData::OVERHEAD));
    let packet = WgData::mut_from_bytes(bytes.buf_mut()).expect("the buffer fits WgData");
    packet.header = WgDataHeader::new()
        .with_receiver_idx(receiver_index)
        .with_counter(0);
    let WgKind::Data(packet) = bytes.try_into_wg().expect("the header names a data packet") else {
        unreachable!("the header names a data packet");
    };
    packet
}

/// Find an index absent from the live session table without guessing whether one is reserved.
fn unknown_receiver_index(lookup: &PacketLookup) -> u32 {
    let state = lookup.state.read();
    (0..=u32::MAX)
        .find(|index| !state.peers_by_idx.contains_key(index))
        .expect("the session table cannot contain every 32-bit index")
}

/// A forged packet with a live receiver index consumes that peer's bounded pre-crypto budget.
///
/// The mock transport is in-memory; no test datagram reaches a host network interface. The tag
/// remains zero, so the queued packet is cryptographically invalid and cannot authenticate an
/// endpoint or reach delivery.
#[tokio::test]
async fn forged_packet_with_live_index_is_charged_before_crypto() {
    let (alice, mut bob, _eavesdropper) = mock::device_pair().await;
    let plaintext = mock::packet(b"establish a live receiver index");
    alice.app_tx.send(plaintext.clone()).await;
    assert_eq!(bob.app_rx.recv().await.as_bytes(), plaintext.as_bytes());

    let lookup = Arc::clone(&bob.device.inner.read().await.packet_lookup);
    let receiver_index = *lookup
        .state
        .read()
        .peers_by_idx
        .keys()
        .next()
        .expect("the completed handshake registered a receiver index");
    let packet = forged_data_packet(receiver_index);
    let peer_arc = lookup
        .peer_by_index(receiver_index)
        .expect("the receiver index maps to its peer");
    let source = peer_arc
        .lock()
        .await
        .endpoint()
        .confirmed
        .expect("the authenticated mock packet confirms the endpoint");
    let classified = classify_incoming_peer(&packet, &lookup, source)
        .expect("the forged packet still names the established peer's index");
    let peer_key = classified.peer_key;
    assert!(!classified.roaming_hint);
    let mut queue: IncomingFairQueue<QueuedIncomingData> = IncomingFairQueue::new();

    assert!(queue_incoming_data(&mut queue, classified, packet, source, 17).is_ok());

    assert_eq!(queue.len(), 1);
    assert_eq!(queue.peer_len(peer_key), 1);
    let (scheduled_peer, mut queued) = queue.pop_next().expect("the forged datagram is queued");
    assert_eq!(scheduled_peer, peer_key);
    assert_eq!(queued.receiver_index, receiver_index);
    assert_eq!(queued.rx_stamp, 17);
    assert_eq!(queued.packet.tag(), &[0; WgData::TAG_LEN]);
}

/// A candidate source gets one bounded queue entry without moving the peer's endpoint.
#[tokio::test]
async fn candidate_roaming_packet_uses_hint_without_committing_endpoint() {
    let (alice, mut bob, _eavesdropper) = mock::device_pair().await;
    let plaintext = mock::packet(b"establish the source endpoint");
    alice.app_tx.send(plaintext.clone()).await;
    assert_eq!(bob.app_rx.recv().await.as_bytes(), plaintext.as_bytes());

    let lookup = Arc::clone(&bob.device.inner.read().await.packet_lookup);
    let receiver_index = *lookup
        .state
        .read()
        .peers_by_idx
        .keys()
        .next()
        .expect("the completed handshake registered a receiver index");
    let peer_arc = lookup
        .peer_by_index(receiver_index)
        .expect("the receiver index maps to its peer");
    let original = peer_arc
        .lock()
        .await
        .endpoint()
        .addr
        .expect("the handshake records the current endpoint");
    let candidate_source = "192.0.2.11:51820"
        .parse()
        .expect("valid candidate endpoint");
    let packet = forged_data_packet(receiver_index);
    let classified = classify_incoming_peer(&packet, &lookup, candidate_source)
        .expect("the candidate packet names a live peer index");
    assert!(classified.roaming_hint);
    let peer_key = classified.peer_key;
    let mut queue: IncomingFairQueue<QueuedIncomingData> = IncomingFairQueue::new();

    assert!(
        queue_incoming_data(&mut queue, classified, packet, candidate_source, 23).is_ok(),
        "the candidate gets its reserved bounded slot"
    );

    assert_eq!(queue.peer_len(peer_key), 1);
    assert_eq!(bob.device.peers().await[0].peer.endpoint, Some(original));
}

/// An unknown receiver index is rejected before allocating any per-peer queue state.
#[tokio::test]
async fn unknown_receiver_index_is_dropped_before_queueing() {
    let (_alice, bob, _eavesdropper) = mock::device_pair().await;
    let lookup = Arc::clone(&bob.device.inner.read().await.packet_lookup);
    let receiver_index = unknown_receiver_index(&lookup);
    let packet = forged_data_packet(receiver_index);
    let queue: IncomingFairQueue<QueuedIncomingData> = IncomingFairQueue::new();

    assert!(classify_incoming_peer(&packet, &lookup, "10.0.0.1:51820".parse().unwrap()).is_none());
    assert!(queue.is_empty());
}
