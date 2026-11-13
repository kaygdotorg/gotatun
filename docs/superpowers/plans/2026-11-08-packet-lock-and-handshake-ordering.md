# Packet Lock and Handshake Ordering Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the packet lookup/configuration writer cycle and make handshake queue packets reserve their peer sequence slots before newer TUN traffic can proceed.

**Architecture:** Packet tasks use a shared, short-held lookup index that clones peer handles without waiting on the async device lock. Configuration updates the index while holding the device lock and peer state lock. Handshake queue draining reserves each bounded prepared run while the peer lock and flush marker still exclude newer producers.

**Tech Stack:** Rust, Tokio, `parking_lot`, existing per-peer ordered crypto lanes.

**Spec:** J380 findings and J225 implementation requirements on #260.

## Global Constraints

- Preserve packet and replay order per peer.
- Keep each peer's in-flight packet window bounded.
- Do not add a crypto library or per-peer worker threads.
- Keep waits outside synchronous lookup and lane metadata locks.
- Keep timers free of device locks while they wait on peer state or lane capacity.
- Retain the existing worker pool, inline path, and idle lane retirement behavior.

## Review Focus

- A queued device writer must not prevent a packet path from looking up its peer while an earlier completion waits on peer state.
- The full-suite candidate timeout regressions are `test_indices` (4/4 timed out) and `one_handshake` (1/4 timed out); rerun both with the required features, alongside the other eavesdrop timeout cases.
- A handshake queue run must keep newer TUN reservations behind its reserved sequence range.
- A full per-peer window must defer handshake drain work without losing the flush marker or exceeding the bound.
- Peer removal or allowed-IP reconfiguration must not route later packets through stale lookup entries.
- Timer output must preserve the established peer and lane ordering.

---

### Task 1: Separate packet lookup from the async device lock

**Files:**
- Modify: `gotatun/src/device/mod.rs`
- Modify: `gotatun/src/device/configure.rs`
- Modify: `gotatun/src/device/builder.rs`
- Test: `gotatun/src/device/tests.rs`

**Interfaces:**
- `DeviceState` owns a shared `PacketLookup` index for peer identity, session indices, and allowed-IP routing.
- Packet tasks clone peer handles from `PacketLookup` and release its synchronous read guard before waiting on peer state.
- The module documentation records the device, lookup, peer, lane, completion, and timer lock order.

- [ ] Add the failing queued-writer delivery/lookup regression from J380.
- [ ] Run it on the candidate and record the expected stuck lookup.
- [ ] Move packet lookup and route checks to `PacketLookup`; ensure packet-task code does not retain the async device guard while waiting for peer state.
- [ ] Run the focused regression and J369/J380 tests with `--all-features`; repeat `test_indices` and `one_handshake` five times each, then run the six observed eavesdrop timeout cases: `ipv6_isnt_used`, `number_of_packets`, `one_handshake`, `one_keepalive`, `test_indices`, and `wg_data_length_is_x16`.
- [ ] Commit the lock redesign with its tests and lock-order documentation.

### Task 2: Reserve handshake queue slots under producer exclusion

**Files:**
- Modify: `gotatun/src/device/mod.rs`
- Modify: `gotatun/src/device/parallel_crypto.rs`

**Interfaces:**
- The active flush marker remains set until the current prepared queue run owns a contiguous sequence range.
- A flush prepares at most the currently available bounded lane capacity and waits for capacity only after releasing peer state.

- [ ] Add the red J380 reservation interleaving and assert the flush marker remains set while reservation is blocked.
- [ ] Reserve bounded runs before releasing the flush marker; defer when lane capacity is unavailable.
- [ ] Run the focused test, ordering/replay regressions, and candidate tests.
- [ ] Commit the queue reservation fix separately.

### Task 3: Platform and throughput verification

**Files:**
- No additional source changes unless a regression is found.

- [ ] Run the requested x86 test suite and clippy.
- [ ] Compare the candidate timeout cases against the recorded pre-J225 5/5 baseline; a filter reporting zero selected tests is invalid evidence.
- [ ] Batch the pending aarch64 checks on dev-02 and remove its target directory afterward.
- [ ] Run three 60-second transfer trials under the perf lock after coordination; record per-run steal and preserve the prior throughput gains.
- [ ] Push the final branch to both fork remotes and post test, lock-order, and transfer evidence on #260.
