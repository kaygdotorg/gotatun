// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

//! Diagnostic switches for the data path, read from the environment once.
//!
//! Each `GOTATUN_DIAG_*` variable turns on a trace or a forced code path that helps when
//! debugging the packet pipeline. They are meant for test runs, not for production.
//!
//! The data path checks these switches for every packet or batch. Reading the environment
//! there is expensive: each lookup takes the process environment lock, copies the name into a
//! C string and scans every variable. On a busy link that cost about 2% of the CPU (#260). So
//! the first check reads all switches at once and later checks only load a cached `bool`.
//!
//! The cache is never refreshed. Set the variables before the process starts; changing them
//! later has no effect.

use std::sync::LazyLock;

/// The cached state of every diagnostic switch.
struct Switches {
    pipeline: bool,
    send_queue: bool,
    force_inline: bool,
    force_workers: bool,
    tun_single_sends: bool,
    udp_single_sends: bool,
    disable_tun_gso: bool,
}

/// Switch state, filled on first use.
static SWITCHES: LazyLock<Switches> = LazyLock::new(|| {
    let set = |name: &str| std::env::var_os(name).is_some();
    Switches {
        pipeline: set("GOTATUN_DIAG_PIPELINE"),
        send_queue: set("GOTATUN_DIAG_SEND_QUEUE"),
        force_inline: set("GOTATUN_DIAG_FORCE_INLINE"),
        force_workers: set("GOTATUN_DIAG_FORCE_WORKERS"),
        tun_single_sends: set("GOTATUN_DIAG_TUN_SINGLE_SENDS"),
        udp_single_sends: set("GOTATUN_DIAG_UDP_SINGLE_SENDS"),
        disable_tun_gso: set("GOTATUN_DIAG_DISABLE_TUN_GSO"),
    }
});

/// `GOTATUN_DIAG_PIPELINE`: print one line on stderr for each pipeline stage a packet passes.
pub(crate) fn pipeline() -> bool {
    SWITCHES.pipeline
}

/// `GOTATUN_DIAG_SEND_QUEUE`: print the sequence of every batched TUN and UDP send.
pub(crate) fn send_queue() -> bool {
    SWITCHES.send_queue
}

/// `GOTATUN_DIAG_FORCE_INLINE`: always run packet crypto on the calling task.
pub(crate) fn force_inline() -> bool {
    SWITCHES.force_inline
}

/// `GOTATUN_DIAG_FORCE_WORKERS`: always hand packet crypto to the worker threads.
pub(crate) fn force_workers() -> bool {
    SWITCHES.force_workers
}

/// `GOTATUN_DIAG_TUN_SINGLE_SENDS`: write TUN batches one packet at a time.
pub(crate) fn tun_single_sends() -> bool {
    SWITCHES.tun_single_sends
}

/// `GOTATUN_DIAG_UDP_SINGLE_SENDS`: send UDP batches one datagram at a time.
pub(crate) fn udp_single_sends() -> bool {
    SWITCHES.udp_single_sends
}

/// `GOTATUN_DIAG_DISABLE_TUN_GSO`: write every TUN packet on its own, without coalescing.
pub(crate) fn disable_tun_gso() -> bool {
    SWITCHES.disable_tun_gso
}
