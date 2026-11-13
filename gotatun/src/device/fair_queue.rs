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

//! Fairly schedules a bounded batch of packets by peer and inner flow.

#[cfg(test)]
mod tests {
    use super::fair_schedule;

    /// A sparse flow gets service between packets from one bulk flow.
    #[test]
    fn sparse_inner_flow_advances_before_bulk_fifo_is_exhausted() {
        let scheduled = fair_schedule([
            (1, 10, "bulk-0"),
            (1, 10, "bulk-1"),
            (1, 11, "probe-0"),
            (1, 10, "bulk-2"),
            (1, 11, "probe-1"),
        ]);

        assert_eq!(
            scheduled,
            ["bulk-0", "probe-0", "bulk-1", "probe-1", "bulk-2"]
        );
    }

    /// Peer turns are equal while each peer's flows retain their own FIFO order.
    #[test]
    fn peers_get_equal_turns_and_each_inner_flow_keeps_fifo() {
        let scheduled = fair_schedule([
            (1, 10, "peer-a-bulk-0"),
            (1, 10, "peer-a-bulk-1"),
            (1, 11, "peer-a-sparse-0"),
            (2, 20, "peer-b-0"),
            (2, 20, "peer-b-1"),
            (1, 10, "peer-a-bulk-2"),
            (1, 11, "peer-a-sparse-1"),
        ]);

        assert_eq!(
            scheduled,
            [
                "peer-a-bulk-0",
                "peer-b-0",
                "peer-a-sparse-0",
                "peer-b-1",
                "peer-a-bulk-1",
                "peer-a-sparse-1",
                "peer-a-bulk-2",
            ]
        );
    }

    /// A batch with only one active peer and flow keeps its original order.
    #[test]
    fn one_peer_and_flow_keeps_fifo_order() {
        let scheduled = fair_schedule([
            (1, 10, "first"),
            (1, 10, "second"),
            (1, 10, "third"),
        ]);

        assert_eq!(scheduled, ["first", "second", "third"]);
    }
}
