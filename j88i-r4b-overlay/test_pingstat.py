#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Check that raw ping percentiles count missing replies as infinite RTT."""

from __future__ import annotations

import importlib.util
import math
import tempfile
import unittest
from pathlib import Path


class PingStatsTest(unittest.TestCase):
    """Protect the loss-aware percentile rule used by the R4b keep table."""

    def test_loss_above_one_percent_makes_p99_infinite(self) -> None:
        """A loss rate above one percent pushes the p99 rank to infinity."""
        script = Path(__file__).parent / "base/lib/pingstat.py"
        spec = importlib.util.spec_from_file_location("pingstat", script)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader if spec is not None else None)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        with tempfile.TemporaryDirectory(prefix="j88i-pingstat-") as temporary:
            sample = Path(temporary) / "ping.txt"
            replies = "".join(
                f"[1.000000] 64 bytes from peer: icmp_seq={seq} ttl=64 time={seq / 1000:.3f} ms\n"
                for seq in range(1, 98)
            )
            sample.write_text(replies + "100 packets transmitted, 97 received\n")

            summary = module.stats([sample])

        self.assertEqual((summary["sent"], summary["lost"]), (100, 3))
        self.assertAlmostEqual(summary["p50_received_ms"], 0.049)
        self.assertAlmostEqual(summary["p99_received_ms"], 0.097)
        self.assertTrue(math.isinf(summary["p99_loss_aware_ms"]))
        self.assertTrue(math.isinf(summary["p999_loss_aware_ms"]))
        self.assertAlmostEqual(summary["max_received_ms"], 0.097)

    def test_loss_below_one_percent_keeps_exact_p99_finite(self) -> None:
        """The p99 rank includes drops at infinity, while a sub-one-percent loss stays finite."""
        script = Path(__file__).parent / "base/lib/pingstat.py"
        spec = importlib.util.spec_from_file_location("pingstat_low_loss", script)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader if spec is not None else None)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        with tempfile.TemporaryDirectory(prefix="j88i-pingstat-low-loss-") as temporary:
            sample = Path(temporary) / "ping.txt"
            replies = "".join(
                f"[1.000000] 64 bytes from peer: icmp_seq={seq} ttl=64 time={seq / 1000:.3f} ms\n"
                for seq in range(1, 996)
            )
            sample.write_text(replies + "1000 packets transmitted, 995 received\n")

            summary = module.stats([sample])

        self.assertEqual((summary["sent"], summary["lost"]), (1000, 5))
        self.assertAlmostEqual(summary["p99_received_ms"], 0.986)
        self.assertAlmostEqual(summary["p99_loss_aware_ms"], 0.990)
        self.assertTrue(math.isinf(summary["p999_loss_aware_ms"]))
        self.assertAlmostEqual(summary["max_received_ms"], 0.995)

    def test_no_loss_keeps_p99_equal_to_received_p99(self) -> None:
        """With no drops, the keep metric is the observed raw p99."""
        script = Path(__file__).parent / "base/lib/pingstat.py"
        spec = importlib.util.spec_from_file_location("pingstat", script)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader if spec is not None else None)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        with tempfile.TemporaryDirectory(prefix="j88i-pingstat-clean-") as temporary:
            sample = Path(temporary) / "ping.txt"
            replies = "".join(
                f"[1.000000] 64 bytes from peer: icmp_seq={seq} ttl=64 time={seq / 1000:.3f} ms\n"
                for seq in range(1, 101)
            )
            sample.write_text(replies + "100 packets transmitted, 100 received\n")
            summary = module.stats([sample])

        self.assertEqual((summary["sent"], summary["lost"]), (100, 0))
        self.assertAlmostEqual(summary["p99_loss_aware_ms"], summary["p99_received_ms"])

    def test_expected_probe_count_covers_an_incomplete_ping_summary(self) -> None:
        """A killed ping process cannot hide probes absent from its final summary."""
        script = Path(__file__).parent / "base/lib/pingstat.py"
        spec = importlib.util.spec_from_file_location("pingstat_incomplete", script)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader if spec is not None else None)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        with tempfile.TemporaryDirectory(prefix="j88i-pingstat-incomplete-") as temporary:
            sample = Path(temporary) / "ping.txt"
            sample.write_text(
                "[1.000000] 64 bytes from peer: icmp_seq=1 ttl=64 time=0.050 ms\n"
                "[1.005000] 64 bytes from peer: icmp_seq=2 ttl=64 time=0.060 ms\n"
            )
            summary = module.stats([sample], expected_sent=3)

        self.assertEqual((summary["sent"], summary["lost"]), (3, 1))
        self.assertTrue(math.isinf(summary["p99_loss_aware_ms"]))


if __name__ == "__main__":
    unittest.main()
