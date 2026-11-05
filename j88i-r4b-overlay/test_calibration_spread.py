#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Check three-control calibration medians and the unpinned spread gate."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


def load_summarizer():
    """Load the calibration summarizer from the R4b overlay."""
    source = Path(__file__).parent / "base/lib/calibration_spread.py"
    if not source.is_file():
        raise AssertionError(f"missing calibration summary implementation: {source}")
    spec = importlib.util.spec_from_file_location("calibration_spread", source)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load calibration summary implementation: {source}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def control_rows() -> dict[str, dict[str, dict[str, float]]]:
    """Return three stable rows with distinguishable medians for each flow count."""
    return {
        "control-a": {
            "throughput_gbit_s": {"1": 2.50, "8": 2.40},
            "p50_ms": {"1": 2.60, "8": 5.80},
            "p99_loss_aware_ms": {"1": 8.40, "8": 17.50},
        },
        "control-b": {
            "throughput_gbit_s": {"1": 2.48, "8": 2.39},
            "p50_ms": {"1": 2.70, "8": 5.90},
            "p99_loss_aware_ms": {"1": 8.50, "8": 17.80},
        },
        "control-c": {
            "throughput_gbit_s": {"1": 2.49, "8": 2.405},
            "p50_ms": {"1": 2.65, "8": 5.85},
            "p99_loss_aware_ms": {"1": 8.45, "8": 17.60},
        },
    }


class CalibrationSpreadTest(unittest.TestCase):
    """Keep the stated median and max/min calibration rule reproducible."""

    def test_three_rows_use_medians_and_pass_within_unpinned_spread(self) -> None:
        """The returned control is the metric-wise median of exactly three rows."""
        module = load_summarizer()
        summary = module.summarize_rows(control_rows())

        self.assertTrue(summary["passed"], summary)
        self.assertEqual(summary["control_median"]["throughput_gbit_s"]["1"], 2.49)
        self.assertEqual(summary["control_median"]["p50_ms"]["8"], 5.85)
        self.assertEqual(summary["control_median"]["p99_loss_aware_ms"]["8"], 17.60)
        self.assertAlmostEqual(
            summary["spread_pct"]["p99_loss_aware_ms"]["8"],
            (17.80 / 17.50 - 1) * 100,
        )

    def test_spread_over_unpinned_limit_rejects_calibration(self) -> None:
        """A wide eight-flow p99 range cannot establish a control median for candidate holds."""
        module = load_summarizer()
        rows = control_rows()
        rows["control-b"]["p99_loss_aware_ms"]["8"] = 18.70

        summary = module.summarize_rows(rows)

        self.assertFalse(summary["passed"], summary)
        self.assertGreater(summary["spread_pct"]["p99_loss_aware_ms"]["8"], 5.9)

    def test_three_control_rows_are_required(self) -> None:
        """Two rows cannot satisfy the revised calibration protocol."""
        module = load_summarizer()
        rows = control_rows()
        del rows["control-c"]

        with self.assertRaises(ValueError):
            module.summarize_rows(rows)

    def test_results_reader_checks_the_actual_transmitted_probe_count(self) -> None:
        """A requested 3,600 probes do not pass when the raw ping footer reports less."""
        module = load_summarizer()
        with tempfile.TemporaryDirectory(prefix="j88i-calibration-files-") as temporary:
            root = Path(temporary)
            for row in ("control-a", "control-b", "control-c"):
                case_dir = root / row / "mesh-gotatun"
                case_dir.mkdir(parents=True)
                for flows in ("1", "8"):
                    (case_dir / f"tput-lan-{flows}.json").write_text(json.dumps({
                        "flows": int(flows),
                        "gbit_per_s": 2.5,
                        "machine_cpu_s_per_gbit": 0.9,
                    }))
                    (case_dir / f"icmp-lan-{flows}.raw").write_text(
                        "64 bytes from 10.66.0.2: icmp_seq=1 ttl=64 time=1.000 ms\n"
                        "3600 packets transmitted, 1 received, 99% packet loss, time 35999ms\n"
                    )

            _, probes = module.read_calibration_rows(root)
            self.assertEqual(probes["control-c"]["8"]["sent"], 3600)

            incomplete = root / "control-c/mesh-gotatun/icmp-lan-8.raw"
            incomplete.write_text(
                "64 bytes from 10.66.0.2: icmp_seq=1 ttl=64 time=1.000 ms\n"
                "3599 packets transmitted, 1 received, 99% packet loss, time 35999ms\n"
            )
            with self.assertRaisesRegex(ValueError, "sent 3599 probes"):
                module.read_calibration_rows(root)


if __name__ == "__main__":
    unittest.main()
