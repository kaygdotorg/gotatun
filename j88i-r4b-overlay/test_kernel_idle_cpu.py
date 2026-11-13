#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Check idle CPU accounting for kernel and userspace tunnel engines."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


SAMPLER = Path(__file__).parent / "base/lib/kernel_idle_cpu.py"
SPEC = importlib.util.spec_from_file_location("kernel_idle_cpu_test_target", SAMPLER)
assert SPEC is not None and SPEC.loader is not None
KERNEL_IDLE_CPU = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(KERNEL_IDLE_CPU)


class KernelIdleCpuTest(unittest.TestCase):
    """Keep an idle kernel row measurable without hiding missing userspace data."""

    def test_kernel_idle_sample_accepts_available_softirq_counters(self) -> None:
        """Zero softirq deltas are a valid kernel idle measurement without crypto workers."""
        before = {
            "engine_process": {},
            "wireguard_crypto": {},
            "network_softirq": {"27": 100, "33": 200, "39": 300, "45": 400},
        }
        after = {
            "engine_process": {},
            "wireguard_crypto": {},
            "network_softirq": {"27": 100, "33": 200, "39": 300, "45": 400},
        }

        result = KERNEL_IDLE_CPU.summarize_window(
            before, after, seconds=10.0, hz=100.0, engine="kernel-plain"
        )

        self.assertEqual(result["status"], "measured")
        self.assertEqual(result["cpu_s_per_minute"], 0.0)
        self.assertEqual(result["engine_cpu_s_per_minute"], 0.0)
        self.assertEqual(result["network_softirq_cpu_s_per_minute"], 0.0)

    def test_userspace_idle_sample_still_requires_engine_process_counters(self) -> None:
        """A softirq sample alone must not mask a missing userspace process sample."""
        sample = {
            "engine_process": {},
            "wireguard_crypto": {},
            "network_softirq": {"27": 100, "33": 200, "39": 300, "45": 400},
        }

        result = KERNEL_IDLE_CPU.summarize_window(
            sample, sample, seconds=10.0, hz=100.0, engine="gotatun"
        )

        self.assertEqual(result["status"], "unavailable")
        self.assertIsNone(result["cpu_s_per_minute"])


if __name__ == "__main__":
    unittest.main()
