#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Exercise the cpuset audit sampler's command-line interface."""

from __future__ import annotations

import json
import importlib.util
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch


class CpusetAuditCliTest(unittest.TestCase):
    """Keep the positional interface used by the R4b shell helper working."""

    def test_sampler_accepts_output_and_parent_pid_arguments(self) -> None:
        """The sampler must write its summary when called with both arguments."""
        script = Path(__file__).parent / "base/lib/cpuset_audit.py"
        with tempfile.TemporaryDirectory(prefix="j88i-audit-") as temporary:
            output = Path(temporary)
            process = subprocess.Popen(
                [sys.executable, "-I", str(script), str(output), str(os.getpid())],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            time.sleep(1.1)
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
            _, stderr = process.communicate(timeout=10)

            summary_path = output / "summary.json"
            self.assertTrue(summary_path.is_file(), stderr)
            summary = json.loads(summary_path.read_text())
            self.assertGreaterEqual(summary["samples"], 1)
            self.assertIn(process.returncode, (0, 1), stderr)

    def test_task_values_reports_both_proc_cpu_masks(self) -> None:
        """The audit must retain Cpus_allowed and its readable list form."""
        script = Path(__file__).parent / "base/lib/cpuset_audit.py"
        with tempfile.TemporaryDirectory(prefix="j88i-import-") as temporary:
            with patch.dict(
                os.environ,
                {
                    "H2H_CPUSET_AUDIT_DIR": temporary,
                    "H2H_CPUSET_AUDIT_PARENT": str(os.getpid()),
                },
            ):
                spec = importlib.util.spec_from_file_location("cpuset_audit", script)
                self.assertIsNotNone(spec)
                self.assertIsNotNone(spec.loader if spec is not None else None)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

            values = module.task_values(os.getpid(), os.getpid())
            self.assertIsNotNone(values)
            self.assertIn("cpus_allowed", values)
            self.assertIn("allowed", values)

    def test_audit_stop_propagates_sampler_failure(self) -> None:
        """A failed placement audit must make the measured case fail too."""
        common = Path(__file__).parent / "base/lib/common.sh"
        with tempfile.TemporaryDirectory(prefix="j88i-stop-") as temporary:
            code = r"""
set -uo pipefail
export H2H_KIT=$1 H2H_RESULTS=$2 H2H_CASE=stop-test H2H_CPUSET_AUDIT=1
source "$H2H_KIT/lib/common.sh"
python3() { return 23; }
h2h_cpu_audit_start failed
if h2h_cpu_audit_stop; then
    exit 1
fi
trap - EXIT
"""
            result = subprocess.run(
                ["bash", "-c", code, "bash", str(common.parent.parent), temporary],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_irq_and_softirq_snapshots_report_per_cpu_deltas(self) -> None:
        """The audit must identify the CPUs that handled network softirq work."""
        script = Path(__file__).parent / "base/lib/cpuset_audit.py"
        spec = importlib.util.spec_from_file_location("cpuset_audit_counters", script)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader if spec is not None else None)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        before = """                CPU0       CPU1
NET_RX:             10         20
NET_TX:              2          4
"""
        after = """                CPU0       CPU1
NET_RX:             13         25
NET_TX:              2          6
"""

        self.assertEqual(
            module.counter_deltas(before, after),
            {"NET_RX": {"CPU0": 3, "CPU1": 5}, "NET_TX": {"CPU1": 2}},
        )


if __name__ == "__main__":
    unittest.main()
