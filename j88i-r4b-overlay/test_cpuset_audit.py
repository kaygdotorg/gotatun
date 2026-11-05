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

    def test_d348_audit_uses_two_test_pairs_and_housekeeping_cpus(self) -> None:
        """Reserve CPUs 0 and 5 for host work and give each side two cores."""
        script = Path(__file__).parent / "base/lib/cpuset_audit.py"
        spec = importlib.util.spec_from_file_location("cpuset_audit_topology", script)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader if spec is not None else None)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        self.assertEqual(module.TEST_CPUS, {1, 2, 3, 4})
        self.assertEqual(
            module.EXPECTED_MASKS,
            {frozenset({1, 2}), frozenset({3, 4})},
        )

    def test_scope_spawn_sets_a_pid_output_name_that_matches_its_local_name(self) -> None:
        """The spawn helper must assign output variables even when callers name one `pid`."""
        common = Path(__file__).parent / "base/lib/common.sh"
        code = r"""
set -euo pipefail
export H2H_KIT=$1 H2H_CASE=scope-output H2H_CPUSET_PIN=0
source "$H2H_KIT/lib/common.sh"
h2h_scope_spawn pid 0-1 sleep 0.1
[[ ${pid:-} =~ ^[0-9]+$ ]] || { echo "scope pid output was not set" >&2; exit 1; }
wait "$H2H_SCOPE_CLIENT_PID"
"""
        result = subprocess.run(
            ["bash", "-c", code, "bash", str(common.parent.parent)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_sampler_signals_only_a_clean_startup_before_loaded_samples(self) -> None:
        """The workload must stay stopped until the sampler sees a clean CPU set."""
        script = Path(__file__).parent / "base/lib/cpuset_audit.py"
        with tempfile.TemporaryDirectory(prefix="j88i-ready-") as temporary:
            output = Path(temporary) / "audit"
            ready = Path(temporary) / "ready"
            output.mkdir()
            with patch.dict(
                os.environ,
                {
                    "H2H_CPUSET_AUDIT_READY_FILE": str(ready),
                },
            ):
                spec = importlib.util.spec_from_file_location("cpuset_audit_ready", script)
                self.assertIsNotNone(spec)
                self.assertIsNotNone(spec.loader if spec is not None else None)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

            dirty = {
                "scope_threads": 1,
                "scope_processes": [],
                "mask_mismatches": [],
                "external_runnable": [{"pid": 1}],
                "kernel_softirq_runnable": [],
                "cpu_pressure": "",
            }
            clean = {**dirty, "external_runnable": []}
            samples = iter([dirty, clean, clean])
            sleep_calls = 0

            def stop_after_loaded_sample(_seconds: float) -> None:
                nonlocal sleep_calls
                sleep_calls += 1
                if ready.is_file() or sleep_calls >= 3:
                    module.STOP = True

            with (
                patch.dict(os.environ, {"H2H_CPUSET_AUDIT_READY_FILE": str(ready)}),
                patch.object(module, "sample", side_effect=lambda: next(samples)),
                patch.object(module, "snapshot"),
                patch.object(module.signal, "signal"),
                patch.object(module.time, "sleep", side_effect=stop_after_loaded_sample),
                patch("sys.argv", [str(script), str(output), str(os.getpid())]),
                patch.object(module, "STOP", False),
            ):
                module.main()

            self.assertTrue(ready.is_file(), "a clean preflight must release the stopped workload")
            summary = json.loads((output / "summary.json").read_text())
            self.assertEqual(summary["samples"], 1, summary)
            self.assertEqual(summary["external_runnable_samples"], 0, summary)

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
wait_for() { return 0; }
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

    def test_kernel_wireguard_crypto_worker_is_workload_only_for_kernel_netbird(self) -> None:
        """Only kernel NetBird crypto workers are reported as measured workload."""
        script = Path(__file__).parent / "base/lib/cpuset_audit.py"
        spec = importlib.util.spec_from_file_location("cpuset_audit_classification", script)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader if spec is not None else None)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        classifier = getattr(module, "classify_runnable_task", None)
        self.assertTrue(callable(classifier), "the audit must classify runnable task roles")

        self.assertEqual(
            classifier("kworker/2:1-wg-crypt-wt0", "mesh-netbird"),
            "kernel-wireguard-crypto",
        )
        self.assertEqual(
            classifier("kworker/2:1+wg-crypt-wt0", "mesh-underlay"),
            "external",
        )
        self.assertEqual(
            classifier("kworker/2:1-events", "mesh-netbird"),
            "external",
        )
        self.assertEqual(
            classifier("systemd", "mesh-netbird"),
            "external",
        )

    def test_summary_preserves_kernel_wireguard_worker_cpu_masks(self) -> None:
        """The audit summary must retain CPU placement for kernel crypto workers."""
        script = Path(__file__).parent / "base/lib/cpuset_audit.py"
        with tempfile.TemporaryDirectory(prefix="j88i-wg-worker-") as temporary:
            output = Path(temporary)
            spec = importlib.util.spec_from_file_location("cpuset_audit_workers", script)
            self.assertIsNotNone(spec)
            self.assertIsNotNone(spec.loader if spec is not None else None)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            worker = {
                "pid": 123,
                "tid": 123,
                "comm": "kworker/2:1-wg-crypt-wt0",
                "processor": 2,
                "cpus_allowed": "4",
                "cpus_allowed_list": "2",
                "cgroup": "/",
            }
            sample = {
                "scope_threads": 1,
                "scope_processes": [],
                "mask_mismatches": [],
                "external_runnable": [],
                "kernel_softirq_runnable": [],
                "kernel_wireguard_crypto_runnable": [worker],
                "cpu_pressure": "",
            }

            def stop_after_one_sample(_seconds: float) -> None:
                module.STOP = True

            with (
                patch.dict(os.environ, {"H2H_CPUSET_AUDIT_CASE": "mesh-netbird"}, clear=True),
                patch.object(module, "sample", return_value=sample),
                patch.object(module, "snapshot"),
                patch.object(module.signal, "signal"),
                patch.object(module.time, "sleep", side_effect=stop_after_one_sample),
                patch("sys.argv", [str(script), str(output), str(os.getpid())]),
                patch.object(module, "STOP", False),
            ):
                module.main()

            summary = json.loads((output / "summary.json").read_text())
            self.assertEqual(summary.get("kernel_wireguard_crypto_runnable_samples"), 1)
            self.assertEqual(summary.get("kernel_wireguard_crypto_workers"), [worker])


if __name__ == "__main__":
    unittest.main()
