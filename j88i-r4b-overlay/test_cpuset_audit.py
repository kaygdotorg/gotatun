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
from types import SimpleNamespace
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
        self.assertEqual(module.HOUSEKEEPING_CPUS, {0, 5})
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

    def test_saved_perf_slice_dropin_accepts_only_its_original_allowed_cpus(self) -> None:
        """Preserve a known perf.slice mask without accepting unrelated settings."""
        state = Path(__file__).parent / "base/runner-overlays/J88i-cpuset-state.sh"
        with tempfile.TemporaryDirectory(prefix="j88i-dropin-") as temporary:
            root = Path(temporary)
            valid = root / "valid.conf"
            wrong = root / "wrong.conf"
            extra = root / "extra.conf"
            valid.write_text("[Slice]\nAllowedCPUs=1-3\n", encoding="utf-8")
            wrong.write_text("[Slice]\nAllowedCPUs=0-5\n", encoding="utf-8")
            extra.write_text("[Slice]\nAllowedCPUs=1-3\nCPUWeight=100\n", encoding="utf-8")
            code = r"""
set -euo pipefail
source "$1"
cpuset_allowed_cpus_dropin_matches "$2" 1-3
"""
            accepted = subprocess.run(
                ["bash", "-c", code, "bash", str(state), str(valid)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            for path in (wrong, extra):
                with self.subTest(path=path):
                    rejected = subprocess.run(
                        ["bash", "-c", code, "bash", str(state), str(path)],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertNotEqual(rejected.returncode, 0, path)

    def test_generated_cpu_dropin_reset_then_saved_mask_is_valid(self) -> None:
        """Accept systemd's empty list reset before its active saved CPU mask."""
        state = Path(__file__).parent / "base/runner-overlays/J88i-cpuset-state.sh"
        with tempfile.TemporaryDirectory(prefix="j88i-dropin-reset-") as temporary:
            generated = Path(temporary) / "50-AllowedCPUs.conf"
            generated.write_text(
                "[Slice]\nAllowedCPUs=\nAllowedCPUs=1-3\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    "bash", "-c",
                    'set -euo pipefail; source "$1"; '
                    'cpuset_allowed_cpus_dropin_matches "$2" 1-3',
                    "bash", str(state), str(generated),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_perf_slice_accepts_only_the_cpu_and_memory_runtime_dropins(self) -> None:
        """Recognize the live CPU and memory files without accepting extra policy."""
        state = Path(__file__).parent / "base/runner-overlays/J88i-cpuset-state.sh"
        cpu = "/run/systemd/system.control/perf.slice.d/50-AllowedCPUs.conf"
        memory = "/run/systemd/system.control/perf.slice.d/50-MemoryMax.conf"
        accepted = subprocess.run(
            [
                "bash", "-c",
                'set -euo pipefail; source "$1"; cpuset_perf_slice_dropins_are_known "$2"',
                "bash", str(state), f"{cpu} {memory}",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(accepted.returncode, 0, accepted.stderr)

        for paths in (f"{cpu} /run/unexpected.conf", memory):
            with self.subTest(paths=paths):
                rejected = subprocess.run(
                    [
                        "bash", "-c",
                        'set -euo pipefail; source "$1"; '
                        'cpuset_perf_slice_dropins_are_known "$2"',
                        "bash", str(state), paths,
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertNotEqual(rejected.returncode, 0, paths)

    def test_restoring_cpu_dropin_leaves_memory_dropin_untouched(self) -> None:
        """Restore the original CPU bytes without removing the perf memory cap."""
        state = Path(__file__).parent / "base/runner-overlays/J88i-cpuset-state.sh"
        with tempfile.TemporaryDirectory(prefix="j88i-dropin-restore-") as temporary:
            root = Path(temporary)
            saved_cpu = root / "saved-AllowedCPUs.conf"
            current_cpu = root / "50-AllowedCPUs.conf"
            memory = root / "50-MemoryMax.conf"
            saved_bytes = b"[Slice]\nAllowedCPUs=\nAllowedCPUs=1-3\n"
            memory_bytes = b"[Slice]\nMemoryMax=6G\n"
            saved_cpu.write_bytes(saved_bytes)
            current_cpu.write_text("[Slice]\nAllowedCPUs=0-5\n", encoding="utf-8")
            memory.write_bytes(memory_bytes)
            result = subprocess.run(
                [
                    "bash", "-c",
                    'set -euo pipefail; source "$1"; '
                    'cpuset_restore_saved_dropin "$2" "$3"',
                    "bash", str(state), str(saved_cpu), str(current_cpu),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(current_cpu.read_bytes(), saved_bytes)
            self.assertEqual(memory.read_bytes(), memory_bytes)

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
            self.assertIn("nr_migrations", values)

    def _sample_scoped_worker(
        self,
        *,
        row_tag: str,
        worker_placement: str,
        worker_comm: str,
        worker_allowed: str,
        target_pids: str = "500",
    ) -> dict[str, object]:
        """Sample a main task and one worker with controlled procfs values."""
        script = Path(__file__).parent / "base/lib/cpuset_audit.py"
        spec = importlib.util.spec_from_file_location("cpuset_audit_locality", script)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader if spec is not None else None)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        def entries(path: str) -> list[SimpleNamespace]:
            if path == "/proc":
                return [SimpleNamespace(name="500")]
            if path == "/proc/500/task":
                return [SimpleNamespace(name="500"), SimpleNamespace(name="501")]
            return []

        def read_proc(path: Path) -> str:
            if str(path) == "/proc/500/comm":
                return "j88i-gotatun\n"
            if str(path).endswith("/cpuset.cpus.effective"):
                return "1-2\n"
            return ""

        def task_values(_pid: int, tid: int) -> dict[str, object]:
            allowed = "1-2" if tid == 500 else worker_allowed
            return {
                "state": "S",
                "processor": 1,
                "parent_pid": 500,
                "allowed": allowed,
                "cpus_allowed": "00000006" if allowed == "1-2" else "00000002",
                "runtime_ns": 10,
                "run_delay_ns": 1,
                "nr_migrations": 0,
                "thread_comm": "gotatun" if tid == 500 else worker_comm,
            }

        with (
            patch.dict(
                os.environ,
                {
                    "H2H_CPUSET_AUDIT_CASE": "mesh-gotatun",
                    "H2H_CPUSET_AUDIT_ENGINE": "gotatun",
                    "H2H_CPUSET_AUDIT_ROW_TAG": row_tag,
                    "H2H_CPUSET_AUDIT_WORKER_PLACEMENT": worker_placement,
                    "H2H_CPUSET_AUDIT_TARGET_PIDS": target_pids,
                },
                clear=True,
            ),
            patch.object(module.os, "scandir", side_effect=entries),
            patch.object(module, "read_text", side_effect=read_proc),
            patch.object(module, "cgroup_path", return_value="/perf.slice/j88i-mesh-gotatun.scope"),
            patch.object(module, "task_values", side_effect=task_values),
        ):
            return module.sample()

    def test_narrow_mask_is_allowed_only_for_tagged_locality_tokio_workers(self) -> None:
        """A singleton worker mask is valid only for Tokio workers in the locality row."""
        locality_row = "gotatun-j88i-locality-33ca6fe-1"
        locality = self._sample_scoped_worker(
            row_tag=locality_row,
            worker_placement="round-robin",
            worker_comm="tokio-runtime-w",
            worker_allowed="1",
        )
        self.assertEqual(locality["mask_mismatches"], [])
        self.assertEqual(locality["scope_processes"][1]["thread_comm"], "tokio-runtime-w")

        invalid_cases = (
            (locality_row, "default", "tokio-runtime-w", "1"),
            ("gotatun-j88i-fair-33ca6fe-1", "round-robin", "tokio-runtime-w", "1"),
            (locality_row, "round-robin", "bulk-worker", "1"),
            (locality_row, "round-robin", "tokio-runtime-w", "1-3"),
            # A worker created after the initial pin pass keeps its side's
            # broad mask; the locality audit must reject it.
            (locality_row, "round-robin", "tokio-runtime-w", "1-2"),
        )
        for row_tag, placement, worker_comm, worker_allowed in invalid_cases:
            with self.subTest(row_tag=row_tag, placement=placement, worker_comm=worker_comm):
                sample = self._sample_scoped_worker(
                    row_tag=row_tag,
                    worker_placement=placement,
                    worker_comm=worker_comm,
                    worker_allowed=worker_allowed,
                )
                self.assertEqual(
                    [task["tid"] for task in sample["mask_mismatches"]],
                    [501],
                )

        unrelated = self._sample_scoped_worker(
            row_tag=locality_row,
            worker_placement="round-robin",
            worker_comm="tokio-runtime-w",
            worker_allowed="1",
            target_pids="999",
        )
        self.assertEqual([task["tid"] for task in unrelated["mask_mismatches"]], [501])

    def test_matrix_j88i_tag_is_locality_only_when_explicitly_placed(self) -> None:
        """The J317 row tag permits narrowed workers only in its locality placement."""
        j317_row = "gotatun-j88i-33ca6fe-1"
        locality = self._sample_scoped_worker(
            row_tag=j317_row,
            worker_placement="round-robin",
            worker_comm="tokio-runtime-w",
            worker_allowed="1",
        )
        self.assertEqual(locality["mask_mismatches"], [])

        ordinary = self._sample_scoped_worker(
            row_tag=j317_row,
            worker_placement="default",
            worker_comm="tokio-runtime-w",
            worker_allowed="1",
        )
        self.assertEqual([task["tid"] for task in ordinary["mask_mismatches"]], [501])

    def test_hold_candidate_tag_allows_locality_workers_only_for_round_robin(self) -> None:
        """The fixed candidate-a row accepts narrow masks only when locality was selected."""
        locality = self._sample_scoped_worker(
            row_tag="candidate-a",
            worker_placement="round-robin",
            worker_comm="tokio-runtime-w",
            worker_allowed="1",
        )
        self.assertEqual(locality["mask_mismatches"], [])

        ordinary = self._sample_scoped_worker(
            row_tag="candidate-a",
            worker_placement="default",
            worker_comm="tokio-runtime-w",
            worker_allowed="1",
        )
        self.assertEqual([task["tid"] for task in ordinary["mask_mismatches"]], [501])

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

    def test_proc_stat_steal_delta_is_recorded_by_cpu_and_window(self) -> None:
        """Each loaded window reports steal time for test and housekeeping CPUs."""
        script = Path(__file__).parent / "base/lib/cpuset_audit.py"
        spec = importlib.util.spec_from_file_location("cpuset_audit_steal", script)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader if spec is not None else None)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        before = """cpu 0 0 0 0 0 0 0 0 0 0
cpu0 0 0 0 0 0 0 0 10 0 0
cpu1 0 0 0 0 0 0 0 20 0 0
cpu2 0 0 0 0 0 0 0 30 0 0
cpu3 0 0 0 0 0 0 0 40 0 0
cpu4 0 0 0 0 0 0 0 50 0 0
cpu5 0 0 0 0 0 0 0 60 0 0
"""
        after = """cpu 0 0 0 0 0 0 0 0 0 0
cpu0 0 0 0 0 0 0 0 12 0 0
cpu1 0 0 0 0 0 0 0 21 0 0
cpu2 0 0 0 0 0 0 0 32 0 0
cpu3 0 0 0 0 0 0 0 43 0 0
cpu4 0 0 0 0 0 0 0 54 0 0
cpu5 0 0 0 0 0 0 0 66 0 0
"""
        before_ticks = module.parse_proc_stat_steal_ticks(before)
        after_ticks = module.parse_proc_stat_steal_ticks(after)
        summary = module.summarize_cpu_steal(
            before_ticks,
            after_ticks,
            test_cpus={1, 2, 3, 4},
            housekeeping_cpus={0, 5},
            ticks_per_second=100,
            window_duration_ns=2_000_000_000,
        )

        self.assertTrue(summary["cpu_steal_data_available"])
        self.assertEqual(
            summary["cpu_steal_delta_ticks_by_cpu"],
            {"0": 2, "1": 1, "2": 2, "3": 3, "4": 4, "5": 6},
        )
        self.assertAlmostEqual(summary["cpu_steal_test_cpu_seconds"], 0.1)
        self.assertAlmostEqual(summary["cpu_steal_housekeeping_cpu_seconds"], 0.08)
        self.assertAlmostEqual(summary["cpu_steal_all_cpu_seconds"], 0.18)
        self.assertAlmostEqual(summary["cpu_steal_test_cpu_percent"], 1.25)

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
            classifier("kworker/3:1-wg-crypt-wgA", "mesh-kernel-plain"),
            "kernel-wireguard-crypto",
        )
        self.assertEqual(
            classifier("kworker/4:1-wg-crypt-wgB", "mesh-kernel-plain"),
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


    def test_only_matching_root_kthreads_are_classified_as_bound_per_cpu_workers(self) -> None:
        """A per-CPU kernel worker must be a kthreadd child pinned to its named CPU."""
        script = Path(__file__).parent / "base/lib/cpuset_audit.py"
        spec = importlib.util.spec_from_file_location("cpuset_audit_worker_class", script)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader if spec is not None else None)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        classifier = getattr(module, "bound_percpu_worker_cpu", lambda *_args: None)

        self.assertEqual(classifier("kworker/2:0-events", 2, "/", {2}), 2)
        self.assertEqual(classifier("ksoftirqd/3", 2, "/", {3}), 3)
        self.assertIsNone(classifier("kworker/2:0-events", 2, "/", {1, 2}))
        self.assertIsNone(classifier("kworker/2:0-events", 2, "/system.slice", {2}))
        self.assertIsNone(classifier("kworker/2:0-events", 99, "/", {2}))
        self.assertIsNone(classifier("kworker/u8:0-events", 2, "/", {1, 2, 3, 4}))

    def test_kernel_network_and_crypto_workers_are_reported_as_workload(self) -> None:
        """Network softirq and kernel-WireGuard crypto runtime is workload, not background interference."""
        script = Path(__file__).parent / "base/lib/cpuset_audit.py"
        spec = importlib.util.spec_from_file_location("cpuset_audit_worker_role", script)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader if spec is not None else None)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        role = getattr(module, "bound_percpu_worker_role", lambda *_args: None)

        self.assertEqual(role("ksoftirqd/2", "mesh-gotatun"), "network-softirq")
        self.assertEqual(
            role("kworker/2:0-wg-crypt-wt0", "mesh-netbird"),
            "kernel-wireguard-crypto",
        )
        self.assertEqual(
            role("kworker/3:1-wg-crypt-wgA", "mesh-kernel-wireguard"),
            "kernel-wireguard-crypto",
        )
        self.assertEqual(
            role("kworker/4:1-wg-crypt-wgB", "mesh-kernel-wireguard"),
            "kernel-wireguard-crypto",
        )
        self.assertEqual(role("kworker/2:0-wg-crypt-wt0", "mesh-gotatun"), "background")
        self.assertEqual(role("kworker/2:0-events", "mesh-netbird"), "background")

    def test_background_worker_runtime_limit_is_strictly_point_five_percent_of_test_cpu_time(self) -> None:
        """Exactly 0.5% background time is allowed; a larger amount rejects the window."""
        script = Path(__file__).parent / "base/lib/cpuset_audit.py"
        spec = importlib.util.spec_from_file_location("cpuset_audit_worker_threshold", script)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader if spec is not None else None)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        exceeds = getattr(module, "kernel_worker_window_exceeds_limit", lambda *_args: True)

        self.assertFalse(exceeds(20_000_000, 4_000_000_000))
        self.assertTrue(exceeds(20_000_001, 4_000_000_000))
        self.assertTrue(exceeds(1, 0))

    def test_sampler_sums_bound_worker_schedstat_deltas_by_cpu(self) -> None:
        """Loaded-window runtime comes from successive schedstat values, not uptime totals."""
        script = Path(__file__).parent / "base/lib/cpuset_audit.py"
        with tempfile.TemporaryDirectory(prefix="j88i-worker-delta-") as temporary:
            output = Path(temporary)
            spec = importlib.util.spec_from_file_location("cpuset_audit_worker_delta", script)
            self.assertIsNotNone(spec)
            self.assertIsNotNone(spec.loader if spec is not None else None)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            worker = {
                "pid": 123, "tid": 123, "comm": "kworker/2:0-events",
                "worker_cpu": 2, "runtime_ns": 10_000_000,
            }
            first = {
                "time_unix": 100.0, "scope_threads": 1, "scope_processes": [],
                "mask_mismatches": [], "external_runnable": [],
                "proc_stat_steal_ticks_by_cpu": {str(cpu): 100 for cpu in range(6)},
                "kernel_bound_percpu_workers": [worker],
                "kernel_wireguard_crypto_runnable": [], "kernel_other_runnable": [],
            }
            second = {
                **first,
                "time_unix": 101.0,
                "kernel_bound_percpu_workers": [{**worker, "runtime_ns": 30_000_000}],
            }
            samples = iter([first, second])
            sleep_calls = 0

            def stop_after_two_samples(_seconds: float) -> None:
                nonlocal sleep_calls
                sleep_calls += 1
                if sleep_calls >= 2:
                    module.STOP = True

            with (
                patch.dict(os.environ, {}, clear=True),
                patch.object(module, "sample", side_effect=lambda: next(samples)),
                patch.object(module, "snapshot"),
                patch.object(module.signal, "signal"),
                patch.object(module.time, "sleep", side_effect=stop_after_two_samples),
                patch("sys.argv", [str(script), str(output), str(os.getpid())]),
                patch.object(module, "STOP", False),
            ):
                module.main()

            summary = json.loads((output / "summary.json").read_text())
            self.assertEqual(summary["kernel_bound_percpu_runtime_delta_ns"], 20_000_000)
            self.assertEqual(
                summary["kernel_bound_percpu_runtime_delta_by_cpu_ns"],
                {"2": 20_000_000},
            )
            self.assertEqual(summary["test_cpu_time_ns"], 4_000_000_000)
            self.assertFalse(summary["kernel_bound_runtime_limit_exceeded"])
            self.assertTrue(summary["cpu_steal_data_available"])
            self.assertEqual(
                summary["cpu_steal_delta_ticks_by_cpu"],
                {str(cpu): 0 for cpu in range(6)},
            )
            self.assertEqual(summary["cpu_steal_test_cpu_percent"], 0.0)

    def _run_worker_window(self, module, output: Path, runtime_deltas: dict[str, int]) -> dict[str, object]:
        """Summarize two sampler snapshots with known per-role runtime deltas."""
        output.mkdir(parents=True, exist_ok=True)
        workers = [
            {"pid": 123, "tid": 123, "comm": "ksoftirqd/2", "worker_cpu": 2},
            {"pid": 124, "tid": 124, "comm": "kworker/3:0-wg-crypt-wt0", "worker_cpu": 3},
            {"pid": 125, "tid": 125, "comm": "kworker/4:0-events", "worker_cpu": 4},
        ]
        first = {
            "time_unix": 100.0, "audit_case": "mesh-netbird",
            "scope_threads": 1, "scope_processes": [],
            "mask_mismatches": [], "external_runnable": [],
            "proc_stat_steal_ticks_by_cpu": {str(cpu): 100 for cpu in range(6)},
            "kernel_bound_percpu_workers": [
                {**worker, "runtime_ns": 0} for worker in workers
            ],
            "kernel_wireguard_crypto_runnable": [], "kernel_other_runnable": [],
        }
        second = {
            **first,
            "time_unix": 101.0,
            "kernel_bound_percpu_workers": [
                {**worker, "runtime_ns": runtime_deltas.get(worker["comm"], 0)}
                for worker in workers
            ],
        }
        sleep_calls = 0

        def stop_after_two_samples(_seconds: float) -> None:
            """Stop the sampler after it records both controlled snapshots."""
            nonlocal sleep_calls
            sleep_calls += 1
            if sleep_calls >= 2:
                module.STOP = True

        with (
            patch.dict(os.environ, {"H2H_CPUSET_AUDIT_CASE": "mesh-netbird"}, clear=True),
            patch.object(module, "sample", side_effect=iter([first, second])),
            patch.object(module, "snapshot"),
            patch.object(module, "parse_per_cpu_counters", return_value={"NET_RX": {}}),
            patch.object(module.signal, "signal"),
            patch.object(module.time, "sleep", side_effect=stop_after_two_samples),
            patch("sys.argv", [str(Path(module.__file__)), str(output), str(os.getpid())]),
            patch.object(module, "STOP", False),
        ):
            module.main()

        return json.loads((output / "summary.json").read_text())

    def test_sampler_budgets_only_unrelated_background_worker_runtime(self) -> None:
        """Kernel crypto and softirq time are measured, while only background uses the budget."""
        script = Path(__file__).parent / "base/lib/cpuset_audit.py"
        with tempfile.TemporaryDirectory(prefix="j88i-worker-roles-") as temporary:
            root = Path(temporary)
            spec = importlib.util.spec_from_file_location("cpuset_audit_worker_roles", script)
            self.assertIsNotNone(spec)
            self.assertIsNotNone(spec.loader if spec is not None else None)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            summary = self._run_worker_window(
                module,
                root / "kernel-wireguard-row",
                {
                    "ksoftirqd/2": 705_317_092,
                    "kworker/3:0-wg-crypt-wt0": 2_457_528_278,
                    "kworker/4:0-events": 5_730,
                },
            )

            self.assertEqual(
                summary["kernel_bound_percpu_runtime_delta_ns"], 3_162_851_100
            )
            self.assertEqual(
                summary["kernel_bound_percpu_runtime_delta_by_role_ns"],
                {
                    "background": 5_730,
                    "kernel-wireguard-crypto": 2_457_528_278,
                    "network-softirq": 705_317_092,
                },
            )
            self.assertEqual(summary["kernel_background_percpu_runtime_delta_ns"], 5_730)
            self.assertGreater(
                summary["kernel_bound_percpu_runtime_percent_of_test_cpu_time"], 0.5
            )
            self.assertLess(
                summary["kernel_background_percpu_runtime_percent_of_test_cpu_time"], 0.5
            )
            self.assertFalse(summary["kernel_bound_runtime_limit_exceeded"])
            self.assertEqual(
                {worker["comm"]: worker["role"]
                 for worker in summary["kernel_bound_percpu_workers"]},
                {
                    "ksoftirqd/2": "network-softirq",
                    "kworker/3:0-wg-crypt-wt0": "kernel-wireguard-crypto",
                    "kworker/4:0-events": "background",
                },
            )
            self.assertTrue(summary["clean"], summary)

            unrelated = self._run_worker_window(
                module,
                root / "unrelated-worker-row",
                {"kworker/4:0-events": 20_000_001},
            )
            self.assertEqual(unrelated["kernel_background_percpu_runtime_delta_ns"], 20_000_001)
            self.assertGreater(
                unrelated["kernel_background_percpu_runtime_percent_of_test_cpu_time"], 0.5
            )
            self.assertTrue(unrelated["kernel_bound_runtime_limit_exceeded"])
            self.assertFalse(unrelated["clean"], unrelated)

    def test_scheduler_migration_parser_reads_the_kernel_counter(self) -> None:
        """Read the cumulative per-thread migration counter exposed by procfs."""
        script = Path(__file__).parent / "base/lib/cpuset_audit.py"
        spec = importlib.util.spec_from_file_location("cpuset_audit_migrations", script)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader if spec is not None else None)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        parser = getattr(module, "parse_task_migrations", None)
        self.assertTrue(callable(parser), "the audit must parse /proc/<task>/sched migrations")

        self.assertEqual(
            parser("nr_switches : 12\nse.nr_migrations : 34\n"),
            34,
        )
        self.assertIsNone(parser("nr_switches : 12\n"))

    def test_sampler_reports_per_thread_migration_deltas(self) -> None:
        """Summarize task migration-counter changes over the loaded sample window."""
        script = Path(__file__).parent / "base/lib/cpuset_audit.py"
        with tempfile.TemporaryDirectory(prefix="j88i-task-migrations-") as temporary:
            output = Path(temporary)
            spec = importlib.util.spec_from_file_location("cpuset_audit_task_migrations", script)
            self.assertIsNotNone(spec)
            self.assertIsNotNone(spec.loader if spec is not None else None)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            task = {
                "pid": 123, "tid": 124, "comm": "gotatun-worker",
                "processor": 1, "nr_migrations": 7,
                "runtime_ns": 10, "run_delay_ns": 1,
            }
            first = {
                "time_unix": 100.0, "scope_threads": 1,
                "scope_processes": [task], "mask_mismatches": [],
                "external_runnable": [], "proc_stat_steal_ticks_by_cpu": {},
            }
            second = {
                **first,
                "time_unix": 101.0,
                "scope_processes": [{
                    **task, "processor": 2, "nr_migrations": 12,
                    "runtime_ns": 20, "run_delay_ns": 2,
                }],
            }
            sleep_calls = 0

            def stop_after_two_samples(_seconds: float) -> None:
                """Stop after the two controlled migration snapshots are recorded."""
                nonlocal sleep_calls
                sleep_calls += 1
                if sleep_calls >= 2:
                    module.STOP = True

            with (
                patch.dict(os.environ, {}, clear=True),
                patch.object(module, "sample", side_effect=iter([first, second])),
                patch.object(module, "snapshot"),
                patch.object(module.signal, "signal"),
                patch.object(module.time, "sleep", side_effect=stop_after_two_samples),
                patch("sys.argv", [str(script), str(output), str(os.getpid())]),
                patch.object(module, "STOP", False),
            ):
                module.main()

            summary = json.loads((output / "summary.json").read_text())
            self.assertIn("scope_task_migration_data_available", summary)
            self.assertTrue(summary["scope_task_migration_data_available"], summary)
            self.assertEqual(summary["scope_task_migrations_total"], 5)
            self.assertEqual(
                summary["scope_task_migrations_by_task"],
                [{
                    "pid": 123, "tid": 124, "comm": "gotatun-worker",
                    "migration_delta": 5, "first_cpu": 1, "last_cpu": 2,
                }],
            )


if __name__ == "__main__":
    unittest.main()
