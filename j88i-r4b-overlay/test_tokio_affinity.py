#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Test the narrow Tokio worker placement used by J88i's locality rows."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).parent / "base/lib/tokio_affinity.py"


def load_module():
    """Load the placement helper from the overlay without requiring a package."""
    if not MODULE_PATH.is_file():
        raise AssertionError(f"locality placement helper is missing: {MODULE_PATH}")
    spec = importlib.util.spec_from_file_location("tokio_affinity", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load locality placement helper: {MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TokioAffinityTests(unittest.TestCase):
    """Keep round-robin affinity limited to Tokio runtime workers."""

    def _make_process(self, root: Path, pid: int, threads: dict[int, str]) -> None:
        """Write just enough procfs state for a deterministic worker selection."""
        for tid, comm in threads.items():
            task = root / str(pid) / "task" / str(tid)
            task.mkdir(parents=True)
            (task / "comm").write_text(f"{comm}\n", encoding="utf-8")

    def test_round_robin_pins_only_tokio_worker_threads(self) -> None:
        """Assign Tokio workers in TID order to one CPU each, rotating the mask."""
        module = load_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._make_process(
                root,
                100,
                {
                    100: "gotatun",
                    101: "tokio-runtime-w",
                    102: "udp-recv",
                    103: "tokio-runtime-w",
                    104: "tokio-runtime-w",
                },
            )
            calls: list[tuple[int, set[int]]] = []

            def set_affinity(tid: int, cpus: set[int]) -> None:
                calls.append((tid, cpus))

            assigned = module.pin_tokio_workers(
                100,
                (1, 2),
                proc_root=root,
                set_affinity=set_affinity,
            )

        self.assertEqual(
            [(row["tid"], row["cpu"]) for row in assigned],
            [(101, 1), (103, 2), (104, 1)],
        )
        self.assertEqual(calls, [(101, {1}), (103, {2}), (104, {1})])

    def test_current_tokio_worker_name_is_detected(self) -> None:
        """Find the worker name used by the fork's locked Tokio version."""
        module = load_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._make_process(
                root,
                150,
                {150: "gotatun", 151: "tokio-rt-worker", 152: "udp-recv"},
            )
            calls: list[tuple[int, set[int]]] = []

            assigned = module.pin_tokio_workers(
                150,
                (3, 4),
                proc_root=root,
                set_affinity=lambda tid, cpus: calls.append((tid, cpus)),
            )

        self.assertEqual([(row["tid"], row["cpu"]) for row in assigned], [(151, 3)])
        self.assertEqual(calls, [(151, {3})])

    def test_missing_tokio_workers_fails_without_changing_any_affinity(self) -> None:
        """Do not silently claim a locality row if the runtime has no workers."""
        module = load_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._make_process(root, 200, {200: "gotatun", 201: "udp-recv"})
            calls: list[tuple[int, set[int]]] = []

            with self.assertRaisesRegex(RuntimeError, "no Tokio runtime workers"):
                module.pin_tokio_workers(
                    200,
                    (3, 4),
                    proc_root=root,
                    set_affinity=lambda tid, cpus: calls.append((tid, cpus)),
                )

        self.assertEqual(calls, [])

    def test_cpu_mask_must_be_nonempty_and_unique(self) -> None:
        """Reject an unusable side mask before applying any affinity."""
        module = load_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._make_process(root, 300, {301: "tokio-runtime-w"})
            for cpus in ((), (1, 1)):
                with self.subTest(cpus=cpus), self.assertRaisesRegex(ValueError, "CPU mask"):
                    module.pin_tokio_workers(
                        300,
                        cpus,
                        proc_root=root,
                        set_affinity=lambda _tid, _cpus: None,
                    )


if __name__ == "__main__":
    unittest.main()
