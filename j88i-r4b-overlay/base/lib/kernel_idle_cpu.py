#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Measure idle engine and network CPU from per-thread proc counters."""

from __future__ import annotations

import argparse
import json
import os
import re
import time
from pathlib import Path
from typing import Any


CRYPTO = re.compile(r"^kworker/(?:u\d+|\d+):[^ ]*wg-crypt-(?:wgA|wgB)$")
SOFTIRQ = re.compile(r"^ksoftirqd/(\d+)$")


def _ticks(stat: str) -> int | None:
    """Parse utime and stime from one proc stat record."""
    close = stat.rfind(")")
    fields = stat[close + 2:].split() if close >= 0 else []
    try:
        return int(fields[11]) + int(fields[12])
    except (IndexError, ValueError):
        return None


def process_ticks(pids: list[int], proc_root: Path = Path("/proc")) -> dict[str, int]:
    """Read selected process trees and their thread CPU ticks."""
    if not pids:
        return {}
    parents: dict[int, int] = {}
    try:
        process_dirs = list(proc_root.iterdir())
    except OSError:
        return {}
    for process in process_dirs:
        if not process.name.isdigit():
            continue
        try:
            stat = (process / "stat").read_text(encoding="utf-8")
        except OSError:
            continue
        close = stat.rfind(")")
        fields = stat[close + 2:].split() if close >= 0 else []
        try:
            parents[int(process.name)] = int(fields[1])
        except (IndexError, ValueError):
            continue

    children: dict[int, list[int]] = {}
    for pid, parent in parents.items():
        children.setdefault(parent, []).append(pid)
    selected: set[int] = set()
    stack = pids.copy()
    while stack:
        pid = stack.pop()
        if pid in selected:
            continue
        selected.add(pid)
        stack.extend(children.get(pid, []))

    result: dict[str, int] = {}
    for pid in selected:
        task_root = proc_root / str(pid) / "task"
        try:
            tasks = list(task_root.iterdir())
        except OSError:
            continue
        for task in tasks:
            if not task.name.isdigit():
                continue
            try:
                ticks = _ticks((task / "stat").read_text(encoding="utf-8"))
            except OSError:
                continue
            if ticks is not None:
                result[f"{pid}:{task.name}"] = ticks
    return result


def worker_ticks(pids: list[int]) -> dict[str, dict[str, int]]:
    """Read engine process, WireGuard crypto, and test-CPU softirq ticks."""
    result: dict[str, dict[str, int]] = {
        "engine_process": process_ticks(pids),
        "wireguard_crypto": {},
        "network_softirq": {},
    }
    try:
        process_dirs = list(Path("/proc").iterdir())
    except OSError:
        return result
    for process in process_dirs:
        if not process.name.isdigit():
            continue
        try:
            task_dirs = list((process / "task").iterdir())
        except OSError:
            continue
        # kthreads such as wg-crypt workers and ksoftirqd are separate procfs
        # processes created by kthreadd, not tasks under /proc/2 itself.
        for task in task_dirs:
            if not task.name.isdigit():
                continue
            try:
                comm = (task / "comm").read_text(encoding="utf-8").strip()
                stat = (task / "stat").read_text(encoding="utf-8")
            except OSError:
                continue
            if CRYPTO.match(comm):
                role = "wireguard_crypto"
            else:
                match = SOFTIRQ.match(comm)
                if not match or int(match.group(1)) not in {1, 2, 3, 4}:
                    continue
                role = "network_softirq"
            ticks = _ticks(stat)
            if ticks is None:
                continue
            result[role][task.name] = ticks
    return result


def summarize_window(
    before: dict[str, dict[str, int]],
    after: dict[str, dict[str, int]],
    seconds: float,
    hz: float,
    *,
    engine: str,
) -> dict[str, Any]:
    """Convert per-thread tick deltas into CPU seconds per minute.

    An idle kernel tunnel may have no crypto worker thread at all. Its sampled
    test-CPU softirq counters still prove the kernel path was observed, so zero
    deltas are a valid idle reading for that engine.
    """
    if not before or not after or seconds <= 0 or hz <= 0:
        return {
            "status": "unavailable",
            "cpu_s_per_minute": None,
            "engine_cpu_s_per_minute": None,
            "reason": "proc worker counters unavailable",
        }
    deltas = {
        role: {
            tid: max(0, ticks - before.get(role, {}).get(tid, ticks))
            for tid, ticks in after.get(role, {}).items()
        }
        for role in after
    }
    totals = {role: sum(values.values()) / hz / seconds * 60 for role, values in deltas.items()}
    matches = sum(len(value) for value in after.values())
    engine_matches = len(after.get("engine_process", {})) + len(after.get("wireguard_crypto", {}))
    if engine == "kernel-plain":
        engine_matches = bool(before.get("network_softirq")) and bool(
            after.get("network_softirq")
        )
    engine_cpu = totals.get("engine_process", 0.0) + totals.get("wireguard_crypto", 0.0)
    return {
        "status": "measured" if engine_matches else "unavailable",
        "cpu_s_per_minute": sum(totals.values()) if engine_matches else None,
        "engine_cpu_s_per_minute": engine_cpu if engine_matches else None,
        "engine_process_cpu_s_per_minute": (
            totals.get("engine_process", 0.0) if after.get("engine_process") else None
        ),
        "wireguard_crypto_cpu_s_per_minute": (
            totals.get("wireguard_crypto", 0.0) if after.get("wireguard_crypto") else None
        ),
        "network_softirq_cpu_s_per_minute": (
            totals.get("network_softirq", 0.0) if after.get("network_softirq") else None
        ),
        "seconds": seconds,
        "matching_threads": matches,
        "method": "sum selected engine-process threads, WireGuard crypto workers, and ksoftirqd on CPUs 1-4",
        "tick_deltas_by_role": deltas,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", required=True, choices=["kernel-plain", "wireguard-go", "gotatun"])
    parser.add_argument("--pids", default="")
    parser.add_argument("--seconds", type=float, default=10.0)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        pids = [int(value) for value in args.pids.split(",") if value]
    except ValueError as error:
        parser.error(f"--pids must be comma-separated process IDs: {error}")
    hz = float(os.sysconf("SC_CLK_TCK"))
    before = worker_ticks(pids)
    started = time.monotonic()
    time.sleep(args.seconds)
    elapsed = time.monotonic() - started
    after = worker_ticks(pids)
    result = summarize_window(before, after, elapsed, hz, engine=args.engine)
    args.output.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(args.output)
    return 0 if result["status"] == "measured" else 1


if __name__ == "__main__":
    raise SystemExit(main())
