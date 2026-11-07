#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Pin only a daemon's Tokio runtime workers for the J88i locality row."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Callable, Iterable


TOKIO_WORKER_COMM = "tokio-runtime-w"


def pin_tokio_workers(
    pid: int,
    cpus: Iterable[int],
    *,
    proc_root: Path = Path("/proc"),
    set_affinity: Callable[[int, set[int]], None] = os.sched_setaffinity,
) -> list[dict[str, int]]:
    """Pin workers in TID order, rotating through the supplied side CPUs."""
    selected = tuple(cpus)
    if (
        not selected
        or any(type(cpu) is not int or cpu < 0 for cpu in selected)
        or len(selected) != len(set(selected))
    ):
        raise ValueError("CPU mask must contain unique non-negative CPU numbers")

    tasks = proc_root / str(pid) / "task"
    workers: list[int] = []
    for entry in tasks.iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            comm = (entry / "comm").read_text(encoding="utf-8").strip()
        except FileNotFoundError:
            # Threads can exit while procfs is being enumerated.
            continue
        if comm == TOKIO_WORKER_COMM:
            workers.append(int(entry.name))

    workers.sort()
    if not workers:
        raise RuntimeError(f"process {pid} has no Tokio runtime workers")

    assigned: list[dict[str, int]] = []
    for index, tid in enumerate(workers):
        cpu = selected[index % len(selected)]
        set_affinity(tid, {cpu})
        assigned.append({"tid": tid, "cpu": cpu})
    return assigned


def parse_cpu_list(value: str) -> tuple[int, ...]:
    """Parse a strict Linux-style CPU list such as `1-2` or `1,3-4`."""
    cpus: list[int] = []
    for part in value.split(","):
        bounds = part.split("-", maxsplit=1)
        if not all(bound.isdecimal() for bound in bounds):
            raise ValueError(f"invalid CPU mask: {value!r}")
        first = int(bounds[0])
        last = int(bounds[-1])
        if last < first:
            raise ValueError(f"invalid CPU mask: {value!r}")
        cpus.extend(range(first, last + 1))
    if not cpus or len(cpus) != len(set(cpus)):
        raise ValueError(f"CPU mask must be nonempty and unique: {value!r}")
    return tuple(cpus)


def main() -> int:
    """Pin one endpoint and print the exact worker-to-CPU assignments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pid", type=int)
    parser.add_argument("cpus", help="allowed CPUs, for example 1-2")
    args = parser.parse_args()
    assigned = pin_tokio_workers(args.pid, parse_cpu_list(args.cpus))
    print(json.dumps({"pid": args.pid, "workers": assigned}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
