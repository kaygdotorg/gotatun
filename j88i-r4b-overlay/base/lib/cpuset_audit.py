#!/usr/bin/env python3
"""Sample D348 process placement, runnable tasks, scheduler delay and network counters.

The R4b cases use veth links between namespaces, so the packet path has no
device IRQ of its own. This audit records IRQ affinity and per-CPU softirq
counters beside each loaded phase, while checking that every process in a
J88i scope has the scope's exact Cpus_allowed_list. When a ready-file is
requested, setup samples stay separate until the measured scopes are present
and no unrelated task is runnable on the test CPUs. Kernel WireGuard crypto
workers are reported as workload only for the kernel NetBird case.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import signal
import time
from pathlib import Path


OUTPUT = Path(os.environ.get("H2H_CPUSET_AUDIT_DIR", "."))
PARENT_PID = int(os.environ.get("H2H_CPUSET_AUDIT_PARENT", "-1"))
SELF_PID = os.getpid()
TEST_CPUS = {0, 1, 2, 3}
EXPECTED_MASKS = {frozenset({0, 1}), frozenset({2, 3})}
STOP = False


def stop(_signum: int, _frame: object) -> None:
    """Ask the sampler to take its final snapshots and exit cleanly."""
    global STOP
    STOP = True


def read_text(path: Path) -> str:
    """Read a proc or cgroup file, returning an empty string if it has exited."""
    try:
        return path.read_text()
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return ""


def parse_cpulist(value: str) -> set[int]:
    """Expand Linux's compact CPU-list format into individual CPU numbers."""
    cpus: set[int] = set()
    for item in value.split(","):
        if not item:
            continue
        bounds = item.split("-", 1)
        low = int(bounds[0])
        high = int(bounds[1]) if len(bounds) == 2 else low
        cpus.update(range(low, high + 1))
    return cpus


def classify_runnable_task(comm: str, case: str) -> str:
    """Separate measured kernel networking work from unrelated runnable tasks."""
    if comm.startswith("ksoftirqd/"):
        return "kernel-softirq"
    if (
        case == "mesh-netbird"
        and comm.startswith("kworker/")
        and comm.endswith("wg-crypt-wt0")
    ):
        return "kernel-wireguard-crypto"
    return "external"


def cgroup_path(pid: int) -> str:
    """Return the unified cgroup path for one process."""
    for line in read_text(Path(f"/proc/{pid}/cgroup")).splitlines():
        if line.startswith("0::"):
            return line[3:]
    return ""


def task_values(pid: int, tid: int) -> dict[str, object] | None:
    """Read one task's state, CPU mask, last CPU and cumulative run-queue delay."""
    root = Path(f"/proc/{pid}/task/{tid}")
    status = read_text(root / "status")
    stat = read_text(root / "stat")
    schedstat = read_text(root / "schedstat").split()
    if not status or not stat:
        return None
    allowed = next((line.split(":", 1)[1].strip() for line in status.splitlines()
                    if line.startswith("Cpus_allowed_list:")), "")
    allowed_mask = next((line.split(":", 1)[1].strip() for line in status.splitlines()
                         if line.startswith("Cpus_allowed:")), "")
    right = stat.rfind(")")
    fields = stat[right + 2:].split() if right >= 0 else []
    if not fields:
        return None
    try:
        processor = int(fields[36])
    except (IndexError, ValueError):
        processor = -1
    try:
        run_delay_ns = int(schedstat[1])
        runtime_ns = int(schedstat[0])
    except (IndexError, ValueError):
        run_delay_ns = runtime_ns = 0
    return {
        "state": fields[0],
        "processor": processor,
        "allowed": allowed,
        "cpus_allowed": allowed_mask,
        "runtime_ns": runtime_ns,
        "run_delay_ns": run_delay_ns,
    }


def irq_affinity() -> list[dict[str, str]]:
    """Capture each visible interrupt's configured CPU affinity."""
    result = []
    for path in sorted(glob.glob("/proc/irq/*/smp_affinity_list")):
        affinity = read_text(Path(path)).strip()
        if affinity:
            result.append({"irq": path.split("/")[3], "cpus": affinity})
    return result


def parse_per_cpu_counters(text: str) -> dict[str, dict[str, int]]:
    """Parse the per-CPU rows in `/proc/interrupts` or `/proc/softirqs`."""
    lines = text.splitlines()
    header = next((line for line in lines if re.search(r"\bCPU\d+\b", line)), "")
    cpus = re.findall(r"CPU\d+", header)
    if not cpus:
        return {}
    counters: dict[str, dict[str, int]] = {}
    for line in lines:
        if ":" not in line:
            continue
        name, values = line.split(":", 1)
        fields = values.split()
        if len(fields) < len(cpus):
            continue
        try:
            counters[name.strip()] = {
                cpu: int(value) for cpu, value in zip(cpus, fields[:len(cpus)])
            }
        except ValueError:
            continue
    return counters


def counter_deltas(before: str, after: str) -> dict[str, dict[str, int]]:
    """Return nonzero per-CPU deltas for counters present in both snapshots."""
    old = parse_per_cpu_counters(before)
    new = parse_per_cpu_counters(after)
    result: dict[str, dict[str, int]] = {}
    for name, values in new.items():
        previous = old.get(name, {})
        delta = {
            cpu: value - previous.get(cpu, value)
            for cpu, value in values.items()
            if value > previous.get(cpu, value)
        }
        if delta:
            result[name] = delta
    return result


def snapshot(name: str) -> None:
    """Save raw kernel counters so the end report can show per-CPU deltas."""
    for source, suffix in (
        ("/proc/interrupts", "interrupts"),
        ("/proc/softirqs", "softirqs"),
        ("/proc/schedstat", "schedstat"),
        ("/proc/pressure/cpu", "cpu-pressure"),
        ("/proc/net/softnet_stat", "softnet-stat"),
    ):
        value = read_text(Path(source))
        (OUTPUT / f"{suffix}.{name}.txt").write_text(value)
    (OUTPUT / f"irq-affinity.{name}.json").write_text(
        json.dumps(irq_affinity(), indent=2) + "\n"
    )


def sample() -> dict[str, object]:
    """Sample J88i scopes and classify other runnable tasks by workload role."""
    audit_case = os.environ.get("H2H_CPUSET_AUDIT_CASE", "")
    scope_threads = 0
    mask_mismatches = []
    external_runnable = []
    kernel_runnable = []
    kernel_wireguard_runnable = []
    scope_processes = []
    run_delay_ns = 0
    runtime_ns = 0

    try:
        pids = [int(entry.name) for entry in os.scandir("/proc") if entry.name.isdigit()]
    except OSError:
        pids = []

    for pid in pids:
        group = cgroup_path(pid)
        in_scope = "/j88i-" in group and group.startswith("/perf.slice/")
        group_cpus: set[int] = set()
        if in_scope:
            group_file = Path("/sys/fs/cgroup") / group.lstrip("/") / "cpuset.cpus.effective"
            try:
                group_cpus = parse_cpulist(read_text(group_file).strip())
            except ValueError:
                group_cpus = set()
        comm = read_text(Path(f"/proc/{pid}/comm")).strip()
        try:
            tids = [int(entry.name) for entry in os.scandir(f"/proc/{pid}/task")
                    if entry.name.isdigit()]
        except OSError:
            continue

        for tid in tids:
            values = task_values(pid, tid)
            if values is None:
                continue
            try:
                allowed = parse_cpulist(str(values["allowed"]))
            except ValueError:
                allowed = set()
            if in_scope:
                scope_threads += 1
                runtime_ns += int(values["runtime_ns"])
                run_delay_ns += int(values["run_delay_ns"])
                scope_processes.append({
                    "pid": pid, "tid": tid, "comm": comm,
                    "state": values["state"], "processor": values["processor"],
                    "cpus_allowed": values["cpus_allowed"],
                    "cpus_allowed_list": values["allowed"], "cgroup": group,
                    "runtime_ns": values["runtime_ns"],
                    "run_delay_ns": values["run_delay_ns"],
                })
                if group_cpus not in EXPECTED_MASKS or allowed != group_cpus:
                    mask_mismatches.append({
                        "pid": pid, "tid": tid, "comm": comm,
                        "cpus_allowed": values["cpus_allowed"],
                        "allowed": values["allowed"],
                        "scope_allowed": sorted(group_cpus),
                    })
                continue
            if values["state"] != "R" or not allowed.intersection(TEST_CPUS):
                continue
            if pid == SELF_PID or pid == PARENT_PID:
                continue
            task = {
                "pid": pid, "tid": tid, "comm": comm,
                "processor": values["processor"],
                "cpus_allowed": values["cpus_allowed"],
                "cpus_allowed_list": values["allowed"], "cgroup": group,
            }
            task_class = classify_runnable_task(comm, audit_case)
            if task_class == "kernel-softirq":
                kernel_runnable.append(task)
            elif task_class == "kernel-wireguard-crypto":
                kernel_wireguard_runnable.append(task)
            else:
                external_runnable.append(task)

    return {
        "time_unix": time.time(),
        "audit_case": audit_case,
        "scope_threads": scope_threads,
        "scope_processes": scope_processes,
        "mask_mismatches": mask_mismatches,
        "external_runnable": external_runnable,
        "kernel_softirq_runnable": kernel_runnable,
        "kernel_wireguard_crypto_runnable": kernel_wireguard_runnable,
        "scope_runtime_ns": runtime_ns,
        "scope_run_delay_ns": run_delay_ns,
        "cpu_pressure": read_text(Path("/proc/pressure/cpu")).strip(),
    }


def clean_startup_sample(current: dict[str, object]) -> bool:
    """Release stopped workloads only after exact masks and a quiet run queue."""
    return (
        int(current.get("scope_threads", 0)) > 0
        and not current.get("mask_mismatches")
        and not current.get("external_runnable")
    )


def main() -> int:
    """Sample until the case asks us to stop, then write a compact summary."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_dir", nargs="?", help="directory for the audit evidence")
    parser.add_argument("parent_pid", nargs="?", type=int,
                        help="case shell PID to exclude from interference samples")
    arguments = parser.parse_args()
    output_dir = arguments.output_dir or os.environ.get("H2H_CPUSET_AUDIT_DIR")
    parent_pid = arguments.parent_pid
    if parent_pid is None:
        parent_value = os.environ.get("H2H_CPUSET_AUDIT_PARENT")
        parent_pid = int(parent_value) if parent_value else None
    if not output_dir or parent_pid is None:
        parser.error("pass output_dir and parent_pid, or set the matching H2H_CPUSET_AUDIT_* variables")
    global OUTPUT, PARENT_PID
    OUTPUT = Path(output_dir)
    PARENT_PID = parent_pid
    OUTPUT.mkdir(parents=True, exist_ok=True)
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    snapshot("before")
    ready_file = os.environ.get("H2H_CPUSET_AUDIT_READY_FILE")
    if ready_file:
        ready_path = Path(ready_file)
        with (OUTPUT / "preflight.jsonl").open("w") as preflight:
            while not STOP:
                current = sample()
                preflight.write(json.dumps(current, separators=(",", ":")) + "\n")
                preflight.flush()
                if clean_startup_sample(current):
                    ready_path.write_text("clean\n")
                    break
                time.sleep(0.1)
    samples = 0
    mismatch_samples = 0
    external_samples = 0
    kernel_wireguard_samples = 0
    kernel_wireguard_workers: dict[str, dict[str, object]] = {}
    max_scope_threads = 0
    runtime_delta_ns = 0
    run_delay_delta_ns = 0
    previous_stats: dict[str, tuple[int, int]] = {}
    with (OUTPUT / "samples.jsonl").open("w") as output:
        while not STOP:
            current = sample()
            samples += 1
            max_scope_threads = max(max_scope_threads, int(current["scope_threads"]))
            mismatch_samples += bool(current["mask_mismatches"])
            external_samples += bool(current["external_runnable"])
            wireguard_workers = current.get("kernel_wireguard_crypto_runnable", [])
            kernel_wireguard_samples += bool(wireguard_workers)
            for worker in wireguard_workers:
                key = f"{worker['pid']}:{worker['tid']}"
                kernel_wireguard_workers[key] = worker
            current_stats: dict[str, tuple[int, int]] = {}
            for task in current["scope_processes"]:
                key = f"{task['pid']}:{task['tid']}"
                runtime = int(task["runtime_ns"])
                delay = int(task["run_delay_ns"])
                old_runtime, old_delay = previous_stats.get(key, (0, 0))
                runtime_delta_ns += max(0, runtime - old_runtime)
                run_delay_delta_ns += max(0, delay - old_delay)
                current_stats[key] = (runtime, delay)
            previous_stats = current_stats
            output.write(json.dumps(current, separators=(",", ":")) + "\n")
            output.flush()
            time.sleep(1.0)
    snapshot("after")
    interrupt_delta = counter_deltas(
        read_text(OUTPUT / "interrupts.before.txt"),
        read_text(OUTPUT / "interrupts.after.txt"),
    )
    softirq_delta = counter_deltas(
        read_text(OUTPUT / "softirqs.before.txt"),
        read_text(OUTPUT / "softirqs.after.txt"),
    )
    interrupt_data_available = bool(parse_per_cpu_counters(
        read_text(OUTPUT / "interrupts.before.txt")
    )) and bool(parse_per_cpu_counters(read_text(OUTPUT / "interrupts.after.txt")))
    softirq_data_available = bool(parse_per_cpu_counters(
        read_text(OUTPUT / "softirqs.before.txt")
    )) and bool(parse_per_cpu_counters(read_text(OUTPUT / "softirqs.after.txt")))
    clean = (
        not mismatch_samples
        and not external_samples
        and max_scope_threads > 0
        and interrupt_data_available
        and softirq_data_available
    )
    summary = {
        "samples": samples,
        "mask_mismatch_samples": mismatch_samples,
        "external_runnable_samples": external_samples,
        "kernel_wireguard_crypto_runnable_samples": kernel_wireguard_samples,
        "kernel_wireguard_crypto_workers": list(kernel_wireguard_workers.values()),
        "max_scope_threads": max_scope_threads,
        "scope_runtime_delta_ns": runtime_delta_ns,
        "scope_run_delay_delta_ns": run_delay_delta_ns,
        "clean": clean,
        "test_cpu_list": sorted(TEST_CPUS),
        "expected_side_cpu_lists": [[0, 1], [2, 3]],
        "interrupt_data_available": interrupt_data_available,
        "softirq_data_available": softirq_data_available,
        "interrupt_delta_per_cpu": interrupt_delta,
        "softirq_delta_per_cpu": softirq_delta,
        "veth_irq_note": "veth links have no device IRQ; interrupt affinity and per-CPU softirq deltas are retained for the measured path",
        "audit_case": os.environ.get("H2H_CPUSET_AUDIT_CASE", ""),
        "interpretation": "ksoftirqd is reported separately; wg-crypt-wt0 workers are reported as workload only for mesh-netbird; all other runnable tasks allowed on test CPUs count as interference",
    }
    (OUTPUT / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return 0 if clean else 1


if __name__ == "__main__":
    raise SystemExit(main())
