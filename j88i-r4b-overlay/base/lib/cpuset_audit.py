#!/usr/bin/env python3
"""Sample D348 placement, runnable work, scheduler migrations, and network counters.

The R4b cases use veth links between namespaces, so the packet path has no
device IRQ of its own. This audit records IRQ affinity, per-thread migration
counters, and per-CPU softirq deltas beside each loaded phase, while checking
that every process in a J88i scope has the scope's exact Cpus_allowed_list. Non-kernel runnable tasks
on test CPUs reject the window. Root cgroup children of kthreadd that are
bound to a matching test CPU are measured by role. Only unrelated background
runtime is compared with the 0.5% budget; kernel crypto and network softirq
runtime belong to the measured workload and are reported without using that
budget. A ready-file keeps setup samples separate until the measured scopes
are present and all process masks match.
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
TEST_CPUS = {1, 2, 3, 4}
HOUSEKEEPING_CPUS = {0, 5}
EXPECTED_MASKS = {frozenset({1, 2}), frozenset({3, 4})}
BOUND_WORKER_PATTERNS = (
    re.compile(r"^kworker/(\d+):"),
    re.compile(r"^ksoftirqd/(\d+)$"),
)
BOUND_WORKER_RUNTIME_LIMIT_PERCENT = 0.5
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


def parse_pid_list(value: str) -> set[int]:
    """Parse the explicit process IDs pinned by the locality-row setup."""
    if not value:
        return set()
    parts = value.split(",")
    if any(not part.isdecimal() or int(part) <= 0 for part in parts):
        raise ValueError(f"invalid PID list: {value!r}")
    return {int(part) for part in parts}


def classify_runnable_task(comm: str, case: str) -> str:
    """Separate measured kernel networking work from unrelated runnable tasks."""
    if comm.startswith("ksoftirqd/"):
        return "kernel-softirq"
    if (
        case in {"mesh-netbird", "mesh-kernel-plain", "mesh-kernel-wireguard"}
        and comm.startswith("kworker/")
        and re.search(r"wg-crypt-(?:wt0|wgA|wgB)$", comm)
    ):
        return "kernel-wireguard-crypto"
    return "external"


def bound_percpu_worker_cpu(
    comm: str, parent_pid: int, cgroup: str, allowed: set[int]
) -> int | None:
    """Return the CPU for a root kthreadd worker pinned to its named CPU.

    A matching name alone is not enough: a user process can choose that name,
    and an unbound worker can have a similarly shaped suffix. The kernel parent,
    root cgroup, and exact one-CPU affinity together identify a bound worker.
    """
    if parent_pid != 2 or cgroup != "/":
        return None
    for pattern in BOUND_WORKER_PATTERNS:
        match = pattern.match(comm)
        if match is None:
            continue
        cpu = int(match.group(1))
        if allowed == {cpu}:
            return cpu
    return None


def bound_percpu_worker_role(comm: str, case: str) -> str:
    """Name expected kernel workload separately from unrelated bound workers."""
    if comm.startswith("ksoftirqd/"):
        return "network-softirq"
    if (
        case in {"mesh-netbird", "mesh-kernel-plain", "mesh-kernel-wireguard"}
        and comm.startswith("kworker/")
        and re.search(r"wg-crypt-(?:wt0|wgA|wgB)$", comm)
    ):
        return "kernel-wireguard-crypto"
    return "background"


def kernel_worker_window_exceeds_limit(
    background_runtime_delta_ns: int, test_cpu_time_ns: int
) -> bool:
    """Reject unrelated bound-worker time only when strictly over 0.5%."""
    if test_cpu_time_ns <= 0:
        return background_runtime_delta_ns > 0
    return background_runtime_delta_ns * 200 > test_cpu_time_ns


def cgroup_path(pid: int) -> str:
    """Return the unified cgroup path for one process."""
    for line in read_text(Path(f"/proc/{pid}/cgroup")).splitlines():
        if line.startswith("0::"):
            return line[3:]
    return ""


def task_values(pid: int, tid: int) -> dict[str, object] | None:
    """Read one task's state, name, CPU mask, migrations, and run-queue delay."""
    root = Path(f"/proc/{pid}/task/{tid}")
    status = read_text(root / "status")
    stat = read_text(root / "stat")
    schedstat = read_text(root / "schedstat").split()
    scheduler = read_text(root / "sched")
    thread_comm = read_text(root / "comm").strip()
    if not status or not stat:
        return None
    allowed = next((line.split(":", 1)[1].strip() for line in status.splitlines()
                    if line.startswith("Cpus_allowed_list:")), "")
    allowed_mask = next((line.split(":", 1)[1].strip() for line in status.splitlines()
                         if line.startswith("Cpus_allowed:")), "")
    parent_pid = next((line.split(":", 1)[1].strip() for line in status.splitlines()
                       if line.startswith("PPid:")), "")
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
    try:
        parsed_parent_pid = int(parent_pid)
    except ValueError:
        parsed_parent_pid = -1
    return {
        "state": fields[0],
        "processor": processor,
        "parent_pid": parsed_parent_pid,
        "thread_comm": thread_comm,
        "allowed": allowed,
        "cpus_allowed": allowed_mask,
        "runtime_ns": runtime_ns,
        "run_delay_ns": run_delay_ns,
        "nr_migrations": parse_task_migrations(scheduler),
    }


def locality_worker_is_in_round_robin_row(
    *,
    process_pid: int,
    target_pids: set[int],
    thread_comm: str,
    audit_case: str,
    audit_engine: str,
    row_tag: str,
    worker_placement: str,
    group_cpus: set[int],
) -> bool:
    """Identify Tokio workers that must be pinned in the locality row."""
    return (
        process_pid in target_pids
        and thread_comm == "tokio-runtime-w"
        and audit_case == "mesh-gotatun"
        and audit_engine == "gotatun"
        and re.fullmatch(r"gotatun-j88i-(?:locality-)?33ca6fe-[0-9]+", row_tag) is not None
        and worker_placement == "round-robin"
        and len(group_cpus) == 2
    )


def locality_worker_may_use_narrow_mask(
    *,
    process_pid: int,
    target_pids: set[int],
    thread_comm: str,
    audit_case: str,
    audit_engine: str,
    row_tag: str,
    worker_placement: str,
    group_cpus: set[int],
    allowed: set[int],
) -> bool:
    """Allow singleton affinity only for assigned Tokio workers in the locality row."""
    return (
        locality_worker_is_in_round_robin_row(
            process_pid=process_pid,
            target_pids=target_pids,
            thread_comm=thread_comm,
            audit_case=audit_case,
            audit_engine=audit_engine,
            row_tag=row_tag,
            worker_placement=worker_placement,
            group_cpus=group_cpus,
        )
        and len(allowed) == 1
        and allowed.issubset(group_cpus)
    )


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


def parse_task_migrations(text: str) -> int | None:
    """Read a task's cumulative migration count from its procfs scheduler record."""
    for line in text.splitlines():
        name, separator, value = line.partition(":")
        if separator and name.strip() in {"se.nr_migrations", "nr_migrations"}:
            try:
                return int(value.strip())
            except ValueError:
                return None
    return None


def parse_proc_stat_steal_ticks(text: str) -> dict[str, int]:
    """Read Linux's per-CPU stolen-time counters from `/proc/stat`.

    The aggregate `cpu` row is omitted so reports can distinguish test CPUs
    from housekeeping CPUs. Linux reports steal in clock ticks, with the value
    in field eight after the CPU label.
    """
    result: dict[str, int] = {}
    for line in text.splitlines():
        fields = line.split()
        if not fields or re.fullmatch(r"cpu\d+", fields[0]) is None or len(fields) <= 8:
            continue
        try:
            result[fields[0][3:]] = int(fields[8])
        except ValueError:
            continue
    return result


def summarize_cpu_steal(
    before_ticks: dict[str, int],
    after_ticks: dict[str, int],
    test_cpus: set[int],
    housekeeping_cpus: set[int],
    ticks_per_second: int,
    window_duration_ns: int,
) -> dict[str, object]:
    """Report stolen CPU time across the measured test and housekeeping sets."""
    required = {str(cpu) for cpu in test_cpus | housekeeping_cpus}
    available = (
        ticks_per_second > 0
        and required.issubset(before_ticks)
        and required.issubset(after_ticks)
    )
    deltas = {
        cpu: max(0, after_ticks[cpu] - before_ticks[cpu])
        for cpu in sorted(required)
        if cpu in before_ticks and cpu in after_ticks
    }
    seconds_by_cpu = {
        cpu: ticks / ticks_per_second
        for cpu, ticks in deltas.items()
    } if ticks_per_second > 0 else {}
    test_seconds = sum(seconds_by_cpu.get(str(cpu), 0.0) for cpu in test_cpus)
    housekeeping_seconds = sum(
        seconds_by_cpu.get(str(cpu), 0.0) for cpu in housekeeping_cpus
    )
    window_seconds = window_duration_ns / 1_000_000_000
    test_cpu_seconds = window_seconds * len(test_cpus)
    return {
        "cpu_steal_data_available": available,
        "cpu_steal_delta_ticks_by_cpu": deltas,
        "cpu_steal_delta_seconds_by_cpu": seconds_by_cpu,
        "cpu_steal_test_cpu_seconds": test_seconds,
        "cpu_steal_housekeeping_cpu_seconds": housekeeping_seconds,
        "cpu_steal_all_cpu_seconds": test_seconds + housekeeping_seconds,
        "cpu_steal_test_cpu_percent": (
            test_seconds * 100 / test_cpu_seconds
            if test_cpu_seconds > 0 else 0.0
        ),
    }


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
        ("/proc/stat", "proc-stat"),
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
    audit_engine = os.environ.get("H2H_CPUSET_AUDIT_ENGINE", "")
    row_tag = os.environ.get("H2H_CPUSET_AUDIT_ROW_TAG", "")
    worker_placement = os.environ.get("H2H_CPUSET_AUDIT_WORKER_PLACEMENT", "default")
    target_pids = parse_pid_list(os.environ.get("H2H_CPUSET_AUDIT_TARGET_PIDS", ""))
    scope_threads = 0
    mask_mismatches = []
    external_runnable = []
    kernel_bound_runnable = []
    kernel_softirq_runnable = []
    kernel_wireguard_runnable = []
    kernel_other_runnable = []
    bound_percpu_workers = []
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
            parent_pid = int(values["parent_pid"])
            bound_cpu = bound_percpu_worker_cpu(comm, parent_pid, group, allowed)
            if bound_cpu in TEST_CPUS:
                bound_percpu_workers.append({
                    "pid": pid, "tid": tid, "comm": comm,
                    "role": bound_percpu_worker_role(comm, audit_case),
                    "worker_cpu": bound_cpu,
                    "state": values["state"],
                    "processor": values["processor"],
                    "cpus_allowed": values["cpus_allowed"],
                    "cpus_allowed_list": values["allowed"], "cgroup": group,
                    "parent_pid": parent_pid,
                    "runtime_ns": values["runtime_ns"],
                    "run_delay_ns": values["run_delay_ns"],
                })
            if in_scope:
                scope_threads += 1
                runtime_ns += int(values["runtime_ns"])
                run_delay_ns += int(values["run_delay_ns"])
                scope_processes.append({
                    "pid": pid, "tid": tid, "comm": comm,
                    "thread_comm": values["thread_comm"],
                    "state": values["state"], "processor": values["processor"],
                    "cpus_allowed": values["cpus_allowed"],
                    "cpus_allowed_list": values["allowed"], "cgroup": group,
                    "runtime_ns": values["runtime_ns"],
                    "run_delay_ns": values["run_delay_ns"],
                    "nr_migrations": values["nr_migrations"],
                })
                locality_worker = locality_worker_may_use_narrow_mask(
                    process_pid=pid,
                    target_pids=target_pids,
                    thread_comm=str(values["thread_comm"]),
                    audit_case=audit_case,
                    audit_engine=audit_engine,
                    row_tag=row_tag,
                    worker_placement=worker_placement,
                    group_cpus=group_cpus,
                    allowed=allowed,
                )
                locality_worker_task = locality_worker_is_in_round_robin_row(
                    process_pid=pid,
                    target_pids=target_pids,
                    thread_comm=str(values["thread_comm"]),
                    audit_case=audit_case,
                    audit_engine=audit_engine,
                    row_tag=row_tag,
                    worker_placement=worker_placement,
                    group_cpus=group_cpus,
                )
                if group_cpus not in EXPECTED_MASKS or (
                    (allowed != group_cpus or locality_worker_task) and not locality_worker
                ):
                    mask_mismatches.append({
                        "pid": pid, "tid": tid, "comm": comm,
                        "thread_comm": values["thread_comm"],
                        "cpus_allowed": values["cpus_allowed"],
                        "allowed": values["allowed"],
                        "scope_allowed": sorted(group_cpus),
                    })
                continue
            if values["state"] != "R" or not allowed.intersection(TEST_CPUS):
                continue
            task = {
                "pid": pid, "tid": tid, "comm": comm,
                "processor": values["processor"],
                "parent_pid": parent_pid,
                "cpus_allowed": values["cpus_allowed"],
                "cpus_allowed_list": values["allowed"], "cgroup": group,
            }
            task_class = classify_runnable_task(comm, audit_case)
            if bound_cpu is not None:
                kernel_bound_runnable.append(task)
                if comm.startswith("ksoftirqd/"):
                    kernel_softirq_runnable.append(task)
            elif task_class == "kernel-wireguard-crypto" and parent_pid == 2 and group == "/":
                kernel_wireguard_runnable.append(task)
            elif parent_pid == 2 and group == "/":
                kernel_other_runnable.append(task)
            else:
                external_runnable.append(task)

    return {
        "time_unix": time.time(),
        "audit_case": audit_case,
        "audit_engine": audit_engine,
        "audit_row_tag": row_tag,
        "worker_placement": worker_placement,
        "locality_target_pids": sorted(target_pids),
        "scope_threads": scope_threads,
        "scope_processes": scope_processes,
        "mask_mismatches": mask_mismatches,
        "external_runnable": external_runnable,
        "kernel_bound_percpu_runnable": kernel_bound_runnable,
        "kernel_softirq_runnable": kernel_softirq_runnable,
        "kernel_wireguard_crypto_runnable": kernel_wireguard_runnable,
        "kernel_other_runnable": kernel_other_runnable,
        "kernel_bound_percpu_workers": bound_percpu_workers,
        "audit_parent_pid": PARENT_PID,
        "scope_runtime_ns": runtime_ns,
        "scope_run_delay_ns": run_delay_ns,
        "cpu_pressure": read_text(Path("/proc/pressure/cpu")).strip(),
        "proc_stat_steal_ticks_by_cpu": parse_proc_stat_steal_ticks(
            read_text(Path("/proc/stat"))
        ),
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
                        help="case shell PID, retained for audit evidence and not exempt from checks")
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
    bound_percpu_worker_records: dict[str, dict[str, object]] = {}
    kernel_worker_runtime_delta_by_cpu_ns: dict[int, int] = {}
    kernel_worker_runtime_delta_by_role_ns: dict[str, int] = {}
    kernel_other_workers: dict[str, dict[str, object]] = {}
    max_scope_threads = 0
    runtime_delta_ns = 0
    run_delay_delta_ns = 0
    previous_stats: dict[str, tuple[int, int]] = {}
    previous_kernel_worker_stats: dict[str, tuple[int, int]] = {}
    previous_migrations: dict[str, int] = {}
    task_migrations: dict[str, dict[str, object]] = {}
    migration_observations = 0
    missing_migration_observations = 0
    window_start_unix: float | None = None
    window_end_unix: float | None = None
    first_steal_ticks: dict[str, int] = {}
    last_steal_ticks: dict[str, int] = {}
    with (OUTPUT / "samples.jsonl").open("w") as output:
        while not STOP:
            current = sample()
            samples += 1
            sample_time = float(current.get("time_unix", time.time()))
            if window_start_unix is None:
                window_start_unix = sample_time
                first_steal_ticks = {
                    str(cpu): int(ticks)
                    for cpu, ticks in current.get("proc_stat_steal_ticks_by_cpu", {}).items()
                }
            window_end_unix = sample_time
            last_steal_ticks = {
                str(cpu): int(ticks)
                for cpu, ticks in current.get("proc_stat_steal_ticks_by_cpu", {}).items()
            }
            max_scope_threads = max(max_scope_threads, int(current["scope_threads"]))
            mismatch_samples += bool(current["mask_mismatches"])
            external_samples += bool(current["external_runnable"])
            wireguard_workers = current.get("kernel_wireguard_crypto_runnable", [])
            kernel_wireguard_samples += bool(wireguard_workers)
            for worker in wireguard_workers:
                key = f"{worker['pid']}:{worker['tid']}"
                kernel_wireguard_workers[key] = worker
            current_kernel_worker_stats: dict[str, tuple[int, int]] = {}
            for worker in current.get("kernel_bound_percpu_workers", []):
                key = f"{worker['pid']}:{worker['tid']}"
                cpu = int(worker["worker_cpu"])
                runtime = int(worker["runtime_ns"])
                role = str(worker.get("role") or bound_percpu_worker_role(
                    str(worker["comm"]), str(current.get("audit_case", ""))
                ))
                bound_percpu_worker_records[key] = {**worker, "role": role}
                previous = previous_kernel_worker_stats.get(key)
                if previous is not None:
                    runtime_delta = max(0, runtime - previous[1])
                    kernel_worker_runtime_delta_by_cpu_ns[cpu] = (
                        kernel_worker_runtime_delta_by_cpu_ns.get(cpu, 0) + runtime_delta
                    )
                    kernel_worker_runtime_delta_by_role_ns[role] = (
                        kernel_worker_runtime_delta_by_role_ns.get(role, 0) + runtime_delta
                    )
                current_kernel_worker_stats[key] = (cpu, runtime)
            previous_kernel_worker_stats = current_kernel_worker_stats
            for worker in current.get("kernel_other_runnable", []):
                key = f"{worker['pid']}:{worker['tid']}"
                kernel_other_workers[key] = worker
            current_stats: dict[str, tuple[int, int]] = {}
            current_migrations: dict[str, int] = {}
            for task in current["scope_processes"]:
                key = f"{task['pid']}:{task['tid']}"
                runtime = int(task["runtime_ns"])
                delay = int(task["run_delay_ns"])
                old_runtime, old_delay = previous_stats.get(key, (0, 0))
                runtime_delta_ns += max(0, runtime - old_runtime)
                run_delay_delta_ns += max(0, delay - old_delay)
                current_stats[key] = (runtime, delay)
                migration_count = task.get("nr_migrations")
                migration_observations += 1
                if migration_count is None:
                    missing_migration_observations += 1
                    continue
                migration_count = int(migration_count)
                current_migrations[key] = migration_count
                record = task_migrations.setdefault(key, {
                    "pid": task["pid"], "tid": task["tid"],
                    "comm": task.get("thread_comm") or task["comm"],
                    "migration_delta": 0, "first_cpu": task["processor"],
                    "last_cpu": task["processor"],
                })
                previous_count = previous_migrations.get(key)
                if previous_count is not None:
                    record["migration_delta"] = int(record["migration_delta"]) + max(
                        0, migration_count - previous_count
                    )
                record["last_cpu"] = task["processor"]
            previous_stats = current_stats
            previous_migrations = current_migrations
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
    kernel_worker_runtime_delta_ns = sum(kernel_worker_runtime_delta_by_cpu_ns.values())
    kernel_background_runtime_delta_ns = kernel_worker_runtime_delta_by_role_ns.get(
        "background", 0
    )
    window_duration_ns = 0
    if window_start_unix is not None and window_end_unix is not None:
        window_duration_ns = max(0, int((window_end_unix - window_start_unix) * 1_000_000_000))
    test_cpu_time_ns = window_duration_ns * len(TEST_CPUS)
    steal_summary = summarize_cpu_steal(
        first_steal_ticks,
        last_steal_ticks,
        TEST_CPUS,
        HOUSEKEEPING_CPUS,
        int(os.sysconf("SC_CLK_TCK")),
        window_duration_ns,
    )
    kernel_bound_runtime_limit_exceeded = kernel_worker_window_exceeds_limit(
        kernel_background_runtime_delta_ns, test_cpu_time_ns
    )
    clean = (
        not mismatch_samples
        and not external_samples
        and not kernel_bound_runtime_limit_exceeded
        and max_scope_threads > 0
        and steal_summary["cpu_steal_data_available"]
        and interrupt_data_available
        and softirq_data_available
    )
    summary = {
        "samples": samples,
        "mask_mismatch_samples": mismatch_samples,
        "external_runnable_samples": external_samples,
        "kernel_wireguard_crypto_runnable_samples": kernel_wireguard_samples,
        "kernel_wireguard_crypto_workers": list(kernel_wireguard_workers.values()),
        "kernel_bound_percpu_workers": list(bound_percpu_worker_records.values()),
        "kernel_other_runnable": list(kernel_other_workers.values()),
        "kernel_bound_percpu_runtime_delta_ns": kernel_worker_runtime_delta_ns,
        "kernel_bound_percpu_runtime_delta_by_cpu_ns": {
            str(cpu): runtime for cpu, runtime in sorted(kernel_worker_runtime_delta_by_cpu_ns.items())
        },
        "kernel_bound_percpu_runtime_delta_by_role_ns": {
            role: runtime for role, runtime in sorted(kernel_worker_runtime_delta_by_role_ns.items())
        },
        "kernel_background_percpu_runtime_delta_ns": kernel_background_runtime_delta_ns,
        "window_duration_ns": window_duration_ns,
        "test_cpu_time_ns": test_cpu_time_ns,
        **steal_summary,
        "kernel_bound_percpu_runtime_limit_percent": BOUND_WORKER_RUNTIME_LIMIT_PERCENT,
        "kernel_bound_runtime_budget_role": "background",
        "kernel_bound_percpu_runtime_percent_of_test_cpu_time": (
            kernel_worker_runtime_delta_ns * 100 / test_cpu_time_ns
            if test_cpu_time_ns > 0 else (float("inf") if kernel_worker_runtime_delta_ns else 0.0)
        ),
        "kernel_background_percpu_runtime_percent_of_test_cpu_time": (
            kernel_background_runtime_delta_ns * 100 / test_cpu_time_ns
            if test_cpu_time_ns > 0 else (float("inf") if kernel_background_runtime_delta_ns else 0.0)
        ),
        "kernel_bound_runtime_limit_exceeded": kernel_bound_runtime_limit_exceeded,
        "max_scope_threads": max_scope_threads,
        "scope_runtime_delta_ns": runtime_delta_ns,
        "scope_run_delay_delta_ns": run_delay_delta_ns,
        "scope_task_migration_observations": migration_observations,
        "scope_task_migration_missing_observations": missing_migration_observations,
        "scope_task_migration_data_available": (
            migration_observations > 0 and missing_migration_observations == 0
        ),
        "scope_task_migrations_total": sum(
            int(task["migration_delta"]) for task in task_migrations.values()
        ),
        "scope_task_migrations_by_task": sorted(
            task_migrations.values(), key=lambda task: (int(task["pid"]), int(task["tid"]))
        ),
        "scope_task_migration_source": (
            "per-thread /proc/<pid>/task/<tid>/sched se.nr_migrations deltas "
            "between one-second samples; short-lived tasks may be missed"
        ),
        "clean": clean,
        "test_cpu_list": sorted(TEST_CPUS),
        "expected_side_cpu_lists": [[1, 2], [3, 4]],
        "interrupt_data_available": interrupt_data_available,
        "softirq_data_available": softirq_data_available,
        "interrupt_delta_per_cpu": interrupt_delta,
        "softirq_delta_per_cpu": softirq_delta,
        "veth_irq_note": "veth links have no device IRQ; interrupt affinity and per-CPU softirq deltas are retained for the measured path",
        "audit_case": os.environ.get("H2H_CPUSET_AUDIT_CASE", ""),
        "audit_engine": os.environ.get("H2H_CPUSET_AUDIT_ENGINE", ""),
        "audit_row_tag": os.environ.get("H2H_CPUSET_AUDIT_ROW_TAG", ""),
        "worker_placement": os.environ.get("H2H_CPUSET_AUDIT_WORKER_PLACEMENT", "default"),
        "locality_target_pids": sorted(parse_pid_list(
            os.environ.get("H2H_CPUSET_AUDIT_TARGET_PIDS", "")
        )),
        "interpretation": "bound kthreadd children in cgroup / named and pinned to one test CPU are measured by role and in total; only unrelated background-worker runtime is budgeted against 0.5% of test-CPU time; kernel crypto and network softirq are measured workload and are reported without using that budget; any non-kernel runnable task allowed on test CPUs rejects the window; other root kernel tasks are reported separately",
    }
    (OUTPUT / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return 0 if clean else 1


if __name__ == "__main__":
    raise SystemExit(main())
