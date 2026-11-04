#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Head-to-head kit entry point (#260): infraternal mesh vs GotaTun, NetBird
# and Tailscale, infraternal sessions vs tmux and Zellij, on one machine.
#
#   sudo ./run.sh [--smoke] [--only case,case] [--label TEXT]
#
# Every case runs in its own hold of the perf lock (/var/lock/perf-bench.lock,
# the lock perf-run/perf-lock use) and inside `systemd-run --scope
# --slice=perf.slice`. Inside each hold: machine snapshot, the case, cleanup,
# a second snapshot; the two must be identical (machine-diff.txt). Results
# land in results/<timestamp>/ next to this script; summary.md is the table.
#
# Environment: H2H_LOCK=none skips the lock and the scope (build-host smoke
# only); H2H_USER picks the account whose login shell the terminal sessions
# run (default: the sudo caller).
set -euo pipefail
H2H_KIT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
export H2H_KIT
SMOKE=0 ONLY="" LABEL=""
while (($#)); do
    case $1 in
        --smoke) SMOKE=1 ;;
        --only) ONLY=$2; shift ;;
        --label) LABEL=$2; shift ;;
        *) echo "usage: sudo ./run.sh [--smoke] [--only case,case] [--label TEXT]" >&2; exit 2 ;;
    esac
    shift
done
export H2H_SMOKE=$SMOKE
[[ $(id -u) == 0 ]] || { echo "run as root (sudo ./run.sh)" >&2; exit 2; }

CASES=(mesh-underlay mesh-infraternal mesh-tailscale mesh-gotatun mesh-boringtun mesh-wireguard-go mesh-netbird mesh-netbird-userspace mesh-kernel-plain term-local term-wan term-loss term-scale)
if [[ -n $ONLY ]]; then IFS=, read -r -a CASES <<< "$ONLY"; fi

stamp=$(date -u +%Y%m%dT%H%M%SZ)
export H2H_RESULTS=${H2H_RESULTS:-$H2H_KIT/results/$stamp}
mkdir -p "$H2H_RESULTS"
if [[ ${H2H_LOCK:-} == external ]]; then
    grep -q 'perf.slice' /proc/self/cgroup || { echo 'external lock mode requires perf.slice' >&2; exit 2; }
fi
if [[ ${H2H_CPUSET_PIN:-0} == 1 ]]; then
    perf_cpus=${H2H_CPUSET_PERF:-0-5}
    [[ ${H2H_CPUSET_A:-} == 1-2 && ${H2H_CPUSET_B:-} == 3-4 ]] || {
        echo 'D348 requires side A CPUs 1-2 and side B CPUs 3-4' >&2
        exit 2
    }
    [[ $(cat /sys/fs/cgroup/perf.slice/cpuset.cpus) == "$perf_cpus" && \
       $(cat /sys/fs/cgroup/perf.slice/cpuset.cpus.effective) == "$perf_cpus" ]] || {
        echo "D348 runtime perf.slice cgroup masks are not $perf_cpus" >&2
        exit 2
    }
    [[ $(awk '/^Cpus_allowed_list:/ {print $2}' /proc/self/status) == 0,5 ]] || {
        echo 'D348 case runner is not pinned to housekeeping CPUs 0,5' >&2
        exit 2
    }
    {
        printf 'side_a=%s\nside_b=%s\n' "$H2H_CPUSET_A" "$H2H_CPUSET_B"
        printf 'housekeeping=%s\n' "${H2H_CPUSET_HOUSEKEEPING:-0,5}"
        printf 'perf_slice_cpuset=%s\n' "$(cat /sys/fs/cgroup/perf.slice/cpuset.cpus)"
        printf 'perf_slice_effective=%s\n' "$(cat /sys/fs/cgroup/perf.slice/cpuset.cpus.effective)"
        printf 'runner_cpus_allowed=%s\n' "$(awk '/^Cpus_allowed:/ {print $2}' /proc/self/status)"
        printf 'runner_allowed=%s\n' "$(awk '/^Cpus_allowed_list:/ {print $2}' /proc/self/status)"
    } > "$H2H_RESULTS/cpuset-preflight.txt"
fi
exec > >(tee -a "$H2H_RESULTS/run.log") 2>&1

arch=$(uname -m)
kit_arch=$(cat "$H2H_KIT/ARCH")
[[ $arch == "$kit_arch" ]] || { echo "this kit is for $kit_arch, machine is $arch" >&2; exit 2; }
if [[ -z $LABEL ]]; then
    if [[ $arch != x86_64 || $SMOKE == 1 ]]; then LABEL="build host, $arch, not perf evidence"; else LABEL="perf VM $(hostname), $arch"; fi
fi

# --- preflight ---------------------------------------------------------------------
missing=()
for tool in ip tc nsenter unshare setpriv flock modprobe python3 timeout sha256sum base64 awk getent systemctl ping; do
    command -v "$tool" >/dev/null || missing+=("$tool")
done
((${#missing[@]} == 0)) || { echo "missing tools: ${missing[*]}" >&2; exit 2; }
for mod in wireguard tun veth bridge sch_netem overlay; do
    modprobe -n "$mod" 2>/dev/null || grep -qw "$mod" /proc/filesystems /proc/modules 2>/dev/null \
        || echo "warning: kernel module $mod not available" >&2
done
command -v sshd >/dev/null || [[ -x /usr/sbin/sshd ]] || echo "warning: no sshd: tmux/Zellij over SSH cases are skipped" >&2
python3 - "$H2H_RESULTS/environment.json" "$LABEL" "$SMOKE" "$H2H_KIT" <<'PY'
import json, os, platform, sys
cpu = next((l.split(":", 1)[1].strip() for l in open("/proc/cpuinfo") if l.startswith(("model name", "Model"))), "")
mem = next(int(l.split()[1]) for l in open("/proc/meminfo") if l.startswith("MemTotal"))
kit = sys.argv[4]
json.dump({
    "label": sys.argv[2], "smoke": sys.argv[3] == "1", "host": platform.node(),
    "kernel": platform.release(), "arch": platform.machine(), "cpu": cpu, "cores": os.cpu_count(),
    "mem_kb": mem, "load": open("/proc/loadavg").read().split()[:3],
    "os": dict(l.rstrip().split("=", 1) for l in open("/etc/os-release") if "=" in l).get("PRETTY_NAME", "").strip('"'),
    "kit_manifest": open(os.path.join(kit, "MANIFEST")).read().splitlines(),
}, open(sys.argv[1], "w"), indent=1)
PY
echo "head-to-head: ${CASES[*]} | $LABEL | results $H2H_RESULTS"

# --- one case, one lock hold ---------------------------------------------------------
run_case() {
    local name=$1 dir="$H2H_RESULTS/$1"
    local script args
    case $name in
        mesh-*) script=mesh.sh; args=${name#mesh-} ;;
        term-*) script=term.sh; args=${name#term-} ;;
        *) echo "unknown case $name" >&2; return 2 ;;
    esac
    mkdir -p "$dir"
    local lockfd
    if [[ ${H2H_LOCK:-} != none && ${H2H_LOCK:-} != external ]]; then
        exec {lockfd}>>/var/lock/perf-bench.lock
        echo "$(date +%T) waiting for /var/lock/perf-bench.lock"
        flock -w 3600 "$lockfd" || { echo "lock not acquired" >&2; return 75; }
        printf 'infraternal head-to-head-260 %s start=%s\n' "$name" "$(date -Is)" > /var/lock/perf-bench.owner
    fi
    local t0=$SECONDS rc=0
    "$H2H_KIT/lib/snapshot.sh" "$H2H_KIT" > "$dir/machine-before.txt"
    export H2H_RUN=/dev/shm/h2h-$$-$name
    mkdir -m 755 "$H2H_RUN"
    local scope=() case_timeout=20m
    [[ ${H2H_SOAK_SECONDS:-0} == 3600 ]] && case_timeout=75m
    [[ ${H2H_LOCK:-} == none || ${H2H_LOCK:-} == external ]] || scope=(systemd-run --scope --quiet --slice=perf.slice --unit="h2h-$name-$$" --)
    "${scope[@]}" timeout --signal=TERM "$case_timeout" bash "$H2H_KIT/cases/$script" "$args" || rc=$?
    if find "$dir" -name '*.failed' -print -quit | grep -q .; then
        echo "one or more measurements failed; inspect .err files in $dir"
        [[ $rc != 0 ]] || rc=4
    fi
    # Safety net behind the case's own cleanup: nothing of ours may outlive it.
    local ns
    for ns in $(ip netns list 2>/dev/null | awk '$1 ~ /^h2h-/ {print $1}'); do
        ip netns pids "$ns" 2>/dev/null | xargs -r kill -KILL 2>/dev/null || true
        ip netns del "$ns" 2>/dev/null || true
    done
    rm -rf "$H2H_RUN"
    # Unload kernel modules this case loaded, so the module list matches again.
    local new
    # Mount namespaces of exited sandboxes release overlayfs asynchronously: retry.
    for _ in 1 2 3 4 5 6; do
        new=$(comm -13 <(sed -n '/^## modules/,/^## /p' "$dir/machine-before.txt" | sed '1d;$d' | sort) <(cut -d' ' -f1 /proc/modules | sort))
        [[ -z $new ]] && break
        for m in $new; do modprobe -r "$m" 2>/dev/null || true; done
        sleep 1
    done
    "$H2H_KIT/lib/snapshot.sh" "$H2H_KIT" > "$dir/machine-after.txt"
    if diff -u "$dir/machine-before.txt" "$dir/machine-after.txt" > "$dir/machine-diff.txt"; then
        echo "machine diff: empty"
    else
        echo "machine diff NOT empty:"; head -40 "$dir/machine-diff.txt"
        [[ $rc == 0 ]] && rc=3
    fi
    printf '{"case":"%s","exit":%d,"seconds":%d}\n' "$name" "$rc" $((SECONDS - t0)) > "$dir/status.json"
    if [[ ${H2H_LOCK:-} != none && ${H2H_LOCK:-} != external ]]; then
        flock -u "$lockfd"
        exec {lockfd}>&-
    fi
    echo "case $name: exit $rc in $((SECONDS - t0)) s"
    return 0
}

start=$SECONDS
for c in "${CASES[@]}"; do run_case "$c"; done
python3 -I "$H2H_KIT/lib/report.py" "$H2H_RESULTS" > "$H2H_RESULTS/summary.md" || true
echo "total: $((SECONDS - start)) s; summary: $H2H_RESULTS/summary.md"
cat "$H2H_RESULTS/summary.md"
# Separate perf-run holds share the results tree. A previous case's failure
# must not change the exit status of the case measured by this hold.
for c in "${CASES[@]}"; do
    [[ -s "$H2H_RESULTS/$c/status.json" ]] || exit 1
    if grep -q '"exit":[1-9]' "$H2H_RESULTS/$c/status.json"; then exit 1; fi
done
exit 0
