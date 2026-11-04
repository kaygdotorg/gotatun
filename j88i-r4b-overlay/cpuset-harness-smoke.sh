#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Prove R4b namespace helpers create separate 0-1 and 2-3 process cpusets.
set -euo pipefail

H2H_KIT=$1
H2H_RESULTS=$2
H2H_CASE=j88i-cpuset-smoke
H2H_CPUSET_PIN=1
H2H_CPUSET_A=0-1
H2H_CPUSET_B=2-3
H2H_CPUSET_AUDIT=1
H2H_CPUSET_AUDIT_REQUIRE_CLEAN=1
H2H_RUN=$(mktemp -d /dev/shm/j88i-cpuset-smoke.XXXXXX)
export H2H_KIT H2H_RESULTS H2H_CASE H2H_CPUSET_PIN H2H_CPUSET_A H2H_CPUSET_B
export H2H_CPUSET_AUDIT H2H_CPUSET_AUDIT_REQUIRE_CLEAN H2H_RUN
mkdir -p "$H2H_RESULTS"
source "$H2H_KIT/lib/common.sh"

finish() {
    local rc=$?
    trap - EXIT
    h2h_cpu_audit_stop || { ((rc != 0)) || rc=1; }
    cleanup || { ((rc != 0)) || rc=1; }
    rm -rf "$H2H_RUN"
    exit "$rc"
}
trap finish EXIT

for name in h2h-a h2h-b; do
    if ip netns list | awk '{print $1}' | grep -qx "$name"; then
        die "namespace $name already exists before the smoke check"
    fi
    netns_add "$name"
done

check_mask() {
    local ns=$1 want=$2 got mask list
    got=$(in_ns "$ns" awk '/^Cpus_allowed:/ {mask=$2} /^Cpus_allowed_list:/ {list=$2} END {print mask, list}' /proc/self/status)
    read -r mask list <<< "$got"
    log "$ns process masks: Cpus_allowed=$mask Cpus_allowed_list=$list, expected $want"
    [[ -n $mask && $list == "$want" ]] || die "$ns process masks were $got, expected list $want"
}

check_mask h2h-a 0-1
check_mask h2h-b 2-3

h2h_cpu_audit_start smoke
spawn_in_ns probe_a_pid h2h-a sleep 30
spawn_in_ns probe_b_pid h2h-b sleep 30
for entry in "probe_a_pid:0-1" "probe_b_pid:2-3"; do
    name=${entry%%:*}
    want=${entry#*:}
    pid=${!name}
    masks=$(awk '/^Cpus_allowed:/ {mask=$2} /^Cpus_allowed_list:/ {list=$2} END {print mask, list}' "/proc/$pid/status")
    read -r mask list <<< "$masks"
    log "background namespace PID $pid masks: Cpus_allowed=$mask Cpus_allowed_list=$list, expected $want"
    [[ -n $mask && $list == "$want" ]] || die "background namespace process masks were $masks"
done
sleep 2
h2h_cpu_audit_stop
python3 -I - "$H2H_RESULTS/$H2H_CASE/cpuset-smoke/summary.json" <<'PY'
import json
import sys
from pathlib import Path

summary = json.loads(Path(sys.argv[1]).read_text())
if not summary.get("clean") or summary.get("samples", 0) < 1:
    raise SystemExit(f"cpuset and runnable-task proof failed: {summary}")
print(json.dumps(summary, sort_keys=True))
PY
log "R4b cpuset helper smoke passed"
