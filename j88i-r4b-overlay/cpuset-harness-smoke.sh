#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Prove R4b namespace helpers create separate 1-2 and 3-4 process cpusets.
set -euo pipefail

H2H_KIT=$1
H2H_RESULTS=$2
H2H_CASE=j88i-cpuset-smoke
H2H_CPUSET_PIN=1
H2H_CPUSET_A=1-2
H2H_CPUSET_B=3-4
H2H_CPUSET_HOUSEKEEPING=0,5
H2H_CPUSET_AUDIT=1
H2H_CPUSET_AUDIT_REQUIRE_CLEAN=1
H2H_RUN=$(mktemp -d /dev/shm/j88i-cpuset-smoke.XXXXXX)
export H2H_KIT H2H_RESULTS H2H_CASE H2H_CPUSET_PIN H2H_CPUSET_A H2H_CPUSET_B H2H_CPUSET_HOUSEKEEPING
export H2H_CPUSET_AUDIT H2H_CPUSET_AUDIT_REQUIRE_CLEAN H2H_RUN
mkdir -p "$H2H_RESULTS"
mkdir -p "$H2H_RESULTS/$H2H_CASE"
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

check_mask h2h-a 1-2
check_mask h2h-b 3-4

# A paused scope lets the audit start after systemd has created every measured
# cgroup, then releases the tools together so setup work is outside the hold.
paused_marker="$H2H_RUN/paused-started"
paused_done="$H2H_RUN/paused-done"
paused_gate="$H2H_RUN/paused-gate"
mkfifo "$paused_gate"
H2H_SCOPE_PAUSE=1 H2H_SCOPE_LOG="$H2H_RUN/paused-scope.log" \
    spawn_in_ns paused_pid h2h-a bash -c \
    'printf started > "$1"; read -r _ < "$2"; printf done > "$3"' \
    bash "$paused_marker" "$paused_gate" "$paused_done"
paused_client=$H2H_SCOPE_CLIENT_PID
paused_state=$(awk '/^State:/ {print $2}' "/proc/$paused_pid/status")
[[ $paused_state == T ]] || die "measured scope was not stopped before release: state=$paused_state"
[[ ! -e $paused_marker ]] || die "measured command ran before the audit started"
kill -CONT "$paused_pid"
wait_for 10 test -e "$paused_marker" || die "released measured command did not start"
printf 'go\n' > "$paused_gate"
wait "$paused_client" || die "released measured scope failed"
[[ -e $paused_done ]] || die "released measured scope did not finish"

spawn_in_ns probe_a_pid h2h-a sleep 30
spawn_in_ns probe_b_pid h2h-b sleep 30
for entry in "probe_a_pid:1-2" "probe_b_pid:3-4"; do
    name=${entry%%:*}
    want=${entry#*:}
    pid=${!name}
    masks=$(awk '/^Cpus_allowed:/ {mask=$2} /^Cpus_allowed_list:/ {list=$2} END {print mask, list}' "/proc/$pid/status")
    read -r mask list <<< "$masks"
    log "background namespace PID $pid masks: Cpus_allowed=$mask Cpus_allowed_list=$list, expected $want"
    [[ -n $mask && $list == "$want" ]] || die "background namespace process masks were $masks"
done
h2h_cpu_audit_start smoke
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
