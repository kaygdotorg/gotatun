# SPDX-License-Identifier: AGPL-3.0-only
# Shared helpers for the head-to-head kit (#260). Sourced by run.sh and the
# case scripts; never run directly.
#
# Invariants every case relies on:
# - Nothing outside $H2H_RUN (a private tmpfs directory under /dev/shm) and
#   the results directory is written by kit code. Third-party daemons run in
#   `sandboxed`, where writes to /etc, /var and /run land in throwaway
#   overlays, so a daemon that edits resolv.conf or its state directory cannot
#   change the machine.
# - Every network namespace, interface and process a case creates is
#   registered for cleanup the moment it exists; `cleanup` runs on every exit.
# - No secret is ever placed in argv or printed: keys and tokens live in 0600
#   files under $H2H_RUN and are read by the programs that need them.

set -euo pipefail

H2H_KIT=${H2H_KIT:?}
H2H_BIN=$H2H_KIT/bin
H2H=$H2H_BIN/h2h
H=$H2H

log() { printf '%s [%s] %s\n' "$(date +%H:%M:%S)" "${H2H_CASE:-kit}" "$*" >&2; }
die() { log "FAIL: $*"; exit 1; }

# Durations shrink in smoke mode; full values are the perf-VM method.
dur() { if [[ ${H2H_SMOKE:-0} == 1 ]]; then echo "$2"; else echo "$1"; fi; }

# D348 validation uses the normal LAN load window so one short kernel-worker
# burst does not dominate the per-window unrelated-work budget.
h2h_lan_tput_duration() {
    local full_seconds=$1 smoke_seconds=$2 override=${H2H_LAN_TPUT_SECONDS:-}
    if [[ -z $override ]]; then
        dur "$full_seconds" "$smoke_seconds"
        return
    fi
    [[ $override =~ ^[1-9][0-9]*$ ]] || die "H2H_LAN_TPUT_SECONDS must be a positive integer"
    printf '%s\n' "$override"
}

# The LAN calibration can increase its sample count without changing the normal or smoke method.
h2h_lan_latency_count() {
    local count=${H2H_LAN_PING_COUNT:-}
    if [[ -z $count ]]; then
        dur 2000 300
        return
    fi
    [[ $count =~ ^[1-9][0-9]*$ ]] || die "H2H_LAN_PING_COUNT must be a positive integer"
    printf '%s\n' "$count"
}

# --- cleanup registry -------------------------------------------------------
H2H_CLEAN_PIDS=()
H2H_CLEAN_NETNS=()
H2H_CLEAN_CMDS=()
register_pid() { H2H_CLEAN_PIDS+=("$1"); }
register_netns() { H2H_CLEAN_NETNS+=("$1"); }
register_cmd() { H2H_CLEAN_CMDS+=("$1"); }
# A TERM from run.sh's timeout must still reach the EXIT trap (cleanup).
trap 'exit 143' TERM INT

stop_pid() {
    local pid=$1
    kill -0 "$pid" 2>/dev/null || return 0
    kill -TERM "$pid" 2>/dev/null || true
    for _ in $(seq 50); do kill -0 "$pid" 2>/dev/null || return 0; sleep 0.1; done
    kill -KILL "$pid" 2>/dev/null || true
}

cleanup() {
    local rc=$?
    set +e
    h2h_cpu_audit_stop
    # A daemon that already exited must not turn our goodbye into SIGPIPE.
    trap '' PIPE
    local i
    for ((i = ${#H2H_CLEAN_CMDS[@]} - 1; i >= 0; i--)); do eval "${H2H_CLEAN_CMDS[$i]}" >/dev/null 2>&1; done
    for ((i = ${#H2H_CLEAN_PIDS[@]} - 1; i >= 0; i--)); do stop_pid "${H2H_CLEAN_PIDS[$i]}"; done
    # Anything still running inside our namespaces belongs to this case.
    for ns in "${H2H_CLEAN_NETNS[@]}"; do
        for pid in $(ip netns pids "$ns" 2>/dev/null); do kill -KILL "$pid" 2>/dev/null; done
        ip netns del "$ns" 2>/dev/null
    done
    return $rc
}

# Return the fixed D348 CPU pair for a namespace's test side.
h2h_cpu_mask_for_ns() {
    case $1 in
        h2h-a | h2h-ts | h2h-c | h2h-u) printf '%s' "${H2H_CPUSET_A:-1-2}" ;;
        h2h-b | h2h-tc) printf '%s' "${H2H_CPUSET_B:-3-4}" ;;
        *) die "no D348 CPU pair is defined for namespace $1" ;;
    esac
}

# Find the test namespace that owns a process, then return its side's CPU pair.
h2h_cpu_mask_for_pid() {
    local pid=$1 target ns
    target=$(stat -Lc '%i' "/proc/$pid/ns/net") || die "cannot read network namespace for PID $pid"
    for ns in h2h-a h2h-b h2h-c h2h-u h2h-ts h2h-tc; do
        [[ -e "/var/run/netns/$ns" ]] || continue
        if [[ $(stat -Lc '%i' "/var/run/netns/$ns") == "$target" ]]; then
            h2h_cpu_mask_for_ns "$ns"
            return
        fi
    done
    die "PID $pid is not in a known R4b test namespace"
}

# Run one short namespace-side command in a transient cpuset scope.
h2h_scope_run() {
    local cpus=$1; shift
    if [[ ${H2H_CPUSET_PIN:-0} != 1 ]]; then
        "$@"
        return
    fi
    local slug unit
    slug=${H2H_CASE:-kit}
    slug=${slug//[^a-zA-Z0-9_.-]/-}
    unit="j88i-$slug-$$-$RANDOM.scope"
    systemd-run --scope --quiet --collect --slice=perf.slice --unit="$unit" \
        --property="AllowedCPUs=$cpus" -- "$@"
}

# Start a longer-lived namespace process in its side's cpuset and return the
# actual command PID. A paused scope writes its PID before stopping, so all
# measured scopes can exist before the clean audit and load start together.
h2h_scope_spawn() {
    local outvar=$1 cpus=$2; shift 2
    local slug unit pidfile scope_log scope_stdout scope_stderr client scope_pid pause
    slug=${H2H_CASE:-kit}
    slug=${slug//[^a-zA-Z0-9_.-]/-}
    unit="j88i-$slug-$$-$RANDOM.scope"
    pause=${H2H_SCOPE_PAUSE:-0}
    if [[ ${H2H_CPUSET_PIN:-0} != 1 ]]; then
        scope_log=${H2H_SCOPE_LOG:-/dev/null}
        scope_stdout=${H2H_SCOPE_STDOUT:-$scope_log}
        scope_stderr=${H2H_SCOPE_STDERR:-$scope_log}
        if [[ $scope_stderr == "$scope_stdout" ]]; then
            "$@" > "$scope_stdout" 2>&1 &
        else
            "$@" > "$scope_stdout" 2>"$scope_stderr" &
        fi
        scope_pid=$!
        register_pid "$scope_pid"
        H2H_SCOPE_CLIENT_PID=$scope_pid
        printf -v "$outvar" '%s' "$scope_pid"
        return
    fi
    pidfile="$H2H_RUN/$unit.pid"
    scope_log=${H2H_SCOPE_LOG:-$H2H_RUN/$unit.log}
    scope_stdout=${H2H_SCOPE_STDOUT:-$scope_log}
    scope_stderr=${H2H_SCOPE_STDERR:-$scope_log}
    mkdir -p "$(dirname "$scope_log")"
    systemd-run --scope --quiet --collect --slice=perf.slice --unit="$unit" \
        --property="AllowedCPUs=$cpus" -- /bin/bash -c \
        'pidfile=$1; pause=$2; stdout=$3; stderr=$4; shift 4; printf "%s\\n" "$$" > "$pidfile"; if [[ $pause == 1 ]]; then kill -STOP "$$"; fi; if [[ $stderr == "$stdout" ]]; then exec "$@" > "$stdout" 2>&1; else exec "$@" > "$stdout" 2>"$stderr"; fi' \
        j88i-scope "$pidfile" "$pause" "$scope_stdout" "$scope_stderr" "$@" > "$scope_log" 2>&1 &
    client=$!
    register_pid "$client"
    wait_for 10 test -s "$pidfile" || die "cpuset scope $unit did not publish its command PID: $(tail -c 600 "$scope_log")"
    read -r scope_pid < "$pidfile"
    register_pid "$scope_pid"
    H2H_SCOPE_CLIENT_PID=$client
    printf '%s\t%s\t%s\n' "$scope_pid" "$cpus" "$unit" >> "$H2H_RESULTS/$H2H_CASE/cpuset-pids.tsv"
    printf -v "$outvar" '%s' "$scope_pid"
}

# Wait for a clean preflight, then sample process placement and scheduler delay
# across the measured phase; setup activity is stored separately from load.
h2h_cpu_audit_start() {
    [[ ${H2H_CPUSET_AUDIT:-0} == 1 ]] || return 0
    [[ -z ${H2H_CPUSET_AUDIT_PID:-} ]] || die "a cpuset audit is already running"
    local tag=$1 dir="$H2H_RESULTS/$H2H_CASE/cpuset-$1" ready_file
    mkdir -p "$dir"
    ready_file="$dir/ready"
    H2H_CPUSET_AUDIT_SUMMARY="$dir/summary.json"
    H2H_CPUSET_AUDIT_CASE="$H2H_CASE" \
    H2H_CPUSET_AUDIT_READY_FILE="$ready_file" \
        python3 -I "$H2H_KIT/lib/cpuset_audit.py" "$dir" "${BASHPID:-$$}" &
    H2H_CPUSET_AUDIT_PID=$!
    log "cpuset audit started for $tag (PID $H2H_CPUSET_AUDIT_PID)"
    wait_for 10 test -s "$ready_file" \
        || die "D348 audit did not find a clean preflight for $tag"
    log "cpuset audit preflight is clean for $tag; measured scopes may start"
}

h2h_cpu_audit_stop() {
    local pid=${H2H_CPUSET_AUDIT_PID:-}
    local status=0
    [[ -n $pid ]] || return 0
    kill -TERM "$pid" 2>/dev/null || true
    if wait "$pid" 2>/dev/null; then
        status=0
    else
        status=$?
    fi
    unset H2H_CPUSET_AUDIT_PID
    if ((status == 0)) && [[ ${H2H_CPUSET_AUDIT_REQUIRE_CLEAN:-0} == 1 ]]; then
        if ! python3 -I - "${H2H_CPUSET_AUDIT_SUMMARY:-}" <<'PY'
import json
import sys
from pathlib import Path

summary_path = Path(sys.argv[1])
if not summary_path.is_file():
    raise SystemExit(f"missing cpuset audit summary: {summary_path}")
summary = json.loads(summary_path.read_text())
if not summary.get("clean") or summary.get("samples", 0) < 1:
    raise SystemExit(f"cpuset audit failed its cleanliness check: {summary}")
PY
        then
            status=1
        fi
    fi
    unset H2H_CPUSET_AUDIT_SUMMARY
    return "$status"
}

# --- namespaces ---------------------------------------------------------------
netns_add() {
    ip netns add "$1"
    register_netns "$1"
    ip -n "$1" link set lo up
}

# Run a command inside a network namespace with the CPU pair assigned to that side.
in_ns() {
    local ns=$1; shift
    if [[ ${H2H_CPUSET_PIN:-0} == 1 ]]; then
        h2h_scope_run "$(h2h_cpu_mask_for_ns "$ns")" ip netns exec "$ns" "$@"
    else
        ip netns exec "$ns" "$@"
    fi
}

# Start a longer-lived command inside a network namespace and return its PID.
spawn_in_ns() {
    local outvar=$1 ns=$2; shift 2
    h2h_scope_spawn "$outvar" "$(h2h_cpu_mask_for_ns "$ns")" ip netns exec "$ns" "$@"
}

# ns_holder <var> <ns>: a long-lived process inside a namespace, so namespace
# entry by PID works after a sandbox hides /run/netns. Sets <var> to its PID
# (no command substitution: that would wait for the process's stdout).
ns_holder() {
    spawn_in_ns "$1" "$2" sleep infinity
}

# netem on one interface: netem_set <ns> <dev> <args...>; limit sized for
# multi-gigabit flows at 100 ms+ so the qdisc is never the bottleneck.
netem_set() {
    local ns=$1 dev=$2; shift 2
    ip -n "$ns" link set dev "$dev" txqueuelen 10000
    tc -n "$ns" qdisc replace dev "$dev" root netem limit 200000 "$@"
}
netem_clear() { tc -n "$1" qdisc del dev "$2" root 2>/dev/null || true; }

# --- sandbox --------------------------------------------------------------------
# sandboxed <ns-pid> <cmd...>: run in the namespace's network stack, in a
# private mount namespace with throwaway overlays on /etc and /var, a fresh
# /run (no D-Bus, no host resolver control socket) and /sys of that netns.
sandboxed() {
    local nspid=$1; shift
    local sb cpus
    sb=$(mktemp -d "$H2H_RUN/sb.XXXXXX")
    cpus=$(h2h_cpu_mask_for_pid "$nspid")
    local -a command=(nsenter -t "$nspid" -n unshare --mount --propagation private -- /bin/sh -c '
        set -e
        sb=$1; shift
        for d in etc var; do
            mkdir -p "$sb/$d.u" "$sb/$d.w"
            mount -t overlay overlay -o "lowerdir=/$d,upperdir=$sb/$d.u,workdir=$sb/$d.w" "/$d"
        done
        mount -t tmpfs -o mode=0755 tmpfs /run
        mkdir -p /run/lock /run/sshd /run/user
        mount -t sysfs sysfs /sys 2>/dev/null || true
        exec "$@"
    ' sandbox "$sb" "$@")
    if [[ ${H2H_CPUSET_PIN:-0} == 1 ]]; then
        h2h_scope_run "$cpus" "${command[@]}"
    else
        exec "${command[@]}"
    fi
}

# Start a sandboxed daemon in the side scope and return its network-namespace PID.
spawn_sandboxed() {
    local outvar=$1 nspid=$2; shift 2
    local sb cpus
    sb=$(mktemp -d "$H2H_RUN/sb.XXXXXX")
    cpus=$(h2h_cpu_mask_for_pid "$nspid")
    local -a command=(nsenter -t "$nspid" -n unshare --mount --propagation private -- /bin/sh -c '
        set -e
        sb=$1; shift
        for d in etc var; do
            mkdir -p "$sb/$d.u" "$sb/$d.w"
            mount -t overlay overlay -o "lowerdir=/$d,upperdir=$sb/$d.u,workdir=$sb/$d.w" "/$d"
        done
        mount -t tmpfs -o mode=0755 tmpfs /run
        mkdir -p /run/lock /run/sshd /run/user
        mount -t sysfs sysfs /sys 2>/dev/null || true
        exec "$@"
    ' sandbox "$sb" "$@")
    h2h_scope_spawn "$outvar" "$cpus" "${command[@]}"
}

# --- accounts -----------------------------------------------------------------
# Terminal sessions run as one unprivileged person: the user who invoked sudo,
# else root. tmux, Zellij and infraternal all start that account's login shell.
h2h_user() { echo "${H2H_USER:-${SUDO_USER:-root}}"; }
# ns_user <ns> <cmd…>: run as that person inside a namespace, with a clean
# login-like environment (the shell from the account, nothing inherited).
ns_user() {
    local ns=$1; shift
    local user home shell
    user=$(h2h_user)
    home=$(getent passwd "$user" | cut -d: -f6)
    shell=$(getent passwd "$user" | cut -d: -f7)
    local -a command=(ip netns exec "$ns" setpriv --reuid="$user" --regid="$(id -g "$user")" --init-groups \
        env -i HOME="$home" USER="$user" LOGNAME="$user" SHELL="$shell" \
        PATH=/usr/local/bin:/usr/bin:/bin TERM=xterm-256color LANG="${LANG:-C.UTF-8}" "$@")
    if [[ ${H2H_CPUSET_PIN:-0} == 1 ]]; then
        h2h_scope_run "$(h2h_cpu_mask_for_ns "$ns")" "${command[@]}"
    else
        "${command[@]}"
    fi
}

# Start an account-owned namespace command in a side scope and return its PID.
spawn_ns_user() {
    local outvar=$1 ns=$2; shift 2
    local user home shell
    user=$(h2h_user)
    home=$(getent passwd "$user" | cut -d: -f6)
    shell=$(getent passwd "$user" | cut -d: -f7)
    h2h_scope_spawn "$outvar" "$(h2h_cpu_mask_for_ns "$ns")" \
        ip netns exec "$ns" setpriv --reuid="$user" --regid="$(id -g "$user")" --init-groups \
        env -i HOME="$home" USER="$user" LOGNAME="$user" SHELL="$shell" \
        PATH=/usr/local/bin:/usr/bin:/bin TERM=xterm-256color LANG="${LANG:-C.UTF-8}" "$@"
}

# --- results --------------------------------------------------------------------
# measure <name> <cmd...>: run a measurement, keep its JSON under the case's
# results directory, and echo it to the log.
measure() {
    local name=$1; shift
    local out="$H2H_RESULTS/$H2H_CASE/$name.json"
    mkdir -p "$(dirname "$out")"
    if "$@" > "$out.tmp" 2> "$out.err"; then
        mv "$out.tmp" "$out"
        rm -f "$out.err"
        log "$name: $(head -c 400 "$out")"
    else
        log "$name failed: $(tail -c 400 "$out.err")"
        mv "$out.tmp" "$out.failed" 2>/dev/null || true
        return 1
    fi
}

# note <name> <json>: record a fact (versions, labels, path type).
note() {
    mkdir -p "$H2H_RESULTS/$H2H_CASE"
    printf '%s\n' "$2" > "$H2H_RESULTS/$H2H_CASE/$1.json"
}

wait_for() { # wait_for <seconds> <cmd...>
    local deadline=$((SECONDS + $1)); shift
    until "$@" >/dev/null 2>&1; do
        ((SECONDS < deadline)) || return 1
        sleep 0.2
    done
}
