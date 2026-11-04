#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Execute one D348 validation, calibration, hold or soak under the shared lock.
set -euo pipefail

kit=$1
out=$2
mode=$3
label=$4
plan=$5
old_cpus=$(systemctl show perf.slice -p AllowedCPUs --value)
old_effective=$(cat /sys/fs/cgroup/perf.slice/cpuset.cpus.effective)
dropins=$(systemctl show perf.slice -p DropInPaths --value)
[[ $old_cpus == 1-3 && $old_effective == 1-3 && -z $dropins ]] || {
    echo "unexpected perf.slice baseline: AllowedCPUs=$old_cpus effective=$old_effective DropInPaths=$dropins" >&2
    exit 2
}

restored=0
restore() {
    ((restored == 0)) || return 0
    systemctl revert perf.slice >/dev/null || return 1
    local allowed effective paths
    allowed=$(systemctl show perf.slice -p AllowedCPUs --value)
    effective=$(cat /sys/fs/cgroup/perf.slice/cpuset.cpus.effective)
    paths=$(systemctl show perf.slice -p DropInPaths --value)
    if [[ $allowed != 1-3 || $effective != 1-3 || -n $paths ]]; then
        echo "perf.slice restoration failed: AllowedCPUs=$allowed effective=$effective DropInPaths=$paths" >&2
        return 1
    fi
    restored=1
    echo "perf.slice restored: AllowedCPUs=$allowed effective=$effective DropInPaths=empty"
}
finish() {
    local rc=$?
    trap - EXIT
    if ! restore; then
        ((rc != 0)) || rc=2
    fi
    exit "$rc"
}
trap finish EXIT
trap 'exit 143' TERM INT

systemctl set-property --runtime perf.slice AllowedCPUs=0-3 >/dev/null
[[ $(systemctl show perf.slice -p AllowedCPUs --value) == 0-3 ]] || {
    echo 'perf.slice did not accept runtime AllowedCPUs=0-3' >&2
    exit 2
}
[[ $(cat /sys/fs/cgroup/perf.slice/cpuset.cpus.effective) == 0-3 ]] || {
    echo 'perf.slice effective cpuset is not 0-3 after widening' >&2
    exit 2
}
[[ $(awk '/^Cpus_allowed_list:/ {print $2}' /proc/self/status) == 0-3 ]] || {
    echo 'perf-run scope did not inherit CPUs 0-3 after widening' >&2
    exit 2
}
runner_cpus_allowed=$(awk '/^Cpus_allowed:/ {print $2}' /proc/self/status)
runner_allowed=$(awk '/^Cpus_allowed_list:/ {print $2}' /proc/self/status)
printf 'side_a=0-1\nside_b=2-3\nperf_slice_allowed=0-3\nperf_slice_effective=0-3\nrunner_cpus_allowed=%s\nrunner_allowed=%s\n' \
    "$runner_cpus_allowed" "$runner_allowed" > "$out/cpuset-preflight.txt"

export H2H_CPUSET_PIN=1
export H2H_CPUSET_A=0-1
export H2H_CPUSET_B=2-3
export H2H_LOCK=external
export H2H_USER=claude
export H2H_CPUSET_AUDIT=1
export H2H_CPUSET_AUDIT_REQUIRE_CLEAN=1

run_row() {
    local tag=$1 engine=$2 binary=$3 source_sha=$4 smoke=$5
    local case_name row_dir row_label
    case $engine in
        gotatun) case_name=mesh-gotatun ;;
        kernel) case_name=mesh-netbird ;;
        underlay) case_name=mesh-underlay ;;
        *) echo "unknown engine $engine for $tag" >&2; return 2 ;;
    esac
    row_dir="$out/$tag"
    row_label="perf VM $(hostname), $(uname -m); D348 A=0-1 B=2-3, 6 GiB; $mode $label; row $tag=$engine"
    mkdir -p "$row_dir"
    local -a args=(--only "$case_name" --label "$row_label")
    [[ $smoke == 1 ]] && args+=(--smoke)
    if [[ $mode == soak ]]; then
        env H2H_RESULTS="$row_dir" H2H_GOTATUN_BIN="$binary" H2H_GOTATUN_SOURCE="$source_sha" \
            H2H_SOAK_SECONDS=3600 bash "$kit/run.sh" "${args[@]}"
    else
        env H2H_RESULTS="$row_dir" H2H_GOTATUN_BIN="$binary" H2H_GOTATUN_SOURCE="$source_sha" \
            bash "$kit/run.sh" "${args[@]}"
    fi
}

run_plan() {
    local smoke=$1 tag engine binary source_sha
    while IFS=$'\t' read -r tag engine binary source_sha; do
        [[ -n $tag ]] || continue
        echo "D348 row start: $tag engine=$engine binary=${binary:-kit-default} source=${source_sha:-unknown}"
        run_row "$tag" "$engine" "$binary" "$source_sha" "$smoke"
        echo "D348 row finish: $tag"
    done < "$plan"
}

case $mode in
    validate)
        smoke_dir="$out/cpuset-smoke"
        mkdir -p "$smoke_dir"
        bash "$kit/cpuset-harness-smoke.sh" "$kit" "$smoke_dir"
        run_row validate-underlay underlay "" "" 1
        run_row validate-kernel kernel "" "" 1
        printf 'cpuset masks, runnable-task audit, veth/namespace counters, and kernel-WireGuard smoke completed\n' \
            > "$out/validation.txt"
        ;;
    smoke)
        run_plan 1
        ;;
    calibration|hold)
        run_plan 0
        ;;
    soak)
        run_plan 0
        ;;
    *) echo "unknown mode $mode" >&2; exit 2 ;;
esac
