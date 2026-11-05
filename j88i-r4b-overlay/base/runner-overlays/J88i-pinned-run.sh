#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Execute one D348 validation, calibration, hold or soak under the shared lock.
set -euo pipefail

kit=$1
out=$2
mode=$3
label=$4
plan=$5
mkdir -p "$out"
side_a=${H2H_CPUSET_A:-1-2}
side_b=${H2H_CPUSET_B:-3-4}
housekeeping=${H2H_CPUSET_HOUSEKEEPING:-0,5}
perf_cpus=${H2H_CPUSET_PERF:-1-4}
[[ $(id -u) == 0 ]] || { echo 'D348 host placement must run as root' >&2; exit 2; }

topology=$(lscpu --parse=CPU,CORE,SOCKET | awk -F, '!/^#/ {print}')
cpu_list=$(printf '%s\n' "$topology" | awk -F, '{print $1}' | paste -sd, -)
core_count=$(printf '%s\n' "$topology" | awk -F, '{print $2 "/" $3}' | sort -u | awk 'END {print NR}')
[[ $(nproc --all) == 6 && $cpu_list == 0,1,2,3,4,5 && $core_count == 6 ]] || {
    echo "unexpected post-resize topology: nproc=$(nproc --all) CPUs=$cpu_list cores=$core_count" >&2
    exit 2
}
[[ $side_a == 1-2 && $side_b == 3-4 && $housekeeping == 0,5 && $perf_cpus == 1-4 ]] || {
    echo "unexpected D348 masks: A=$side_a B=$side_b housekeeping=$housekeeping perf=$perf_cpus" >&2
    exit 2
}

effective_cpus() {
    local unit=$1 group
    group=$(systemctl show "$unit" -p ControlGroup --value)
    if [[ -n $group && -r "/sys/fs/cgroup$group/cpuset.cpus.effective" ]]; then
        cat "/sys/fs/cgroup$group/cpuset.cpus.effective"
    else
        systemctl show "$unit" -p EffectiveCPUs --value
    fi
}

units=(init.scope system.slice user.slice perf.slice)
declare -A old_allowed old_effective old_dropins old_irq_affinity
for unit in "${units[@]}"; do
    old_allowed[$unit]=$(systemctl show "$unit" -p AllowedCPUs --value)
    old_effective[$unit]=$(effective_cpus "$unit")
    old_dropins[$unit]=$(systemctl show "$unit" -p DropInPaths --value)
    [[ -z ${old_dropins[$unit]} ]] || {
        echo "refusing to alter $unit with existing drop-ins: ${old_dropins[$unit]}" >&2
        exit 2
    }
done
old_cpus=$(systemctl show perf.slice -p AllowedCPUs --value)
old_perf_effective=$(cat /sys/fs/cgroup/perf.slice/cpuset.cpus.effective)
[[ $old_cpus == 1-3 && $old_perf_effective == 1-3 ]] || {
    echo "unexpected perf.slice baseline: AllowedCPUs=$old_cpus effective=$old_perf_effective" >&2
    exit 2
}

host_net_irqs=()
declare -A irq_seen
for netdev in /sys/class/net/*; do
    [[ -e "$netdev/device/driver" ]] || continue
    driver=$(basename "$(readlink -f "$netdev/device/driver")")
    [[ $driver == virtio_net ]] || continue
    device=$(basename "$(readlink -f "$netdev/device")")
    while read -r irq; do
        [[ -n $irq && -z ${irq_seen[$irq]+x} ]] || continue
        affinity_file="/proc/irq/$irq/smp_affinity_list"
        [[ -r $affinity_file && -w $affinity_file ]] || {
            echo "cannot read and pin $netdev IRQ $irq" >&2
            exit 2
        }
        irq_seen[$irq]=1
        host_net_irqs+=("$irq")
        old_irq_affinity[$irq]=$(cat "$affinity_file")
    done < <(awk -v prefix="$device-" '$1 ~ /^[0-9]+:/ && index($0, prefix) {gsub(":", "", $1); print $1}' /proc/interrupts)
done

restored=0
restore() {
    ((restored == 0)) || return 0
    local rc=0 allowed effective paths attempt irq unit
    for irq in "${host_net_irqs[@]}"; do
        printf '%s\n' "${old_irq_affinity[$irq]}" > "/proc/irq/$irq/smp_affinity_list" || rc=1
    done
    for unit in "${units[@]}"; do
        systemctl revert "$unit" >/dev/null || rc=1
    done
    for attempt in {1..50}; do
        rc=0
        for unit in "${units[@]}"; do
            allowed=$(systemctl show "$unit" -p AllowedCPUs --value)
            effective=$(effective_cpus "$unit")
            paths=$(systemctl show "$unit" -p DropInPaths --value)
            [[ $allowed == "${old_allowed[$unit]}" && $effective == "${old_effective[$unit]}" && \
               $paths == "${old_dropins[$unit]}" ]] || rc=1
        done
        for irq in "${host_net_irqs[@]}"; do
            [[ $(cat "/proc/irq/$irq/smp_affinity_list") == "${old_irq_affinity[$irq]}" ]] || rc=1
        done
        effective=$(cat /sys/fs/cgroup/perf.slice/cpuset.cpus.effective)
        [[ $effective == 1-3 ]] || rc=1
        if ((rc == 0)); then
            restored=1
            {
                echo "restored at $(date -Is)"
                for unit in "${units[@]}"; do
                    printf '%s allowed=%s effective=%s dropins=%s\n' "$unit" \
                        "$(systemctl show "$unit" -p AllowedCPUs --value)" \
                        "$(effective_cpus "$unit")" \
                        "$(systemctl show "$unit" -p DropInPaths --value)"
                done
                for irq in "${host_net_irqs[@]}"; do
                    printf 'host_network_irq_%s_affinity=%s\n' "$irq" "$(cat "/proc/irq/$irq/smp_affinity_list")"
                done
            } > "$out/host-layout-restored.txt"
            echo "host service slices and IRQ affinities restored; perf.slice AllowedCPUs=$old_cpus effective=$effective"
            return 0
        fi
        sleep 0.1
    done
    echo "host placement restore failed: AllowedCPUs=$allowed DropInPaths=$paths perf.slice effective=$effective" >&2
    return 1
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

for unit in init.scope system.slice user.slice; do
    systemctl set-property --runtime "$unit" "AllowedCPUs=$housekeeping" >/dev/null
done
systemctl set-property --runtime perf.slice "AllowedCPUs=$perf_cpus" >/dev/null
for unit in init.scope system.slice user.slice; do
    [[ $(systemctl show "$unit" -p AllowedCPUs --value) == "$housekeeping" && \
       $(effective_cpus "$unit") == "$housekeeping" ]] || {
        echo "$unit did not inherit housekeeping CPUs $housekeeping" >&2
        exit 2
    }
done
[[ $(systemctl show perf.slice -p AllowedCPUs --value) == "$perf_cpus" && \
   $(cat /sys/fs/cgroup/perf.slice/cpuset.cpus.effective) == "$perf_cpus" ]] || {
    echo "perf.slice did not accept test CPUs $perf_cpus" >&2
    exit 2
}
for irq in "${host_net_irqs[@]}"; do
    printf '%s\n' "$housekeeping" > "/proc/irq/$irq/smp_affinity_list"
    [[ $(cat "/proc/irq/$irq/smp_affinity_list") == "$housekeeping" ]] || {
        echo "host network IRQ $irq did not move to housekeeping CPUs $housekeeping" >&2
        exit 2
    }
done
[[ $(awk '/^Cpus_allowed_list:/ {print $2}' /proc/self/status) == "$perf_cpus" ]] || {
    echo "perf-run scope did not inherit CPUs $perf_cpus after widening" >&2
    exit 2
}
runner_cpus_allowed=$(awk '/^Cpus_allowed:/ {print $2}' /proc/self/status)
runner_allowed=$(awk '/^Cpus_allowed_list:/ {print $2}' /proc/self/status)
{
    echo "topology: nproc_all=$(nproc --all)"
    printf 'CPU,CORE,SOCKET\n%s\n' "$topology"
    printf 'side_a=%s\nside_b=%s\nhousekeeping=%s\n' "$side_a" "$side_b" "$housekeeping"
    printf 'perf_slice_allowed=%s\nperf_slice_effective=%s\n' \
        "$(systemctl show perf.slice -p AllowedCPUs --value)" \
        "$(cat /sys/fs/cgroup/perf.slice/cpuset.cpus.effective)"
    printf 'runner_cpus_allowed=%s\nrunner_allowed=%s\n' "$runner_cpus_allowed" "$runner_allowed"
    for unit in init.scope system.slice user.slice netbird.service tailscaled.service containerd.service docker.service systemd-journald.service; do
        state=$(systemctl show "$unit" -p ActiveState --value)
        allowed=$(systemctl show "$unit" -p AllowedCPUs --value)
        effective=$(effective_cpus "$unit")
        printf 'unit=%s state=%s allowed=%s effective=%s\n' "$unit" "$state" "$allowed" "$effective"
        if [[ $unit == *.service && $state == active ]]; then
            [[ $effective == "$housekeeping" ]] || {
                echo "$unit is not confined to housekeeping CPUs $housekeeping" >&2
                exit 2
            }
        fi
    done
    for irq in "${host_net_irqs[@]}"; do
        printf 'host_network_irq_%s_affinity=%s\n' "$irq" "$(cat "/proc/irq/$irq/smp_affinity_list")"
    done
} > "$out/cpuset-preflight.txt"
cp "$out/cpuset-preflight.txt" "$out/host-layout-pinned.txt"

export H2H_CPUSET_PIN=1
export H2H_CPUSET_A="$side_a"
export H2H_CPUSET_B="$side_b"
export H2H_CPUSET_HOUSEKEEPING="$housekeeping"
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
    row_label="perf VM $(hostname), $(uname -m); D348 A=$side_a B=$side_b housekeeping=$housekeeping; $mode $label; row $tag=$engine"
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
