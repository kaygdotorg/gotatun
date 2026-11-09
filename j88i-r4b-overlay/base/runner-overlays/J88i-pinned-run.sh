#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Execute one D348 validation, calibration, matrix row, hold or soak under the shared lock.
set -euo pipefail

kit=$1
out=$2
mode=$3
label=$4
plan=$5
mkdir -p "$out"
source "$(dirname -- "${BASH_SOURCE[0]}")/J88i-cpuset-state.sh"
side_a=${H2H_CPUSET_A:-1-2}
side_b=${H2H_CPUSET_B:-3-4}
housekeeping=${H2H_CPUSET_HOUSEKEEPING:-0,5}
perf_cpus=${H2H_CPUSET_PERF:-0-5}
[[ $(id -u) == 0 ]] || { echo 'D348 host placement must run as root' >&2; exit 2; }

topology=$(lscpu --parse=CPU,CORE,SOCKET | awk -F, '!/^#/ {print}')
cpu_list=$(printf '%s\n' "$topology" | awk -F, '{print $1}' | paste -sd, -)
guest_core_count=$(printf '%s\n' "$topology" | awk -F, '{print $2 "/" $3}' | sort -u | awk 'END {print NR}')
[[ $(nproc --all) == 6 && $cpu_list == 0,1,2,3,4,5 && $guest_core_count == 6 ]] || {
    echo "unexpected six-vCPU guest topology: nproc=$(nproc --all) CPUs=$cpu_list virtual_cores=$guest_core_count" >&2
    exit 2
}
[[ $side_a == 1-2 && $side_b == 3-4 && $housekeeping == 0,5 && $perf_cpus == 0-5 ]] || {
    echo "unexpected D348 masks: A=$side_a B=$side_b housekeeping=$housekeeping perf=$perf_cpus" >&2
    exit 2
}

# Resolve a systemd unit to its cgroup v2 directory so CPU masks come from
# the kernel's live state rather than systemd's presentation format.
unit_cgroup() {
    local unit=$1 group
    group=$(systemctl show "$unit" -p ControlGroup --value)
    [[ $group == /* ]] || { echo "$unit has no cgroup path" >&2; return 2; }
    printf '/sys/fs/cgroup%s\n' "$group"
}

# Read one live cpuset file; missing cgroup state is an error, never a fallback.
unit_cpus() {
    local unit=$1 file=$2 group
    group=$(unit_cgroup "$unit") || return
    [[ -r "$group/$file" ]] || { echo "$unit cgroup lacks $file" >&2; return 2; }
    cat "$group/$file"
}

units=(init.scope system.slice user.slice perf.slice)
declare -A old_cpuset old_effective old_dropins old_allowed old_restore_mode old_irq_affinity
for unit in "${units[@]}"; do
    old_cpuset[$unit]=$(unit_cpus "$unit" cpuset.cpus)
    old_effective[$unit]=$(unit_cpus "$unit" cpuset.cpus.effective)
    old_dropins[$unit]=$(systemctl show "$unit" -p DropInPaths --value)
    old_allowed[$unit]=$(systemctl show "$unit" -p AllowedCPUs --value)
    old_restore_mode[$unit]=$(cpuset_restore_mode "$unit" "${old_dropins[$unit]}" "${old_allowed[$unit]}") || {
        echo "refusing to alter $unit with existing drop-ins: ${old_dropins[$unit]}" >&2
        exit 2
    }
done
old_cpus=${old_cpuset[perf.slice]}
old_perf_effective=${old_effective[perf.slice]}
[[ $old_cpus == 1-3 && $old_perf_effective == 1-3 && ${old_allowed[perf.slice]} == 1-3 ]] || {
    echo "unexpected perf.slice baseline: cpuset.cpus=$old_cpus cpuset.cpus.effective=$old_perf_effective AllowedCPUs=${old_allowed[perf.slice]}" >&2
    exit 2
}

for unit in init.scope system.slice user.slice; do
    baseline_cpus=${old_cpuset[$unit]}
    baseline_effective=${old_effective[$unit]}
    [[ $baseline_effective == 0-5 && ( -z $baseline_cpus || $baseline_cpus == 0-5 ) ]] || {
        echo "$unit must inherit or be configured for 0-5 before D348, got cpuset.cpus=$baseline_cpus effective=$baseline_effective" >&2
        exit 2
    }
done

# Encode empty TSV fields because Bash treats tab separators as whitespace and
# collapses adjacent separators while reading the restore manifest.
manifest_field() {
    [[ -n $1 ]] && printf '%s' "$1" || printf '%s' '__EMPTY__'
}

# Keep a machine-readable baseline so the second perf-run scope can verify
# real cgroup files after this scope has gone away.
: > "$out/cgroup-masks-before.tsv"
for unit in "${units[@]}"; do
    group=$(unit_cgroup "$unit")
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$unit" "${group#/sys/fs/cgroup}" \
        "$(manifest_field "${old_cpuset[$unit]}")" "$(manifest_field "${old_effective[$unit]}")" \
        "$(manifest_field "${old_dropins[$unit]}")" "$(manifest_field "${old_allowed[$unit]}")" \
        >> "$out/cgroup-masks-before.tsv"
done

# The global and per-workqueue cpumasks all start from their own exact values.
# Pinning them together keeps unbound kernel work off the measured CPUs.
workqueue_mask_files=(/sys/devices/virtual/workqueue/cpumask)
for path in /sys/devices/virtual/workqueue/*/cpumask; do
    [[ -f $path ]] && workqueue_mask_files+=("$path")
done
declare -A old_workqueue_mask
: > "$out/workqueue-masks-before.tsv"
for path in "${workqueue_mask_files[@]}"; do
    [[ -r $path && -w $path ]] || { echo "cannot read and set workqueue cpumask $path" >&2; exit 2; }
    old_workqueue_mask[$path]=$(cat "$path")
    printf '%s\t%s\n' "$path" "${old_workqueue_mask[$path]}" >> "$out/workqueue-masks-before.tsv"
done

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

: > "$out/irq-affinity-before.tsv"
for irq in "${host_net_irqs[@]}"; do
    printf '%s\t%s\n' "$irq" "${old_irq_affinity[$irq]}" >> "$out/irq-affinity-before.tsv"
done

restored=0
# Restore saved cgroup masks and IRQ affinities, then verify the real state.
restore() {
    ((restored == 0)) || return 0
    local rc=0 command_rc=0 cpus effective paths allowed attempt irq unit path
    for path in "${workqueue_mask_files[@]}"; do
        printf '%s\n' "${old_workqueue_mask[$path]}" > "$path" || command_rc=1
    done
    for irq in "${host_net_irqs[@]}"; do
        printf '%s\n' "${old_irq_affinity[$irq]}" > "/proc/irq/$irq/smp_affinity_list" || command_rc=1
    done
    # Restore existing units in place; revert only the temporary drop-ins this
    # run added, never the perf.slice resource limits already owned by the host.
    for unit in "${units[@]}"; do
        if [[ ${old_restore_mode[$unit]} == preserve-existing-dropins ]]; then
            systemctl set-property --runtime "$unit" "AllowedCPUs=${old_allowed[$unit]}" >/dev/null || command_rc=1
        else
            systemctl set-property --runtime "$unit" "AllowedCPUs=${old_effective[$unit]}" >/dev/null || command_rc=1
            systemctl revert "$unit" >/dev/null || command_rc=1
        fi
    done
    for attempt in {1..50}; do
        rc=0
        for unit in "${units[@]}"; do
            cpus=$(unit_cpus "$unit" cpuset.cpus) || rc=1
            effective=$(unit_cpus "$unit" cpuset.cpus.effective) || rc=1
            paths=$(systemctl show "$unit" -p DropInPaths --value)
            allowed=$(systemctl show "$unit" -p AllowedCPUs --value)
            cpuset_state_matches "$cpus" "${old_cpuset[$unit]}" \
                "$effective" "${old_effective[$unit]}" || rc=1
            [[ $paths == "${old_dropins[$unit]}" ]] || rc=1
            [[ $allowed == "${old_allowed[$unit]}" ]] || rc=1
        done
        for irq in "${host_net_irqs[@]}"; do
            [[ $(cat "/proc/irq/$irq/smp_affinity_list") == "${old_irq_affinity[$irq]}" ]] || rc=1
        done
        for path in "${workqueue_mask_files[@]}"; do
            [[ $(cat "$path") == "${old_workqueue_mask[$path]}" ]] || rc=1
        done
        cpus=$(unit_cpus perf.slice cpuset.cpus) || rc=1
        effective=$(unit_cpus perf.slice cpuset.cpus.effective) || rc=1
        [[ $cpus == "$old_cpus" && $effective == "$old_perf_effective" ]] || rc=1
        if ((rc == 0 && command_rc == 0)); then
            restored=1
            {
                echo "restored at $(date -Is)"
                for unit in "${units[@]}"; do
                    printf '%s cpuset.cpus=%s cpuset.cpus.effective=%s dropins=%s AllowedCPUs=%s\n' "$unit" \
                        "$(unit_cpus "$unit" cpuset.cpus)" \
                        "$(unit_cpus "$unit" cpuset.cpus.effective)" \
                        "$(systemctl show "$unit" -p DropInPaths --value)" \
                        "$(systemctl show "$unit" -p AllowedCPUs --value)"
                done
                for irq in "${host_net_irqs[@]}"; do
                    printf 'host_network_irq_%s_affinity=%s\n' "$irq" "$(cat "/proc/irq/$irq/smp_affinity_list")"
                done
                for path in "${workqueue_mask_files[@]}"; do
                    printf 'workqueue_cpumask_%s=%s\n' "${path##*/}" "$(cat "$path")"
                done
            } > "$out/host-layout-restored.txt"
            echo "host service slices, IRQ affinities, and workqueue masks restored; perf.slice cpuset.cpus=$cpus cpuset.cpus.effective=$effective"
            return 0
        fi
        sleep 0.1
    done
    echo "host placement restore failed: command_status=$command_rc cpuset.cpus=$cpus DropInPaths=$paths perf.slice cpuset.cpus.effective=$effective" >&2
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

for path in "${workqueue_mask_files[@]}"; do
    printf '21\n' > "$path"
    [[ $(cat "$path") == 21 ]] || {
        echo "workqueue cpumask did not pin to housekeeping CPUs $housekeeping: $path=$(cat "$path")" >&2
        exit 2
    }
done

for unit in init.scope system.slice user.slice; do
    systemctl set-property --runtime "$unit" "AllowedCPUs=$housekeeping" >/dev/null
done
systemctl set-property --runtime perf.slice "AllowedCPUs=$perf_cpus" >/dev/null
for unit in init.scope system.slice user.slice; do
    [[ $(unit_cpus "$unit" cpuset.cpus) == "$housekeeping" && \
       $(unit_cpus "$unit" cpuset.cpus.effective) == "$housekeeping" ]] || {
        echo "$unit did not inherit housekeeping CPUs $housekeeping" >&2
        exit 2
    }
done
[[ $(unit_cpus perf.slice cpuset.cpus) == "$perf_cpus" && \
   $(unit_cpus perf.slice cpuset.cpus.effective) == "$perf_cpus" ]] || {
    echo "perf.slice did not accept test CPUs $perf_cpus" >&2
    exit 2
}
taskset -pc "$housekeeping" "$$" >/dev/null
[[ $(awk '/^Cpus_allowed_list:/ {print $2}' /proc/self/status) == "$housekeeping" ]] || {
    echo "D348 coordinator was not pinned to housekeeping CPUs $housekeeping" >&2
    exit 2
}
for irq in "${host_net_irqs[@]}"; do
    printf '%s\n' "$housekeeping" > "/proc/irq/$irq/smp_affinity_list"
    [[ $(cat "/proc/irq/$irq/smp_affinity_list") == "$housekeeping" ]] || {
        echo "host network IRQ $irq did not move to housekeeping CPUs $housekeeping" >&2
        exit 2
    }
done
[[ $(awk '/^Cpus_allowed_list:/ {print $2}' /proc/self/status) == "$housekeeping" ]] || {
    echo "D348 coordinator affinity is not restricted to housekeeping CPUs $housekeeping" >&2
    exit 2
}
runner_cpus_allowed=$(awk '/^Cpus_allowed:/ {print $2}' /proc/self/status)
runner_allowed=$(awk '/^Cpus_allowed_list:/ {print $2}' /proc/self/status)
{
    echo "topology: nproc_all=$(nproc --all)"
    printf 'CPU,CORE,SOCKET\n%s\n' "$topology"
    echo 'host_physical_mapping: vCPU0=host-thread7/core7;vCPU1=host-thread5/core5;vCPU2=host-thread13/core5;vCPU3=host-thread6/core6;vCPU4=host-thread14/core6;vCPU5=host-thread15/core7'
    printf 'side_a=%s\nside_b=%s\nhousekeeping=%s\n' "$side_a" "$side_b" "$housekeeping"
    printf 'perf_slice_cpuset=%s\nperf_slice_effective=%s\n' \
        "$(unit_cpus perf.slice cpuset.cpus)" \
        "$(unit_cpus perf.slice cpuset.cpus.effective)"
    printf 'runner_cpus_allowed=%s\nrunner_allowed=%s\n' "$runner_cpus_allowed" "$runner_allowed"
    for unit in init.scope system.slice user.slice netbird.service tailscaled.service containerd.service docker.service systemd-journald.service; do
        state=$(systemctl show "$unit" -p ActiveState --value)
        property=$(systemctl show "$unit" -p AllowedCPUs --value)
        cpus=""
        effective=""
        if [[ $state == active ]]; then
            cpus=$(unit_cpus "$unit" cpuset.cpus)
            effective=$(unit_cpus "$unit" cpuset.cpus.effective)
        fi
        printf 'unit=%s state=%s AllowedCPUs_property=%s cpuset.cpus=%s cpuset.cpus.effective=%s\n' \
            "$unit" "$state" "$property" "$cpus" "$effective"
        if [[ $unit == *.service && $state == active ]]; then
            # Service cpuset.cpus may be empty because it inherits system.slice.
            [[ $effective == "$housekeeping" ]] || {
                echo "$unit is not confined to housekeeping CPUs $housekeeping" >&2
                exit 2
            }
        fi
    done
    for irq in "${host_net_irqs[@]}"; do
        printf 'host_network_irq_%s_affinity=%s\n' "$irq" "$(cat "/proc/irq/$irq/smp_affinity_list")"
    done
    for path in "${workqueue_mask_files[@]}"; do
        printf 'workqueue_cpumask_%s=%s\n' "${path##*/}" "$(cat "$path")"
    done
} > "$out/cpuset-preflight.txt"
cp "$out/cpuset-preflight.txt" "$out/host-layout-pinned.txt"

export H2H_CPUSET_PIN=1
export H2H_CPUSET_A="$side_a"
export H2H_CPUSET_B="$side_b"
export H2H_CPUSET_HOUSEKEEPING="$housekeeping"
export H2H_CPUSET_PERF="$perf_cpus"
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
        kernel-plain) case_name=mesh-kernel-plain ;;
        wireguard-go) case_name=mesh-wireguard-go ;;
        underlay) case_name=mesh-underlay ;;
        *) echo "unknown engine $engine for $tag" >&2; return 2 ;;
    esac
    row_dir="$out/$tag"
    row_label="perf VM $(hostname), $(uname -m); D348 A=$side_a B=$side_b housekeeping=$housekeeping; $mode $label; row $tag=$engine"
    mkdir -p "$row_dir"
    local -a args=(--only "$case_name" --label "$row_label")
    [[ $smoke == 1 ]] && args+=(--smoke)
    if [[ $mode == soak ]]; then
        taskset -c "$housekeeping" env H2H_RESULTS="$row_dir" H2H_GOTATUN_BIN="$binary" H2H_GOTATUN_SOURCE="$source_sha" \
            H2H_SOAK_SECONDS=3600 bash "$kit/run.sh" "${args[@]}"
    else
        taskset -c "$housekeeping" env H2H_RESULTS="$row_dir" H2H_GOTATUN_BIN="$binary" H2H_GOTATUN_SOURCE="$source_sha" \
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
        # The overlay is installed into the harness root, beside its smoke helper.
        bash "$kit/cpuset-harness-smoke.sh" "$kit" "$smoke_dir"
        run_row validate-underlay underlay "" "" 1
        run_row validate-kernel kernel "" "" 1
        run_row validate-kernel-plain kernel-plain "" "" 1
        printf 'cpuset masks, runnable-task audit, veth/namespace counters, NetBird kernel smoke, and direct MTU-1420 kernel WireGuard smoke completed\n' \
            > "$out/validation.txt"
        ;;
    smoke)
        run_plan 1
        ;;
    calibration|hold)
        run_plan 0
        ;;
    matrix)
        run_plan 0
        ;;
    soak)
        run_plan 0
        ;;
    *) echo "unknown mode $mode" >&2; exit 2 ;;
esac
