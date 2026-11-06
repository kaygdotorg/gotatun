#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Verify restored host cgroups, workqueues and IRQ affinities after perf-run exits.
set -euo pipefail

output=$1
cgroup_manifest=${2:-}
workqueue_manifest=${3:-}
irq_manifest=${4:-}
cgroup_root=${J88I_CGROUP_ROOT:-/sys/fs/cgroup}
results=()
failed=0

# Decode the manifest marker used for empty cpuset and DropInPaths values.
manifest_value() {
    [[ $1 == '__EMPTY__' ]] && printf '' || printf '%s' "$1"
}

if [[ -n $cgroup_manifest ]]; then
    [[ -r $cgroup_manifest ]] || { echo "missing cgroup baseline manifest: $cgroup_manifest" >&2; exit 2; }
    while IFS=$'\t' read -r unit group expected_cpus expected_effective expected_dropins; do
        [[ -n $unit ]] || continue
        expected_cpus=$(manifest_value "$expected_cpus")
        expected_effective=$(manifest_value "$expected_effective")
        expected_dropins=$(manifest_value "$expected_dropins")
        cgroup="$cgroup_root$group"
        cpus=$(cat "$cgroup/cpuset.cpus")
        effective=$(cat "$cgroup/cpuset.cpus.effective")
        actual_group=$(systemctl show "$unit" -p ControlGroup --value)
        dropins=$(systemctl show "$unit" -p DropInPaths --value)
        if [[ $actual_group != "$group" || $cpus != "$expected_cpus" || \
              $effective != "$expected_effective" || $dropins != "$expected_dropins" ]]; then
            printf '%s restoration failed: cgroup=%s expected=%s cpuset.cpus=%s expected=%s cpuset.cpus.effective=%s expected=%s DropInPaths=%s expected=%s\n' \
                "$unit" "$actual_group" "$group" "$cpus" "$expected_cpus" \
                "$effective" "$expected_effective" "$dropins" "$expected_dropins" >&2
            failed=1
        fi
        allowed=$(systemctl show "$unit" -p AllowedCPUs --value)
        systemd_effective=$(systemctl show "$unit" -p EffectiveCPUs --value)
        results+=("$unit restored: cpuset.cpus=$cpus cpuset.cpus.effective=$effective DropInPaths=$dropins (AllowedCPUs=$allowed EffectiveCPUs=$systemd_effective informational)")
    done < "$cgroup_manifest"
else
    # Keep a safe read-only check for an early failure before the overlay could
    # write its full baseline manifest.
    slice_cgroup=${J88I_PERF_SLICE_CGROUP:-/sys/fs/cgroup/perf.slice}
    expected=${J88I_EXPECTED_PERF_CPUS:-1-3}
    allowed=$(systemctl show perf.slice -p AllowedCPUs --value)
    systemd_effective=$(systemctl show perf.slice -p EffectiveCPUs --value)
    dropins=$(systemctl show perf.slice -p DropInPaths --value)
    cpus=$(cat "$slice_cgroup/cpuset.cpus")
    effective=$(cat "$slice_cgroup/cpuset.cpus.effective")
    if [[ $cpus != "$expected" || $effective != "$expected" || -n $dropins ]]; then
        printf 'perf.slice restoration failed: cpuset.cpus=%s expected=%s cpuset.cpus.effective=%s expected=%s DropInPaths=%s (AllowedCPUs=%s EffectiveCPUs=%s informational)\n' \
            "$cpus" "$expected" "$effective" "$expected" "$dropins" "$allowed" "$systemd_effective" >&2
        failed=1
    fi
    results+=("perf.slice restored: cpuset.cpus=$cpus cpuset.cpus.effective=$effective DropInPaths=$dropins (AllowedCPUs=$allowed EffectiveCPUs=$systemd_effective informational)")
fi

if [[ -n $workqueue_manifest ]]; then
    [[ -r $workqueue_manifest ]] || { echo "missing workqueue baseline manifest: $workqueue_manifest" >&2; exit 2; }
    while IFS=$'\t' read -r path expected; do
        [[ -n $path ]] || continue
        actual=$(cat "$path")
        if [[ $actual != "$expected" ]]; then
            printf 'workqueue cpumask restore failed: %s=%s expected=%s\n' "$path" "$actual" "$expected" >&2
            failed=1
        fi
        results+=("workqueue cpumask restored: $path=$actual")
    done < "$workqueue_manifest"
fi

if [[ -n $irq_manifest ]]; then
    [[ -r $irq_manifest ]] || { echo "missing IRQ baseline manifest: $irq_manifest" >&2; exit 2; }
    while IFS=$'\t' read -r irq expected; do
        [[ -n $irq ]] || continue
        path="/proc/irq/$irq/smp_affinity_list"
        actual=$(cat "$path")
        if [[ $actual != "$expected" ]]; then
            printf 'IRQ affinity restore failed: irq=%s cpus=%s expected=%s\n' "$irq" "$actual" "$expected" >&2
            failed=1
        fi
        results+=("IRQ affinity restored: irq=$irq cpus=$actual")
    done < "$irq_manifest"
fi

if ((failed)); then
    exit 2
fi
printf '%s\n' "${results[@]}" > "$output"
cat "$output"
