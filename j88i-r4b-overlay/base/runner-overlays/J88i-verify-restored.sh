#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Verify perf.slice after the enclosing perf-run scope has exited.
set -euo pipefail

output=$1
slice_cgroup=${J88I_PERF_SLICE_CGROUP:-/sys/fs/cgroup/perf.slice}
allowed=$(systemctl show perf.slice -p AllowedCPUs --value)
effective=$(systemctl show perf.slice -p EffectiveCPUs --value)
dropins=$(systemctl show perf.slice -p DropInPaths --value)
cpus=$(cat "$slice_cgroup/cpuset.cpus")
cpus_effective=$(cat "$slice_cgroup/cpuset.cpus.effective")

if [[ $cpus != 1-3 || $cpus_effective != 1-3 || -n $dropins ]]; then
    printf 'perf.slice restoration failed: AllowedCPUs=%s EffectiveCPUs=%s cpuset.cpus=%s cpuset.cpus.effective=%s DropInPaths=%s\n' \
        "$allowed" "$effective" "$cpus" "$cpus_effective" "$dropins" >&2
    exit 2
fi

printf 'perf.slice restored after scope exit: cpuset.cpus=%s cpuset.cpus.effective=%s DropInPaths=empty (AllowedCPUs=%s EffectiveCPUs=%s are informational)\n' \
    "$cpus" "$cpus_effective" "$allowed" "$effective" > "$output"
cat "$output"
