#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Shared cgroup-mask matching rule for the in-scope and post-scope verifiers.

# Accept a saved cgroup state or systemd's equivalent explicit full guest mask.
# Empty and 0-5 configured masks are equivalent only while effective CPUs stay 0-5.
cpuset_state_matches() {
    local actual_cpus=$1 expected_cpus=$2 actual_effective=$3 expected_effective=$4
    [[ $actual_effective == "$expected_effective" ]] || return 1
    [[ $actual_cpus == "$expected_cpus" ]] && return 0
    [[ $expected_effective == 0-5 && \
       ( -z $expected_cpus || $expected_cpus == 0-5 ) && \
       ( -z $actual_cpus || $actual_cpus == 0-5 ) ]]
}

# Recognize systemd's exact known perf.slice runtime drop-in set. The memory
# file is left in place while the CPU file is temporarily rewritten.
cpuset_perf_slice_dropins_are_known() {
    local paths=$1
    local cpu=/run/systemd/system.control/perf.slice.d/50-AllowedCPUs.conf
    local memory=/run/systemd/system.control/perf.slice.d/50-MemoryMax.conf
    [[ $paths == "$cpu" || $paths == "$cpu $memory" || $paths == "$memory $cpu" ]]
}

# Accept the saved effective mask after an optional systemd list reset.
cpuset_allowed_cpus_dropin_matches() {
    local path=$1 expected=$2
    [[ -r $path && -n $expected ]] || return 1
    awk -v expected="$expected" '
        /^[[:space:]]*($|#|;)/ { next }
        /^[[:space:]]*\[Slice\][[:space:]]*$/ {
            sections++
            if (sections > 1) exit 1
            in_slice = 1
            next
        }
        {
            if ($0 ~ /^[[:space:]]*\[/ || !in_slice) exit 1
            if ($0 !~ /^[[:space:]]*AllowedCPUs[[:space:]]*=/) exit 1
            value = $0
            sub(/^[[:space:]]*AllowedCPUs[[:space:]]*=/, "", value)
            sub(/^[[:space:]]+/, "", value)
            sub(/[[:space:]]+$/, "", value)
            if (value == "") {
                active = ""
                next
            }
            if (value != expected || assigned++) exit 1
            active = value
        }
        END { if (sections != 1 || active != expected || assigned != 1) exit 1 }
    ' "$path"
}

# Restore one saved systemd drop-in without reverting its unit or neighbours.
cpuset_restore_saved_dropin() {
    local saved=$1 destination=$2
    [[ -r $saved && -d $(dirname -- "$destination") ]] || return 1
    cp -a -- "$saved" "$destination"
}
