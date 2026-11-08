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

# Preserve pre-existing unit properties when removing a temporary CPU limit.
# perf.slice may have AllowedCPUs and MemoryMax control drop-ins; reverting the
# unit would delete both, so its captured AllowedCPUs value is restored in place.
cpuset_restore_mode() {
    local unit=$1 drop_ins=$2 allowed_cpus=$3
    if [[ -z $drop_ins ]]; then
        printf 'revert-generated-dropin\n'
    elif [[ $unit == perf.slice && -n $allowed_cpus ]]; then
        printf 'preserve-existing-dropins\n'
    else
        echo "cannot safely change $unit with existing drop-ins and AllowedCPUs=$allowed_cpus" >&2
        return 2
    fi
}
