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
