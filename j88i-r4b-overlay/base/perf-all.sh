#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Run one complete pinned R4b comparison inside a single perf-run lock.
set -euo pipefail

kit=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
[[ $(id -un) == claude ]] || { echo 'run as claude on the perf VM' >&2; exit 2; }
housekeeping=${H2H_CPUSET_HOUSEKEEPING:-0,5}
taskset -pc "$housekeeping" "$$" >/dev/null
[[ $(awk '/^Cpus_allowed_list:/ {print $2}' /proc/self/status) == "$housekeeping" ]] || {
    echo "D348 perf-all coordinator is not pinned to housekeeping CPUs $housekeeping" >&2
    exit 2
}

mode=""
label=""
out=""
rows=()
declare -A binaries sources
binary_count=0
source_count=0

usage() {
    cat <<'USAGE'
usage:
  perf-all.sh --validate [--out DIR]
  perf-all.sh --smoke --row TAG=gotatun|kernel|kernel-plain|wireguard-go [--binary TAG=PATH] [--source TAG=SHA] [--out DIR]
  perf-all.sh --calibration --row control-a=gotatun --row control-b=gotatun --row control-c=gotatun [--binary TAG=PATH] [--out DIR]
  perf-all.sh --hold --label CUT --row kernel-before=kernel-plain --row wireguard-go-before=wireguard-go \
    --row control-a=gotatun --row candidate-a=gotatun --row candidate-b=gotatun \
    --row control-b=gotatun --row wireguard-go-after=wireguard-go --row kernel-after=kernel-plain \
    --binary TAG=PATH [--source TAG=SHA] [--out DIR]
  perf-all.sh --soak --label CUT --row control=gotatun --row candidate=gotatun \
    --binary TAG=PATH [--source TAG=SHA] [--out DIR]

The full hold order is fixed: direct kernel WireGuard at MTU 1420, wireguard-go, current control,
candidate twice, control, wireguard-go, kernel. All rows share one perf-run lock and distinct result dirs.
Unpinned results are historical data and must be reported separately.
USAGE
}

set_mode() {
    local requested=$1
    [[ -z $mode ]] || { echo 'choose one mode' >&2; exit 2; }
    mode=$requested
}

parse_pair() {
    local value=$1 out_name=$2 out_value=$3
    [[ $value == *=* ]] || { echo "expected NAME=VALUE, got: $value" >&2; exit 2; }
    printf -v "$out_name" '%s' "${value%%=*}"
    printf -v "$out_value" '%s' "${value#*=}"
}

while (($#)); do
    case $1 in
        --validate) set_mode validate ;;
        --smoke) set_mode smoke ;;
        --calibration) set_mode calibration ;;
        --hold) set_mode hold ;;
        --soak) set_mode soak ;;
        --label) (($# >= 2)) || { echo '--label needs a value' >&2; exit 2; }; label=$2; shift ;;
        --out) (($# >= 2)) || { echo '--out needs a value' >&2; exit 2; }; out=$2; shift ;;
        --row)
            (($# >= 2)) || { echo '--row needs a value' >&2; exit 2; }
            parse_pair "$2" tag engine
            [[ $tag =~ ^[A-Za-z0-9_.-]+$ ]] || { echo "invalid row tag: $tag" >&2; exit 2; }
            [[ $engine == gotatun || $engine == kernel || $engine == kernel-plain || $engine == wireguard-go || $engine == underlay ]] || {
                echo "invalid engine for row $tag: $engine" >&2; exit 2;
            }
            for existing in "${rows[@]}"; do
                [[ ${existing%%=*} != "$tag" ]] || { echo "duplicate row tag: $tag" >&2; exit 2; }
            done
            rows+=("$tag=$engine")
            shift
            ;;
        --binary)
            (($# >= 2)) || { echo '--binary needs a value' >&2; exit 2; }
            parse_pair "$2" tag path
            [[ $tag =~ ^[A-Za-z0-9_.-]+$ && -x $path ]] || {
                echo "binary for $tag must name an executable file" >&2; exit 2;
            }
            [[ $path != *$'\n'* && $path != *$'\t'* ]] || { echo 'binary paths cannot contain tabs or newlines' >&2; exit 2; }
            binaries[$tag]=$(readlink -f -- "$path")
            binary_count=$((binary_count + 1))
            shift
            ;;
        --source)
            (($# >= 2)) || { echo '--source needs a value' >&2; exit 2; }
            parse_pair "$2" tag source
            [[ $tag =~ ^[A-Za-z0-9_.-]+$ && $source =~ ^[0-9a-fA-F]{7,64}$ ]] || {
                echo "source for $tag must be a commit SHA" >&2; exit 2;
            }
            sources[$tag]=$source
            source_count=$((source_count + 1))
            shift
            ;;
        --help|-h) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

[[ -n $mode ]] || { usage >&2; exit 2; }
if [[ $mode == validate ]]; then
    ((${#rows[@]} == 0 && binary_count == 0 && source_count == 0)) || {
        echo '--validate does not take row, binary, or source options' >&2; exit 2;
    }
else
    ((${#rows[@]} > 0)) || { echo "$mode requires at least one --row" >&2; exit 2; }
fi

check_row() {
    local index=$1 want_tag=$2 want_engine=$3 actual_tag actual_engine
    [[ ${rows[$index]} == *=* ]] || { echo "missing row $want_tag" >&2; exit 2; }
    actual_tag=${rows[$index]%%=*}
    actual_engine=${rows[$index]#*=}
    [[ $actual_tag == "$want_tag" && $actual_engine == "$want_engine" ]] || {
        echo "row $((index + 1)) must be $want_tag=$want_engine, got $actual_tag=$actual_engine" >&2
        exit 2
    }
}

case $mode in
    validate) ;;
    smoke)
        ((${#rows[@]} == 1)) || { echo '--smoke takes exactly one row' >&2; exit 2; }
        ;;
    calibration)
        ((${#rows[@]} == 3)) || { echo '--calibration takes exactly three rows' >&2; exit 2; }
        check_row 0 control-a gotatun
        check_row 1 control-b gotatun
        check_row 2 control-c gotatun
        [[ ${binaries[control-a]:-} == "${binaries[control-b]:-}" && \
           ${binaries[control-a]:-} == "${binaries[control-c]:-}" ]] || {
            echo 'all control rows must use the same binary' >&2; exit 2;
        }
        [[ -n ${sources[control-a]:-} && ${sources[control-a]} == "${sources[control-b]:-}" && \
           ${sources[control-a]} == "${sources[control-c]:-}" ]] || {
            echo 'all control rows need the same source SHA' >&2; exit 2;
        }
        ;;
    hold)
        ((${#rows[@]} == 8)) || { echo '--hold takes exactly eight rows' >&2; exit 2; }
        check_row 0 kernel-before kernel-plain
        check_row 1 wireguard-go-before wireguard-go
        check_row 2 control-a gotatun
        check_row 3 candidate-a gotatun
        check_row 4 candidate-b gotatun
        check_row 5 control-b gotatun
        check_row 6 wireguard-go-after wireguard-go
        check_row 7 kernel-after kernel-plain
        [[ -n $label ]] || { echo '--hold requires --label CUT' >&2; exit 2; }
        [[ ${binaries[control-a]:-} == "${binaries[control-b]:-}" ]] || {
            echo 'control-a and control-b must use the same binary' >&2; exit 2;
        }
        [[ -n ${binaries[candidate-a]:-} && ${binaries[candidate-a]} == "${binaries[candidate-b]:-}" ]] || {
            echo 'candidate-a and candidate-b must use the same executable' >&2; exit 2;
        }
        [[ ${sources[control-a]:-} == "${sources[control-b]:-}" && ${sources[candidate-a]:-} == "${sources[candidate-b]:-}" ]] || {
            echo 'each repeated binary must have one matching source SHA' >&2; exit 2;
        }
        [[ -n ${sources[control-a]:-} && -n ${sources[candidate-a]:-} ]] || {
            echo 'control and candidate rows need source SHAs' >&2; exit 2;
        }
        ;;
    soak)
        ((${#rows[@]} == 2)) || { echo '--soak takes exactly two rows' >&2; exit 2; }
        check_row 0 control gotatun
        check_row 1 candidate gotatun
        [[ -n $label && -n ${binaries[control]:-} && -n ${binaries[candidate]:-} ]] || {
            echo '--soak requires --label and both binary paths' >&2; exit 2;
        }
        [[ -n ${sources[control]:-} && -n ${sources[candidate]:-} ]] || {
            echo '--soak requires source SHAs for both binaries' >&2; exit 2;
        }
        ;;
esac

for row in "${rows[@]}"; do
    tag=${row%%=*}
    engine=${row#*=}
    if [[ $engine == gotatun && $mode != smoke && -z ${binaries[$tag]:-} ]]; then
        echo "row $tag needs --binary $tag=PATH" >&2
        exit 2
    fi
done

if [[ -z $out ]]; then
    out="$kit/results/j88i-pinned-$mode-$(date -u +%Y%m%dT%H%M%SZ)"
fi
[[ ! -e $out ]] || { echo "results directory already exists: $out" >&2; exit 2; }
mkdir -p "$out/receipts"
out=$(cd -- "$out" && pwd -P)
plan="$out/rows.tsv"
: > "$plan"
chmod 0644 "$plan"
for row in "${rows[@]}"; do
    tag=${row%%=*}
    engine=${row#*=}
    printf '%s\t%s\t%s\t%s\n' "$tag" "$engine" "${binaries[$tag]:-}" "${sources[$tag]:-}" >> "$plan"
done

runner=${PERF_RUN:-/usr/local/bin/perf-run}
[[ -x $runner ]] || { echo "perf runner is not executable: $runner" >&2; exit 2; }
echo "D348 pinned $mode: $label; results $out"
run_env=(H2H_CPUSET_AUDIT=1 H2H_RESULTS="$out" "H2H_CPUSET_HOUSEKEEPING=$housekeeping")
if [[ $mode == validate ]]; then
    run_env+=(H2H_LAN_TPUT_SECONDS=10)
fi
[[ -z ${H2H_ETHTOOL_BIN:-} ]] || run_env+=("H2H_ETHTOOL_BIN=$H2H_ETHTOOL_BIN")
if [[ $mode == calibration && -z ${H2H_LAN_PING_COUNT:-} ]]; then
    H2H_LAN_PING_COUNT=3600
fi
if [[ -n ${H2H_LAN_PING_COUNT:-} ]]; then
    # perf-run enters a sudo scope, so measured overrides must be command env assignments.
    run_env+=("H2H_LAN_PING_COUNT=$H2H_LAN_PING_COUNT")
fi
run_status=0
set +e
taskset -c "$housekeeping" "$runner" --root --out "$out/receipts" -- \
    env "${run_env[@]}" \
    bash "$kit/runner-overlays/J88i-pinned-run.sh" "$kit" "$out" "$mode" "$label" "$plan"
run_status=$?
set -e

# Take a second locked, read-only pass after the measured scope exits. Baseline
# manifests verify the real cgroup masks, workqueues, and IRQ affinities.
mkdir -p "$out/restore-receipts"
restore_status=0
set +e
restore_args=("$out/cpuset-restoration.txt")
[[ -s $out/cgroup-masks-before.tsv ]] && restore_args+=("$out/cgroup-masks-before.tsv") || restore_args+=("")
[[ -s $out/workqueue-masks-before.tsv ]] && restore_args+=("$out/workqueue-masks-before.tsv") || restore_args+=("")
[[ -s $out/irq-affinity-before.tsv ]] && restore_args+=("$out/irq-affinity-before.tsv") || restore_args+=("")
[[ -s $out/dropin-masks-before.tsv ]] && restore_args+=("$out/dropin-masks-before.tsv") || restore_args+=("")
if ((run_status == 0)) && [[ ! -s $out/cgroup-masks-before.tsv || ! -s $out/workqueue-masks-before.tsv || ! -s $out/irq-affinity-before.tsv ]]; then
    echo 'D348 baseline manifests are missing after a successful measured scope' >&2
    restore_status=2
else
    taskset -c "$housekeeping" "$runner" --root --out "$out/restore-receipts" -- \
        bash "$kit/runner-overlays/J88i-verify-restored.sh" "${restore_args[@]}"
    restore_status=$?
fi
set -e
if ((restore_status != 0)); then
    echo 'D348 perf.slice restoration was not verified after the measured scope exited' >&2
    exit 2
fi
if ((run_status != 0)); then
    exit "$run_status"
fi
echo "results: $out"
if [[ $mode == calibration ]]; then
    spread_report="$out/calibration-spread.json"
    spread_status=0
    set +e
    python3 -I "$kit/lib/calibration_spread.py" "$out" --expected-probes 3600 --output "$spread_report"
    spread_status=$?
    set -e
    if ((spread_status != 0)); then
        echo "D348 control calibration failed the unpinned max/min spread gate; candidate holds are not enabled ($spread_report)" >&2
        exit "$spread_status"
    fi
fi
