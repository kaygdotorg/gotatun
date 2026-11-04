#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Summarize three pinned control rows and gate their spread against unpinned history.

The calibration uses each row's LAN throughput JSON and raw ICMP replies. It
requires all 3,600 probes to have been sent, computes p50 and loss-aware p99
from the raw packets, and reports CPU per Gbit. Only metrics with published
unpinned control spreads gate the pass: throughput and loss-aware p99.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import math
import statistics
import sys
from pathlib import Path
from typing import Any


CONTROL_ROWS = ("control-a", "control-b", "control-c")
FLOW_COUNTS = ("1", "8")
UNPINNED_SPREAD_LIMITS_PCT: dict[str, dict[str, float]] = {
    "throughput_gbit_s": {"1": 1.6, "8": 0.8},
    "p99_loss_aware_ms": {"1": 3.2, "8": 5.9},
}


def load_pingstat() -> Any:
    """Load the shared raw-ping analyzer beside this module."""
    source = Path(__file__).with_name("pingstat.py")
    spec = importlib.util.spec_from_file_location("j88i_pingstat", source)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load raw ping analyzer: {source}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_probe_count(path: Path, pingstat: Any) -> int:
    """Read the actual transmitted count, failing if ping did not finish its run."""
    match = pingstat.SENT.search(path.read_text(errors="replace"))
    if match is None:
        raise ValueError(f"raw ping file has no transmitted-count footer: {path}")
    return int(match.group(1))


def read_calibration_rows(results_root: Path, expected_probes: int = 3600) -> tuple[
    dict[str, dict[str, dict[str, float]]], dict[str, dict[str, dict[str, int]]]
]:
    """Read three harness rows into comparable per-flow metrics and probe counts."""
    pingstat = load_pingstat()
    rows: dict[str, dict[str, dict[str, float]]] = {}
    probes: dict[str, dict[str, dict[str, int]]] = {}
    for row in CONTROL_ROWS:
        case_dir = results_root / row / "mesh-gotatun"
        metrics: dict[str, dict[str, float]] = {
            "throughput_gbit_s": {},
            "cpu_s_per_gbit": {},
            "p50_ms": {},
            "p99_loss_aware_ms": {},
        }
        probes[row] = {}
        for flows in FLOW_COUNTS:
            throughput_path = case_dir / f"tput-lan-{flows}.json"
            raw_ping_path = case_dir / f"icmp-lan-{flows}.raw"
            throughput = json.loads(throughput_path.read_text())
            sent = read_probe_count(raw_ping_path, pingstat)
            if sent != expected_probes:
                raise ValueError(
                    f"{row}/{flows} flows sent {sent} probes, expected {expected_probes}"
                )
            ping = pingstat.stats([raw_ping_path], expected_sent=expected_probes)
            metrics["throughput_gbit_s"][flows] = float(throughput["gbit_per_s"])
            metrics["cpu_s_per_gbit"][flows] = float(throughput["machine_cpu_s_per_gbit"])
            metrics["p50_ms"][flows] = float(ping["p50_received_ms"])
            metrics["p99_loss_aware_ms"][flows] = float(ping["p99_loss_aware_ms"])
            probes[row][flows] = {
                "sent": sent,
                "received": int(ping["sent"] - ping["lost"]),
                "lost": int(ping["lost"]),
            }
        rows[row] = metrics
    return rows, probes


def max_min_spread_pct(values: list[float]) -> float:
    """Return `(max / min - 1) * 100`; undefined ranges fail as infinite spread."""
    if len(values) != 3 or any(math.isnan(value) for value in values):
        return math.inf
    minimum = min(values)
    maximum = max(values)
    if minimum <= 0 or math.isinf(maximum):
        return math.inf
    return (maximum / minimum - 1) * 100


def summarize_rows(rows: dict[str, dict[str, dict[str, float]]]) -> dict[str, object]:
    """Calculate metric medians and the max/min historical spread gate."""
    if set(rows) != set(CONTROL_ROWS):
        raise ValueError(f"calibration requires exactly {', '.join(CONTROL_ROWS)}")
    metric_names = set(rows[CONTROL_ROWS[0]])
    if any(set(rows[row]) != metric_names for row in CONTROL_ROWS):
        raise ValueError("all control rows must contain the same metrics")

    medians: dict[str, dict[str, float]] = {}
    spreads: dict[str, dict[str, float]] = {}
    exceedances = []
    for metric in sorted(metric_names):
        medians[metric] = {}
        spreads[metric] = {}
        for flows in FLOW_COUNTS:
            values = [float(rows[row][metric][flows]) for row in CONTROL_ROWS]
            spread = max_min_spread_pct(values)
            medians[metric][flows] = float(statistics.median(values))
            spreads[metric][flows] = spread
            limit = UNPINNED_SPREAD_LIMITS_PCT.get(metric, {}).get(flows)
            if limit is not None and spread > limit:
                exceedances.append({
                    "metric": metric,
                    "flows": flows,
                    "spread_pct": spread,
                    "limit_pct": limit,
                })
    return {
        "control_median": medians,
        "spread_pct": spreads,
        "spread_limits_pct": UNPINNED_SPREAD_LIMITS_PCT,
        "ungated_spread_metrics": sorted(metric_names - set(UNPINNED_SPREAD_LIMITS_PCT)),
        "exceedances": exceedances,
        "passed": not exceedances,
    }


def main() -> int:
    """Write the raw-probe calibration summary and return nonzero when it fails."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results_root", type=Path, help="root created by perf-all.sh --calibration")
    parser.add_argument("--expected-probes", type=int, default=3600)
    parser.add_argument("--output", type=Path, help="optional JSON report path")
    arguments = parser.parse_args()
    if arguments.expected_probes < 1:
        parser.error("--expected-probes must be positive")
    try:
        rows, probes = read_calibration_rows(arguments.results_root, arguments.expected_probes)
        summary = summarize_rows(rows)
    except (OSError, KeyError, ValueError, json.JSONDecodeError) as error:
        print(f"calibration summary failed: {error}", file=sys.stderr)
        return 2
    summary["rows"] = rows
    summary["probe_counts"] = probes
    summary["expected_probes_per_flow"] = arguments.expected_probes
    output = json.dumps(summary, indent=2, allow_nan=True) + "\n"
    if arguments.output:
        arguments.output.write_text(output)
    print(output, end="")
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
