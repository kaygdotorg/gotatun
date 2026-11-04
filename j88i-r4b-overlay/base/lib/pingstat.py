#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Summarize raw ICMP replies for the D331/J201 loss-aware p99 keep rule."""

from __future__ import annotations

import argparse
import math
import re
from pathlib import Path
from typing import Iterable


REPLY = re.compile(r"icmp_seq=(\d+) .*time=([\d.]+) ms")
SENT = re.compile(r"(\d+) packets transmitted")


def percentile(values: list[float], fraction: float) -> float:
    """Return the nearest-rank percentile, or NaN when no replies arrived."""
    if not values:
        return math.nan
    ordered = sorted(values)
    rank = max(1, math.ceil(fraction * len(ordered)))
    return ordered[rank - 1]


def stats(
    paths: Iterable[str | Path], expected_sent: int = 0
) -> dict[str, int | float]:
    """Read ping output files and calculate received and loss-aware percentiles.

    Each ICMP sequence contributes at most once per file. The keep-rule p99 is
    deliberately infinite after any loss, even when the mathematical nearest
    rank would still land on a received sample, so a dropped probe cannot look
    like a latency improvement.
    """
    received: list[float] = []
    sent = 0
    for path in paths:
        replies: dict[int, float] = {}
        text = Path(path).read_text(errors="replace")
        for match in REPLY.finditer(text):
            replies.setdefault(int(match.group(1)), float(match.group(2)))
        reported = SENT.search(text)
        sent += int(reported.group(1)) if reported else max(replies, default=0)
        received.extend(replies.values())

    sent = max(sent, len(received), expected_sent)
    lost = max(0, sent - len(received))
    p50_received = percentile(received, 0.50)
    p99_received = percentile(received, 0.99)
    p999_loss_aware = percentile(received + [math.inf] * lost, 0.999)
    p99_loss_aware = math.inf if lost else p99_received
    return {
        "sent": sent,
        "lost": lost,
        "p50_received_ms": p50_received,
        "p99_received_ms": p99_received,
        "p99_loss_aware_ms": p99_loss_aware,
        "p999_loss_aware_ms": p999_loss_aware,
        "max_received_ms": max(received, default=math.nan),
    }


def format_ms(value: float) -> str:
    """Print finite percentiles in milliseconds and keep loss visible as `inf`."""
    if math.isinf(value):
        return "inf"
    if math.isnan(value):
        return "nan"
    return f"{value:.3f}"


def main() -> int:
    """Read one or more `ping -D -O -n` logs and print the keep metrics."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--expected-sent",
        type=int,
        default=0,
        help="minimum expected probe count when ping exits before its summary",
    )
    parser.add_argument("files", nargs="+", type=Path, help="raw ping output file(s)")
    arguments = parser.parse_args()
    result = stats(arguments.files, expected_sent=arguments.expected_sent)
    print(
        "sent {sent} lost {lost} p50 {p50} p99_received {p99_received} "
        "p99_loss_aware {p99_loss_aware} p99.9_loss_aware {p999} max {maximum}".format(
            sent=result["sent"],
            lost=result["lost"],
            p50=format_ms(float(result["p50_received_ms"])),
            p99_received=format_ms(float(result["p99_received_ms"])),
            p99_loss_aware=format_ms(float(result["p99_loss_aware_ms"])),
            p999=format_ms(float(result["p999_loss_aware_ms"])),
            maximum=format_ms(float(result["max_received_ms"])),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
