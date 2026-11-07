#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Select Tokio worker placement only for the J88i locality candidate."""

from __future__ import annotations

import re
import sys


LOCALITY_ROW = re.compile(r"gotatun-j88i-locality-33ca6fe-[0-9]+")
FAIRNESS_ROW = re.compile(r"gotatun-j88i-33ca6fe-[0-9]+")


def placement(row_tag: str, locality_matrix: bool) -> str:
    """Return the placement to use for this row in a locality experiment."""
    if LOCALITY_ROW.fullmatch(row_tag):
        return "round-robin"
    if locality_matrix and FAIRNESS_ROW.fullmatch(row_tag):
        return "round-robin"
    return "default"


def main(argv: list[str]) -> int:
    """Print one row's worker-placement mode for the shell runner."""
    if len(argv) != 3 or argv[2] not in {"0", "1"}:
        print("usage: matrix_locality.py ROW_TAG 0|1", file=sys.stderr)
        return 2
    print(placement(argv[1], argv[2] == "1"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
