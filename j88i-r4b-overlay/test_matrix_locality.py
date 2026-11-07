#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Exercise the matrix runner's candidate-specific locality switch."""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parent / "base/lib/matrix_locality.py"


class MatrixLocalityTests(unittest.TestCase):
    """Only the J88i candidate gets Tokio placement in the locality matrix."""

    def placement(self, row_tag: str, enabled: bool) -> subprocess.CompletedProcess[str]:
        """Run the same placement selector that the matrix runner invokes."""
        return subprocess.run(
            [sys.executable, "-I", str(SCRIPT), row_tag, "1" if enabled else "0"],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_locality_is_limited_to_the_j88i_candidate_row(self) -> None:
        """The candidate row is round-robin only when the locality matrix is enabled."""
        candidate = "gotatun-j88i-33ca6fe-3"
        enabled = self.placement(candidate, True)
        ordinary = self.placement(candidate, False)
        shipped = self.placement("gotatun-shipped-84b7bb2-3", True)
        locality_tag = self.placement("gotatun-j88i-locality-33ca6fe-3", False)

        self.assertEqual(enabled.returncode, 0, enabled.stderr)
        self.assertEqual(enabled.stdout.strip(), "round-robin")
        self.assertEqual(ordinary.returncode, 0, ordinary.stderr)
        self.assertEqual(ordinary.stdout.strip(), "default")
        self.assertEqual(shipped.returncode, 0, shipped.stderr)
        self.assertEqual(shipped.stdout.strip(), "default")
        self.assertEqual(locality_tag.returncode, 0, locality_tag.stderr)
        self.assertEqual(locality_tag.stdout.strip(), "round-robin")

    def test_hold_candidate_names_select_locality_only_when_enabled(self) -> None:
        """The hold runner's fixed candidate row names can activate locality explicitly."""
        candidate_a = self.placement("candidate-a", True)
        candidate_b = self.placement("candidate-b", True)
        ordinary = self.placement("candidate-a", False)
        control = self.placement("control-a", True)

        self.assertEqual(candidate_a.returncode, 0, candidate_a.stderr)
        self.assertEqual(candidate_a.stdout.strip(), "round-robin")
        self.assertEqual(candidate_b.returncode, 0, candidate_b.stderr)
        self.assertEqual(candidate_b.stdout.strip(), "round-robin")
        self.assertEqual(ordinary.returncode, 0, ordinary.stderr)
        self.assertEqual(ordinary.stdout.strip(), "default")
        self.assertEqual(control.returncode, 0, control.stderr)
        self.assertEqual(control.stdout.strip(), "default")


if __name__ == "__main__":
    unittest.main()
