#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Exercise the pinned R4b command-line parser without running a benchmark."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


class PerfAllCliTest(unittest.TestCase):
    """Keep validation mode reachable when optional row maps are empty."""

    def test_validate_reaches_perf_runner_without_rows(self) -> None:
        """Empty validation options must not trip nounset before perf-run."""
        script = Path(__file__).parent / "base/perf-all.sh"
        with tempfile.TemporaryDirectory(prefix="j88i-perf-all-") as temporary:
            root = Path(temporary)
            runner = root / "perf-run"
            capture = root / "runner-args.txt"
            output = root / "validation"
            runner.write_text(
                "#!/usr/bin/env bash\n"
                "printf '%s\\n' \"$@\" > \"$PERF_RUN_CAPTURE\"\n"
                "exit 23\n"
            )
            runner.chmod(0o755)
            environment = os.environ.copy()
            environment["PERF_RUN"] = str(runner)
            environment["PERF_RUN_CAPTURE"] = str(capture)

            result = subprocess.run(
                ["bash", str(script), "--validate", "--out", str(output)],
                capture_output=True,
                text=True,
                env=environment,
                check=False,
            )

            self.assertEqual(result.returncode, 23, result.stderr)
            self.assertIn("D348 pinned validate", result.stdout)
            self.assertEqual(
                capture.read_text().splitlines()[:3],
                ["--root", "--out", str(output / "receipts")],
            )


if __name__ == "__main__":
    unittest.main()
