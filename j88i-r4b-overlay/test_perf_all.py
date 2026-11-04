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

    def fake_restore_environment(self, root: Path, effective: str) -> dict[str, str]:
        """Provide a controlled systemd and cgroup view for restoration tests."""
        bin_dir = root / "bin"
        state_dir = root / "systemd-state"
        cgroup = root / "perf.slice"
        bin_dir.mkdir(exist_ok=True)
        state_dir.mkdir(exist_ok=True)
        cgroup.mkdir(exist_ok=True)
        systemctl = bin_dir / "systemctl"
        systemctl.write_text(
            "#!/usr/bin/env bash\n"
            "case \" $* \" in\n"
            "  *AllowedCPUs*) cat \"$J88I_TEST_SYSTEMD_STATE/allowed\" ;;\n"
            "  *EffectiveCPUs*) cat \"$J88I_TEST_SYSTEMD_STATE/effective\" ;;\n"
            "  *DropInPaths*) cat \"$J88I_TEST_SYSTEMD_STATE/dropins\" ;;\n"
            "  *) exit 2 ;;\n"
            "esac\n"
        )
        systemctl.chmod(0o755)
        (state_dir / "allowed").write_text("1-3\n")
        (state_dir / "effective").write_text(f"{effective}\n")
        (state_dir / "dropins").write_text("")
        (cgroup / "cpuset.cpus").write_text("1-3\n")
        (cgroup / "cpuset.cpus.effective").write_text(f"{effective}\n")
        environment = os.environ.copy()
        environment["PATH"] = f"{bin_dir}{os.pathsep}{environment['PATH']}"
        environment["J88I_PERF_SLICE_CGROUP"] = str(cgroup)
        environment["J88I_TEST_SYSTEMD_STATE"] = str(state_dir)
        return environment

    def run_restore_check(self, root: Path, effective: str) -> subprocess.CompletedProcess[str]:
        """Run the post-scope verifier against a temporary cgroup and systemd view."""
        script = Path(__file__).parent / "base/runner-overlays/J88i-verify-restored.sh"
        output = root / "restoration.txt"
        environment = self.fake_restore_environment(root, effective)
        return subprocess.run(
            ["bash", str(script), str(output)],
            capture_output=True,
            text=True,
            env=environment,
            check=False,
        )

    def test_restore_check_accepts_baseline_cgroup_after_scope_exit(self) -> None:
        """The second locked run must see the restored 1-3 effective set."""
        with tempfile.TemporaryDirectory(prefix="j88i-restore-ok-") as temporary:
            root = Path(temporary)
            result = self.run_restore_check(root, "1-3")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("cpuset.cpus.effective=1-3", (root / "restoration.txt").read_text())

    def test_restore_check_rejects_a_still_widened_cgroup(self) -> None:
        """The post-scope check must reject an effective 0-3 cgroup."""
        with tempfile.TemporaryDirectory(prefix="j88i-restore-widened-") as temporary:
            result = self.run_restore_check(Path(temporary), "0-3")
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("cpuset.cpus.effective=0-3", result.stderr)

    def test_validate_reaches_perf_runner_without_rows(self) -> None:
        """Empty validation options must not trip nounset before perf-run."""
        script = Path(__file__).parent / "base/perf-all.sh"
        with tempfile.TemporaryDirectory(prefix="j88i-perf-all-") as temporary:
            root = Path(temporary)
            runner = root / "perf-run"
            capture = root / "runner-args.txt"
            count_file = root / "runner-count.txt"
            output = root / "validation"
            runner.write_text(
                "#!/usr/bin/env bash\n"
                "count=0\n"
                "[[ ! -f $PERF_RUN_COUNT_FILE ]] || count=$(cat \"$PERF_RUN_COUNT_FILE\")\n"
                "count=$((count + 1))\n"
                "printf '%s\\n' \"$count\" > \"$PERF_RUN_COUNT_FILE\"\n"
                "if ((count == 1)); then printf '%s\\n' \"$@\" > \"$PERF_RUN_CAPTURE\"; exit 23; fi\n"
                "printf 'verify-call\\n' >> \"$PERF_RUN_CAPTURE\"\n"
                "while (($#)) && [[ $1 != -- ]]; do shift; done\n"
                "[[ ${1:-} == -- ]] && shift\n"
                "\"$@\"\n"
            )
            runner.chmod(0o755)
            environment = self.fake_restore_environment(root, "1-3")
            environment["PERF_RUN"] = str(runner)
            environment["PERF_RUN_CAPTURE"] = str(capture)
            environment["PERF_RUN_COUNT_FILE"] = str(count_file)

            result = subprocess.run(
                ["bash", str(script), "--validate", "--out", str(output)],
                capture_output=True,
                text=True,
                env=environment,
                check=False,
            )

            self.assertEqual(result.returncode, 23, result.stderr)
            self.assertIn("D348 pinned validate", result.stdout)
            self.assertEqual(count_file.read_text().strip(), "2")
            self.assertIn("verify-call", capture.read_text())
            self.assertEqual(
                capture.read_text().splitlines()[:3],
                ["--root", "--out", str(output / "receipts")],
            )
            self.assertIn("cpuset.cpus.effective=1-3", (output / "cpuset-restoration.txt").read_text())


if __name__ == "__main__":
    unittest.main()
