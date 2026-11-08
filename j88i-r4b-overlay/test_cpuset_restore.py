#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Check that D348 restores CPU masks and preserves existing slice properties."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


class CpusetRestoreTest(unittest.TestCase):
    """Exercise the real restore verifier against isolated cgroup fixtures."""

    def run_restore_mode(
        self,
        unit: str,
        drop_ins: str,
        allowed_cpus: str,
    ) -> subprocess.CompletedProcess[str]:
        """Ask the placement helper how to restore one unit's temporary CPU property."""
        helper = Path(__file__).parent / "base/runner-overlays/J88i-cpuset-state.sh"
        return subprocess.run(
            [
                "bash",
                "-c",
                'source "$1"; cpuset_restore_mode "$2" "$3" "$4"',
                "bash",
                str(helper),
                unit,
                drop_ins,
                allowed_cpus,
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    def run_verifier(
        self,
        configured_cpus: str,
        effective_cpus: str = "0-5",
        *,
        unit: str = "init.scope",
        expected_configured_cpus: str = "",
        expected_effective_cpus: str = "0-5",
        expected_dropins: str = "",
        expected_allowed_cpus: str = "",
        reported_allowed_cpus: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Verify one cpuset state using a temporary cgroup tree and systemctl stub."""
        verifier = Path(__file__).parent / "base/runner-overlays/J88i-verify-restored.sh"
        with tempfile.TemporaryDirectory(prefix="j88i-cpuset-restore-") as temporary:
            root = Path(temporary)
            group = f"/{unit}"
            cgroup = root / "cgroup" / unit
            cgroup.mkdir(parents=True)
            (cgroup / "cpuset.cpus").write_text(configured_cpus)
            (cgroup / "cpuset.cpus.effective").write_text(effective_cpus)

            binary_dir = root / "bin"
            binary_dir.mkdir()
            systemctl = binary_dir / "systemctl"
            systemctl.write_text(
                "#!/usr/bin/env bash\n"
                "if [[ $1 == show && $3 == -p && $5 == --value ]]; then\n"
                "  case $4 in\n"
                "    ControlGroup) printf '%s\\n' \"$J88I_TEST_GROUP\" ;;\n"
                "    DropInPaths) printf '%s\\n' \"$J88I_TEST_DROPINS\" ;;\n"
                "    AllowedCPUs) printf '%s\\n' \"$J88I_TEST_ALLOWED\" ;;\n"
                "    EffectiveCPUs) printf '0-5\\n' ;;\n"
                "    *) exit 2 ;;\n"
                "  esac\n"
                "else\n"
                "  exit 2\n"
                "fi\n"
            )
            systemctl.chmod(0o755)

            manifest = root / "cgroup-masks-before.tsv"
            encode = lambda value: value if value else "__EMPTY__"
            manifest.write_text(
                f"{unit}\t{group}\t{encode(expected_configured_cpus)}\t{encode(expected_effective_cpus)}\t"
                f"{encode(expected_dropins)}\t{encode(expected_allowed_cpus)}\n"
            )
            output = root / "restore.txt"
            environment = {
                **os.environ,
                "PATH": f"{binary_dir}:{os.environ['PATH']}",
                "J88I_CGROUP_ROOT": str(root / "cgroup"),
                "J88I_TEST_GROUP": group,
                "J88I_TEST_DROPINS": expected_dropins,
                "J88I_TEST_ALLOWED": (
                    expected_allowed_cpus
                    if reported_allowed_cpus is None
                    else reported_allowed_cpus
                ),
            }
            return subprocess.run(
                ["bash", str(verifier), str(output), str(manifest)],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
            )

    def test_empty_inherited_cpuset_is_restored_exactly(self) -> None:
        """An inherited empty mask with effective 0-5 passes exact restore verification."""
        result = self.run_verifier("")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("cpuset.cpus= cpuset.cpus.effective=0-5", result.stdout)

    def test_explicit_full_mask_is_accepted_when_systemd_reverts_inherited_baseline(self) -> None:
        """A full configured mask is equivalent when the live effective mask is still 0-5."""
        result = self.run_verifier("0-5")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("cpuset.cpus=0-5 cpuset.cpus.effective=0-5", result.stdout)

    def test_narrow_live_cpuset_does_not_pass_when_effective_mask_changes(self) -> None:
        """The verifier rejects a real live mask that no longer allows every CPU."""
        result = self.run_verifier("1-4", "1-4")

        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("cpuset.cpus.effective=1-4 expected=0-5", result.stderr)

    def test_perf_slice_dropins_and_allowed_cpus_are_verified_after_restore(self) -> None:
        """The verifier accepts the captured perf.slice properties and real masks."""
        dropins = (
            "/run/systemd/system.control/perf.slice.d/50-AllowedCPUs.conf "
            "/run/systemd/system.control/perf.slice.d/50-MemoryMax.conf"
        )
        result = self.run_verifier(
            "1-3",
            "1-3",
            unit="perf.slice",
            expected_configured_cpus="1-3",
            expected_effective_cpus="1-3",
            expected_dropins=dropins,
            expected_allowed_cpus="1-3",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("AllowedCPUs=1-3", result.stdout)

    def test_perf_slice_allowed_cpus_mismatch_fails_restore_verification(self) -> None:
        """A correct cpuset cannot hide a changed systemd CPU property."""
        result = self.run_verifier(
            "1-3",
            "1-3",
            unit="perf.slice",
            expected_configured_cpus="1-3",
            expected_effective_cpus="1-3",
            expected_dropins="/run/systemd/system.control/perf.slice.d/50-AllowedCPUs.conf",
            expected_allowed_cpus="1-3",
            reported_allowed_cpus="0-5",
        )

        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("AllowedCPUs=0-5 expected=1-3", result.stderr)

    def test_existing_runtime_dropins_restore_allowed_cpus_without_reverting(self) -> None:
        """A pre-existing AllowedCPUs drop-in must survive placement cleanup."""
        result = self.run_restore_mode(
            "perf.slice",
            "/run/systemd/system.control/perf.slice.d/50-AllowedCPUs.conf "
            "/run/systemd/system.control/perf.slice.d/50-MemoryMax.conf",
            "1-3",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "preserve-existing-dropins")

    def test_other_units_with_existing_dropins_are_rejected(self) -> None:
        """Host service properties are never erased to pin a test slice."""
        result = self.run_restore_mode(
            "system.slice",
            "/run/systemd/system.control/system.slice.d/50-AllowedCPUs.conf",
            "0-5",
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("cannot safely change system.slice", result.stderr)

    def test_new_runtime_dropin_can_be_reverted_after_restore(self) -> None:
        """A unit without prior drop-ins can remove the temporary runtime property."""
        result = self.run_restore_mode("system.slice", "", "")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "revert-generated-dropin")


if __name__ == "__main__":
    unittest.main()
