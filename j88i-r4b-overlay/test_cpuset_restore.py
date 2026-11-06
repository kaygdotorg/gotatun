#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Check that D348 restoration preserves inherited cgroup CPU masks exactly."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


class CpusetRestoreTest(unittest.TestCase):
    """Exercise the real restore verifier against isolated cgroup fixtures."""

    def run_verifier(self, configured_cpus: str) -> subprocess.CompletedProcess[str]:
        """Verify one cpuset state using a temporary cgroup tree and systemctl stub."""
        verifier = Path(__file__).parent / "base/runner-overlays/J88i-verify-restored.sh"
        with tempfile.TemporaryDirectory(prefix="j88i-cpuset-restore-") as temporary:
            root = Path(temporary)
            cgroup = root / "cgroup/init.scope"
            cgroup.mkdir(parents=True)
            (cgroup / "cpuset.cpus").write_text(configured_cpus)
            (cgroup / "cpuset.cpus.effective").write_text("0-5")

            binary_dir = root / "bin"
            binary_dir.mkdir()
            systemctl = binary_dir / "systemctl"
            systemctl.write_text(
                "#!/usr/bin/env bash\n"
                "if [[ $1 == show && $3 == -p && $5 == --value ]]; then\n"
                "  case $4 in\n"
                "    ControlGroup) printf '/init.scope\\n' ;;\n"
                "    DropInPaths|AllowedCPUs) printf '\\n' ;;\n"
                "    EffectiveCPUs) printf '0-5\\n' ;;\n"
                "    *) exit 2 ;;\n"
                "  esac\n"
                "else\n"
                "  exit 2\n"
                "fi\n"
            )
            systemctl.chmod(0o755)

            manifest = root / "cgroup-masks-before.tsv"
            manifest.write_text("init.scope\t/init.scope\t__EMPTY__\t0-5\t__EMPTY__\n")
            output = root / "restore.txt"
            environment = {
                **os.environ,
                "PATH": f"{binary_dir}:{os.environ['PATH']}",
                "J88I_CGROUP_ROOT": str(root / "cgroup"),
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

    def test_changed_configured_cpuset_does_not_pass_on_effective_mask_alone(self) -> None:
        """Changing an originally empty configured mask fails even if effective CPUs match."""
        result = self.run_verifier("0-5")

        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("cpuset.cpus=0-5 expected=", result.stderr)


if __name__ == "__main__":
    unittest.main()
