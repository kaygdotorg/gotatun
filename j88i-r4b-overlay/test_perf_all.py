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

    def fake_restore_environment(
        self,
        root: Path,
        effective: str,
        cpuset: str = "0-5",
    ) -> dict[str, str]:
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
            "  *ControlGroup*) printf '/perf.slice\\n' ;;\n"
            "  *AllowedCPUs*) cat \"$J88I_TEST_SYSTEMD_STATE/allowed\" ;;\n"
            "  *EffectiveCPUs*) cat \"$J88I_TEST_SYSTEMD_STATE/effective\" ;;\n"
            "  *DropInPaths*) cat \"$J88I_TEST_SYSTEMD_STATE/dropins\" ;;\n"
            "  *) exit 2 ;;\n"
            "esac\n"
        )
        systemctl.chmod(0o755)
        (state_dir / "allowed").write_text("0-5\n")
        (state_dir / "effective").write_text(f"{effective}\n")
        (state_dir / "dropins").write_text("")
        (cgroup / "cpuset.cpus").write_text(f"{cpuset}\n")
        (cgroup / "cpuset.cpus.effective").write_text(f"{effective}\n")
        environment = os.environ.copy()
        environment["PATH"] = f"{bin_dir}{os.pathsep}{environment['PATH']}"
        environment["J88I_PERF_SLICE_CGROUP"] = str(cgroup)
        environment["J88I_EXPECTED_PERF_CPUS"] = "0-5"
        environment["J88I_TEST_SYSTEMD_STATE"] = str(state_dir)
        return environment

    def run_restore_check(
        self,
        root: Path,
        effective: str,
        *,
        cpuset: str = "0-5",
        allowed: str = "0-5",
        systemd_effective: str | None = None,
        workqueue_manifest: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Run the post-scope verifier against a temporary cgroup and systemd view."""
        script = Path(__file__).parent / "base/runner-overlays/J88i-verify-restored.sh"
        output = root / "restoration.txt"
        environment = self.fake_restore_environment(root, effective, cpuset)
        state_dir = root / "systemd-state"
        (state_dir / "allowed").write_text(f"{allowed}\n")
        (state_dir / "effective").write_text(
            f"{effective if systemd_effective is None else systemd_effective}\n"
        )
        cgroup_manifest = root / "cgroup-masks-before.tsv"
        cgroup_manifest.write_text("perf.slice\t/perf.slice\t0-5\t0-5\t\n")
        environment["J88I_CGROUP_ROOT"] = str(root)
        command = ["bash", str(script), str(output), str(cgroup_manifest)]
        if workqueue_manifest is not None:
            command.append(str(workqueue_manifest))
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            env=environment,
            check=False,
        )

    def test_restore_check_accepts_baseline_cgroup_after_scope_exit(self) -> None:
        """The second locked run must see every captured cgroup mask restored."""
        with tempfile.TemporaryDirectory(prefix="j88i-restore-ok-") as temporary:
            root = Path(temporary)
            result = self.run_restore_check(root, "0-5")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("cpuset.cpus.effective=0-5", (root / "restoration.txt").read_text())

    def test_restore_check_rejects_a_still_widened_cgroup(self) -> None:
        """The post-scope check must reject an effective mask that differs from its baseline."""
        with tempfile.TemporaryDirectory(prefix="j88i-restore-widened-") as temporary:
            result = self.run_restore_check(Path(temporary), "0-3")
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("cpuset.cpus.effective=0-3", result.stderr)

    def test_restore_check_uses_cgroup_masks_when_systemd_lists_differ(self) -> None:
        """The final CPU mask comes from cgroups, even when systemd prints a different form."""
        with tempfile.TemporaryDirectory(prefix="j88i-restore-cgroup-authority-") as temporary:
            root = Path(temporary)
            result = self.run_restore_check(
                root,
                "0-5",
                allowed="",
                systemd_effective="1-3",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("cpuset.cpus.effective=0-5", (root / "restoration.txt").read_text())

    def test_restore_check_rejects_wrong_cgroup_even_when_systemd_claims_baseline(self) -> None:
        """A correct property string cannot hide a cgroup that still has extra CPUs."""
        with tempfile.TemporaryDirectory(prefix="j88i-restore-cgroup-widened-") as temporary:
            result = self.run_restore_check(
                Path(temporary),
                "0-5",
                cpuset="0-4",
                allowed="0-5",
                systemd_effective="0-5",
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("cpuset.cpus=0-4", result.stderr)

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
            environment = self.fake_restore_environment(root, "0-5")
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
            self.assertIn("cpuset.cpus.effective=0-5", (output / "cpuset-restoration.txt").read_text())

    def test_validation_resolves_smoke_helper_from_installed_kit_root(self) -> None:
        """D348 validation must find the helper copied beside the installed harness kit."""
        overlay = Path(__file__).parent
        runner = overlay / "base/runner-overlays/J88i-pinned-run.sh"
        helper = overlay / "cpuset-harness-smoke.sh"

        self.assertTrue(helper.is_file())
        self.assertIn('bash "$kit/cpuset-harness-smoke.sh"', runner.read_text())

    def test_calibration_forwards_lan_probe_count_to_measured_scope(self) -> None:
        """The 3,600-probe override must cross perf-run's sudo boundary explicitly."""
        script = Path(__file__).parent / "base/perf-all.sh"
        with tempfile.TemporaryDirectory(prefix="j88i-calibration-count-") as temporary:
            root = Path(temporary)
            runner = root / "perf-run"
            capture = root / "runner-args.txt"
            count_file = root / "runner-count.txt"
            output = root / "calibration"
            binary = root / "gotatun"
            binary.write_text("#!/usr/bin/env bash\nexit 0\n")
            binary.chmod(0o755)
            runner.write_text(
                "#!/usr/bin/env bash\n"
                "count=0\n"
                "[[ ! -f $PERF_RUN_COUNT_FILE ]] || count=$(cat \"$PERF_RUN_COUNT_FILE\")\n"
                "count=$((count + 1))\n"
                "printf '%s\\n' \"$count\" > \"$PERF_RUN_COUNT_FILE\"\n"
                "if ((count == 1)); then printf '%s\\n' \"$@\" > \"$PERF_RUN_CAPTURE\"; exit 23; fi\n"
                "while (($#)) && [[ $1 != -- ]]; do shift; done\n"
                "[[ ${1:-} == -- ]] && shift\n"
                "\"$@\"\n"
            )
            runner.chmod(0o755)
            environment = self.fake_restore_environment(root, "0-5")
            environment["PERF_RUN"] = str(runner)
            environment["PERF_RUN_CAPTURE"] = str(capture)
            environment["PERF_RUN_COUNT_FILE"] = str(count_file)
            environment["H2H_LAN_PING_COUNT"] = "3600"

            result = subprocess.run(
                [
                    "bash",
                    str(script),
                    "--calibration",
                    "--row",
                    "control-a=gotatun",
                    "--row",
                    "control-b=gotatun",
                    "--row",
                    "control-c=gotatun",
                    "--binary",
                    f"control-a={binary}",
                    "--binary",
                    f"control-b={binary}",
                    "--binary",
                    f"control-c={binary}",
                    "--source",
                    "control-a=84b7bb28e385d57dfb80493e78202898fad24d1e",
                    "--source",
                    "control-b=84b7bb28e385d57dfb80493e78202898fad24d1e",
                    "--source",
                    "control-c=84b7bb28e385d57dfb80493e78202898fad24d1e",
                    "--out",
                    str(output),
                ],
                capture_output=True,
                text=True,
                env=environment,
                check=False,
            )

            self.assertEqual(result.returncode, 23, result.stderr)
            self.assertIn("H2H_LAN_PING_COUNT=3600", capture.read_text().splitlines())

    def test_restore_check_rejects_a_changed_workqueue_cpumask(self) -> None:
        """A mask left on housekeeping CPUs must fail the second locked restore check."""
        with tempfile.TemporaryDirectory(prefix="j88i-restore-workqueue-") as temporary:
            root = Path(temporary)
            mask = root / "workqueue" / "writeback" / "cpumask"
            mask.parent.mkdir(parents=True)
            mask.write_text("21\n")
            manifest = root / "workqueue-masks-before.tsv"
            manifest.write_text(f"{mask}\t3f\n")
            result = self.run_restore_check(
                root,
                "0-5",
                workqueue_manifest=manifest,
            )

            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("workqueue cpumask restore failed", result.stderr)

    def test_smoke_plan_accepts_wireguard_go_reference_engine(self) -> None:
        """The baseline comparison can schedule the existing wireguard-go harness case."""
        script = Path(__file__).parent / "base/perf-all.sh"
        with tempfile.TemporaryDirectory(prefix="j88i-wireguard-go-row-") as temporary:
            root = Path(temporary)
            runner = root / "perf-run"
            capture = root / "runner-args.txt"
            count_file = root / "runner-count.txt"
            output = root / "wireguard-go"
            runner.write_text(
                "#!/usr/bin/env bash\n"
                "count=0\n"
                "[[ ! -f $PERF_RUN_COUNT_FILE ]] || count=$(cat \"$PERF_RUN_COUNT_FILE\")\n"
                "count=$((count + 1))\n"
                "printf '%s\\n' \"$count\" > \"$PERF_RUN_COUNT_FILE\"\n"
                "if ((count == 1)); then printf '%s\\n' \"$@\" > \"$PERF_RUN_CAPTURE\"; exit 23; fi\n"
                "while (($#)) && [[ $1 != -- ]]; do shift; done\n"
                "[[ ${1:-} == -- ]] && shift\n"
                "\"$@\"\n"
            )
            runner.chmod(0o755)
            environment = self.fake_restore_environment(root, "0-5")
            environment["PERF_RUN"] = str(runner)
            environment["PERF_RUN_CAPTURE"] = str(capture)
            environment["PERF_RUN_COUNT_FILE"] = str(count_file)

            result = subprocess.run(
                [
                    "bash",
                    str(script),
                    "--smoke",
                    "--row",
                    "wireguard-go=wireguard-go",
                    "--out",
                    str(output),
                ],
                capture_output=True,
                text=True,
                env=environment,
                check=False,
            )

            self.assertEqual(result.returncode, 23, result.stderr)
            self.assertIn("wireguard-go\twireguard-go", (output / "rows.tsv").read_text())

    def test_hold_plan_uses_plain_kernel_wireguard_as_the_matched_mtu_baseline(self) -> None:
        """A counted cut hold must use the direct kernel row at the userspace MTU."""
        script = Path(__file__).parent / "base/perf-all.sh"
        with tempfile.TemporaryDirectory(prefix="j88i-kernel-mtu1420-") as temporary:
            root = Path(temporary)
            runner = root / "perf-run"
            runner.write_text(
                "#!/usr/bin/env bash\n"
                "for arg in \"$@\"; do\n"
                "  [[ $arg == */J88i-pinned-run.sh ]] && exit 23\n"
                "done\n"
                "exit 0\n"
            )
            runner.chmod(0o755)
            control = root / "control"
            candidate = root / "candidate"
            for binary in (control, candidate):
                binary.write_text("#!/usr/bin/env sh\\nexit 0\\n")
                binary.chmod(0o755)
            output = root / "hold"
            environment = self.fake_restore_environment(root, "0-5")
            environment["PERF_RUN"] = str(runner)

            result = subprocess.run(
                [
                    "bash",
                    str(script),
                    "--hold",
                    "--label",
                    "batch64-idle-lane",
                    "--row",
                    "kernel-before=kernel-plain",
                    "--row",
                    "wireguard-go-before=wireguard-go",
                    "--row",
                    "control-a=gotatun",
                    "--row",
                    "candidate-a=gotatun",
                    "--row",
                    "candidate-b=gotatun",
                    "--row",
                    "control-b=gotatun",
                    "--row",
                    "wireguard-go-after=wireguard-go",
                    "--row",
                    "kernel-after=kernel-plain",
                    "--binary",
                    f"control-a={control}",
                    "--binary",
                    f"control-b={control}",
                    "--binary",
                    f"candidate-a={candidate}",
                    "--binary",
                    f"candidate-b={candidate}",
                    "--source",
                    "control-a=1234567",
                    "--source",
                    "control-b=1234567",
                    "--source",
                    "candidate-a=7654321",
                    "--source",
                    "candidate-b=7654321",
                    "--out",
                    str(output),
                ],
                capture_output=True,
                text=True,
                env=environment,
                check=False,
            )

            self.assertEqual(result.returncode, 23, result.stderr)
            rows = (output / "rows.tsv").read_text()
            self.assertIn("kernel-before\tkernel-plain\t", rows)
            self.assertIn("kernel-after\tkernel-plain\t", rows)
            self.assertNotIn("mesh-netbird", rows)
            runner_overlay = Path(__file__).parent / "base/runner-overlays/J88i-pinned-run.sh"
            mesh_case = Path(__file__).parent / "base/cases/mesh.sh"
            self.assertIn("kernel-plain) case_name=mesh-kernel-plain", runner_overlay.read_text())
            kernel_setup = mesh_case.read_text().split("start_kernel_plain() {", 1)[1].split("\n}\n", 1)[0]
            self.assertIn("ip -n h2h-a link add wgA type wireguard", kernel_setup)
            self.assertIn('"$H2H_BIN/wg" set wgA', kernel_setup)
            self.assertIn("mtu 1420", kernel_setup)
            self.assertNotIn("start_netbird", kernel_setup)


if __name__ == "__main__":
    unittest.main()
