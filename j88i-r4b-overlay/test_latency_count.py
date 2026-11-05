#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Keep the LAN latency probe count adjustable for pinned calibration."""

from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path


class LatencyCountTest(unittest.TestCase):
    """Exercise the LAN probe-count helper without starting a benchmark."""

    def run_count(self, *, override: str | None = None, smoke: bool = False) -> subprocess.CompletedProcess[str]:
        """Run the count helper with isolated calibration settings."""
        kit = Path(__file__).parent / "base"
        environment = os.environ.copy()
        environment["H2H_KIT"] = str(kit)
        environment.pop("H2H_LAN_PING_COUNT", None)
        environment.pop("H2H_SMOKE", None)
        if override is not None:
            environment["H2H_LAN_PING_COUNT"] = override
        if smoke:
            environment["H2H_SMOKE"] = "1"
        return subprocess.run(
            ["bash", "-c", 'source "$H2H_KIT/lib/common.sh"; h2h_lan_latency_count'],
            capture_output=True,
            text=True,
            env=environment,
            check=False,
        )

    def test_lan_probe_count_override_is_used(self) -> None:
        """A calibration can request exactly 3,600 probes per flow."""
        result = self.run_count(override="3600")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "3600")

    def test_loaded_ping_count_is_not_extended_until_all_replies_arrive(self) -> None:
        """A lost echo reply must not make a fixed-count ping send extra probes."""
        mesh = Path(__file__).parent / "base/cases/mesh.sh"
        source = mesh.read_text()
        start = source.index("spawn_in_ns ping_pid h2h-a ping -D -O -n -i 0.005")
        end = source.index('"$PEER"', start)
        ping_command = source[start:end]

        self.assertIn('-c "$count"', ping_command)
        self.assertNotIn("-w", ping_command)

    def test_full_run_probe_count_keeps_the_existing_default(self) -> None:
        """Full measurements keep the existing 2,000-probe default."""
        result = self.run_count()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "2000")

    def test_smoke_probe_count_keeps_the_existing_short_default(self) -> None:
        """Smoke runs keep the existing 300-probe count."""
        result = self.run_count(smoke=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "300")

    def test_invalid_probe_count_is_rejected(self) -> None:
        """An invalid override fails with a clear diagnostic before ping starts."""
        result = self.run_count(override="0")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("H2H_LAN_PING_COUNT must be a positive integer", result.stderr)


if __name__ == "__main__":
    unittest.main()
