#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Check conversion from hex UAPI keys to the kernel CLI key format."""

from __future__ import annotations

import base64
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


OVERLAY = Path(__file__).parent
HELPER = OVERLAY / "base/lib/wg_cli_keys.py"


class WireGuardCliKeyTest(unittest.TestCase):
    """Keep kernel CLI setup separate from the userspace UAPI key encoding."""

    def run_helper(self, directory: Path) -> subprocess.CompletedProcess[str]:
        """Run the converter with the test's isolated key directory."""
        self.assertTrue(HELPER.is_file(), f"missing helper: {HELPER}")
        return subprocess.run(
            [sys.executable, str(HELPER), str(directory)],
            capture_output=True,
            text=True,
            check=False,
        )

    def write_hex_keys(self, directory: Path) -> tuple[bytes, bytes, bytes, bytes]:
        """Create four fixed 32-byte test keys in the format the harness emits."""
        keys = {
            "a.private": bytes(range(32)),
            "a.public": bytes(range(32, 64)),
            "b.private": bytes(reversed(range(32))),
            "b.public": bytes(reversed(range(32, 64))),
        }
        for name, value in keys.items():
            (directory / name).write_text(value.hex() + "\n", encoding="ascii")
        return keys["a.private"], keys["a.public"], keys["b.private"], keys["b.public"]

    def test_hex_keys_become_base64_files_for_kernel_cli(self) -> None:
        """The kernel CLI must receive base64 keys decoded from the original bytes."""
        with tempfile.TemporaryDirectory(prefix="wg-cli-keys-") as temporary:
            directory = Path(temporary)
            a_private, a_public, b_private, b_public = self.write_hex_keys(directory)

            result = self.run_helper(directory)

            self.assertEqual(result.returncode, 0, result.stderr)
            for name, original in (
                ("a.wg.private", a_private),
                ("a.wg.public", a_public),
                ("b.wg.private", b_private),
                ("b.wg.public", b_public),
            ):
                encoded = (directory / name).read_text(encoding="ascii").strip()
                self.assertEqual(base64.b64decode(encoded, validate=True), original)
            self.assertEqual(os.stat(directory / "a.wg.private").st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(directory / "b.wg.private").st_mode & 0o777, 0o600)

    def test_invalid_hex_does_not_leave_partial_cli_key_files(self) -> None:
        """Malformed input must stop before any converted key is written."""
        with tempfile.TemporaryDirectory(prefix="wg-cli-keys-invalid-") as temporary:
            directory = Path(temporary)
            self.write_hex_keys(directory)
            (directory / "b.public").write_text("not-a-32-byte-key\n", encoding="ascii")

            result = self.run_helper(directory)

            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(list(directory.glob("*.wg.*")), [])


if __name__ == "__main__":
    unittest.main()
