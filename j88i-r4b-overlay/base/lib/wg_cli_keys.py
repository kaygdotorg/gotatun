#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Convert the head-to-head fixture's hex keys into files for the kernel CLI."""

from __future__ import annotations

import argparse
import base64
import os
from pathlib import Path


def read_hex_key(path: Path) -> bytes:
    """Read one 32-byte key from the hex format used by the UAPI fixture."""
    value = path.read_text(encoding="ascii").strip()
    if len(value) != 64:
        raise ValueError(f"{path.name} must contain exactly 64 hex characters")
    try:
        key = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(f"{path.name} must contain only hexadecimal characters") from error
    if len(key) != 32:
        raise ValueError(f"{path.name} must decode to exactly 32 bytes")
    return key


def convert_keys(directory: Path) -> None:
    """Write base64 copies after every source key has passed validation."""
    keys = {
        "a.wg.private": (read_hex_key(directory / "a.private"), 0o600),
        "a.wg.public": (read_hex_key(directory / "a.public"), 0o644),
        "b.wg.private": (read_hex_key(directory / "b.private"), 0o600),
        "b.wg.public": (read_hex_key(directory / "b.public"), 0o644),
    }

    created: list[Path] = []
    try:
        for name, (key, mode) in keys.items():
            path = directory / name
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
            created.append(path)
            with os.fdopen(fd, "wb") as stream:
                # The `wg` CLI reads base64 from a file; UAPI hex is not valid here.
                stream.write(base64.b64encode(key) + b"\n")
    except OSError:
        for path in created:
            path.unlink(missing_ok=True)
        raise


def main() -> None:
    """Convert both fixture peers for the direct kernel WireGuard row."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    try:
        convert_keys(args.directory)
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
