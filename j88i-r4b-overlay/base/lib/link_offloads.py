#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Capture each mesh row's tunnel and veth offload settings with `ethtool -k`.

The JSON summary keeps enabled GSO and GRO feature names beside the complete
command output. These flags describe the interface configuration; they do not
count whether a particular packet was segmented or coalesced during the run.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path


# Linux feature names that expose enabled packet-segmentation settings.
GSO_FEATURES = frozenset({
    "generic-segmentation-offload",
    "tcp-segmentation-offload",
    "tx-gso-partial",
    "tx-udp-segmentation",
    "tx-udp_tnl-segmentation",
    "tx-udp_tnl-csum-segmentation",
})
# Linux feature names that expose enabled packet-coalescing settings.
GRO_FEATURES = frozenset({
    "generic-receive-offload",
    "rx-gro-hw",
    "rx-gro-list",
    "rx-udp-gro-forwarding",
})
# Recognize one `ethtool -k` feature and its optional annotation.
FEATURE_LINE = re.compile(r"^\s*([^:]+):\s+(on|off)(?:\s+(.*))?$")
# Find the MTU printed by `ip -o link show`.
MTU_VALUE = re.compile(r"\bmtu\s+(\d+)\b")


def parse_ethtool_features(output: str) -> dict[str, dict[str, object]]:
    """Parse feature states while retaining annotations such as `[fixed]`."""
    features: dict[str, dict[str, object]] = {}
    for line in output.splitlines():
        match = FEATURE_LINE.match(line)
        if match is None:
            continue
        name, state, details = match.groups()
        features[name] = {
            "enabled": state == "on",
            "details": details or "",
        }
    return features


def feature_state(
    features: dict[str, dict[str, object]], names: frozenset[str]
) -> dict[str, object]:
    """Report whether any listed GSO or GRO feature is enabled on a link."""
    reported = sorted(names.intersection(features))
    enabled = sorted(
        name for name in reported if bool(features[name]["enabled"])
    )
    return {
        "state": "enabled" if enabled else "disabled" if reported else "not-reported",
        "reported_features": reported,
        "enabled_features": enabled,
    }


def run_text(arguments: list[str]) -> str:
    """Run a read-only network inspection command and return its output."""
    result = subprocess.run(arguments, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"command exited {result.returncode}: {' '.join(arguments)}\n"
            f"{result.stderr.strip()}"
        )
    return result.stdout


def capture_interface(
    ethtool: str, namespace: str, interface: str, role: str, raw_dir: Path
) -> dict[str, object]:
    """Capture one interface's MTU and exact `ethtool -k` output."""
    tag = f"{namespace}-{interface}"
    link = run_text(["ip", "-n", namespace, "-o", "link", "show", "dev", interface])
    features_text = run_text(
        ["ip", "netns", "exec", namespace, ethtool, "-k", interface]
    )
    features = parse_ethtool_features(features_text)
    if not features:
        raise RuntimeError(f"ethtool reported no link features for {namespace}/{interface}")
    (raw_dir / f"{tag}.link.txt").write_text(link)
    (raw_dir / f"{tag}.ethtool-k.txt").write_text(features_text)
    mtu_match = MTU_VALUE.search(link)
    return {
        "namespace": namespace,
        "interface": interface,
        "role": role,
        "mtu": int(mtu_match.group(1)) if mtu_match else None,
        "gso": feature_state(features, GSO_FEATURES),
        "gro": feature_state(features, GRO_FEATURES),
        "features": features,
        "raw_link_file": f"{tag}.link.txt",
        "raw_ethtool_file": f"{tag}.ethtool-k.txt",
    }


def main() -> int:
    """Write raw link inspections and their row-level GSO/GRO summary."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--system", required=True)
    parser.add_argument("--ethtool", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument(
        "--interface", action="append", nargs=3,
        metavar=("NAMESPACE", "DEVICE", "ROLE"), required=True,
    )
    arguments = parser.parse_args()
    output_dir = arguments.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    version = run_text([arguments.ethtool, "--version"]).strip()
    interfaces = [
        capture_interface(arguments.ethtool, namespace, interface, role, output_dir)
        for namespace, interface, role in arguments.interface
    ]
    report = {
        "system": arguments.system,
        "ethtool_version": version,
        "command": "ethtool -k",
        "interfaces": interfaces,
        "interpretation": (
            "GSO/GRO values are configured interface feature states. ethtool -k "
            "does not count packets segmented or coalesced during this row."
        ),
    }
    (output_dir / "offloads.json").write_text(json.dumps(report, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
