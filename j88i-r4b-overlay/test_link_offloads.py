#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Check that the D348 report identifies configured GSO and GRO features."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


class LinkOffloadsTest(unittest.TestCase):
    """Keep the `ethtool -k` feature summary honest for each measured link."""

    @staticmethod
    def module():
        """Load the overlay helper without adding its directory to global imports."""
        script = Path(__file__).parent / "base/lib/link_offloads.py"
        spec = importlib.util.spec_from_file_location("link_offloads", script)
        if spec is None or spec.loader is None:
            raise AssertionError("could not load the link-offload helper")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_ethtool_features_keep_gso_and_gro_states_separate(self) -> None:
        """The report distinguishes enabled features from off and unreported ones."""
        module = self.module()
        features = module.parse_ethtool_features(
            """Features for wgA:
rx-checksumming: on [fixed]
generic-segmentation-offload: on
tx-udp_tnl-segmentation: off [fixed]
generic-receive-offload: on
rx-udp-gro-forwarding: off
"""
        )

        self.assertEqual(features["rx-checksumming"], {"enabled": True, "details": "[fixed]"})
        self.assertEqual(
            module.feature_state(features, module.GSO_FEATURES),
            {
                "state": "enabled",
                "reported_features": ["generic-segmentation-offload", "tx-udp_tnl-segmentation"],
                "enabled_features": ["generic-segmentation-offload"],
            },
        )
        self.assertEqual(
            module.feature_state(features, module.GRO_FEATURES),
            {
                "state": "enabled",
                "reported_features": ["generic-receive-offload", "rx-udp-gro-forwarding"],
                "enabled_features": ["generic-receive-offload"],
            },
        )

    def test_missing_features_are_not_reported_as_disabled(self) -> None:
        """A link driver that omits a feature group is distinct from one disabling it."""
        module = self.module()
        self.assertEqual(
            module.feature_state({}, module.GSO_FEATURES),
            {"state": "not-reported", "reported_features": [], "enabled_features": []},
        )


if __name__ == "__main__":
    unittest.main()
