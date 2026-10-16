"""Deterministic coverage and isolation checks for the tiered test runner."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.run_test_tier import (
    DOMAIN_MODULES,
    FAST_MODULES,
    HISTORICAL_MODULES,
    TIER_ORDER,
    continues_after_failure,
    discover_modules,
    exclusive_run,
    selected_modules,
    tiers,
    unittest_command,
)


class TestTierTests(unittest.TestCase):
    def test_assignments_are_disjoint_and_cover_every_test_module(self):
        configured = tiers()
        assigned = [module for name in TIER_ORDER for module in configured[name]]
        self.assertEqual(len(assigned), len(set(assigned)))
        self.assertEqual(set(assigned), set(discover_modules()))
        self.assertEqual(configured["fast"], FAST_MODULES)
        self.assertEqual(configured["domain"], DOMAIN_MODULES)
        self.assertEqual(configured["historical"], HISTORICAL_MODULES)
        self.assertEqual(selected_modules("all"), tuple(assigned))

    def test_new_unclassified_module_is_denied(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tests = root / "tests"
            tests.mkdir()
            for module in (*FAST_MODULES, *DOMAIN_MODULES, *HISTORICAL_MODULES):
                (tests / f"{module.rsplit('.', 1)[1]}.py").touch()
            (tests / "test_new_control.py").touch()
            with self.assertRaisesRegex(RuntimeError, "Unclassified test modules"):
                tiers(root)

    def test_isolated_command_uses_file_discovery_for_legacy_imports(self):
        command = unittest_command("tests.test_quant_protocol")
        self.assertEqual(command[2:8], ["unittest", "discover", "-s", "tests", "-p", "test_quant_protocol.py"])

    def test_only_historical_modules_continue_after_failure(self):
        self.assertTrue(continues_after_failure("tests.test_research_protocol"))
        self.assertFalse(continues_after_failure("tests.test_data_integrity"))

    def test_second_tiered_run_is_denied_while_lock_is_held(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with exclusive_run(root):
                with self.assertRaisesRegex(RuntimeError, "concurrent runs are denied"):
                    with exclusive_run(root):
                        self.fail("nested run unexpectedly acquired the lock")


if __name__ == "__main__":
    unittest.main()
