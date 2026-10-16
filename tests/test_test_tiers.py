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
from tools.verify_historical_outcomes import (
    HistoricalOutcomeError,
    _diagnostic_sha256,
    parse_observation,
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

    def test_historical_observation_parser_captures_exact_nonpasses(self):
        blocks = []
        for index, module in enumerate(HISTORICAL_MODULES, 1):
            if index == 1:
                body = (
                    "test_one (case.Tests.test_one) ... FAIL\n"
                    "test_two (case.Tests.test_two) ... ERROR\n\n"
                    "======================================================================\n"
                    "FAIL: test_one (case.Tests.test_one) (state='A')\n"
                    "----------------------------------------------------------------------\n"
                    "Traceback (most recent call last):\nAssertionError: one\n\n"
                    "======================================================================\n"
                    "ERROR: test_two (case.Tests.test_two)\n"
                    "----------------------------------------------------------------------\n"
                    "Traceback (most recent call last):\nValueError: two\n\n"
                    "----------------------------------------------------------------------\n"
                    "Ran 2 tests in 0.001s\n\n"
                    "FAILED (failures=1, errors=1)\n"
                )
                exit_code = 1
            else:
                body = "Ran 1 test in 0.001s\n\nOK\n"
                exit_code = 0
            blocks.append(
                f"[{index}/{len(HISTORICAL_MODULES)}] {module}\n"
                f"{body}{module}: exit {exit_code} in 0.002s\n"
            )
        blocks.append(
            "Tier historical completed with failures in 1.000s:\n"
            f"  {HISTORICAL_MODULES[0]}: exit 1\n"
        )
        observed = parse_observation(
            f"EdgeLab test tier: historical ({len(HISTORICAL_MODULES)} isolated modules)\n"
            + "".join(blocks)
        )
        self.assertEqual(len(observed), len(HISTORICAL_MODULES))
        self.assertEqual(observed[0]["tests"], 2)
        self.assertEqual(observed[0]["failures"], 1)
        self.assertEqual(observed[0]["errors"], 1)
        self.assertEqual(
            observed[0]["nonpasses"],
            [
                {
                    "outcome": "FAIL",
                    "test_identity": "test_one (case.Tests.test_one) (state='A')",
                    "diagnostic_sha256": observed[0]["nonpasses"][0]["diagnostic_sha256"],
                },
                {
                    "outcome": "ERROR",
                    "test_identity": "test_two (case.Tests.test_two)",
                    "diagnostic_sha256": observed[0]["nonpasses"][1]["diagnostic_sha256"],
                },
            ],
        )

    def test_historical_observation_parser_denies_incomplete_run(self):
        module = HISTORICAL_MODULES[0]
        with self.assertRaisesRegex(HistoricalOutcomeError, "order or completeness"):
            parse_observation(
                f"EdgeLab test tier: historical ({len(HISTORICAL_MODULES)} isolated modules)\n"
                f"[1/{len(HISTORICAL_MODULES)}] {module}\n"
                f"Ran 1 test in 0.001s\n\nOK\n{module}: exit 0 in 0.002s\n"
            )

    def test_historical_observation_parser_denies_count_identity_mismatch(self):
        blocks = []
        for index, module in enumerate(HISTORICAL_MODULES, 1):
            body = "Ran 1 test in 0.001s\n\nOK\n"
            exit_code = 0
            if index == 1:
                body = (
                    "======================================================================\n"
                    "ERROR: test_one (case.Tests.test_one)\n"
                    "----------------------------------------------------------------------\n"
                    "Traceback (most recent call last):\nValueError: one\n\n"
                    "----------------------------------------------------------------------\n"
                    "Ran 1 test in 0.001s\n\nFAILED (errors=2)\n"
                )
                exit_code = 1
            blocks.append(
                f"[{index}/{len(HISTORICAL_MODULES)}] {module}\n"
                f"{body}{module}: exit {exit_code} in 0.002s\n"
            )
        with self.assertRaisesRegex(HistoricalOutcomeError, "traceback identities"):
            parse_observation(
                f"EdgeLab test tier: historical ({len(HISTORICAL_MODULES)} isolated modules)\n"
                + "".join(blocks)
                + "Tier historical completed with failures in 1.000s:\n"
                + f"  {HISTORICAL_MODULES[0]}: exit 1\n"
            )

    def test_historical_diagnostic_hash_normalizes_root_but_not_cause(self):
        first = _diagnostic_sha256(f'  File "{Path.cwd()}/tests/test_x.py"\nValueError: one')
        same = _diagnostic_sha256(f'  File "{Path.cwd().resolve()}/tests/test_x.py"\nValueError: one')
        changed = _diagnostic_sha256(
            f'  File "{Path.cwd()}/tests/test_x.py"\nRuntimeError: one'
        )
        self.assertEqual(first, same)
        self.assertNotEqual(first, changed)


if __name__ == "__main__":
    unittest.main()
