"""Boundary evidence for the private runtime-v2 path-component limit."""
from __future__ import annotations

import builtins
import unittest
from unittest.mock import patch

from src.edgelab import runtime_v2_closure as closure


COORDINATE = "/evidence/component"


class RuntimeV2PortableComponentBoundTests(unittest.TestCase):
    def assert_denied(
        self,
        supplied: object,
        code: str,
        coordinate: str = COORDINATE,
    ) -> closure.ClosureValidationError:
        with self.assertRaises(closure.ClosureValidationError) as captured:
            closure._path(supplied, coordinate)
        self.assertEqual(captured.exception.code, code)
        self.assertEqual(captured.exception.coordinate, coordinate)
        self.assertEqual(str(captured.exception), f"{code}:{coordinate}")
        return captured.exception

    def test_exact_constant_is_the_inclusive_character_maximum(self):
        self.assertIs(type(closure._PORTABLE_COMPONENT_MAX), int)
        self.assertEqual(closure._PORTABLE_COMPONENT_MAX, 255)

    def test_boundary_matrix_retains_exact_admitted_string(self):
        maximum = closure._PORTABLE_COMPONENT_MAX
        for count in (maximum - 1, maximum, maximum + 1):
            with self.subTest(count=count):
                supplied = "a" * count
                self.assertLess(len(supplied), closure._PORTABLE_PATH_MAX)
                if count <= maximum:
                    admitted = closure._path(supplied, COORDINATE)
                    self.assertIs(admitted, supplied)
                else:
                    self.assert_denied(supplied, "PATH_LENGTH")

    def test_first_middle_and_last_overflow_are_rejected(self):
        oversized = "x" * (closure._PORTABLE_COMPONENT_MAX + 1)
        for supplied in (
            f"{oversized}/a/b",
            f"a/{oversized}/b",
            f"a/b/{oversized}",
        ):
            with self.subTest(position=supplied.index(oversized)):
                self.assertLess(len(supplied), closure._PORTABLE_PATH_MAX)
                self.assert_denied(supplied, "PATH_LENGTH")

    def test_multiple_maximum_components_exclude_separators(self):
        components = tuple(chr(ord("a") + index) * 255 for index in range(4))
        supplied = "/".join(components)
        self.assertEqual(tuple(map(len, supplied.split("/"))), (255,) * 4)
        self.assertEqual(len(supplied), 4 * 255 + 3)
        self.assertIs(closure._path(supplied, COORDINATE), supplied)

    def test_total_overflow_short_circuits_before_component_generator(self):
        supplied = "/".join(("a" * 255,) * 17)
        self.assertGreater(len(supplied), closure._PORTABLE_PATH_MAX)
        calls: list[object] = []

        def observed_len(value: object) -> int:
            calls.append(value)
            return builtins.len(value)  # type: ignore[arg-type]

        with patch.object(closure, "len", observed_len, create=True):
            self.assert_denied(supplied, "PATH_LENGTH")
        self.assertEqual(calls, [supplied])

    def test_component_generator_stops_at_first_overflow(self):
        components = ("a", "b" * 256, "c")
        supplied = "/".join(components)
        calls: list[object] = []

        def observed_len(value: object) -> int:
            calls.append(value)
            return builtins.len(value)  # type: ignore[arg-type]

        with patch.object(closure, "len", observed_len, create=True):
            self.assert_denied(supplied, "PATH_LENGTH")
        self.assertEqual(calls, [supplied, components[0], components[1]])

    def test_component_generator_inspects_all_components_on_admission(self):
        components = ("a", "bb", "ccc")
        supplied = "/".join(components)
        calls: list[object] = []

        def observed_len(value: object) -> int:
            calls.append(value)
            return builtins.len(value)  # type: ignore[arg-type]

        with patch.object(closure, "len", observed_len, create=True):
            admitted = closure._path(supplied, COORDINATE)
        self.assertIs(admitted, supplied)
        self.assertEqual(calls, [supplied, *components])

    def test_pattern_guards_precede_component_measurement(self):
        class LengthMustNotRun(str):
            calls = 0

            def __len__(self):
                type(self).calls += 1
                raise AssertionError("string-subclass length was inspected")

        self.assert_denied(LengthMustNotRun("valid/path"), "PATTERN")
        self.assertEqual(LengthMustNotRun.calls, 0)
        for supplied in (None, b"valid/path", "a//b", "../a", "snowman-☃"):
            with self.subTest(supplied=supplied):
                self.assert_denied(supplied, "PATTERN")

    def test_total_path_and_later_portability_rules_remain_independent(self):
        valid_components_total_overflow = "/".join(("a" * 255,) * 17)
        self.assertTrue(
            all(
                len(component) <= closure._PORTABLE_COMPONENT_MAX
                for component in valid_components_total_overflow.split("/")
            )
        )
        self.assert_denied(valid_components_total_overflow, "PATH_LENGTH")

        for supplied in ("a" * 254 + ".", "valid/CON.txt"):
            with self.subTest(supplied=supplied[-12:]):
                self.assertLessEqual(
                    max(map(len, supplied.split("/"))),
                    closure._PORTABLE_COMPONENT_MAX,
                )
                self.assert_denied(supplied, "PATH_PORTABILITY")

    def test_rejection_is_deterministic_and_preserves_coordinate(self):
        supplied = "a/" + "b" * 256 + "/c"
        coordinate = "/caller/supplied/component"
        outcomes: list[tuple[str, str, str]] = []
        for _ in range(3):
            error = self.assert_denied(supplied, "PATH_LENGTH", coordinate)
            outcomes.append((error.code, error.coordinate, str(error)))
        self.assertEqual(
            outcomes,
            [("PATH_LENGTH", coordinate, f"PATH_LENGTH:{coordinate}")] * 3,
        )

    def test_successful_private_validation_grants_no_authority(self):
        supplied = "a" * closure._PORTABLE_COMPONENT_MAX
        admitted = closure._path(supplied, COORDINATE)
        self.assertIs(admitted, supplied)
        self.assertFalse(hasattr(admitted, "approved"))
        self.assertFalse(hasattr(admitted, "authority"))


if __name__ == "__main__":
    unittest.main()
