"""Boundary evidence for the private runtime-v2 portable-path limit."""
from __future__ import annotations

import unittest

from src.edgelab import runtime_v2_closure as closure


COORDINATE = "/evidence/path"


def valid_path(character_count: int) -> str:
    """Return a valid portable path with no component above 255 characters."""
    if character_count < 1:
        raise ValueError("positive character count required")
    component_count = (character_count + 256) // 256
    content_characters = character_count - (component_count - 1)
    components: list[str] = []
    remaining = content_characters
    character = ord("a")
    for index in range(component_count):
        remaining_components = component_count - index - 1
        component_length = min(255, remaining - remaining_components)
        components.append(chr(character) * component_length)
        remaining -= component_length
        character += 1
    if remaining != 0:
        raise AssertionError("fixture allocation mismatch")
    result = "/".join(components)
    if len(result) != character_count:
        raise AssertionError("fixture length mismatch")
    if any(len(component) > 255 for component in components):
        raise AssertionError("fixture crossed sibling component limit")
    return result


class RuntimeV2PortablePathBoundTests(unittest.TestCase):
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
        self.assertEqual(closure._PORTABLE_PATH_MAX, 4_096)

    def test_boundary_matrix_retains_exact_admitted_string(self):
        maximum = closure._PORTABLE_PATH_MAX
        for count in (maximum - 1, maximum, maximum + 1):
            with self.subTest(count=count):
                supplied = valid_path(count)
                self.assertIs(type(supplied), str)
                self.assertEqual(len(supplied), count)
                self.assertTrue(
                    all(len(component) <= 255 for component in supplied.split("/"))
                )
                if count <= maximum:
                    admitted = closure._path(supplied, COORDINATE)
                    self.assertIs(admitted, supplied)
                    self.assertEqual(admitted, supplied)
                else:
                    self.assert_denied(supplied, "PATH_LENGTH")

    def test_exact_maximum_fixture_has_the_documented_component_shape(self):
        supplied = valid_path(closure._PORTABLE_PATH_MAX)
        components = supplied.split("/")
        self.assertEqual(len(components), 17)
        self.assertEqual(tuple(map(len, components)), (255,) * 15 + (254, 1))
        self.assertIs(closure._path(supplied, COORDINATE), supplied)

    def test_hostile_string_subclass_is_rejected_before_length_inspection(self):
        class LengthMustNotRun(str):
            calls = 0

            def __len__(self):
                type(self).calls += 1
                raise AssertionError("string-subclass length was inspected")

        supplied = LengthMustNotRun("valid/path")
        self.assert_denied(supplied, "PATTERN")
        self.assertEqual(LengthMustNotRun.calls, 0)

    def test_plain_non_strings_are_rejected_by_exact_pattern_guard(self):
        for supplied in (None, b"valid/path", ["valid", "path"], 4_096):
            with self.subTest(supplied_type=type(supplied)):
                self.assert_denied(supplied, "PATTERN")

    def test_pattern_rejection_precedes_total_length_inspection(self):
        self.assert_denied("", "PATTERN")
        for supplied in (
            "/" + "a" * 4_096,
            "a//" + "b" * 4_096,
            "../" + "a" * 4_096,
            "snowman-☃" + "a" * 4_096,
        ):
            with self.subTest(prefix=supplied[:12]):
                self.assertGreater(len(supplied), closure._PORTABLE_PATH_MAX - 1)
                self.assert_denied(supplied, "PATTERN")

    def test_sibling_component_and_portability_rules_remain_independent(self):
        component_overflow = "a" * 256
        self.assertLess(len(component_overflow), closure._PORTABLE_PATH_MAX)
        self.assert_denied(component_overflow, "PATH_LENGTH")

        for supplied in ("valid/component.", "valid/CON.txt"):
            with self.subTest(supplied=supplied):
                self.assertLess(len(supplied), closure._PORTABLE_PATH_MAX)
                self.assert_denied(supplied, "PATH_PORTABILITY")

    def test_total_overflow_rejection_is_deterministic_and_preserves_coordinate(self):
        supplied = valid_path(closure._PORTABLE_PATH_MAX + 1)
        coordinate = "/caller/supplied/coordinate"
        outcomes: list[tuple[str, str, str]] = []
        for _ in range(3):
            error = self.assert_denied(supplied, "PATH_LENGTH", coordinate)
            outcomes.append((error.code, error.coordinate, str(error)))
        self.assertEqual(
            outcomes,
            [
                (
                    "PATH_LENGTH",
                    coordinate,
                    f"PATH_LENGTH:{coordinate}",
                )
            ] * 3,
        )

    def test_successful_private_path_validation_grants_no_external_effect(self):
        supplied = valid_path(closure._PORTABLE_PATH_MAX)
        before = supplied
        admitted = closure._path(supplied, COORDINATE)

        self.assertIs(admitted, before)
        self.assertEqual(admitted, before)
        self.assertIs(type(admitted), str)
        self.assertFalse(hasattr(admitted, "approved"))
        self.assertFalse(hasattr(admitted, "authority"))


if __name__ == "__main__":
    unittest.main()
