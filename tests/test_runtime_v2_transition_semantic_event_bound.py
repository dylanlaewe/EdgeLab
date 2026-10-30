"""Boundary evidence for the transition semantic-event construction limit."""
from __future__ import annotations

import unittest

from src.edgelab import runtime_v2_transition as transition


def valid_event_ids(count: int) -> tuple[str, ...]:
    return tuple(
        f"{index:08x}-0000-4000-8000-{index:012x}"
        for index in range(count)
    )


def valid_arguments(count: int) -> tuple[tuple[str, object], ...]:
    return tuple((f"argument-{index:02d}", index) for index in range(count))


class RuntimeV2TransitionSemanticEventBoundTests(unittest.TestCase):
    def assert_denied(
        self,
        expected: tuple[str, str],
        *args: object,
        **kwargs: object,
    ) -> transition.TransitionViolation:
        with self.assertRaises(transition.TransitionViolation) as captured:
            transition.TransitionIntent(*args, **kwargs)
        self.assertEqual(
            (captured.exception.code, captured.exception.coordinate),
            expected,
        )
        self.assertEqual(
            str(captured.exception),
            f"{expected[0]}:{expected[1]}",
        )
        return captured.exception

    def test_exact_constant_is_the_inclusive_constructor_maximum(self):
        self.assertIs(type(transition.MAX_GROUP_EVENTS), int)
        self.assertEqual(transition.MAX_GROUP_EVENTS, 10_002)

    def test_boundary_matrix_retains_exact_admitted_tuple(self):
        maximum = transition.MAX_GROUP_EVENTS
        for count in (maximum - 1, maximum, maximum + 1):
            with self.subTest(count=count):
                supplied = valid_event_ids(count)
                if count <= maximum:
                    intent = transition.TransitionIntent(
                        "EVIDENCE_ONLY", semantic_event_ids=supplied
                    )
                    self.assertIs(intent.semantic_event_ids, supplied)
                    self.assertEqual(intent.semantic_event_ids, supplied)
                    self.assertEqual(len(intent.semantic_event_ids), count)
                else:
                    self.assert_denied(
                        ("TRANSITION_RESOURCE_EVENTS", "/semantic_event_ids"),
                        "EVIDENCE_ONLY",
                        semantic_event_ids=supplied,
                    )

    def test_exact_tuple_guard_precedes_hostile_length_and_iteration(self):
        class HostileTuple(tuple):
            length_calls = 0
            iteration_calls = 0

            def __len__(self):
                type(self).length_calls += 1
                raise AssertionError("tuple-subclass length inspected")

            def __iter__(self):
                type(self).iteration_calls += 1
                raise AssertionError("tuple-subclass iteration inspected")

        supplied = HostileTuple()
        self.assert_denied(
            ("TRANSITION_CONTAINER_TYPE", "/"),
            "EVIDENCE_ONLY",
            semantic_event_ids=supplied,
        )
        self.assertEqual(HostileTuple.length_calls, 0)
        self.assertEqual(HostileTuple.iteration_calls, 0)

        self.assert_denied(
            ("TRANSITION_CONTAINER_TYPE", "/"),
            "EVIDENCE_ONLY",
            semantic_event_ids=[],
        )

    def test_resource_bound_precedes_member_validation(self):
        oversized_malformed = (object(),) * (transition.MAX_GROUP_EVENTS + 1)
        self.assert_denied(
            ("TRANSITION_RESOURCE_EVENTS", "/semantic_event_ids"),
            "EVIDENCE_ONLY",
            semantic_event_ids=oversized_malformed,
        )

        admitted_malformed = (
            *valid_event_ids(transition.MAX_GROUP_EVENTS - 1),
            "not-a-uuid",
        )
        self.assert_denied(
            ("TRANSITION_TEXT", "/semantic_event_ids"),
            "EVIDENCE_ONLY",
            semantic_event_ids=admitted_malformed,
        )

    def test_operation_container_and_argument_guards_have_precedence(self):
        oversized = valid_event_ids(transition.MAX_GROUP_EVENTS + 1)
        self.assert_denied(
            ("TRANSITION_OPERATION_TYPE", "/operation"),
            None,
            semantic_event_ids=oversized,
        )
        self.assert_denied(
            ("TRANSITION_CONTAINER_TYPE", "/"),
            "EVIDENCE_ONLY",
            arguments=[],
            semantic_event_ids=oversized,
        )
        self.assert_denied(
            ("TRANSITION_RESOURCE_ARGUMENTS", "/arguments"),
            "EVIDENCE_ONLY",
            arguments=valid_arguments(transition.MAX_ARGUMENTS + 1),
            semantic_event_ids=oversized,
        )

    def test_empty_and_duplicate_valid_ids_are_constructor_admissible(self):
        empty: tuple[str, ...] = ()
        empty_intent = transition.TransitionIntent(
            "EVIDENCE_ONLY", semantic_event_ids=empty
        )
        self.assertIs(empty_intent.semantic_event_ids, empty)

        repeated = (valid_event_ids(1)[0],) * transition.MAX_GROUP_EVENTS
        duplicate_intent = transition.TransitionIntent(
            "EVIDENCE_ONLY", semantic_event_ids=repeated
        )
        self.assertIs(duplicate_intent.semantic_event_ids, repeated)
        with self.assertRaises(transition.TransitionViolation) as captured:
            transition._expect_events(duplicate_intent, len(repeated))
        self.assertEqual(
            (captured.exception.code, captured.exception.coordinate),
            ("TRANSITION_EVENT_DUPLICATE", "/semantic_event_ids"),
        )

    def test_constructor_maximum_is_not_a_valid_operation_count(self):
        supplied = valid_event_ids(transition.MAX_GROUP_EVENTS)
        intent = transition.TransitionIntent(
            "IMPORT_REPOSITORY", semantic_event_ids=supplied
        )
        self.assertIs(intent.semantic_event_ids, supplied)
        with self.assertRaises(transition.TransitionViolation) as captured:
            transition._expect_events(intent, 10_001)
        self.assertEqual(
            (captured.exception.code, captured.exception.coordinate),
            ("TRANSITION_EVENT_COUNT", "/semantic_event_ids"),
        )

    def test_overflow_rejection_is_deterministic_and_exact(self):
        supplied = valid_event_ids(transition.MAX_GROUP_EVENTS + 1)
        outcomes: list[tuple[str, str, str]] = []
        for _ in range(3):
            error = self.assert_denied(
                ("TRANSITION_RESOURCE_EVENTS", "/semantic_event_ids"),
                "EVIDENCE_ONLY",
                semantic_event_ids=supplied,
            )
            outcomes.append((error.code, error.coordinate, str(error)))
        self.assertEqual(
            outcomes,
            [
                (
                    "TRANSITION_RESOURCE_EVENTS",
                    "/semantic_event_ids",
                    "TRANSITION_RESOURCE_EVENTS:/semantic_event_ids",
                )
            ] * 3,
        )

    def test_constructor_admission_grants_no_authority_or_mutation(self):
        supplied = valid_event_ids(transition.MAX_GROUP_EVENTS)
        intent = transition.TransitionIntent(
            "EVIDENCE_ONLY", semantic_event_ids=supplied
        )
        self.assertIs(intent.semantic_event_ids, supplied)
        self.assertEqual(intent.operation, "EVIDENCE_ONLY")
        self.assertFalse(hasattr(intent, "approved"))
        self.assertFalse(hasattr(intent, "authority"))


if __name__ == "__main__":
    unittest.main()
