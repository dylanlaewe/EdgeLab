"""Boundary evidence for the private runtime-v2 transition argument limit."""
from __future__ import annotations

import unittest

from src.edgelab.runtime_v2_transition import (
    MAX_ARGUMENTS,
    ReducerState,
    TransitionIntent,
    TransitionViolation,
    reduce_transition,
)


def valid_arguments(count: int) -> tuple[tuple[str, object], ...]:
    """Return a sorted, unique, well-shaped exact tuple of the requested size."""
    return tuple((f"argument-{index:02d}", index) for index in range(count))


class RuntimeV2TransitionArgumentBoundTests(unittest.TestCase):
    def test_exact_constant_is_the_inclusive_eight_item_maximum(self):
        self.assertEqual(MAX_ARGUMENTS, 8)

    def test_boundary_matrix_retains_exact_admitted_tuple(self):
        maximum = MAX_ARGUMENTS
        for count in (maximum - 1, maximum, maximum + 1):
            with self.subTest(count=count):
                supplied = valid_arguments(count)
                if count <= maximum:
                    intent = TransitionIntent("EVIDENCE_ONLY", arguments=supplied)
                    self.assertIs(intent.arguments, supplied)
                    self.assertEqual(intent.arguments, supplied)
                    self.assertEqual(len(intent.arguments), count)
                    self.assertEqual(
                        tuple(key for key, _ in intent.arguments),
                        tuple(key for key, _ in supplied),
                    )
                else:
                    with self.assertRaises(TransitionViolation) as captured:
                        TransitionIntent("EVIDENCE_ONLY", arguments=supplied)
                    self.assertEqual(
                        (captured.exception.code, captured.exception.coordinate),
                        ("TRANSITION_RESOURCE_ARGUMENTS", "/arguments"),
                    )

    def test_hostile_tuple_subclass_is_rejected_before_length_inspection(self):
        class LengthMustNotRun(tuple):
            calls = 0

            def __len__(self):
                self.calls += 1
                raise AssertionError("tuple-subclass length was inspected")

        supplied = LengthMustNotRun()
        with self.assertRaises(TransitionViolation) as captured:
            TransitionIntent("EVIDENCE_ONLY", arguments=supplied)
        self.assertEqual(
            (captured.exception.code, captured.exception.coordinate),
            ("TRANSITION_CONTAINER_TYPE", "/"),
        )
        self.assertEqual(supplied.calls, 0)

    def test_plain_non_tuple_is_rejected_by_exact_container_guard(self):
        supplied = object()
        with self.assertRaises(TransitionViolation) as captured:
            TransitionIntent("EVIDENCE_ONLY", arguments=supplied)
        self.assertEqual(
            (captured.exception.code, captured.exception.coordinate),
            ("TRANSITION_CONTAINER_TYPE", "/"),
        )

    def test_resource_bound_precedes_member_shape_validation(self):
        oversized_malformed = tuple(object() for _ in range(MAX_ARGUMENTS + 1))
        with self.assertRaises(TransitionViolation) as captured:
            TransitionIntent("EVIDENCE_ONLY", arguments=oversized_malformed)
        self.assertEqual(
            (captured.exception.code, captured.exception.coordinate),
            ("TRANSITION_RESOURCE_ARGUMENTS", "/arguments"),
        )

        admitted_malformed = tuple(object() for _ in range(MAX_ARGUMENTS))
        with self.assertRaises(TransitionViolation) as captured:
            TransitionIntent("EVIDENCE_ONLY", arguments=admitted_malformed)
        self.assertEqual(
            (captured.exception.code, captured.exception.coordinate),
            ("TRANSITION_ARGUMENT_SHAPE", "/arguments"),
        )

    def test_at_limit_order_and_uniqueness_rules_follow_size_admission(self):
        reverse_sorted = tuple(reversed(valid_arguments(MAX_ARGUMENTS)))
        duplicate_keys = tuple(
            ("duplicate", index) for index in range(MAX_ARGUMENTS)
        )
        for label, supplied in (
            ("reverse_sorted", reverse_sorted),
            ("duplicate_keys", duplicate_keys),
        ):
            with self.subTest(label=label):
                self.assertEqual(len(supplied), MAX_ARGUMENTS)
                with self.assertRaises(TransitionViolation) as captured:
                    TransitionIntent("EVIDENCE_ONLY", arguments=supplied)
                self.assertEqual(
                    (captured.exception.code, captured.exception.coordinate),
                    ("TRANSITION_ARGUMENT_SHAPE", "/arguments"),
                )

    def test_argument_limit_is_independent_of_semantic_event_subject(self):
        supplied = valid_arguments(MAX_ARGUMENTS)
        event_ids = (
            "00000000-0000-4000-8000-000000000001",
            "00000000-0000-4000-8000-000000000002",
        )
        intent = TransitionIntent(
            "EVIDENCE_ONLY",
            arguments=supplied,
            semantic_event_ids=event_ids,
        )
        self.assertIs(intent.arguments, supplied)
        self.assertIs(intent.semantic_event_ids, event_ids)

        with self.assertRaises(TransitionViolation) as captured:
            TransitionIntent(
                "EVIDENCE_ONLY",
                arguments=valid_arguments(MAX_ARGUMENTS + 1),
                semantic_event_ids=(),
            )
        self.assertEqual(
            (captured.exception.code, captured.exception.coordinate),
            ("TRANSITION_RESOURCE_ARGUMENTS", "/arguments"),
        )

    def test_overflow_rejection_is_deterministic_and_exact(self):
        supplied = valid_arguments(MAX_ARGUMENTS + 1)
        outcomes: list[tuple[str, str, str]] = []
        for _ in range(3):
            with self.assertRaises(TransitionViolation) as captured:
                TransitionIntent("EVIDENCE_ONLY", arguments=supplied)
            outcomes.append((
                captured.exception.code,
                captured.exception.coordinate,
                str(captured.exception),
            ))
        self.assertEqual(
            outcomes,
            [
                (
                    "TRANSITION_RESOURCE_ARGUMENTS",
                    "/arguments",
                    "TRANSITION_RESOURCE_ARGUMENTS:/arguments",
                )
            ] * 3,
        )

    def test_maximum_size_construction_is_not_transition_authority(self):
        digest = "a" * 64
        initial_event = "00000000-0000-4000-8000-000000000001"
        unknown_event = "00000000-0000-4000-8000-000000000002"
        empty = ReducerState(0, digest)
        initialized = reduce_transition(
            empty,
            TransitionIntent(
                "INITIALIZE",
                task_id="T1",
                attempt=1,
                arguments=(
                    ("decision_receipt_digest", digest),
                    ("owner", "evidence-owner"),
                    ("owner_role", "03 Research"),
                ),
                semantic_event_ids=(initial_event,),
            ),
        )
        before = initialized
        maximum_sized = TransitionIntent(
            "EVIDENCE_ONLY",
            task_id="T1",
            attempt=1,
            arguments=valid_arguments(MAX_ARGUMENTS),
            semantic_event_ids=(unknown_event,),
        )

        with self.assertRaises(TransitionViolation) as captured:
            reduce_transition(initialized, maximum_sized)
        self.assertEqual(
            (captured.exception.code, captured.exception.coordinate),
            ("TRANSITION_OPERATION_OUTSIDE_CORE", "/operation"),
        )
        self.assertIs(initialized, before)
        self.assertEqual(initialized, before)
        self.assertEqual(initialized.repository_generation, 0)
        self.assertEqual(initialized.repository_bundle_sha256, digest)
        self.assertEqual(tuple(task.task_id for task in initialized.tasks), ("T1",))


if __name__ == "__main__":
    unittest.main()
