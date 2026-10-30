"""Boundary evidence for the transition task-record resource maximum."""
from __future__ import annotations

import unittest

from src.edgelab import runtime_v2_transition as transition


DIGEST = "a" * 64


def uuid4(number: int) -> str:
    return f"00000000-0000-4000-8000-{number:012x}"


def task(task_id: str) -> transition.TaskState:
    empty = transition.ReducerState(0, DIGEST)
    intent = transition.TransitionIntent(
        "INITIALIZE",
        task_id=task_id,
        attempt=1,
        arguments=(
            ("decision_receipt_digest", DIGEST),
            ("owner", "owner-fixture"),
            ("owner_role", "03 Research"),
        ),
        semantic_event_ids=(uuid4(1),),
    )
    return transition.reduce_transition(empty, intent).tasks[0]


def delta(
    write: transition._TaskWrite,
) -> transition._TransitionDelta:
    return transition._TransitionDelta(
        task_writes=(write,),
        claim_writes=(),
        review_writes=(),
        decision_writes=(),
        after_task=write.after,
    )


class ReportedLengthTasks(dict[str, transition.TaskState]):
    """Small exact fixture with a controlled resource-accounting length."""

    def __init__(
        self,
        values: dict[str, transition.TaskState],
        reported_length: int,
    ) -> None:
        super().__init__(values)
        self.reported_length = reported_length

    def __len__(self) -> int:
        return self.reported_length


class RuntimeV2TransitionTaskBoundTests(unittest.TestCase):
    def assert_violation(
        self,
        expected: tuple[str, str],
        action,
    ) -> transition.TransitionViolation:
        with self.assertRaises(transition.TransitionViolation) as captured:
            action()
        self.assertEqual(
            (captured.exception.code, captured.exception.coordinate),
            expected,
        )
        self.assertEqual(
            str(captured.exception),
            f"{expected[0]}:{expected[1]}",
        )
        return captured.exception

    def test_exact_constant_is_the_inclusive_task_record_maximum(self):
        self.assertIs(type(transition.MAX_TASKS), int)
        self.assertEqual(transition.MAX_TASKS, 100_000)

    def test_state_boundary_precedes_member_validation(self):
        maximum = transition.MAX_TASKS
        malformed = object()
        for count in (maximum - 1, maximum):
            with self.subTest(count=count):
                supplied = (malformed,) * count
                self.assert_violation(
                    ("TRANSITION_MEMBER_TYPE", "/tasks/0"),
                    lambda supplied=supplied: transition.ReducerState(
                        0, DIGEST, tasks=supplied
                    ),
                )

        supplied = (malformed,) * (maximum + 1)
        self.assert_violation(
            ("TRANSITION_RESOURCE_TASKS", "/tasks"),
            lambda: transition.ReducerState(0, DIGEST, tasks=supplied),
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
        self.assert_violation(
            ("TRANSITION_CONTAINER_TYPE", "/tasks"),
            lambda: transition.ReducerState(0, DIGEST, tasks=supplied),
        )
        self.assertEqual(HostileTuple.length_calls, 0)
        self.assertEqual(HostileTuple.iteration_calls, 0)
        self.assert_violation(
            ("TRANSITION_CONTAINER_TYPE", "/tasks"),
            lambda: transition.ReducerState(0, DIGEST, tasks=[]),
        )

    def test_workspace_boundary_counts_only_genuinely_new_task_keys(self):
        maximum = transition.MAX_TASKS
        existing = task("T1")
        replacement = transition._TaskWrite("T1", existing, existing)
        workspace = transition._TransitionWorkspace(
            transition.ReducerState(0, DIGEST)
        )
        workspace._tasks = ReportedLengthTasks({"T1": existing}, maximum)
        workspace._precheck(delta(replacement))
        self.assertIs(workspace._tasks["T1"], existing)

        new_task = task("T2")
        addition = transition._TaskWrite("T2", None, new_task)
        workspace._tasks = ReportedLengthTasks({}, maximum - 1)
        workspace._precheck(delta(addition))
        self.assertNotIn("T2", workspace._tasks)

        workspace._tasks = ReportedLengthTasks({}, maximum)
        self.assert_violation(
            ("TRANSITION_RESOURCE_TASKS", "/tasks"),
            lambda: workspace._precheck(delta(addition)),
        )
        self.assertNotIn("T2", workspace._tasks)

    def test_workspace_write_shape_and_cas_precede_resource_evaluation(self):
        maximum = transition.MAX_TASKS
        existing = task("T1")
        workspace = transition._TransitionWorkspace(
            transition.ReducerState(0, DIGEST)
        )
        workspace._tasks = ReportedLengthTasks({"T1": existing}, maximum)

        wrong_key = transition._TaskWrite("WRONG", None, existing)
        self.assert_violation(
            ("TRANSITION_WORKSPACE_PLAN", "/tasks"),
            lambda: workspace._precheck(delta(wrong_key)),
        )

        stale = transition._TaskWrite("T1", None, existing)
        self.assert_violation(
            ("TRANSITION_WORKSPACE_CAS", "/tasks/T1"),
            lambda: workspace._precheck(delta(stale)),
        )

    def test_workspace_plan_shape_precedes_resource_evaluation(self):
        maximum = transition.MAX_TASKS
        existing = task("T1")
        workspace = transition._TransitionWorkspace(
            transition.ReducerState(0, DIGEST)
        )
        workspace._tasks = ReportedLengthTasks({"T1": existing}, maximum + 1)
        empty_delta = transition._TransitionDelta((), (), (), (), existing)
        self.assert_violation(
            ("TRANSITION_WORKSPACE_PLAN", "/"),
            lambda: workspace._precheck(empty_delta),
        )

    def test_workspace_resource_rejection_is_deterministic_and_read_only(self):
        maximum = transition.MAX_TASKS
        new_task = task("T2")
        addition = transition._TaskWrite("T2", None, new_task)
        workspace = transition._TransitionWorkspace(
            transition.ReducerState(0, DIGEST)
        )
        reported = ReportedLengthTasks({}, maximum)
        workspace._tasks = reported
        before_revision = workspace.revision
        outcomes: list[tuple[str, str, str]] = []
        for _ in range(3):
            error = self.assert_violation(
                ("TRANSITION_RESOURCE_TASKS", "/tasks"),
                lambda: workspace._precheck(delta(addition)),
            )
            outcomes.append((error.code, error.coordinate, str(error)))
        self.assertEqual(
            outcomes,
            [
                (
                    "TRANSITION_RESOURCE_TASKS",
                    "/tasks",
                    "TRANSITION_RESOURCE_TASKS:/tasks",
                )
            ] * 3,
        )
        self.assertIs(workspace._tasks, reported)
        self.assertEqual(dict(workspace._tasks), {})
        self.assertEqual(workspace.revision, before_revision)

    def test_task_resource_admission_grants_no_authority(self):
        one_task = task("T1")
        state = transition.ReducerState(0, DIGEST, tasks=(one_task,))
        self.assertIs(state.tasks[0], one_task)
        self.assertFalse(hasattr(state, "approved"))
        self.assertFalse(hasattr(state, "authority"))
        workspace = transition._TransitionWorkspace(state)
        self.assertFalse(hasattr(workspace, "approved"))
        self.assertFalse(hasattr(workspace, "authority"))


if __name__ == "__main__":
    unittest.main()
