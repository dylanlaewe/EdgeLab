from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import ast
import unittest

from src.edgelab.runtime_v2_codec import remediation_link_digest
from src.edgelab.runtime_v2_transition import (
    ClaimRecord,
    INT64_MAX,
    ReducerState,
    ReviewDecision,
    ReviewRecord,
    TaskState,
    TransitionIntent,
    TransitionViolation,
    reduce_transition,
)


DIGEST = "a" * 64
OTHER_DIGEST = "b" * 64


def uuid4(number: int) -> str:
    return f"00000000-0000-4000-8000-{number:012x}"


def arguments(**values: object) -> tuple[tuple[str, object], ...]:
    return tuple(sorted(values.items()))


def intent(
    operation: str,
    *,
    task_id: str | None = "T1",
    attempt: int | None = 1,
    child_task_id: str | None = None,
    child_attempt: int | None = None,
    args: tuple[tuple[str, object], ...] = (),
    generated_id: str | None = None,
    events: tuple[str, ...] = (uuid4(1),),
    generation: int | None = None,
    bundle: str | None = None,
) -> TransitionIntent:
    return TransitionIntent(
        operation=operation,
        task_id=task_id,
        attempt=attempt,
        child_task_id=child_task_id,
        child_attempt=child_attempt,
        arguments=args,
        generated_id=generated_id,
        semantic_event_ids=events,
        candidate_repository_generation=generation,
        candidate_repository_bundle_sha256=bundle,
    )


def empty_state() -> ReducerState:
    return ReducerState(0, DIGEST)


def initialize(state: ReducerState, task_id: str = "T1") -> ReducerState:
    return reduce_transition(
        state,
        intent(
            "INITIALIZE",
            task_id=task_id,
            args=arguments(
                decision_receipt_digest=DIGEST,
                owner="owner-fixture",
                owner_role="03 Research",
            ),
        ),
    )


def claim(state: ReducerState, event: int = 2) -> ReducerState:
    task = state.tasks[0]
    return reduce_transition(
        state,
        intent(
            "CLAIM",
            attempt=task.attempt,
            args=arguments(actor="worker-fixture"),
            generated_id=uuid4(100),
            events=(uuid4(event),),
        ),
    )


def start(state: ReducerState, event: int = 3) -> ReducerState:
    task = state.tasks[0]
    return reduce_transition(
        state,
        intent(
            "START",
            attempt=task.attempt,
            args=arguments(claim_id=task.active_claim_id, fence=task.task_fence),
            events=(uuid4(event),),
        ),
    )


def complete_for_review(state: ReducerState, event: int = 4) -> ReducerState:
    task = state.tasks[0]
    return reduce_transition(
        state,
        intent(
            "COMPLETE",
            attempt=task.attempt,
            args=arguments(
                claim_id=task.active_claim_id,
                close=False,
                completion_evidence_sha256=DIGEST,
                fence=task.task_fence,
            ),
            events=(uuid4(event),),
        ),
    )


def assign_review(state: ReducerState, event: int = 5) -> ReducerState:
    task = state.tasks[0]
    return reduce_transition(
        state,
        intent(
            "ASSIGN_REVIEW",
            attempt=task.attempt,
            args=arguments(actor="skeptic-fixture", role="05 Skeptic"),
            generated_id=uuid4(200),
            events=(uuid4(event),),
        ),
    )


def state_for_code(code: str) -> ReducerState:
    state = initialize(empty_state())
    if code == "N0":
        return state
    state = claim(state)
    if code == "N1":
        return state
    state = start(state)
    if code == "N2":
        return state
    if code == "F0":
        task = state.tasks[0]
        return reduce_transition(
            state,
            intent(
                "FAIL",
                args=arguments(
                    claim_id=task.active_claim_id,
                    failure_code="FAILED",
                    failure_evidence_sha256=DIGEST,
                    fence=task.task_fence,
                ),
                events=(uuid4(4),),
            ),
        )
    if code == "C0":
        task = state.tasks[0]
        return reduce_transition(
            state,
            intent(
                "COMPLETE",
                args=arguments(
                    claim_id=task.active_claim_id,
                    close=True,
                    completion_evidence_sha256=DIGEST,
                    fence=task.task_fence,
                ),
                events=(uuid4(4),),
            ),
        )
    state = complete_for_review(state)
    if code == "N3":
        return state
    if code == "B1":
        return reduce_transition(
            state,
            intent(
                "GOVERNANCE_BLOCK",
                args=arguments(evidence_sha256=DIGEST, reason_code="BLOCK"),
                events=(uuid4(5),),
            ),
        )
    state = assign_review(state)
    if code == "N4":
        return state
    operation = {"N5": "REJECT", "N6": "REMEDIATE", "N7": "APPROVE", "N8": "APPROVE"}.get(code)
    if operation is not None:
        state = reduce_transition(
            state,
            intent(
                operation,
                args=arguments(
                    assignment_id=state.tasks[0].reviewer_assignment_id,
                    decision_sha256=OTHER_DIGEST,
                ),
                events=(uuid4(6),),
            ),
        )
        if code == "N8":
            state = reduce_transition(
                state,
                intent(
                    "ROUTE",
                    args=arguments(routing_evidence_sha256=DIGEST),
                    events=(uuid4(7),),
                ),
            )
        return state
    if code == "B0":
        return reduce_transition(
            initialize(empty_state()),
            intent(
                "GOVERNANCE_BLOCK",
                args=arguments(evidence_sha256=DIGEST, reason_code="BLOCK"),
                events=(uuid4(2),),
            ),
        )
    raise AssertionError(code)


class RuntimeV2TransitionTests(unittest.TestCase):
    def test_full_approved_route_lifecycle(self) -> None:
        state = start(claim(initialize(empty_state())))
        task = state.tasks[0]
        state = reduce_transition(
            state,
            intent(
                "CONTINUE",
                args=arguments(
                    claim_id=task.active_claim_id,
                    fence=task.task_fence,
                    progress_evidence_sha256=DIGEST,
                ),
                events=(uuid4(4),),
            ),
        )
        self.assertEqual(state.tasks[0].continuation_count, 1)
        state = complete_for_review(state, 5)
        state = assign_review(state, 6)
        assignment = state.tasks[0].reviewer_assignment_id
        state = reduce_transition(
            state,
            intent(
                "APPROVE",
                args=arguments(assignment_id=assignment, decision_sha256=OTHER_DIGEST),
                events=(uuid4(7),),
            ),
        )
        state = reduce_transition(
            state,
            intent(
                "ROUTE",
                args=arguments(routing_evidence_sha256=DIGEST),
                events=(uuid4(8),),
            ),
        )
        self.assertEqual(state.tasks[0].code, "N8")
        self.assertEqual(state.claims[0].status, "COMPLETED")
        self.assertEqual(state.reviews[0].status, "APPROVED")
        self.assertEqual(state.decisions[0].decision_sha256, OTHER_DIGEST)

    def test_complete_close_reaches_terminal_c0(self) -> None:
        state = start(claim(initialize(empty_state())))
        task = state.tasks[0]
        state = reduce_transition(
            state,
            intent(
                "COMPLETE",
                args=arguments(
                    claim_id=task.active_claim_id,
                    close=True,
                    completion_evidence_sha256=DIGEST,
                    fence=task.task_fence,
                ),
            ),
        )
        self.assertEqual(state.tasks[0].code, "C0")
        self.assertEqual(state.claims[0].status, "COMPLETED")

    def test_yield_from_claimed_and_in_progress(self) -> None:
        for started in (False, True):
            with self.subTest(started=started):
                state = claim(initialize(empty_state()))
                if started:
                    state = start(state)
                task = state.tasks[0]
                state = reduce_transition(
                    state,
                    intent(
                        "YIELD",
                        args=arguments(
                            claim_id=task.active_claim_id,
                            fence=task.task_fence,
                            yield_evidence_sha256=DIGEST,
                        ),
                    ),
                )
                self.assertEqual(state.tasks[0].code, "N0")
                self.assertEqual(state.claims[0].status, "YIELDED")

    def test_fail_then_retry_opens_new_attempt(self) -> None:
        state = start(claim(initialize(empty_state())))
        task = state.tasks[0]
        state = reduce_transition(
            state,
            intent(
                "FAIL",
                args=arguments(
                    claim_id=task.active_claim_id,
                    failure_code="WORKER_ERROR",
                    failure_evidence_sha256=DIGEST,
                    fence=task.task_fence,
                ),
            ),
        )
        failed = state.tasks[0]
        state = reduce_transition(
            state,
            intent(
                "RETRY",
                attempt=failed.attempt,
                args=arguments(retry_evidence_sha256=DIGEST, retryable=True),
            ),
        )
        self.assertEqual((state.tasks[0].code, state.tasks[0].attempt), ("N0", 2))
        self.assertEqual(state.tasks[0].continuation_count, 0)

    def test_fail_from_claimed_is_allowed(self) -> None:
        state = claim(initialize(empty_state()))
        task = state.tasks[0]
        before = (
            task.scheduler_generation, task.dispatch_generation, task.task_fence,
            task.continuation_count,
        )
        state = reduce_transition(
            state,
            intent(
                "FAIL",
                args=arguments(
                    claim_id=task.active_claim_id,
                    failure_code="CLAIM_FAILED",
                    failure_evidence_sha256=DIGEST,
                    fence=task.task_fence,
                ),
            ),
        )
        after = state.tasks[0]
        self.assertEqual(after.code, "F0")
        self.assertEqual(
            (after.scheduler_generation, after.dispatch_generation, after.task_fence, after.continuation_count),
            (before[0] + 1, before[1] + 1, before[2] + 1, before[3]),
        )

    def test_recover_only_from_claimed(self) -> None:
        state = claim(initialize(empty_state()))
        task = state.tasks[0]
        state = reduce_transition(
            state,
            intent(
                "RECOVER",
                args=arguments(
                    claim_id=task.active_claim_id,
                    liveness_evidence_sha256=DIGEST,
                ),
            ),
        )
        self.assertEqual(state.tasks[0].code, "N0")
        self.assertEqual(state.claims[0].status, "RECOVERED")

    def test_core_source_state_and_cas_rejections(self) -> None:
        cases = (
            (state_for_code("N0"), "START", arguments(claim_id=uuid4(100), fence=0), "TRANSITION_SOURCE_STATE"),
            (state_for_code("N1"), "CONTINUE", arguments(claim_id=uuid4(100), fence=1, progress_evidence_sha256=DIGEST), "TRANSITION_SOURCE_STATE"),
            (state_for_code("N0"), "RETRY", arguments(retry_evidence_sha256=DIGEST, retryable=True), "TRANSITION_SOURCE_STATE"),
            (state_for_code("N0"), "ROUTE", arguments(routing_evidence_sha256=DIGEST), "TRANSITION_SOURCE_STATE"),
            (state_for_code("N3"), "APPROVE", arguments(assignment_id=uuid4(200), decision_sha256=DIGEST), "TRANSITION_SOURCE_STATE"),
            (state_for_code("N0"), "REVALIDATE", arguments(evidence_sha256=DIGEST), "TRANSITION_SOURCE_STATE"),
        )
        for state, operation, args, code in cases:
            with self.subTest(operation=operation), self.assertRaisesRegex(TransitionViolation, code):
                reduce_transition(state, intent(operation, args=args))

        claimed = state_for_code("N1")
        with self.assertRaisesRegex(TransitionViolation, "TRANSITION_CLAIM_CAS"):
            reduce_transition(
                claimed,
                intent("START", args=arguments(claim_id=uuid4(999), fence=claimed.tasks[0].task_fence)),
            )
        with self.assertRaisesRegex(TransitionViolation, "TRANSITION_FENCE_CAS"):
            reduce_transition(
                claimed,
                intent(
                    "START",
                    args=arguments(
                        claim_id=claimed.tasks[0].active_claim_id,
                        fence=claimed.tasks[0].task_fence + 1,
                    ),
                ),
            )
        reviewing = state_for_code("N4")
        with self.assertRaisesRegex(TransitionViolation, "TRANSITION_REVIEW_CAS"):
            reduce_transition(
                reviewing,
                intent(
                    "APPROVE",
                    args=arguments(assignment_id=uuid4(999), decision_sha256=DIGEST),
                ),
            )
        failed = state_for_code("F0")
        with self.assertRaisesRegex(TransitionViolation, "TRANSITION_RETRYABLE"):
            reduce_transition(
                failed,
                intent("RETRY", args=arguments(retry_evidence_sha256=DIGEST, retryable=False)),
            )
        with self.assertRaisesRegex(TransitionViolation, "TRANSITION_TASK_ABSENT"):
            reduce_transition(
                state_for_code("N0"),
                intent(
                    "CLAIM", task_id="MISSING", args=arguments(actor="worker"),
                    generated_id=uuid4(300),
                ),
            )
        with self.assertRaisesRegex(TransitionViolation, "TRANSITION_ATTEMPT_MISMATCH"):
            reduce_transition(
                state_for_code("N0"),
                intent(
                    "CLAIM", attempt=2, args=arguments(actor="worker"),
                    generated_id=uuid4(300),
                ),
            )

    def test_governance_block_and_revalidate_replace_receipt(self) -> None:
        state = start(claim(initialize(empty_state())))
        state = reduce_transition(
            state,
            intent(
                "GOVERNANCE_BLOCK",
                args=arguments(evidence_sha256=DIGEST, reason_code="SOURCE_CHANGED"),
            ),
        )
        self.assertEqual(state.tasks[0].code, "B0")
        self.assertEqual(state.claims[0].status, "GOVERNANCE_INVALIDATED")
        state = reduce_transition(
            state,
            intent("REVALIDATE", args=arguments(evidence_sha256=OTHER_DIGEST)),
        )
        self.assertEqual(state.tasks[0].code, "N0")
        self.assertEqual(state.tasks[0].decision_receipt_digest, OTHER_DIGEST)

    def test_block_and_revalidate_review_path(self) -> None:
        state = assign_review(complete_for_review(start(claim(initialize(empty_state())))))
        state = reduce_transition(
            state,
            intent(
                "GOVERNANCE_BLOCK",
                args=arguments(evidence_sha256=DIGEST, reason_code="POLICY_CHANGED"),
            ),
        )
        self.assertEqual(state.tasks[0].code, "B1")
        self.assertEqual(state.reviews[0].status, "GOVERNANCE_REVOKED")
        state = reduce_transition(
            state,
            intent("REVALIDATE", args=arguments(evidence_sha256=OTHER_DIGEST)),
        )
        self.assertEqual(state.tasks[0].code, "N3")
        self.assertIsNone(state.tasks[0].reviewer_assignment_id)

    def test_governance_block_all_remaining_source_branches(self) -> None:
        sources = {
            "N0": initialize(empty_state()),
            "N1": claim(initialize(empty_state())),
            "N3": complete_for_review(start(claim(initialize(empty_state())))),
        }
        for source_code, source in sources.items():
            with self.subTest(source=source_code):
                before = source.tasks[0]
                result = reduce_transition(
                    source,
                    intent(
                        "GOVERNANCE_BLOCK",
                        args=arguments(evidence_sha256=DIGEST, reason_code="INPUT_CHANGED"),
                    ),
                )
                after = result.tasks[0]
                self.assertEqual(after.code, "B0" if source_code in {"N0", "N1"} else "B1")
                self.assertEqual(
                    (after.scheduler_generation, after.dispatch_generation, after.task_fence),
                    (
                        before.scheduler_generation + 1,
                        before.dispatch_generation + 1,
                        before.task_fence + 1,
                    ),
                )

    def test_only_governance_block_can_consume_stale_task(self) -> None:
        state = initialize(empty_state())
        state = replace(state, repository_generation=1, repository_bundle_sha256=OTHER_DIGEST)
        with self.assertRaisesRegex(TransitionViolation, "TRANSITION_STALE_TASK"):
            reduce_transition(
                state,
                intent(
                    "CLAIM",
                    args=arguments(actor="worker"),
                    generated_id=uuid4(100),
                ),
            )
        state = reduce_transition(
            state,
            intent(
                "GOVERNANCE_BLOCK",
                args=arguments(evidence_sha256=DIGEST, reason_code="STALE"),
            ),
        )
        self.assertEqual((state.tasks[0].code, state.tasks[0].repository_generation), ("B0", 1))

    def test_review_independence_checks_each_axis(self) -> None:
        base = complete_for_review(start(claim(initialize(empty_state()))))
        for actor, role, code in (
            ("owner-fixture", "05 Skeptic", "TRANSITION_REVIEW_ACTOR_NOT_INDEPENDENT"),
            ("skeptic-fixture", "03 Research", "TRANSITION_REVIEW_ROLE_NOT_INDEPENDENT"),
        ):
            with self.subTest(code=code), self.assertRaisesRegex(TransitionViolation, code):
                reduce_transition(
                    base,
                    intent(
                        "ASSIGN_REVIEW",
                        args=arguments(actor=actor, role=role),
                        generated_id=uuid4(200),
                    ),
                )

    def test_reject_and_remediate_close_review_with_exact_decision(self) -> None:
        for operation, target, status in (
            ("REJECT", "N5", "REJECTED"),
            ("REMEDIATE", "N6", "REMEDIATION_REQUIRED"),
        ):
            with self.subTest(operation=operation):
                state = assign_review(complete_for_review(start(claim(initialize(empty_state())))))
                before = state.tasks[0]
                assignment = before.reviewer_assignment_id
                state = reduce_transition(
                    state,
                    intent(
                        operation,
                        args=arguments(assignment_id=assignment, decision_sha256=OTHER_DIGEST),
                        events=(uuid4(77),),
                    ),
                )
                after = state.tasks[0]
                self.assertEqual(after.code, target)
                self.assertIsNone(after.reviewer_assignment_id)
                self.assertEqual(after.scheduler_generation, before.scheduler_generation + 1)
                self.assertEqual(state.reviews[0].status, status)
                self.assertEqual(state.reviews[0].closed_event_id, uuid4(77))
                self.assertEqual(state.decisions[0].decision_sha256, OTHER_DIGEST)

    def test_remediation_child_and_link_are_atomic(self) -> None:
        state = assign_review(complete_for_review(start(claim(initialize(empty_state())))))
        assignment = state.tasks[0].reviewer_assignment_id
        state = reduce_transition(
            state,
            intent(
                "REJECT",
                args=arguments(assignment_id=assignment, decision_sha256=OTHER_DIGEST),
                events=(uuid4(20),),
            ),
        )
        state = reduce_transition(
            state,
            intent(
                "CREATE_REMEDIATION_TASK",
                child_task_id="T2",
                child_attempt=1,
                args=arguments(
                    child_decision_receipt_digest=DIGEST,
                    child_owner="remediation-owner",
                    child_owner_role="03 Research",
                    decision_sha256=OTHER_DIGEST,
                    relationship_id=uuid4(300),
                ),
                events=(uuid4(21), uuid4(22)),
            ),
        )
        self.assertEqual(tuple(task.task_id for task in state.tasks), ("T1", "T2"))
        self.assertEqual(state.tasks[0].successor_task, "T2")
        self.assertEqual(state.tasks[1].predecessor_task, "T1")
        self.assertEqual(len(state.remediation_links), 1)
        link = state.remediation_links[0]
        expected = remediation_link_digest({
            "link_id": link.link_id,
            "source_task_id": "T1",
            "source_attempt": 1,
            "child_task_id": "T2",
            "child_attempt": 1,
            "source_event_id": uuid4(21),
            "child_event_id": uuid4(22),
            "decision_sha256": OTHER_DIGEST,
            "link_sha256": "0" * 64,
        })
        self.assertEqual(link.link_sha256, expected)

    def test_remediation_from_n6_and_duplicate_event_rejection(self) -> None:
        state = assign_review(complete_for_review(start(claim(initialize(empty_state())))))
        state = reduce_transition(
            state,
            intent(
                "REMEDIATE",
                args=arguments(
                    assignment_id=state.tasks[0].reviewer_assignment_id,
                    decision_sha256=OTHER_DIGEST,
                ),
            ),
        )
        remediation = intent(
            "CREATE_REMEDIATION_TASK",
            child_task_id="T2",
            child_attempt=1,
            args=arguments(
                child_decision_receipt_digest=DIGEST,
                child_owner="owner-2",
                child_owner_role="03 Research",
                decision_sha256=OTHER_DIGEST,
                relationship_id=uuid4(300),
            ),
            events=(uuid4(21), uuid4(21)),
        )
        with self.assertRaisesRegex(TransitionViolation, "TRANSITION_EVENT_DUPLICATE"):
            reduce_transition(state, remediation)
        state = reduce_transition(state, replace(remediation, semantic_event_ids=(uuid4(21), uuid4(22))))
        self.assertEqual((state.tasks[0].code, state.tasks[1].code), ("N6", "N0"))

    def test_remediation_child_retry_preserves_creation_link(self) -> None:
        state = assign_review(complete_for_review(start(claim(initialize(empty_state())))))
        state = reduce_transition(
            state,
            intent(
                "REJECT",
                args=arguments(
                    assignment_id=state.tasks[0].reviewer_assignment_id,
                    decision_sha256=OTHER_DIGEST,
                ),
                events=(uuid4(20),),
            ),
        )
        state = reduce_transition(
            state,
            intent(
                "CREATE_REMEDIATION_TASK",
                child_task_id="T2",
                child_attempt=1,
                args=arguments(
                    child_decision_receipt_digest=DIGEST,
                    child_owner="owner-2",
                    child_owner_role="03 Research",
                    decision_sha256=OTHER_DIGEST,
                    relationship_id=uuid4(300),
                ),
                events=(uuid4(21), uuid4(22)),
            ),
        )
        state = reduce_transition(
            state,
            intent(
                "CLAIM", task_id="T2", args=arguments(actor="worker-2"),
                generated_id=uuid4(301), events=(uuid4(30),),
            ),
        )
        child = {task.task_id: task for task in state.tasks}["T2"]
        state = reduce_transition(
            state,
            intent(
                "START", task_id="T2",
                args=arguments(claim_id=child.active_claim_id, fence=child.task_fence),
                events=(uuid4(31),),
            ),
        )
        child = {task.task_id: task for task in state.tasks}["T2"]
        state = reduce_transition(
            state,
            intent(
                "FAIL", task_id="T2",
                args=arguments(
                    claim_id=child.active_claim_id,
                    failure_code="CHILD_FAILED",
                    failure_evidence_sha256=DIGEST,
                    fence=child.task_fence,
                ),
                events=(uuid4(32),),
            ),
        )
        state = reduce_transition(
            state,
            intent(
                "RETRY", task_id="T2",
                args=arguments(retry_evidence_sha256=DIGEST, retryable=True),
                events=(uuid4(33),),
            ),
        )
        child = {task.task_id: task for task in state.tasks}["T2"]
        self.assertEqual((child.attempt, child.predecessor_task), (2, "T1"))
        self.assertEqual(state.remediation_links[0].child_attempt, 1)

    def test_wrong_remediation_decision_rejects_without_partial_effect(self) -> None:
        state = assign_review(complete_for_review(start(claim(initialize(empty_state())))))
        assignment = state.tasks[0].reviewer_assignment_id
        state = reduce_transition(
            state,
            intent(
                "REMEDIATE",
                args=arguments(assignment_id=assignment, decision_sha256=OTHER_DIGEST),
            ),
        )
        before = state
        with self.assertRaisesRegex(TransitionViolation, "TRANSITION_DECISION_MISMATCH"):
            reduce_transition(
                state,
                intent(
                    "CREATE_REMEDIATION_TASK",
                    child_task_id="T2",
                    child_attempt=1,
                    args=arguments(
                        child_decision_receipt_digest=DIGEST,
                        child_owner="owner-2",
                        child_owner_role="03 Research",
                        decision_sha256=DIGEST,
                        relationship_id=uuid4(300),
                    ),
                    events=(uuid4(21), uuid4(22)),
                ),
            )
        self.assertIs(state, before)
        self.assertIsNone(state.tasks[0].successor_task)

    def test_late_remediation_child_failure_is_atomic(self) -> None:
        state = assign_review(complete_for_review(start(claim(initialize(empty_state())))))
        state = reduce_transition(
            state,
            intent(
                "REJECT",
                args=arguments(
                    assignment_id=state.tasks[0].reviewer_assignment_id,
                    decision_sha256=OTHER_DIGEST,
                ),
            ),
        )
        before = state
        with self.assertRaisesRegex(TransitionViolation, "TRANSITION_IDENTITY"):
            reduce_transition(
                state,
                intent(
                    "CREATE_REMEDIATION_TASK",
                    child_task_id="T2",
                    child_attempt=1,
                    args=arguments(
                        child_decision_receipt_digest=DIGEST,
                        child_owner="invalid\nowner",
                        child_owner_role="03 Research",
                        decision_sha256=OTHER_DIGEST,
                        relationship_id=uuid4(300),
                    ),
                    events=(uuid4(21), uuid4(22)),
                ),
            )
        self.assertIs(state, before)
        self.assertIsNone(state.tasks[0].successor_task)

    def test_repository_import_fences_active_work_and_leaves_optional_stale(self) -> None:
        state = initialize(empty_state(), "T1")
        state = initialize(state, "T2")
        # Claim T1 while leaving optional N0 T2 unlisted.
        state = reduce_transition(
            state,
            intent(
                "CLAIM",
                task_id="T1",
                args=arguments(actor="worker"),
                generated_id=uuid4(100),
                events=(uuid4(30),),
            ),
        )
        state = reduce_transition(
            state,
            intent(
                "IMPORT_REPOSITORY",
                task_id=None,
                attempt=None,
                args=arguments(
                    affected_task_ids=("T1",),
                    policy_capability_sha256=DIGEST,
                    project_state_sha256=DIGEST,
                    reason_code="IMPORT",
                    source_commit="c" * 40,
                    stop_set_sha256=DIGEST,
                    task_inventory_sha256=DIGEST,
                ),
                events=(uuid4(31), uuid4(32)),
                generation=1,
                bundle=OTHER_DIGEST,
            ),
        )
        by_id = {task.task_id: task for task in state.tasks}
        self.assertEqual((state.repository_generation, state.repository_bundle_sha256), (1, OTHER_DIGEST))
        self.assertEqual((by_id["T1"].code, by_id["T1"].repository_generation), ("B0", 1))
        self.assertEqual((by_id["T2"].code, by_id["T2"].repository_generation), ("N0", 0))
        self.assertEqual(state.claims[0].status, "GOVERNANCE_INVALIDATED")

    def test_empty_repository_import_advances_only_metadata(self) -> None:
        state = reduce_transition(
            empty_state(),
            intent(
                "IMPORT_REPOSITORY",
                task_id=None,
                attempt=None,
                args=arguments(
                    affected_task_ids=(),
                    policy_capability_sha256=DIGEST,
                    project_state_sha256=DIGEST,
                    reason_code="IMPORT",
                    source_commit="c" * 40,
                    stop_set_sha256=DIGEST,
                    task_inventory_sha256=DIGEST,
                ),
                events=(uuid4(90),),
                generation=1,
                bundle=OTHER_DIGEST,
            ),
        )
        self.assertEqual((state.repository_generation, state.tasks), (1, ()))

    def test_repository_import_covers_every_state_branch(self) -> None:
        stable = {"N0", "F0", "N5", "N6", "N7", "N8", "B0", "B1"}
        blocking = {"N1": "B0", "N2": "B0", "N3": "B1", "N4": "B1"}
        for source_code in tuple(sorted(stable | set(blocking))):
            with self.subTest(source=source_code):
                state = state_for_code(source_code)
                before = state.tasks[0]
                state = reduce_transition(
                    state,
                    intent(
                        "IMPORT_REPOSITORY",
                        task_id=None,
                        attempt=None,
                        args=arguments(
                            affected_task_ids=("T1",),
                            policy_capability_sha256=DIGEST,
                            project_state_sha256=DIGEST,
                            reason_code="IMPORT",
                            source_commit="c" * 40,
                            stop_set_sha256=DIGEST,
                            task_inventory_sha256=DIGEST,
                        ),
                        events=(uuid4(80), uuid4(81)),
                        generation=1,
                        bundle=OTHER_DIGEST,
                    ),
                )
                after = state.tasks[0]
                self.assertEqual(after.code, blocking.get(source_code, source_code))
                self.assertEqual(after.repository_generation, 1)
                self.assertEqual(after.scheduler_generation, before.scheduler_generation + 1)
                expected_df = 1 if source_code in blocking else 0
                self.assertEqual(after.dispatch_generation, before.dispatch_generation + expected_df)
                self.assertEqual(after.task_fence, before.task_fence + expected_df)
                self.assertEqual(after.continuation_count, before.continuation_count)
                self.assertEqual(
                    (after.owner, after.owner_role, after.decision_receipt_digest),
                    (before.owner, before.owner_role, before.decision_receipt_digest),
                )
                if source_code in {"N1", "N2"}:
                    self.assertEqual(state.claims[0].status, "GOVERNANCE_INVALIDATED")
                if source_code == "N4":
                    self.assertEqual(state.reviews[0].status, "GOVERNANCE_REVOKED")

        closed = state_for_code("C0")
        unchanged = reduce_transition(
            closed,
            intent(
                "IMPORT_REPOSITORY",
                task_id=None,
                attempt=None,
                args=arguments(
                    affected_task_ids=(),
                    policy_capability_sha256=DIGEST,
                    project_state_sha256=DIGEST,
                    reason_code="IMPORT",
                    source_commit="c" * 40,
                    stop_set_sha256=DIGEST,
                    task_inventory_sha256=DIGEST,
                ),
                events=(uuid4(80),),
                generation=1,
                bundle=OTHER_DIGEST,
            ),
        )
        self.assertEqual(unchanged.tasks[0], closed.tasks[0])
        with self.assertRaisesRegex(TransitionViolation, "TRANSITION_IMPORT_CLOSED_TASK"):
            reduce_transition(
                closed,
                intent(
                    "IMPORT_REPOSITORY",
                    task_id=None,
                    attempt=None,
                    args=arguments(
                        affected_task_ids=("T1",),
                        policy_capability_sha256=DIGEST,
                        project_state_sha256=DIGEST,
                        reason_code="IMPORT",
                        source_commit="c" * 40,
                        stop_set_sha256=DIGEST,
                        task_inventory_sha256=DIGEST,
                    ),
                    events=(uuid4(80), uuid4(81)),
                    generation=1,
                    bundle=OTHER_DIGEST,
                ),
            )

    def test_import_order_duplicates_and_generation_overflow_are_rejected(self) -> None:
        state = initialize(initialize(empty_state(), "T1"), "T2")
        for affected, code in (
            (("T2", "T1"), "TRANSITION_IMPORT_AFFECTED_ORDER"),
            (("T1", "T1"), "TRANSITION_IMPORT_AFFECTED_ORDER"),
        ):
            with self.subTest(affected=affected), self.assertRaisesRegex(TransitionViolation, code):
                reduce_transition(
                    state,
                    intent(
                        "IMPORT_REPOSITORY",
                        task_id=None,
                        attempt=None,
                        args=arguments(
                            affected_task_ids=affected,
                            policy_capability_sha256=DIGEST,
                            project_state_sha256=DIGEST,
                            reason_code="IMPORT",
                            source_commit="c" * 40,
                            stop_set_sha256=DIGEST,
                            task_inventory_sha256=DIGEST,
                        ),
                        events=(uuid4(80), uuid4(81), uuid4(82)),
                        generation=1,
                        bundle=OTHER_DIGEST,
                    ),
                )
        maximum = replace(empty_state(), repository_generation=INT64_MAX)
        with self.assertRaisesRegex(TransitionViolation, "TRANSITION_COUNTER_OVERFLOW"):
            reduce_transition(
                maximum,
                intent(
                    "IMPORT_REPOSITORY",
                    task_id=None,
                    attempt=None,
                    args=arguments(
                        affected_task_ids=(),
                        policy_capability_sha256=DIGEST,
                        project_state_sha256=DIGEST,
                        reason_code="IMPORT",
                        source_commit="c" * 40,
                        stop_set_sha256=DIGEST,
                        task_inventory_sha256=DIGEST,
                    ),
                    events=(uuid4(80),),
                    generation=INT64_MAX,
                    bundle=OTHER_DIGEST,
                ),
            )

    def test_boolean_integer_aliases_are_rejected(self) -> None:
        with self.assertRaisesRegex(TransitionViolation, "TRANSITION_INTEGER"):
            reduce_transition(
                empty_state(),
                intent(
                    "INITIALIZE",
                    attempt=True,
                    args=arguments(
                        decision_receipt_digest=DIGEST,
                        owner="owner",
                        owner_role="role",
                    ),
                ),
            )
        with self.assertRaisesRegex(TransitionViolation, "TRANSITION_INTEGER"):
            reduce_transition(
                empty_state(),
                intent(
                    "IMPORT_REPOSITORY",
                    task_id=None,
                    attempt=None,
                    args=arguments(
                        affected_task_ids=(),
                        policy_capability_sha256=DIGEST,
                        project_state_sha256=DIGEST,
                        reason_code="IMPORT",
                        source_commit="c" * 40,
                        stop_set_sha256=DIGEST,
                        task_inventory_sha256=DIGEST,
                    ),
                    events=(uuid4(90),),
                    generation=True,
                    bundle=OTHER_DIGEST,
                ),
            )

    def test_import_must_include_mandatory_states_and_is_atomic(self) -> None:
        state = start(claim(initialize(empty_state())))
        task = state.tasks[0]
        state = reduce_transition(
            state,
            intent(
                "FAIL",
                args=arguments(
                    claim_id=task.active_claim_id,
                    failure_code="FAILED",
                    failure_evidence_sha256=DIGEST,
                    fence=task.task_fence,
                ),
            ),
        )
        with self.assertRaisesRegex(TransitionViolation, "TRANSITION_IMPORT_MANDATORY_MISSING"):
            reduce_transition(
                state,
                intent(
                    "IMPORT_REPOSITORY",
                    task_id=None,
                    attempt=None,
                    args=arguments(
                        affected_task_ids=(),
                        policy_capability_sha256=DIGEST,
                        project_state_sha256=DIGEST,
                        reason_code="IMPORT",
                        source_commit="c" * 40,
                        stop_set_sha256=DIGEST,
                        task_inventory_sha256=DIGEST,
                    ),
                    events=(uuid4(40),),
                    generation=1,
                    bundle=OTHER_DIGEST,
                ),
            )
        self.assertEqual((state.repository_generation, state.tasks[0].code), (0, "F0"))

    def test_counter_overflow_rejects_without_mutation(self) -> None:
        state = initialize(empty_state())
        overflow = replace(state.tasks[0], scheduler_generation=INT64_MAX)
        state = replace(state, tasks=(overflow,))
        with self.assertRaisesRegex(TransitionViolation, "TRANSITION_COUNTER_OVERFLOW"):
            reduce_transition(
                state,
                intent(
                    "CLAIM",
                    args=arguments(actor="worker"),
                    generated_id=uuid4(100),
                ),
            )
        self.assertEqual(state.tasks[0].scheduler_generation, INT64_MAX)

    def test_late_import_failure_does_not_close_earlier_claim(self) -> None:
        state = initialize(initialize(empty_state(), "T1"), "T2")
        state = reduce_transition(
            state,
            intent(
                "CLAIM", task_id="T1", args=arguments(actor="worker-1"),
                generated_id=uuid4(101), events=(uuid4(11),),
            ),
        )
        state = reduce_transition(
            state,
            intent(
                "CLAIM", task_id="T2", args=arguments(actor="worker-2"),
                generated_id=uuid4(102), events=(uuid4(12),),
            ),
        )
        by_id = {task.task_id: task for task in state.tasks}
        by_id["T2"] = replace(by_id["T2"], scheduler_generation=INT64_MAX)
        state = replace(state, tasks=tuple(by_id[key] for key in sorted(by_id)))
        before = state
        with self.assertRaisesRegex(TransitionViolation, "TRANSITION_COUNTER_OVERFLOW"):
            reduce_transition(
                state,
                intent(
                    "IMPORT_REPOSITORY",
                    task_id=None,
                    attempt=None,
                    args=arguments(
                        affected_task_ids=("T1", "T2"),
                        policy_capability_sha256=DIGEST,
                        project_state_sha256=DIGEST,
                        reason_code="IMPORT",
                        source_commit="c" * 40,
                        stop_set_sha256=DIGEST,
                        task_inventory_sha256=DIGEST,
                    ),
                    events=(uuid4(21), uuid4(22), uuid4(23)),
                    generation=1,
                    bundle=OTHER_DIGEST,
                ),
            )
        self.assertIs(state, before)
        self.assertEqual(tuple(claim.status for claim in state.claims), ("OPEN", "OPEN"))

    def test_argument_order_and_exact_boolean_types_are_closed(self) -> None:
        with self.assertRaisesRegex(TransitionViolation, "TRANSITION_ARGUMENT_SHAPE"):
            TransitionIntent(
                operation="INITIALIZE",
                task_id="T1",
                attempt=1,
                arguments=(("owner", "x"), ("decision_receipt_digest", DIGEST)),
                semantic_event_ids=(uuid4(1),),
            )
        state = start(claim(initialize(empty_state())))
        task = state.tasks[0]
        with self.assertRaisesRegex(TransitionViolation, "TRANSITION_CLOSE_TYPE"):
            reduce_transition(
                state,
                intent(
                    "COMPLETE",
                    args=arguments(
                        claim_id=task.active_claim_id,
                        close=1,
                        completion_evidence_sha256=DIGEST,
                        fence=task.task_fence,
                    ),
                ),
            )

    def test_state_cross_record_and_host_types_fail_closed(self) -> None:
        base = initialize(empty_state())
        forged_task = replace(
            base.tasks[0],
            workflow="ACTIVE",
            execution="CLAIMED",
            active_claim_id=uuid4(100),
        )
        with self.assertRaisesRegex(TransitionViolation, "TRANSITION_STATE_CLAIM_CLOSURE"):
            replace(base, tasks=(forged_task,))
        with self.assertRaisesRegex(TransitionViolation, "TRANSITION_MEMBER_TYPE"):
            replace(base, tasks=(object(),))
        with self.assertRaisesRegex(TransitionViolation, "TRANSITION_UNREACHABLE_TRIPLE"):
            replace(base.tasks[0], workflow=[])
        with self.assertRaisesRegex(TransitionViolation, "TRANSITION_ARGUMENT_SHAPE"):
            TransitionIntent(
                operation="INITIALIZE",
                task_id="T2",
                attempt=1,
                arguments=(([], DIGEST),),
                semantic_event_ids=(uuid4(1),),
            )
        with self.assertRaisesRegex(TransitionViolation, "TRANSITION_CLAIM_STATUS"):
            ClaimRecord(uuid4(1), "T1", 1, 1, [], "worker", uuid4(2))
        with self.assertRaisesRegex(TransitionViolation, "TRANSITION_REVIEW_STATUS"):
            ReviewRecord(uuid4(1), "T1", 1, "actor", "role", {}, uuid4(2))
        with self.assertRaisesRegex(TransitionViolation, "TRANSITION_DECISION_OPERATION"):
            ReviewDecision("T1", 1, [], DIGEST, uuid4(2))

    def test_state_rejects_forged_self_review_history(self) -> None:
        for code in ("N4", "N5"):
            with self.subTest(code=code):
                state = state_for_code(code)
                forged = replace(state.reviews[0], actor=state.tasks[0].owner)
                with self.assertRaisesRegex(
                    TransitionViolation, "TRANSITION_REVIEW_ACTOR_NOT_INDEPENDENT"
                ):
                    replace(state, reviews=(forged,))

    def test_state_rejects_impossible_link_review_and_claim_history(self) -> None:
        remediation = state_for_code("N5")
        remediation = reduce_transition(
            remediation,
            intent(
                "CREATE_REMEDIATION_TASK",
                child_task_id="T2",
                child_attempt=1,
                args=arguments(
                    child_decision_receipt_digest=DIGEST,
                    child_owner="owner-2",
                    child_owner_role="03 Research",
                    decision_sha256=OTHER_DIGEST,
                    relationship_id=uuid4(300),
                ),
                events=(uuid4(21), uuid4(22)),
            ),
        )
        link = remediation.remediation_links[0]
        forged_digest = remediation_link_digest({
            "link_id": link.link_id,
            "source_task_id": link.source_task_id,
            "source_attempt": link.source_attempt,
            "child_task_id": link.child_task_id,
            "child_attempt": 2,
            "source_event_id": link.source_event_id,
            "child_event_id": link.child_event_id,
            "decision_sha256": link.decision_sha256,
            "link_sha256": "0" * 64,
        })
        forged_link = replace(link, child_attempt=2, link_sha256=forged_digest)
        with self.assertRaisesRegex(TransitionViolation, "TRANSITION_STATE_LINK_CLOSURE"):
            replace(remediation, remediation_links=(forged_link,))

        pending = state_for_code("N3")
        orphan_review = ReviewRecord(
            uuid4(500), "T1", 1, "skeptic", "05 Skeptic", "APPROVED",
            uuid4(51), uuid4(52),
        )
        with self.assertRaisesRegex(TransitionViolation, "TRANSITION_STATE_REVIEW_DECISION"):
            replace(pending, reviews=(orphan_review,))

        idle = state_for_code("N0")
        ghost_claim = ClaimRecord(
            uuid4(600), "GHOST", 1, 1, "FAILED", "worker", uuid4(61), uuid4(62)
        )
        with self.assertRaisesRegex(TransitionViolation, "TRANSITION_STATE_CLAIM_TASK"):
            replace(idle, claims=(ghost_claim,))

    def test_irrelevant_intent_fields_are_rejected(self) -> None:
        state = initialize(empty_state())
        with self.assertRaisesRegex(TransitionViolation, "TRANSITION_INTENT_EXTRA"):
            reduce_transition(
                state,
                intent(
                    "START",
                    args=arguments(claim_id=uuid4(100), fence=0),
                    child_task_id="T2",
                    child_attempt=1,
                ),
            )
        with self.assertRaisesRegex(TransitionViolation, "TRANSITION_INTENT_GENERATED"):
            reduce_transition(
                state,
                intent(
                    "ROUTE",
                    args=arguments(routing_evidence_sha256=DIGEST),
                    generated_id=uuid4(100),
                ),
            )

    def test_system_and_snapshot_operations_remain_outside_private_core(self) -> None:
        state = initialize(empty_state())
        for operation in ("SYSTEM_GENESIS", "SYSTEM_LEGACY_BRIDGE", "CHECKPOINT", "EXPORT_SNAPSHOT"):
            with self.subTest(operation=operation), self.assertRaisesRegex(
                TransitionViolation, "TRANSITION_OPERATION_OUTSIDE_CORE"
            ):
                reduce_transition(state, intent(operation))

    def test_module_has_no_io_or_authority_dependencies(self) -> None:
        path = (
            Path(__file__).resolve().parents[1]
            / "src" / "edgelab" / "runtime_v2_transition.py"
        )
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imported.add(node.module)
        self.assertEqual(
            imported,
            {"__future__", "dataclasses", "re", "typing", "runtime_v2_codec"},
        )
        for forbidden in (
            "import os", "import sqlite3", "import subprocess", "from pathlib",
            "transactional_scheduler", "risk_controls", "authority_binding",
            "locked_authority", "project_status", "datetime", "uuid.uuid4",
        ):
            self.assertNotIn(forbidden, source)
        verifier = (
            Path(__file__).resolve().parents[1]
            / "src" / "edgelab" / "runtime_v2_verifier.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("runtime_v2_transition", verifier)


if __name__ == "__main__":
    unittest.main()
