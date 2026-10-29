"""Adversarial tests for the private staged transition workspace."""
from __future__ import annotations

import copy
from dataclasses import replace
import unittest

import src.edgelab.runtime_v2_group as group
import src.edgelab.runtime_v2_initial as initial
import src.edgelab.runtime_v2_transition as transition


DIGEST = "a" * 64


def uuid4(number: int) -> str:
    return f"00000000-0000-4000-8000-{number:012x}"


def arguments(**values: object) -> tuple[tuple[str, object], ...]:
    return tuple(sorted(values.items()))


def intent(
    operation: str,
    *,
    task_id: str = "T1",
    attempt: int = 1,
    args: tuple[tuple[str, object], ...] = (),
    generated_id: str | None = None,
    event: int = 1,
) -> transition.TransitionIntent:
    return transition.TransitionIntent(
        operation=operation,
        task_id=task_id,
        attempt=attempt,
        arguments=args,
        generated_id=generated_id,
        semantic_event_ids=(uuid4(event),),
    )


def initialize_intent(
    event: int = 1, task_id: str = "T1"
) -> transition.TransitionIntent:
    return intent(
        "INITIALIZE",
        task_id=task_id,
        args=arguments(
            decision_receipt_digest=DIGEST,
            owner="owner-fixture",
            owner_role="03 Research",
        ),
        event=event,
    )


def cursor_pair(
    sequence: int,
    *,
    attempt: int,
    task_sequence: int,
    predecessor: tuple[str, str],
) -> tuple[dict[str, object], dict[str, object]]:
    semantic = {
        "event_id": uuid4(1000 + sequence),
        "event_sha256": f"{sequence % 16:x}" * 64,
        "stream": "TASK",
        "task_context": {
            "task_id": "T1",
            "attempt": attempt,
            "task_sequence": task_sequence,
            "task_predecessor": {
                "event_id": predecessor[0],
                "event_sha256": predecessor[1],
            },
        },
        "transaction": {
            "transaction_id": uuid4(2000 + sequence),
            "operation_key": f"v2:{DIGEST}:cursor-{sequence}",
        },
    }
    commit = {
        "event_id": uuid4(3000 + sequence),
        "event_sha256": f"{(sequence + 8) % 16:x}" * 64,
        "global_sequence": sequence + 1,
    }
    return semantic, commit


class RuntimeV2TransitionWorkspaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.empty = transition.ReducerState(0, DIGEST)

    def commit(
        self,
        workspace: transition._TransitionWorkspace,
        next_intent: transition.TransitionIntent,
    ) -> transition._StagedTransition:
        staged = workspace.stage(next_intent)
        workspace.commit(staged)
        return staged

    def test_stage_is_side_effect_free_and_freeze_is_canonical(self) -> None:
        workspace = transition._TransitionWorkspace(self.empty)
        staged = workspace.stage(initialize_intent())
        self.assertEqual(workspace.revision, 0)
        self.assertEqual(workspace.freeze(), self.empty)
        self.assertEqual(staged.after_task.code, "N0")

        workspace.commit(staged)
        self.assertEqual(workspace.revision, 1)
        self.assertEqual(workspace.freeze().tasks, (staged.after_task,))

    def test_workspace_trace_matches_immutable_reduction(self) -> None:
        claim_id = uuid4(100)
        trace = [
            initialize_intent(1),
            intent(
                "CLAIM",
                args=arguments(actor="worker-fixture"),
                generated_id=claim_id,
                event=2,
            ),
            intent("START", args=arguments(claim_id=claim_id, fence=1), event=3),
            intent(
                "CONTINUE",
                args=arguments(
                    claim_id=claim_id,
                    fence=1,
                    progress_evidence_sha256=DIGEST,
                ),
                event=4,
            ),
            intent(
                "YIELD",
                args=arguments(
                    claim_id=claim_id,
                    fence=1,
                    yield_evidence_sha256=DIGEST,
                ),
                event=5,
            ),
        ]
        immutable = self.empty
        workspace = transition._TransitionWorkspace(self.empty)
        for item in trace:
            immutable = transition.reduce_transition(immutable, item)
            self.commit(workspace, item)
        self.assertEqual(workspace.freeze(), immutable)

    def test_invalid_stage_and_reused_retained_event_leave_state_unchanged(self) -> None:
        workspace = transition._TransitionWorkspace(self.empty)
        self.commit(workspace, initialize_intent())
        baseline = workspace.freeze()
        with self.assertRaises(transition.TransitionViolation) as caught:
            workspace.stage(intent("START", args=arguments(claim_id=uuid4(100), fence=1), event=2))
        self.assertEqual(caught.exception.code, "TRANSITION_SOURCE_STATE")
        self.assertEqual(workspace.revision, 1)
        self.assertEqual(workspace.freeze(), baseline)

        claim_id = uuid4(100)
        self.commit(
            workspace,
            intent(
                "CLAIM",
                args=arguments(actor="worker-fixture"),
                generated_id=claim_id,
                event=2,
            ),
        )
        claimed = workspace.freeze()
        with self.assertRaises(transition.TransitionViolation) as caught:
            workspace.stage(
                intent(
                    "RECOVER",
                    args=arguments(claim_id=claim_id, liveness_evidence_sha256=DIGEST),
                    event=2,
                )
            )
        self.assertEqual(caught.exception.code, "TRANSITION_STATE_EVENT_REUSED")
        self.assertEqual(workspace.freeze(), claimed)

    def test_stale_double_and_foreign_commits_reject_without_writes(self) -> None:
        first = transition._TransitionWorkspace(self.empty)
        second = transition._TransitionWorkspace(self.empty)
        staged = first.stage(initialize_intent())
        with self.assertRaises(transition.TransitionViolation) as caught:
            second.commit(staged)
        self.assertEqual(caught.exception.code, "TRANSITION_WORKSPACE_FOREIGN")
        self.assertEqual(second.freeze(), self.empty)

        competing = first.stage(initialize_intent(task_id="T2", event=2))
        first.commit(staged)
        committed = first.freeze()
        with self.assertRaises(transition.TransitionViolation) as caught:
            first.commit(staged)
        self.assertEqual(caught.exception.code, "TRANSITION_WORKSPACE_STALE")
        with self.assertRaises(transition.TransitionViolation) as caught:
            first.commit(competing)
        self.assertEqual(caught.exception.code, "TRANSITION_WORKSPACE_STALE")
        self.assertEqual(first.freeze(), committed)

    def test_forged_delta_from_legitimate_plan_rejects_without_writes(self) -> None:
        workspace = transition._TransitionWorkspace(self.empty)
        staged = workspace.stage(initialize_intent())
        forbidden = transition._with_code(staged.after_task, "C0")
        forged_write = replace(staged.delta.task_writes[0], after=forbidden)
        forged_delta = replace(
            staged.delta,
            task_writes=(forged_write,),
            after_task=forbidden,
        )
        forged = replace(staged, delta=forged_delta)

        with self.assertRaises(transition.TransitionViolation) as caught:
            workspace.commit(forged)
        self.assertEqual(caught.exception.code, "TRANSITION_WORKSPACE_FORGED")
        self.assertEqual(workspace.revision, 0)
        self.assertEqual(workspace.freeze(), self.empty)

        workspace.commit(staged)
        self.assertEqual(workspace.freeze().tasks[0].code, "N0")

    def test_workspace_cannot_be_shallow_or_deep_copied(self) -> None:
        workspace = transition._TransitionWorkspace(self.empty)
        staged = workspace.stage(initialize_intent())
        for copier in (copy.copy, copy.deepcopy):
            with self.subTest(copier=copier.__name__):
                with self.assertRaises(transition.TransitionViolation) as caught:
                    copier(workspace)
                self.assertEqual(caught.exception.code, "TRANSITION_WORKSPACE_COPY")
                self.assertEqual(workspace.revision, 0)
                self.assertEqual(workspace.freeze(), self.empty)
        workspace.commit(staged)
        self.assertEqual(workspace.freeze().tasks[0].code, "N0")

    def test_task_and_claim_close_commit_as_one_delta(self) -> None:
        workspace = transition._TransitionWorkspace(self.empty)
        self.commit(workspace, initialize_intent())
        claim_id = uuid4(100)
        claim_plan = workspace.stage(
            intent(
                "CLAIM",
                args=arguments(actor="worker-fixture"),
                generated_id=claim_id,
                event=2,
            )
        )
        self.assertEqual(len(claim_plan.delta.task_writes), 1)
        self.assertEqual(len(claim_plan.delta.claim_writes), 1)
        workspace.commit(claim_plan)

        close_plan = workspace.stage(
            intent(
                "RECOVER",
                args=arguments(claim_id=claim_id, liveness_evidence_sha256=DIGEST),
                event=3,
            )
        )
        self.assertEqual(close_plan.after_task.code, "N0")
        self.assertEqual(close_plan.delta.claim_writes[0].after.status, "RECOVERED")
        before_close = workspace.freeze()
        self.assertEqual(before_close.tasks[0].code, "N1")
        self.assertEqual(before_close.claims[0].status, "OPEN")
        workspace.commit(close_plan)
        after_close = workspace.freeze()
        self.assertEqual(after_close.tasks[0].code, "N0")
        self.assertEqual(after_close.claims[0].status, "RECOVERED")

    def test_governance_and_revalidation_share_atomic_workspace_semantics(self) -> None:
        claim_id = uuid4(100)
        trace = (
            initialize_intent(1),
            intent(
                "CLAIM",
                args=arguments(actor="worker-fixture"),
                generated_id=claim_id,
                event=2,
            ),
            intent(
                "GOVERNANCE_BLOCK",
                args=arguments(evidence_sha256=DIGEST, reason_code="STOP"),
                event=3,
            ),
            intent(
                "REVALIDATE",
                args=arguments(evidence_sha256="b" * 64),
                event=4,
            ),
        )
        immutable = self.empty
        workspace = transition._TransitionWorkspace(self.empty)
        for item in trace:
            immutable = transition.reduce_transition(immutable, item)
            staged = workspace.stage(item)
            if item.operation == "GOVERNANCE_BLOCK":
                self.assertEqual(staged.after_task.code, "B0")
                self.assertEqual(
                    staged.delta.claim_writes[0].after.status,
                    "GOVERNANCE_INVALIDATED",
                )
            workspace.commit(staged)
        self.assertEqual(workspace.freeze(), immutable)
        final = workspace.freeze()
        self.assertEqual(final.tasks[0].code, "N0")
        self.assertEqual(final.tasks[0].decision_receipt_digest, "b" * 64)
        self.assertEqual(final.tasks[0].dispatch_generation, 2)
        self.assertEqual(final.tasks[0].task_fence, 2)
        self.assertEqual(final.claims[0].status, "GOVERNANCE_INVALIDATED")

        completed = transition.reduce_transition(self.empty, initialize_intent(11))
        completed = transition.reduce_transition(
            completed,
            intent(
                "CLAIM",
                args=arguments(actor="worker-fixture"),
                generated_id=uuid4(110),
                event=12,
            ),
        )
        completed = transition.reduce_transition(
            completed,
            intent("START", args=arguments(claim_id=uuid4(110), fence=1), event=13),
        )
        completed = transition.reduce_transition(
            completed,
            intent(
                "COMPLETE",
                args=arguments(
                    claim_id=uuid4(110),
                    close=False,
                    completion_evidence_sha256=DIGEST,
                    fence=1,
                ),
                event=14,
            ),
        )
        completed = transition.reduce_transition(
            completed,
            intent(
                "ASSIGN_REVIEW",
                args=arguments(actor="skeptic-fixture", role="05 Skeptic"),
                generated_id=uuid4(120),
                event=15,
            ),
        )
        review_workspace = transition._TransitionWorkspace(completed)
        block_review = intent(
            "GOVERNANCE_BLOCK",
            args=arguments(evidence_sha256=DIGEST, reason_code="STOP"),
            event=16,
        )
        staged = review_workspace.stage(block_review)
        self.assertEqual(staged.after_task.code, "B1")
        self.assertEqual(
            staged.delta.review_writes[0].after.status,
            "GOVERNANCE_REVOKED",
        )
        review_workspace.commit(staged)
        completed = transition.reduce_transition(completed, block_review)
        self.assertEqual(review_workspace.freeze(), completed)

    def test_only_governance_block_may_consume_a_stale_workspace_task(self) -> None:
        current = transition.reduce_transition(self.empty, initialize_intent())
        stale = replace(
            current,
            repository_generation=1,
            repository_bundle_sha256="b" * 64,
        )
        workspace = transition._TransitionWorkspace(stale)
        before = workspace.freeze()
        with self.assertRaises(transition.TransitionViolation) as caught:
            workspace.stage(
                intent(
                    "REVALIDATE",
                    args=arguments(evidence_sha256=DIGEST),
                    event=2,
                )
            )
        self.assertEqual(caught.exception.code, "TRANSITION_STALE_TASK")
        self.assertEqual(workspace.freeze(), before)

        staged = workspace.stage(
            intent(
                "GOVERNANCE_BLOCK",
                args=arguments(evidence_sha256=DIGEST, reason_code="STALE"),
                event=3,
            )
        )
        self.assertEqual(staged.after_task.repository_generation, 1)
        workspace.commit(staged)
        self.assertEqual(workspace.freeze().tasks[0].code, "B0")

    def test_review_decisions_and_route_share_one_atomic_workspace(self) -> None:
        targets = {
            "APPROVE": ("N7", "APPROVED"),
            "REJECT": ("N5", "REJECTED"),
            "REMEDIATE": ("N6", "REMEDIATION_REQUIRED"),
        }
        for operation, (target, review_status) in targets.items():
            with self.subTest(operation=operation):
                claim_id = uuid4(200)
                assignment_id = uuid4(201)
                trace = (
                    initialize_intent(1),
                    intent(
                        "CLAIM",
                        args=arguments(actor="worker-fixture"),
                        generated_id=claim_id,
                        event=2,
                    ),
                    intent(
                        "START",
                        args=arguments(claim_id=claim_id, fence=1),
                        event=3,
                    ),
                    intent(
                        "COMPLETE",
                        args=arguments(
                            claim_id=claim_id,
                            close=False,
                            completion_evidence_sha256=DIGEST,
                            fence=1,
                        ),
                        event=4,
                    ),
                    intent(
                        "ASSIGN_REVIEW",
                        args=arguments(
                            actor="skeptic-fixture", role="05 Skeptic"
                        ),
                        generated_id=assignment_id,
                        event=5,
                    ),
                    intent(
                        operation,
                        args=arguments(
                            assignment_id=assignment_id,
                            decision_sha256="b" * 64,
                        ),
                        event=6,
                    ),
                )
                immutable = self.empty
                workspace = transition._TransitionWorkspace(self.empty)
                for item in trace:
                    immutable = transition.reduce_transition(immutable, item)
                    staged = workspace.stage(item)
                    if item.operation == operation:
                        self.assertEqual(len(staged.delta.review_writes), 1)
                        self.assertEqual(len(staged.delta.decision_writes), 1)
                        self.assertEqual(
                            staged.delta.review_writes[0].after.status,
                            review_status,
                        )
                        self.assertEqual(
                            staged.delta.decision_writes[0].after.operation,
                            operation,
                        )
                    workspace.commit(staged)
                frozen = workspace.freeze()
                self.assertEqual(frozen, immutable)
                self.assertEqual(frozen.tasks[0].code, target)
                self.assertEqual(frozen.reviews[0].status, review_status)
                self.assertEqual(frozen.reviews[0].closed_event_id, uuid4(6))
                self.assertEqual(frozen.decisions[0].decision_sha256, "b" * 64)

                if operation == "APPROVE":
                    route = intent(
                        "ROUTE",
                        args=arguments(routing_evidence_sha256="c" * 64),
                        event=7,
                    )
                    immutable = transition.reduce_transition(immutable, route)
                    self.commit(workspace, route)
                    routed = workspace.freeze()
                    self.assertEqual(routed, immutable)
                    self.assertEqual(routed.tasks[0].code, "N8")
                    self.assertEqual(routed.reviews[0].status, "APPROVED")
                    self.assertEqual(routed.decisions, frozen.decisions)

    def test_remediation_replacement_stages_and_commits_atomically(self) -> None:
        claim_id = uuid4(220)
        assignment_id = uuid4(221)
        workspace = transition._TransitionWorkspace(self.empty)
        for item in (
            initialize_intent(1),
            intent(
                "CLAIM",
                args=arguments(actor="worker-fixture"),
                generated_id=claim_id,
                event=2,
            ),
            intent(
                "START", args=arguments(claim_id=claim_id, fence=1), event=3,
            ),
            intent(
                "COMPLETE",
                args=arguments(
                    claim_id=claim_id,
                    close=False,
                    completion_evidence_sha256=DIGEST,
                    fence=1,
                ),
                event=4,
            ),
            intent(
                "ASSIGN_REVIEW",
                args=arguments(actor="skeptic-fixture", role="05 Skeptic"),
                generated_id=assignment_id,
                event=5,
            ),
            intent(
                "REJECT",
                args=arguments(
                    assignment_id=assignment_id,
                    decision_sha256="b" * 64,
                ),
                event=6,
            ),
        ):
            self.commit(workspace, item)
        before = workspace.freeze()
        remediation = transition.TransitionIntent(
            operation="CREATE_REMEDIATION_TASK",
            task_id="T1",
            attempt=1,
            child_task_id="T2",
            child_attempt=1,
            arguments=arguments(
                child_decision_receipt_digest="c" * 64,
                child_owner="remediation-owner",
                child_owner_role="research-remediation",
                decision_sha256="b" * 64,
                relationship_id=uuid4(222),
            ),
            semantic_event_ids=(uuid4(7), uuid4(8)),
        )
        staged = workspace.stage_remediation(remediation)
        self.assertEqual(workspace.revision, 6)
        self.assertEqual(workspace.freeze(), before)
        self.assertEqual(tuple(item.task_id for item in staged.after.tasks), ("T1", "T2"))
        self.assertEqual(staged.after.tasks[0].successor_task, "T2")
        self.assertEqual(staged.after.tasks[1].predecessor_task, "T1")
        self.assertEqual(staged.after.remediation_links[0].decision_sha256, "b" * 64)

        wrong = replace(
            remediation,
            arguments=arguments(
                child_decision_receipt_digest="c" * 64,
                child_owner="remediation-owner",
                child_owner_role="research-remediation",
                decision_sha256="d" * 64,
                relationship_id=uuid4(223),
            ),
        )
        with self.assertRaises(transition.TransitionViolation) as caught:
            workspace.stage_remediation(wrong)
        self.assertEqual(caught.exception.code, "TRANSITION_DECISION_MISMATCH")
        self.assertEqual(workspace.freeze(), before)

        workspace.commit(staged)
        after = workspace.freeze()
        self.assertEqual(workspace.revision, 7)
        self.assertEqual(len(after.tasks), 2)
        self.assertEqual(len(after.remediation_links), 1)

    def test_review_decision_rejects_reused_close_event_without_writes(self) -> None:
        claim_id = uuid4(210)
        assignment_id = uuid4(211)
        workspace = transition._TransitionWorkspace(self.empty)
        for item in (
            initialize_intent(1),
            intent(
                "CLAIM",
                args=arguments(actor="worker-fixture"),
                generated_id=claim_id,
                event=2,
            ),
            intent(
                "START", args=arguments(claim_id=claim_id, fence=1), event=3
            ),
            intent(
                "COMPLETE",
                args=arguments(
                    claim_id=claim_id,
                    close=False,
                    completion_evidence_sha256=DIGEST,
                    fence=1,
                ),
                event=4,
            ),
            intent(
                "ASSIGN_REVIEW",
                args=arguments(actor="skeptic-fixture", role="05 Skeptic"),
                generated_id=assignment_id,
                event=5,
            ),
        ):
            self.commit(workspace, item)
        before = workspace.freeze()
        with self.assertRaises(transition.TransitionViolation) as caught:
            workspace.stage(intent(
                "APPROVE",
                args=arguments(
                    assignment_id=assignment_id, decision_sha256=DIGEST
                ),
                event=5,
            ))
        self.assertEqual(caught.exception.code, "TRANSITION_STATE_EVENT_REUSED")
        self.assertEqual(workspace.freeze(), before)

    def test_group_patch_pair_mismatch_rejects_before_workspace_or_cursor_mutation(self) -> None:
        genesis = {
            "runtime_id": uuid4(900),
            "chain_id": DIGEST,
            "repository_generation": 0,
            "repository_bundle_sha256": DIGEST,
            "global_sequence": 0,
            "event_id": uuid4(901),
            "event_sha256": "b" * 64,
            "transaction": {
                "transaction_id": uuid4(902),
                "operation_key": "system:v2:genesis",
            },
        }
        cursor = group._ReplayCursor(genesis)
        workspace = transition._TransitionWorkspace(self.empty)
        staged = workspace.stage(initialize_intent(event=2))
        patch = group.InitializeGroupPatch(
            transition=staged,
            event_pair=(uuid4(2), "c" * 64, uuid4(3), "d" * 64),
            reachable_blob_digests=(),
            opens_attempt=True,
            predecessor_attempt=None,
            idempotency_row=(),
        )
        with self.assertRaises(group.GroupValidationError) as caught:
            initial._commit_group_patch(
                cursor=cursor,
                workspace=workspace,
                patch=patch,
                semantic_event={"event_id": uuid4(4), "event_sha256": "c" * 64},
                commit_event={"event_id": uuid4(3), "event_sha256": "d" * 64},
            )
        self.assertEqual(caught.exception.code, "GROUP_PATCH_PAIR")
        self.assertEqual(cursor.global_sequence, 0)
        self.assertEqual(workspace.revision, 0)
        self.assertEqual(workspace.freeze(), self.empty)

    def test_cursor_projects_cumulative_attempt_history_without_rewriting_old_heads(self) -> None:
        genesis = {
            "runtime_id": uuid4(900),
            "chain_id": DIGEST,
            "repository_generation": 0,
            "repository_bundle_sha256": DIGEST,
            "global_sequence": 0,
            "event_id": uuid4(901),
            "event_sha256": "b" * 64,
            "transaction": {
                "transaction_id": uuid4(902),
                "operation_key": "system:v2:genesis",
            },
        }
        cursor = group._ReplayCursor(genesis)
        first_root = group.task_predecessor(DIGEST, "T1", 1)
        first, first_commit = cursor_pair(
            1, attempt=1, task_sequence=1, predecessor=first_root
        )
        cursor.check_attempt_advance(
            first, opens_attempt=True, predecessor_attempt=None
        )
        cursor.advance_pair(
            first, first_commit, opens_attempt=True, predecessor_attempt=None
        )
        failed, failed_commit = cursor_pair(
            3,
            attempt=1,
            task_sequence=2,
            predecessor=(first["event_id"], first["event_sha256"]),
        )
        cursor.check_attempt_advance(
            failed, opens_attempt=False, predecessor_attempt=None
        )
        cursor.advance_pair(
            failed, failed_commit, opens_attempt=False, predecessor_attempt=None
        )
        old_row = cursor.attempt_rows()[0]

        retry_root = group.task_predecessor(DIGEST, "T1", 2)
        retried, retried_commit = cursor_pair(
            5, attempt=2, task_sequence=1, predecessor=retry_root
        )
        cursor.check_attempt_advance(
            retried, opens_attempt=True, predecessor_attempt=1
        )
        cursor.advance_pair(
            retried, retried_commit, opens_attempt=True, predecessor_attempt=1
        )
        claimed, claimed_commit = cursor_pair(
            7,
            attempt=2,
            task_sequence=2,
            predecessor=(retried["event_id"], retried["event_sha256"]),
        )
        cursor.check_attempt_advance(
            claimed, opens_attempt=False, predecessor_attempt=None
        )
        cursor.advance_pair(
            claimed, claimed_commit, opens_attempt=False, predecessor_attempt=None
        )

        rows = cursor.attempt_rows()
        self.assertEqual(rows[0], old_row)
        self.assertEqual(rows[0][4:], (2, failed["event_id"], failed["event_sha256"]))
        self.assertEqual(rows[1], (
            "T1", 2, 1, retried["event_id"], 2,
            claimed["event_id"], claimed["event_sha256"],
        ))

    def test_invalid_attempt_projection_metadata_rejects_before_any_commit(self) -> None:
        genesis = {
            "runtime_id": uuid4(900),
            "chain_id": DIGEST,
            "repository_generation": 0,
            "repository_bundle_sha256": DIGEST,
            "global_sequence": 0,
            "event_id": uuid4(901),
            "event_sha256": "b" * 64,
            "transaction": {
                "transaction_id": uuid4(902),
                "operation_key": "system:v2:genesis",
            },
        }
        cursor = group._ReplayCursor(genesis)
        workspace = transition._TransitionWorkspace(self.empty)
        staged = workspace.stage(initialize_intent(event=2))
        semantic, commit = cursor_pair(
            1, attempt=1, task_sequence=2, predecessor=(uuid4(910), "a" * 64)
        )
        patch = group.InitializeGroupPatch(
            transition=staged,
            event_pair=(
                semantic["event_id"], semantic["event_sha256"],
                commit["event_id"], commit["event_sha256"],
            ),
            reachable_blob_digests=(),
            opens_attempt=True,
            predecessor_attempt=None,
            idempotency_row=(),
        )
        with self.assertRaises(group.GroupValidationError) as caught:
            initial._commit_group_patch(
                cursor=cursor,
                workspace=workspace,
                patch=patch,
                semantic_event=semantic,
                commit_event=commit,
            )
        self.assertEqual(caught.exception.code, "GROUP_ATTEMPT_OPEN")
        self.assertEqual(workspace.revision, 0)
        self.assertEqual(cursor.global_sequence, 0)
        self.assertEqual(cursor.attempt_rows(), ())

        first_root = group.task_predecessor(DIGEST, "T1", 1)
        valid, valid_commit = cursor_pair(
            1, attempt=1, task_sequence=1, predecessor=first_root
        )
        cursor.check_attempt_advance(
            valid, opens_attempt=True, predecessor_attempt=None
        )
        cursor.advance_pair(
            valid, valid_commit, opens_attempt=True, predecessor_attempt=None
        )
        baseline = cursor.attempt_rows()
        third_root = group.task_predecessor(DIGEST, "T1", 3)
        skipped, _ = cursor_pair(
            3, attempt=3, task_sequence=1, predecessor=third_root
        )
        with self.assertRaises(group.GroupValidationError) as caught:
            cursor.check_attempt_advance(
                skipped, opens_attempt=True, predecessor_attempt=2
            )
        self.assertEqual(caught.exception.code, "GROUP_ATTEMPT_PREDECESSOR")
        self.assertEqual(cursor.attempt_rows(), baseline)

    def test_workspace_retry_matches_immutable_kernel_and_preserves_failed_claim(self) -> None:
        workspace = transition._TransitionWorkspace(self.empty)
        immutable = self.empty
        claim_id = uuid4(100)
        trace = (
            initialize_intent(event=1),
            intent(
                "CLAIM",
                args=arguments(actor="worker-fixture"),
                generated_id=claim_id,
                event=2,
            ),
            intent(
                "FAIL",
                args=arguments(
                    claim_id=claim_id,
                    failure_code="WORKER_ERROR",
                    failure_evidence_sha256=DIGEST,
                    fence=1,
                ),
                event=3,
            ),
        )
        for item in trace:
            immutable = transition.reduce_transition(immutable, item)
            self.commit(workspace, item)
        failed = workspace.freeze()
        failed_revision = workspace.revision
        for bad_retry, expected in (
            (
                intent(
                    "RETRY",
                    args=arguments(
                        retry_evidence_sha256=DIGEST, retryable=False
                    ),
                    event=40,
                ),
                "TRANSITION_RETRYABLE",
            ),
            (
                intent(
                    "RETRY",
                    attempt=2,
                    args=arguments(
                        retry_evidence_sha256=DIGEST, retryable=True
                    ),
                    event=41,
                ),
                "TRANSITION_ATTEMPT_MISMATCH",
            ),
        ):
            with self.subTest(expected=expected):
                with self.assertRaises(transition.TransitionViolation) as caught:
                    workspace.stage(bad_retry)
                self.assertEqual(caught.exception.code, expected)
                self.assertEqual(workspace.revision, failed_revision)
                self.assertEqual(workspace.freeze(), failed)
        retry = intent(
            "RETRY",
            args=arguments(retry_evidence_sha256=DIGEST, retryable=True),
            event=4,
        )
        staged = workspace.stage(retry)
        self.assertEqual(len(staged.delta.task_writes), 1)
        self.assertEqual(staged.delta.claim_writes, ())
        workspace.commit(staged)
        immutable = transition.reduce_transition(immutable, retry)
        retried = workspace.freeze()
        self.assertEqual(retried, immutable)
        self.assertEqual(retried.tasks[0].attempt, 2)
        self.assertEqual(retried.tasks[0].code, "N0")
        self.assertEqual(retried.tasks[0].scheduler_generation, 3)
        self.assertEqual(retried.tasks[0].dispatch_generation, 3)
        self.assertEqual(retried.tasks[0].task_fence, 3)
        self.assertEqual(retried.claims, failed.claims)
        self.assertEqual(retried.claims[0].status, "FAILED")

    def test_workspace_scope_is_closed_and_private(self) -> None:
        workspace = transition._TransitionWorkspace(self.empty)
        with self.assertRaises(transition.TransitionViolation) as caught:
            workspace.stage(
                intent(
                    "CHECKPOINT",
                    args=arguments(checkpoint_sha256=DIGEST),
                )
            )
        self.assertEqual(caught.exception.code, "TRANSITION_OPERATION_OUTSIDE_WORKSPACE")
        self.assertNotIn("_TransitionWorkspace", transition.__all__)
        self.assertNotIn("_StagedTransition", transition.__all__)

    def test_freeze_remains_the_full_invariant_backstop(self) -> None:
        workspace = transition._TransitionWorkspace(self.empty)
        self.commit(workspace, initialize_intent())
        task = workspace.task("T1")
        assert task is not None
        workspace._tasks["T1"] = transition._with_code(
            task, "N1", active_claim_id=uuid4(999)
        )
        with self.assertRaises(transition.TransitionViolation) as caught:
            workspace.freeze()
        self.assertEqual(caught.exception.code, "TRANSITION_STATE_CLAIM_CLOSURE")


if __name__ == "__main__":
    unittest.main()
