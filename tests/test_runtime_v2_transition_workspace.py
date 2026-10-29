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
            attempt_row=(),
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

    def test_workspace_scope_is_closed_and_private(self) -> None:
        workspace = transition._TransitionWorkspace(self.empty)
        with self.assertRaises(transition.TransitionViolation) as caught:
            workspace.stage(
                intent(
                    "RETRY",
                    args=arguments(retry_evidence_sha256=DIGEST, retryable=True),
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
