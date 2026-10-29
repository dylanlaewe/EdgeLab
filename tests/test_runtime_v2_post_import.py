"""Adversarial explicit task selection after runtime-v2 repository imports."""
import unittest

from src.edgelab.runtime_v2_initial import reduce_initial_runtime_image
from tests.test_runtime_v2_initial import (
    _append_claim_fixture,
    _append_governance_fixture,
    _append_import_fixture,
    _append_remediation_fixture,
    _append_retry_fixture,
    _append_review_assignment_fixture,
    _append_review_decision_fixture,
    _rehash_group_request,
    _rehash_semantic_context,
    _worker_fixture,
    claim_fixture,
    complete_review_fixture,
    fail_fixture,
    initialize_fixture,
)
from tests.test_runtime_v2_snapshot import _append_snapshot


def _remediated_fixture():
    image, values = complete_review_fixture()
    image, values = _append_review_assignment_fixture(image, values)
    image, values = _append_review_decision_fixture(
        image,
        values,
        operation="REJECT",
        prefix="reject",
        semantic_id="123e4567-e89b-42d3-a456-426614174167",
        commit_id="123e4567-e89b-42d3-a456-426614174168",
        transaction_id="123e4567-e89b-42d3-a456-426614174169",
    )
    return _append_remediation_fixture(image, values)


def _append_post_import_claim(image, values, state, *, prefix="post-import-claim"):
    values[prefix + "_selected_state"] = state
    return _append_claim_fixture(
        image,
        values,
        before_state_key=prefix + "_selected_state",
        prefix=prefix,
        semantic_id="123e4567-e89b-42d3-a456-426614175001",
        commit_id="123e4567-e89b-42d3-a456-426614175002",
        transaction_id="123e4567-e89b-42d3-a456-426614175003",
        claim_id="123e4567-e89b-42d3-a456-426614175004",
    )


class RuntimeV2PostImportSelectionTests(unittest.TestCase):
    @staticmethod
    def codes(report):
        return {item.code for item in report.violations}

    def assert_deny_only(self, image):
        report = reduce_initial_runtime_image(image)
        self.assertEqual(report.status, "UNSUPPORTED")
        self.assertEqual(self.codes(report), {"CLOSURE_NOT_COMPILED"})
        self.assertEqual(report.authorizing_use, "DENY")

    def test_selected_child_claim_preserves_unrelated_source_and_heads(self):
        image, values = _remediated_fixture()
        imported, values = _append_import_fixture(image, values)
        imported_rows = {
            item.table: item.rows for item in imported.table_snapshots
        }
        source_task = imported_rows["tasks"][0]
        source_attempt = next(
            row for row in imported_rows["attempts"]
            if row[:2] == ("task-alpha", 1)
        )
        unrelated_claims = imported_rows["claims"]
        unrelated_auxiliary = tuple(
            imported_rows[name] for name in ("reviews", "remediation_links")
        )
        selected = values["import_after_states"]["task-alpha-remediation"]
        claimed, values = _append_post_import_claim(imported, values, selected)

        self.assert_deny_only(claimed)
        rows = {item.table: item.rows for item in claimed.table_snapshots}
        self.assertEqual(rows["tasks"][0], source_task)
        self.assertEqual(
            next(row for row in rows["attempts"] if row[:2] == ("task-alpha", 1)),
            source_attempt,
        )
        self.assertTrue(all(row in rows["claims"] for row in unrelated_claims))
        self.assertEqual(
            tuple(rows[name] for name in ("reviews", "remediation_links")),
            unrelated_auxiliary,
        )
        self.assertEqual(rows["tasks"][1][8], values["post-import-claim_after_state"]["active_claim_id"])

    def test_imported_mandatory_rejected_source_can_create_its_child(self):
        image, values = complete_review_fixture()
        image, values = _append_review_assignment_fixture(image, values)
        image, values = _append_review_decision_fixture(
            image,
            values,
            operation="REJECT",
            prefix="reject",
            semantic_id="123e4567-e89b-42d3-a456-426614174167",
            commit_id="123e4567-e89b-42d3-a456-426614174168",
            transaction_id="123e4567-e89b-42d3-a456-426614174169",
        )
        imported, values = _append_import_fixture(image, values)
        values["post-import-rejected"] = values["import_after_states"]["task-alpha"]
        remediated, values = _append_remediation_fixture(
            imported,
            values,
            before_state_key="post-import-rejected",
        )
        self.assert_deny_only(remediated)
        rows = {item.table: item.rows for item in remediated.table_snapshots}
        self.assertEqual([row[0] for row in rows["tasks"]], [
            "task-alpha", "task-alpha-remediation",
        ])
        self.assertTrue(all(row[11] == 1 for row in rows["tasks"]))

    def test_odd_width_import_allows_mandatory_failed_task_retry(self):
        image, values = fail_fixture()
        imported, values = _append_import_fixture(image, values)
        self.assertEqual(len(values["import_semantic_events"]), 2)
        self.assertEqual(values["import_commit"]["transaction"]["event_count"], 3)
        values["post-import-failed"] = values["import_after_states"]["task-alpha"]
        retried, values = _append_retry_fixture(
            imported,
            values,
            before_state_key="post-import-failed",
            prefix="post-import-retry",
            semantic_id="123e4567-e89b-42d3-a456-426614175011",
            commit_id="123e4567-e89b-42d3-a456-426614175012",
            transaction_id="123e4567-e89b-42d3-a456-426614175013",
        )
        self.assert_deny_only(retried)
        self.assertEqual(values["post-import-retry_after_state"]["attempt"], 2)
        self.assertEqual(values["post-import-retry_after_state"]["repository_generation"], 1)

    def test_unlisted_stale_child_denies_claim_but_governance_block_consumes_it(self):
        image, values = _remediated_fixture()
        imported, values = _append_import_fixture(
            image, values, affected_task_ids=("task-alpha",),
        )
        stale = values["remediation_child_after_state"]
        attacked, _ = _append_post_import_claim(imported, dict(values), stale)
        report = reduce_initial_runtime_image(attacked)
        self.assertEqual(report.status, "INVALID")
        self.assertIn("TRANSITION_STALE_TASK", self.codes(report))

        values["stale-child"] = stale
        blocked, values = _append_governance_fixture(
            imported,
            values,
            before_state_key="stale-child",
            prefix="block-stale-child",
            semantic_id="123e4567-e89b-42d3-a456-426614175021",
            commit_id="123e4567-e89b-42d3-a456-426614175022",
            transaction_id="123e4567-e89b-42d3-a456-426614175023",
            operation="GOVERNANCE_BLOCK",
        )
        self.assert_deny_only(blocked)
        self.assertEqual(values["block-stale-child_after_state"]["repository_generation"], 1)

    def test_stale_active_claim_only_governance_block_can_close_it(self):
        image, values = claim_fixture()
        imported, values = _append_import_fixture(
            image, values, affected_task_ids=(),
        )
        attacked, _ = _worker_fixture(imported, dict(values), {
            "operation": "START",
            "prefix": "start-stale-claim",
            "before_state": "claim_after_state",
            "semantic_id": "123e4567-e89b-42d3-a456-426614175051",
            "commit_id": "123e4567-e89b-42d3-a456-426614175052",
            "transaction_id": "123e4567-e89b-42d3-a456-426614175053",
            "event_type": "TASK_STARTED",
        })
        report = reduce_initial_runtime_image(attacked)
        self.assertEqual(report.status, "INVALID")
        self.assertIn("TRANSITION_STALE_TASK", self.codes(report))

        values["stale-claimed"] = values["claim_after_state"]
        blocked, values = _append_governance_fixture(
            imported,
            values,
            before_state_key="stale-claimed",
            prefix="block-stale-claim",
            semantic_id="123e4567-e89b-42d3-a456-426614175054",
            commit_id="123e4567-e89b-42d3-a456-426614175055",
            transaction_id="123e4567-e89b-42d3-a456-426614175056",
            operation="GOVERNANCE_BLOCK",
        )
        self.assert_deny_only(blocked)
        rows = {item.table: item.rows for item in blocked.table_snapshots}
        self.assertEqual(rows["claims"][0][4], "GOVERNANCE_INVALIDATED")
        self.assertEqual(
            rows["claims"][0][7],
            "123e4567-e89b-42d3-a456-426614175054",
        )
        self.assertEqual(rows["tasks"][0][11], 1)

    def test_import_snapshot_then_selected_retry_preserves_cut_tail(self):
        image, values = fail_fixture()
        imported, values = _append_import_fixture(image, values)
        snapshotted, _ = _append_snapshot(
            imported, kind="CHECKPOINT", ordinal=10,
        )
        values["snapshot-selected"] = values["import_after_states"]["task-alpha"]
        retried, _ = _append_retry_fixture(
            snapshotted,
            values,
            before_state_key="snapshot-selected",
            prefix="post-snapshot-retry",
            semantic_id="123e4567-e89b-42d3-a456-426614175031",
            commit_id="123e4567-e89b-42d3-a456-426614175032",
            transaction_id="123e4567-e89b-42d3-a456-426614175033",
        )
        self.assert_deny_only(retried)
        rows = {item.table: item.rows for item in retried.table_snapshots}
        self.assertEqual(len(rows["snapshots"]), 1)
        self.assertEqual(rows["snapshots"][0][1], "CHECKPOINT")

    def test_repeated_imports_remain_replayable_and_stale_task_is_governable(self):
        image, values = initialize_fixture()
        first, values = _append_import_fixture(
            image, values, affected_task_ids=(), ordinal=1,
        )
        second, values = _append_import_fixture(
            first,
            values,
            affected_task_ids=(),
            next_bundle="8" * 64,
            ordinal=2,
        )
        values["twice-stale"] = values["initialize_state"]
        blocked, values = _append_governance_fixture(
            second,
            values,
            before_state_key="twice-stale",
            prefix="block-twice-stale",
            semantic_id="123e4567-e89b-42d3-a456-426614175041",
            commit_id="123e4567-e89b-42d3-a456-426614175042",
            transaction_id="123e4567-e89b-42d3-a456-426614175043",
            operation="GOVERNANCE_BLOCK",
        )
        self.assert_deny_only(blocked)
        self.assertEqual(values["block-twice-stale_after_state"]["repository_generation"], 2)

    def test_foreign_wrong_and_hostile_subjects_or_contexts_fail_closed(self):
        image, values = _remediated_fixture()
        imported, values = _append_import_fixture(image, values)
        valid, values = _append_post_import_claim(
            imported,
            values,
            values["import_after_states"]["task-alpha-remediation"],
        )
        attacks = (
            _rehash_group_request(
                valid, values, "post-import-claim",
                lambda request: request["subject"].update(task_id="foreign-task"),
            ),
            _rehash_group_request(
                valid, values, "post-import-claim",
                lambda request: request["subject"].update(attempt=2),
            ),
            _rehash_group_request(
                valid, values, "post-import-claim",
                lambda request: request.update(subject=[]),
            ),
            _rehash_group_request(
                valid, values, "post-import-claim",
                lambda request: request["subject"].update(task_id=[]),
            ),
            _rehash_group_request(
                valid, values, "post-import-claim",
                lambda request: request["subject"].update(attempt=True),
            ),
            _rehash_group_request(
                valid, values, "post-import-claim",
                lambda request: request["subject"].update(attempt="1"),
            ),
            _rehash_group_request(
                valid, values, "post-import-claim",
                lambda request: request["subject"].update(task_id="task-alpha"),
            ),
            _rehash_semantic_context(
                valid, values, "post-import-claim",
                lambda context: context.update(task_id="task-alpha"),
            ),
        )
        for attacked in attacks:
            with self.subTest():
                report = reduce_initial_runtime_image(attacked)
                self.assertEqual(report.status, "INVALID")
                self.assertNotEqual(self.codes(report), {"TABLE_DERIVATION"})


if __name__ == "__main__":
    unittest.main()
