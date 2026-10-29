"""Adversarial cursor-relative INITIALIZE replay tests for runtime v2."""
import json
import unittest
from dataclasses import replace

from src.edgelab.runtime_v2_codec import (
    blob_digest,
    canonical_json,
    event_digest,
    task_predecessor,
)
from src.edgelab.runtime_v2_genesis import (
    PAYLOAD_SCHEMA_ID,
    REQUEST_SCHEMA_ID,
    RESPONSE_SCHEMA_ID,
)
from src.edgelab.runtime_v2_group import TASK_STATE_SCHEMA_ID
from src.edgelab.runtime_v2_image import BlobRecord, TABLE_NAMES, TableSnapshot
from src.edgelab.runtime_v2_initial import reduce_initial_runtime_image
from tests.test_runtime_v2_initial import (
    CHAIN_ID,
    RUNTIME_ID,
    _append_import_fixture,
    _rehash_group_request,
    _rehash_semantic_context,
    claim_fixture,
    fixture,
    initialize_fixture,
)
from tests.test_runtime_v2_snapshot import _append_snapshot


def _append_initialize(image, values, *, task_id, ordinal):
    """Append one exact absent-task INITIALIZE at the retained global head."""
    rows = {snapshot.table: snapshot.rows for snapshot in image.table_snapshots}
    metadata = rows["metadata"][0]
    generation = metadata[13]
    repository_bundle = metadata[14]
    parsed_events = tuple(json.loads(raw) for raw in image.events)
    head = parsed_events[-1]
    semantic_index = head["global_sequence"] + 1
    commit_index = semantic_index + 1
    base = 700 + ordinal * 3
    semantic_id = f"123e4567-e89b-42d3-a456-42661417{base:04d}"
    commit_id = f"123e4567-e89b-42d3-a456-42661417{base + 1:04d}"
    transaction_id = f"123e4567-e89b-42d3-a456-42661417{base + 2:04d}"
    operation_key = f"v2:{CHAIN_ID}:initialize-{task_id}-{ordinal}"
    occurred_at = f"2026-11-{ordinal + 1:02d}T00:00:00Z"
    receipt = f"{(ordinal % 9) + 1}" * 64
    state = {
        "task_id": task_id,
        "attempt": 1,
        "workflow": "ACTIVE",
        "execution": "CLAIMABLE",
        "review": "NOT_REQUIRED",
        "scheduler_generation": 0,
        "dispatch_generation": 0,
        "task_fence": 0,
        "active_claim_id": None,
        "reviewer_assignment_id": None,
        "continuation_count": 0,
        "repository_generation": generation,
        "decision_receipt_digest": receipt,
        "owner": "03 Research",
        "owner_role": "research",
        "reviewer": None,
        "predecessor_task": None,
        "successor_task": None,
    }
    state_sha = blob_digest(state)
    request = {
        "schema_version": 1,
        "request_format_version": 2,
        "runtime_id": RUNTIME_ID,
        "chain_id": CHAIN_ID,
        "operation": "INITIALIZE",
        "operation_key": operation_key,
        "repository_generation": generation,
        "repository_bundle_sha256": repository_bundle,
        "subject": {"task_id": task_id, "attempt": 1},
        "expected_state_ref": None,
        "arguments": {
            "decision_receipt_digest": receipt,
            "owner": "03 Research",
            "owner_role": "research",
        },
    }
    response = {
        "schema_version": 1,
        "response_format_version": 2,
        "runtime_id": RUNTIME_ID,
        "chain_id": CHAIN_ID,
        "operation": "INITIALIZE",
        "operation_key": operation_key,
        "status": "COMMITTED",
        "affected_states": [{
            "task_id": task_id,
            "attempt": 1,
            "state_ref": {
                "schema_id": TASK_STATE_SCHEMA_ID,
                "sha256": state_sha,
            },
        }],
        "generated_refs": [],
    }
    semantic_payload = {
        "schema_version": 1,
        "payload_format_version": 2,
        "event_type": "TASK_INITIALIZED",
        "data": {},
    }
    request_sha = blob_digest(request)
    response_sha = blob_digest(response)
    semantic_payload_sha = blob_digest(semantic_payload)
    predecessor_id, predecessor_sha = task_predecessor(CHAIN_ID, task_id, 1)
    semantic = {
        "schema_version": 1,
        "event_format_version": 2,
        "runtime_id": RUNTIME_ID,
        "chain_id": CHAIN_ID,
        "event_id": semantic_id,
        "event_type": "TASK_INITIALIZED",
        "occurred_at": occurred_at,
        "global_sequence": semantic_index,
        "global_predecessor": {
            "event_id": head["event_id"],
            "event_sha256": head["event_sha256"],
        },
        "stream": "TASK",
        "task_context": {
            "task_id": task_id,
            "attempt": 1,
            "task_sequence": 1,
            "task_predecessor": {
                "event_id": predecessor_id,
                "event_sha256": predecessor_sha,
            },
        },
        "transaction": {
            "transaction_id": transaction_id,
            "position": 0,
            "event_count": 2,
            "operation_key": operation_key,
            "request_sha256": request_sha,
            "response_sha256": response_sha,
        },
        "payload_ref": {
            "schema_id": PAYLOAD_SCHEMA_ID,
            "sha256": semantic_payload_sha,
        },
        "state_before_ref": None,
        "state_after_ref": {
            "schema_id": TASK_STATE_SCHEMA_ID,
            "sha256": state_sha,
        },
        "repository_generation": generation,
        "repository_bundle_sha256": repository_bundle,
        "authority_binding_sha256": None,
        "authorizing_use": "DENY",
        "event_sha256": "0" * 64,
    }
    semantic["event_sha256"] = event_digest(semantic)
    commit_payload = {
        "schema_version": 1,
        "payload_format_version": 2,
        "event_type": "COMMAND_COMMITTED",
        "data": {
            "semantic_event_ids": [semantic_id],
            "pre_command_head": {
                "global_sequence": head["global_sequence"],
                "event_id": head["event_id"],
                "event_sha256": head["event_sha256"],
            },
            "post_semantic_head": {
                "global_sequence": semantic_index,
                "event_id": semantic_id,
                "event_sha256": semantic["event_sha256"],
            },
            "operation": "INITIALIZE",
            "operation_key": operation_key,
            "request_ref": {
                "schema_id": REQUEST_SCHEMA_ID,
                "sha256": request_sha,
            },
            "response_ref": {
                "schema_id": RESPONSE_SCHEMA_ID,
                "sha256": response_sha,
            },
            "result": "COMMITTED",
        },
    }
    commit_payload_sha = blob_digest(commit_payload)
    commit = {
        "schema_version": 1,
        "event_format_version": 2,
        "runtime_id": RUNTIME_ID,
        "chain_id": CHAIN_ID,
        "event_id": commit_id,
        "event_type": "COMMAND_COMMITTED",
        "occurred_at": occurred_at,
        "global_sequence": commit_index,
        "global_predecessor": {
            "event_id": semantic_id,
            "event_sha256": semantic["event_sha256"],
        },
        "stream": "RUNTIME",
        "task_context": None,
        "transaction": {
            "transaction_id": transaction_id,
            "position": 1,
            "event_count": 2,
            "operation_key": operation_key,
            "request_sha256": request_sha,
            "response_sha256": response_sha,
        },
        "payload_ref": {
            "schema_id": PAYLOAD_SCHEMA_ID,
            "sha256": commit_payload_sha,
        },
        "state_before_ref": None,
        "state_after_ref": None,
        "repository_generation": generation,
        "repository_bundle_sha256": repository_bundle,
        "authority_binding_sha256": None,
        "authorizing_use": "DENY",
        "event_sha256": "0" * 64,
    }
    commit["event_sha256"] = event_digest(commit)
    additions = (
        BlobRecord(request_sha, REQUEST_SCHEMA_ID, canonical_json(request)),
        BlobRecord(response_sha, RESPONSE_SCHEMA_ID, canonical_json(response)),
        BlobRecord(
            semantic_payload_sha,
            PAYLOAD_SCHEMA_ID,
            canonical_json(semantic_payload),
        ),
        BlobRecord(
            commit_payload_sha,
            PAYLOAD_SCHEMA_ID,
            canonical_json(commit_payload),
        ),
        BlobRecord(state_sha, TASK_STATE_SCHEMA_ID, canonical_json(state)),
    )
    blob_by_digest = {record.sha256: record for record in image.blobs}
    for addition in additions:
        blob_by_digest.setdefault(addition.sha256, addition)
    blobs = tuple(sorted(blob_by_digest.values(), key=lambda item: item.sha256))
    rows["blobs"] = tuple(
        (record.sha256, record.schema_id, record.canonical_json.decode("ascii"))
        for record in blobs
    )
    rows["events"] += (
        (
            semantic_index,
            semantic_id,
            semantic["event_sha256"],
            canonical_json(semantic).decode("ascii"),
        ),
        (
            commit_index,
            commit_id,
            commit["event_sha256"],
            canonical_json(commit).decode("ascii"),
        ),
    )
    rows["attempts"] = tuple(sorted(rows["attempts"] + ((
        task_id,
        1,
        None,
        semantic_id,
        1,
        semantic_id,
        semantic["event_sha256"],
    ),), key=lambda row: row[:2]))
    rows["idempotency"] = tuple(sorted(rows["idempotency"] + ((
        operation_key,
        transaction_id,
        request_sha,
        response_sha,
        commit_id,
        commit_index,
        occurred_at,
    ),)))
    metadata = list(metadata)
    metadata[15:18] = [commit_index, commit_id, commit["event_sha256"]]
    rows["metadata"] = (tuple(metadata),)
    task_row = (
        task_id, 1, "ACTIVE", "CLAIMABLE", "NOT_REQUIRED", 0, 0, 0,
        None, None, 0, generation, receipt, "03 Research", "research",
        None, None, None,
    )
    rows["tasks"] = tuple(sorted(rows["tasks"] + (task_row,)))
    result = replace(
        image,
        blobs=blobs,
        events=image.events + (canonical_json(semantic), canonical_json(commit)),
        table_snapshots=tuple(
            TableSnapshot(name, rows[name]) for name in TABLE_NAMES
        ),
    )
    prefix = f"initialize_{ordinal}"
    values.update({
        f"{prefix}_request": request,
        f"{prefix}_response": response,
        f"{prefix}_after_state": state,
        f"{prefix}_semantic_payload": semantic_payload,
        f"{prefix}_commit_payload": commit_payload,
        f"{prefix}_semantic": semantic,
        f"{prefix}_commit": commit,
    })
    return result, values


def _rehash_last_transaction_identity(image, values, prefix, transaction_id):
    semantic = json.loads(json.dumps(values[f"{prefix}_semantic"]))
    commit = json.loads(json.dumps(values[f"{prefix}_commit"]))
    semantic["transaction"]["transaction_id"] = transaction_id
    commit["transaction"]["transaction_id"] = transaction_id
    semantic["event_sha256"] = event_digest(semantic)
    commit_payload = json.loads(json.dumps(values[f"{prefix}_commit_payload"]))
    commit_payload["data"]["post_semantic_head"]["event_sha256"] = semantic[
        "event_sha256"
    ]
    commit_payload_sha = blob_digest(commit_payload)
    commit["global_predecessor"]["event_sha256"] = semantic["event_sha256"]
    commit["payload_ref"]["sha256"] = commit_payload_sha
    commit["event_sha256"] = event_digest(commit)
    old_payload = blob_digest(values[f"{prefix}_commit_payload"])
    blobs = {
        record.sha256: record for record in image.blobs
        if record.sha256 != old_payload
    }
    blobs[commit_payload_sha] = BlobRecord(
        commit_payload_sha, PAYLOAD_SCHEMA_ID, canonical_json(commit_payload)
    )
    return replace(
        image,
        blobs=tuple(sorted(blobs.values(), key=lambda item: item.sha256)),
        events=image.events[:-2] + (
            canonical_json(semantic), canonical_json(commit)
        ),
    )


class RuntimeV2InitializeReplayTests(unittest.TestCase):
    @staticmethod
    def codes(report):
        return {item.code for item in report.violations}

    def assert_deny_only(self, image):
        report = reduce_initial_runtime_image(image)
        self.assertEqual(report.status, "UNSUPPORTED")
        self.assertEqual(self.codes(report), {"CLOSURE_NOT_COMPILED"})
        self.assertEqual(report.authorizing_use, "DENY")

    def test_distinct_tasks_initialize_after_snapshot_and_import_prefixes(self):
        image, values = initialize_fixture()
        image, _ = _append_snapshot(image, kind="CHECKPOINT", ordinal=10)
        image, values = _append_import_fixture(
            image, values, affected_task_ids=(), ordinal=3,
        )
        image, values = _append_initialize(
            image, values, task_id="task-beta", ordinal=1,
        )
        self.assert_deny_only(image)
        rows = {snapshot.table: snapshot.rows for snapshot in image.table_snapshots}
        self.assertEqual([row[0] for row in rows["tasks"]], ["task-alpha", "task-beta"])
        self.assertEqual(rows["tasks"][0][11], 0)
        self.assertEqual(rows["tasks"][1][11], 1)
        self.assertEqual(rows["attempts"][0][4], 1)
        self.assertEqual(rows["attempts"][1][4], 1)

    def test_first_task_initializes_after_empty_genesis_import(self):
        image, values = fixture()
        image, values = _append_import_fixture(
            image, values, affected_task_ids=(), ordinal=12,
        )
        image, _ = _append_initialize(
            image, values, task_id="task-first-after-import", ordinal=12,
        )
        self.assert_deny_only(image)
        rows = {
            snapshot.table: snapshot.rows for snapshot in image.table_snapshots
        }
        self.assertEqual(len(rows["tasks"]), 1)
        self.assertEqual(rows["tasks"][0][0], "task-first-after-import")
        self.assertEqual(rows["tasks"][0][11], 1)
        self.assertEqual(rows["attempts"][0][:5], (
            "task-first-after-import", 1, None,
            values["initialize_12_semantic"]["event_id"], 1,
        ))

    def test_first_task_initializes_after_snapshot_only_prefixes(self):
        for kind, snapshot_ordinal, initialize_ordinal in (
            ("CHECKPOINT", 10, 13),
            ("EXPORT", 11, 14),
        ):
            with self.subTest(kind=kind):
                image, values = fixture()
                image, _ = _append_snapshot(
                    image, kind=kind, ordinal=snapshot_ordinal,
                )
                image, _ = _append_initialize(
                    image,
                    values,
                    task_id=f"task-first-after-{kind.lower()}",
                    ordinal=initialize_ordinal,
                )
                self.assert_deny_only(image)

    def test_distinct_tasks_initialize_directly_and_after_export(self):
        direct, direct_values = initialize_fixture()
        direct, _ = _append_initialize(
            direct, direct_values, task_id="task-beta", ordinal=8,
        )
        self.assert_deny_only(direct)

        exported, export_values = initialize_fixture()
        exported, _ = _append_snapshot(exported, kind="EXPORT", ordinal=11)
        exported, _ = _append_initialize(
            exported, export_values, task_id="task-export-tail", ordinal=9,
        )
        self.assert_deny_only(exported)

    def test_initialize_selection_is_position_and_parity_independent(self):
        odd, odd_values = initialize_fixture()
        odd, odd_values = _append_import_fixture(
            odd, odd_values, affected_task_ids=(), ordinal=4,
        )
        odd, _ = _append_initialize(
            odd, odd_values, task_id="task-odd-tail", ordinal=2,
        )
        even, even_values = initialize_fixture()
        even, even_values = _append_import_fixture(
            even, even_values, affected_task_ids=("task-alpha",), ordinal=5,
        )
        even, _ = _append_initialize(
            even, even_values, task_id="task-even-tail", ordinal=3,
        )
        self.assertEqual(json.loads(odd.events[-2])["global_sequence"] % 2, 1)
        self.assertEqual(json.loads(even.events[-2])["global_sequence"] % 2, 0)
        self.assert_deny_only(odd)
        self.assert_deny_only(even)

    def test_duplicate_task_and_stale_repository_coordinates_fail_closed(self):
        image, values = initialize_fixture()
        image, values = _append_initialize(
            image, values, task_id="task-beta", ordinal=4,
        )
        prefix = "initialize_4"
        duplicate = _rehash_group_request(
            image, values, prefix,
            lambda request: request["subject"].update(task_id="task-alpha"),
        )
        report = reduce_initial_runtime_image(duplicate)
        self.assertEqual(report.status, "INVALID")
        self.assertIn("GROUP_TASK_SELECTION", self.codes(report))

        imported, values = _append_import_fixture(
            image, values, affected_task_ids=(), ordinal=6,
        )
        imported, values = _append_initialize(
            imported, values, task_id="task-gamma", ordinal=5,
        )
        stale = _rehash_group_request(
            imported, values, "initialize_5",
            lambda request: request.update(repository_generation=0),
        )
        report = reduce_initial_runtime_image(stale)
        self.assertEqual(report.status, "INVALID")
        self.assertIn("GROUP_CONST", self.codes(report))

        stale_bundle = _rehash_group_request(
            imported, values, "initialize_5",
            lambda request: request.update(
                repository_bundle_sha256="2" * 64
            ),
        )
        report = reduce_initial_runtime_image(stale_bundle)
        self.assertEqual(report.status, "INVALID")
        self.assertIn("GROUP_CONST", self.codes(report))

    def test_initialize_rejects_reused_identity_and_hostile_scalar_types(self):
        image, values = initialize_fixture()
        image, values = _append_initialize(
            image, values, task_id="task-beta", ordinal=6,
        )
        prior_transaction = json.loads(image.events[1])["transaction"][
            "transaction_id"
        ]
        reused = _rehash_last_transaction_identity(
            image, values, "initialize_6", prior_transaction,
        )
        report = reduce_initial_runtime_image(reused)
        self.assertEqual(report.status, "INVALID")
        self.assertIn("GROUP_TRANSACTION_DUPLICATE", self.codes(report))

        for field, hostile in (
            ("repository_generation", True),
            ("repository_bundle_sha256", ["2" * 64]),
        ):
            attacked = _rehash_group_request(
                image,
                values,
                "initialize_6",
                lambda request, field=field, hostile=hostile: request.update(
                    {field: hostile}
                ),
            )
            with self.subTest(field=field):
                report = reduce_initial_runtime_image(attacked)
                self.assertEqual(report.status, "INVALID")
                self.assertIn("GROUP_CONST", self.codes(report))

        for subject_field, hostile in (
            ("task_id", ["task-beta"]),
            ("attempt", True),
        ):
            attacked = _rehash_group_request(
                image,
                values,
                "initialize_6",
                lambda request, subject_field=subject_field, hostile=hostile:
                    request["subject"].update({subject_field: hostile}),
            )
            with self.subTest(subject_field=subject_field):
                report = reduce_initial_runtime_image(attacked)
                self.assertEqual(report.status, "INVALID")
                self.assertTrue(
                    {"GROUP_PATTERN", "GROUP_CONST"} & self.codes(report)
                )

    def test_initialize_preserves_unrelated_claim_and_attempt_history(self):
        image, values = claim_fixture()
        rows_before = {
            snapshot.table: snapshot.rows for snapshot in image.table_snapshots
        }
        image, _ = _append_initialize(
            image, values, task_id="task-beta", ordinal=10,
        )
        self.assert_deny_only(image)
        rows_after = {
            snapshot.table: snapshot.rows for snapshot in image.table_snapshots
        }
        self.assertEqual(rows_after["claims"], rows_before["claims"])
        self.assertEqual(rows_after["attempts"][0], rows_before["attempts"][0])
        self.assertEqual(rows_after["tasks"][0], rows_before["tasks"][0])
        self.assertEqual(rows_after["reviews"], rows_before["reviews"])
        self.assertEqual(
            rows_after["remediation_links"], rows_before["remediation_links"]
        )

    def test_partial_forged_root_and_materialization_attacks_fail_closed(self):
        image, values = initialize_fixture()
        image, values = _append_initialize(
            image, values, task_id="task-beta", ordinal=11,
        )
        partial = replace(image, events=image.events[:-1])
        report = reduce_initial_runtime_image(partial)
        self.assertEqual(report.status, "INVALID")
        self.assertIn("GROUP_EVENT_COUNT", self.codes(report))

        forged = _rehash_semantic_context(
            image,
            values,
            "initialize_11",
            lambda context: context["task_predecessor"].update(
                event_sha256="f" * 64
            ),
        )
        report = reduce_initial_runtime_image(forged)
        self.assertEqual(report.status, "INVALID")
        self.assertIn("GROUP_CONST", self.codes(report))

        snapshots = list(image.table_snapshots)
        task_index = TABLE_NAMES.index("tasks")
        tasks = list(snapshots[task_index].rows)
        changed = list(tasks[-1])
        changed[13] = "forged-owner"
        tasks[-1] = tuple(changed)
        snapshots[task_index] = TableSnapshot("tasks", tuple(tasks))
        report = reduce_initial_runtime_image(replace(
            image, table_snapshots=tuple(snapshots)
        ))
        self.assertEqual(report.status, "INVALID")
        self.assertIn("TABLE_DERIVATION", self.codes(report))

        extra = dict(values["initialize_11_after_state"])
        extra["task_id"] = "unreachable-task"
        extra_blob = BlobRecord(
            blob_digest(extra), TASK_STATE_SCHEMA_ID, canonical_json(extra)
        )
        report = reduce_initial_runtime_image(replace(
            image,
            blobs=tuple(sorted(
                image.blobs + (extra_blob,), key=lambda item: item.sha256
            )),
        ))
        self.assertEqual(report.status, "INVALID")
        self.assertIn("BLOB_REACHABILITY", self.codes(report))

    def test_invalid_tail_does_not_mutate_unrelated_candidate_history(self):
        image, values = initialize_fixture()
        prior_events = image.events
        prior_tasks = image.table_snapshots[TABLE_NAMES.index("tasks")].rows
        candidate, values = _append_initialize(
            image, values, task_id="task-beta", ordinal=7,
        )
        invalid = _rehash_group_request(
            candidate,
            values,
            "initialize_7",
            lambda request: request["subject"].update(attempt=2),
        )
        report = reduce_initial_runtime_image(invalid)
        self.assertEqual(report.status, "INVALID")
        self.assertIn("GROUP_CONST", self.codes(report))
        self.assertEqual(image.events, prior_events)
        self.assertEqual(
            image.table_snapshots[TABLE_NAMES.index("tasks")].rows,
            prior_tasks,
        )


if __name__ == "__main__":
    unittest.main()
