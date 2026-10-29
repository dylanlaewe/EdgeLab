"""Adversarial checkpoint/export cut tests for private runtime-v2 replay."""
import json
import unittest
from dataclasses import replace

import src.edgelab.runtime_v2_initial as initial_module

from src.edgelab.runtime_v2_codec import (
    blob_digest,
    canonical_json,
    checkpoint_digest,
    event_digest,
    export_digest,
    selector_digest,
    selector_history_digest,
    table_root,
)
from src.edgelab.runtime_v2_genesis import (
    PAYLOAD_SCHEMA_ID,
    REQUEST_SCHEMA_ID,
    RESPONSE_SCHEMA_ID,
)
from src.edgelab.runtime_v2_image import (
    BlobRecord,
    TABLE_NAMES,
    TableSnapshot,
    inspect_runtime_image_host,
)
from src.edgelab.runtime_v2_initial import reduce_initial_runtime_image
from tests.test_runtime_v2_initial import (
    CHAIN_ID,
    RUNTIME_ID,
    _append_import_fixture,
    fixture,
    initialize_fixture,
)


CHECKPOINT_SCHEMA_ID = "urn:edgelab:m0-3a-runtime-checkpoint:2"
EXPORT_SCHEMA_ID = "urn:edgelab:m0-3a-runtime-export:2"


def _append_snapshot(image, *, kind, ordinal, copy=False):
    rows = {snapshot.table: snapshot.rows for snapshot in image.table_snapshots}
    roots = {
        name: table_root(name, [list(row) for row in rows[name]])
        for name in TABLE_NAMES
    }
    events = [json.loads(raw) for raw in image.events]
    head = events[-1]
    metadata = rows["metadata"][0]
    existing = [row for row in rows["snapshots"] if row[1] == kind]
    sequence = len(existing)
    prior = existing[-1][4] if existing else None
    semantic_id = f"123e4567-e89b-42d3-a456-42661417{500 + ordinal * 3:04d}"
    commit_id = f"123e4567-e89b-42d3-a456-42661417{501 + ordinal * 3:04d}"
    transaction_id = f"123e4567-e89b-42d3-a456-42661417{502 + ordinal * 3:04d}"
    snapshot_id = f"123e4567-e89b-42d3-a456-42661418{500 + ordinal:04d}"
    occurred_at = f"2026-10-{20 + ordinal:02d}T00:00:00Z"
    operation = "CHECKPOINT" if kind == "CHECKPOINT" else "EXPORT_SNAPSHOT"
    semantic_type = (
        "RUNTIME_CHECKPOINTED"
        if kind == "CHECKPOINT" else "RUNTIME_SNAPSHOT_EXPORTED"
    )
    digest_name = "checkpoint_sha256" if kind == "CHECKPOINT" else "export_sha256"
    blob_name = "checkpoint_blob_sha256" if kind == "CHECKPOINT" else "export_blob_sha256"
    sequence_name = "checkpoint_sequence" if kind == "CHECKPOINT" else "export_sequence"
    prior_name = "prior_checkpoint_sha256" if kind == "CHECKPOINT" else "prior_export_sha256"
    document = {
        "schema_version": 1,
        "runtime_format_version": 2,
        "runtime_id": RUNTIME_ID,
        "chain_id": CHAIN_ID,
        sequence_name: sequence,
        "through_global_sequence": head["global_sequence"],
        "head_event_id": head["event_id"],
        "head_event_sha256": head["event_sha256"],
        "manifest_sha256": metadata[7],
        prior_name: prior,
        "roots": roots,
        digest_name: "0" * 64,
        "anchor_status": "LOCAL_UNANCHORED",
        "currentness_status": "UNKNOWN",
        "authorizing_use": "DENY",
        "created_at": occurred_at,
    }
    if kind == "EXPORT":
        document["source_checkpoint_sha256"] = metadata[18]
    document[digest_name] = (
        checkpoint_digest(document) if kind == "CHECKPOINT" else export_digest(document)
    )
    document_blob_sha = blob_digest(document)
    arguments = {
        "snapshot_id": snapshot_id,
        sequence_name: sequence,
        digest_name: document[digest_name],
        blob_name: document_blob_sha,
        prior_name: prior,
    }
    selectors = [json.loads(raw) for raw in image.selector_history]
    next_selector = None
    if kind == "CHECKPOINT":
        generation = len(selectors)
        next_selector = {
            "schema_version": 1,
            "selector_format_version": 1,
            "selector_generation": generation,
            "active_runtime_format_version": 2,
            "active_runtime_id": RUNTIME_ID,
            "active_database_path": "runtime.v2.sqlite",
            "active_attachment_path": "attachment.v2.json",
            "active_manifest_path": "runtime.v2.manifest.json",
            "active_manifest_sha256": metadata[7],
            "latest_v2_checkpoint_sha256": document[digest_name],
            "selector_history_path": f"selectors/{generation:020d}.json",
            "prior_selector_path": f"selectors/{generation - 1:020d}.json",
            "prior_selector_sha256": selectors[-1]["selector_sha256"],
            "cutover_state": "V2_ACTIVE",
            "currentness_status": "UNKNOWN",
            "authorizing_use": "DENY",
            "written_at": occurred_at,
            "selector_sha256": "0" * 64,
        }
        next_selector["selector_sha256"] = selector_digest(next_selector)
        arguments.update({
            "next_selector_generation": generation,
            "next_selector_sha256": next_selector["selector_sha256"],
            "next_selector_history_sha256": selector_history_digest(
                selectors + [next_selector]
            ),
        })
    operation_key = f"v2:{CHAIN_ID}:{kind.lower()}-{ordinal}"
    request = {
        "schema_version": 1,
        "request_format_version": 2,
        "runtime_id": RUNTIME_ID,
        "chain_id": CHAIN_ID,
        "operation": operation,
        "operation_key": operation_key,
        "repository_generation": metadata[13],
        "repository_bundle_sha256": metadata[14],
        "subject": None,
        "expected_state_ref": None,
        "arguments": arguments,
    }
    response = {
        "schema_version": 1,
        "response_format_version": 2,
        "runtime_id": RUNTIME_ID,
        "chain_id": CHAIN_ID,
        "operation": operation,
        "operation_key": operation_key,
        "status": "COMMITTED",
        "affected_states": [],
        "generated_refs": [{
            "kind": kind,
            "identifier": snapshot_id,
            "sha256": document[digest_name],
        }],
    }
    cut_head = {
        "global_sequence": head["global_sequence"],
        "event_id": head["event_id"],
        "event_sha256": head["event_sha256"],
    }
    payload = {
        "schema_version": 1,
        "payload_format_version": 2,
        "event_type": semantic_type,
        "data": {**arguments, "cut_head": cut_head},
    }
    request_sha, response_sha, payload_sha = map(
        blob_digest, (request, response, payload)
    )
    common = {
        "schema_version": 1,
        "event_format_version": 2,
        "runtime_id": RUNTIME_ID,
        "chain_id": CHAIN_ID,
        "occurred_at": occurred_at,
        "repository_generation": metadata[13],
        "repository_bundle_sha256": metadata[14],
        "authority_binding_sha256": None,
        "authorizing_use": "DENY",
    }
    transaction = {
        "transaction_id": transaction_id,
        "position": 0,
        "event_count": 2,
        "operation_key": operation_key,
        "request_sha256": request_sha,
        "response_sha256": response_sha,
    }
    semantic = {
        **common,
        "event_id": semantic_id,
        "event_type": semantic_type,
        "global_sequence": head["global_sequence"] + 1,
        "global_predecessor": {
            "event_id": head["event_id"],
            "event_sha256": head["event_sha256"],
        },
        "stream": "RUNTIME",
        "task_context": None,
        "transaction": transaction,
        "payload_ref": {"schema_id": PAYLOAD_SCHEMA_ID, "sha256": payload_sha},
        "state_before_ref": None,
        "state_after_ref": None,
        "event_sha256": "0" * 64,
    }
    semantic["event_sha256"] = event_digest(semantic)
    commit_payload = {
        "schema_version": 1,
        "payload_format_version": 2,
        "event_type": "COMMAND_COMMITTED",
        "data": {
            "semantic_event_ids": [semantic_id],
            "pre_command_head": cut_head,
            "post_semantic_head": {
                "global_sequence": semantic["global_sequence"],
                "event_id": semantic_id,
                "event_sha256": semantic["event_sha256"],
            },
            "operation": operation,
            "operation_key": operation_key,
            "request_ref": {"schema_id": REQUEST_SCHEMA_ID, "sha256": request_sha},
            "response_ref": {"schema_id": RESPONSE_SCHEMA_ID, "sha256": response_sha},
            "result": "COMMITTED",
        },
    }
    commit_payload_sha = blob_digest(commit_payload)
    commit = {
        **common,
        "event_id": commit_id,
        "event_type": "COMMAND_COMMITTED",
        "global_sequence": semantic["global_sequence"] + 1,
        "global_predecessor": {
            "event_id": semantic_id,
            "event_sha256": semantic["event_sha256"],
        },
        "stream": "RUNTIME",
        "task_context": None,
        "transaction": {**transaction, "position": 1},
        "payload_ref": {
            "schema_id": PAYLOAD_SCHEMA_ID,
            "sha256": commit_payload_sha,
        },
        "state_before_ref": None,
        "state_after_ref": None,
        "event_sha256": "0" * 64,
    }
    commit["event_sha256"] = event_digest(commit)
    new_records = (
        BlobRecord(request_sha, REQUEST_SCHEMA_ID, canonical_json(request)),
        BlobRecord(response_sha, RESPONSE_SCHEMA_ID, canonical_json(response)),
        BlobRecord(payload_sha, PAYLOAD_SCHEMA_ID, canonical_json(payload)),
        BlobRecord(commit_payload_sha, PAYLOAD_SCHEMA_ID, canonical_json(commit_payload)),
        BlobRecord(
            document_blob_sha,
            CHECKPOINT_SCHEMA_ID if kind == "CHECKPOINT" else EXPORT_SCHEMA_ID,
            canonical_json(document),
        ),
    )
    blobs = tuple(sorted(image.blobs + new_records, key=lambda item: item.sha256))
    rows["blobs"] = tuple(
        (record.sha256, record.schema_id, record.canonical_json.decode("ascii"))
        for record in blobs
    )
    rows["events"] += (
        (semantic["global_sequence"], semantic_id, semantic["event_sha256"], canonical_json(semantic).decode("ascii")),
        (commit["global_sequence"], commit_id, commit["event_sha256"], canonical_json(commit).decode("ascii")),
    )
    rows["idempotency"] = tuple(sorted(rows["idempotency"] + ((
        operation_key, transaction_id, request_sha, response_sha, commit_id,
        commit["global_sequence"], occurred_at,
    ),)))
    rows["snapshots"] = tuple(sorted(rows["snapshots"] + ((
        snapshot_id, kind, sequence, semantic_id, document[digest_name],
        document_blob_sha, head["global_sequence"], head["event_id"],
        head["event_sha256"], prior, occurred_at,
    ),), key=lambda row: (row[1], row[2], row[0])))
    meta = list(metadata)
    meta[15:18] = [commit["global_sequence"], commit_id, commit["event_sha256"]]
    if kind == "CHECKPOINT":
        selectors.append(next_selector)
        meta[18:22] = [
            document[digest_name], next_selector["selector_generation"],
            next_selector["selector_sha256"], selector_history_digest(selectors),
        ]
    rows["metadata"] = (tuple(meta),)
    copies = image.checkpoint_copies + ((canonical_json(document),) if copy else ())
    return replace(
        image,
        blobs=blobs,
        events=image.events + (canonical_json(semantic), canonical_json(commit)),
        table_snapshots=tuple(TableSnapshot(name, rows[name]) for name in TABLE_NAMES),
        checkpoint_copies=copies,
        selector_history=tuple(canonical_json(selector) for selector in selectors),
    ), document


def _coherently_forge_export_root(image):
    """Rebind a sole export group after changing its claimed events root."""
    events = [json.loads(raw) for raw in image.events]
    semantic, commit = events[-2:]
    by_digest = {record.sha256: record for record in image.blobs}
    request = json.loads(by_digest[semantic["transaction"]["request_sha256"]].canonical_json)
    response = json.loads(by_digest[semantic["transaction"]["response_sha256"]].canonical_json)
    payload = json.loads(by_digest[semantic["payload_ref"]["sha256"]].canonical_json)
    commit_payload = json.loads(by_digest[commit["payload_ref"]["sha256"]].canonical_json)
    old_document_blob = request["arguments"]["export_blob_sha256"]
    document = json.loads(by_digest[old_document_blob].canonical_json)
    document["roots"]["events"] = "f" * 64
    document["export_sha256"] = export_digest(document)
    document_blob_sha = blob_digest(document)
    request["arguments"]["export_sha256"] = document["export_sha256"]
    request["arguments"]["export_blob_sha256"] = document_blob_sha
    payload["data"].update(request["arguments"])
    response["generated_refs"][0]["sha256"] = document["export_sha256"]
    request_sha, response_sha, payload_sha = map(
        blob_digest, (request, response, payload)
    )
    semantic["transaction"]["request_sha256"] = request_sha
    semantic["transaction"]["response_sha256"] = response_sha
    semantic["payload_ref"]["sha256"] = payload_sha
    semantic["event_sha256"] = event_digest(semantic)
    commit_payload["data"]["request_ref"]["sha256"] = request_sha
    commit_payload["data"]["response_ref"]["sha256"] = response_sha
    commit_payload["data"]["post_semantic_head"]["event_sha256"] = semantic["event_sha256"]
    commit_payload_sha = blob_digest(commit_payload)
    commit["transaction"]["request_sha256"] = request_sha
    commit["transaction"]["response_sha256"] = response_sha
    commit["global_predecessor"]["event_sha256"] = semantic["event_sha256"]
    commit["payload_ref"]["sha256"] = commit_payload_sha
    commit["event_sha256"] = event_digest(commit)
    # The image has only genesis plus this export, so retain the three genesis
    # blobs by excluding every old non-genesis record through its schema/value.
    retained = tuple(
        record for record in image.blobs
        if json.loads(record.canonical_json).get("operation") == "SYSTEM_GENESIS"
        or json.loads(record.canonical_json).get("event_type") == "RUNTIME_GENESIS"
    )
    additions = (
        BlobRecord(request_sha, REQUEST_SCHEMA_ID, canonical_json(request)),
        BlobRecord(response_sha, RESPONSE_SCHEMA_ID, canonical_json(response)),
        BlobRecord(payload_sha, PAYLOAD_SCHEMA_ID, canonical_json(payload)),
        BlobRecord(commit_payload_sha, PAYLOAD_SCHEMA_ID, canonical_json(commit_payload)),
        BlobRecord(document_blob_sha, EXPORT_SCHEMA_ID, canonical_json(document)),
    )
    blobs = tuple(sorted(retained + additions, key=lambda item: item.sha256))
    rows = {snapshot.table: snapshot.rows for snapshot in image.table_snapshots}
    rows["blobs"] = tuple(
        (record.sha256, record.schema_id, record.canonical_json.decode("ascii"))
        for record in blobs
    )
    rows["events"] = rows["events"][:1] + (
        (semantic["global_sequence"], semantic["event_id"], semantic["event_sha256"], canonical_json(semantic).decode("ascii")),
        (commit["global_sequence"], commit["event_id"], commit["event_sha256"], canonical_json(commit).decode("ascii")),
    )
    idem = list(rows["idempotency"][0])
    idem[2:4] = [request_sha, response_sha]
    rows["idempotency"] = (tuple(idem),)
    snapshot = list(rows["snapshots"][0])
    snapshot[4:6] = [document["export_sha256"], document_blob_sha]
    rows["snapshots"] = (tuple(snapshot),)
    metadata = list(rows["metadata"][0])
    metadata[17] = commit["event_sha256"]
    rows["metadata"] = (tuple(metadata),)
    return replace(
        image,
        blobs=blobs,
        events=image.events[:1] + (canonical_json(semantic), canonical_json(commit)),
        table_snapshots=tuple(TableSnapshot(name, rows[name]) for name in TABLE_NAMES),
    )


def _rebind_last_snapshot_id_but_leave_supplied_row(image, snapshot_id):
    """Create a derived duplicate that host table-PK checks cannot see."""
    events = [json.loads(raw) for raw in image.events]
    semantic, commit = events[-2:]
    by_digest = {record.sha256: record for record in image.blobs}
    old = {
        semantic["transaction"]["request_sha256"],
        semantic["transaction"]["response_sha256"],
        semantic["payload_ref"]["sha256"],
        commit["payload_ref"]["sha256"],
    }
    request = json.loads(by_digest[semantic["transaction"]["request_sha256"]].canonical_json)
    response = json.loads(by_digest[semantic["transaction"]["response_sha256"]].canonical_json)
    payload = json.loads(by_digest[semantic["payload_ref"]["sha256"]].canonical_json)
    commit_payload = json.loads(by_digest[commit["payload_ref"]["sha256"]].canonical_json)
    request["arguments"]["snapshot_id"] = snapshot_id
    response["generated_refs"][0]["identifier"] = snapshot_id
    payload["data"]["snapshot_id"] = snapshot_id
    request_sha, response_sha, payload_sha = map(blob_digest, (request, response, payload))
    semantic["transaction"]["request_sha256"] = request_sha
    semantic["transaction"]["response_sha256"] = response_sha
    semantic["payload_ref"]["sha256"] = payload_sha
    semantic["event_sha256"] = event_digest(semantic)
    commit_payload["data"]["request_ref"]["sha256"] = request_sha
    commit_payload["data"]["response_ref"]["sha256"] = response_sha
    commit_payload["data"]["post_semantic_head"]["event_sha256"] = semantic["event_sha256"]
    commit_payload_sha = blob_digest(commit_payload)
    commit["transaction"]["request_sha256"] = request_sha
    commit["transaction"]["response_sha256"] = response_sha
    commit["global_predecessor"]["event_sha256"] = semantic["event_sha256"]
    commit["payload_ref"]["sha256"] = commit_payload_sha
    commit["event_sha256"] = event_digest(commit)
    additions = (
        BlobRecord(request_sha, REQUEST_SCHEMA_ID, canonical_json(request)),
        BlobRecord(response_sha, RESPONSE_SCHEMA_ID, canonical_json(response)),
        BlobRecord(payload_sha, PAYLOAD_SCHEMA_ID, canonical_json(payload)),
        BlobRecord(commit_payload_sha, PAYLOAD_SCHEMA_ID, canonical_json(commit_payload)),
    )
    blobs = tuple(sorted(
        tuple(record for record in image.blobs if record.sha256 not in old)
        + additions,
        key=lambda record: record.sha256,
    ))
    rows = {snapshot.table: snapshot.rows for snapshot in image.table_snapshots}
    rows["blobs"] = tuple(
        (record.sha256, record.schema_id, record.canonical_json.decode("ascii"))
        for record in blobs
    )
    rows["events"] = rows["events"][:-2] + (
        (semantic["global_sequence"], semantic["event_id"], semantic["event_sha256"], canonical_json(semantic).decode("ascii")),
        (commit["global_sequence"], commit["event_id"], commit["event_sha256"], canonical_json(commit).decode("ascii")),
    )
    idempotency = list(rows["idempotency"])
    item = list(next(row for row in idempotency if row[4] == commit["event_id"]))
    idempotency.remove(tuple(item))
    item[2:4] = [request_sha, response_sha]
    idempotency.append(tuple(item))
    rows["idempotency"] = tuple(sorted(idempotency))
    metadata = list(rows["metadata"][0])
    metadata[17] = commit["event_sha256"]
    rows["metadata"] = (tuple(metadata),)
    return replace(
        image,
        blobs=blobs,
        events=image.events[:-2] + (canonical_json(semantic), canonical_json(commit)),
        table_snapshots=tuple(TableSnapshot(name, rows[name]) for name in TABLE_NAMES),
    )


class RuntimeV2SnapshotTests(unittest.TestCase):
    def codes(self, report):
        return {item.code for item in report.violations}

    def test_snapshot_first_export_binds_null_checkpoint_and_exact_roots(self):
        image, _ = fixture()
        image, document = _append_snapshot(image, kind="EXPORT", ordinal=0)
        self.assertIsNone(document["source_checkpoint_sha256"])
        report = reduce_initial_runtime_image(image)
        self.assertEqual(report.status, "UNSUPPORTED")
        self.assertEqual(self.codes(report), {"CLOSURE_NOT_COMPILED"})

    def test_checkpoint_export_checkpoint_interleaving_and_copy(self):
        image, _ = initialize_fixture()
        image, first = _append_snapshot(
            image, kind="CHECKPOINT", ordinal=1, copy=True,
        )
        image, exported = _append_snapshot(image, kind="EXPORT", ordinal=2)
        image, second = _append_snapshot(image, kind="CHECKPOINT", ordinal=3)
        image, exported_second = _append_snapshot(
            image, kind="EXPORT", ordinal=4,
        )
        self.assertEqual(exported["source_checkpoint_sha256"], first["checkpoint_sha256"])
        self.assertEqual(second["prior_checkpoint_sha256"], first["checkpoint_sha256"])
        self.assertEqual(
            exported_second["prior_export_sha256"], exported["export_sha256"],
        )
        self.assertEqual(
            exported_second["source_checkpoint_sha256"],
            second["checkpoint_sha256"],
        )
        report = reduce_initial_runtime_image(image)
        self.assertEqual(report.status, "UNSUPPORTED")
        self.assertEqual(self.codes(report), {"CLOSURE_NOT_COMPILED"})
        rows = {item.table: item.rows for item in image.table_snapshots}
        self.assertEqual(len(rows["snapshots"]), 4)
        self.assertEqual(
            [(row[1], row[2]) for row in rows["snapshots"]],
            [("CHECKPOINT", 0), ("CHECKPOINT", 1), ("EXPORT", 0), ("EXPORT", 1)],
        )
        self.assertEqual(rows["metadata"][0][18], second["checkpoint_sha256"])
        self.assertEqual(rows["metadata"][0][19], 3)
        self.assertEqual(rows["metadata"][0][25], "DENY")

    def test_root_selector_sequence_and_copy_attacks_fail_closed(self):
        image, _ = fixture()
        image, _ = _append_snapshot(image, kind="CHECKPOINT", ordinal=4, copy=True)

        blobs = list(image.blobs)
        index = next(i for i, item in enumerate(blobs) if item.schema_id == CHECKPOINT_SCHEMA_ID)
        document = json.loads(blobs[index].canonical_json)
        document["roots"]["events"] = "f" * 64
        document["checkpoint_sha256"] = checkpoint_digest(document)
        raw = canonical_json(document)
        blobs[index] = BlobRecord(blob_digest(document), CHECKPOINT_SCHEMA_ID, raw)
        attacked = replace(image, blobs=tuple(sorted(blobs, key=lambda item: item.sha256)))
        report = reduce_initial_runtime_image(attacked)
        self.assertEqual(report.status, "INVALID")
        self.assertTrue({"GROUP_BLOB_MISSING", "BLOB_REACHABILITY"} & self.codes(report))

        selectors = list(image.selector_history)
        selector = json.loads(selectors[-1])
        selector["prior_selector_sha256"] = "e" * 64
        selector["selector_sha256"] = selector_digest(selector)
        selectors[-1] = canonical_json(selector)
        report = reduce_initial_runtime_image(replace(image, selector_history=tuple(selectors)))
        self.assertEqual(report.status, "INVALID")
        self.assertIn("SELECTOR_DERIVATION", self.codes(report))

        report = reduce_initial_runtime_image(replace(
            image, checkpoint_copies=image.checkpoint_copies * 2,
        ))
        self.assertEqual(report.status, "INVALID")
        self.assertTrue(
            {"CHECKPOINT_COPY_CARDINALITY", "CHECKPOINT_COPY_ORDER"}
            & self.codes(report)
        )

    def test_coherently_rehashed_root_forgery_reaches_root_comparison(self):
        image, _ = fixture()
        image, _ = _append_snapshot(image, kind="EXPORT", ordinal=5)
        forged = _coherently_forge_export_root(image)
        report = reduce_initial_runtime_image(forged)
        self.assertEqual(report.status, "INVALID")
        self.assertIn("GROUP_CONST", self.codes(report))
        self.assertNotIn("GROUP_BLOB_MISSING", self.codes(report))

    def test_cumulative_root_budget_exact_boundary_and_one_byte_over(self):
        base, _ = fixture()
        image, _ = _append_snapshot(base, kind="EXPORT", ordinal=6)
        final_charge = inspect_runtime_image_host(image).final_supplied_root_work_bytes
        self.assertIsNotNone(final_charge)
        cut_rows = {item.table: item.rows for item in base.table_snapshots}
        cut_charge = sum(
            len(b"EDGELAB\0TABLE\0V2\0") + len(name.encode("utf-8")) + 1
            + len(canonical_json([list(row) for row in cut_rows[name]]))
            for name in TABLE_NAMES
        )
        exact = final_charge + cut_charge
        original = initial_module.MAX_TOTAL_ROOT_WORK_BYTES
        try:
            initial_module.MAX_TOTAL_ROOT_WORK_BYTES = exact
            self.assertEqual(
                reduce_initial_runtime_image(image).status, "UNSUPPORTED",
            )
            initial_module.MAX_TOTAL_ROOT_WORK_BYTES = exact - 1
            report = reduce_initial_runtime_image(image)
        finally:
            initial_module.MAX_TOTAL_ROOT_WORK_BYTES = original
        self.assertEqual(report.status, "INVALID")
        self.assertIn("TOTAL_ROOT_WORK_LIMIT", self.codes(report))

    def test_import_may_be_followed_by_snapshots_and_malformed_tail_denies(self):
        initialized, values = initialize_fixture()
        imported, _ = _append_import_fixture(
            initialized, values, affected_task_ids=(),
        )
        image, _ = _append_snapshot(imported, kind="CHECKPOINT", ordinal=7)
        report = reduce_initial_runtime_image(image)
        self.assertEqual(report.status, "UNSUPPORTED")
        self.assertEqual(self.codes(report), {"CLOSURE_NOT_COMPILED"})

        attacked = replace(
            image, events=image.events + initialized.events[-2:],
        )
        report = reduce_initial_runtime_image(attacked)
        self.assertEqual(report.status, "INVALID")
        self.assertIn("GROUP_EVENT_ID_DUPLICATE", self.codes(report))

    def test_derived_duplicate_snapshot_id_is_rejected_before_cursor_advance(self):
        image, _ = fixture()
        image, _ = _append_snapshot(image, kind="EXPORT", ordinal=8)
        first_id = next(
            row[0] for item in image.table_snapshots
            if item.table == "snapshots" for row in item.rows
        )
        image, _ = _append_snapshot(image, kind="EXPORT", ordinal=9)
        attacked = _rebind_last_snapshot_id_but_leave_supplied_row(image, first_id)
        report = reduce_initial_runtime_image(attacked)
        self.assertEqual(report.status, "INVALID")
        self.assertIn("GROUP_SNAPSHOT_ID_DUPLICATE", self.codes(report))


if __name__ == "__main__":
    unittest.main()
