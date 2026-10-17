"""Focused adversarial tests for the private NEW initial-image reducer."""
import ast
import json
import unittest
from dataclasses import replace
from pathlib import Path

from src.edgelab.runtime_v2_codec import (
    attachment_digest,
    blob_digest,
    canonical_json,
    event_digest,
    manifest_digest,
    schema_document_digest,
    selector_digest,
    selector_history_digest,
    verifier_dependency_closure_digest,
)
from src.edgelab.runtime_v2_genesis import (
    GenesisValidationError,
    PAYLOAD_SCHEMA_ID,
    REQUEST_SCHEMA_ID,
    RESPONSE_SCHEMA_ID,
    validate_new_genesis_request,
    validate_new_genesis_response,
    validate_runtime_genesis_envelope,
    validate_runtime_genesis_payload,
)
from src.edgelab.runtime_v2_image import (
    BlobRecord,
    RuntimeImage,
    SchemaDocumentRecord,
    TABLE_NAMES,
    TableSnapshot,
)
from src.edgelab.runtime_v2_initial import (
    SCHEMA_DOCUMENT_PINS,
    reduce_initial_runtime_image,
)
from tests.runtime_v2_closure_fixture import closure_fixture


ROOT = Path(__file__).resolve().parents[1]
RUNTIME_ID = "123e4567-e89b-42d3-a456-426614174000"
EVENT_ID = "123e4567-e89b-42d3-a456-426614174001"
TRANSACTION_ID = "123e4567-e89b-42d3-a456-426614174002"
CHAIN_ID = "1" * 64
BUNDLE = "2" * 64
CREATED_AT = "2026-10-16T00:00:00Z"
STORAGE_SHA = "8a588ce0bd23a10ea984fa656b2f172dcc4b0ede501c501d414a662d17c60a63"
REGISTRY_SHA = "6b68797766e10c5ff8260d9d7b6cb31759466765287e7a23c377bd781a97bfd6"

SCHEMA_FILES = {
    "urn:edgelab:m0-3a-command-request:2": "m0-3a-command-request.v2.schema.json",
    "urn:edgelab:m0-3a-event-envelope:2": "m0-3a-event-envelope.v2.schema.json",
    "urn:edgelab:m0-3a-event-payload:2": "m0-3a-event-payload.v2.schema.json",
    "urn:edgelab:m0-3a-legacy-v1-projection:1": "m0-3a-legacy-v1-projection.v1.schema.json",
    "urn:edgelab:m0-3a-legacy-v1-row-archive:1": "m0-3a-legacy-v1-row-archive.v1.schema.json",
    "urn:edgelab:m0-3a-response-projection:2": "m0-3a-response-projection.v2.schema.json",
    "urn:edgelab:m0-3a-runtime-checkpoint:2": "m0-3a-runtime-checkpoint.v2.schema.json",
    "urn:edgelab:m0-3a-runtime-export:2": "m0-3a-runtime-export.v2.schema.json",
    "urn:edgelab:m0-3a-task-state:2": "m0-3a-task-state.v2.schema.json",
}


def published(name):
    return json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))


def fixture():
    storage = published("m0-3a-runtime-storage.v2.json")
    registry = published("m0-3a-schema-registry.v2.json")
    closure = closure_fixture()
    closure_sha = closure["verifier_dependency_closure_sha256"]
    attachment = {
        "attachment_schema_version": 2,
        "runtime_format_version": 2,
        "runtime_id": RUNTIME_ID,
        "chain_id": CHAIN_ID,
        "canonical_project_id": "EdgeLab",
        "repository_root_realpath": "/fixture/EdgeLab",
        "expected_remote": "https://github.com/dylanlaewe/EdgeLab.git",
        "git_common_dir_identity": "/fixture/EdgeLab/.git",
        "repository_marker_sha256": "3" * 64,
        "checkout_nonce": "4" * 64,
        "created_at": CREATED_AT,
        "anchor_status": "UNANCHORED",
        "currentness_status": "UNKNOWN",
        "authorizing_use": "DENY",
    }
    attachment_sha = attachment_digest(attachment)
    request = {
        "schema_version": 1,
        "request_format_version": 2,
        "runtime_id": RUNTIME_ID,
        "chain_id": CHAIN_ID,
        "operation": "SYSTEM_GENESIS",
        "operation_key": "system:v2:genesis",
        "repository_generation": 0,
        "repository_bundle_sha256": BUNDLE,
        "subject": None,
        "expected_state_ref": None,
        "arguments": {
            "attachment_sha256": attachment_sha,
            "schema_registry_sha256": REGISTRY_SHA,
            "storage_schema_sha256": STORAGE_SHA,
        },
    }
    response = {
        "schema_version": 1,
        "response_format_version": 2,
        "runtime_id": RUNTIME_ID,
        "chain_id": CHAIN_ID,
        "operation": "SYSTEM_GENESIS",
        "operation_key": "system:v2:genesis",
        "status": "COMMITTED",
        "affected_states": [],
        "generated_refs": [],
    }
    payload = {
        "schema_version": 1,
        "payload_format_version": 2,
        "event_type": "RUNTIME_GENESIS",
        "data": {
            "runtime_id": RUNTIME_ID,
            "chain_id": CHAIN_ID,
            "runtime_format_version": 2,
            "event_format_version": 2,
            "attachment_sha256": attachment_sha,
            "storage_schema_sha256": STORAGE_SHA,
            "schema_registry_sha256": REGISTRY_SHA,
            "verifier_dependency_closure_sha256": closure_sha,
            "repository_generation": 0,
            "repository_bundle_sha256": BUNDLE,
        },
    }
    request_sha = blob_digest(request)
    response_sha = blob_digest(response)
    payload_sha = blob_digest(payload)
    event = {
        "schema_version": 1,
        "event_format_version": 2,
        "runtime_id": RUNTIME_ID,
        "chain_id": CHAIN_ID,
        "event_id": EVENT_ID,
        "event_type": "RUNTIME_GENESIS",
        "occurred_at": CREATED_AT,
        "global_sequence": 0,
        "global_predecessor": {
            "event_id": "FORMAT2_GENESIS_PREDECESSOR",
            "event_sha256": "228a5eca65d6da5649229c520a9c922c7de239b821e362beddadacdf278f5a99",
        },
        "stream": "RUNTIME",
        "task_context": None,
        "transaction": {
            "transaction_id": TRANSACTION_ID,
            "position": 0,
            "event_count": 1,
            "operation_key": "system:v2:genesis",
            "request_sha256": request_sha,
            "response_sha256": response_sha,
        },
        "payload_ref": {"schema_id": PAYLOAD_SCHEMA_ID, "sha256": payload_sha},
        "state_before_ref": None,
        "state_after_ref": None,
        "repository_generation": 0,
        "repository_bundle_sha256": BUNDLE,
        "authority_binding_sha256": None,
        "authorizing_use": "DENY",
        "event_sha256": "0" * 64,
    }
    event["event_sha256"] = event_digest(event)
    manifest = {
        "schema_version": 1,
        "runtime_format_version": 2,
        "event_format_version": 2,
        "runtime_id": RUNTIME_ID,
        "chain_id": CHAIN_ID,
        "canonicalization": "EDGELAB_CANONICAL_JSON_V1",
        "digest_algorithm": "SHA-256",
        "sqlite_application_id": 1162102578,
        "sqlite_user_version": 2,
        "storage_schema_sha256": STORAGE_SHA,
        "schema_registry_sha256": REGISTRY_SHA,
        "genesis_event_id": EVENT_ID,
        "genesis_event_sha256": event["event_sha256"],
        "attachment_sha256": attachment_sha,
        "source_kind": "NEW",
        "legacy_bridge": None,
        "authority_binding": None,
        "anchor_status": "UNANCHORED",
        "currentness_status": "UNKNOWN",
        "authorizing_use": "DENY",
        "created_at": CREATED_AT,
    }
    manifest_sha = manifest_digest(manifest)
    selector0 = {
        "schema_version": 1,
        "selector_format_version": 1,
        "selector_generation": 0,
        "active_runtime_format_version": 1,
        "active_runtime_id": "precutover-runtime",
        "active_database_path": "runtime.sqlite",
        "active_attachment_path": "attachment.json",
        "active_manifest_path": None,
        "active_manifest_sha256": None,
        "latest_v2_checkpoint_sha256": None,
        "selector_history_path": "selectors/00000000000000000000.json",
        "prior_selector_path": None,
        "prior_selector_sha256": None,
        "cutover_state": "V1_ACTIVE",
        "currentness_status": "UNKNOWN",
        "authorizing_use": "DENY",
        "written_at": "2026-10-15T23:59:59Z",
        "selector_sha256": "0" * 64,
    }
    selector0["selector_sha256"] = selector_digest(selector0)
    selector1 = {
        "schema_version": 1,
        "selector_format_version": 1,
        "selector_generation": 1,
        "active_runtime_format_version": 2,
        "active_runtime_id": RUNTIME_ID,
        "active_database_path": "runtime.v2.sqlite",
        "active_attachment_path": "attachment.v2.json",
        "active_manifest_path": "runtime.v2.manifest.json",
        "active_manifest_sha256": manifest_sha,
        "latest_v2_checkpoint_sha256": None,
        "selector_history_path": "selectors/00000000000000000001.json",
        "prior_selector_path": "selectors/00000000000000000000.json",
        "prior_selector_sha256": selector0["selector_sha256"],
        "cutover_state": "V2_ACTIVE",
        "currentness_status": "UNKNOWN",
        "authorizing_use": "DENY",
        "written_at": CREATED_AT,
        "selector_sha256": "0" * 64,
    }
    selector1["selector_sha256"] = selector_digest(selector1)
    history_sha = selector_history_digest([selector0, selector1])

    documents = []
    for schema_id, expected_digest in SCHEMA_DOCUMENT_PINS:
        document = published(SCHEMA_FILES[schema_id])
        raw = canonical_json(document)
        assert schema_document_digest(document) == expected_digest
        documents.append(SchemaDocumentRecord(schema_id, expected_digest, raw))
    blob_records = tuple(sorted((
        BlobRecord(request_sha, REQUEST_SCHEMA_ID, canonical_json(request)),
        BlobRecord(response_sha, RESPONSE_SCHEMA_ID, canonical_json(response)),
        BlobRecord(payload_sha, PAYLOAD_SCHEMA_ID, canonical_json(payload)),
    ), key=lambda record: record.sha256))
    rows = {name: () for name in TABLE_NAMES}
    rows["blobs"] = tuple(
        (record.sha256, record.schema_id, record.canonical_json.decode("ascii"))
        for record in blob_records
    )
    rows["events"] = ((0, EVENT_ID, event["event_sha256"], canonical_json(event).decode("ascii")),)
    rows["metadata"] = ((
        "runtime", RUNTIME_ID, CHAIN_ID, 2, 2, "NEW", CREATED_AT,
        manifest_sha, attachment_sha, STORAGE_SHA, REGISTRY_SHA, EVENT_ID,
        event["event_sha256"], 0, BUNDLE, 0, EVENT_ID, event["event_sha256"],
        None, 1, selector1["selector_sha256"], history_sha, None,
        "UNANCHORED", "UNKNOWN", "DENY",
    ),)
    rows["schema_documents"] = tuple(
        (record.schema_id, record.document_sha256, record.canonical_json.decode("ascii"))
        for record in documents
    )
    rows["schema_registry"] = (("registry", REGISTRY_SHA, canonical_json(registry).decode("ascii")),)
    rows["seals"] = ((
        "RUNTIME_GENESIS_IDENTITY", RUNTIME_ID, CHAIN_ID,
        "RUNTIME_GENESIS_IDENTITY", attachment_sha, EVENT_ID,
        event["event_sha256"], manifest_sha, EVENT_ID, CREATED_AT,
    ),)
    image = RuntimeImage(
        storage_descriptor=canonical_json(storage),
        verifier_dependency_closure=canonical_json(closure),
        manifest=canonical_json(manifest),
        attachment=canonical_json(attachment),
        schema_registry=canonical_json(registry),
        schema_documents=tuple(documents),
        blobs=blob_records,
        events=(canonical_json(event),),
        table_snapshots=tuple(TableSnapshot(name, rows[name]) for name in TABLE_NAMES),
        checkpoint_copies=(),
        selector_history=(canonical_json(selector0), canonical_json(selector1)),
        legacy_evidence=None,
    )
    return image, {
        "request": request, "response": response, "payload": payload,
        "event": event, "manifest": manifest, "selector0": selector0,
        "selector1": selector1, "closure": closure,
    }


class RuntimeV2InitialTests(unittest.TestCase):
    def codes(self, report):
        return {violation.code for violation in report.violations}

    def test_uncompiled_closure_keeps_derived_identity_unexposed(self):
        image, _ = fixture()
        report = reduce_initial_runtime_image(image)
        self.assertEqual(report.status, "UNSUPPORTED")
        self.assertEqual(self.codes(report), {"CLOSURE_NOT_COMPILED"})
        self.assertEqual(
            tuple(field.name for field in report.__dataclass_fields__.values()),
            ("status", "violations", "authorizing_use"),
        )
        self.assertEqual(report.authorizing_use, "DENY")
        with self.assertRaises(TypeError):
            bool(report)

    def test_compiled_genesis_validators_are_narrow_and_strict(self):
        _, values = fixture()
        cases = (
            (validate_new_genesis_request, values["request"]),
            (validate_new_genesis_response, values["response"]),
            (validate_runtime_genesis_payload, values["payload"]),
            (validate_runtime_genesis_envelope, values["event"]),
        )
        for validator, value in cases:
            with self.subTest(validator=validator.__name__):
                self.assertIsNone(validator(json.loads(json.dumps(value))))
        bad = dict(values["request"])
        bad["repository_generation"] = False
        with self.assertRaises(GenesisValidationError):
            validate_new_genesis_request(bad)
        bad = dict(values["event"])
        bad["occurred_at"] = "2026-02-30T00:00:00Z"
        with self.assertRaises(GenesisValidationError):
            validate_runtime_genesis_envelope(bad)
        bad = dict(values["payload"])
        bad["extra"] = None
        with self.assertRaises(GenesisValidationError):
            validate_runtime_genesis_payload(bad)

        strict_mutations = (
            (validate_new_genesis_response, "response", "affected_states", ()),
            (validate_new_genesis_response, "response", "extra", None),
            (validate_runtime_genesis_envelope, "event", "global_sequence", False),
            (validate_runtime_genesis_envelope, "event", "extra", None),
        )
        for validator, name, key, replacement in strict_mutations:
            bad = json.loads(json.dumps(values[name]))
            bad[key] = replacement
            with self.subTest(validator=validator.__name__, key=key):
                with self.assertRaises(GenesisValidationError):
                    validator(bad)

    def test_host_and_canonical_failures_are_invalid_without_partial_state(self):
        report = reduce_initial_runtime_image(object())
        self.assertEqual(report.status, "INVALID")
        self.assertIn("IMAGE_TYPE", self.codes(report))

        image, _ = fixture()
        report = reduce_initial_runtime_image(replace(
            image, events=(image.events[0] + b"\n",),
        ))
        self.assertEqual(report.status, "INVALID")
        self.assertIn("CANONICAL_JSON", self.codes(report))

    def test_self_consistent_rehashed_cross_document_mutation_still_denies(self):
        image, values = fixture()
        request = json.loads(json.dumps(values["request"]))
        request["runtime_id"] = "123e4567-e89b-42d3-a456-426614174099"
        changed = BlobRecord(blob_digest(request), REQUEST_SCHEMA_ID, canonical_json(request))
        records = tuple(sorted(
            (changed,) + tuple(record for record in image.blobs if record.schema_id != REQUEST_SCHEMA_ID),
            key=lambda record: record.sha256,
        ))
        report = reduce_initial_runtime_image(replace(image, blobs=records))
        self.assertEqual(report.status, "INVALID")
        self.assertIn("BINDING_MISMATCH", self.codes(report))

    def test_blob_roles_and_event_digest_references_are_exact(self):
        image, values = fixture()
        request_record = next(
            record for record in image.blobs if record.schema_id == REQUEST_SCHEMA_ID
        )
        role_attacks = (
            replace(request_record, schema_id=RESPONSE_SCHEMA_ID),
            replace(request_record, schema_id=PAYLOAD_SCHEMA_ID),
        )
        for attack in role_attacks:
            records = tuple(
                attack if record.schema_id == REQUEST_SCHEMA_ID else record
                for record in image.blobs
            )
            with self.subTest(attack=attack):
                report = reduce_initial_runtime_image(replace(image, blobs=records))
                self.assertEqual(report.status, "INVALID")
                self.assertTrue({
                    "GENESIS_BLOB_ROLE_DUPLICATE", "GENESIS_BLOB_INVENTORY",
                } & self.codes(report))

        for coordinate in ("request_sha256", "response_sha256", "payload_sha256"):
            event = json.loads(json.dumps(values["event"]))
            if coordinate == "payload_sha256":
                event["payload_ref"]["sha256"] = "f" * 64
            else:
                event["transaction"][coordinate] = "f" * 64
            event["event_sha256"] = event_digest(event)
            with self.subTest(coordinate=coordinate):
                report = reduce_initial_runtime_image(replace(
                    image, events=(canonical_json(event),),
                ))
                self.assertEqual(report.status, "INVALID")
                self.assertIn("DIGEST_MISMATCH", self.codes(report))

    def test_manifest_time_attachment_and_event_bindings_are_exact(self):
        image, values = fixture()
        mutations = (
            ("genesis_event_id", "123e4567-e89b-42d3-a456-426614174099"),
            ("genesis_event_sha256", "f" * 64),
            ("attachment_sha256", "f" * 64),
            ("created_at", "2026-10-16T00:00:01Z"),
        )
        for key, replacement_value in mutations:
            manifest = json.loads(json.dumps(values["manifest"]))
            manifest[key] = replacement_value
            with self.subTest(key=key):
                report = reduce_initial_runtime_image(replace(
                    image, manifest=canonical_json(manifest),
                ))
                self.assertEqual(report.status, "INVALID")
                self.assertTrue({
                    "BINDING_MISMATCH", "DIGEST_MISMATCH",
                    "SELECTOR_DERIVATION", "TABLE_DERIVATION",
                } & self.codes(report))

        selector0 = json.loads(image.selector_history[0])
        selector0["selector_sha256"] = "f" * 64
        report = reduce_initial_runtime_image(replace(
            image,
            selector_history=(canonical_json(selector0), image.selector_history[1]),
        ))
        self.assertEqual(report.status, "INVALID")
        self.assertIn("DIGEST_MISMATCH", self.codes(report))

    def test_supplied_tables_are_comparison_only_and_must_match_derivation(self):
        image, _ = fixture()
        snapshots = list(image.table_snapshots)
        index = TABLE_NAMES.index("metadata")
        row = list(snapshots[index].rows[0])
        row[-1] = "ALLOW"
        snapshots[index] = TableSnapshot("metadata", (tuple(row),))
        report = reduce_initial_runtime_image(replace(image, table_snapshots=tuple(snapshots)))
        self.assertEqual(report.status, "INVALID")
        self.assertIn("TABLE_DERIVATION", self.codes(report))

        for table in ("blobs", "events", "schema_documents", "seals"):
            snapshots = list(image.table_snapshots)
            index = TABLE_NAMES.index(table)
            rows = list(snapshots[index].rows)
            row = list(rows[0])
            text_index = next(
                cell_index for cell_index, cell in enumerate(row)
                if type(cell) is str
            )
            row[text_index] += "-mutated"
            rows[0] = tuple(row)
            snapshots[index] = TableSnapshot(table, tuple(rows))
            with self.subTest(table=table):
                report = reduce_initial_runtime_image(replace(
                    image, table_snapshots=tuple(snapshots),
                ))
                self.assertEqual(report.status, "INVALID")
                self.assertIn("TABLE_DERIVATION", self.codes(report))

    def test_selector_one_is_derived_even_after_a_valid_rehash(self):
        image, values = fixture()
        selector = json.loads(json.dumps(values["selector1"]))
        selector["active_runtime_id"] = "123e4567-e89b-42d3-a456-426614174099"
        selector["selector_sha256"] = selector_digest(selector)
        report = reduce_initial_runtime_image(replace(
            image,
            selector_history=(image.selector_history[0], canonical_json(selector)),
        ))
        self.assertEqual(report.status, "INVALID")
        self.assertIn("SELECTOR_DERIVATION", self.codes(report))

    def test_schema_and_closure_identity_fail_closed(self):
        image, values = fixture()
        documents = list(image.schema_documents)
        documents[0] = replace(documents[0], document_sha256="f" * 64)
        report = reduce_initial_runtime_image(replace(image, schema_documents=tuple(documents)))
        self.assertEqual(report.status, "INVALID")
        self.assertIn("SCHEMA_DOCUMENT_INVENTORY", self.codes(report))

        closure = dict(values["closure"])
        closure["verifier_dependency_closure_sha256"] = "f" * 64
        report = reduce_initial_runtime_image(replace(
            image, verifier_dependency_closure=canonical_json(closure),
        ))
        self.assertEqual(report.status, "INVALID")
        self.assertIn("CLOSURE_SELF_DIGEST_MISMATCH", self.codes(report))

        closure = json.loads(json.dumps(values["closure"]))
        closure["deny_only_boundary"]["authorizing_use"] = "ALLOW"
        closure["verifier_dependency_closure_sha256"] = (
            verifier_dependency_closure_digest(closure)
        )
        report = reduce_initial_runtime_image(replace(
            image, verifier_dependency_closure=canonical_json(closure),
        ))
        self.assertEqual(report.status, "INVALID")
        self.assertIn("CONST", self.codes(report))

    def test_untrusted_finding_text_is_bounded(self):
        image, _ = fixture()
        documents = list(image.schema_documents)
        documents[0] = replace(
            documents[0],
            schema_id="x" * 10_000,
            canonical_json=b"{",
        )
        report = reduce_initial_runtime_image(replace(
            image, schema_documents=tuple(documents),
        ))
        self.assertEqual(report.status, "INVALID")
        self.assertTrue(all(len(item.code) <= 128 for item in report.violations))
        self.assertTrue(all(len(item.artifact) <= 256 for item in report.violations))
        self.assertTrue(all(len(item.coordinate) <= 512 for item in report.violations))
        self.assertTrue(any("#sha256=" in item.artifact for item in report.violations))

    def test_new_reducer_import_graph_has_no_io_or_public_verifier(self):
        forbidden = {
            "os", "pathlib", "sqlite3", "subprocess", "socket", "urllib",
            "requests", "jsonschema", "runtime_v2_verifier",
        }
        for name in ("runtime_v2_genesis.py", "runtime_v2_initial.py"):
            tree = ast.parse((ROOT / "src" / "edgelab" / name).read_text(encoding="utf-8"))
            imports = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports.update(alias.name.split(".")[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imports.add(node.module.split(".")[-1])
            self.assertTrue(forbidden.isdisjoint(imports), (name, imports & forbidden))


if __name__ == "__main__":
    unittest.main()
