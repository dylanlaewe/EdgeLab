"""Machine checks for the non-operational runtime-format-2 design contracts."""
import copy
import hashlib
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator, FormatChecker, ValidationError


ROOT = Path(__file__).resolve().parents[1]
D = "a" * 64
GENESIS_D = "228a5eca65d6da5649229c520a9c922c7de239b821e362beddadacdf278f5a99"
TASK_ROOT_D = "25ca6ef44038ccbafdd34705ab241d2bdaf13f03e94f21e09c75e4f33b5c1036"
EVENT_TYPES = (
    "RUNTIME_GENESIS", "LEGACY_V1_BRIDGE", "COMMAND_COMMITTED",
    "TASK_INITIALIZED", "CLAIM_ISSUED", "TASK_STARTED", "TASK_CONTINUED",
    "TASK_YIELDED", "TASK_FAILED", "TASK_COMPLETED", "CLAIM_RECOVERED",
    "TASK_RETRIED", "GOVERNANCE_BLOCKED", "GOVERNANCE_REVALIDATED",
    "REVIEW_ASSIGNED", "REVIEW_APPROVED", "REVIEW_REJECTED",
    "REVIEW_REMEDIATED", "DIRECTOR_ROUTED", "REMEDIATION_CREATED",
    "TASK_CREATED_FROM_REMEDIATION", "REPOSITORY_GENERATION_APPLIED",
    "REPOSITORY_GENERATION_ADVANCED", "RUNTIME_CHECKPOINTED",
    "RUNTIME_SNAPSHOT_EXPORTED", "MIGRATION_RECORDED",
)
RUNTIME_TYPES = {
    "RUNTIME_GENESIS", "LEGACY_V1_BRIDGE", "COMMAND_COMMITTED",
    "REPOSITORY_GENERATION_ADVANCED", "RUNTIME_CHECKPOINTED",
    "RUNTIME_SNAPSHOT_EXPORTED", "MIGRATION_RECORDED",
}


def schema(name):
    return json.loads((ROOT / "schemas" / name).read_text())


def validate(name, value):
    Draft202012Validator(schema(name), format_checker=FormatChecker()).validate(value)


class SuccessorRuntimeContractTests(unittest.TestCase):
    def manifest(self, *, migrated=False):
        bridge = None
        if migrated:
            bridge = {
                "source_runtime_format_version": 1,
                "source_assurance": "V16_BOUNDED_REPLAY_ONLY",
                "source_runtime_id": "legacy-runtime",
                "source_attachment_sha256": D,
                "source_storage_inventory_sha256": D,
                "source_backup_sha256": D,
                "source_global_head_id": "legacy-head",
                "source_global_head_sha256": D,
                "source_row_archive_sha256": D,
                "source_projection_sha256": D,
                "migration_plan_sha256": D,
                "frozen_verifier_commit": "a" * 40,
                "frozen_verifier_closure_sha256": D,
                "source_repository_bundle_sha256": D,
            }
        return {
            "schema_version": 1,
            "runtime_format_version": 2,
            "event_format_version": 2,
            "runtime_id": "runtime-2",
            "chain_id": D,
            "canonicalization": "EDGELAB_CANONICAL_JSON_V1",
            "digest_algorithm": "SHA-256",
            "sqlite_application_id": 1162102578,
            "sqlite_user_version": 2,
            "storage_schema_sha256": D,
            "schema_registry_sha256": D,
            "genesis_event_id": "event-0",
            "genesis_event_sha256": D,
            "attachment_sha256": D,
            "source_kind": "V1_MIGRATION" if migrated else "NEW",
            "legacy_bridge": bridge,
            "authority_binding": None,
            "anchor_status": "UNANCHORED",
            "currentness_status": "UNKNOWN",
            "authorizing_use": "DENY",
            "created_at": "2026-10-16T00:00:00Z",
        }

    def event(self, *, stream="TASK"):
        task_context = None
        if stream == "TASK":
            task_context = {
                "task_id": "T",
                "attempt": 1,
                "task_sequence": 1,
                "task_predecessor": {
                    "event_id": f"FORMAT2_TASK_PREDECESSOR:{TASK_ROOT_D}",
                    "event_sha256": TASK_ROOT_D,
                },
            }
        return {
            "schema_version": 1,
            "event_format_version": 2,
            "runtime_id": "runtime-2",
            "chain_id": D,
            "event_id": "event-1",
            "event_type": "TASK_INITIALIZED" if stream == "TASK" else "COMMAND_COMMITTED",
            "occurred_at": "2026-10-16T00:00:00Z",
            "global_sequence": 1,
            "global_predecessor": {"event_id": "event-0", "event_sha256": D},
            "stream": stream,
            "task_context": task_context,
            "transaction": {
                "transaction_id": "transaction-1",
                "position": 0,
                "event_count": 2,
                "operation_key": "initialize-T",
                "request_sha256": D,
                "response_sha256": D,
            },
            "payload_ref": {"schema_id": "urn:edgelab:event-payload:task-initialized:2", "sha256": D},
            "state_before_ref": None,
            "state_after_ref": {"schema_id": "urn:edgelab:task-state:2", "sha256": D},
            "repository_generation": 0,
            "repository_bundle_sha256": D,
            "authority_binding_sha256": None,
            "authorizing_use": "DENY",
            "event_sha256": D,
        }

    def checkpoint(self):
        return {
            "schema_version": 1,
            "runtime_format_version": 2,
            "runtime_id": "runtime-2",
            "chain_id": D,
            "checkpoint_sequence": 0,
            "through_global_sequence": 2,
            "head_event_id": "event-2",
            "head_event_sha256": D,
            "manifest_sha256": D,
            "prior_checkpoint_sha256": None,
            "roots": {name: D for name in (
                "events", "metadata", "tasks", "attempts", "claims", "reviews",
                "remediation_links", "idempotency", "seals", "migrations",
                "snapshots", "blobs", "schema_documents", "schema_registry"
            )} | {"legacy_archive": D},
            "checkpoint_sha256": D,
            "anchor_status": "LOCAL_UNANCHORED",
            "currentness_status": "UNKNOWN",
            "authorizing_use": "DENY",
            "created_at": "2026-10-16T00:00:00Z",
        }

    def selector(self, *, generation=0):
        v2 = generation > 0
        return {
            "schema_version": 1,
            "selector_format_version": 1,
            "selector_generation": generation,
            "active_runtime_format_version": 2 if v2 else 1,
            "active_runtime_id": "runtime-2" if v2 else "runtime-1",
            "active_database_path": "runtime.v2.sqlite" if v2 else "runtime.sqlite",
            "active_attachment_path": "attachment.v2.json" if v2 else "attachment.json",
            "active_manifest_path": "runtime.v2.manifest.json" if v2 else None,
            "active_manifest_sha256": D if v2 else None,
            "latest_v2_checkpoint_sha256": D if v2 else None,
            "selector_history_path": f"selectors/{generation:020d}.json",
            "prior_selector_path": f"selectors/{generation-1:020d}.json" if v2 else None,
            "prior_selector_sha256": D if v2 else None,
            "cutover_state": "V2_ACTIVE" if v2 else "V1_ACTIVE",
            "currentness_status": "UNKNOWN",
            "authorizing_use": "DENY",
            "written_at": "2026-10-16T00:00:00Z",
            "selector_sha256": D,
        }

    def legacy_projection(self):
        table_names = (
            "meta", "seals", "tasks", "attempts", "claims", "reviews",
            "idempotency", "runtime_events", "task_events", "remediation_links",
            "migration_ledger", "snapshots",
        )
        row_defs = {
            "meta": "metaRow", "seals": "sealsRow", "tasks": "tasksRow",
            "attempts": "attemptsRow", "claims": "claimsRow",
            "reviews": "reviewsRow", "idempotency": "idempotencyRow",
            "runtime_events": "runtimeEventsRow", "task_events": "taskEventsRow",
            "remediation_links": "remediationLinksRow",
            "migration_ledger": "migrationLedgerRow", "snapshots": "snapshotsRow",
        }
        return {
            "schema_version": 1,
            "projection_format_version": 1,
            "source_runtime_format_version": 1,
            "source_assurance": "V16_BOUNDED_REPLAY_ONLY",
            "source_runtime_id": "runtime-1",
            "attachment_sha256": D,
            "storage_inventory_sha256": D,
            "backup_sha256": D,
            "global_head_id": "legacy-head",
            "global_head_sha256": D,
            "repository_generation": 0,
            "repository_bundle_sha256": D,
            "meta_keys": [
                "attachment_digest", "available", "bundle_digest", "genesis",
                "genesis_digest", "global_head_digest", "global_head_id",
                "repository_generation", "runtime_id", "schema_version",
            ],
            "tables": {
                name: {
                    "columns_sha256": D,
                    "row_schema_id": (
                        "urn:edgelab:m0-3a-legacy-v1-row-archive:1#/$defs/"
                        f"{row_defs[name]}"
                    ),
                    "row_count": 0,
                    "ordered_rows_sha256": D,
                }
                for name in table_names
            },
            "legacy_event_type_mapping": {
                "TASK_YIELDD": "TASK_YIELDED",
                "TASK_FAILD": "TASK_FAILED",
                "REVIEW_REJECTD": "REVIEW_REJECTED",
            },
            "row_archive_sha256": D,
            "projection_sha256": D,
            "currentness_status": "UNKNOWN",
            "authorizing_use": "DENY",
            "created_at": "2026-10-16T00:00:00Z",
        }

    def legacy_archive(self):
        return {
            "schema_version": 1,
            "archive_format_version": 1,
            "attachment_bytes_base64": "e30=",
            "storage_inventory": [{
                "name": "runtime.sqlite", "type": "REGULAR_FILE",
                "mode": "0600", "size": 4096, "sha256": D,
            }],
            "tables": {name: [] for name in (
                "meta", "seals", "tasks", "attempts", "claims", "reviews",
                "idempotency", "runtime_events", "task_events",
                "remediation_links", "migration_ledger", "snapshots",
            )},
        }

    def registry(self):
        documents = [
            {"schema_id": "payload", "document_sha256": D, "content_role": "PAYLOAD"},
            {"schema_id": "state", "document_sha256": D, "content_role": "TASK_STATE"},
            {"schema_id": "request", "document_sha256": D, "content_role": "REQUEST"},
            {"schema_id": "response", "document_sha256": D, "content_role": "RESPONSE_PROJECTION"},
        ]
        return {
            "schema_version": 1,
            "runtime_format_version": 2,
            "documents": documents,
            "event_bindings": [
                {
                    "event_type": event_type,
                    "stream": "RUNTIME" if event_type in RUNTIME_TYPES else "TASK",
                    "payload_schema_id": "payload",
                    "state_before_schema_id": None if event_type in RUNTIME_TYPES else "state",
                    "state_after_schema_id": None if event_type in RUNTIME_TYPES else "state",
                    "request_schema_id": "request",
                    "response_projection_schema_id": "response",
                }
                for event_type in EVENT_TYPES
            ],
        }

    def test_schemas_and_bounded_examples_are_valid(self):
        for name in (
            "m0-3a-runtime-manifest.v2.schema.json",
            "m0-3a-event-envelope.v2.schema.json",
            "m0-3a-runtime-checkpoint.v2.schema.json",
            "m0-3a-active-runtime-selector.v2.schema.json",
            "m0-3a-legacy-v1-projection.v1.schema.json",
            "m0-3a-legacy-v1-row-archive.v1.schema.json",
            "m0-3a-schema-registry.v2.schema.json",
        ):
            Draft202012Validator.check_schema(schema(name))
        validate("m0-3a-runtime-manifest.v2.schema.json", self.manifest())
        validate("m0-3a-runtime-manifest.v2.schema.json", self.manifest(migrated=True))
        validate("m0-3a-event-envelope.v2.schema.json", self.event())
        validate("m0-3a-event-envelope.v2.schema.json", self.event(stream="RUNTIME"))
        validate("m0-3a-runtime-checkpoint.v2.schema.json", self.checkpoint())
        validate("m0-3a-active-runtime-selector.v2.schema.json", self.selector())
        validate("m0-3a-active-runtime-selector.v2.schema.json", self.selector(generation=1))
        validate("m0-3a-legacy-v1-projection.v1.schema.json", self.legacy_projection())
        validate("m0-3a-legacy-v1-row-archive.v1.schema.json", self.legacy_archive())
        validate("m0-3a-schema-registry.v2.schema.json", self.registry())

    def test_unknown_versions_and_fields_deny(self):
        for field, value in (("runtime_format_version", 3), ("event_format_version", True)):
            altered = self.manifest()
            altered[field] = value
            with self.assertRaises(ValidationError):
                validate("m0-3a-runtime-manifest.v2.schema.json", altered)
        altered = self.event()
        altered["override"] = True
        with self.assertRaises(ValidationError):
            validate("m0-3a-event-envelope.v2.schema.json", altered)

    def test_migration_bridge_is_exactly_conditional(self):
        new_with_bridge = self.manifest()
        new_with_bridge["legacy_bridge"] = self.manifest(migrated=True)["legacy_bridge"]
        migrated_without_bridge = self.manifest(migrated=True)
        migrated_without_bridge["legacy_bridge"] = None
        for altered in (new_with_bridge, migrated_without_bridge):
            with self.assertRaises(ValidationError):
                validate("m0-3a-runtime-manifest.v2.schema.json", altered)

    def test_stream_and_task_context_must_agree(self):
        runtime_with_task = self.event(stream="RUNTIME")
        runtime_with_task["task_context"] = self.event()["task_context"]
        task_without_context = self.event()
        task_without_context["task_context"] = None
        for altered in (runtime_with_task, task_without_context):
            with self.assertRaises(ValidationError):
                validate("m0-3a-event-envelope.v2.schema.json", altered)

    def test_stream_and_event_type_must_agree(self):
        runtime_with_task_type = self.event(stream="RUNTIME")
        runtime_with_task_type["event_type"] = "TASK_STARTED"
        task_with_runtime_type = self.event()
        task_with_runtime_type["event_type"] = "COMMAND_COMMITTED"
        for altered in (runtime_with_task_type, task_with_runtime_type):
            with self.assertRaises(ValidationError):
                validate("m0-3a-event-envelope.v2.schema.json", altered)

    def test_genesis_is_sequence_zero_with_exact_predecessor_and_system_key(self):
        genesis = self.event(stream="RUNTIME")
        genesis.update(
            event_type="RUNTIME_GENESIS",
            global_sequence=0,
            global_predecessor={
                "event_id": "FORMAT2_GENESIS_PREDECESSOR",
                "event_sha256": GENESIS_D,
            },
        )
        genesis["transaction"].update(
            position=0, event_count=1, operation_key="system:v2:genesis"
        )
        validate("m0-3a-event-envelope.v2.schema.json", genesis)
        for mutate in (
            lambda value: value.update(global_sequence=1),
            lambda value: value["global_predecessor"].update(event_id="other"),
            lambda value: value["transaction"].update(operation_key="caller"),
        ):
            altered = copy.deepcopy(genesis)
            mutate(altered)
            with self.assertRaises(ValidationError):
                validate("m0-3a-event-envelope.v2.schema.json", altered)

    def test_predecessor_transaction_and_blob_coordinates_are_closed(self):
        mutations = []
        for path, value in (
            (("global_predecessor", "event_sha256"), "not-a-digest"),
            (("transaction", "event_count"), 0),
            (("payload_ref", "schema_id"), ""),
            (("task_context", "attempt"), True),
        ):
            altered = self.event()
            altered[path[0]][path[1]] = value
            mutations.append(altered)
        for altered in mutations:
            with self.assertRaises(ValidationError):
                validate("m0-3a-event-envelope.v2.schema.json", altered)

    def test_first_task_predecessor_uses_closed_task_root_shape(self):
        coordinates = json.dumps(
            {"attempt": 1, "chain_id": D, "task_id": "T"},
            sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ).encode()
        self.assertEqual(
            hashlib.sha256(
                b"EDGELAB\0EVENT\0V2\0TASK_PREDECESSOR\0" + coordinates
            ).hexdigest(),
            TASK_ROOT_D,
        )
        altered = self.event()
        altered["task_context"]["task_predecessor"] = {
            "event_id": "TASK_GENESIS:T", "event_sha256": D,
        }
        with self.assertRaises(ValidationError):
            validate("m0-3a-event-envelope.v2.schema.json", altered)

    def test_positive_authority_claims_are_unrepresentable(self):
        cases = [
            ("m0-3a-runtime-manifest.v2.schema.json", self.manifest(), "currentness_status", "CURRENT"),
            ("m0-3a-runtime-manifest.v2.schema.json", self.manifest(), "authorizing_use", "ALLOW"),
            ("m0-3a-runtime-checkpoint.v2.schema.json", self.checkpoint(), "anchor_status", "EXTERNALLY_ANCHORED"),
            ("m0-3a-runtime-checkpoint.v2.schema.json", self.checkpoint(), "authorizing_use", "ALLOW"),
            ("m0-3a-event-envelope.v2.schema.json", self.event(), "authorizing_use", "ALLOW"),
            ("m0-3a-event-envelope.v2.schema.json", self.event(), "authority_binding_sha256", D),
        ]
        for name, record, field, value in cases:
            altered = copy.deepcopy(record)
            altered[field] = value
            with self.assertRaises(ValidationError):
                validate(name, altered)

    def test_selector_is_one_way_and_history_bound(self):
        generation_zero_v2 = self.selector()
        generation_zero_v2.update(
            active_runtime_format_version=2,
            active_database_path="runtime.v2.sqlite",
            active_attachment_path="attachment.v2.json",
            active_manifest_path="runtime.v2.manifest.json",
            active_manifest_sha256=D,
            cutover_state="V2_ACTIVE",
        )
        later_v1 = self.selector(generation=1)
        later_v1.update(
            active_runtime_format_version=1,
            active_database_path="runtime.sqlite",
            active_attachment_path="attachment.json",
            active_manifest_path=None,
            active_manifest_sha256=None,
            latest_v2_checkpoint_sha256=None,
            cutover_state="V1_ACTIVE",
        )
        missing_prior = self.selector(generation=1)
        missing_prior["prior_selector_path"] = None
        for altered in (generation_zero_v2, later_v1, missing_prior):
            with self.assertRaises(ValidationError):
                validate("m0-3a-active-runtime-selector.v2.schema.json", altered)

    def test_checkpoint_predecessor_and_canonical_utc_are_closed(self):
        later = self.checkpoint()
        later["checkpoint_sequence"] = 1
        with self.assertRaises(ValidationError):
            validate("m0-3a-runtime-checkpoint.v2.schema.json", later)
        offset = self.manifest()
        offset["created_at"] = "2026-10-15T20:00:00-04:00"
        with self.assertRaises(ValidationError):
            validate("m0-3a-runtime-manifest.v2.schema.json", offset)

    def test_legacy_projection_table_schema_ids_are_fixed(self):
        altered = self.legacy_projection()
        altered["tables"]["tasks"]["row_schema_id"] = "arbitrary"
        with self.assertRaises(ValidationError):
            validate("m0-3a-legacy-v1-projection.v1.schema.json", altered)

    def test_legacy_archive_closes_rows_cells_and_storage(self):
        archive = self.legacy_archive()
        archive["tables"]["meta"] = [[
            {"storage_class": "TEXT", "value": "runtime_id"},
            {"storage_class": "TEXT", "value": "runtime-1"},
        ]]
        validate("m0-3a-legacy-v1-row-archive.v1.schema.json", archive)
        wrong_width = copy.deepcopy(archive)
        wrong_width["tables"]["meta"][0].append(
            {"storage_class": "TEXT", "value": "extra"}
        )
        real_cell = copy.deepcopy(archive)
        real_cell["tables"]["meta"][0][1] = {
            "storage_class": "REAL", "value": 1.5,
        }
        sidecar = copy.deepcopy(archive)
        sidecar["storage_inventory"].append({
            "name": "runtime.sqlite-wal", "type": "REGULAR_FILE",
            "mode": "0600", "size": 32768, "sha256": D,
        })
        noncanonical_attachment = copy.deepcopy(archive)
        noncanonical_attachment["attachment_bytes_base64"] = "AB=="
        noncanonical_blob = copy.deepcopy(archive)
        noncanonical_blob["tables"]["meta"] = [[
            {"storage_class": "TEXT", "value": "blob"},
            {"storage_class": "BLOB", "value": "AAB="},
        ]]
        for altered in (
            wrong_width, real_cell, sidecar,
            noncanonical_attachment, noncanonical_blob,
        ):
            with self.assertRaises(ValidationError):
                validate("m0-3a-legacy-v1-row-archive.v1.schema.json", altered)

    def test_registry_requires_complete_closed_binding_count(self):
        missing = self.registry()
        missing["event_bindings"].pop()
        with self.assertRaises(ValidationError):
            validate("m0-3a-schema-registry.v2.schema.json", missing)
        substituted = self.registry()
        substituted["event_bindings"][-1] = {
            **substituted["event_bindings"][0],
            "payload_schema_id": "different-payload",
        }
        with self.assertRaises(ValidationError):
            validate("m0-3a-schema-registry.v2.schema.json", substituted)

    def test_checkpoint_requires_complete_closed_roots(self):
        missing = self.checkpoint()
        del missing["roots"]["idempotency"]
        extra = self.checkpoint()
        extra["roots"]["capital"] = D
        for altered in (missing, extra):
            with self.assertRaises(ValidationError):
                validate("m0-3a-runtime-checkpoint.v2.schema.json", altered)

    def test_format_one_wire_typos_are_not_valid_format_two_events(self):
        for legacy in ("TASK_YIELDD", "TASK_FAILD", "REVIEW_REJECTD"):
            altered = self.event()
            altered["event_type"] = legacy
            with self.assertRaises(ValidationError):
                validate("m0-3a-event-envelope.v2.schema.json", altered)


if __name__ == "__main__":
    unittest.main()
