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
    task_predecessor,
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
from src.edgelab.runtime_v2_group import TASK_STATE_SCHEMA_ID
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


def initialize_fixture():
    image, values = fixture()
    task_id = "task-alpha"
    semantic_id = "123e4567-e89b-42d3-a456-426614174003"
    commit_id = "123e4567-e89b-42d3-a456-426614174004"
    transaction_id = "123e4567-e89b-42d3-a456-426614174005"
    operation_key = f"v2:{CHAIN_ID}:initialize-task-alpha"
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
        "repository_generation": 0,
        "decision_receipt_digest": "5" * 64,
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
        "repository_generation": 0,
        "repository_bundle_sha256": BUNDLE,
        "subject": {"task_id": task_id, "attempt": 1},
        "expected_state_ref": None,
        "arguments": {
            "decision_receipt_digest": "5" * 64,
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
            "state_ref": {"schema_id": TASK_STATE_SCHEMA_ID, "sha256": state_sha},
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
        "occurred_at": CREATED_AT,
        "global_sequence": 1,
        "global_predecessor": {
            "event_id": EVENT_ID,
            "event_sha256": values["event"]["event_sha256"],
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
        "payload_ref": {"schema_id": PAYLOAD_SCHEMA_ID, "sha256": semantic_payload_sha},
        "state_before_ref": None,
        "state_after_ref": {"schema_id": TASK_STATE_SCHEMA_ID, "sha256": state_sha},
        "repository_generation": 0,
        "repository_bundle_sha256": BUNDLE,
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
                "global_sequence": 0,
                "event_id": EVENT_ID,
                "event_sha256": values["event"]["event_sha256"],
            },
            "post_semantic_head": {
                "global_sequence": 1,
                "event_id": semantic_id,
                "event_sha256": semantic["event_sha256"],
            },
            "operation": "INITIALIZE",
            "operation_key": operation_key,
            "request_ref": {"schema_id": REQUEST_SCHEMA_ID, "sha256": request_sha},
            "response_ref": {"schema_id": RESPONSE_SCHEMA_ID, "sha256": response_sha},
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
        "occurred_at": CREATED_AT,
        "global_sequence": 2,
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
        "payload_ref": {"schema_id": PAYLOAD_SCHEMA_ID, "sha256": commit_payload_sha},
        "state_before_ref": None,
        "state_after_ref": None,
        "repository_generation": 0,
        "repository_bundle_sha256": BUNDLE,
        "authority_binding_sha256": None,
        "authorizing_use": "DENY",
        "event_sha256": "0" * 64,
    }
    commit["event_sha256"] = event_digest(commit)
    additions = (
        BlobRecord(request_sha, REQUEST_SCHEMA_ID, canonical_json(request)),
        BlobRecord(response_sha, RESPONSE_SCHEMA_ID, canonical_json(response)),
        BlobRecord(semantic_payload_sha, PAYLOAD_SCHEMA_ID, canonical_json(semantic_payload)),
        BlobRecord(commit_payload_sha, PAYLOAD_SCHEMA_ID, canonical_json(commit_payload)),
        BlobRecord(state_sha, TASK_STATE_SCHEMA_ID, canonical_json(state)),
    )
    blobs = tuple(sorted(image.blobs + additions, key=lambda record: record.sha256))
    rows = {snapshot.table: snapshot.rows for snapshot in image.table_snapshots}
    rows["blobs"] = tuple(
        (record.sha256, record.schema_id, record.canonical_json.decode("ascii"))
        for record in blobs
    )
    rows["events"] = rows["events"] + (
        (1, semantic_id, semantic["event_sha256"], canonical_json(semantic).decode("ascii")),
        (2, commit_id, commit["event_sha256"], canonical_json(commit).decode("ascii")),
    )
    rows["attempts"] = ((task_id, 1, None, semantic_id, 1, semantic_id, semantic["event_sha256"]),)
    rows["idempotency"] = ((
        operation_key, transaction_id, request_sha, response_sha, commit_id, 2, CREATED_AT,
    ),)
    metadata = list(rows["metadata"][0])
    metadata[15:18] = [2, commit_id, commit["event_sha256"]]
    rows["metadata"] = (tuple(metadata),)
    rows["tasks"] = ((
        task_id, 1, "ACTIVE", "CLAIMABLE", "NOT_REQUIRED", 0, 0, 0,
        None, None, 0, 0, "5" * 64, "03 Research", "research", None,
        None, None,
    ),)
    result = replace(
        image,
        blobs=blobs,
        events=(image.events[0], canonical_json(semantic), canonical_json(commit)),
        table_snapshots=tuple(TableSnapshot(name, rows[name]) for name in TABLE_NAMES),
    )
    values.update({
        "initialize_request": request,
        "initialize_response": response,
        "initialize_state": state,
        "semantic_payload": semantic_payload,
        "commit_payload": commit_payload,
        "semantic": semantic,
        "commit": commit,
    })
    return result, values


def claim_fixture():
    image, values = initialize_fixture()
    task_id = values["initialize_state"]["task_id"]
    semantic_id = "123e4567-e89b-42d3-a456-426614174006"
    commit_id = "123e4567-e89b-42d3-a456-426614174007"
    transaction_id = "123e4567-e89b-42d3-a456-426614174008"
    claim_id = "123e4567-e89b-42d3-a456-426614174009"
    operation_key = f"v2:{CHAIN_ID}:claim-task-alpha"
    before_state = values["initialize_state"]
    before_sha = blob_digest(before_state)
    after_state = json.loads(json.dumps(before_state))
    after_state.update({
        "execution": "CLAIMED",
        "scheduler_generation": 1,
        "dispatch_generation": 1,
        "task_fence": 1,
        "active_claim_id": claim_id,
    })
    after_sha = blob_digest(after_state)
    request = {
        "schema_version": 1,
        "request_format_version": 2,
        "runtime_id": RUNTIME_ID,
        "chain_id": CHAIN_ID,
        "operation": "CLAIM",
        "operation_key": operation_key,
        "repository_generation": 0,
        "repository_bundle_sha256": BUNDLE,
        "subject": {"task_id": task_id, "attempt": 1},
        "expected_state_ref": {"schema_id": TASK_STATE_SCHEMA_ID, "sha256": before_sha},
        "arguments": {"actor": "worker-a"},
    }
    response = {
        "schema_version": 1,
        "response_format_version": 2,
        "runtime_id": RUNTIME_ID,
        "chain_id": CHAIN_ID,
        "operation": "CLAIM",
        "operation_key": operation_key,
        "status": "COMMITTED",
        "affected_states": [{
            "task_id": task_id,
            "attempt": 1,
            "state_ref": {"schema_id": TASK_STATE_SCHEMA_ID, "sha256": after_sha},
        }],
        "generated_refs": [{
            "kind": "CLAIM", "identifier": claim_id, "sha256": None,
        }],
    }
    semantic_payload = {
        "schema_version": 1,
        "payload_format_version": 2,
        "event_type": "CLAIM_ISSUED",
        "data": {"claim_id": claim_id},
    }
    request_sha = blob_digest(request)
    response_sha = blob_digest(response)
    payload_sha = blob_digest(semantic_payload)
    init_semantic = values["semantic"]
    init_commit = values["commit"]
    semantic = {
        "schema_version": 1,
        "event_format_version": 2,
        "runtime_id": RUNTIME_ID,
        "chain_id": CHAIN_ID,
        "event_id": semantic_id,
        "event_type": "CLAIM_ISSUED",
        "occurred_at": CREATED_AT,
        "global_sequence": 3,
        "global_predecessor": {
            "event_id": init_commit["event_id"],
            "event_sha256": init_commit["event_sha256"],
        },
        "stream": "TASK",
        "task_context": {
            "task_id": task_id,
            "attempt": 1,
            "task_sequence": 2,
            "task_predecessor": {
                "event_id": init_semantic["event_id"],
                "event_sha256": init_semantic["event_sha256"],
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
        "payload_ref": {"schema_id": PAYLOAD_SCHEMA_ID, "sha256": payload_sha},
        "state_before_ref": {"schema_id": TASK_STATE_SCHEMA_ID, "sha256": before_sha},
        "state_after_ref": {"schema_id": TASK_STATE_SCHEMA_ID, "sha256": after_sha},
        "repository_generation": 0,
        "repository_bundle_sha256": BUNDLE,
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
                "global_sequence": 2,
                "event_id": init_commit["event_id"],
                "event_sha256": init_commit["event_sha256"],
            },
            "post_semantic_head": {
                "global_sequence": 3,
                "event_id": semantic_id,
                "event_sha256": semantic["event_sha256"],
            },
            "operation": "CLAIM",
            "operation_key": operation_key,
            "request_ref": {"schema_id": REQUEST_SCHEMA_ID, "sha256": request_sha},
            "response_ref": {"schema_id": RESPONSE_SCHEMA_ID, "sha256": response_sha},
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
        "occurred_at": CREATED_AT,
        "global_sequence": 4,
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
        "payload_ref": {"schema_id": PAYLOAD_SCHEMA_ID, "sha256": commit_payload_sha},
        "state_before_ref": None,
        "state_after_ref": None,
        "repository_generation": 0,
        "repository_bundle_sha256": BUNDLE,
        "authority_binding_sha256": None,
        "authorizing_use": "DENY",
        "event_sha256": "0" * 64,
    }
    commit["event_sha256"] = event_digest(commit)
    additions = (
        BlobRecord(request_sha, REQUEST_SCHEMA_ID, canonical_json(request)),
        BlobRecord(response_sha, RESPONSE_SCHEMA_ID, canonical_json(response)),
        BlobRecord(payload_sha, PAYLOAD_SCHEMA_ID, canonical_json(semantic_payload)),
        BlobRecord(commit_payload_sha, PAYLOAD_SCHEMA_ID, canonical_json(commit_payload)),
        BlobRecord(after_sha, TASK_STATE_SCHEMA_ID, canonical_json(after_state)),
    )
    blobs = tuple(sorted(image.blobs + additions, key=lambda record: record.sha256))
    rows = {snapshot.table: snapshot.rows for snapshot in image.table_snapshots}
    rows["blobs"] = tuple(
        (record.sha256, record.schema_id, record.canonical_json.decode("ascii"))
        for record in blobs
    )
    rows["events"] = rows["events"] + (
        (3, semantic_id, semantic["event_sha256"], canonical_json(semantic).decode("ascii")),
        (4, commit_id, commit["event_sha256"], canonical_json(commit).decode("ascii")),
    )
    rows["attempts"] = ((
        task_id, 1, None, init_semantic["event_id"], 2,
        semantic_id, semantic["event_sha256"],
    ),)
    rows["claims"] = ((
        claim_id, task_id, 1, 1, "OPEN", "worker-a", semantic_id, None,
    ),)
    claim_idempotency = (
        operation_key, transaction_id, request_sha, response_sha, commit_id, 4, CREATED_AT,
    )
    rows["idempotency"] = tuple(sorted(rows["idempotency"] + (claim_idempotency,)))
    metadata = list(rows["metadata"][0])
    metadata[15:18] = [4, commit_id, commit["event_sha256"]]
    rows["metadata"] = (tuple(metadata),)
    rows["tasks"] = ((
        task_id, 1, "ACTIVE", "CLAIMED", "NOT_REQUIRED", 1, 1, 1,
        claim_id, None, 0, 0, "5" * 64, "03 Research", "research", None,
        None, None,
    ),)
    result = replace(
        image,
        blobs=blobs,
        events=image.events + (canonical_json(semantic), canonical_json(commit)),
        table_snapshots=tuple(TableSnapshot(name, rows[name]) for name in TABLE_NAMES),
    )
    values.update({
        "claim_request": request,
        "claim_response": response,
        "claim_before_state": before_state,
        "claim_after_state": after_state,
        "claim_semantic_payload": semantic_payload,
        "claim_commit_payload": commit_payload,
        "claim_semantic": semantic,
        "claim_commit": commit,
    })
    return result, values


def _task_table_row(state):
    return tuple(state[name] for name in (
        "task_id", "attempt", "workflow", "execution", "review",
        "scheduler_generation", "dispatch_generation", "task_fence",
        "active_claim_id", "reviewer_assignment_id", "continuation_count",
        "repository_generation", "decision_receipt_digest", "owner",
        "owner_role", "reviewer", "predecessor_task", "successor_task",
    ))


def _worker_fixture(image, values, operation):
    profile = {
        "START": {
            "semantic_id": "123e4567-e89b-42d3-a456-426614174010",
            "commit_id": "123e4567-e89b-42d3-a456-426614174011",
            "transaction_id": "123e4567-e89b-42d3-a456-426614174012",
            "event_type": "TASK_STARTED",
        },
        "YIELD": {
            "semantic_id": "123e4567-e89b-42d3-a456-426614174013",
            "commit_id": "123e4567-e89b-42d3-a456-426614174014",
            "transaction_id": "123e4567-e89b-42d3-a456-426614174015",
            "event_type": "TASK_YIELDED",
        },
    }[operation]
    prefix = operation.lower()
    before_state = (
        values["claim_after_state"]
        if operation == "START"
        else values["start_after_state"]
    )
    after_state = json.loads(json.dumps(before_state))
    after_state["scheduler_generation"] += 1
    claim_id = before_state["active_claim_id"]
    if operation == "START":
        after_state["execution"] = "IN_PROGRESS"
        arguments = {"claim_id": claim_id, "fence": before_state["task_fence"]}
    else:
        after_state.update({
            "execution": "CLAIMABLE",
            "dispatch_generation": before_state["dispatch_generation"] + 1,
            "task_fence": before_state["task_fence"] + 1,
            "active_claim_id": None,
        })
        arguments = {
            "claim_id": claim_id,
            "fence": before_state["task_fence"],
            "yield_evidence_sha256": "6" * 64,
        }
    task_id = before_state["task_id"]
    before_sha = blob_digest(before_state)
    after_sha = blob_digest(after_state)
    operation_key = f"v2:{CHAIN_ID}:{prefix}-task-alpha"
    request = {
        "schema_version": 1,
        "request_format_version": 2,
        "runtime_id": RUNTIME_ID,
        "chain_id": CHAIN_ID,
        "operation": operation,
        "operation_key": operation_key,
        "repository_generation": 0,
        "repository_bundle_sha256": BUNDLE,
        "subject": {"task_id": task_id, "attempt": 1},
        "expected_state_ref": {
            "schema_id": TASK_STATE_SCHEMA_ID,
            "sha256": before_sha,
        },
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
        "affected_states": [{
            "task_id": task_id,
            "attempt": 1,
            "state_ref": {
                "schema_id": TASK_STATE_SCHEMA_ID,
                "sha256": after_sha,
            },
        }],
        "generated_refs": [],
    }
    semantic_payload = {
        "schema_version": 1,
        "payload_format_version": 2,
        "event_type": profile["event_type"],
        "data": {},
    }
    request_sha = blob_digest(request)
    response_sha = blob_digest(response)
    payload_sha = blob_digest(semantic_payload)
    prior_events = tuple(json.loads(raw) for raw in image.events)
    prior = prior_events[-1]
    prior_task_events = tuple(
        event for event in prior_events if event["stream"] == "TASK"
    )
    prior_task = prior_task_events[-1]
    semantic_index = len(prior_events)
    task_sequence = len(prior_task_events) + 1
    semantic = {
        "schema_version": 1,
        "event_format_version": 2,
        "runtime_id": RUNTIME_ID,
        "chain_id": CHAIN_ID,
        "event_id": profile["semantic_id"],
        "event_type": profile["event_type"],
        "occurred_at": CREATED_AT,
        "global_sequence": semantic_index,
        "global_predecessor": {
            "event_id": prior["event_id"],
            "event_sha256": prior["event_sha256"],
        },
        "stream": "TASK",
        "task_context": {
            "task_id": task_id,
            "attempt": 1,
            "task_sequence": task_sequence,
            "task_predecessor": {
                "event_id": prior_task["event_id"],
                "event_sha256": prior_task["event_sha256"],
            },
        },
        "transaction": {
            "transaction_id": profile["transaction_id"],
            "position": 0,
            "event_count": 2,
            "operation_key": operation_key,
            "request_sha256": request_sha,
            "response_sha256": response_sha,
        },
        "payload_ref": {"schema_id": PAYLOAD_SCHEMA_ID, "sha256": payload_sha},
        "state_before_ref": {
            "schema_id": TASK_STATE_SCHEMA_ID,
            "sha256": before_sha,
        },
        "state_after_ref": {
            "schema_id": TASK_STATE_SCHEMA_ID,
            "sha256": after_sha,
        },
        "repository_generation": 0,
        "repository_bundle_sha256": BUNDLE,
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
            "semantic_event_ids": [semantic["event_id"]],
            "pre_command_head": {
                "global_sequence": prior["global_sequence"],
                "event_id": prior["event_id"],
                "event_sha256": prior["event_sha256"],
            },
            "post_semantic_head": {
                "global_sequence": semantic_index,
                "event_id": semantic["event_id"],
                "event_sha256": semantic["event_sha256"],
            },
            "operation": operation,
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
        "event_id": profile["commit_id"],
        "event_type": "COMMAND_COMMITTED",
        "occurred_at": CREATED_AT,
        "global_sequence": semantic_index + 1,
        "global_predecessor": {
            "event_id": semantic["event_id"],
            "event_sha256": semantic["event_sha256"],
        },
        "stream": "RUNTIME",
        "task_context": None,
        "transaction": {
            "transaction_id": profile["transaction_id"],
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
        "repository_generation": 0,
        "repository_bundle_sha256": BUNDLE,
        "authority_binding_sha256": None,
        "authorizing_use": "DENY",
        "event_sha256": "0" * 64,
    }
    commit["event_sha256"] = event_digest(commit)
    additions = (
        BlobRecord(request_sha, REQUEST_SCHEMA_ID, canonical_json(request)),
        BlobRecord(response_sha, RESPONSE_SCHEMA_ID, canonical_json(response)),
        BlobRecord(payload_sha, PAYLOAD_SCHEMA_ID, canonical_json(semantic_payload)),
        BlobRecord(
            commit_payload_sha, PAYLOAD_SCHEMA_ID, canonical_json(commit_payload)
        ),
        BlobRecord(after_sha, TASK_STATE_SCHEMA_ID, canonical_json(after_state)),
    )
    blobs = tuple(sorted(image.blobs + additions, key=lambda record: record.sha256))
    rows = {snapshot.table: snapshot.rows for snapshot in image.table_snapshots}
    rows["blobs"] = tuple(
        (record.sha256, record.schema_id, record.canonical_json.decode("ascii"))
        for record in blobs
    )
    rows["events"] = rows["events"] + (
        (
            semantic_index, semantic["event_id"], semantic["event_sha256"],
            canonical_json(semantic).decode("ascii"),
        ),
        (
            semantic_index + 1, commit["event_id"], commit["event_sha256"],
            canonical_json(commit).decode("ascii"),
        ),
    )
    attempt = list(rows["attempts"][0])
    attempt[4:] = [task_sequence, semantic["event_id"], semantic["event_sha256"]]
    rows["attempts"] = (tuple(attempt),)
    if operation == "YIELD":
        claim = list(rows["claims"][0])
        claim[4] = "YIELDED"
        claim[7] = semantic["event_id"]
        rows["claims"] = (tuple(claim),)
    idempotency = (
        operation_key, profile["transaction_id"], request_sha, response_sha,
        commit["event_id"], semantic_index + 1, CREATED_AT,
    )
    rows["idempotency"] = tuple(sorted(rows["idempotency"] + (idempotency,)))
    metadata = list(rows["metadata"][0])
    metadata[15:18] = [
        semantic_index + 1, commit["event_id"], commit["event_sha256"],
    ]
    rows["metadata"] = (tuple(metadata),)
    rows["tasks"] = (_task_table_row(after_state),)
    result = replace(
        image,
        blobs=blobs,
        events=image.events + (canonical_json(semantic), canonical_json(commit)),
        table_snapshots=tuple(TableSnapshot(name, rows[name]) for name in TABLE_NAMES),
    )
    values.update({
        f"{prefix}_request": request,
        f"{prefix}_response": response,
        f"{prefix}_before_state": before_state,
        f"{prefix}_after_state": after_state,
        f"{prefix}_semantic_payload": semantic_payload,
        f"{prefix}_commit_payload": commit_payload,
        f"{prefix}_semantic": semantic,
        f"{prefix}_commit": commit,
    })
    return result, values


def start_fixture():
    image, values = claim_fixture()
    return _worker_fixture(image, values, "START")


def yield_fixture():
    image, values = start_fixture()
    return _worker_fixture(image, values, "YIELD")


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

    def test_initialize_group_reduces_end_to_end_but_remains_opaque(self):
        image, _ = initialize_fixture()
        report = reduce_initial_runtime_image(image)
        self.assertEqual(report.status, "UNSUPPORTED")
        self.assertEqual(self.codes(report), {"CLOSURE_NOT_COMPILED"})
        self.assertEqual(report.authorizing_use, "DENY")

    def test_claim_group_reduces_end_to_end_but_remains_opaque(self):
        image, _ = claim_fixture()
        report = reduce_initial_runtime_image(image)
        self.assertEqual(report.status, "UNSUPPORTED")
        self.assertEqual(self.codes(report), {"CLOSURE_NOT_COMPILED"})
        self.assertEqual(report.authorizing_use, "DENY")

    def test_claim_group_binds_global_and_task_predecessors(self):
        image, values = claim_fixture()
        semantic = json.loads(json.dumps(values["claim_semantic"]))
        semantic["task_context"]["task_predecessor"]["event_id"] = (
            "123e4567-e89b-42d3-a456-426614174099"
        )
        semantic["event_sha256"] = event_digest(semantic)
        commit_payload = json.loads(json.dumps(values["claim_commit_payload"]))
        commit_payload["data"]["post_semantic_head"]["event_sha256"] = (
            semantic["event_sha256"]
        )
        commit_payload_sha = blob_digest(commit_payload)
        commit = json.loads(json.dumps(values["claim_commit"]))
        commit["global_predecessor"]["event_sha256"] = semantic["event_sha256"]
        commit["payload_ref"]["sha256"] = commit_payload_sha
        commit["event_sha256"] = event_digest(commit)
        old_payload_sha = blob_digest(values["claim_commit_payload"])
        blobs = tuple(
            record for record in image.blobs if record.sha256 != old_payload_sha
        ) + (
            BlobRecord(
                commit_payload_sha,
                PAYLOAD_SCHEMA_ID,
                canonical_json(commit_payload),
            ),
        )
        report = reduce_initial_runtime_image(replace(
            image,
            blobs=tuple(sorted(blobs, key=lambda record: record.sha256)),
            events=image.events[:3] + (
                canonical_json(semantic), canonical_json(commit),
            ),
        ))
        self.assertEqual(report.status, "INVALID")
        self.assertIn("GROUP_CONST", self.codes(report))

        semantic = json.loads(json.dumps(values["claim_semantic"]))
        semantic["global_predecessor"]["event_sha256"] = "f" * 64
        semantic["event_sha256"] = event_digest(semantic)
        report = reduce_initial_runtime_image(replace(
            image,
            events=image.events[:3] + (
                canonical_json(semantic), image.events[4],
            ),
        ))
        self.assertEqual(report.status, "INVALID")
        self.assertIn("GROUP_CONST", self.codes(report))

    def test_claim_group_rejects_duplicate_transaction_and_operation_key(self):
        image, values = claim_fixture()
        initialize = values["semantic"]
        for field, replacement_value, expected_code in (
            (
                "transaction_id",
                initialize["transaction"]["transaction_id"],
                "GROUP_TRANSACTION_DUPLICATE",
            ),
            (
                "operation_key",
                initialize["transaction"]["operation_key"],
                "GROUP_OPERATION_KEY_DUPLICATE",
            ),
        ):
            semantic = json.loads(json.dumps(values["claim_semantic"]))
            commit = json.loads(json.dumps(values["claim_commit"]))
            semantic["transaction"][field] = replacement_value
            commit["transaction"][field] = replacement_value
            semantic["event_sha256"] = event_digest(semantic)
            commit["global_predecessor"]["event_sha256"] = semantic["event_sha256"]
            commit["event_sha256"] = event_digest(commit)
            with self.subTest(field=field):
                report = reduce_initial_runtime_image(replace(
                    image,
                    events=image.events[:3] + (
                        canonical_json(semantic), canonical_json(commit),
                    ),
                ))
                self.assertEqual(report.status, "INVALID")
                self.assertIn(expected_code, self.codes(report))

    def test_claim_generated_identity_is_not_trusted_from_response(self):
        image, values = claim_fixture()
        response = json.loads(json.dumps(values["claim_response"]))
        response["generated_refs"][0]["identifier"] = (
            "123e4567-e89b-42d3-a456-426614174099"
        )
        response_sha = blob_digest(response)
        semantic = json.loads(json.dumps(values["claim_semantic"]))
        semantic["transaction"]["response_sha256"] = response_sha
        semantic["event_sha256"] = event_digest(semantic)
        commit_payload = json.loads(json.dumps(values["claim_commit_payload"]))
        commit_payload["data"]["response_ref"]["sha256"] = response_sha
        commit_payload["data"]["post_semantic_head"]["event_sha256"] = (
            semantic["event_sha256"]
        )
        commit_payload_sha = blob_digest(commit_payload)
        commit = json.loads(json.dumps(values["claim_commit"]))
        commit["transaction"]["response_sha256"] = response_sha
        commit["global_predecessor"]["event_sha256"] = semantic["event_sha256"]
        commit["payload_ref"]["sha256"] = commit_payload_sha
        commit["event_sha256"] = event_digest(commit)
        old_response_sha = blob_digest(values["claim_response"])
        old_commit_payload_sha = blob_digest(values["claim_commit_payload"])
        blobs = tuple(
            record for record in image.blobs
            if record.sha256 not in {old_response_sha, old_commit_payload_sha}
        ) + (
            BlobRecord(response_sha, RESPONSE_SCHEMA_ID, canonical_json(response)),
            BlobRecord(
                commit_payload_sha,
                PAYLOAD_SCHEMA_ID,
                canonical_json(commit_payload),
            ),
        )
        report = reduce_initial_runtime_image(replace(
            image,
            blobs=tuple(sorted(blobs, key=lambda record: record.sha256)),
            events=image.events[:3] + (
                canonical_json(semantic), canonical_json(commit),
            ),
        ))
        self.assertEqual(report.status, "INVALID")
        self.assertIn("GROUP_CONST", self.codes(report))

    def test_claim_state_is_recomputed_not_trusted(self):
        image, values = claim_fixture()
        state = json.loads(json.dumps(values["claim_after_state"]))
        state["task_fence"] = 9
        state_sha = blob_digest(state)
        response = json.loads(json.dumps(values["claim_response"]))
        response["affected_states"][0]["state_ref"]["sha256"] = state_sha
        response_sha = blob_digest(response)
        semantic = json.loads(json.dumps(values["claim_semantic"]))
        semantic["state_after_ref"]["sha256"] = state_sha
        semantic["transaction"]["response_sha256"] = response_sha
        semantic["event_sha256"] = event_digest(semantic)
        commit_payload = json.loads(json.dumps(values["claim_commit_payload"]))
        commit_payload["data"]["response_ref"]["sha256"] = response_sha
        commit_payload["data"]["post_semantic_head"]["event_sha256"] = (
            semantic["event_sha256"]
        )
        commit_payload_sha = blob_digest(commit_payload)
        commit = json.loads(json.dumps(values["claim_commit"]))
        commit["transaction"]["response_sha256"] = response_sha
        commit["global_predecessor"]["event_sha256"] = semantic["event_sha256"]
        commit["payload_ref"]["sha256"] = commit_payload_sha
        commit["event_sha256"] = event_digest(commit)
        removed = {
            blob_digest(values["claim_response"]),
            blob_digest(values["claim_commit_payload"]),
            blob_digest(values["claim_after_state"]),
        }
        blobs = tuple(
            record for record in image.blobs if record.sha256 not in removed
        ) + (
            BlobRecord(response_sha, RESPONSE_SCHEMA_ID, canonical_json(response)),
            BlobRecord(
                commit_payload_sha,
                PAYLOAD_SCHEMA_ID,
                canonical_json(commit_payload),
            ),
            BlobRecord(state_sha, TASK_STATE_SCHEMA_ID, canonical_json(state)),
        )
        report = reduce_initial_runtime_image(replace(
            image,
            blobs=tuple(sorted(blobs, key=lambda record: record.sha256)),
            events=image.events[:3] + (
                canonical_json(semantic), canonical_json(commit),
            ),
        ))
        self.assertEqual(report.status, "INVALID")
        self.assertIn("GROUP_STATE_DERIVATION", self.codes(report))

    def test_claim_rows_are_derived_not_trusted(self):
        image, _ = claim_fixture()
        for table, column, replacement_value in (
            ("attempts", 4, 99),
            ("claims", 3, 99),
            ("idempotency", 5, 99),
            ("tasks", 7, 99),
        ):
            snapshots = list(image.table_snapshots)
            index = TABLE_NAMES.index(table)
            rows = list(snapshots[index].rows)
            row_index = len(rows) - 1
            row = list(rows[row_index])
            row[column] = replacement_value
            rows[row_index] = tuple(row)
            snapshots[index] = TableSnapshot(table, tuple(rows))
            with self.subTest(table=table):
                report = reduce_initial_runtime_image(replace(
                    image, table_snapshots=tuple(snapshots),
                ))
                self.assertEqual(report.status, "INVALID")
                self.assertIn("TABLE_DERIVATION", self.codes(report))

    def test_start_and_yield_reduce_end_to_end_but_remain_opaque(self):
        for name, build in (("start", start_fixture), ("yield", yield_fixture)):
            with self.subTest(group=name):
                image, _ = build()
                report = reduce_initial_runtime_image(image)
                self.assertEqual(report.status, "UNSUPPORTED")
                self.assertEqual(self.codes(report), {"CLOSURE_NOT_COMPILED"})
                self.assertEqual(report.authorizing_use, "DENY")

    def test_worker_groups_enforce_claim_and_fence_cas(self):
        for name, build in (("start", start_fixture), ("yield", yield_fixture)):
            image, values = build()
            for field, replacement_value, expected_code in (
                (
                    "claim_id",
                    "123e4567-e89b-42d3-a456-426614174099",
                    "TRANSITION_CLAIM_CAS",
                ),
                (
                    "fence",
                    values[f"{name}_request"]["arguments"]["fence"] + 1,
                    "TRANSITION_FENCE_CAS",
                ),
            ):
                request = json.loads(json.dumps(values[f"{name}_request"]))
                request["arguments"][field] = replacement_value
                request_sha = blob_digest(request)
                semantic = json.loads(json.dumps(values[f"{name}_semantic"]))
                semantic["transaction"]["request_sha256"] = request_sha
                semantic["event_sha256"] = event_digest(semantic)
                commit = json.loads(json.dumps(values[f"{name}_commit"]))
                commit["transaction"]["request_sha256"] = request_sha
                commit["global_predecessor"]["event_sha256"] = (
                    semantic["event_sha256"]
                )
                commit["event_sha256"] = event_digest(commit)
                old_request_sha = blob_digest(values[f"{name}_request"])
                blobs = tuple(
                    record for record in image.blobs
                    if record.sha256 != old_request_sha
                ) + (
                    BlobRecord(
                        request_sha, REQUEST_SCHEMA_ID, canonical_json(request)
                    ),
                )
                with self.subTest(group=name, field=field):
                    report = reduce_initial_runtime_image(replace(
                        image,
                        blobs=tuple(sorted(
                            blobs, key=lambda record: record.sha256
                        )),
                        events=image.events[:-2] + (
                            canonical_json(semantic), canonical_json(commit),
                        ),
                    ))
                    self.assertEqual(report.status, "INVALID")
                    self.assertIn(expected_code, self.codes(report))

    def test_worker_groups_bind_task_chain_and_empty_payload(self):
        image, values = yield_fixture()
        semantic = json.loads(json.dumps(values["yield_semantic"]))
        semantic["task_context"]["task_predecessor"]["event_sha256"] = "f" * 64
        semantic["event_sha256"] = event_digest(semantic)
        commit = json.loads(json.dumps(values["yield_commit"]))
        commit["global_predecessor"]["event_sha256"] = semantic["event_sha256"]
        commit["event_sha256"] = event_digest(commit)
        report = reduce_initial_runtime_image(replace(
            image,
            events=image.events[:-2] + (
                canonical_json(semantic), canonical_json(commit),
            ),
        ))
        self.assertEqual(report.status, "INVALID")
        self.assertIn("GROUP_CONST", self.codes(report))

        payload = json.loads(json.dumps(values["yield_semantic_payload"]))
        payload["data"] = {"invented": True}
        payload_sha = blob_digest(payload)
        semantic = json.loads(json.dumps(values["yield_semantic"]))
        semantic["payload_ref"]["sha256"] = payload_sha
        semantic["event_sha256"] = event_digest(semantic)
        commit = json.loads(json.dumps(values["yield_commit"]))
        commit["global_predecessor"]["event_sha256"] = semantic["event_sha256"]
        commit["event_sha256"] = event_digest(commit)
        old_payload_sha = blob_digest(values["yield_semantic_payload"])
        blobs = tuple(
            record for record in image.blobs if record.sha256 != old_payload_sha
        ) + (
            BlobRecord(payload_sha, PAYLOAD_SCHEMA_ID, canonical_json(payload)),
        )
        report = reduce_initial_runtime_image(replace(
            image,
            blobs=tuple(sorted(blobs, key=lambda record: record.sha256)),
            events=image.events[:-2] + (
                canonical_json(semantic), canonical_json(commit),
            ),
        ))
        self.assertEqual(report.status, "INVALID")
        self.assertIn("GROUP_CONST", self.codes(report))

    def test_worker_state_and_claim_closure_are_derived_not_trusted(self):
        image, values = yield_fixture()
        state = json.loads(json.dumps(values["yield_after_state"]))
        state["task_fence"] += 7
        state_sha = blob_digest(state)
        semantic = json.loads(json.dumps(values["yield_semantic"]))
        semantic["state_after_ref"]["sha256"] = state_sha
        semantic["event_sha256"] = event_digest(semantic)
        commit = json.loads(json.dumps(values["yield_commit"]))
        commit["global_predecessor"]["event_sha256"] = semantic["event_sha256"]
        commit["event_sha256"] = event_digest(commit)
        old_state_sha = blob_digest(values["yield_after_state"])
        blobs = tuple(
            record for record in image.blobs if record.sha256 != old_state_sha
        ) + (
            BlobRecord(state_sha, TASK_STATE_SCHEMA_ID, canonical_json(state)),
        )
        report = reduce_initial_runtime_image(replace(
            image,
            blobs=tuple(sorted(blobs, key=lambda record: record.sha256)),
            events=image.events[:-2] + (
                canonical_json(semantic), canonical_json(commit),
            ),
        ))
        self.assertEqual(report.status, "INVALID")
        self.assertIn("GROUP_STATE_DERIVATION", self.codes(report))

        snapshots = list(image.table_snapshots)
        index = TABLE_NAMES.index("claims")
        claim = list(snapshots[index].rows[0])
        claim[4] = "OPEN"
        claim[7] = None
        snapshots[index] = TableSnapshot("claims", (tuple(claim),))
        report = reduce_initial_runtime_image(replace(
            image, table_snapshots=tuple(snapshots),
        ))
        self.assertEqual(report.status, "INVALID")
        self.assertIn("TABLE_DERIVATION", self.codes(report))

    def test_initialize_group_rejects_shared_grammar_and_commit_mutations(self):
        image, values = initialize_fixture()
        semantic = json.loads(json.dumps(values["semantic"]))
        semantic["transaction"]["event_count"] = 3
        semantic["event_sha256"] = event_digest(semantic)
        report = reduce_initial_runtime_image(replace(
            image,
            events=(image.events[0], canonical_json(semantic), image.events[2]),
        ))
        self.assertEqual(report.status, "INVALID")
        self.assertIn("GROUP_CONST", self.codes(report))

        payload = json.loads(json.dumps(values["commit_payload"]))
        payload["data"]["semantic_event_ids"] = [values["commit"]["event_id"]]
        changed = BlobRecord(blob_digest(payload), PAYLOAD_SCHEMA_ID, canonical_json(payload))
        commit = json.loads(json.dumps(values["commit"]))
        commit["payload_ref"]["sha256"] = changed.sha256
        commit["event_sha256"] = event_digest(commit)
        blobs = tuple(sorted(
            tuple(record for record in image.blobs if record.sha256 != blob_digest(values["commit_payload"])) + (changed,),
            key=lambda record: record.sha256,
        ))
        report = reduce_initial_runtime_image(replace(
            image,
            blobs=blobs,
            events=(image.events[0], image.events[1], canonical_json(commit)),
        ))
        self.assertEqual(report.status, "INVALID")
        self.assertIn("GROUP_CONST", self.codes(report))

    def test_initialize_group_rejects_reused_event_and_transaction_identity(self):
        image, values = initialize_fixture()
        semantic = json.loads(json.dumps(values["semantic"]))
        semantic["event_id"] = EVENT_ID
        semantic["event_sha256"] = event_digest(semantic)
        report = reduce_initial_runtime_image(replace(
            image,
            events=(image.events[0], canonical_json(semantic), image.events[2]),
        ))
        self.assertEqual(report.status, "INVALID")
        self.assertIn("GROUP_EVENT_ID_DUPLICATE", self.codes(report))

        semantic = json.loads(json.dumps(values["semantic"]))
        semantic["transaction"]["transaction_id"] = TRANSACTION_ID
        semantic["event_sha256"] = event_digest(semantic)
        commit = json.loads(json.dumps(values["commit"]))
        commit["transaction"]["transaction_id"] = TRANSACTION_ID
        commit["global_predecessor"]["event_sha256"] = semantic["event_sha256"]
        commit["event_sha256"] = event_digest(commit)
        report = reduce_initial_runtime_image(replace(
            image,
            events=(image.events[0], canonical_json(semantic), canonical_json(commit)),
        ))
        self.assertEqual(report.status, "INVALID")
        self.assertIn("GROUP_TRANSACTION_DUPLICATE", self.codes(report))

    def test_initialize_state_is_recomputed_not_trusted(self):
        image, values = initialize_fixture()
        state = json.loads(json.dumps(values["initialize_state"]))
        state["owner"] = "hostile-owner"
        state_sha = blob_digest(state)
        response = json.loads(json.dumps(values["initialize_response"]))
        response["affected_states"][0]["state_ref"]["sha256"] = state_sha
        response_sha = blob_digest(response)
        semantic = json.loads(json.dumps(values["semantic"]))
        semantic["state_after_ref"]["sha256"] = state_sha
        semantic["transaction"]["response_sha256"] = response_sha
        semantic["event_sha256"] = event_digest(semantic)
        commit_payload = json.loads(json.dumps(values["commit_payload"]))
        commit_payload["data"]["post_semantic_head"]["event_sha256"] = semantic["event_sha256"]
        commit_payload["data"]["response_ref"]["sha256"] = response_sha
        commit_payload_sha = blob_digest(commit_payload)
        commit = json.loads(json.dumps(values["commit"]))
        commit["global_predecessor"]["event_sha256"] = semantic["event_sha256"]
        commit["transaction"]["response_sha256"] = response_sha
        commit["payload_ref"]["sha256"] = commit_payload_sha
        commit["event_sha256"] = event_digest(commit)
        replacement_roles = {
            TASK_STATE_SCHEMA_ID: BlobRecord(state_sha, TASK_STATE_SCHEMA_ID, canonical_json(state)),
        }
        old_response_sha = blob_digest(values["initialize_response"])
        old_commit_payload_sha = blob_digest(values["commit_payload"])
        blobs = tuple(
            record for record in image.blobs
            if record.sha256 not in {old_response_sha, old_commit_payload_sha, blob_digest(values["initialize_state"])}
        ) + (
            BlobRecord(response_sha, RESPONSE_SCHEMA_ID, canonical_json(response)),
            BlobRecord(commit_payload_sha, PAYLOAD_SCHEMA_ID, canonical_json(commit_payload)),
            replacement_roles[TASK_STATE_SCHEMA_ID],
        )
        report = reduce_initial_runtime_image(replace(
            image,
            blobs=tuple(sorted(blobs, key=lambda record: record.sha256)),
            events=(image.events[0], canonical_json(semantic), canonical_json(commit)),
        ))
        self.assertEqual(report.status, "INVALID")
        self.assertIn("GROUP_STATE_DERIVATION", self.codes(report))

    def test_initialize_reachability_and_tables_are_exact(self):
        image, values = initialize_fixture()
        # Use a valid but unreachable task-state blob.
        extra = json.loads(json.dumps(values["initialize_state"]))
        extra["task_id"] = "unreachable-task"
        record = BlobRecord(blob_digest(extra), TASK_STATE_SCHEMA_ID, canonical_json(extra))
        report = reduce_initial_runtime_image(replace(
            image,
            blobs=tuple(sorted(image.blobs + (record,), key=lambda item: item.sha256)),
        ))
        self.assertEqual(report.status, "INVALID")
        self.assertIn("BLOB_REACHABILITY", self.codes(report))

        snapshots = list(image.table_snapshots)
        index = TABLE_NAMES.index("tasks")
        row = list(snapshots[index].rows[0])
        row[13] = "forged-owner"
        snapshots[index] = TableSnapshot("tasks", (tuple(row),))
        report = reduce_initial_runtime_image(replace(
            image, table_snapshots=tuple(snapshots),
        ))
        self.assertEqual(report.status, "INVALID")
        self.assertIn("TABLE_DERIVATION", self.codes(report))

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
        for name in (
            "runtime_v2_genesis.py", "runtime_v2_group.py",
            "runtime_v2_initial.py",
        ):
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
