"""Focused adversarial tests for the private NEW initial-image reducer."""
import ast
import json
import unittest
from dataclasses import replace
from pathlib import Path

import src.edgelab.runtime_v2_initial as initial_module

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
    blob_by_digest = {record.sha256: record for record in image.blobs}
    for addition in additions:
        blob_by_digest.setdefault(addition.sha256, addition)
    blobs = tuple(sorted(blob_by_digest.values(), key=lambda record: record.sha256))
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
        "subject": {
            "task_id": task_id,
            "attempt": before_state["attempt"],
        },
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
            "attempt": after_state["attempt"],
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
    blob_by_digest = {record.sha256: record for record in image.blobs}
    for addition in additions:
        blob_by_digest.setdefault(addition.sha256, addition)
    blobs = tuple(sorted(blob_by_digest.values(), key=lambda record: record.sha256))
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


def _append_special_group(
    image,
    values,
    *,
    prefix,
    before_state_key,
    operation,
    event_type,
    semantic_id,
    commit_id,
    transaction_id,
    arguments,
    after_state,
    payload_data,
    generated_refs,
    opens_attempt=False,
    new_claim_row=None,
):
    """Append a CLAIM or RETRY fixture without trusting materialized rows."""
    before_state = values[before_state_key]
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
        "subject": {
            "task_id": task_id,
            "attempt": before_state["attempt"],
        },
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
            "attempt": after_state["attempt"],
            "state_ref": {
                "schema_id": TASK_STATE_SCHEMA_ID,
                "sha256": after_sha,
            },
        }],
        "generated_refs": generated_refs,
    }
    semantic_payload = {
        "schema_version": 1,
        "payload_format_version": 2,
        "event_type": event_type,
        "data": payload_data,
    }
    request_sha = blob_digest(request)
    response_sha = blob_digest(response)
    payload_sha = blob_digest(semantic_payload)
    prior_events = tuple(json.loads(raw) for raw in image.events)
    prior = prior_events[-1]
    semantic_index = len(prior_events)
    if opens_attempt:
        context_attempt = after_state["attempt"]
        task_sequence = 1
        predecessor_id, predecessor_sha = task_predecessor(
            CHAIN_ID, task_id, context_attempt
        )
    else:
        context_attempt = before_state["attempt"]
        prior_task_events = tuple(
            event for event in prior_events
            if event["stream"] == "TASK"
            and event["task_context"]["task_id"] == task_id
            and event["task_context"]["attempt"] == context_attempt
        )
        prior_task = prior_task_events[-1]
        task_sequence = prior_task["task_context"]["task_sequence"] + 1
        predecessor_id = prior_task["event_id"]
        predecessor_sha = prior_task["event_sha256"]
    semantic = {
        "schema_version": 1,
        "event_format_version": 2,
        "runtime_id": RUNTIME_ID,
        "chain_id": CHAIN_ID,
        "event_id": semantic_id,
        "event_type": event_type,
        "occurred_at": CREATED_AT,
        "global_sequence": semantic_index,
        "global_predecessor": {
            "event_id": prior["event_id"],
            "event_sha256": prior["event_sha256"],
        },
        "stream": "TASK",
        "task_context": {
            "task_id": task_id,
            "attempt": context_attempt,
            "task_sequence": task_sequence,
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
            "semantic_event_ids": [semantic_id],
            "pre_command_head": {
                "global_sequence": prior["global_sequence"],
                "event_id": prior["event_id"],
                "event_sha256": prior["event_sha256"],
            },
            "post_semantic_head": {
                "global_sequence": semantic_index,
                "event_id": semantic_id,
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
        "event_id": commit_id,
        "event_type": "COMMAND_COMMITTED",
        "occurred_at": CREATED_AT,
        "global_sequence": semantic_index + 1,
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
    blob_by_digest = {record.sha256: record for record in image.blobs}
    for addition in additions:
        blob_by_digest.setdefault(addition.sha256, addition)
    blobs = tuple(sorted(blob_by_digest.values(), key=lambda record: record.sha256))
    rows = {snapshot.table: snapshot.rows for snapshot in image.table_snapshots}
    rows["blobs"] = tuple(
        (record.sha256, record.schema_id, record.canonical_json.decode("ascii"))
        for record in blobs
    )
    rows["events"] = rows["events"] + (
        (
            semantic_index, semantic_id, semantic["event_sha256"],
            canonical_json(semantic).decode("ascii"),
        ),
        (
            semantic_index + 1, commit_id, commit["event_sha256"],
            canonical_json(commit).decode("ascii"),
        ),
    )
    attempt_rows = list(rows["attempts"])
    if opens_attempt:
        attempt_rows.append((
            task_id, context_attempt, before_state["attempt"], semantic_id,
            1, semantic_id, semantic["event_sha256"],
        ))
    else:
        attempt_index = next(
            index for index, row in enumerate(attempt_rows)
            if row[:2] == (task_id, context_attempt)
        )
        attempt = list(attempt_rows[attempt_index])
        attempt[4:] = [task_sequence, semantic_id, semantic["event_sha256"]]
        attempt_rows[attempt_index] = tuple(attempt)
    rows["attempts"] = tuple(sorted(attempt_rows, key=lambda row: row[:2]))
    if new_claim_row is not None:
        rows["claims"] = tuple(sorted(rows["claims"] + (new_claim_row,)))
    idempotency = (
        operation_key, transaction_id, request_sha, response_sha,
        commit_id, semantic_index + 1, CREATED_AT,
    )
    rows["idempotency"] = tuple(sorted(rows["idempotency"] + (idempotency,)))
    metadata = list(rows["metadata"][0])
    metadata[15:18] = [semantic_index + 1, commit_id, commit["event_sha256"]]
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


def _append_claim_fixture(
    image, values, *, before_state_key, prefix, semantic_id, commit_id,
    transaction_id, claim_id, actor="worker-b",
):
    before_state = values[before_state_key]
    after_state = json.loads(json.dumps(before_state))
    after_state.update({
        "execution": "CLAIMED",
        "scheduler_generation": before_state["scheduler_generation"] + 1,
        "dispatch_generation": before_state["dispatch_generation"] + 1,
        "task_fence": before_state["task_fence"] + 1,
        "active_claim_id": claim_id,
    })
    new_claim_row = (
        claim_id, before_state["task_id"], before_state["attempt"],
        after_state["task_fence"], "OPEN", actor, semantic_id, None,
    )
    return _append_special_group(
        image,
        values,
        prefix=prefix,
        before_state_key=before_state_key,
        operation="CLAIM",
        event_type="CLAIM_ISSUED",
        semantic_id=semantic_id,
        commit_id=commit_id,
        transaction_id=transaction_id,
        arguments={"actor": actor},
        after_state=after_state,
        payload_data={"claim_id": claim_id},
        generated_refs=[{
            "kind": "CLAIM", "identifier": claim_id, "sha256": None,
        }],
        new_claim_row=new_claim_row,
    )


def _append_retry_fixture(
    image, values, *, before_state_key, prefix, semantic_id, commit_id,
    transaction_id,
):
    before_state = values[before_state_key]
    after_state = json.loads(json.dumps(before_state))
    after_state.update({
        "attempt": before_state["attempt"] + 1,
        "execution": "CLAIMABLE",
        "scheduler_generation": before_state["scheduler_generation"] + 1,
        "dispatch_generation": before_state["dispatch_generation"] + 1,
        "task_fence": before_state["task_fence"] + 1,
        "active_claim_id": None,
        "reviewer_assignment_id": None,
        "continuation_count": 0,
    })
    return _append_special_group(
        image,
        values,
        prefix=prefix,
        before_state_key=before_state_key,
        operation="RETRY",
        event_type="TASK_RETRIED",
        semantic_id=semantic_id,
        commit_id=commit_id,
        transaction_id=transaction_id,
        arguments={
            "retry_evidence_sha256": "2" * 64,
            "retryable": True,
        },
        after_state=after_state,
        payload_data={},
        generated_refs=[],
        opens_attempt=True,
    )


def _task_table_row(state):
    return tuple(state[name] for name in (
        "task_id", "attempt", "workflow", "execution", "review",
        "scheduler_generation", "dispatch_generation", "task_fence",
        "active_claim_id", "reviewer_assignment_id", "continuation_count",
        "repository_generation", "decision_receipt_digest", "owner",
        "owner_role", "reviewer", "predecessor_task", "successor_task",
    ))


def _worker_fixture(image, values, fixture_operation):
    profiles = {
        "START": {
            "operation": "START",
            "prefix": "start",
            "before_state": "claim_after_state",
            "semantic_id": "123e4567-e89b-42d3-a456-426614174010",
            "commit_id": "123e4567-e89b-42d3-a456-426614174011",
            "transaction_id": "123e4567-e89b-42d3-a456-426614174012",
            "event_type": "TASK_STARTED",
        },
        "YIELD": {
            "operation": "YIELD",
            "prefix": "yield",
            "before_state": "start_after_state",
            "semantic_id": "123e4567-e89b-42d3-a456-426614174013",
            "commit_id": "123e4567-e89b-42d3-a456-426614174014",
            "transaction_id": "123e4567-e89b-42d3-a456-426614174015",
            "event_type": "TASK_YIELDED",
        },
        "CONTINUE": {
            "operation": "CONTINUE",
            "prefix": "continue",
            "before_state": "start_after_state",
            "semantic_id": "123e4567-e89b-42d3-a456-426614174016",
            "commit_id": "123e4567-e89b-42d3-a456-426614174017",
            "transaction_id": "123e4567-e89b-42d3-a456-426614174018",
            "event_type": "TASK_CONTINUED",
        },
        "CLAIM_FAIL": {
            "operation": "FAIL",
            "prefix": "claim_fail",
            "before_state": "claim_after_state",
            "semantic_id": "123e4567-e89b-42d3-a456-426614174019",
            "commit_id": "123e4567-e89b-42d3-a456-426614174020",
            "transaction_id": "123e4567-e89b-42d3-a456-426614174021",
            "event_type": "TASK_FAILED",
        },
        "FAIL": {
            "operation": "FAIL",
            "prefix": "fail",
            "before_state": "start_after_state",
            "semantic_id": "123e4567-e89b-42d3-a456-426614174022",
            "commit_id": "123e4567-e89b-42d3-a456-426614174023",
            "transaction_id": "123e4567-e89b-42d3-a456-426614174024",
            "event_type": "TASK_FAILED",
        },
        "COMPLETE_REVIEW": {
            "operation": "COMPLETE",
            "prefix": "complete_review",
            "before_state": "start_after_state",
            "close": False,
            "semantic_id": "123e4567-e89b-42d3-a456-426614174025",
            "commit_id": "123e4567-e89b-42d3-a456-426614174026",
            "transaction_id": "123e4567-e89b-42d3-a456-426614174027",
            "event_type": "TASK_COMPLETED",
        },
        "COMPLETE_CLOSE": {
            "operation": "COMPLETE",
            "prefix": "complete_close",
            "before_state": "start_after_state",
            "close": True,
            "semantic_id": "123e4567-e89b-42d3-a456-426614174028",
            "commit_id": "123e4567-e89b-42d3-a456-426614174029",
            "transaction_id": "123e4567-e89b-42d3-a456-426614174030",
            "event_type": "TASK_COMPLETED",
        },
        "CONTINUE_FAIL": {
            "operation": "FAIL",
            "prefix": "continue_fail",
            "before_state": "continue_after_state",
            "semantic_id": "123e4567-e89b-42d3-a456-426614174031",
            "commit_id": "123e4567-e89b-42d3-a456-426614174032",
            "transaction_id": "123e4567-e89b-42d3-a456-426614174033",
            "event_type": "TASK_FAILED",
        },
        "CONTINUE_COMPLETE_REVIEW": {
            "operation": "COMPLETE",
            "prefix": "continue_complete_review",
            "before_state": "continue_after_state",
            "close": False,
            "semantic_id": "123e4567-e89b-42d3-a456-426614174034",
            "commit_id": "123e4567-e89b-42d3-a456-426614174035",
            "transaction_id": "123e4567-e89b-42d3-a456-426614174036",
            "event_type": "TASK_COMPLETED",
        },
        "CLAIM_COMPLETE_REVIEW": {
            "operation": "COMPLETE",
            "prefix": "claim_complete_review",
            "before_state": "claim_after_state",
            "close": False,
            "semantic_id": "123e4567-e89b-42d3-a456-426614174037",
            "commit_id": "123e4567-e89b-42d3-a456-426614174038",
            "transaction_id": "123e4567-e89b-42d3-a456-426614174039",
            "event_type": "TASK_COMPLETED",
        },
        "CONTINUE_COMPLETE_CLOSE": {
            "operation": "COMPLETE",
            "prefix": "continue_complete_close",
            "before_state": "continue_after_state",
            "close": True,
            "semantic_id": "123e4567-e89b-42d3-a456-426614174040",
            "commit_id": "123e4567-e89b-42d3-a456-426614174041",
            "transaction_id": "123e4567-e89b-42d3-a456-426614174042",
            "event_type": "TASK_COMPLETED",
        },
        "RECOVER": {
            "operation": "RECOVER",
            "prefix": "recover",
            "before_state": "claim_after_state",
            "semantic_id": "123e4567-e89b-42d3-a456-426614174043",
            "commit_id": "123e4567-e89b-42d3-a456-426614174044",
            "transaction_id": "123e4567-e89b-42d3-a456-426614174045",
            "event_type": "CLAIM_RECOVERED",
        },
        "RECOVER_STARTED": {
            "operation": "RECOVER",
            "prefix": "recover_started",
            "before_state": "start_after_state",
            "semantic_id": "123e4567-e89b-42d3-a456-426614174046",
            "commit_id": "123e4567-e89b-42d3-a456-426614174047",
            "transaction_id": "123e4567-e89b-42d3-a456-426614174048",
            "event_type": "CLAIM_RECOVERED",
        },
        "CONTINUE_AGAIN": {
            "operation": "CONTINUE",
            "prefix": "continue_again",
            "before_state": "continue_after_state",
            "semantic_id": "123e4567-e89b-42d3-a456-426614174049",
            "commit_id": "123e4567-e89b-42d3-a456-426614174050",
            "transaction_id": "123e4567-e89b-42d3-a456-426614174051",
            "event_type": "TASK_CONTINUED",
        },
        "CONTINUE_THIRD": {
            "operation": "CONTINUE",
            "prefix": "continue_third",
            "before_state": "continue_again_after_state",
            "semantic_id": "123e4567-e89b-42d3-a456-426614174052",
            "commit_id": "123e4567-e89b-42d3-a456-426614174053",
            "transaction_id": "123e4567-e89b-42d3-a456-426614174054",
            "event_type": "TASK_CONTINUED",
        },
    }
    profile = (
        fixture_operation
        if type(fixture_operation) is dict
        else profiles[fixture_operation]
    )
    operation = profile["operation"]
    prefix = profile["prefix"]
    before_state = values[profile["before_state"]]
    after_state = json.loads(json.dumps(before_state))
    after_state["scheduler_generation"] += 1
    claim_id = before_state["active_claim_id"]
    if operation == "START":
        after_state["execution"] = "IN_PROGRESS"
        arguments = {"claim_id": claim_id, "fence": before_state["task_fence"]}
    elif operation == "CONTINUE":
        after_state["continuation_count"] += 1
        arguments = {
            "claim_id": claim_id,
            "fence": before_state["task_fence"],
            "progress_evidence_sha256": "7" * 64,
        }
    elif operation == "YIELD":
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
    elif operation == "FAIL":
        after_state.update({
            "execution": "FAILED",
            "dispatch_generation": before_state["dispatch_generation"] + 1,
            "task_fence": before_state["task_fence"] + 1,
            "active_claim_id": None,
        })
        arguments = {
            "claim_id": claim_id,
            "fence": before_state["task_fence"],
            "failure_code": "WORKER_ERROR",
            "failure_evidence_sha256": "5" * 64,
        }
    elif operation == "COMPLETE":
        close = profile["close"]
        after_state.update({
            "workflow": "CLOSED" if close else "ACTIVE",
            "execution": "EXECUTION_COMPLETED",
            "review": "NOT_REQUIRED" if close else "REVIEW_PENDING",
            "dispatch_generation": before_state["dispatch_generation"] + 1,
            "task_fence": before_state["task_fence"] + 1,
            "active_claim_id": None,
        })
        arguments = {
            "claim_id": claim_id,
            "fence": before_state["task_fence"],
            "close": close,
            "completion_evidence_sha256": "4" * 64,
        }
    else:
        after_state.update({
            "execution": "CLAIMABLE",
            "dispatch_generation": before_state["dispatch_generation"] + 1,
            "task_fence": before_state["task_fence"] + 1,
            "active_claim_id": None,
        })
        arguments = {
            "claim_id": claim_id,
            "liveness_evidence_sha256": "3" * 64,
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
        "subject": {
            "task_id": task_id,
            "attempt": before_state["attempt"],
        },
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
            "attempt": after_state["attempt"],
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
        event for event in prior_events
        if event["stream"] == "TASK"
        and event["task_context"]["task_id"] == task_id
        and event["task_context"]["attempt"] == before_state["attempt"]
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
            "attempt": before_state["attempt"],
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
    blob_by_digest = {record.sha256: record for record in image.blobs}
    for addition in additions:
        blob_by_digest.setdefault(addition.sha256, addition)
    blobs = tuple(sorted(blob_by_digest.values(), key=lambda record: record.sha256))
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
    attempt_rows = list(rows["attempts"])
    attempt_index = next(
        index for index, row in enumerate(attempt_rows)
        if row[:2] == (task_id, before_state["attempt"])
    )
    attempt = list(attempt_rows[attempt_index])
    attempt[4:] = [task_sequence, semantic["event_id"], semantic["event_sha256"]]
    attempt_rows[attempt_index] = tuple(attempt)
    rows["attempts"] = tuple(attempt_rows)
    claim_status = {
        "YIELD": "YIELDED",
        "FAIL": "FAILED",
        "COMPLETE": "COMPLETED",
        "RECOVER": "RECOVERED",
    }.get(operation)
    if claim_status is not None:
        claim_rows = list(rows["claims"])
        claim_index = next(
            index for index, row in enumerate(claim_rows)
            if row[0] == claim_id
        )
        claim = list(claim_rows[claim_index])
        claim[4] = claim_status
        claim[7] = semantic["event_id"]
        claim_rows[claim_index] = tuple(claim)
        rows["claims"] = tuple(claim_rows)
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


def continue_fixture():
    image, values = start_fixture()
    return _worker_fixture(image, values, "CONTINUE")


def claim_fail_fixture():
    image, values = claim_fixture()
    return _worker_fixture(image, values, "CLAIM_FAIL")


def fail_fixture():
    image, values = start_fixture()
    return _worker_fixture(image, values, "FAIL")


def complete_review_fixture():
    image, values = start_fixture()
    return _worker_fixture(image, values, "COMPLETE_REVIEW")


def complete_close_fixture():
    image, values = start_fixture()
    return _worker_fixture(image, values, "COMPLETE_CLOSE")


def continue_fail_fixture():
    image, values = continue_fixture()
    return _worker_fixture(image, values, "CONTINUE_FAIL")


def continue_complete_review_fixture():
    image, values = continue_fixture()
    return _worker_fixture(image, values, "CONTINUE_COMPLETE_REVIEW")


def claim_complete_review_fixture():
    image, values = claim_fixture()
    return _worker_fixture(image, values, "CLAIM_COMPLETE_REVIEW")


def continue_complete_close_fixture():
    image, values = continue_fixture()
    return _worker_fixture(image, values, "CONTINUE_COMPLETE_CLOSE")


def recover_fixture():
    image, values = claim_fixture()
    return _worker_fixture(image, values, "RECOVER")


def recover_started_fixture():
    image, values = start_fixture()
    return _worker_fixture(image, values, "RECOVER_STARTED")


def recover_reclaim_start_fixture():
    image, values = recover_fixture()
    image, values = _append_claim_fixture(
        image,
        values,
        before_state_key="recover_after_state",
        prefix="recover-reclaim",
        semantic_id="123e4567-e89b-42d3-a456-426614174060",
        commit_id="123e4567-e89b-42d3-a456-426614174061",
        transaction_id="123e4567-e89b-42d3-a456-426614174062",
        claim_id="123e4567-e89b-42d3-a456-426614174063",
    )
    return _worker_fixture(image, values, {
        "operation": "START",
        "prefix": "recover_reclaim_start",
        "before_state": "recover-reclaim_after_state",
        "semantic_id": "123e4567-e89b-42d3-a456-426614174064",
        "commit_id": "123e4567-e89b-42d3-a456-426614174065",
        "transaction_id": "123e4567-e89b-42d3-a456-426614174066",
        "event_type": "TASK_STARTED",
    })


def yield_reclaim_fixture():
    image, values = yield_fixture()
    return _append_claim_fixture(
        image,
        values,
        before_state_key="yield_after_state",
        prefix="yield-reclaim",
        semantic_id="123e4567-e89b-42d3-a456-426614174067",
        commit_id="123e4567-e89b-42d3-a456-426614174068",
        transaction_id="123e4567-e89b-42d3-a456-426614174069",
        claim_id="123e4567-e89b-42d3-a456-426614174070",
    )


def fail_retry_reclaim_start_fixture():
    image, values = fail_fixture()
    image, values = _append_retry_fixture(
        image,
        values,
        before_state_key="fail_after_state",
        prefix="retry-attempt-2",
        semantic_id="123e4567-e89b-42d3-a456-426614174071",
        commit_id="123e4567-e89b-42d3-a456-426614174072",
        transaction_id="123e4567-e89b-42d3-a456-426614174073",
    )
    image, values = _append_claim_fixture(
        image,
        values,
        before_state_key="retry-attempt-2_after_state",
        prefix="claim-attempt-2",
        semantic_id="123e4567-e89b-42d3-a456-426614174074",
        commit_id="123e4567-e89b-42d3-a456-426614174075",
        transaction_id="123e4567-e89b-42d3-a456-426614174076",
        claim_id="123e4567-e89b-42d3-a456-426614174077",
    )
    return _worker_fixture(image, values, {
        "operation": "START",
        "prefix": "start_attempt_2",
        "before_state": "claim-attempt-2_after_state",
        "semantic_id": "123e4567-e89b-42d3-a456-426614174078",
        "commit_id": "123e4567-e89b-42d3-a456-426614174079",
        "transaction_id": "123e4567-e89b-42d3-a456-426614174080",
        "event_type": "TASK_STARTED",
    })


def two_retry_cycles_fixture():
    image, values = fail_retry_reclaim_start_fixture()
    image, values = _worker_fixture(image, values, {
        "operation": "FAIL",
        "prefix": "fail_attempt_2",
        "before_state": "start_attempt_2_after_state",
        "semantic_id": "123e4567-e89b-42d3-a456-426614174081",
        "commit_id": "123e4567-e89b-42d3-a456-426614174082",
        "transaction_id": "123e4567-e89b-42d3-a456-426614174083",
        "event_type": "TASK_FAILED",
    })
    image, values = _append_retry_fixture(
        image,
        values,
        before_state_key="fail_attempt_2_after_state",
        prefix="retry-attempt-3",
        semantic_id="123e4567-e89b-42d3-a456-426614174084",
        commit_id="123e4567-e89b-42d3-a456-426614174085",
        transaction_id="123e4567-e89b-42d3-a456-426614174086",
    )
    return _append_claim_fixture(
        image,
        values,
        before_state_key="retry-attempt-3_after_state",
        prefix="claim-attempt-3",
        semantic_id="123e4567-e89b-42d3-a456-426614174087",
        commit_id="123e4567-e89b-42d3-a456-426614174088",
        transaction_id="123e4567-e89b-42d3-a456-426614174089",
        claim_id="123e4567-e89b-42d3-a456-426614174090",
    )


def _rehash_semantic_context(image, values, prefix, mutate):
    """Rehash a final semantic pair so context attacks reach group semantics."""
    semantic = json.loads(json.dumps(values[f"{prefix}_semantic"]))
    commit_payload = json.loads(json.dumps(values[f"{prefix}_commit_payload"]))
    commit = json.loads(json.dumps(values[f"{prefix}_commit"]))
    mutate(semantic["task_context"])
    semantic["event_sha256"] = event_digest(semantic)
    commit_payload["data"]["post_semantic_head"]["event_sha256"] = (
        semantic["event_sha256"]
    )
    commit_payload_sha = blob_digest(commit_payload)
    commit["global_predecessor"]["event_sha256"] = semantic["event_sha256"]
    commit["payload_ref"]["sha256"] = commit_payload_sha
    commit["event_sha256"] = event_digest(commit)
    old_commit_payload_sha = blob_digest(values[f"{prefix}_commit_payload"])
    blob_by_digest = {
        record.sha256: record for record in image.blobs
        if record.sha256 != old_commit_payload_sha
    }
    blob_by_digest[commit_payload_sha] = BlobRecord(
        commit_payload_sha,
        PAYLOAD_SCHEMA_ID,
        canonical_json(commit_payload),
    )
    return replace(
        image,
        blobs=tuple(sorted(blob_by_digest.values(), key=lambda record: record.sha256)),
        events=image.events[:-2] + (
            canonical_json(semantic), canonical_json(commit),
        ),
    )


def _rehash_group_request(image, values, prefix, mutate):
    """Rehash request and dependent pair bindings for exact argument attacks."""
    request = json.loads(json.dumps(values[f"{prefix}_request"]))
    semantic = json.loads(json.dumps(values[f"{prefix}_semantic"]))
    commit_payload = json.loads(json.dumps(values[f"{prefix}_commit_payload"]))
    commit = json.loads(json.dumps(values[f"{prefix}_commit"]))
    mutate(request)
    request_sha = blob_digest(request)
    semantic["transaction"]["request_sha256"] = request_sha
    semantic["event_sha256"] = event_digest(semantic)
    commit_payload["data"]["request_ref"]["sha256"] = request_sha
    commit_payload["data"]["post_semantic_head"]["event_sha256"] = (
        semantic["event_sha256"]
    )
    commit_payload_sha = blob_digest(commit_payload)
    commit["transaction"]["request_sha256"] = request_sha
    commit["global_predecessor"]["event_sha256"] = semantic["event_sha256"]
    commit["payload_ref"]["sha256"] = commit_payload_sha
    commit["event_sha256"] = event_digest(commit)
    removed = {
        blob_digest(values[f"{prefix}_request"]),
        blob_digest(values[f"{prefix}_commit_payload"]),
    }
    blob_by_digest = {
        record.sha256: record for record in image.blobs
        if record.sha256 not in removed
    }
    for record in (
        BlobRecord(request_sha, REQUEST_SCHEMA_ID, canonical_json(request)),
        BlobRecord(
            commit_payload_sha, PAYLOAD_SCHEMA_ID, canonical_json(commit_payload)
        ),
    ):
        blob_by_digest[record.sha256] = record
    return replace(
        image,
        blobs=tuple(sorted(blob_by_digest.values(), key=lambda record: record.sha256)),
        events=image.events[:-2] + (
            canonical_json(semantic), canonical_json(commit),
        ),
    )


def continue_twice_fixture():
    image, values = continue_fixture()
    return _worker_fixture(image, values, "CONTINUE_AGAIN")


def continue_thrice_fixture():
    image, values = continue_twice_fixture()
    return _worker_fixture(image, values, "CONTINUE_THIRD")


def continue_many_fixture(count):
    image, values = start_fixture()
    before_state = "start_after_state"
    for index in range(count):
        prefix = f"continue_many_{index}"
        base = 100 + index * 3
        image, values = _worker_fixture(image, values, {
            "operation": "CONTINUE",
            "prefix": prefix,
            "before_state": before_state,
            "semantic_id": (
                f"123e4567-e89b-42d3-a456-{base:012d}"
            ),
            "commit_id": (
                f"123e4567-e89b-42d3-a456-{base + 1:012d}"
            ),
            "transaction_id": (
                f"123e4567-e89b-42d3-a456-{base + 2:012d}"
            ),
            "event_type": "TASK_CONTINUED",
        })
        before_state = f"{prefix}_after_state"
    return image, values


def _replace_worker_request(image, values, prefix, request):
    request_sha = blob_digest(request)
    semantic = json.loads(json.dumps(values[f"{prefix}_semantic"]))
    semantic["transaction"]["request_sha256"] = request_sha
    semantic["event_sha256"] = event_digest(semantic)
    commit_payload = json.loads(json.dumps(values[f"{prefix}_commit_payload"]))
    commit_payload["data"]["request_ref"]["sha256"] = request_sha
    commit_payload["data"]["post_semantic_head"]["event_sha256"] = (
        semantic["event_sha256"]
    )
    commit_payload_sha = blob_digest(commit_payload)
    commit = json.loads(json.dumps(values[f"{prefix}_commit"]))
    commit["transaction"]["request_sha256"] = request_sha
    commit["global_predecessor"]["event_sha256"] = semantic["event_sha256"]
    commit["payload_ref"]["sha256"] = commit_payload_sha
    commit["event_sha256"] = event_digest(commit)
    removed = {
        blob_digest(values[f"{prefix}_request"]),
        blob_digest(values[f"{prefix}_commit_payload"]),
    }
    blobs = tuple(
        record for record in image.blobs if record.sha256 not in removed
    ) + (
        BlobRecord(request_sha, REQUEST_SCHEMA_ID, canonical_json(request)),
        BlobRecord(
            commit_payload_sha,
            PAYLOAD_SCHEMA_ID,
            canonical_json(commit_payload),
        ),
    )
    return replace(
        image,
        blobs=tuple(sorted(blobs, key=lambda record: record.sha256)),
        events=image.events[:-2] + (
            canonical_json(semantic), canonical_json(commit),
        ),
    )


def _replace_worker_after_state(image, values, prefix, state):
    state_sha = blob_digest(state)
    response = json.loads(json.dumps(values[f"{prefix}_response"]))
    response["affected_states"][0]["state_ref"]["sha256"] = state_sha
    response_sha = blob_digest(response)
    semantic = json.loads(json.dumps(values[f"{prefix}_semantic"]))
    semantic["state_after_ref"]["sha256"] = state_sha
    semantic["transaction"]["response_sha256"] = response_sha
    semantic["event_sha256"] = event_digest(semantic)
    commit_payload = json.loads(json.dumps(values[f"{prefix}_commit_payload"]))
    commit_payload["data"]["response_ref"]["sha256"] = response_sha
    commit_payload["data"]["post_semantic_head"]["event_sha256"] = (
        semantic["event_sha256"]
    )
    commit_payload_sha = blob_digest(commit_payload)
    commit = json.loads(json.dumps(values[f"{prefix}_commit"]))
    commit["transaction"]["response_sha256"] = response_sha
    commit["global_predecessor"]["event_sha256"] = semantic["event_sha256"]
    commit["payload_ref"]["sha256"] = commit_payload_sha
    commit["event_sha256"] = event_digest(commit)
    removed = {
        blob_digest(values[f"{prefix}_response"]),
        blob_digest(values[f"{prefix}_commit_payload"]),
        blob_digest(values[f"{prefix}_after_state"]),
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
    return replace(
        image,
        blobs=tuple(sorted(blobs, key=lambda record: record.sha256)),
        events=image.events[:-2] + (
            canonical_json(semantic), canonical_json(commit),
        ),
    )


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

    def test_worker_groups_reduce_end_to_end_but_remain_opaque(self):
        for name, build in (
            ("start", start_fixture),
            ("continue", continue_fixture),
            ("yield", yield_fixture),
            ("claim_fail", claim_fail_fixture),
            ("fail", fail_fixture),
            ("complete_review", complete_review_fixture),
            ("complete_close", complete_close_fixture),
            ("continue_fail", continue_fail_fixture),
            ("continue_complete_review", continue_complete_review_fixture),
            ("continue_complete_close", continue_complete_close_fixture),
            ("recover", recover_fixture),
            ("continue_thrice", continue_thrice_fixture),
        ):
            with self.subTest(group=name):
                image, _ = build()
                report = reduce_initial_runtime_image(image)
                self.assertEqual(report.status, "UNSUPPORTED")
                self.assertEqual(self.codes(report), {"CLOSURE_NOT_COMPILED"})
                self.assertEqual(report.authorizing_use, "DENY")

    def test_reclaim_and_retry_cycles_reduce_cumulative_history_but_remain_opaque(self):
        for name, build in (
            ("recover_reclaim_start", recover_reclaim_start_fixture),
            ("yield_reclaim", yield_reclaim_fixture),
            ("fail_retry_reclaim_start", fail_retry_reclaim_start_fixture),
            ("two_retry_cycles", two_retry_cycles_fixture),
        ):
            with self.subTest(trace=name):
                image, values = build()
                report = reduce_initial_runtime_image(image)
                self.assertEqual(report.status, "UNSUPPORTED")
                self.assertEqual(self.codes(report), {"CLOSURE_NOT_COMPILED"})
                self.assertEqual(report.authorizing_use, "DENY")
                rows = {snapshot.table: snapshot.rows for snapshot in image.table_snapshots}
                self.assertEqual(rows["tasks"][0][1], values[
                    {
                        "recover_reclaim_start": "recover_reclaim_start_after_state",
                        "yield_reclaim": "yield-reclaim_after_state",
                        "fail_retry_reclaim_start": "start_attempt_2_after_state",
                        "two_retry_cycles": "claim-attempt-3_after_state",
                    }[name]
                ]["attempt"])

        image, values = recover_reclaim_start_fixture()
        rows = {snapshot.table: snapshot.rows for snapshot in image.table_snapshots}
        self.assertEqual(len(rows["attempts"]), 1)
        self.assertEqual([row[3] for row in rows["claims"]], [1, 3])
        self.assertEqual([row[4] for row in rows["claims"]], ["RECOVERED", "OPEN"])
        self.assertEqual(
            rows["attempts"][0][5],
            values["recover_reclaim_start_semantic"]["event_id"],
        )

        image, _ = yield_reclaim_fixture()
        rows = {snapshot.table: snapshot.rows for snapshot in image.table_snapshots}
        self.assertEqual([row[4] for row in rows["claims"]], ["YIELDED", "OPEN"])
        self.assertEqual([row[3] for row in rows["claims"]], [1, 3])

        image, values = fail_retry_reclaim_start_fixture()
        rows = {snapshot.table: snapshot.rows for snapshot in image.table_snapshots}
        self.assertEqual(len(rows["attempts"]), 2)
        self.assertEqual(
            rows["attempts"][0][5], values["fail_semantic"]["event_id"]
        )
        self.assertEqual(rows["attempts"][1][2], 1)
        self.assertEqual(
            rows["attempts"][1][3],
            values["retry-attempt-2_semantic"]["event_id"],
        )
        self.assertEqual(rows["attempts"][1][4], 3)
        self.assertEqual([row[2] for row in rows["claims"]], [1, 2])
        self.assertEqual([row[4] for row in rows["claims"]], ["FAILED", "OPEN"])

        image, values = two_retry_cycles_fixture()
        rows = {snapshot.table: snapshot.rows for snapshot in image.table_snapshots}
        self.assertEqual([row[1] for row in rows["attempts"]], [1, 2, 3])
        self.assertEqual([row[2] for row in rows["attempts"]], [None, 1, 2])
        self.assertEqual(
            [row[5] for row in rows["attempts"]],
            [
                values["fail_semantic"]["event_id"],
                values["fail_attempt_2_semantic"]["event_id"],
                values["claim-attempt-3_semantic"]["event_id"],
            ],
        )
        self.assertEqual([row[2] for row in rows["claims"]], [1, 2, 3])
        self.assertEqual(
            [row[4] for row in rows["claims"]],
            ["FAILED", "FAILED", "OPEN"],
        )

    def test_retry_attempt_boundary_and_task_root_are_exact(self):
        image, values = fail_fixture()
        retry_image, retry_values = _append_retry_fixture(
            image,
            values,
            before_state_key="fail_after_state",
            prefix="retry-boundary",
            semantic_id="123e4567-e89b-42d3-a456-426614174091",
            commit_id="123e4567-e89b-42d3-a456-426614174092",
            transaction_id="123e4567-e89b-42d3-a456-426614174093",
        )
        for name, mutate in (
            ("old_attempt", lambda context: context.update(attempt=1)),
            ("skipped_attempt", lambda context: context.update(attempt=3)),
            ("wrong_sequence", lambda context: context.update(task_sequence=2)),
            (
                "old_failure_predecessor",
                lambda context: context.update(task_predecessor={
                    "event_id": retry_values["fail_semantic"]["event_id"],
                    "event_sha256": retry_values["fail_semantic"]["event_sha256"],
                }),
            ),
            (
                "wrong_attempt_root",
                lambda context: context.update(task_predecessor=dict(zip(
                    ("event_id", "event_sha256"),
                    task_predecessor(CHAIN_ID, context["task_id"], 1),
                ))),
            ),
        ):
            attacked = _rehash_semantic_context(
                retry_image, retry_values, "retry-boundary", mutate
            )
            with self.subTest(attack=name):
                report = reduce_initial_runtime_image(attacked)
                self.assertEqual(report.status, "INVALID")
                self.assertTrue(
                    {"GROUP_CONST", "GROUP_ATTEMPT_ROOT"} & self.codes(report)
                )

        for name, mutate, expected in (
            (
                "wrong_subject_attempt",
                lambda request: request["subject"].update(attempt=2),
                "GROUP_CONST",
            ),
            (
                "retryable_false",
                lambda request: request["arguments"].update(retryable=False),
                "TRANSITION_RETRYABLE",
            ),
            (
                "retryable_integer_alias",
                lambda request: request["arguments"].update(retryable=1),
                "TRANSITION_RETRYABLE",
            ),
            (
                "wrong_evidence",
                lambda request: request["arguments"].update(
                    retry_evidence_sha256="not-a-digest"
                ),
                "TRANSITION_TEXT",
            ),
        ):
            attacked = _rehash_group_request(
                retry_image, retry_values, "retry-boundary", mutate
            )
            with self.subTest(request_attack=name):
                report = reduce_initial_runtime_image(attacked)
                self.assertEqual(report.status, "INVALID")
                self.assertIn(expected, self.codes(report))

    def test_retry_and_reclaim_wrong_source_states_deny(self):
        image, values = initialize_fixture()
        image, _ = _append_retry_fixture(
            image,
            values,
            before_state_key="initialize_state",
            prefix="retry-from-n0",
            semantic_id="123e4567-e89b-42d3-a456-426614174094",
            commit_id="123e4567-e89b-42d3-a456-426614174095",
            transaction_id="123e4567-e89b-42d3-a456-426614174096",
        )
        report = reduce_initial_runtime_image(image)
        self.assertEqual(report.status, "INVALID")
        self.assertIn("TRANSITION_SOURCE_STATE", self.codes(report))

        image, values = start_fixture()
        image, _ = _append_claim_fixture(
            image,
            values,
            before_state_key="start_after_state",
            prefix="reclaim-from-n2",
            semantic_id="123e4567-e89b-42d3-a456-426614174097",
            commit_id="123e4567-e89b-42d3-a456-426614174098",
            transaction_id="123e4567-e89b-42d3-a456-426614174099",
            claim_id="123e4567-e89b-42d3-a456-426614174100",
        )
        report = reduce_initial_runtime_image(image)
        self.assertEqual(report.status, "INVALID")
        self.assertIn("TRANSITION_SOURCE_STATE", self.codes(report))

    def test_cumulative_attempt_and_claim_tables_are_derived_not_trusted(self):
        image, _ = two_retry_cycles_fixture()
        baseline = {snapshot.table: snapshot for snapshot in image.table_snapshots}
        attacks = []

        attempts = list(baseline["attempts"].rows)
        attacks.append(("attempt_missing_old", "attempts", tuple(attempts[1:])))
        changed = list(attempts)
        row = list(changed[1])
        row[2] = None
        changed[1] = tuple(row)
        attacks.append(("attempt_wrong_predecessor", "attempts", tuple(changed)))
        changed = list(attempts)
        row = list(changed[0])
        row[3] = changed[1][3]
        changed[0] = tuple(row)
        attacks.append(("attempt_rewritten_origin", "attempts", tuple(changed)))
        changed = list(attempts)
        row = list(changed[0])
        row[5:7] = [changed[1][3], changed[1][6]]
        changed[0] = tuple(row)
        attacks.append(("attempt_rewritten_head", "attempts", tuple(changed)))
        attacks.append(("attempt_reordered", "attempts", tuple(reversed(attempts))))

        claims = list(baseline["claims"].rows)
        attacks.append(("claim_missing_old", "claims", tuple(claims[1:])))
        for name, column, value in (
            ("claim_wrong_attempt", 2, 3),
            ("claim_wrong_fence", 3, 99),
            ("claim_reopened", 4, "OPEN"),
            ("claim_wrong_open", 6, claims[1][6]),
            ("claim_wrong_close", 7, claims[1][7]),
        ):
            changed = list(claims)
            row = list(changed[0])
            row[column] = value
            changed[0] = tuple(row)
            attacks.append((name, "claims", tuple(changed)))
        attacks.append(("claim_reordered", "claims", tuple(reversed(claims))))

        for name, table, rows in attacks:
            snapshots = list(image.table_snapshots)
            index = TABLE_NAMES.index(table)
            snapshots[index] = TableSnapshot(table, rows)
            with self.subTest(attack=name):
                report = reduce_initial_runtime_image(replace(
                    image, table_snapshots=tuple(snapshots),
                ))
                self.assertEqual(report.status, "INVALID")
                self.assertTrue(
                    {"TABLE_DERIVATION", "TABLE_ROW_ORDER"}
                    & self.codes(report)
                )

    def test_cursor_replays_non_enumerated_worker_depth_exactly(self):
        image, values = continue_thrice_fixture()
        self.assertEqual(len(image.events), 13)
        report = reduce_initial_runtime_image(image)
        self.assertEqual(report.status, "UNSUPPORTED")
        self.assertEqual(self.codes(report), {"CLOSURE_NOT_COMPILED"})

        state = values["continue_third_after_state"]
        self.assertEqual(state["continuation_count"], 3)
        self.assertEqual(state["scheduler_generation"], 5)
        rows = {item.table: item.rows for item in image.table_snapshots}
        self.assertEqual(rows["attempts"][0][4], 6)
        self.assertEqual(rows["attempts"][0][5], values["continue_third_semantic"]["event_id"])
        self.assertEqual(len(rows["idempotency"]), 6)
        self.assertEqual(rows["tasks"][0][10], 3)

        partial = replace(image, events=image.events[:-1])
        report = reduce_initial_runtime_image(partial)
        self.assertEqual(report.status, "INVALID")
        self.assertIn("COMPILED_EVENT_CARDINALITY", self.codes(report))

        long_image, long_values = continue_many_fixture(16)
        self.assertEqual(len(long_image.events), 39)
        report = reduce_initial_runtime_image(long_image)
        self.assertEqual(report.status, "UNSUPPORTED")
        self.assertEqual(self.codes(report), {"CLOSURE_NOT_COMPILED"})
        long_rows = {
            item.table: item.rows for item in long_image.table_snapshots
        }
        self.assertEqual(long_rows["attempts"][0][4], 19)
        self.assertEqual(len(long_rows["idempotency"]), 19)
        self.assertEqual(
            long_values["continue_many_15_after_state"]["continuation_count"],
            16,
        )

    def test_image_replay_freezes_transition_workspace_once(self):
        image, _ = continue_many_fixture(16)
        original_freeze = initial_module._TransitionWorkspace.freeze
        freeze_calls = 0

        def counted_freeze(workspace):
            nonlocal freeze_calls
            freeze_calls += 1
            return original_freeze(workspace)

        initial_module._TransitionWorkspace.freeze = counted_freeze
        try:
            report = reduce_initial_runtime_image(image)
        finally:
            initial_module._TransitionWorkspace.freeze = original_freeze
        self.assertEqual(report.status, "UNSUPPORTED")
        self.assertEqual(freeze_calls, 1)

    def test_cursor_retains_early_identity_indexes_at_late_depth(self):
        image, values = continue_thrice_fixture()

        semantic = json.loads(json.dumps(values["continue_third_semantic"]))
        semantic["event_id"] = values["start_semantic"]["event_id"]
        semantic["event_sha256"] = event_digest(semantic)
        report = reduce_initial_runtime_image(replace(
            image,
            events=image.events[:-2] + (
                canonical_json(semantic), image.events[-1],
            ),
        ))
        self.assertEqual(report.status, "INVALID")
        self.assertIn("GROUP_EVENT_ID_DUPLICATE", self.codes(report))

        for field, earlier, code in (
            (
                "transaction_id",
                values["continue_semantic"]["transaction"]["transaction_id"],
                "GROUP_TRANSACTION_DUPLICATE",
            ),
            (
                "operation_key",
                values["continue_semantic"]["transaction"]["operation_key"],
                "GROUP_OPERATION_KEY_DUPLICATE",
            ),
        ):
            semantic = json.loads(json.dumps(values["continue_third_semantic"]))
            commit = json.loads(json.dumps(values["continue_third_commit"]))
            semantic["transaction"][field] = earlier
            commit["transaction"][field] = earlier
            semantic["event_sha256"] = event_digest(semantic)
            commit["event_sha256"] = event_digest(commit)
            with self.subTest(field=field):
                report = reduce_initial_runtime_image(replace(
                    image,
                    events=image.events[:-2] + (
                        canonical_json(semantic), canonical_json(commit),
                    ),
                ))
                self.assertEqual(report.status, "INVALID")
                self.assertIn(code, self.codes(report))

        for event_type in ("CLAIM_ISSUED", "TASK_RETRIED"):
            semantic = json.loads(json.dumps(values["continue_third_semantic"]))
            semantic["event_type"] = event_type
            semantic["event_sha256"] = event_digest(semantic)
            with self.subTest(mismatched_dispatched_event_type=event_type):
                report = reduce_initial_runtime_image(replace(
                    image,
                    events=image.events[:-2] + (
                        canonical_json(semantic), image.events[-1],
                    ),
                ))
                self.assertEqual(report.status, "INVALID")
                self.assertIn("GROUP_CONST", self.codes(report))

        semantic = json.loads(json.dumps(values["continue_third_semantic"]))
        semantic["event_type"] = "TASK_UNKNOWN"
        semantic["event_sha256"] = event_digest(semantic)
        report = reduce_initial_runtime_image(replace(
            image,
            events=image.events[:-2] + (
                canonical_json(semantic), image.events[-1],
            ),
        ))
        self.assertEqual(report.status, "INVALID")
        self.assertIn("GROUP_FOLLOWUP_OPERATION", self.codes(report))

        for hostile_event_type in ([], {}, None, 7):
            semantic = json.loads(json.dumps(values["continue_third_semantic"]))
            semantic["event_type"] = hostile_event_type
            with self.subTest(hostile_event_type=hostile_event_type):
                report = reduce_initial_runtime_image(replace(
                    image,
                    events=image.events[:-2] + (
                        canonical_json(semantic), image.events[-1],
                    ),
                ))
                self.assertEqual(report.status, "INVALID")
                self.assertIn("GROUP_FOLLOWUP_OPERATION", self.codes(report))

        semantic = json.loads(json.dumps(values["continue_third_semantic"]))
        semantic["task_context"]["task_sequence"] = 1
        semantic["event_sha256"] = event_digest(semantic)
        report = reduce_initial_runtime_image(replace(
            image,
            events=image.events[:-2] + (
                canonical_json(semantic), image.events[-1],
            ),
        ))
        self.assertEqual(report.status, "INVALID")
        self.assertIn("GROUP_CONST", self.codes(report))

    def test_worker_groups_enforce_claim_and_fence_cas(self):
        for name, build in (
            ("start", start_fixture),
            ("continue", continue_fixture),
            ("yield", yield_fixture),
            ("claim_fail", claim_fail_fixture),
            ("fail", fail_fixture),
            ("complete_review", complete_review_fixture),
            ("complete_close", complete_close_fixture),
            ("continue_fail", continue_fail_fixture),
            ("continue_complete_review", continue_complete_review_fixture),
            ("continue_complete_close", continue_complete_close_fixture),
        ):
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

    def test_recover_enforces_claim_cas_and_liveness_evidence(self):
        image, values = recover_fixture()
        for field, replacement_value, expected_code in (
            (
                "claim_id",
                "123e4567-e89b-42d3-a456-426614174099",
                "TRANSITION_CLAIM_CAS",
            ),
            ("liveness_evidence_sha256", "x" * 64, "TRANSITION_TEXT"),
        ):
            request = json.loads(json.dumps(values["recover_request"]))
            request["arguments"][field] = replacement_value
            with self.subTest(field=field):
                report = reduce_initial_runtime_image(_replace_worker_request(
                    image, values, "recover", request,
                ))
                self.assertEqual(report.status, "INVALID")
                self.assertIn(expected_code, self.codes(report))

        request = json.loads(json.dumps(values["recover_request"]))
        request["arguments"]["fence"] = values["recover_before_state"][
            "task_fence"
        ]
        report = reduce_initial_runtime_image(_replace_worker_request(
            image, values, "recover", request,
        ))
        self.assertEqual(report.status, "INVALID")
        self.assertIn("GROUP_OBJECT", self.codes(report))

        image, _ = recover_started_fixture()
        report = reduce_initial_runtime_image(image)
        self.assertEqual(report.status, "INVALID")
        self.assertIn("TRANSITION_SOURCE_STATE", self.codes(report))

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

    def test_continue_count_is_derived_not_trusted(self):
        image, values = continue_fixture()
        state = json.loads(json.dumps(values["continue_after_state"]))
        state["continuation_count"] += 8
        state_sha = blob_digest(state)
        semantic = json.loads(json.dumps(values["continue_semantic"]))
        semantic["state_after_ref"]["sha256"] = state_sha
        semantic["event_sha256"] = event_digest(semantic)
        commit = json.loads(json.dumps(values["continue_commit"]))
        commit["global_predecessor"]["event_sha256"] = semantic["event_sha256"]
        commit["event_sha256"] = event_digest(commit)
        old_state_sha = blob_digest(values["continue_after_state"])
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
        index = TABLE_NAMES.index("tasks")
        task = list(snapshots[index].rows[0])
        task[10] += 1
        snapshots[index] = TableSnapshot("tasks", (tuple(task),))
        report = reduce_initial_runtime_image(replace(
            image, table_snapshots=tuple(snapshots),
        ))
        self.assertEqual(report.status, "INVALID")
        self.assertIn("TABLE_DERIVATION", self.codes(report))

    def test_fail_and_complete_claim_closure_is_derived_not_trusted(self):
        for name, build in (
            ("claim_fail", claim_fail_fixture),
            ("fail", fail_fixture),
            ("complete_review", complete_review_fixture),
            ("complete_close", complete_close_fixture),
            ("continue_fail", continue_fail_fixture),
            ("continue_complete_review", continue_complete_review_fixture),
            ("continue_complete_close", continue_complete_close_fixture),
            ("recover", recover_fixture),
        ):
            image, _ = build()
            snapshots = list(image.table_snapshots)
            index = TABLE_NAMES.index("claims")
            claim = list(snapshots[index].rows[0])
            claim[4] = "OPEN"
            claim[7] = None
            snapshots[index] = TableSnapshot("claims", (tuple(claim),))
            with self.subTest(group=name):
                report = reduce_initial_runtime_image(replace(
                    image, table_snapshots=tuple(snapshots),
                ))
                self.assertEqual(report.status, "INVALID")
                self.assertIn("TABLE_DERIVATION", self.codes(report))

    def test_terminal_worker_targets_and_claim_history_are_exact(self):
        for name, build, expected_triple, expected_status, continuation_count in (
            (
                "claim_fail", claim_fail_fixture,
                ("ACTIVE", "FAILED", "NOT_REQUIRED"), "FAILED", 0,
            ),
            (
                "fail", fail_fixture,
                ("ACTIVE", "FAILED", "NOT_REQUIRED"), "FAILED", 0,
            ),
            (
                "complete_review", complete_review_fixture,
                ("ACTIVE", "EXECUTION_COMPLETED", "REVIEW_PENDING"),
                "COMPLETED", 0,
            ),
            (
                "complete_close", complete_close_fixture,
                ("CLOSED", "EXECUTION_COMPLETED", "NOT_REQUIRED"),
                "COMPLETED", 0,
            ),
            (
                "continue_fail", continue_fail_fixture,
                ("ACTIVE", "FAILED", "NOT_REQUIRED"), "FAILED", 1,
            ),
            (
                "continue_complete_review", continue_complete_review_fixture,
                ("ACTIVE", "EXECUTION_COMPLETED", "REVIEW_PENDING"),
                "COMPLETED", 1,
            ),
            (
                "continue_complete_close", continue_complete_close_fixture,
                ("CLOSED", "EXECUTION_COMPLETED", "NOT_REQUIRED"),
                "COMPLETED", 1,
            ),
            (
                "recover", recover_fixture,
                ("ACTIVE", "CLAIMABLE", "NOT_REQUIRED"), "RECOVERED", 0,
            ),
        ):
            image, values = build()
            state = values[f"{name}_after_state"]
            claim_row = image.table_snapshots[TABLE_NAMES.index("claims")].rows[0]
            with self.subTest(group=name):
                self.assertEqual(
                    (state["workflow"], state["execution"], state["review"]),
                    expected_triple,
                )
                self.assertEqual(state["continuation_count"], continuation_count)
                self.assertIsNone(state["active_claim_id"])
                self.assertEqual(claim_row[4], expected_status)
                self.assertEqual(
                    claim_row[7], values[f"{name}_semantic"]["event_id"]
                )

    def test_terminal_event_and_request_operation_cannot_be_swapped(self):
        image, values = fail_fixture()
        request = json.loads(json.dumps(values["fail_request"]))
        request["operation"] = "COMPLETE"
        report = reduce_initial_runtime_image(_replace_worker_request(
            image, values, "fail", request,
        ))
        self.assertEqual(report.status, "INVALID")
        self.assertIn("GROUP_CONST", self.codes(report))

    def test_complete_boolean_and_source_state_fail_closed(self):
        image, values = complete_review_fixture()
        for replacement_value in (0, 1, "false", None):
            request = json.loads(json.dumps(values["complete_review_request"]))
            request["arguments"]["close"] = replacement_value
            with self.subTest(close=replacement_value):
                report = reduce_initial_runtime_image(_replace_worker_request(
                    image, values, "complete_review", request,
                ))
                self.assertEqual(report.status, "INVALID")
                self.assertIn("TRANSITION_CLOSE_TYPE", self.codes(report))

        image, _ = claim_complete_review_fixture()
        report = reduce_initial_runtime_image(image)
        self.assertEqual(report.status, "INVALID")
        self.assertIn("TRANSITION_SOURCE_STATE", self.codes(report))

    def test_terminal_worker_arguments_fail_closed(self):
        image, values = fail_fixture()
        for field, replacement_value, expected_code in (
            ("failure_code", "worker_error", "TRANSITION_TEXT"),
            ("failure_code", "A" * 65, "TRANSITION_TEXT"),
            ("failure_evidence_sha256", "x" * 64, "TRANSITION_TEXT"),
            ("fence", True, "TRANSITION_INTEGER"),
        ):
            request = json.loads(json.dumps(values["fail_request"]))
            request["arguments"][field] = replacement_value
            with self.subTest(operation="FAIL", field=field):
                report = reduce_initial_runtime_image(_replace_worker_request(
                    image, values, "fail", request,
                ))
                self.assertEqual(report.status, "INVALID")
                self.assertIn(expected_code, self.codes(report))

        image, values = complete_review_fixture()
        request = json.loads(json.dumps(values["complete_review_request"]))
        request["arguments"]["completion_evidence_sha256"] = "x" * 64
        report = reduce_initial_runtime_image(_replace_worker_request(
            image, values, "complete_review", request,
        ))
        self.assertEqual(report.status, "INVALID")
        self.assertIn("TRANSITION_TEXT", self.codes(report))

    def test_terminal_after_state_is_recomputed_after_consistent_rehash(self):
        for name, build, field, replacement_value in (
            ("fail", fail_fixture, "workflow", "CLOSED"),
            (
                "complete_review", complete_review_fixture,
                "review", "NOT_REQUIRED",
            ),
            (
                "complete_close", complete_close_fixture,
                "workflow", "ACTIVE",
            ),
            (
                "continue_complete_review", continue_complete_review_fixture,
                "continuation_count", 0,
            ),
            ("recover", recover_fixture, "task_fence", 99),
        ):
            image, values = build()
            state = json.loads(json.dumps(values[f"{name}_after_state"]))
            state[field] = replacement_value
            with self.subTest(group=name, field=field):
                report = reduce_initial_runtime_image(
                    _replace_worker_after_state(image, values, name, state)
                )
                self.assertEqual(report.status, "INVALID")
                self.assertIn("GROUP_STATE_DERIVATION", self.codes(report))

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

        group_source = (
            ROOT / "src" / "edgelab" / "runtime_v2_group.py"
        ).read_text(encoding="utf-8")
        initial_source = (
            ROOT / "src" / "edgelab" / "runtime_v2_initial.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("prior_events", group_source)
        self.assertNotIn("parsed_events[:", initial_source)
        self.assertNotIn("{1, 3, 5, 7, 9, 11}", initial_source)


if __name__ == "__main__":
    unittest.main()
