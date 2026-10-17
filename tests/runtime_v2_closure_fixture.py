"""Synthetic shape fixture; incomplete, non-release, and authority-free."""
from src.edgelab.runtime_v2_codec import verifier_dependency_closure_digest


SHA = "a" * 64


def closure_fixture() -> dict:
    value = {
        "schema_version": 1,
        "closure_id": "urn:edgelab:m0-3a-verifier-dependency-closure:1",
        "closure_version": 1,
        "runtime_format_version": 2,
        "canonicalization": "EDGELAB_CANONICAL_JSON_V1",
        "digest_algorithm": "SHA-256",
        "digest_domain": "EDGELAB\0VERIFIER_DEPENDENCY_CLOSURE\0V2\0",
        "entrypoint": {
            "artifact_path": "src/edgelab/runtime_v2_verifier.py",
            "module": "edgelab.runtime_v2_verifier",
            "callable": "verify_runtime_image",
        },
        "root_boundary": {
            "repository_relative": True,
            "local_import_roots": ["src/edgelab"],
            "filesystem_reads": "DENY",
            "network_access": "DENY",
            "environment_access": "DENY",
            "dynamic_imports": "DENY",
        },
        "pin_elision_profile": {
            "profile_id": "PIN_BLOCK_ELIDED_V1",
            "artifact_path": "src/edgelab/_runtime_v2_release.py",
            "begin_marker": "# BEGIN GENERATED PIN BLOCK",
            "end_marker": "# END GENERATED PIN BLOCK",
            "replacement_literal": "PIN_BLOCK_ELIDED_V1",
            "required_match_count": 1,
        },
        "local_artifacts": [
            {
                "path": "src/edgelab/_runtime_v2_release.py",
                "role": "PIN_CARRIER",
                "sha256": SHA,
                "byte_length": 1,
                "pin_elision_applied": True,
            },
            {
                "path": "src/edgelab/runtime_v2_verifier.py",
                "role": "ENTRYPOINT",
                "sha256": SHA,
                "byte_length": 1,
                "pin_elision_applied": False,
            },
        ],
        "bootstrap_schemas": [
            {
                "role": "ACTIVE_RUNTIME_SELECTOR",
                "schema_id": "urn:edgelab:m0-3a-active-runtime-selector:2",
                "path": "schemas/m0-3a-active-runtime-selector.v2.schema.json",
                "raw_sha256": SHA,
                "schema_document_sha256": SHA,
                "byte_length": 1,
            },
            {
                "role": "ATTACHMENT",
                "schema_id": "urn:edgelab:m0-3a-runtime-attachment:2",
                "path": "schemas/m0-3a-runtime-attachment.v2.schema.json",
                "raw_sha256": SHA,
                "schema_document_sha256": SHA,
                "byte_length": 1,
            },
            {
                "role": "RUNTIME_MANIFEST",
                "schema_id": "urn:edgelab:m0-3a-runtime-manifest:2",
                "path": "schemas/m0-3a-runtime-manifest.v2.schema.json",
                "raw_sha256": SHA,
                "schema_document_sha256": SHA,
                "byte_length": 1,
            },
            {
                "role": "STORAGE_DESCRIPTOR_SCHEMA",
                "schema_id": "urn:edgelab:m0-3a-runtime-storage-descriptor:2",
                "path": "schemas/m0-3a-runtime-storage-descriptor.v2.schema.json",
                "raw_sha256": SHA,
                "schema_document_sha256": SHA,
                "byte_length": 1,
            },
            {
                "role": "SCHEMA_REGISTRY_SCHEMA",
                "schema_id": "urn:edgelab:m0-3a-schema-registry:2",
                "path": "schemas/m0-3a-schema-registry.v2.schema.json",
                "raw_sha256": SHA,
                "schema_document_sha256": SHA,
                "byte_length": 1,
            },
        ],
        "retained_schema_documents": [
            {
                "content_role": role,
                "schema_id": schema_id,
                "path": path,
                "raw_sha256": SHA,
                "document_sha256": SHA,
                "byte_length": 1,
            }
            for role, schema_id, path in (
                ("REQUEST", "urn:edgelab:m0-3a-command-request:2", "schemas/m0-3a-command-request.v2.schema.json"),
                ("EVENT_ENVELOPE", "urn:edgelab:m0-3a-event-envelope:2", "schemas/m0-3a-event-envelope.v2.schema.json"),
                ("PAYLOAD", "urn:edgelab:m0-3a-event-payload:2", "schemas/m0-3a-event-payload.v2.schema.json"),
                ("LEGACY_PROJECTION", "urn:edgelab:m0-3a-legacy-v1-projection:1", "schemas/m0-3a-legacy-v1-projection.v1.schema.json"),
                ("LEGACY_ROW_ARCHIVE", "urn:edgelab:m0-3a-legacy-v1-row-archive:1", "schemas/m0-3a-legacy-v1-row-archive.v1.schema.json"),
                ("RESPONSE_PROJECTION", "urn:edgelab:m0-3a-response-projection:2", "schemas/m0-3a-response-projection.v2.schema.json"),
                ("CHECKPOINT_DOCUMENT", "urn:edgelab:m0-3a-runtime-checkpoint:2", "schemas/m0-3a-runtime-checkpoint.v2.schema.json"),
                ("EXPORT_DOCUMENT", "urn:edgelab:m0-3a-runtime-export:2", "schemas/m0-3a-runtime-export.v2.schema.json"),
                ("TASK_STATE", "urn:edgelab:m0-3a-task-state:2", "schemas/m0-3a-task-state.v2.schema.json"),
            )
        ],
        "content_assets": {
            "storage_descriptor": {
                "path": "schemas/m0-3a-runtime-storage.v2.json",
                "raw_sha256": SHA,
                "domain_sha256": SHA,
                "byte_length": 1,
            },
            "schema_registry": {
                "path": "schemas/m0-3a-schema-registry.v2.json",
                "raw_sha256": SHA,
                "domain_sha256": SHA,
                "byte_length": 1,
            },
        },
        "digest_domains": [
            {"name": "blob", "domain": "EDGELAB\0BLOB\0V2\0"},
            {
                "name": "closure",
                "domain": "EDGELAB\0VERIFIER_DEPENDENCY_CLOSURE\0V2\0",
            },
        ],
        "resource_limits": [
            {"name": "MAX_FINDINGS", "maximum": 128, "unit": "ITEMS"},
            {"name": "TOTAL_INPUT_BYTES", "maximum": 1_073_741_824, "unit": "BYTES"},
        ],
        "standard_library_modules": [
            {"module": "hashlib", "purpose": "SHA-256"},
            {"module": "json", "purpose": "canonical JSON parsing"},
            {"module": "re", "purpose": "closed lexical profiles"},
            {"module": "typing", "purpose": "type annotations"},
        ],
        "external_distributions": [],
        "tested_runtime_assumptions": [
            {"name": "PYTHON_IMPLEMENTATION", "expected": "CPython"},
            {"name": "PYTHON_VERSION", "expected": "3.13"},
        ],
        "generator_identity": {
            "artifact_path": "tools/build_runtime_v2_release.py",
            "artifact_sha256": SHA,
            "generator_version": 1,
            "invocation": "build_runtime_v2_release.py --check",
        },
        "deny_only_boundary": {
            "positive_status": "LOCALLY_CONSISTENT_DENY_ONLY",
            "anchor_status": "UNANCHORED",
            "currentness_status": "UNKNOWN",
            "authorizing_use": "DENY",
            "live_execution": "PROHIBITED",
        },
        "verifier_dependency_closure_sha256": "0" * 64,
    }
    value["verifier_dependency_closure_sha256"] = (
        verifier_dependency_closure_digest(value)
    )
    return value
