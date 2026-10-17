"""Build the exact retained-schema registry for runtime format 2."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from edgelab.runtime_v2_codec import schema_document_digest  # noqa: E402


OUTPUT = ROOT / "schemas" / "m0-3a-schema-registry.v2.json"
DOCUMENTS = {
    "m0-3a-event-envelope.v2.schema.json": "EVENT_ENVELOPE",
    "m0-3a-event-payload.v2.schema.json": "PAYLOAD",
    "m0-3a-task-state.v2.schema.json": "TASK_STATE",
    "m0-3a-command-request.v2.schema.json": "REQUEST",
    "m0-3a-response-projection.v2.schema.json": "RESPONSE_PROJECTION",
    "m0-3a-runtime-checkpoint.v2.schema.json": "CHECKPOINT_DOCUMENT",
    "m0-3a-runtime-export.v2.schema.json": "EXPORT_DOCUMENT",
    "m0-3a-legacy-v1-row-archive.v1.schema.json": "LEGACY_ROW_ARCHIVE",
    "m0-3a-legacy-v1-projection.v1.schema.json": "LEGACY_PROJECTION",
}
RUNTIME_EVENTS = {
    "COMMAND_COMMITTED",
    "LEGACY_V1_BRIDGE",
    "REPOSITORY_GENERATION_ADVANCED",
    "RUNTIME_CHECKPOINTED",
    "RUNTIME_GENESIS",
    "RUNTIME_SNAPSHOT_EXPORTED",
}
TASK_EVENTS = {
    "CLAIM_ISSUED",
    "CLAIM_RECOVERED",
    "DIRECTOR_ROUTED",
    "GOVERNANCE_BLOCKED",
    "GOVERNANCE_REVALIDATED",
    "REMEDIATION_CREATED",
    "REPOSITORY_GENERATION_APPLIED",
    "REVIEW_APPROVED",
    "REVIEW_ASSIGNED",
    "REVIEW_REJECTED",
    "REVIEW_REMEDIATED",
    "TASK_COMPLETED",
    "TASK_CONTINUED",
    "TASK_CREATED_FROM_REMEDIATION",
    "TASK_FAILED",
    "TASK_INITIALIZED",
    "TASK_RETRIED",
    "TASK_STARTED",
    "TASK_YIELDED",
}


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def parse_schema(text: str) -> dict[str, object]:
    value = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    if type(value) is not dict:
        raise ValueError("schema document must be an object")
    return value


def build() -> dict[str, object]:
    retained: list[tuple[str, str, dict[str, object]]] = []
    for filename, role in DOCUMENTS.items():
        document = parse_schema((ROOT / "schemas" / filename).read_text())
        retained.append((document["$id"], role, document))
    documents = [
        {
            "schema_id": schema_id,
            "document_sha256": schema_document_digest(document),
            "content_role": role,
        }
        for schema_id, role, document in sorted(retained)
    ]
    role_ids = {entry["content_role"]: entry["schema_id"] for entry in documents}
    bindings = []
    for event_type in sorted(RUNTIME_EVENTS | TASK_EVENTS):
        task = event_type in TASK_EVENTS
        state_id = role_ids["TASK_STATE"] if task else None
        before_id = None if event_type in {
            "TASK_INITIALIZED", "TASK_CREATED_FROM_REMEDIATION"
        } else state_id
        bindings.append({
            "event_type": event_type,
            "stream": "TASK" if task else "RUNTIME",
            "payload_schema_id": role_ids["PAYLOAD"],
            "state_before_schema_id": before_id,
            "state_after_schema_id": state_id,
            "request_schema_id": role_ids["REQUEST"],
            "response_projection_schema_id": role_ids["RESPONSE_PROJECTION"],
        })
    return {
        "schema_version": 1,
        "runtime_format_version": 2,
        "documents": documents,
        "event_bindings": bindings,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rendered = json.dumps(build(), indent=2, ensure_ascii=True) + "\n"
    if args.check:
        return 0 if OUTPUT.exists() and OUTPUT.read_text() == rendered else 1
    OUTPUT.write_text(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
