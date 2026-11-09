"""Fail-closed composition of the existing M0.3A synthetic lifecycle pieces.

This is a local test harness, not an executor or an authority resolver.  It
records a complete scheduler lifecycle only after both public verification
boundaries have returned their expected non-authorizing results.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .authority_binding import compose_authority_binding, verify_binding_integrity
from .locked_authority import read_locked_authority
from .runtime_v2_codec import canonical_json
from .runtime_v2_verifier import (
    RuntimeImage,
    SchemaDocumentRecord,
    verify_runtime_image,
)
from .transactional_scheduler import Scheduler, digest


CANONICAL_ROOT = Path(__file__).resolve().parents[2]
TASK_ID = "T-SYNTHETIC-001"
CAPTURE_ID = "AUTH-AUTHENTIC-STAGE1-DISPATCH"
SYNTHETIC_RECEIPT = "UNTRUSTED_SYNTHETIC_RECEIPT"


class SyntheticLifecycleError(RuntimeError):
    """The composed harness could not preserve its fail-closed contract."""


def _public_runtime_v2_preflight(root: Path) -> dict[str, Any]:
    descriptor = json.loads(
        (root / "schemas/m0-3a-runtime-storage.v2.json").read_text(encoding="utf-8")
    )
    registry = json.loads(
        (root / "schemas/m0-3a-schema-registry.v2.json").read_text(encoding="utf-8")
    )
    documents: dict[str, Any] = {}
    for path in sorted((root / "schemas").glob("m0-3a-*.schema.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        schema_id = document.get("$id")
        if isinstance(schema_id, str):
            if schema_id in documents:
                raise SyntheticLifecycleError("duplicate public schema id")
            documents[schema_id] = document
    try:
        records = tuple(
            SchemaDocumentRecord(
                entry["schema_id"],
                entry["document_sha256"],
                canonical_json(documents[entry["schema_id"]]),
            )
            for entry in registry["documents"]
        )
    except (KeyError, TypeError) as error:
        raise SyntheticLifecycleError("public schema bundle is incomplete") from error

    result = verify_runtime_image(
        RuntimeImage(
            canonical_json(descriptor),
            schema_registry=canonical_json(registry),
            schema_documents=records,
        )
    ).as_mapping()
    if (
        result.get("status") != "UNSUPPORTED"
        or result.get("anchor_status") != "UNANCHORED"
        or result.get("currentness_status") != "UNKNOWN"
        or result.get("authorizing_use") != "DENY"
    ):
        raise SyntheticLifecycleError("public runtime-v2 boundary did not fail closed")
    return result


def _locked_request(scheduler: Scheduler) -> tuple[dict[str, Any], dict[str, Any]]:
    observation = read_locked_authority(scheduler, TASK_ID)
    verification = observation.get("verification", {})
    authority = observation.get("authority")
    if (
        observation.get("observation_status") != "COHERENT_DENY_ONLY"
        or not isinstance(authority, dict)
        or verification.get("currentness_status") != "UNKNOWN"
        or verification.get("authorizing_use") != "DENY"
    ):
        raise SyntheticLifecycleError("locked authority observation did not fail closed")
    task_tuple = authority["task"]["tuple"]
    return observation, {
        "expected": task_tuple,
        "repository_generation": authority["runtime"]["repository_generation"],
        "receipt_digest": task_tuple["decision_receipt_digest"],
    }


def _record(response: dict[str, Any]) -> dict[str, Any]:
    return {
        "operation": response["operation"],
        "event": response["event"],
        "tuple": response["tuple"],
    }


def run_synthetic_lifecycle(
    runtime_dir: Path,
    *,
    root: Path = CANONICAL_ROOT,
) -> dict[str, Any]:
    """Run and replay one synthetic task while retaining DENY authorization.

    ``runtime_dir`` must be a new directory outside the repository.  No result
    from this function authorizes execution, release, currentness, or capital.
    """
    root = root.resolve()
    runtime_dir = runtime_dir.resolve()
    if root != CANONICAL_ROOT:
        raise SyntheticLifecycleError("non-canonical repository root")
    if runtime_dir == root or runtime_dir.is_relative_to(root):
        raise SyntheticLifecycleError("runtime directory must be outside the repository")
    if runtime_dir.exists():
        raise SyntheticLifecycleError("runtime directory must not already exist")

    public_result = _public_runtime_v2_preflight(root)

    scheduler = Scheduler(root, runtime_dir)
    scheduler.initialize()
    events = [
        _record(scheduler.create_task(TASK_ID, SYNTHETIC_RECEIPT, "synthetic-owner"))
    ]

    binding = compose_authority_binding(scheduler, TASK_ID, CAPTURE_ID)
    binding_verification = binding.get("verification", {})
    if (
        binding.get("status") != "BOUND_DENY_ONLY"
        or binding.get("evidence_class") != "R_GATE_CANDIDATE_EVIDENCE"
        or binding_verification.get("currentness_status") != "UNKNOWN"
        or binding_verification.get("verifier_status") != "FAIL"
        or binding_verification.get("generation_match") is not False
        or binding_verification.get("authorizing_use") != "DENY"
        or not verify_binding_integrity(binding)
    ):
        raise SyntheticLifecycleError("historical/runtime binding did not fail closed")

    _, request = _locked_request(scheduler)
    claimed = scheduler.transition(
        "CLAIM",
        TASK_ID,
        {**request, "actor": "synthetic-worker"},
        operation_key="synthetic-claim",
    )
    events.append(_record(claimed))
    claim_id = claimed["tuple"]["active_claim_id"]
    fence = claimed["tuple"]["task_fence"]

    _, request = _locked_request(scheduler)
    events.append(_record(scheduler.transition(
        "START",
        TASK_ID,
        {**request, "claim_id": claim_id, "fence": fence},
        operation_key="synthetic-start",
    )))

    _, request = _locked_request(scheduler)
    events.append(_record(scheduler.transition(
        "COMPLETE",
        TASK_ID,
        {**request, "claim_id": claim_id, "fence": fence},
        operation_key="synthetic-complete",
    )))

    _, request = _locked_request(scheduler)
    assigned = scheduler.transition(
        "ASSIGN_REVIEW",
        TASK_ID,
        {**request, "actor": "synthetic-reviewer", "role": "05 Skeptic"},
        operation_key="synthetic-assign-review",
    )
    events.append(_record(assigned))
    reviewer_id = assigned["tuple"]["reviewer_assignment_id"]

    decision_digest = digest({
        "kind": "SYNTHETIC_NON_OPERATIONAL_REVIEW",
        "binding_candidate_sha256": binding["candidate_sha256"],
    })
    _, request = _locked_request(scheduler)
    events.append(_record(scheduler.transition(
        "APPROVE",
        TASK_ID,
        {**request, "reviewer_id": reviewer_id, "decision_digest": decision_digest},
        operation_key="synthetic-approve",
    )))

    _, request = _locked_request(scheduler)
    events.append(_record(scheduler.transition(
        "ROUTE",
        TASK_ID,
        {**request, "routing_evidence": "synthetic-local-only"},
        operation_key="synthetic-route",
    )))

    scheduler.startup()
    final_observation, _ = _locked_request(scheduler)
    final_tuple = final_observation["authority"]["task"]["tuple"]
    if (
        final_tuple["workflow"],
        final_tuple["execution"],
        final_tuple["review"],
    ) != ("DIRECTOR_GATE_READY", "EXECUTION_COMPLETED", "APPROVED"):
        raise SyntheticLifecycleError("synthetic lifecycle did not reach recorded completion")

    report = {
        "schema_version": 1,
        "integration_status": "RECORDED_NON_OPERATIONAL_LIFECYCLE",
        "mode": "SYNTHETIC_LOCAL_ONLY",
        "task_id": TASK_ID,
        "events": events,
        "historical_binding": {
            "status": binding["status"],
            "evidence_class": binding["evidence_class"],
            "candidate_sha256": binding["candidate_sha256"],
            "seal_sha256": binding["historical_seal"]["seal_sha256"],
            "decision_id": binding["historical_seal"]["decision"]["decision_id"],
            "verification": binding_verification,
        },
        "public_runtime_v2_verification": public_result,
        "final_locked_authority": {
            "observation_status": final_observation["observation_status"],
            "authority_sha256": final_observation["authority_sha256"],
            "tuple": final_tuple,
            "verification": final_observation["verification"],
        },
        "scheduler_replay": "PASSED",
        "authorization": {
            "authorizing_use": "DENY",
            "operational_release": "DENIED",
            "currentness": "UNKNOWN",
        },
        "limitations": [
            "public runtime-v2 verifier remains disconnected from the private reducer",
            "stored synthetic receipt is caller-supplied and non-authoritative",
            "no currentness or composed R-gate decision is implemented",
            "no executor, operational release, live action, or capital action is authorized",
        ],
        "report_sha256": "",
    }
    report["report_sha256"] = digest(
        {key: value for key, value in report.items() if key != "report_sha256"}
    )
    return report
