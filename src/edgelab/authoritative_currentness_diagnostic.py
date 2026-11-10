"""Read-only H-M0-187 historical/current authority diagnostic.

The diagnostic composes the accepted historical binding with independently
rechecked canonical-repository and Scheduler v1 observations.  It deliberately
cannot express CURRENT, PASS, generation equality, or ALLOW.
"""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import stat
from typing import Any

from jsonschema import Draft202012Validator

from .authority_binding import (
    CANONICAL_ROOT,
    compose_authority_binding,
    verify_binding_integrity,
)
from .locked_authority import read_locked_authority
from .transactional_scheduler import EXPECTED_REMOTE, Scheduler, digest


RESULT_SCHEMA_PATH = Path("schemas/authoritative-currentness-diagnostic.v1.schema.json")
DIAGNOSTIC_ID = "H-M0-187-AUTHORITATIVE-CURRENTNESS-DIAGNOSTIC"
DEFAULT_CAPTURE_ID = "AUTH-AUTHENTIC-STAGE1-DISPATCH"
DEFAULT_TASK_ID = "T-SYNTHETIC-001"

_LIMITATIONS = (
    "coherent current source observation is not proof of historical-to-current equality",
    "project, STOP, assignment, handoff, dependency, capability, reachability, and policy-generation historical mappings remain absent",
    "Scheduler v1 decision_receipt_digest is caller supplied and is not an authenticated historical receipt",
    "runtime and task generation coherence is observed only within the current runtime; historical generation equality is undefined",
    "the result is diagnostic only and cannot authorize scheduler, executor, paper, live, STOP clearance, or capital action",
)

_INVALIDATORS = (
    "any historical verification or subject-binding failure",
    "any current repository, project, STOP, attachment, runtime, task, attempt, claim, fence, or generation inconsistency",
    "any changed observation between read and recheck",
    "any missing required dimension or source mapping",
    "any attempted CURRENT, PASS, generation_match true, or ALLOW substitution",
)

_REQUIRED_DIMENSIONS = (
    "historical_verification",
    "historical_subject_binding",
    "canonical_repository_observation",
    "project_source_observation",
    "stop_source_observation",
    "attachment_runtime_binding",
    "scheduler_replay_materialization",
    "task_attempt_observation",
    "claim_fence_observation",
    "current_generation_coherence",
    "historical_project_stop_equality",
    "historical_assignment_handoff_equality",
    "historical_dependency_capability_equality",
    "historical_git_reachability_equality",
    "authenticated_receipt_binding",
    "historical_generation_equality",
)


class CurrentnessDiagnosticError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _verification(*, historical_valid: bool, compatible: bool) -> dict[str, Any]:
    return {
        "historical_status": "VALID" if historical_valid else "INVALID",
        "currentness_status": "UNKNOWN",
        "runtime_compatible": compatible,
        "verifier_status": "FAIL",
        "generation_match": False,
        "authorizing_use": "DENY",
        "reason_code": "VERIFIER_FAILURE" if historical_valid else "HISTORICAL_INVALID",
    }


def _dimension(
    identifier: str,
    status: str,
    reason: str,
    sources: list[str],
    evidence_sha256: str | None,
) -> dict[str, Any]:
    return {
        "id": identifier,
        "status": status,
        "reason": reason,
        "sources": sources,
        "evidence_sha256": evidence_sha256,
        "invalidates_positive_currentness": True,
    }


def _schema(root: Path) -> Draft202012Validator:
    path = root / RESULT_SCHEMA_PATH
    schema = json.loads(path.read_text(encoding="utf-8"))
    return Draft202012Validator(schema)


def _finalize(root: Path, record: dict[str, Any]) -> dict[str, Any]:
    record["result_sha256"] = digest(
        {key: value for key, value in record.items() if key != "result_sha256"}
    )
    _schema(root).validate(record)
    if not verify_diagnostic_integrity(record, root=root):
        raise CurrentnessDiagnosticError("INTERNAL_INTEGRITY_FAILURE")
    return record


def _unavailable(
    root: Path,
    *,
    task_id: str,
    capture_id: str,
    failure: str,
    historical_valid: bool = False,
    compatible: bool = False,
) -> dict[str, Any]:
    record = {
        "schema_version": 1,
        "diagnostic_id": DIAGNOSTIC_ID,
        "status": "UNAVAILABLE",
        "task_id": task_id,
        "capture_id": capture_id,
        "attempt": None,
        "failure_reason": failure,
        "historical_binding": None,
        "current_observation": None,
        "trusted_sources": [],
        "dimensions": [
            _dimension(
                "diagnostic_completion",
                "INVALID",
                failure,
                [],
                None,
            )
        ],
        "verified_dimensions": [],
        "unknown_dimensions": list(_REQUIRED_DIMENSIONS),
        "invalid_dimensions": ["diagnostic_completion"],
        "invalidators": [failure],
        "verification": _verification(
            historical_valid=historical_valid, compatible=compatible
        ),
        "limitations": list(_LIMITATIONS),
        "result_sha256": "",
    }
    try:
        return _finalize(root, record)
    except Exception:
        record["failure_reason"] = "INTERNAL_FAILURE"
        record["dimensions"][0]["reason"] = "INTERNAL_FAILURE"
        record["invalidators"] = ["INTERNAL_FAILURE"]
        record["result_sha256"] = digest(
            {key: value for key, value in record.items() if key != "result_sha256"}
        )
        return record


def _regular_bytes(root: Path, relative: Path) -> bytes:
    path = root / relative
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise CurrentnessDiagnosticError("REPOSITORY_SOURCE_INVALID")
    resolved = path.resolve(strict=True)
    if resolved != path or not resolved.is_relative_to(root):
        raise CurrentnessDiagnosticError("REPOSITORY_SOURCE_INVALID")
    return path.read_bytes()


def _repository_sources(scheduler: Scheduler) -> dict[str, Any]:
    root = scheduler.root
    if root != CANONICAL_ROOT:
        raise CurrentnessDiagnosticError("NONCANONICAL_ROOT")
    bundle = scheduler.bundle()
    project_paths = [Path("docs/project-state.json")]
    stop_paths = sorted(
        (path.relative_to(root) for path in (root / "reports/stops").glob("*.json")),
        key=lambda path: path.as_posix().encode("utf-8"),
    )
    orchestration_paths = sorted(
        (path.relative_to(root) for path in (root / "orchestration").rglob("*.json")),
        key=lambda path: path.as_posix().encode("utf-8"),
    )
    portfolio_paths = sorted(
        (path.relative_to(root) for path in (root / "portfolio").glob("*.json")),
        key=lambda path: path.as_posix().encode("utf-8"),
    )
    selected = [*project_paths, *stop_paths, *orchestration_paths, *portfolio_paths]
    if len(selected) != len(set(selected)):
        raise CurrentnessDiagnosticError("REPOSITORY_SOURCE_INVALID")
    pairs = [(path.as_posix(), _sha256(_regular_bytes(root, path))) for path in selected]

    def group(prefix: str) -> str:
        return digest([pair for pair in pairs if pair[0].startswith(prefix)])

    recomputed = {
        "commit": scheduler._git("rev-parse", "HEAD"),
        "digest": digest({"files": pairs}),
        "project": group("docs/project-state"),
        "stops": group("reports/stops"),
        "policy": digest([
            pair
            for pair in pairs
            if pair[0].startswith("portfolio/")
            or pair[0].startswith("orchestration/capabilities")
        ]),
        "tasks": group("orchestration/"),
    }
    if recomputed != asdict(bundle):
        raise CurrentnessDiagnosticError("REPOSITORY_BUNDLE_MISMATCH")
    if scheduler._git("remote", "get-url", "origin") != EXPECTED_REMOTE:
        raise CurrentnessDiagnosticError("REPOSITORY_IDENTITY_MISMATCH")
    if scheduler._git("rev-parse", "--show-toplevel") != str(root):
        raise CurrentnessDiagnosticError("REPOSITORY_IDENTITY_MISMATCH")

    project = json.loads(_regular_bytes(root, project_paths[0]))
    active_refs = project.get("active_stop_refs")
    if not isinstance(active_refs, list) or not active_refs:
        raise CurrentnessDiagnosticError("PROJECT_STOP_MAPPING_INVALID")
    active_stops = []
    stop_set = {path.as_posix() for path in stop_paths}
    pair_map = dict(pairs)
    for reference in active_refs:
        if not isinstance(reference, str) or reference not in stop_set:
            raise CurrentnessDiagnosticError("PROJECT_STOP_MAPPING_INVALID")
        stop = json.loads(_regular_bytes(root, Path(reference)))
        if stop.get("status") != "OPEN":
            raise CurrentnessDiagnosticError("PROJECT_STOP_MAPPING_INVALID")
        active_stops.append({
            "path": reference,
            "sha256": pair_map[reference],
            "id": stop.get("id"),
            "version": stop.get("version"),
            "status": stop.get("status"),
        })

    return {
        "repository": recomputed,
        "remote": EXPECTED_REMOTE,
        "root": str(root),
        "source_inventory_sha256": digest(pairs),
        "source_file_count": len(pairs),
        "project": {
            "path": project_paths[0].as_posix(),
            "sha256": pair_map[project_paths[0].as_posix()],
            "phase": project.get("phase"),
            "increment": project.get("increment"),
            "status": project.get("status"),
            "live_status": project.get("live_status"),
            "active_stop_refs": active_refs,
        },
        "stops": {
            "source_glob": "reports/stops/*.json",
            "file_count": len(stop_paths),
            "inventory_sha256": digest([
                pair for pair in pairs if pair[0].startswith("reports/stops/")
            ]),
            "active": active_stops,
        },
    }


def _dimension_definitions(
    binding: dict[str, Any],
    authority: dict[str, Any],
    repository: dict[str, Any],
) -> list[dict[str, Any]]:
    seal = binding["historical_seal"]
    task_tuple = authority["task"]["tuple"]
    claim = authority["claim"]
    current_repository = authority["repository"]
    return [
        _dimension(
            "historical_verification", "VERIFIED",
            "accepted historical replay completed and raw result matched",
            [seal["capture"]["fixture_path"], "tools.verify_authentic_history.verify_authentic_history"],
            seal["stable_projection_sha256"],
        ),
        _dimension(
            "historical_subject_binding", "VERIFIED",
            "historical task and attempt equal the locked runtime subject",
            ["docs/M0.3A_AUTHORITY_SOURCE_MAPPING.v1.md", "locked-authority:task"],
            digest({"subject": seal["subject"], "task": authority["task"], "attempts": authority["attempts"]}),
        ),
        _dimension(
            "canonical_repository_observation", "VERIFIED",
            "canonical root, remote, HEAD, selected source inventory, and Scheduler bundle agree",
            ["git:HEAD", "git:origin", "scheduler.bundle", "canonical-source-inventory"],
            current_repository["digest"],
        ),
        _dimension(
            "project_source_observation", "VERIFIED",
            "current project-state bytes are included in and reproduce the Scheduler bundle",
            [repository["project"]["path"]],
            repository["project"]["sha256"],
        ),
        _dimension(
            "stop_source_observation", "VERIFIED",
            "current complete STOP inventory and active OPEN STOP references reproduce the Scheduler bundle",
            [repository["stops"]["source_glob"], "docs/project-state.json#/active_stop_refs"],
            current_repository["stops"],
        ),
        _dimension(
            "attachment_runtime_binding", "VERIFIED",
            "attachment seal, canonical checkout identity, runtime attachment digest, and bundle digest agree",
            ["runtime:attachment.json", "runtime:meta", "locked-authority:attachment"],
            digest({"attachment": authority["attachment"], "runtime_attachment_digest": authority["runtime"]["attachment_digest"]}),
        ),
        _dimension(
            "scheduler_replay_materialization", "VERIFIED",
            "Scheduler startup/replay and locked read accepted the event/materialized state",
            ["runtime:runtime.sqlite", "src/edgelab/transactional_scheduler.py", "src/edgelab/locked_authority.py"],
            authority["runtime"]["global_head_digest"],
        ),
        _dimension(
            "task_attempt_observation", "VERIFIED",
            "task identity, positive attempt, and contiguous attempt history are replay coherent",
            ["locked-authority:task", "locked-authority:attempts"],
            digest({"task": authority["task"], "attempts": authority["attempts"]}),
        ),
        _dimension(
            "claim_fence_observation", "VERIFIED",
            "active claim/fence is internally coherent or its absence is replay verified",
            ["locked-authority:claim", "locked-authority:task.tuple.task_fence"],
            digest({"claim": claim, "task_fence": task_tuple["task_fence"], "active_claim_id": task_tuple["active_claim_id"]}),
        ),
        _dimension(
            "current_generation_coherence", "VERIFIED",
            "runtime and task repository generations agree within the current locked observation",
            ["locked-authority:runtime.repository_generation", "locked-authority:task.tuple.repository_generation"],
            digest({"runtime": authority["runtime"]["repository_generation"], "task": task_tuple["repository_generation"], "scheduler": task_tuple["scheduler_generation"], "dispatch": task_tuple["dispatch_generation"]}),
        ),
        _dimension(
            "historical_project_stop_equality", "UNKNOWN",
            "SOURCE_MAPPING_ABSENT: historical seal contains no project or STOP projection",
            ["docs/M0.3A_AUTHORITY_SOURCE_MAPPING.v1.md#explicit-absent-claims"],
            None,
        ),
        _dimension(
            "historical_assignment_handoff_equality", "UNKNOWN",
            "SOURCE_MAPPING_ABSENT: historical seal contains no current assignment or handoff heads",
            ["docs/M0.3A_AUTHORITY_SOURCE_MAPPING.v1.md#explicit-absent-claims"],
            None,
        ),
        _dimension(
            "historical_dependency_capability_equality", "UNKNOWN",
            "SOURCE_MAPPING_ABSENT: dependency and capability generations are not mapped",
            ["docs/M0.3A_AUTHORITY_SOURCE_MAPPING.v1.md#explicit-absent-claims"],
            None,
        ),
        _dimension(
            "historical_git_reachability_equality", "UNKNOWN",
            "SOURCE_MAPPING_ABSENT: current Git observation is not mapped to frozen authorization equality",
            ["docs/M0.3A_AUTHORITY_SOURCE_MAPPING.v1.md#explicit-absent-claims"],
            None,
        ),
        _dimension(
            "authenticated_receipt_binding", "UNKNOWN",
            "AUTHENTICATED_RECEIPT_ABSENT: decision_receipt_digest is caller supplied",
            ["locked-authority:task.tuple.decision_receipt_digest", "reports/stops/STOP-M0-3A-001.v1.json"],
            None,
        ),
        _dimension(
            "historical_generation_equality", "UNKNOWN",
            "SOURCE_MAPPING_ABSENT: no accepted historical-to-runtime generation equation exists",
            ["docs/M0.2_CURRENTNESS_MODEL.v1.md", "docs/M0.3A_AUTHORITY_SOURCE_MAPPING.v1.md"],
            None,
        ),
    ]


def _trusted_source_projection(
    binding: dict[str, Any], current: dict[str, Any]
) -> list[dict[str, Any]]:
    seal = binding["historical_seal"]
    repository = current["repository"]
    return [
        {"id": "authority-source-mapping", "kind": "REPOSITORY_FILE", "locator": "docs/M0.3A_AUTHORITY_SOURCE_MAPPING.v1.md", "sha256": seal["mapping_contract"]["sha256"]},
        {"id": "m0.2-trusted-root", "kind": "SELF_VERIFIED_TRUST_ROOT", "locator": "docs/M0.2_STAGE1_TRUST_ROOT.v1.json", "sha256": seal["trusted_root"]["sha256"]},
        {"id": "m0.2-capture-root", "kind": "SELF_VERIFIED_CAPTURE_ROOT", "locator": "docs/M0.2_HISTORICAL_CAPTURE_ROOT.v1.json", "sha256": seal["capture_root"]["sha256"]},
        {"id": "historical-capture-sidecar", "kind": "HISTORICAL_CAPTURE", "locator": seal["capture"]["fixture_path"], "sha256": seal["capture"]["sidecar_sha256"]},
        {"id": "historical-persisted-graph", "kind": "HISTORICAL_GRAPH", "locator": "persisted-graph:" + seal["capture"]["graph_sha256"], "sha256": seal["capture"]["graph_sha256"]},
        {"id": "current-source-inventory", "kind": "CURRENT_REPOSITORY", "locator": "canonical Scheduler.bundle source inventory", "sha256": repository["source_inventory_sha256"]},
        {"id": "current-project-state", "kind": "CURRENT_REPOSITORY", "locator": repository["project"]["path"], "sha256": repository["project"]["sha256"]},
        {"id": "current-stop-inventory", "kind": "CURRENT_REPOSITORY", "locator": repository["stops"]["source_glob"], "sha256": repository["stops"]["inventory_sha256"]},
        {"id": "locked-scheduler-authority", "kind": "PERSISTED_RUNTIME", "locator": "Scheduler v1 locked read/recheck", "sha256": current["authority_sha256"]},
    ]


def verify_diagnostic_integrity(
    record: dict[str, Any], *, root: Path = CANONICAL_ROOT
) -> bool:
    """Verify the closed returned artifact without re-observing live sources."""
    try:
        _schema(root).validate(record)
        if record["result_sha256"] != digest(
            {key: value for key, value in record.items() if key != "result_sha256"}
        ):
            return False
        if record["verification"]["currentness_status"] != "UNKNOWN" or record["verification"]["authorizing_use"] != "DENY":
            return False
        if record["status"] == "UNAVAILABLE":
            return all((
                record["attempt"] is None,
                record["historical_binding"] is None,
                record["current_observation"] is None,
                record["trusted_sources"] == [],
                record["verified_dimensions"] == [],
                record["unknown_dimensions"] == list(_REQUIRED_DIMENSIONS),
                record["invalid_dimensions"] == ["diagnostic_completion"],
                record["dimensions"] == [
                    _dimension(
                        "diagnostic_completion", "INVALID",
                        record["failure_reason"], [], None,
                    )
                ],
                record["invalidators"] == [record["failure_reason"]],
            ))

        binding = record["historical_binding"]
        current = record["current_observation"]
        if not verify_binding_integrity(binding):
            return False
        authority = {
            "repository": current["repository"]["repository"],
            "runtime": current["runtime"],
            "attachment": current["attachment"],
            "task": current["task"],
            "claim": current["claim"],
            "attempts": current["attempts"],
            "review": current["review"],
        }
        if any((
            current["authority_sha256"] != digest(authority),
            current["authority_sha256"] != binding["locked_authority_sha256"],
            record["task_id"] != binding["task_id"],
            binding["task_id"] != current["task"]["task_id"],
            record["capture_id"] != binding["capture_id"],
            record["attempt"] != binding["attempt"],
            binding["attempt"] != current["task"]["tuple"]["attempt_no"],
            current["runtime"]["bundle_digest"] != current["repository"]["repository"]["digest"],
        )):
            return False
        expected_dimensions = _dimension_definitions(
            binding, authority, current["repository"]
        )
        expected_verified = [
            item["id"] for item in expected_dimensions if item["status"] == "VERIFIED"
        ]
        expected_unknown = [
            item["id"] for item in expected_dimensions if item["status"] == "UNKNOWN"
        ]
        if any((
            tuple(item["id"] for item in expected_dimensions) != _REQUIRED_DIMENSIONS,
            record["dimensions"] != expected_dimensions,
            record["verified_dimensions"] != expected_verified,
            record["unknown_dimensions"] != expected_unknown,
            record["invalid_dimensions"] != [],
            record["trusted_sources"] != _trusted_source_projection(binding, current),
            record["verification"] != _verification(historical_valid=True, compatible=True),
            record["limitations"] != list(_LIMITATIONS),
            record["invalidators"] != list(_INVALIDATORS),
        )):
            return False
        return True
    except Exception:
        return False


def diagnose_authoritative_currentness(
    scheduler: Scheduler,
    task_id: str = DEFAULT_TASK_ID,
    capture_id: str = DEFAULT_CAPTURE_ID,
) -> dict[str, Any]:
    """Return a deterministic, read-only UNKNOWN/DENY diagnostic."""
    root = scheduler.root
    historical_valid = False
    compatible = False
    try:
        if root != CANONICAL_ROOT:
            raise CurrentnessDiagnosticError("NONCANONICAL_ROOT")
        scheduler.startup()
        binding = compose_authority_binding(scheduler, task_id, capture_id)
        if binding.get("status") != "BOUND_DENY_ONLY":
            raise CurrentnessDiagnosticError(
                "HISTORICAL_BINDING_" + str(binding.get("failure_reason") or "UNAVAILABLE")
            )
        if (
            not verify_binding_integrity(binding)
            or binding.get("verification") != _verification(historical_valid=True, compatible=True)
        ):
            raise CurrentnessDiagnosticError("HISTORICAL_BINDING_INVALID")
        historical_valid = True
        compatible = True

        first_repository = _repository_sources(scheduler)
        first = read_locked_authority(scheduler, task_id)
        if (
            first.get("observation_status") != "COHERENT_DENY_ONLY"
            or first.get("authority_sha256") != binding["locked_authority_sha256"]
        ):
            raise CurrentnessDiagnosticError("CURRENT_AUTHORITY_MISMATCH")
        authority = first["authority"]
        if (
            authority["repository"] != first_repository["repository"]
            or authority["runtime"]["bundle_digest"] != first_repository["repository"]["digest"]
            or authority["task"]["task_id"] != task_id
            or authority["task"]["tuple"]["attempt_no"] != binding["attempt"]
        ):
            raise CurrentnessDiagnosticError("CURRENT_AUTHORITY_MISMATCH")

        second_repository = _repository_sources(scheduler)
        second = read_locked_authority(scheduler, task_id)
        if (
            second_repository != first_repository
            or second.get("observation_status") != "COHERENT_DENY_ONLY"
            or second.get("authority_sha256") != first["authority_sha256"]
            or second.get("authority") != authority
        ):
            raise CurrentnessDiagnosticError("OBSERVATION_RACE")

        dimensions = _dimension_definitions(binding, authority, first_repository)
        if tuple(item["id"] for item in dimensions) != _REQUIRED_DIMENSIONS:
            raise CurrentnessDiagnosticError("SOURCE_MAPPING_INCOMPLETE")
        verified = [item["id"] for item in dimensions if item["status"] == "VERIFIED"]
        unknown = [item["id"] for item in dimensions if item["status"] == "UNKNOWN"]
        invalid = [item["id"] for item in dimensions if item["status"] == "INVALID"]
        if invalid or not unknown:
            raise CurrentnessDiagnosticError("DIAGNOSTIC_CLASSIFICATION_INVALID")

        seal = binding["historical_seal"]
        current_observation = {
            "repository": first_repository,
            "runtime": authority["runtime"],
            "attachment": authority["attachment"],
            "task": authority["task"],
            "attempts": authority["attempts"],
            "claim": authority["claim"],
            "review": authority["review"],
            "authority_sha256": first["authority_sha256"],
        }
        record = {
            "schema_version": 1,
            "diagnostic_id": DIAGNOSTIC_ID,
            "status": "COHERENT_UNKNOWN_DENY",
            "task_id": task_id,
            "capture_id": capture_id,
            "attempt": binding["attempt"],
            "failure_reason": None,
            "historical_binding": binding,
            "current_observation": current_observation,
            "trusted_sources": _trusted_source_projection(binding, current_observation),
            "dimensions": dimensions,
            "verified_dimensions": verified,
            "unknown_dimensions": unknown,
            "invalid_dimensions": invalid,
            "invalidators": list(_INVALIDATORS),
            "verification": _verification(historical_valid=True, compatible=True),
            "limitations": list(_LIMITATIONS),
            "result_sha256": "",
        }
        return _finalize(root, record)
    except CurrentnessDiagnosticError as error:
        return _unavailable(
            root if root == CANONICAL_ROOT else CANONICAL_ROOT,
            task_id=task_id if isinstance(task_id, str) else "",
            capture_id=capture_id if isinstance(capture_id, str) else "",
            failure=error.code,
            historical_valid=historical_valid,
            compatible=compatible,
        )
    except Exception:
        return _unavailable(
            root if root == CANONICAL_ROOT else CANONICAL_ROOT,
            task_id=task_id if isinstance(task_id, str) else "",
            capture_id=capture_id if isinstance(capture_id, str) else "",
            failure="INTERNAL_FAILURE",
            historical_valid=historical_valid,
            compatible=compatible,
        )


def format_human(result: dict[str, Any]) -> str:
    lines = [
        "EdgeLab H-M0-187 authoritative currentness diagnostic",
        f"Status: {result['status']}",
        f"Historical: {result['verification']['historical_status']}",
        f"Currentness: {result['verification']['currentness_status']}",
        f"Authorization: {result['verification']['authorizing_use']}",
    ]
    if result["failure_reason"]:
        lines.append("Failure: " + result["failure_reason"])
    else:
        lines.extend([
            "Verified dimensions: " + ", ".join(result["verified_dimensions"]),
            "Unknown dimensions: " + ", ".join(result["unknown_dimensions"]),
        ])
    lines.append("This diagnostic cannot establish an authenticated R-gate.")
    return "\n".join(lines) + "\n"
