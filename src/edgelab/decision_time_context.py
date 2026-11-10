"""H-M0-188 bounded decision-time context capture for new synthetic tasks.

This module records observable context beside Scheduler v1.  It neither changes
the runtime nor turns the observation into an authenticated receipt.  All
outputs are structurally UNKNOWN and DENY.
"""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import re
import stat
from typing import Any, Callable

from jsonschema import Draft202012Validator

from .authoritative_currentness_diagnostic import (
    CANONICAL_ROOT,
    DEFAULT_CAPTURE_ID,
    diagnose_authoritative_currentness,
)
from .locked_authority import read_locked_authority
from .transactional_scheduler import EXPECTED_REMOTE, Scheduler, digest


CONTEXT_ID = "H-M0-188-DECISION-TIME-CONTEXT"
SCHEMA_PATH = Path("schemas/decision-time-context.v1.schema.json")
BOUNDARY = "BOUNDED_REPOSITORY_THEN_LOCKED_RUNTIME_READ_RECHECK"
UNKNOWN = (
    "authenticated_receipt_authority",
    "atomic_cross_system_snapshot",
    "legacy_m0_2_project_stop_equality",
    "legacy_m0_2_assignment_handoff_equality",
    "legacy_m0_2_dependency_capability_equality",
    "legacy_m0_2_git_reachability_equality",
    "legacy_m0_2_generation_equality",
)
SUPPORTED = (
    "fresh_project_stop_context",
    "fresh_assignment_handoff_context",
    "fresh_dependency_capability_context",
    "fresh_git_repository_context",
    "fresh_attachment_task_attempt_claim_fence_context",
    "fresh_runtime_generation_context",
)
LIMITATIONS = (
    "context digest is not an authenticated receipt",
    "bounded read/recheck is not an atomic repository/SQLite snapshot",
    "fresh contextual equality does not establish legacy M0.2 historical equality",
    "no field can authorize scheduler, executor, paper, live, STOP clearance, or capital action",
)


class ContextError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _regular(root: Path, relative: Path) -> bytes:
    path = root / relative
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise ContextError("SOURCE_INVALID")
    resolved = path.resolve(strict=True)
    if resolved != path or not resolved.is_relative_to(root):
        raise ContextError("SOURCE_INVALID")
    return path.read_bytes()


def _head(root: Path, directory: str, identifier: str) -> Path:
    pattern = re.compile(rf"^{re.escape(identifier)}\.v([1-9][0-9]*)\.json$")
    found: list[tuple[int, Path]] = []
    for path in (root / directory).glob(f"{identifier}.v*.json"):
        match = pattern.fullmatch(path.name)
        if match:
            found.append((int(match.group(1)), path.relative_to(root)))
    if not found:
        raise ContextError("SOURCE_MAPPING_MISSING")
    found.sort()
    if len({version for version, _ in found}) != len(found):
        raise ContextError("SOURCE_MAPPING_CONFLICT")
    return found[-1][1]


def _record(root: Path, relative: Path, family: str) -> dict[str, Any]:
    raw = _regular(root, relative)
    return {
        "family": family,
        "kind": "REPOSITORY_FILE",
        "locator": relative.as_posix(),
        "source_identity": "git-repository-file:" + relative.as_posix(),
        "content_sha256": _sha(raw),
        "byte_length": len(raw),
        "observation_boundary": BOUNDARY,
    }


def _pseudo(family: str, kind: str, locator: str, identity: str, value: Any) -> dict[str, Any]:
    raw = value if isinstance(value, bytes) else value.encode("utf-8") if isinstance(value, str) else json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return {
        "family": family,
        "kind": kind,
        "locator": locator,
        "source_identity": identity,
        "content_sha256": _sha(raw),
        "byte_length": len(raw),
        "observation_boundary": BOUNDARY,
    }


def _repository_records(scheduler: Scheduler, task_id: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    root = scheduler.root
    bundle = scheduler.bundle()
    remote = scheduler._git("remote", "get-url", "origin")
    head = scheduler._git("rev-parse", "HEAD")
    if remote != EXPECTED_REMOTE or scheduler._git("rev-parse", "--show-toplevel") != str(root):
        raise ContextError("REPOSITORY_IDENTITY_MISMATCH")

    task_path = _head(root, "orchestration/tasks", task_id)
    task = json.loads(_regular(root, task_path))
    if task.get("task_id") != task_id or not isinstance(task.get("attempt"), int):
        raise ContextError("TASK_SOURCE_INVALID")
    assignment_path = _head(root, "orchestration/assignments", task_id)
    binding_path = _head(root, "orchestration/handoff-bindings", task_id)
    handoff_ref = task.get("handoff_ref")
    if not isinstance(handoff_ref, str):
        raise ContextError("SOURCE_MAPPING_MISSING")
    handoff_path = Path(handoff_ref)
    if handoff_path.is_absolute() or ".." in handoff_path.parts:
        raise ContextError("SOURCE_MAPPING_INVALID")

    paths: list[tuple[Path, str]] = [(Path("docs/project-state.json"), "project_stop")]
    paths.extend((path.relative_to(root), "project_stop") for path in sorted((root / "reports/stops").glob("*.json")))
    paths.extend([
        (task_path, "assignment_handoff"),
        (assignment_path, "assignment_handoff"),
        (binding_path, "assignment_handoff"),
        (handoff_path, "assignment_handoff"),
    ])

    dependencies = task.get("dependencies")
    capabilities = task.get("capability_refs")
    if not isinstance(dependencies, list) or not all(isinstance(item, str) and item for item in dependencies):
        raise ContextError("DEPENDENCY_SOURCE_INVALID")
    if not isinstance(capabilities, list) or not all(isinstance(item, str) and item for item in capabilities):
        raise ContextError("CAPABILITY_SOURCE_INVALID")
    for dependency in dependencies:
        dependency_path = _head(root, "orchestration/tasks", dependency)
        paths.append((dependency_path, "dependency_capability"))
        dependency_record = json.loads(_regular(root, dependency_path))
        for evidence_ref in dependency_record.get("completion_evidence", []):
            paths.append((Path(evidence_ref), "dependency_capability"))
    capability_files = list((root / "orchestration/capabilities").glob("*.json"))
    for capability_id in capabilities:
        matches = []
        for path in capability_files:
            parsed = json.loads(_regular(root, path.relative_to(root)))
            if parsed.get("capability_id") == capability_id:
                matches.append(path.relative_to(root))
        if len(matches) != 1:
            raise ContextError("CAPABILITY_SOURCE_CONFLICT")
        paths.append((matches[0], "dependency_capability"))

    seen: set[str] = set()
    records = []
    for relative, family in paths:
        key = relative.as_posix()
        if key in seen:
            continue
        seen.add(key)
        records.append(_record(root, relative, family))
    records.extend([
        _pseudo("git_repository", "GIT_VALUE", "git:HEAD", "git-object-name:HEAD", head),
        _pseudo("git_repository", "GIT_VALUE", "git:origin", "git-remote:origin", remote),
        _pseudo("git_repository", "SCHEDULER_BUNDLE", "scheduler:bundle", "scheduler-v1:authoritative-bundle", asdict(bundle)),
    ])
    records.sort(key=lambda item: (item["family"], item["locator"]))
    facts = {
        "task_source": task_path.as_posix(),
        "task_attempt": task["attempt"],
        "assignment_source": assignment_path.as_posix(),
        "handoff_binding_source": binding_path.as_posix(),
        "handoff_source": handoff_path.as_posix(),
        "dependency_ids": dependencies,
        "capability_ids": capabilities,
        "repository_root": str(root),
        "remote": remote,
        "head": head,
        "bundle": asdict(bundle),
    }
    return records, facts


def _observe_once(scheduler: Scheduler, task_id: str) -> dict[str, Any]:
    records, facts = _repository_records(scheduler, task_id)
    authority_result = read_locked_authority(scheduler, task_id)
    if authority_result.get("observation_status") != "COHERENT_DENY_ONLY":
        raise ContextError("RUNTIME_AUTHORITY_UNAVAILABLE")
    authority = authority_result["authority"]
    task = authority["task"]
    if task["task_id"] != task_id or task["tuple"]["attempt_no"] != facts["task_attempt"]:
        raise ContextError("TASK_ATTEMPT_MISMATCH")
    if authority["repository"] != facts["bundle"] or authority["runtime"]["bundle_digest"] != facts["bundle"]["digest"]:
        raise ContextError("REPOSITORY_RUNTIME_MISMATCH")
    attachment_raw = scheduler.attachment.read_bytes()
    attachment = json.loads(attachment_raw)
    if digest(attachment) != authority["runtime"]["attachment_digest"] or any(
        attachment.get(key) != value for key, value in authority["attachment"].items()
    ):
        raise ContextError("ATTACHMENT_MISMATCH")
    records.extend([
        _pseudo("runtime_subject", "RUNTIME_FILE", "runtime:attachment.json", "scheduler-v1:attachment-file", attachment_raw),
        _pseudo("runtime_subject", "LOCKED_SQLITE_PROJECTION", "sqlite:runtime.sqlite#locked-authority", "scheduler-v1:locked-authority", authority),
    ])
    records.sort(key=lambda item: (item["family"], item["locator"]))
    families = {
        family: digest([item for item in records if item["family"] == family])
        for family in sorted({item["family"] for item in records})
    }
    subject = {
        "task_id": task_id,
        "attempt": task["tuple"]["attempt_no"],
        "claim_id": task["tuple"]["active_claim_id"],
        "task_fence": task["tuple"]["task_fence"],
        "scheduler_generation": task["tuple"]["scheduler_generation"],
        "dispatch_generation": task["tuple"]["dispatch_generation"],
        "repository_generation": task["tuple"]["repository_generation"],
        "runtime_repository_generation": authority["runtime"]["repository_generation"],
        "runtime_id": authority["runtime"]["runtime_id"],
        "attachment_id": authority["attachment"]["attachment_id"],
        "authority_sha256": authority_result["authority_sha256"],
    }
    return {"source_records": records, "family_sha256": families, "source_facts": facts, "subject": subject}


def observe_context(
    scheduler: Scheduler,
    task_id: str,
    *,
    after_first_read: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Read/recheck repository and locked runtime state; reject any race."""
    scheduler.startup()
    first = _observe_once(scheduler, task_id)
    if after_first_read is not None:
        after_first_read()
    second = _observe_once(scheduler, task_id)
    if first != second:
        raise ContextError("OBSERVATION_RACE")
    return first


def _verification() -> dict[str, Any]:
    return {
        "currentness_status": "UNKNOWN",
        "verifier_status": "FAIL",
        "generation_match": False,
        "authorizing_use": "DENY",
        "authenticated_receipt": False,
        "atomic_cross_system_snapshot": False,
    }


def _schema(root: Path) -> Draft202012Validator:
    return Draft202012Validator(json.loads((root / SCHEMA_PATH).read_text(encoding="utf-8")))


def verify_context_integrity(record: dict[str, Any], *, root: Path = CANONICAL_ROOT) -> bool:
    """Check the closed artifact; a separately pinned raw digest is still required."""
    try:
        _schema(root).validate(record)
        if record["context_sha256"] != digest({key: value for key, value in record.items() if key != "context_sha256"}):
            return False
        if record["context_id"] != CONTEXT_ID or record["observation_boundary"]["mode"] != BOUNDARY:
            return False
        if record["verification"] != _verification() or tuple(record["supported_fresh_dimensions"]) != SUPPORTED or tuple(record["unknown_dimensions"]) != UNKNOWN or tuple(record["limitations"]) != LIMITATIONS:
            return False
        records = record["contextual_evidence"]["source_records"]
        if records != sorted(records, key=lambda item: (item["family"], item["locator"])):
            return False
        if len({(item["family"], item["locator"]) for item in records}) != len(records):
            return False
        for item in records:
            if item["observation_boundary"] != BOUNDARY:
                return False
            if item["kind"] == "REPOSITORY_FILE" and item["source_identity"] != "git-repository-file:" + item["locator"]:
                return False
        families = {family: digest([item for item in records if item["family"] == family]) for family in sorted({item["family"] for item in records})}
        if families != record["contextual_evidence"]["family_sha256"]:
            return False
        subject = record["contextual_evidence"]["subject"]
        facts = record["contextual_evidence"]["source_facts"]
        by_locator = {item["locator"]: item for item in records}
        historical = record["actual_m0_2_decision_inputs"]
        return all((
            record["task_id"] == subject["task_id"] == historical["task_id"],
            record["attempt"] == subject["attempt"] == historical["attempt"],
            historical["classification"] == "ACTUAL_FROZEN_M0_2_INPUT_CLOSURE",
            historical["not_retrofitted"] is True,
            record["contextual_evidence"]["classification"] == "SEPARATELY_OBSERVED_CONTEXT_NOT_DECISION_INPUT",
            facts["task_source"] in by_locator,
            facts["assignment_source"] in by_locator,
            facts["handoff_binding_source"] in by_locator,
            facts["handoff_source"] in by_locator,
            by_locator["git:HEAD"]["content_sha256"] == _sha(facts["head"].encode()),
            by_locator["git:origin"]["content_sha256"] == _sha(facts["remote"].encode()),
            by_locator["scheduler:bundle"]["content_sha256"] == _sha(json.dumps(facts["bundle"], sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()),
            by_locator["sqlite:runtime.sqlite#locked-authority"]["content_sha256"] == subject["authority_sha256"],
        ))
    except Exception:
        return False


def capture_context(
    scheduler: Scheduler,
    task_id: str,
    capture_id: str = DEFAULT_CAPTURE_ID,
    *,
    after_first_read: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Capture fresh context from canonical sources; no caller snapshot is accepted."""
    if scheduler.root != CANONICAL_ROOT:
        raise ContextError("NONCANONICAL_ROOT")
    diagnostic = diagnose_authoritative_currentness(scheduler, task_id, capture_id)
    if diagnostic.get("status") != "COHERENT_UNKNOWN_DENY":
        raise ContextError("HISTORICAL_DIAGNOSTIC_UNAVAILABLE")
    observed = observe_context(scheduler, task_id, after_first_read=after_first_read)
    if observed["subject"]["authority_sha256"] != diagnostic["current_observation"]["authority_sha256"]:
        raise ContextError("DIAGNOSTIC_CONTEXT_RACE")
    binding = diagnostic["historical_binding"]
    seal = binding["historical_seal"]
    record = {
        "schema_version": 1,
        "context_id": CONTEXT_ID,
        "capture_id": capture_id,
        "task_id": task_id,
        "attempt": binding["attempt"],
        "observation_boundary": {
            "mode": BOUNDARY,
            "repository_and_runtime_independently_rechecked": True,
            "atomic_cross_system_snapshot": False,
        },
        "actual_m0_2_decision_inputs": {
            "classification": "ACTUAL_FROZEN_M0_2_INPUT_CLOSURE",
            "task_id": seal["subject"]["task_id"],
            "attempt": seal["subject"]["attempt"],
            "capture_fixture_path": seal["capture"]["fixture_path"],
            "capture_sidecar_sha256": seal["capture"]["sidecar_sha256"],
            "historical_seal_sha256": seal["seal_sha256"],
            "authority_binding_sha256": binding["candidate_sha256"],
            "not_retrofitted": True,
        },
        "contextual_evidence": {
            "classification": "SEPARATELY_OBSERVED_CONTEXT_NOT_DECISION_INPUT",
            **observed,
        },
        "supported_fresh_dimensions": list(SUPPORTED),
        "unknown_dimensions": list(UNKNOWN),
        "verification": _verification(),
        "limitations": list(LIMITATIONS),
        "context_sha256": "",
    }
    record["context_sha256"] = digest({key: value for key, value in record.items() if key != "context_sha256"})
    _schema(scheduler.root).validate(record)
    if not verify_context_integrity(record, root=scheduler.root):
        raise ContextError("INTERNAL_INTEGRITY_FAILURE")
    return record


def compare_context(
    scheduler: Scheduler,
    retained_bytes: bytes,
    expected_artifact_sha256: str,
    *,
    after_first_read: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Reopen externally pinned retained bytes and compare newly observed state."""
    base = {
        "schema_version": 1,
        "comparison_id": "H-M0-188-CONTEXT-COMPARISON",
        "status": "EVIDENCE_REJECTED_DENY",
        "task_id": None,
        "retained_artifact_sha256": _sha(retained_bytes),
        "expected_artifact_sha256": expected_artifact_sha256,
        "changed_dimensions": [],
        "unchanged_dimensions": [],
        "failure_reason": None,
        "verification": _verification(),
        "comparison_sha256": "",
    }
    try:
        if _sha(retained_bytes) != expected_artifact_sha256:
            raise ContextError("ARTIFACT_DIGEST_MISMATCH")
        retained = json.loads(retained_bytes)
        if not verify_context_integrity(retained, root=CANONICAL_ROOT):
            raise ContextError("ARTIFACT_INTEGRITY_INVALID")
        current = observe_context(scheduler, retained["task_id"], after_first_read=after_first_read)
        old = retained["contextual_evidence"]
        dimensions = {
            "project_stop": old["family_sha256"]["project_stop"] == current["family_sha256"]["project_stop"],
            "assignment_handoff": old["family_sha256"]["assignment_handoff"] == current["family_sha256"]["assignment_handoff"],
            "dependency_capability": old["family_sha256"]["dependency_capability"] == current["family_sha256"]["dependency_capability"],
            "git_repository": old["family_sha256"]["git_repository"] == current["family_sha256"]["git_repository"],
            "attachment_task_attempt_claim_fence": (
                old["family_sha256"]["runtime_subject"] == current["family_sha256"]["runtime_subject"]
                and {key: old["subject"][key] for key in ("task_id", "attempt", "claim_id", "task_fence", "runtime_id", "attachment_id")}
                == {key: current["subject"][key] for key in ("task_id", "attempt", "claim_id", "task_fence", "runtime_id", "attachment_id")}
            ),
            "runtime_generation": (
                {key: old["subject"][key] for key in ("scheduler_generation", "dispatch_generation", "repository_generation", "runtime_repository_generation")}
                == {key: current["subject"][key] for key in ("scheduler_generation", "dispatch_generation", "repository_generation", "runtime_repository_generation")}
            ),
        }
        base.update({
            "status": "UNCHANGED_CONTEXT_UNKNOWN_DENY" if all(dimensions.values()) else "DRIFT_DETECTED_DENY",
            "task_id": retained["task_id"],
            "changed_dimensions": [key for key, same in dimensions.items() if not same],
            "unchanged_dimensions": [key for key, same in dimensions.items() if same],
        })
    except ContextError as error:
        base["failure_reason"] = error.code
    except Exception:
        base["failure_reason"] = "INTERNAL_FAILURE"
    base["comparison_sha256"] = digest({key: value for key, value in base.items() if key != "comparison_sha256"})
    return base


def format_human(record: dict[str, Any]) -> str:
    if "comparison_id" in record:
        lines = [
            "EdgeLab H-M0-188 context comparison",
            "Status: " + record["status"],
            "Currentness: UNKNOWN",
            "Authorization: DENY",
        ]
        if record["failure_reason"]:
            lines.append("Failure: " + record["failure_reason"])
        if record["changed_dimensions"]:
            lines.append("Changed: " + ", ".join(record["changed_dimensions"]))
        return "\n".join(lines) + "\n"
    return "\n".join([
        "EdgeLab H-M0-188 decision-time context",
        "Task: " + record["task_id"],
        "Boundary: " + record["observation_boundary"]["mode"],
        "Currentness: UNKNOWN",
        "Authorization: DENY",
        "Context digest is not an authenticated receipt.",
    ]) + "\n"
