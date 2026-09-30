"""Repository-resolved, offline M0.2 synthetic scheduler preflight.

This module is deliberately a decision *boundary*, not an executor.  It only
authorizes a mock-only synthetic task whose complete semantics are persisted in
this repository.  Completion and review transitions remain unavailable pending
the authenticated append-only evidence future gate.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
from typing import Any

from jsonschema import Draft202012Validator

from .validate import ROOT, read, validate_record


EXPECTED_REMOTE = "https://github.com/dylanlaewe/EdgeLab.git"
SAFE_OPERATIONS = frozenset({"STATE_READ", "SCHEMA_WRITE", "SYNTHETIC_ASSERT"})
SAFE_EFFECTS = frozenset({"REPOSITORY_READ", "REPOSITORY_WRITE"})
PROHIBITED_SEMANTICS = frozenset({"PLUGIN_INSTALL", "PLUGIN_ACTIVATE", "SKILL_INSTALL", "SKILL_ACTIVATE", "MCP", "NETWORK", "CREDENTIAL", "EXTERNAL_EXECUTION", "SPORTS_SOURCE_ACQUISITION", "EXTERNAL_DATA_INGESTION", "PAPER", "LIVE", "CAPITAL_MUTATION", "VENUE", "ACCOUNT"})
REQUIRED_PROJECT_STATUS = "BLOCKED_FOR_APPROVAL_REMEDIATION_ALLOWED"


def _remote(root: Path) -> str:
    """Return the canonical origin URL without accepting caller supplied identity."""
    return subprocess.run(
        ["git", "-C", str(root), "remote", "get-url", "origin"],
        text=True,
        capture_output=True,
        check=False,
    ).stdout.strip()


def _is_ancestor_of_remote_main(root: Path) -> bool:
    """Require the checkout's committed history to be reachable from origin/main."""
    return subprocess.run(
        ["git", "-C", str(root), "merge-base", "--is-ancestor", "HEAD", "origin/main"],
        text=True,
        capture_output=True,
        check=False,
    ).returncode == 0


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_scheduler_state(root: Path) -> dict[str, Any]:
    state = read(root / "orchestration/scheduler-state.json")
    schema = read(root / "schemas/scheduler-state.schema.json")
    errors = sorted(Draft202012Validator(schema).iter_errors(state), key=lambda error: list(error.path))
    if errors:
        raise ValueError("Invalid authoritative scheduler state")
    return state


def _validate_identity(root: Path) -> None:
    # resolve accepts a symlink to this checkout, but rejects copied lookalikes.
    if (
        root.resolve() != ROOT.resolve()
        or _remote(root) != EXPECTED_REMOTE
        or not _is_ancestor_of_remote_main(root)
    ):
        raise ValueError("Repository identity denied")


def _validate_project_and_stops(root: Path, state: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    project_ref = state["project_state"]["ref"]
    project_path = root / project_ref
    if _sha256(project_path) != state["project_state"]["sha256"]:
        raise ValueError("Authoritative project state changed")
    project = read(project_path)
    validate_record("project-state", project, root)

    actual_stop_paths = sorted((root / "reports/stops").glob("STOP-*.v*.json"))
    state_stop_refs = {item["ref"]: item["sha256"] for item in state["stops"]}
    actual_stop_refs = {str(path.relative_to(root)): _sha256(path) for path in actual_stop_paths}
    if state_stop_refs != actual_stop_refs:
        raise ValueError("STOP inventory is incomplete, altered, or superseded")
    stops = []
    for path in actual_stop_paths:
        stop = read(path)
        validate_record("stop", stop, root)
        stops.append(stop)

    if project["phase"] != "M0" or project["status"] != REQUIRED_PROJECT_STATUS:
        raise ValueError("Current project state denies dispatch")
    heads: dict[str, dict[str, Any]] = {}
    for stop in stops:
        if stop["id"] in heads and heads[stop["id"]]["version"] == stop["version"]:
            raise ValueError("Conflicting STOP head")
        if stop["id"] not in heads or stop["version"] > heads[stop["id"]]["version"]:
            heads[stop["id"]] = stop
    if heads.get("STOP-M0-001", {}).get("status") != "OPEN":
        raise ValueError("STOP-M0-001 must remain OPEN")
    if any(stop_id != "STOP-M0-001" and stop["status"] == "OPEN" for stop_id, stop in heads.items()):
        raise ValueError("Unknown OPEN STOP applicability denies dispatch")
    if project["live_status"] != "LOCKED":
        raise ValueError("Live state must remain locked")
    return project, stops


def _validate_capabilities(root: Path, task: dict[str, Any]) -> None:
    """Deny unknown, unsafe, unapproved, or revoked capability references."""
    if not task["capability_refs"]:
        raise ValueError("Effect-bearing task requires explicit capability")
    for capability_id in task["capability_refs"]:
        matches = []
        for path in sorted((root / "orchestration/capabilities").glob("*.json")):
            record = read(path)
            validate_record("capability-registry", record, root)
            if record["capability_id"] == capability_id:
                matches.append(record)
        if len(matches) != 1:
            raise ValueError("Capability reference is unknown or ambiguous")
        capability = matches[0]
        if (
            capability["network_required"]
            or capability["credential_required"]
            or capability["executable_code"]
            or capability["external_dependencies"]
            or capability["revoked"]
            or capability["trust_status"] != "TRUSTED"
            or capability["approval_status"] != "APPROVED"
            or capability["security_review"] != "REVIEWED"
            or set(capability["semantic_types"]) & PROHIBITED_SEMANTICS
            or not set(capability["semantic_types"]).issubset(SAFE_EFFECTS)
            or task["assigned_role"] not in capability["intended_roles"]
            or not set(task["effects"]).issubset(set(capability["permissions"]))
        ):
            raise ValueError("Capability violates mock-only boundary")


def _current_handoff(root: Path, ref: str) -> dict[str, Any]:
    handoffs = []
    for path in (root / "docs/handoffs").glob("*.json"):
        record = read(path)
        if str(path.relative_to(root)) == ref:
            handoffs.append(record)
    if len(handoffs) != 1 or handoffs[0]["status"] != "CLAIMED":
        raise ValueError("Claim handoff is not current and active")
    record = handoffs[0]
    newer = [read(path) for path in (root / "docs/handoffs").glob(f"{record['id']}.v*.json")]
    if any(item["version"] > record["version"] for item in newer):
        raise ValueError("Claim handoff has been superseded")
    return record


def _validate_dependencies(root: Path, state: dict[str, Any], task: dict[str, Any], seen: set[str] | None = None) -> None:
    seen = set() if seen is None else seen
    if task["task_id"] in seen:
        raise ValueError("Dependency graph is cyclic")
    seen.add(task["task_id"])
    for dependency in task["dependencies"]:
        ref = state["tasks"].get(dependency)
        if not ref:
            raise ValueError("Dependency task is unknown")
        dep = read(root / ref); validate_record("orchestration-task", dep, root)
        if dep["task_id"] != dependency or dep["status"] != "COMPLETED" or not dep["completion_evidence"]:
            raise ValueError("Dependency lacks verified synthetic completion")
        _validate_dependencies(root, state, dep, seen)
    seen.remove(task["task_id"])


def _validate_task(root: Path, state: dict[str, Any], intent: dict[str, Any]) -> dict[str, Any]:
    if set(intent) != {"task_id", "attempt"} or not isinstance(intent["task_id"], str) or type(intent["attempt"]) is not int:
        raise ValueError("Intent may name only an authoritative task and attempt")
    task_ref = state["tasks"].get(intent["task_id"])
    if task_ref is None:
        raise ValueError("Unknown authoritative task")
    task = read(root / task_ref)
    validate_record("orchestration-task", task, root)
    if task["task_id"] != intent["task_id"] or task["attempt"] != intent["attempt"]:
        raise ValueError("Intent does not match authoritative task")
    if task["status"] != "QUEUED" or task["operation"] not in SAFE_OPERATIONS:
        raise ValueError("Task state or operation is not dispatchable")
    if not set(task["effects"]).issubset(SAFE_EFFECTS):
        raise ValueError("Task effect exceeds synthetic boundary")

    claim = state["claims"].get(task["task_id"])
    active_claims = [item for item in state["claims"].values() if item["status"] == "ACTIVE"]
    expected_claim = {
        "role": task["assigned_role"],
        "attempt": task["attempt"],
        "status": "ACTIVE",
        "handoff_ref": task["handoff_ref"],
        "generation": state["generation"],
    }
    if claim != expected_claim or len(active_claims) != 1:
        raise ValueError("Authoritative writer claim is absent or conflicted")
    _current_handoff(root, task["handoff_ref"])
    _validate_dependencies(root, state, task)
    _validate_capabilities(root, task)
    return task


def decision(root: Path, intent: dict[str, Any], **legacy_inputs: Any) -> dict[str, Any]:
    """Preflight one repository-resolved task; never execute it.

    Legacy task, dependency, writer, capability, or completion arguments are
    rejected so callers cannot regain authority through an old API shape.
    """
    try:
        if legacy_inputs:
            raise ValueError("Caller-controlled scheduler inputs are denied")
        _validate_identity(root)
        state = _load_scheduler_state(root)
        project, stops = _validate_project_and_stops(root, state)
        task = _validate_task(root, state, intent)
        return {
            "decision": "DISPATCH",
            "decision_id": "D-" + hashlib.sha256((str(state["generation"]) + task["task_id"] + str(task["attempt"]) + task["handoff_ref"] + _sha256(root / "docs/project-state.json") + "".join(sorted(_sha256(root / item["ref"]) for item in state["stops"])) + str(state["claims"]) + str(task["dependencies"]) + str(task["capability_refs"]) + "DISPATCH").encode()).hexdigest()[:24],
            "task_id": task["task_id"],
            "reason": "repository-resolved synthetic task passed preflight",
            "execution_adapter": "MOCK_ONLY",
            "operation": task["operation"],
        }
    except Exception as error:
        task_id = intent.get("task_id") if isinstance(intent, dict) else None
        return {
            "decision": "DENY",
            "decision_id": "D-DENY-" + hashlib.sha256(str(error).encode()).hexdigest()[:24],
            "task_id": task_id,
            "reason": str(error),
            "execution_adapter": "MOCK_ONLY",
        }


def completion(*_: Any, **__: Any) -> None:
    """Fail closed until the authenticated append-only evidence gate exists."""
    raise ValueError("Completion and review transitions unavailable pending FUTURE_GATE")
