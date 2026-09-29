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


def _validate_project_and_stops(root: Path, state: dict[str, Any]) -> None:
    project_ref = state["project_state"]["ref"]
    project_path = root / project_ref
    if _sha256(project_path) != state["project_state"]["sha256"]:
        raise ValueError("Authoritative project state changed")
    project = read(project_path)
    validate_record("project-state", project, root)

    actual_stop_paths = sorted((root / "reports/stops").glob("STOP-M0-001.v*.json"))
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
    if len(stops) != 1 or stops[0]["id"] != "STOP-M0-001" or stops[0]["status"] != "OPEN":
        raise ValueError("STOP-M0-001 must be uniquely OPEN")
    if project["live_status"] != "LOCKED":
        raise ValueError("Live state must remain locked")


def _validate_capabilities(root: Path, task: dict[str, Any]) -> None:
    """Deny unknown, unsafe, unapproved, or revoked capability references."""
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
        ):
            raise ValueError("Capability violates mock-only boundary")


def _validate_task(root: Path, state: dict[str, Any], intent: dict[str, Any]) -> dict[str, Any]:
    if set(intent) != {"task_id", "attempt"} or not isinstance(intent["task_id"], str) or not isinstance(intent["attempt"], int):
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
    if task["handoff_ref"] != "docs/handoffs/H-M0-028.v2.json":
        raise ValueError("Task is not bound to the current remediation claim")
    if task["task_id"] in task["dependencies"] or any(
        dependency not in state["completed_tasks"] for dependency in task["dependencies"]
    ):
        raise ValueError("Dependencies are incomplete or cyclic")
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
        _validate_project_and_stops(root, state)
        task = _validate_task(root, state, intent)
        return {
            "decision": "DISPATCH",
            "decision_id": f"D-{state['generation']}-{task['task_id']}-{task['attempt']}",
            "task_id": task["task_id"],
            "reason": "repository-resolved synthetic task passed preflight",
            "execution_adapter": "MOCK_ONLY",
            "operation": task["operation"],
        }
    except Exception as error:
        task_id = intent.get("task_id") if isinstance(intent, dict) else None
        return {
            "decision": "DENY",
            "task_id": task_id,
            "reason": str(error),
            "execution_adapter": "MOCK_ONLY",
        }


def completion(*_: Any, **__: Any) -> None:
    """Fail closed until the authenticated append-only evidence gate exists."""
    raise ValueError("Completion and review transitions unavailable pending FUTURE_GATE")
