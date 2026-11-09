"""Cold-process recovery for the H-M0-184 synthetic research workflow.

This module adds no scheduler operation or persistence field.  It treats a
successful Scheduler.startup()/replay and the locked-authority projection as
the only source of durable progress, validates the exact H-M0-184 evidence
chain, and either performs the next already-supported transition or denies.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .scheduler_coordinated_research import (
    CANONICAL_ROOT,
    DIRECTOR_TASK_ID,
    PINNED_H183_RESULT_SHA256,
    PINNED_INPUT_SHA256,
    PIPELINE_TASK_ID,
    RESULT_SCHEMA_PATH as H184_RESULT_SCHEMA_PATH,
    RISK_TASK_ID,
    SchedulerResearchError,
    _data_stage,
    _director_stage,
    _evidence_sha,
    _load_retained,
    _locked_request,
    _quant_stage,
    _research_stage,
    _risk_stage,
    _skeptic_stage,
    _stable_history,
    _transition,
)
from .synthetic_research_experiment import (
    _load_schema,
    _validate_schema,
    evaluate_scientific_package,
)
from .transactional_scheduler import RuntimeUnavailable, Scheduler, digest


RESULT_SCHEMA_PATH = Path("schemas/recoverable-scheduler-research-result.v1.schema.json")
INTEGRATION_ID = "H-M0-186-RECOVERABLE-SCHEDULER-RESEARCH"
INTERRUPTION_POINTS = ("RESEARCH", "QUANT", "REVIEW_ASSIGNED", "RISK_CREATED")
EXPECTED_TASKS = {PIPELINE_TASK_ID, RISK_TASK_ID, DIRECTOR_TASK_ID}


class RecoveryError(SchedulerResearchError):
    """The persisted workflow cannot be recovered without inventing authority."""


def _deny(code: str, message: str) -> None:
    raise RecoveryError(code, message)


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        _deny(code, message)


def _pipeline_receipt(package: dict[str, Any]) -> str:
    return digest({
        "contract": "H-M0-184-SCHEDULER-COORDINATED-SCIENCE-V1",
        "input_package_sha256": PINNED_INPUT_SHA256,
        "hypothesis_sha256": package["hypothesis_ref"]["sha256"],
        "authorizing_use": "DENY",
    })


def _route_sha(quant_sha: str, skeptic_sha: str) -> str:
    return digest({
        "scope": "SYNTHETIC_SCIENTIFIC_FINDINGS_ONLY",
        "quant_evidence_sha256": quant_sha,
        "skeptic_evidence_sha256": skeptic_sha,
        "formal_approval": False,
        "authorizing_use": "DENY",
    })


def _task_inventory(scheduler: Scheduler) -> dict[str, dict[str, Any]]:
    snapshot = scheduler.export(scheduler.dir / "h-m0-186-recovery-snapshot.json")
    inventory = {task["task_id"]: task for task in snapshot["tasks"]}
    unexpected = set(inventory) - EXPECTED_TASKS
    _require(not unexpected, "UNEXPECTED_TASK_IN_RUNTIME", ",".join(sorted(unexpected)))
    return inventory


def _authority(scheduler: Scheduler, task_id: str) -> dict[str, Any]:
    # _locked_request validates the deny-only locked reader, current bundle,
    # task generation, and exact receipt before returning transition inputs.
    _locked_request(scheduler, task_id)
    from .locked_authority import read_locked_authority

    record = read_locked_authority(scheduler, task_id)
    authority = record.get("authority")
    _require(
        record.get("observation_status") == "COHERENT_DENY_ONLY"
        and isinstance(authority, dict),
        "LOCKED_AUTHORITY_INVALID",
        task_id,
    )
    return authority


def _claim_identity(
    scheduler: Scheduler, task_id: str, expected_actor: str
) -> tuple[str, int]:
    authority = _authority(scheduler, task_id)
    claim = authority.get("claim")
    task_tuple = authority["task"]["tuple"]
    _require(
        isinstance(claim, dict)
        and claim.get("status") == "ACTIVE"
        and claim.get("actor") == expected_actor
        and claim.get("claim_id") == task_tuple["active_claim_id"]
        and claim.get("fence") == task_tuple["task_fence"],
        "ACTIVE_CLAIM_INVALID",
        task_id,
    )
    return claim["claim_id"], claim["fence"]


def _review_identity(scheduler: Scheduler) -> str:
    authority = _authority(scheduler, PIPELINE_TASK_ID)
    review = authority.get("review")
    task_tuple = authority["task"]["tuple"]
    _require(
        isinstance(review, dict)
        and review.get("status") == "ACTIVE"
        and review.get("actor") == "synthetic-skeptic"
        and review.get("role") == "05 Skeptic synthetic non-formal"
        and review.get("assignment_id") == task_tuple["reviewer_assignment_id"],
        "ACTIVE_REVIEW_INVALID",
        PIPELINE_TASK_ID,
    )
    return review["assignment_id"]


def _pipeline_expected_events(
    receipt: str,
    research_sha: str,
    data_sha: str,
    quant_sha: str,
    skeptic_sha: str,
    route_sha: str,
) -> list[dict[str, Any]]:
    return [
        {"task_seq": 1, "event_type": "TASK_INITIALIZED", "receipt_digest": receipt, "owner": "03 Research synthetic coordinator"},
        {"task_seq": 2, "event_type": "CLAIM_ISSUED"},
        {"task_seq": 3, "event_type": "TASK_STARTED"},
        {"task_seq": 4, "event_type": "TASK_CONTINUED", "stage": "RESEARCH", "input_evidence_sha256": PINNED_INPUT_SHA256, "output_evidence_sha256": research_sha},
        {"task_seq": 5, "event_type": "TASK_CONTINUED", "stage": "DATA", "input_evidence_sha256": research_sha, "output_evidence_sha256": data_sha},
        {"task_seq": 6, "event_type": "TASK_CONTINUED", "stage": "QUANT", "input_evidence_sha256": data_sha, "output_evidence_sha256": quant_sha},
        {"task_seq": 7, "event_type": "TASK_COMPLETED", "completion_evidence_sha256": quant_sha},
        {"task_seq": 8, "event_type": "REVIEW_ASSIGNED", "actor": "synthetic-skeptic", "role": "05 Skeptic synthetic non-formal"},
        {"task_seq": 9, "event_type": "REVIEW_APPROVED", "decision_digest": skeptic_sha},
        {"task_seq": 10, "event_type": "DIRECTOR_ROUTED", "routing_evidence": route_sha},
    ]


def _expected_pipeline_state(event_count: int) -> tuple[str, str, str, int]:
    states = {
        1: ("ACTIVE", "CLAIMABLE", "NOT_REQUIRED", 0),
        2: ("ACTIVE", "CLAIMED", "NOT_REQUIRED", 0),
        3: ("ACTIVE", "IN_PROGRESS", "NOT_REQUIRED", 0),
        4: ("ACTIVE", "IN_PROGRESS", "NOT_REQUIRED", 1),
        5: ("ACTIVE", "IN_PROGRESS", "NOT_REQUIRED", 2),
        6: ("ACTIVE", "IN_PROGRESS", "NOT_REQUIRED", 3),
        7: ("ACTIVE", "EXECUTION_COMPLETED", "REVIEW_PENDING", 3),
        8: ("ACTIVE", "EXECUTION_COMPLETED", "REVIEWING", 3),
        9: ("ACTIVE", "EXECUTION_COMPLETED", "APPROVED", 3),
        10: ("DIRECTOR_GATE_READY", "EXECUTION_COMPLETED", "APPROVED", 3),
    }
    if event_count not in states:
        _deny("PIPELINE_HISTORY_UNRECOVERABLE", str(event_count))
    return states[event_count]


def _validate_pipeline_prefix(
    scheduler: Scheduler,
    receipt: str,
    evidence: dict[str, str],
) -> tuple[dict[str, Any], int]:
    history = _stable_history(scheduler, PIPELINE_TASK_ID)
    expected = _pipeline_expected_events(
        receipt,
        evidence["research"],
        evidence["data"],
        evidence["quant"],
        evidence["synthetic_skeptic"],
        evidence["route"],
    )
    events = history["events"]
    _require(
        history["receipt_digest"] == receipt
        and history["owner"] == "03 Research synthetic coordinator"
        and events == expected[: len(events)],
        "PIPELINE_HISTORY_MISMATCH",
        PIPELINE_TASK_ID,
    )
    logical_count = len(events)
    workflow, execution, review, continuations = _expected_pipeline_state(
        logical_count
    )
    _require(
        history["final_state"] == {
            "workflow": workflow,
            "execution": execution,
            "review": review,
            "continuation_count": continuations,
        },
        "PIPELINE_STATE_MISMATCH",
        PIPELINE_TASK_ID,
    )
    if execution in {"CLAIMED", "IN_PROGRESS"}:
        _claim_identity(scheduler, PIPELINE_TASK_ID, "synthetic-science-worker")
    if review == "REVIEWING":
        _review_identity(scheduler)
    return history, logical_count


def _closed_task_expected_events(
    receipt: str, owner: str, evidence_sha: str
) -> list[dict[str, Any]]:
    return [
        {"task_seq": 1, "event_type": "TASK_INITIALIZED", "receipt_digest": receipt, "owner": owner},
        {"task_seq": 2, "event_type": "CLAIM_ISSUED"},
        {"task_seq": 3, "event_type": "TASK_STARTED"},
        {"task_seq": 4, "event_type": "TASK_COMPLETED", "completion_evidence_sha256": evidence_sha, "close": True},
    ]


def _validate_closed_task_prefix(
    scheduler: Scheduler,
    *,
    task_id: str,
    receipt: str,
    owner: str,
    actor: str,
    evidence_sha: str,
) -> tuple[dict[str, Any], int]:
    history = _stable_history(scheduler, task_id)
    expected = _closed_task_expected_events(receipt, owner, evidence_sha)
    events = history["events"]
    _require(
        history["receipt_digest"] == receipt
        and history["owner"] == owner
        and events == expected[: len(events)]
        and 1 <= len(events) <= 4,
        "TASK_HISTORY_MISMATCH",
        task_id,
    )
    states = {
        1: ("ACTIVE", "CLAIMABLE", "NOT_REQUIRED"),
        2: ("ACTIVE", "CLAIMED", "NOT_REQUIRED"),
        3: ("ACTIVE", "IN_PROGRESS", "NOT_REQUIRED"),
        4: ("CLOSED", "EXECUTION_COMPLETED", "NOT_REQUIRED"),
    }
    logical_count = len(events)
    workflow, execution, review = states[logical_count]
    _require(
        history["final_state"] == {
            "workflow": workflow,
            "execution": execution,
            "review": review,
            "continuation_count": 0,
        },
        "TASK_STATE_MISMATCH",
        task_id,
    )
    if execution in {"CLAIMED", "IN_PROGRESS"}:
        _claim_identity(scheduler, task_id, actor)
    return history, logical_count


def _claim_and_start(
    scheduler: Scheduler, task_id: str, actor: str, prefix: str
) -> tuple[str, int]:
    claimed = _transition(scheduler, "CLAIM", task_id, {"actor": actor}, f"{prefix}-claim")
    claim_id = claimed["tuple"]["active_claim_id"]
    fence = claimed["tuple"]["task_fence"]
    _transition(
        scheduler,
        "START",
        task_id,
        {"claim_id": claim_id, "fence": fence},
        f"{prefix}-start",
    )
    return claim_id, fence


def _checkpoint_result(
    scheduler: Scheduler,
    *,
    interruption_after: str,
    resume_from: str,
) -> dict[str, Any]:
    scheduler.startup()
    inventory = _task_inventory(scheduler)
    result = {
        "schema_version": 1,
        "integration_id": INTEGRATION_ID,
        "mode": "SYNTHETIC_LOCAL_ONLY",
        "status": "INTERRUPTED",
        "interruption_after": interruption_after,
        "recovered_from": resume_from,
        "durable_task_states": {
            task_id: {
                "workflow": task["workflow"],
                "execution": task["execution"],
                "review": task["review"],
                "continuation_count": task["continuations"],
            }
            for task_id, task in sorted(inventory.items())
        },
        "coordinated_result": None,
        "replay": "PASSED",
        "authorization": _authorization(),
        "formal_skeptic_approval": False,
        "result_sha256": "",
    }
    result["result_sha256"] = digest({k: v for k, v in result.items() if k != "result_sha256"})
    return result


def _authorization() -> dict[str, Any]:
    return {
        "authorizing_use": "DENY",
        "operational_release": "DENIED",
        "paper_trading": "DENIED",
        "live": "LOCKED",
        "kill": "ENGAGED",
        "deployable_capital_usd": "0.00",
    }


def _assemble_h184_result(
    *,
    root: Path,
    research: dict[str, Any],
    data: dict[str, Any],
    quant: dict[str, Any],
    skeptic: dict[str, Any],
    risk: dict[str, Any],
    director: dict[str, Any],
    pipeline_history: dict[str, Any],
    risk_history: dict[str, Any],
    director_history: dict[str, Any],
) -> dict[str, Any]:
    def event_seq(
        history: dict[str, Any], event_type: str, *, stage: str | None = None
    ) -> int:
        matches = [
            event["task_seq"]
            for event in history["events"]
            if event["event_type"] == event_type
            and (stage is None or event.get("stage") == stage)
        ]
        _require(len(matches) == 1, "TASK_HISTORY_MISMATCH", event_type)
        return matches[0]

    evidence = {
        "research": _evidence_sha(research),
        "data": _evidence_sha(data),
        "quant": _evidence_sha(quant),
        "synthetic_skeptic": _evidence_sha(skeptic),
        "risk": _evidence_sha(risk),
        "director": _evidence_sha(director),
    }
    pipeline_history_sha = digest(pipeline_history)
    risk_history_sha = digest(risk_history)
    risk_receipt = risk_history["receipt_digest"]
    director_receipt = director_history["receipt_digest"]
    stages = {
        "research": {"evidence": research, "evidence_sha256": evidence["research"], "scheduler_binding": {"task_id": PIPELINE_TASK_ID, "task_seq": event_seq(pipeline_history, "TASK_CONTINUED", stage="RESEARCH"), "event_type": "TASK_CONTINUED"}},
        "data": {"evidence": data, "evidence_sha256": evidence["data"], "scheduler_binding": {"task_id": PIPELINE_TASK_ID, "task_seq": event_seq(pipeline_history, "TASK_CONTINUED", stage="DATA"), "event_type": "TASK_CONTINUED", "depends_on_evidence_sha256": evidence["research"]}},
        "quant": {"evidence": quant, "evidence_sha256": evidence["quant"], "scheduler_binding": {"task_id": PIPELINE_TASK_ID, "task_seq": event_seq(pipeline_history, "TASK_CONTINUED", stage="QUANT"), "event_type": "TASK_CONTINUED", "depends_on_evidence_sha256": evidence["data"]}},
        "synthetic_skeptic": {"evidence": skeptic, "evidence_sha256": evidence["synthetic_skeptic"], "scheduler_binding": {"task_id": PIPELINE_TASK_ID, "task_seq": event_seq(pipeline_history, "REVIEW_APPROVED"), "event_type": "REVIEW_APPROVED", "review_actor": "synthetic-skeptic", "formal_approval": False, "depends_on_evidence_sha256": evidence["quant"]}},
        "risk": {"evidence": risk, "evidence_sha256": evidence["risk"], "scheduler_binding": {"task_id": RISK_TASK_ID, "task_seq": event_seq(risk_history, "TASK_COMPLETED"), "event_type": "TASK_COMPLETED", "origin_receipt_digest": risk_receipt, "depends_on_history_sha256": pipeline_history_sha}},
        "director": {"evidence": director, "evidence_sha256": evidence["director"], "scheduler_binding": {"task_id": DIRECTOR_TASK_ID, "task_seq": event_seq(director_history, "TASK_COMPLETED"), "event_type": "TASK_COMPLETED", "origin_receipt_digest": director_receipt, "depends_on_history_sha256": risk_history_sha}},
    }
    result = {
        "schema_version": 1,
        "integration_id": "H-M0-184-SCHEDULER-COORDINATED-RESEARCH",
        "mode": "SYNTHETIC_LOCAL_ONLY",
        "input_package_sha256": PINNED_INPUT_SHA256,
        "h_m0_183_result_sha256": PINNED_H183_RESULT_SHA256,
        "stages": stages,
        "task_histories": {"pipeline": pipeline_history, "risk": risk_history, "director": director_history},
        "dependency_model": {
            "status": "COORDINATOR_ENFORCED_CONTENT_BOUND_RECEIPTS",
            "native_general_dependency_edge": False,
            "remediation_links_used_as_dependencies": False,
            "limitation": "Scheduler v1 stores task-origin receipt digests and event payloads but has no native general prerequisite edge or typed scientific evidence table.",
        },
        "replay": "PASSED",
        "final_result": director["output"]["experiment_result"],
        "authorization": _authorization(),
        "formal_skeptic_approval": False,
        "result_sha256": "",
    }
    result["result_sha256"] = digest({k: v for k, v in result.items() if k != "result_sha256"})
    _validate_schema(root, H184_RESULT_SCHEMA_PATH, result)
    return result


def _completed_result(
    scheduler: Scheduler,
    *,
    root: Path,
    recovered_from: str,
    science: dict[str, dict[str, Any]],
    pipeline_history: dict[str, Any],
    risk_history: dict[str, Any],
    director_history: dict[str, Any],
) -> dict[str, Any]:
    coordinated = _assemble_h184_result(
        root=root,
        research=science["research"],
        data=science["data"],
        quant=science["quant"],
        skeptic=science["synthetic_skeptic"],
        risk=science["risk"],
        director=science["director"],
        pipeline_history=pipeline_history,
        risk_history=risk_history,
        director_history=director_history,
    )
    scheduler.startup()
    result = {
        "schema_version": 1,
        "integration_id": INTEGRATION_ID,
        "mode": "SYNTHETIC_LOCAL_ONLY",
        "status": "COMPLETED",
        "interruption_after": None,
        "recovered_from": recovered_from,
        "durable_task_states": {
            key: value["final_state"]
            for key, value in coordinated["task_histories"].items()
        },
        "coordinated_result": coordinated,
        "replay": "PASSED",
        "authorization": _authorization(),
        "formal_skeptic_approval": False,
        "result_sha256": "",
    }
    result["result_sha256"] = digest({k: v for k, v in result.items() if k != "result_sha256"})
    _validate_schema(root, RESULT_SCHEMA_PATH, result)
    return result


def _derive_resume_point(inventory: dict[str, dict[str, Any]]) -> str:
    if DIRECTOR_TASK_ID in inventory:
        state = inventory[DIRECTOR_TASK_ID]
        if state["workflow"] == "CLOSED":
            return "COMPLETED"
        return "DIRECTOR"
    if RISK_TASK_ID in inventory:
        state = inventory[RISK_TASK_ID]
        if state["workflow"] == "CLOSED":
            return "RISK_COMPLETED"
        return "RISK"
    if PIPELINE_TASK_ID not in inventory:
        return "NEW"
    state = inventory[PIPELINE_TASK_ID]
    if state["workflow"] == "DIRECTOR_GATE_READY":
        return "PIPELINE_ROUTED"
    if state["review"] == "REVIEWING":
        return "REVIEW_ASSIGNED"
    if state["review"] == "REVIEW_PENDING":
        return "QUANT_COMPLETED"
    return {0: "STARTED", 1: "RESEARCH", 2: "DATA", 3: "QUANT"}.get(
        state["continuations"], "UNRECOVERABLE"
    )


def run_recoverable_scheduler_research(
    runtime_dir: Path,
    *,
    root: Path = CANONICAL_ROOT,
    resume: bool = False,
    interrupt_after: str | None = None,
) -> dict[str, Any]:
    """Create or cold-resume one bounded H-M0-184 Scheduler v1 runtime."""
    root = root.resolve()
    runtime_dir = runtime_dir.resolve()
    _require(root == CANONICAL_ROOT, "NONCANONICAL_ROOT", str(root))
    _require(runtime_dir != root and not runtime_dir.is_relative_to(root), "INVALID_RUNTIME_PATH", str(runtime_dir))
    _require(interrupt_after is None or interrupt_after in INTERRUPTION_POINTS, "INVALID_INTERRUPTION_POINT", str(interrupt_after))
    _require(resume == runtime_dir.exists(), "RUNTIME_MODE_MISMATCH", str(runtime_dir))

    result_schema = _load_schema(root, RESULT_SCHEMA_PATH)
    package, retained = _load_retained(root)
    scheduler = Scheduler(root, runtime_dir)
    if resume:
        scheduler.startup()
    else:
        scheduler.initialize()

    initial_inventory = _task_inventory(scheduler)
    recovered_from = _derive_resume_point(initial_inventory)
    _require(recovered_from != "UNRECOVERABLE", "UNRECOVERABLE_STATE", "continuation count")

    # Retained evidence supplies the expected digests used to inspect partial
    # history.  Stage functions themselves run only after their scheduler
    # predecessor has been verified, including during cold recovery.
    evidence = {
        name: _evidence_sha(retained["stages"][name])
        for name in (
            "research", "data", "quant", "synthetic_skeptic", "risk", "director"
        )
    }
    evidence["route"] = _route_sha(evidence["quant"], evidence["synthetic_skeptic"])
    receipt = _pipeline_receipt(package)
    science: dict[str, dict[str, Any]] = {}

    inventory = _task_inventory(scheduler)
    if PIPELINE_TASK_ID not in inventory:
        scheduler.create_task(PIPELINE_TASK_ID, receipt, "03 Research synthetic coordinator")
    _, pipeline_count = _validate_pipeline_prefix(scheduler, receipt, evidence)
    if pipeline_count == 1:
        _claim_and_start(scheduler, PIPELINE_TASK_ID, "synthetic-science-worker", "science")
        _, pipeline_count = _validate_pipeline_prefix(scheduler, receipt, evidence)
    if pipeline_count == 2:
        _deny(
            "CLAIMED_WITHOUT_AUTHENTICATED_LIVENESS",
            "Scheduler v1 RECOVER requires lease/liveness evidence that H-M0-186 cannot authenticate",
        )

    _, pipeline_count = _validate_pipeline_prefix(scheduler, receipt, evidence)
    if 3 <= pipeline_count <= 10:
        claim_id: str | None = None
        fence: int | None = None
        if pipeline_count <= 6:
            claim_id, fence = _claim_identity(
                scheduler, PIPELINE_TASK_ID, "synthetic-science-worker"
            )
        stages = (
            (4, "RESEARCH", "research", PINNED_INPUT_SHA256, "science-research"),
            (5, "DATA", "data", evidence["research"], "science-data"),
            (6, "QUANT", "quant", evidence["data"], "science-quant"),
        )
        for target_count, stage, name, input_sha, operation_key in stages:
            if name == "research":
                stage_evidence = _research_stage(package, retained, root)
            elif name == "data":
                _require("research" in science, "RESEARCH_NOT_VERIFIED", name)
                stage_evidence = _data_stage(package, retained)
            else:
                _require("data" in science, "DATA_NOT_VERIFIED", name)
                stage_evidence = _quant_stage(package, retained)
            _require(
                _evidence_sha(stage_evidence) == evidence[name],
                "ALTERED_STAGE_EVIDENCE",
                name,
            )
            science[name] = stage_evidence
            if pipeline_count < target_count:
                _require(
                    isinstance(claim_id, str) and type(fence) is int,
                    "ACTIVE_CLAIM_INVALID",
                    PIPELINE_TASK_ID,
                )
                _transition(
                    scheduler,
                    "CONTINUE",
                    PIPELINE_TASK_ID,
                    {"claim_id": claim_id, "fence": fence, "stage": stage, "input_evidence_sha256": input_sha, "output_evidence_sha256": evidence[name]},
                    operation_key,
                )
                _, pipeline_count = _validate_pipeline_prefix(scheduler, receipt, evidence)
                if interrupt_after == stage:
                    result = _checkpoint_result(scheduler, interruption_after=stage, resume_from=recovered_from)
                    _validate_schema(root, RESULT_SCHEMA_PATH, result, schema=result_schema)
                    return result
        if pipeline_count == 6:
            _require(
                isinstance(claim_id, str) and type(fence) is int,
                "ACTIVE_CLAIM_INVALID",
                PIPELINE_TASK_ID,
            )
            _transition(
                scheduler,
                "COMPLETE",
                PIPELINE_TASK_ID,
                {"claim_id": claim_id, "fence": fence, "completion_evidence_sha256": evidence["quant"]},
                "science-complete",
            )

    _, pipeline_count = _validate_pipeline_prefix(scheduler, receipt, evidence)
    if pipeline_count == 7:
        _transition(
            scheduler,
            "ASSIGN_REVIEW",
            PIPELINE_TASK_ID,
            {"actor": "synthetic-skeptic", "role": "05 Skeptic synthetic non-formal"},
            "science-review-assign",
        )
        _, pipeline_count = _validate_pipeline_prefix(scheduler, receipt, evidence)
        if interrupt_after == "REVIEW_ASSIGNED":
            result = _checkpoint_result(scheduler, interruption_after="REVIEW_ASSIGNED", resume_from=recovered_from)
            _validate_schema(root, RESULT_SCHEMA_PATH, result, schema=result_schema)
            return result
    if pipeline_count == 8:
        reviewer_id = _review_identity(scheduler)
        _require("quant" in science, "QUANT_NOT_VERIFIED", PIPELINE_TASK_ID)
        science["synthetic_skeptic"] = _skeptic_stage(
            package, science["quant"], retained
        )
        _transition(
            scheduler,
            "APPROVE",
            PIPELINE_TASK_ID,
            {"reviewer_id": reviewer_id, "decision_digest": evidence["synthetic_skeptic"]},
            "science-review-decision",
        )
    elif pipeline_count >= 9:
        _require("quant" in science, "QUANT_NOT_VERIFIED", PIPELINE_TASK_ID)
        science["synthetic_skeptic"] = _skeptic_stage(
            package, science["quant"], retained
        )
    _, pipeline_count = _validate_pipeline_prefix(scheduler, receipt, evidence)
    if pipeline_count == 9:
        _transition(
            scheduler,
            "ROUTE",
            PIPELINE_TASK_ID,
            {"routing_evidence": evidence["route"]},
            "science-route",
        )
    pipeline_history, pipeline_count = _validate_pipeline_prefix(scheduler, receipt, evidence)
    _require(pipeline_count == 10, "PIPELINE_INCOMPLETE", str(pipeline_count))
    pipeline_history_sha = digest(pipeline_history)

    risk_receipt = digest({
        "dependency_task": PIPELINE_TASK_ID,
        "dependency_history_sha256": pipeline_history_sha,
        "quant_evidence_sha256": evidence["quant"],
        "skeptic_evidence_sha256": evidence["synthetic_skeptic"],
        "authorizing_use": "DENY",
    })
    inventory = _task_inventory(scheduler)
    if RISK_TASK_ID not in inventory:
        scheduler.create_task(RISK_TASK_ID, risk_receipt, "06 Risk synthetic coordinator")
        if interrupt_after == "RISK_CREATED":
            result = _checkpoint_result(scheduler, interruption_after="RISK_CREATED", resume_from=recovered_from)
            _validate_schema(root, RESULT_SCHEMA_PATH, result, schema=result_schema)
            return result
    risk_history, risk_count = _validate_closed_task_prefix(
        scheduler,
        task_id=RISK_TASK_ID,
        receipt=risk_receipt,
        owner="06 Risk synthetic coordinator",
        actor="synthetic-risk-worker",
        evidence_sha=evidence["risk"],
    )
    if risk_count == 1:
        _claim_and_start(scheduler, RISK_TASK_ID, "synthetic-risk-worker", "risk")
        risk_history, risk_count = _validate_closed_task_prefix(
            scheduler, task_id=RISK_TASK_ID, receipt=risk_receipt,
            owner="06 Risk synthetic coordinator", actor="synthetic-risk-worker",
            evidence_sha=evidence["risk"],
        )
    if risk_count == 2:
        _deny(
            "CLAIMED_WITHOUT_AUTHENTICATED_LIVENESS",
            "Scheduler v1 RECOVER requires lease/liveness evidence that H-M0-186 cannot authenticate",
        )
    if risk_count == 3:
        _require(
            all(name in science for name in ("quant", "synthetic_skeptic")),
            "RISK_INPUT_NOT_VERIFIED",
            RISK_TASK_ID,
        )
        science["risk"] = _risk_stage(
            package, science["quant"], science["synthetic_skeptic"], retained
        )
        risk_claim, risk_fence = _claim_identity(scheduler, RISK_TASK_ID, "synthetic-risk-worker")
        _transition(
            scheduler,
            "COMPLETE",
            RISK_TASK_ID,
            {"claim_id": risk_claim, "fence": risk_fence, "completion_evidence_sha256": evidence["risk"], "close": True},
            "risk-complete",
        )
    elif risk_count == 4:
        _require(
            all(name in science for name in ("quant", "synthetic_skeptic")),
            "RISK_INPUT_NOT_VERIFIED",
            RISK_TASK_ID,
        )
        science["risk"] = _risk_stage(
            package, science["quant"], science["synthetic_skeptic"], retained
        )
    risk_history, risk_count = _validate_closed_task_prefix(
        scheduler, task_id=RISK_TASK_ID, receipt=risk_receipt,
        owner="06 Risk synthetic coordinator", actor="synthetic-risk-worker",
        evidence_sha=evidence["risk"],
    )
    _require(risk_count == 4, "RISK_INCOMPLETE", str(risk_count))
    risk_history_sha = digest(risk_history)

    director_receipt = digest({
        "dependency_task": RISK_TASK_ID,
        "dependency_history_sha256": risk_history_sha,
        "risk_evidence_sha256": evidence["risk"],
        "pipeline_history_sha256": pipeline_history_sha,
        "authorizing_use": "DENY",
    })
    inventory = _task_inventory(scheduler)
    if DIRECTOR_TASK_ID not in inventory:
        scheduler.create_task(DIRECTOR_TASK_ID, director_receipt, "00 Director synthetic coordinator")
    director_history, director_count = _validate_closed_task_prefix(
        scheduler, task_id=DIRECTOR_TASK_ID, receipt=director_receipt,
        owner="00 Director synthetic coordinator", actor="synthetic-director-worker",
        evidence_sha=evidence["director"],
    )
    if director_count == 1:
        _claim_and_start(scheduler, DIRECTOR_TASK_ID, "synthetic-director-worker", "director")
        director_history, director_count = _validate_closed_task_prefix(
            scheduler, task_id=DIRECTOR_TASK_ID, receipt=director_receipt,
            owner="00 Director synthetic coordinator", actor="synthetic-director-worker",
            evidence_sha=evidence["director"],
        )
    if director_count == 2:
        _deny(
            "CLAIMED_WITHOUT_AUTHENTICATED_LIVENESS",
            "Scheduler v1 RECOVER requires lease/liveness evidence that H-M0-186 cannot authenticate",
        )
    if director_count == 3:
        _require(
            all(name in science for name in ("research", "data", "quant", "synthetic_skeptic", "risk")),
            "DIRECTOR_INPUT_NOT_VERIFIED",
            DIRECTOR_TASK_ID,
        )
        science["director"] = _director_stage(
            science["research"], science["data"], science["quant"],
            science["synthetic_skeptic"], science["risk"], retained,
        )
        director_claim, director_fence = _claim_identity(scheduler, DIRECTOR_TASK_ID, "synthetic-director-worker")
        _transition(
            scheduler,
            "COMPLETE",
            DIRECTOR_TASK_ID,
            {"claim_id": director_claim, "fence": director_fence, "completion_evidence_sha256": evidence["director"], "close": True},
            "director-complete",
        )
    elif director_count == 4:
        _require(
            all(name in science for name in ("research", "data", "quant", "synthetic_skeptic", "risk")),
            "DIRECTOR_INPUT_NOT_VERIFIED",
            DIRECTOR_TASK_ID,
        )
        science["director"] = _director_stage(
            science["research"], science["data"], science["quant"],
            science["synthetic_skeptic"], science["risk"], retained,
        )
    director_history, director_count = _validate_closed_task_prefix(
        scheduler, task_id=DIRECTOR_TASK_ID, receipt=director_receipt,
        owner="00 Director synthetic coordinator", actor="synthetic-director-worker",
        evidence_sha=evidence["director"],
    )
    _require(director_count == 4, "DIRECTOR_INCOMPLETE", str(director_count))

    preserved = evaluate_scientific_package(package, root=root)
    _require(
        all(science[name] == preserved[name] for name in preserved),
        "H183_PRESERVATION_MISMATCH",
        "scientific stages",
    )
    result = _completed_result(
        scheduler,
        root=root,
        recovered_from=recovered_from,
        science=science,
        pipeline_history=pipeline_history,
        risk_history=risk_history,
        director_history=director_history,
    )
    _validate_schema(root, RESULT_SCHEMA_PATH, result, schema=result_schema)
    return result


def format_human(result: dict[str, Any]) -> str:
    lines = [
        "EdgeLab H-M0-186 recoverable scheduler research",
        f"Status: {result['status']}",
        f"Replay: {result['replay']}",
        f"Recovered from: {result['recovered_from']}",
    ]
    if result["status"] == "INTERRUPTED":
        lines.append(f"Durable interruption after: {result['interruption_after']}")
    else:
        lines.append(f"Scientific result: {result['coordinated_result']['final_result']}")
    lines.extend([
        "Authorization: DENY",
        "Formal Skeptic approval: false",
        "Live: LOCKED; kill: ENGAGED; deployable capital: $0.00",
    ])
    return "\n".join(lines) + "\n"
