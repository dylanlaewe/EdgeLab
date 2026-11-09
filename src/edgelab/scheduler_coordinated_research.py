"""Scheduler-coordinated execution of the retained H-M0-183 experiment.

This local harness uses the existing transactional scheduler as the ordering
and replay substrate.  It records content digests, never operational authority.
Scheduler v1 has no general dependency edge or typed evidence table, so later
task origins bind verified predecessor history through non-authorizing receipt
digests enforced by this coordinator.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .data_integrity import canonical, exact
from .locked_authority import read_locked_authority
from .synthetic_research_experiment import (
    CANONICAL_ROOT,
    INPUT_PATH,
    INPUT_SCHEMA_PATH,
    PINNED_INPUT_SHA256,
    _check_unique,
    _load_schema,
    _negative_controls,
    _quant_evaluate,
    _sha256,
    _synthetic_skeptic_review,
    _validate_observation,
    _validate_schema,
    evaluate_scientific_package,
)
from .transactional_scheduler import Scheduler, digest
from .validate import instant, read


RESULT_PATH = Path("reports/synthetic-research/H-M0-183-result.v1.json")
RESULT_SCHEMA_PATH = Path("schemas/scheduler-coordinated-research-result.v1.schema.json")
PINNED_H183_RESULT_SHA256 = "936a6183f23d606dcaccb356fa593c90d28c223d5c25966363fdbecc4e7237ed"
PIPELINE_TASK_ID = "T-SYNTHETIC-SCIENCE-PIPELINE-001"
RISK_TASK_ID = "T-SYNTHETIC-SCIENCE-RISK-001"
DIRECTOR_TASK_ID = "T-SYNTHETIC-SCIENCE-DIRECTOR-001"


class SchedulerResearchError(RuntimeError):
    """The scheduler-coordinated synthetic experiment failed closed."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise SchedulerResearchError(code, message)


def _evidence_sha(stage: dict[str, Any]) -> str:
    return digest(stage)


def _load_retained(root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    input_bytes = (root / INPUT_PATH).read_bytes()
    result_bytes = (root / RESULT_PATH).read_bytes()
    _require(
        _sha256(input_bytes) == PINNED_INPUT_SHA256,
        "STALE_OR_FORGED_INPUT",
        INPUT_PATH.as_posix(),
    )
    _require(
        _sha256(result_bytes) == PINNED_H183_RESULT_SHA256,
        "STALE_OR_FORGED_H183_RESULT",
        RESULT_PATH.as_posix(),
    )
    package = read(root / INPUT_PATH)
    retained = read(root / RESULT_PATH)
    _validate_schema(root, INPUT_SCHEMA_PATH, package)
    evaluator_sha = hashlib.sha256(
        (root / "src/edgelab/synthetic_research_experiment.py").read_bytes()
    ).hexdigest()
    _require(
        evaluator_sha == retained["evaluator_sha256"],
        "STALE_H183_EVALUATOR",
        evaluator_sha,
    )
    return package, retained


def _match_retained(
    name: str, stage: dict[str, Any], retained: dict[str, Any]
) -> dict[str, Any]:
    if stage != retained["stages"][name]:
        raise SchedulerResearchError("ALTERED_STAGE_EVIDENCE", name)
    return stage


def _research_stage(
    package: dict[str, Any], retained: dict[str, Any], root: Path
) -> dict[str, Any]:
    hypothesis = exact(root, package["hypothesis_ref"], {"hypothesis"})
    protocol = package["protocol"]
    if not (
        instant(hypothesis["registered_at"])
        < instant(protocol["protocol_frozen_at"])
        <= instant(protocol["evaluation_started_at"])
        <= instant(protocol["evaluation_completed_at"])
    ):
        raise SchedulerResearchError(
            "PREREGISTRATION_ORDER_INVALID", "registration/freeze/evaluation"
        )
    _require(
        not hypothesis["unresolved_thresholds"],
        "UNRESOLVED_THRESHOLD",
        hypothesis["id"],
    )
    return _match_retained("research", {
        "status": "PREREGISTERED_BEFORE_EVALUATION",
        "input_refs": [package["hypothesis_ref"]["path"]],
        "output": {
            "hypothesis_id": hypothesis["id"],
            "registered_at": hypothesis["registered_at"],
            "protocol_frozen_at": protocol["protocol_frozen_at"],
            "unresolved_thresholds": [],
        },
    }, retained)


def _data_stage(
    package: dict[str, Any], retained: dict[str, Any]
) -> dict[str, Any]:
    source = package["source_provenance"]
    observations = package["primary_observations"]
    _check_unique(observations)
    for observation in observations:
        _validate_observation(observation, source["source_id"])
        if instant(observation["outcome_available_at"]) > instant(
            package["protocol"]["evaluation_started_at"]
        ):
            raise SchedulerResearchError(
                "STALE_OR_INCOMPLETE_EVIDENCE", observation["observation_id"]
            )
    return _match_retained("data", {
        "status": "VALID_SYNTHETIC_TIMESTAMPED_EVIDENCE",
        "input_refs": [
            f"{INPUT_PATH.as_posix()}#/source_provenance",
            f"{INPUT_PATH.as_posix()}#/primary_observations",
        ],
        "output": {
            "source_id": source["source_id"],
            "source_type": source["source_type"],
            "external_data": False,
            "observation_count": len(observations),
            "observation_inventory_sha256": _sha256(canonical(observations)),
            "temporal_integrity": "PASSED",
        },
    }, retained)


def _quant_stage(
    package: dict[str, Any], retained: dict[str, Any]
) -> dict[str, Any]:
    quant = _quant_evaluate(package["primary_observations"], package["protocol"])
    return _match_retained("quant", {
        "status": quant["status"],
        "input_refs": [
            f"{INPUT_PATH.as_posix()}#/protocol",
            f"{INPUT_PATH.as_posix()}#/primary_observations",
        ],
        "output": quant,
    }, retained)


def _skeptic_stage(
    package: dict[str, Any], quant: dict[str, Any], retained: dict[str, Any]
) -> dict[str, Any]:
    controls = _negative_controls(
        package["negative_controls"], package["source_provenance"]["source_id"]
    )
    skeptic = _synthetic_skeptic_review(quant["output"], controls)
    return _match_retained("synthetic_skeptic", {
        "status": skeptic["status"],
        "input_refs": [
            "stage:quant/output",
            f"{INPUT_PATH.as_posix()}#/negative_controls",
        ],
        "output": skeptic,
    }, retained)


def _risk_stage(
    package: dict[str, Any], quant: dict[str, Any], skeptic: dict[str, Any],
    retained: dict[str, Any],
) -> dict[str, Any]:
    _require(
        quant["status"] == "INSUFFICIENT_DATA"
        and skeptic["output"]["outcome"] == "REJECT_ANY_CLAIM_OF_DEMONSTRATED_EDGE"
        and skeptic["output"]["formal_skeptic_approval"] is False,
        "INVALID_RISK_INPUT",
        "scientific findings",
    )
    return _match_retained("risk", {
        "status": "DENY",
        "input_refs": [
            "stage:quant/output",
            "stage:synthetic_skeptic/output",
            f"{INPUT_PATH.as_posix()}#/safety_boundary",
        ],
        "output": {
            "capital_authorization": "DENY",
            "deployable_capital_usd": "0.00",
            "strategy_promotion": "DENY",
            "paper_trading": "DENY",
            "limitations": [
                "fictional observations do not establish external validity",
                "sample size is below the preregistered minimum",
                "uncertainty includes the cost-adjusted break-even rate",
                "formal Skeptic approval is absent",
            ],
        },
    }, retained)


def _director_stage(
    research: dict[str, Any], data: dict[str, Any], quant: dict[str, Any],
    skeptic: dict[str, Any], risk: dict[str, Any], retained: dict[str, Any],
) -> dict[str, Any]:
    _require(
        research["status"] == "PREREGISTERED_BEFORE_EVALUATION"
        and data["status"] == "VALID_SYNTHETIC_TIMESTAMPED_EVIDENCE"
        and quant["status"] == "INSUFFICIENT_DATA"
        and skeptic["status"] == "CHALLENGE_CONFIRMED"
        and risk["status"] == "DENY",
        "INVALID_DIRECTOR_INPUT",
        "stage closure",
    )
    return _match_retained("director", {
        "status": "INSUFFICIENT_DATA",
        "input_refs": [
            "stage:research/output",
            "stage:data/output",
            "stage:quant/output",
            "stage:synthetic_skeptic/output",
            "stage:risk/output",
        ],
        "output": {
            "experiment_result": "INSUFFICIENT_DATA",
            "claim": "NO_REAL_EDGE_OR_OPERATIONAL_READINESS_DEMONSTRATED",
            "authorization": "DENY",
            "formal_review_status": "NOT_GRANTED",
        },
    }, retained)


def _locked_request(scheduler: Scheduler, task_id: str) -> dict[str, Any]:
    observation = read_locked_authority(scheduler, task_id)
    authority = observation.get("authority")
    verification = observation.get("verification", {})
    if (
        observation.get("observation_status") != "COHERENT_DENY_ONLY"
        or not isinstance(authority, dict)
        or verification.get("currentness_status") != "UNKNOWN"
        or verification.get("authorizing_use") != "DENY"
    ):
        raise SchedulerResearchError("LOCKED_AUTHORITY_INVALID", task_id)
    task_tuple = authority["task"]["tuple"]
    return {
        "expected": task_tuple,
        "repository_generation": authority["runtime"]["repository_generation"],
        "receipt_digest": task_tuple["decision_receipt_digest"],
    }


def _transition(
    scheduler: Scheduler, operation: str, task_id: str, extra: dict[str, Any],
    operation_key: str,
) -> dict[str, Any]:
    return scheduler.transition(
        operation,
        task_id,
        {**_locked_request(scheduler, task_id), **extra},
        operation_key=operation_key,
    )


def _claim_start(
    scheduler: Scheduler, task_id: str, actor: str, prefix: str
) -> tuple[str, int]:
    claimed = _transition(
        scheduler, "CLAIM", task_id, {"actor": actor}, f"{prefix}-claim"
    )
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


def _stable_history(scheduler: Scheduler, task_id: str) -> dict[str, Any]:
    snapshot = scheduler.export(scheduler.dir / "coordinated-snapshot.json")
    tasks = [task for task in snapshot["tasks"] if task["task_id"] == task_id]
    _require(len(tasks) == 1, "TASK_HISTORY_INVALID", task_id)
    events = [event for event in snapshot["task_events"] if event["task_id"] == task_id]
    projected = []
    for event in events:
        payload = json.loads(event["payload"])
        item: dict[str, Any] = {
            "task_seq": event["task_seq"],
            "event_type": event["event_type"],
        }
        if event["event_type"] == "TASK_INITIALIZED":
            request = payload["request"]["request"]
            item.update({
                "receipt_digest": request["receipt_digest"],
                "owner": request["owner"],
            })
        elif event["event_type"] in {
            "TASK_CONTINUED", "TASK_COMPLETED", "REVIEW_ASSIGNED",
            "REVIEW_APPROVED", "DIRECTOR_ROUTED",
        }:
            request = payload["request"]["request"]
            for field in (
                "stage", "input_evidence_sha256", "output_evidence_sha256",
                "completion_evidence_sha256", "actor", "role",
                "decision_digest", "routing_evidence", "close",
            ):
                if field in request:
                    item[field] = request[field]
        projected.append(item)
    task = tasks[0]
    return {
        "task_id": task_id,
        "receipt_digest": task["receipt_digest"],
        "owner": task["owner"],
        "final_state": {
            "workflow": task["workflow"],
            "execution": task["execution"],
            "review": task["review"],
            "continuation_count": task["continuations"],
        },
        "events": projected,
    }


def _verify_pipeline_history(
    history: dict[str, Any], receipt: str, research_sha: str, data_sha: str,
    quant_sha: str, skeptic_sha: str, route_sha: str,
) -> None:
    expected = {
        "task_id": PIPELINE_TASK_ID,
        "receipt_digest": receipt,
        "owner": "03 Research synthetic coordinator",
        "final_state": {
            "workflow": "DIRECTOR_GATE_READY",
            "execution": "EXECUTION_COMPLETED",
            "review": "APPROVED",
            "continuation_count": 3,
        },
        "events": [
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
        ],
    }
    _require(history == expected, "PIPELINE_HISTORY_MISMATCH", PIPELINE_TASK_ID)


def _verify_closed_task_history(
    history: dict[str, Any], *, task_id: str, receipt: str, owner: str,
    evidence_sha: str,
) -> None:
    expected = {
        "task_id": task_id,
        "receipt_digest": receipt,
        "owner": owner,
        "final_state": {
            "workflow": "CLOSED",
            "execution": "EXECUTION_COMPLETED",
            "review": "NOT_REQUIRED",
            "continuation_count": 0,
        },
        "events": [
            {"task_seq": 1, "event_type": "TASK_INITIALIZED", "receipt_digest": receipt, "owner": owner},
            {"task_seq": 2, "event_type": "CLAIM_ISSUED"},
            {"task_seq": 3, "event_type": "TASK_STARTED"},
            {"task_seq": 4, "event_type": "TASK_COMPLETED", "completion_evidence_sha256": evidence_sha, "close": True},
        ],
    }
    _require(history == expected, "TASK_HISTORY_MISMATCH", task_id)


def _begin_closed_task(
    scheduler: Scheduler, *, task_id: str, receipt: str, owner: str,
    actor: str, prefix: str,
) -> tuple[str, int]:
    scheduler.create_task(task_id, receipt, owner)
    return _claim_start(scheduler, task_id, actor, prefix)


def _finish_closed_task(
    scheduler: Scheduler, *, task_id: str, receipt: str, owner: str,
    claim_id: str, fence: int, evidence_sha: str, prefix: str,
) -> dict[str, Any]:
    _transition(
        scheduler,
        "COMPLETE",
        task_id,
        {
            "claim_id": claim_id,
            "fence": fence,
            "completion_evidence_sha256": evidence_sha,
            "close": True,
        },
        f"{prefix}-complete",
    )
    scheduler.startup()
    history = _stable_history(scheduler, task_id)
    _verify_closed_task_history(
        history,
        task_id=task_id,
        receipt=receipt,
        owner=owner,
        evidence_sha=evidence_sha,
    )
    return history


def run_scheduler_coordinated_research(
    runtime_dir: Path, *, root: Path = CANONICAL_ROOT
) -> dict[str, Any]:
    """Run the H-M0-183 science in scheduler-controlled stage order."""
    root = root.resolve()
    runtime_dir = runtime_dir.resolve()
    _require(root == CANONICAL_ROOT, "NONCANONICAL_ROOT", str(root))
    _require(
        runtime_dir != root and not runtime_dir.is_relative_to(root),
        "INVALID_RUNTIME_PATH",
        "runtime must be outside repository",
    )
    _require(not runtime_dir.exists(), "INVALID_RUNTIME_PATH", "runtime already exists")
    result_schema = _load_schema(root, RESULT_SCHEMA_PATH)
    package, retained = _load_retained(root)

    scheduler = Scheduler(root, runtime_dir)
    scheduler.initialize()
    pipeline_receipt = digest({
        "contract": "H-M0-184-SCHEDULER-COORDINATED-SCIENCE-V1",
        "input_package_sha256": PINNED_INPUT_SHA256,
        "hypothesis_sha256": package["hypothesis_ref"]["sha256"],
        "authorizing_use": "DENY",
    })
    scheduler.create_task(
        PIPELINE_TASK_ID, pipeline_receipt, "03 Research synthetic coordinator"
    )
    claim_id, fence = _claim_start(
        scheduler, PIPELINE_TASK_ID, "synthetic-science-worker", "science"
    )

    research = _research_stage(package, retained, root)
    research_sha = _evidence_sha(research)
    _transition(
        scheduler,
        "CONTINUE",
        PIPELINE_TASK_ID,
        {
            "claim_id": claim_id,
            "fence": fence,
            "stage": "RESEARCH",
            "input_evidence_sha256": PINNED_INPUT_SHA256,
            "output_evidence_sha256": research_sha,
        },
        "science-research",
    )

    data = _data_stage(package, retained)
    data_sha = _evidence_sha(data)
    _transition(
        scheduler,
        "CONTINUE",
        PIPELINE_TASK_ID,
        {
            "claim_id": claim_id,
            "fence": fence,
            "stage": "DATA",
            "input_evidence_sha256": research_sha,
            "output_evidence_sha256": data_sha,
        },
        "science-data",
    )

    quant = _quant_stage(package, retained)
    quant_sha = _evidence_sha(quant)
    _transition(
        scheduler,
        "CONTINUE",
        PIPELINE_TASK_ID,
        {
            "claim_id": claim_id,
            "fence": fence,
            "stage": "QUANT",
            "input_evidence_sha256": data_sha,
            "output_evidence_sha256": quant_sha,
        },
        "science-quant",
    )
    _transition(
        scheduler,
        "COMPLETE",
        PIPELINE_TASK_ID,
        {
            "claim_id": claim_id,
            "fence": fence,
            "completion_evidence_sha256": quant_sha,
        },
        "science-complete",
    )

    assigned = _transition(
        scheduler,
        "ASSIGN_REVIEW",
        PIPELINE_TASK_ID,
        {"actor": "synthetic-skeptic", "role": "05 Skeptic synthetic non-formal"},
        "science-review-assign",
    )
    reviewer_id = assigned["tuple"]["reviewer_assignment_id"]
    skeptic = _skeptic_stage(package, quant, retained)
    skeptic_sha = _evidence_sha(skeptic)
    _transition(
        scheduler,
        "APPROVE",
        PIPELINE_TASK_ID,
        {"reviewer_id": reviewer_id, "decision_digest": skeptic_sha},
        "science-review-decision",
    )
    route_sha = digest({
        "scope": "SYNTHETIC_SCIENTIFIC_FINDINGS_ONLY",
        "quant_evidence_sha256": quant_sha,
        "skeptic_evidence_sha256": skeptic_sha,
        "formal_approval": False,
        "authorizing_use": "DENY",
    })
    _transition(
        scheduler,
        "ROUTE",
        PIPELINE_TASK_ID,
        {"routing_evidence": route_sha},
        "science-route",
    )
    scheduler.startup()
    pipeline_history = _stable_history(scheduler, PIPELINE_TASK_ID)
    _verify_pipeline_history(
        pipeline_history,
        pipeline_receipt,
        research_sha,
        data_sha,
        quant_sha,
        skeptic_sha,
        route_sha,
    )
    pipeline_history_sha = digest(pipeline_history)

    risk_receipt = digest({
        "dependency_task": PIPELINE_TASK_ID,
        "dependency_history_sha256": pipeline_history_sha,
        "quant_evidence_sha256": quant_sha,
        "skeptic_evidence_sha256": skeptic_sha,
        "authorizing_use": "DENY",
    })
    risk_claim_id, risk_fence = _begin_closed_task(
        scheduler,
        task_id=RISK_TASK_ID,
        receipt=risk_receipt,
        owner="06 Risk synthetic coordinator",
        actor="synthetic-risk-worker",
        prefix="risk",
    )
    risk = _risk_stage(package, quant, skeptic, retained)
    risk_sha = _evidence_sha(risk)
    risk_history = _finish_closed_task(
        scheduler,
        task_id=RISK_TASK_ID,
        receipt=risk_receipt,
        owner="06 Risk synthetic coordinator",
        claim_id=risk_claim_id,
        fence=risk_fence,
        evidence_sha=risk_sha,
        prefix="risk",
    )
    risk_history_sha = digest(risk_history)

    director_receipt = digest({
        "dependency_task": RISK_TASK_ID,
        "dependency_history_sha256": risk_history_sha,
        "risk_evidence_sha256": risk_sha,
        "pipeline_history_sha256": pipeline_history_sha,
        "authorizing_use": "DENY",
    })
    director_claim_id, director_fence = _begin_closed_task(
        scheduler,
        task_id=DIRECTOR_TASK_ID,
        receipt=director_receipt,
        owner="00 Director synthetic coordinator",
        actor="synthetic-director-worker",
        prefix="director",
    )
    director = _director_stage(research, data, quant, skeptic, risk, retained)
    director_sha = _evidence_sha(director)
    director_history = _finish_closed_task(
        scheduler,
        task_id=DIRECTOR_TASK_ID,
        receipt=director_receipt,
        owner="00 Director synthetic coordinator",
        claim_id=director_claim_id,
        fence=director_fence,
        evidence_sha=director_sha,
        prefix="director",
    )
    scheduler.startup()

    stages = {
        "research": {"evidence": research, "evidence_sha256": research_sha, "scheduler_binding": {"task_id": PIPELINE_TASK_ID, "task_seq": 4, "event_type": "TASK_CONTINUED"}},
        "data": {"evidence": data, "evidence_sha256": data_sha, "scheduler_binding": {"task_id": PIPELINE_TASK_ID, "task_seq": 5, "event_type": "TASK_CONTINUED", "depends_on_evidence_sha256": research_sha}},
        "quant": {"evidence": quant, "evidence_sha256": quant_sha, "scheduler_binding": {"task_id": PIPELINE_TASK_ID, "task_seq": 6, "event_type": "TASK_CONTINUED", "depends_on_evidence_sha256": data_sha}},
        "synthetic_skeptic": {"evidence": skeptic, "evidence_sha256": skeptic_sha, "scheduler_binding": {"task_id": PIPELINE_TASK_ID, "task_seq": 9, "event_type": "REVIEW_APPROVED", "review_actor": "synthetic-skeptic", "formal_approval": False, "depends_on_evidence_sha256": quant_sha}},
        "risk": {"evidence": risk, "evidence_sha256": risk_sha, "scheduler_binding": {"task_id": RISK_TASK_ID, "task_seq": 4, "event_type": "TASK_COMPLETED", "origin_receipt_digest": risk_receipt, "depends_on_history_sha256": pipeline_history_sha}},
        "director": {"evidence": director, "evidence_sha256": director_sha, "scheduler_binding": {"task_id": DIRECTOR_TASK_ID, "task_seq": 4, "event_type": "TASK_COMPLETED", "origin_receipt_digest": director_receipt, "depends_on_history_sha256": risk_history_sha}},
    }
    preserved = evaluate_scientific_package(package, root=root)
    _require(
        all(stages[name]["evidence"] == preserved[name] for name in preserved),
        "H183_PRESERVATION_MISMATCH",
        "scientific stages",
    )
    result = {
        "schema_version": 1,
        "integration_id": "H-M0-184-SCHEDULER-COORDINATED-RESEARCH",
        "mode": "SYNTHETIC_LOCAL_ONLY",
        "input_package_sha256": PINNED_INPUT_SHA256,
        "h_m0_183_result_sha256": PINNED_H183_RESULT_SHA256,
        "stages": stages,
        "task_histories": {
            "pipeline": pipeline_history,
            "risk": risk_history,
            "director": director_history,
        },
        "dependency_model": {
            "status": "COORDINATOR_ENFORCED_CONTENT_BOUND_RECEIPTS",
            "native_general_dependency_edge": False,
            "remediation_links_used_as_dependencies": False,
            "limitation": "Scheduler v1 stores task-origin receipt digests and event payloads but has no native general prerequisite edge or typed scientific evidence table.",
        },
        "replay": "PASSED",
        "final_result": director["output"]["experiment_result"],
        "authorization": {
            "authorizing_use": "DENY",
            "operational_release": "DENIED",
            "paper_trading": "DENIED",
            "live": "LOCKED",
            "kill": "ENGAGED",
            "deployable_capital_usd": "0.00",
        },
        "formal_skeptic_approval": False,
        "result_sha256": "",
    }
    result["result_sha256"] = digest({
        key: value for key, value in result.items() if key != "result_sha256"
    })
    _validate_schema(root, RESULT_SCHEMA_PATH, result, schema=result_schema)
    return result


def format_human(result: dict[str, Any]) -> str:
    quant = result["stages"]["quant"]["evidence"]["output"]
    lines = [
        "EdgeLab H-M0-184 scheduler-coordinated synthetic research",
        "Scheduler stages: RESEARCH -> DATA -> QUANT -> SYNTHETIC_SKEPTIC -> RISK -> DIRECTOR",
        f"Scientific result: {result['final_result']}",
        f"Fictional record: {quant['wins']}-{quant['losses']}; net ROI {quant['net_roi']}",
        "Replay: " + result["replay"],
        "Dependency model: " + result["dependency_model"]["status"],
        "Native general dependency edge: unavailable (truthfully unrepresented)",
        "Authorization: DENY; live LOCKED; kill ENGAGED; deployable capital $0.00",
        "Synthetic review is not formal Skeptic approval.",
        f"Result SHA-256: {result['result_sha256']}",
    ]
    return "\n".join(lines) + "\n"


__all__ = [
    "CANONICAL_ROOT",
    "DIRECTOR_TASK_ID",
    "PIPELINE_TASK_ID",
    "RISK_TASK_ID",
    "SchedulerResearchError",
    "format_human",
    "run_scheduler_coordinated_research",
]
