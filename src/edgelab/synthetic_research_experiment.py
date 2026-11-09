"""Deterministic, fictional, non-authorizing scientific experiment harness.

The harness composes existing validation primitives and the H-M0-179 local
scheduler lifecycle.  It never treats synthetic results or scheduler review as
formal Skeptic approval, strategy promotion, or operational authority.
"""
from __future__ import annotations

from copy import deepcopy
from decimal import Decimal, ROUND_HALF_EVEN
import hashlib
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from .data_integrity import canonical, exact
from .synthetic_lifecycle import TASK_ID, run_synthetic_lifecycle
from .validate import CHECKER, instant, read


CANONICAL_ROOT = Path(__file__).resolve().parents[2]
INPUT_PATH = Path("reports/synthetic-research/H-M0-183-input.v1.json")
INPUT_SCHEMA_PATH = Path("schemas/synthetic-research-input.v1.schema.json")
RESULT_SCHEMA_PATH = Path("schemas/synthetic-research-result.v1.schema.json")
PINNED_INPUT_SHA256 = "48b5fe80a19a402ba676285d67d90fda8d3a98ecdd2089c14844fa13841768fb"
Q6 = Decimal("0.000001")


class SyntheticResearchError(RuntimeError):
    """The retained experiment or its fail-closed boundary is invalid."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _q(value: Decimal) -> str:
    return str(value.quantize(Q6, rounding=ROUND_HALF_EVEN))


def _load_schema(root: Path, path: Path) -> dict[str, Any]:
    schema_path = root / path
    if not schema_path.is_file():
        raise SyntheticResearchError("MISSING_SCHEMA", path.as_posix())
    schema = read(schema_path)
    Draft202012Validator.check_schema(schema)
    return schema


def _validate_schema(
    root: Path,
    path: Path,
    value: dict[str, Any],
    *,
    schema: dict[str, Any] | None = None,
) -> None:
    schema = schema or _load_schema(root, path)
    errors = sorted(
        Draft202012Validator(schema, format_checker=CHECKER).iter_errors(value),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        first = errors[0]
        location = "/" + "/".join(str(part) for part in first.absolute_path)
        raise SyntheticResearchError("MALFORMED_EVIDENCE", f"{location}: {first.message}")


def _validate_observation(observation: dict[str, Any], source_id: str) -> None:
    if observation["provenance_source_id"] != source_id:
        raise SyntheticResearchError("PROVENANCE_MISMATCH", observation["observation_id"])
    signal_at = instant(observation["signal_published_at"])
    price_at = instant(observation["price_observed_at"])
    decision_at = instant(observation["decision_at"])
    event_at = instant(observation["event_at"])
    outcome_at = instant(observation["outcome_available_at"])
    if signal_at > decision_at or price_at > decision_at:
        raise SyntheticResearchError("FUTURE_LEAKAGE", observation["observation_id"])
    if decision_at >= event_at or event_at >= outcome_at:
        raise SyntheticResearchError("INVALID_TEMPORAL_ORDER", observation["observation_id"])
    if Decimal(observation["offered_decimal_odds"]) <= Decimal("1"):
        raise SyntheticResearchError("INVALID_PRICE", observation["observation_id"])
    if Decimal(observation["opposing_decimal_odds"]) <= Decimal("1"):
        raise SyntheticResearchError("INVALID_PRICE", observation["observation_id"])


def _check_unique(observations: list[dict[str, Any]]) -> None:
    for field in ("observation_id", "event_id"):
        values = [observation[field] for observation in observations]
        if len(values) != len(set(values)):
            raise SyntheticResearchError("DUPLICATE_EVIDENCE", field)


def _wilson_interval(wins: int, count: int, z: Decimal) -> tuple[Decimal, Decimal]:
    n = Decimal(count)
    p = Decimal(wins) / n
    z2 = z * z
    denominator = Decimal(1) + z2 / n
    center = (p + z2 / (Decimal(2) * n)) / denominator
    margin = (
        z
        * ((p * (Decimal(1) - p) / n) + z2 / (Decimal(4) * n * n)).sqrt()
        / denominator
    )
    return center - margin, center + margin


def _quant_evaluate(
    observations: list[dict[str, Any]], protocol: dict[str, Any]
) -> dict[str, Any]:
    signal_threshold = Decimal(protocol["signal_threshold"])
    minimum_odds = Decimal(protocol["minimum_offered_decimal_odds"])
    stake = Decimal(protocol["stake_units"])
    cost = Decimal(protocol["cost_units_per_selection"])
    selected = [
        observation
        for observation in observations
        if Decimal(observation["public_signal_score"]) >= signal_threshold
        and Decimal(observation["offered_decimal_odds"]) >= minimum_odds
    ]
    if not selected:
        raise SyntheticResearchError("NO_ELIGIBLE_OBSERVATIONS", "selection is empty")

    wins = sum(observation["outcome"] == "WIN" for observation in selected)
    offered = [Decimal(observation["offered_decimal_odds"]) for observation in selected]
    opposing = [Decimal(observation["opposing_decimal_odds"]) for observation in selected]
    pnls = [
        (odds * stake - stake - cost)
        if observation["outcome"] == "WIN"
        else (-stake - cost)
        for observation, odds in zip(selected, offered, strict=True)
    ]
    cumulative = Decimal(0)
    peak = Decimal(0)
    max_drawdown = Decimal(0)
    for pnl in pnls:
        cumulative += pnl
        peak = max(peak, cumulative)
        max_drawdown = max(max_drawdown, peak - cumulative)

    count = len(selected)
    average_odds = sum(offered, Decimal(0)) / Decimal(count)
    average_overround = sum(
        (Decimal(1) / price) + (Decimal(1) / other) - Decimal(1)
        for price, other in zip(offered, opposing, strict=True)
    ) / Decimal(count)
    total_stake = stake * Decimal(count)
    win_rate = Decimal(wins) / Decimal(count)
    break_even = (stake + cost) / (average_odds * stake)
    lower, upper = _wilson_interval(wins, count, Decimal(protocol["wilson_z"]))
    sample_sufficient = count >= protocol["minimum_sample_size"]
    uncertainty_excludes_break_even = lower > break_even
    status = (
        "NO_DEMONSTRATED_EDGE"
        if sample_sufficient and uncertainty_excludes_break_even and cumulative > 0
        else "INSUFFICIENT_DATA"
        if not sample_sufficient
        else "NO_DEMONSTRATED_EDGE"
    )
    return {
        "status": status,
        "eligible_observation_ids": [item["observation_id"] for item in selected],
        "sample_size": count,
        "minimum_sample_size": protocol["minimum_sample_size"],
        "wins": wins,
        "losses": count - wins,
        "win_rate": _q(win_rate),
        "average_offered_decimal_odds": _q(average_odds),
        "average_two_way_overround": _q(average_overround),
        "stake_units_per_selection": _q(stake),
        "cost_units_per_selection": _q(cost),
        "total_stake_units": _q(total_stake),
        "net_profit_units": _q(cumulative),
        "net_roi": _q(cumulative / total_stake),
        "maximum_drawdown_units": _q(max_drawdown),
        "cost_adjusted_break_even_win_rate": _q(break_even),
        "wilson_95_lower": _q(lower),
        "wilson_95_upper": _q(upper),
        "sample_sufficient": sample_sufficient,
        "uncertainty_excludes_break_even": uncertainty_excludes_break_even,
    }


def _negative_controls(
    controls: list[dict[str, Any]], source_id: str
) -> list[dict[str, Any]]:
    results = []
    for control in controls:
        try:
            _validate_observation(control["observation"], source_id)
        except SyntheticResearchError as error:
            if error.code != control["expected_finding"]:
                raise SyntheticResearchError(
                    "NEGATIVE_CONTROL_MISMATCH",
                    f"{control['control_id']} produced {error.code}",
                ) from error
            results.append({
                "control_id": control["control_id"],
                "status": "REJECTED_AS_EXPECTED",
                "finding": error.code,
                "admitted_to_primary_analysis": False,
            })
        else:
            raise SyntheticResearchError(
                "NEGATIVE_CONTROL_FAILED", control["control_id"]
            )
    return results


def _synthetic_skeptic_review(
    quant: dict[str, Any], controls: list[dict[str, Any]]
) -> dict[str, Any]:
    findings = []
    if not quant["sample_sufficient"]:
        findings.append("SAMPLE_SIZE_BELOW_PREREGISTERED_MINIMUM")
    if not quant["uncertainty_excludes_break_even"]:
        findings.append("UNCERTAINTY_INCLUDES_COST_ADJUSTED_BREAK_EVEN")
    if Decimal(quant["net_roi"]) > 0:
        findings.append("POSITIVE_SYNTHETIC_ROI_IS_NOT_REAL_EDGE_EVIDENCE")
    if not controls or any(item["status"] != "REJECTED_AS_EXPECTED" for item in controls):
        raise SyntheticResearchError("ADVERSARIAL_CHECK_FAILED", "negative control")
    if not findings:
        raise SyntheticResearchError("UNSUPPORTED_POSITIVE_CONCLUSION", "no limitation")
    return {
        "status": "CHALLENGE_CONFIRMED",
        "review_class": "SYNTHETIC_INTERNAL_NON_AUTHORIZING",
        "formal_skeptic_approval": False,
        "findings": findings,
        "negative_controls": controls,
        "outcome": "REJECT_ANY_CLAIM_OF_DEMONSTRATED_EDGE",
    }


def evaluate_scientific_package(
    package: dict[str, Any], *, root: Path = CANONICAL_ROOT
) -> dict[str, Any]:
    """Evaluate already-parsed evidence without running the scheduler."""
    root = root.resolve()
    if root != CANONICAL_ROOT:
        raise SyntheticResearchError("NONCANONICAL_ROOT", str(root))
    _validate_schema(root, INPUT_SCHEMA_PATH, package)

    hypothesis = exact(root, package["hypothesis_ref"], {"hypothesis"})
    protocol = package["protocol"]
    registered_at = instant(hypothesis["registered_at"])
    frozen_at = instant(protocol["protocol_frozen_at"])
    started_at = instant(protocol["evaluation_started_at"])
    completed_at = instant(protocol["evaluation_completed_at"])
    if not registered_at < frozen_at <= started_at <= completed_at:
        raise SyntheticResearchError(
            "PREREGISTRATION_ORDER_INVALID", "registration/freeze/evaluation"
        )
    if hypothesis["unresolved_thresholds"]:
        raise SyntheticResearchError("UNRESOLVED_THRESHOLD", hypothesis["id"])

    source = package["source_provenance"]
    observations = package["primary_observations"]
    _check_unique(observations)
    for observation in observations:
        _validate_observation(observation, source["source_id"])
        if instant(observation["outcome_available_at"]) > started_at:
            raise SyntheticResearchError("STALE_OR_INCOMPLETE_EVIDENCE", observation["observation_id"])
    controls = _negative_controls(package["negative_controls"], source["source_id"])
    quant = _quant_evaluate(observations, protocol)
    skeptic = _synthetic_skeptic_review(quant, controls)
    conclusion = (
        "INSUFFICIENT_DATA"
        if quant["status"] == "INSUFFICIENT_DATA"
        else "NO_DEMONSTRATED_EDGE"
    )
    return {
        "research": {
            "status": "PREREGISTERED_BEFORE_EVALUATION",
            "input_refs": [package["hypothesis_ref"]["path"]],
            "output": {
                "hypothesis_id": hypothesis["id"],
                "registered_at": hypothesis["registered_at"],
                "protocol_frozen_at": protocol["protocol_frozen_at"],
                "unresolved_thresholds": [],
            },
        },
        "data": {
            "status": "VALID_SYNTHETIC_TIMESTAMPED_EVIDENCE",
            "input_refs": [f"{INPUT_PATH.as_posix()}#/source_provenance", f"{INPUT_PATH.as_posix()}#/primary_observations"],
            "output": {
                "source_id": source["source_id"],
                "source_type": source["source_type"],
                "external_data": False,
                "observation_count": len(observations),
                "observation_inventory_sha256": _sha256(canonical(observations)),
                "temporal_integrity": "PASSED",
            },
        },
        "quant": {
            "status": quant["status"],
            "input_refs": [f"{INPUT_PATH.as_posix()}#/protocol", f"{INPUT_PATH.as_posix()}#/primary_observations"],
            "output": quant,
        },
        "synthetic_skeptic": {
            "status": skeptic["status"],
            "input_refs": ["stage:quant/output", f"{INPUT_PATH.as_posix()}#/negative_controls"],
            "output": skeptic,
        },
        "risk": {
            "status": "DENY",
            "input_refs": ["stage:quant/output", "stage:synthetic_skeptic/output", f"{INPUT_PATH.as_posix()}#/safety_boundary"],
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
        },
        "director": {
            "status": conclusion,
            "input_refs": ["stage:research/output", "stage:data/output", "stage:quant/output", "stage:synthetic_skeptic/output", "stage:risk/output"],
            "output": {
                "experiment_result": conclusion,
                "claim": "NO_REAL_EDGE_OR_OPERATIONAL_READINESS_DEMONSTRATED",
                "authorization": "DENY",
                "formal_review_status": "NOT_GRANTED",
            },
        },
    }


def _scheduler_projection(lifecycle: dict[str, Any]) -> dict[str, Any]:
    expected_events = [
        "TASK_INITIALIZED",
        "CLAIM_ISSUED",
        "TASK_STARTED",
        "TASK_COMPLETED",
        "REVIEW_ASSIGNED",
        "REVIEW_APPROVED",
        "DIRECTOR_ROUTED",
    ]
    try:
        event_sequence = [event["event"] for event in lifecycle["events"]]
        final = lifecycle["final_locked_authority"]
        final_tuple = final["tuple"]
        public = lifecycle["public_runtime_v2_verification"]
        binding = lifecycle["historical_binding"]
        authorization = lifecycle["authorization"]
        valid = (
            lifecycle["integration_status"] == "RECORDED_NON_OPERATIONAL_LIFECYCLE"
            and lifecycle["mode"] == "SYNTHETIC_LOCAL_ONLY"
            and lifecycle["task_id"] == TASK_ID
            and event_sequence == expected_events
            and lifecycle["scheduler_replay"] == "PASSED"
            and binding["status"] == "BOUND_DENY_ONLY"
            and binding["evidence_class"] == "R_GATE_CANDIDATE_EVIDENCE"
            and binding["verification"]["authorizing_use"] == "DENY"
            and binding["verification"]["currentness_status"] == "UNKNOWN"
            and public["status"] == "UNSUPPORTED"
            and public["anchor_status"] == "UNANCHORED"
            and public["currentness_status"] == "UNKNOWN"
            and public["authorizing_use"] == "DENY"
            and final["observation_status"] == "COHERENT_DENY_ONLY"
            and final["verification"]["authorizing_use"] == "DENY"
            and final["verification"]["currentness_status"] == "UNKNOWN"
            and (
                final_tuple["workflow"],
                final_tuple["execution"],
                final_tuple["review"],
            ) == ("DIRECTOR_GATE_READY", "EXECUTION_COMPLETED", "APPROVED")
            and authorization == {
                "authorizing_use": "DENY",
                "operational_release": "DENIED",
                "currentness": "UNKNOWN",
            }
        )
    except (KeyError, TypeError) as error:
        raise SyntheticResearchError(
            "SCHEDULER_CONTRACT_MISMATCH", "missing or malformed lifecycle evidence"
        ) from error
    if not valid:
        raise SyntheticResearchError(
            "SCHEDULER_CONTRACT_MISMATCH", "lifecycle evidence did not match the closed DENY contract"
        )
    return {
        "status": lifecycle["integration_status"],
        "input_refs": ["stage:director/output", "src/edgelab/synthetic_lifecycle.py"],
        "output": {
            "task_id": lifecycle["task_id"],
            "event_sequence": event_sequence,
            "final_workflow": lifecycle["final_locked_authority"]["tuple"]["workflow"],
            "final_execution": lifecycle["final_locked_authority"]["tuple"]["execution"],
            "final_review": lifecycle["final_locked_authority"]["tuple"]["review"],
            "scheduler_replay": lifecycle["scheduler_replay"],
            "public_runtime_v2_status": lifecycle["public_runtime_v2_verification"]["status"],
            "authorizing_use": "DENY",
            "review_scope": "SYNTHETIC_TASK_RECORDING_ONLY",
            "formal_skeptic_approval": False,
        },
    }


def run_synthetic_research_experiment(
    runtime_dir: Path, *, root: Path = CANONICAL_ROOT
) -> dict[str, Any]:
    """Run the retained experiment and existing scheduler in a new local runtime."""
    root = root.resolve()
    if root != CANONICAL_ROOT:
        raise SyntheticResearchError("NONCANONICAL_ROOT", str(root))
    input_bytes = (root / INPUT_PATH).read_bytes()
    input_sha = _sha256(input_bytes)
    if input_sha != PINNED_INPUT_SHA256:
        raise SyntheticResearchError("STALE_OR_FORGED_PACKAGE", input_sha)
    package = read(root / INPUT_PATH)
    result_schema = _load_schema(root, RESULT_SCHEMA_PATH)
    stages = evaluate_scientific_package(package, root=root)
    lifecycle = run_synthetic_lifecycle(runtime_dir, root=root)
    stages["scheduler"] = _scheduler_projection(lifecycle)
    evaluator_sha = _sha256(Path(__file__).read_bytes())
    result = {
        "schema_version": 1,
        "experiment_id": package["id"],
        "experiment_version": package["version"],
        "mode": "SYNTHETIC_LOCAL_ONLY",
        "input_package_sha256": input_sha,
        "evaluator_sha256": evaluator_sha,
        "stages": stages,
        "final_result": stages["director"]["output"]["experiment_result"],
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
    result["result_sha256"] = _sha256(canonical({
        key: value for key, value in result.items() if key != "result_sha256"
    }))
    _validate_schema(root, RESULT_SCHEMA_PATH, result, schema=result_schema)
    return result


def format_human(result: dict[str, Any]) -> str:
    """Render a stable human-readable summary of the closed JSON result."""
    quant = result["stages"]["quant"]["output"]
    skeptic = result["stages"]["synthetic_skeptic"]["output"]
    lines = [
        "EdgeLab H-M0-183 synthetic research experiment",
        f"Result: {result['final_result']}",
        f"Sample: {quant['sample_size']}/{quant['minimum_sample_size']} required",
        f"Record: {quant['wins']}-{quant['losses']}",
        f"Net PnL: {quant['net_profit_units']} units; ROI: {quant['net_roi']}",
        f"95% Wilson win-rate interval: {quant['wilson_95_lower']} to {quant['wilson_95_upper']}",
        "Synthetic Skeptic: " + skeptic["outcome"],
        "Negative control: " + skeptic["negative_controls"][0]["status"],
        "Scheduler: " + result["stages"]["scheduler"]["output"]["scheduler_replay"],
        "Authorization: DENY; live LOCKED; kill ENGAGED; deployable capital $0.00",
        "Synthetic evidence does not demonstrate a real sports-market edge.",
        f"Result SHA-256: {result['result_sha256']}",
    ]
    return "\n".join(lines) + "\n"


def mutable_package_copy(*, root: Path = CANONICAL_ROOT) -> dict[str, Any]:
    """Return a deep copy for adversarial tests; production uses pinned bytes."""
    return deepcopy(read(root / INPUT_PATH))


__all__ = [
    "CANONICAL_ROOT",
    "INPUT_PATH",
    "PINNED_INPUT_SHA256",
    "SyntheticResearchError",
    "evaluate_scientific_package",
    "format_human",
    "mutable_package_copy",
    "run_synthetic_research_experiment",
]
