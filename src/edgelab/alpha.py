"""Read-only EdgeLab developer alpha over retained synthetic evidence.

The alpha is a visibility layer, not a scheduler, scientific evaluator, paper
trader, or execution adapter. It reads content-bound repository artifacts,
reuses existing validation components against isolated fixture copies, and
reports current fail-closed controls.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable

from .data_integrity import validate_data
from .orchestration import decision
from .research_protocol import validate_research
from .validate import ROOT, read, validate_record


DEFAULT_MANIFEST = Path("examples/alpha/sample-workflow.v1.json")
ARTIFACT_KEYS = {
    "director_capture",
    "data_source",
    "data_observation",
    "research_hypothesis",
    "research_preregistration",
    "quant_result",
    "skeptic_result",
    "risk_result",
    "bankroll",
    "risk_policy",
}
MANIFEST_KEYS = {
    "schema_version",
    "sample_id",
    "title",
    "scope",
    "scenario",
    "artifacts",
    "current_stop_artifacts",
    "expected_controls",
}
CONTROL_KEYS = {
    "historical_execution_adapter",
    "historical_operation",
    "current_open_stop_ids",
    "live_status",
    "kill_switch",
    "live_deployable_minor",
    "live_enabled",
}
REF_KEYS = {"path", "sha256"}


class AlphaEvidenceError(ValueError):
    """The closed alpha evidence bundle failed validation."""


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _path(root: Path, relative: str) -> Path:
    if not isinstance(relative, str):
        raise AlphaEvidenceError("Artifact path must be a string")
    candidate = Path(relative)
    if candidate.is_absolute() or candidate.as_posix() != relative or ".." in candidate.parts:
        raise AlphaEvidenceError(f"Noncanonical artifact path: {relative!r}")
    resolved = (root / candidate).resolve()
    if not resolved.is_relative_to(root.resolve()) or not resolved.is_file():
        raise AlphaEvidenceError(f"Missing or non-repository artifact: {relative}")
    if resolved.relative_to(root.resolve()).as_posix() != relative:
        raise AlphaEvidenceError(f"Aliased artifact path: {relative}")
    return resolved


def _check_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise AlphaEvidenceError(f"{label} must contain exactly {sorted(expected)}")
    return value


def _bound_json(root: Path, ref: Any, label: str) -> tuple[dict[str, Any], dict[str, str]]:
    ref = _check_keys(ref, REF_KEYS, f"{label} reference")
    if not isinstance(ref["sha256"], str) or len(ref["sha256"]) != 64:
        raise AlphaEvidenceError(f"Invalid SHA-256 for {label}")
    path = _path(root, ref["path"])
    actual = _sha256(path)
    if actual != ref["sha256"]:
        raise AlphaEvidenceError(f"Content digest mismatch: {ref['path']}")
    value = read(path)
    if not isinstance(value, dict):
        raise AlphaEvidenceError(f"Artifact is not a JSON object: {ref['path']}")
    return value, {"label": label, "path": ref["path"], "sha256": actual}


def _validate_fixture_components(root: Path, source: dict[str, Any],
                                 observation: dict[str, Any],
                                 preregistration: dict[str, Any]) -> None:
    """Exercise existing Data and Research validators without mutating the repo."""
    with tempfile.TemporaryDirectory(prefix="edgelab-alpha-") as directory:
        scratch = Path(directory)
        data_root = scratch / "data-fixture"
        shutil.copytree(root / "tests/fixtures/data-integrity/data", data_root / "data")
        shutil.copytree(root / "schemas", data_root / "schemas")
        validate_record("source", source, data_root)
        validate_data(data_root, "observation", observation)

        research_root = scratch / "research-fixture"
        shutil.copytree(root / "tests/fixtures/research-protocol/data", research_root / "data")
        shutil.copytree(root / "tests/fixtures/research-protocol/research", research_root / "research")
        shutil.copytree(root / "schemas", research_root / "schemas")
        validate_research(research_root, "preregistration", preregistration)


def _load_manifest(root: Path, manifest_path: Path | None) -> dict[str, Any]:
    path = root / DEFAULT_MANIFEST if manifest_path is None else manifest_path
    manifest = read(path)
    _check_keys(manifest, MANIFEST_KEYS, "Alpha manifest")
    if manifest["schema_version"] != 1:
        raise AlphaEvidenceError("Unsupported alpha manifest version")
    if manifest["scope"] != "DEVELOPER_ALPHA_MOCK_ONLY":
        raise AlphaEvidenceError("Alpha scope is not MOCK_ONLY")
    _check_keys(manifest["artifacts"], ARTIFACT_KEYS, "Alpha artifact map")
    _check_keys(manifest["expected_controls"], CONTROL_KEYS, "Expected controls")
    if not isinstance(manifest["current_stop_artifacts"], list) or not manifest["current_stop_artifacts"]:
        raise AlphaEvidenceError("Current STOP inventory must be nonempty")
    return manifest


def _current_stop_heads(stops: list[tuple[dict[str, Any], str]]) -> list[dict[str, Any]]:
    """Select numeric STOP heads while preserving and validating every version."""
    heads: dict[str, dict[str, Any]] = {}
    identities: set[tuple[str, int]] = set()
    paths: set[str] = set()
    versions: dict[str, set[int]] = {}
    for stop, relative_path in stops:
        identity = (stop["id"], stop["version"])
        if relative_path in paths or identity in identities:
            raise AlphaEvidenceError("Duplicate or ambiguous STOP artifact")
        paths.add(relative_path)
        identities.add(identity)
        expected_name = f"{stop['id']}.v{stop['version']}.json"
        if Path(relative_path).name != expected_name or not re.fullmatch(
            r"STOP-.+\.v[1-9][0-9]*\.json", expected_name
        ):
            raise AlphaEvidenceError(f"STOP filename/identity mismatch: {relative_path}")
        versions.setdefault(stop["id"], set()).add(stop["version"])
        current = heads.get(stop["id"])
        if current is None or stop["version"] > current["version"]:
            heads[stop["id"]] = stop
    for stop_id, observed in versions.items():
        expected = set(range(1, max(observed) + 1))
        if observed != expected:
            raise AlphaEvidenceError(f"STOP version gap: {stop_id}")
    return sorted(heads.values(), key=lambda stop: stop["id"])


def build_report(root: Path = ROOT, manifest_path: Path | None = None) -> dict[str, Any]:
    """Build a non-authorizing report; fail closed on missing or changed evidence."""
    root = root.resolve()
    manifest = _load_manifest(root, manifest_path)
    controls = manifest["expected_controls"]
    values: dict[str, dict[str, Any]] = {}
    provenance: list[dict[str, str]] = []
    for label in sorted(ARTIFACT_KEYS):
        values[label], item = _bound_json(root, manifest["artifacts"][label], label)
        provenance.append(item)

    stop_versions: list[tuple[dict[str, Any], str]] = []
    stop_paths: set[str] = set()
    for index, ref in enumerate(manifest["current_stop_artifacts"]):
        stop, item = _bound_json(root, ref, f"current_stop_{index + 1}")
        validate_record("stop", stop, root)
        stop_versions.append((stop, item["path"]))
        stop_paths.add(item["path"])
        provenance.append(item)
    actual_stop_paths = {
        path.relative_to(root).as_posix()
        for path in (root / "reports/stops").glob("STOP-*.v*.json")
    }
    if stop_paths != actual_stop_paths:
        raise AlphaEvidenceError("Current STOP inventory is incomplete, altered, or superseded")

    capture = values["director_capture"]
    source = values["data_source"]
    observation = values["data_observation"]
    hypothesis = values["research_hypothesis"]
    preregistration = values["research_preregistration"]
    quant = values["quant_result"]
    skeptic = values["skeptic_result"]
    risk = values["risk_result"]
    bankroll = values["bankroll"]
    risk_policy = values["risk_policy"]

    validate_record("hypothesis", hypothesis, root)
    validate_record("bankroll", bankroll, root)
    validate_record("risk-policy", risk_policy, root)
    _validate_fixture_components(root, source, observation, preregistration)

    historical = capture.get("result", {})
    if (
        historical.get("decision") != "DISPATCH"
        or historical.get("execution_adapter") != controls["historical_execution_adapter"]
        or historical.get("operation") != controls["historical_operation"]
    ):
        raise AlphaEvidenceError("Historical MOCK_ONLY capture contradicts the manifest")
    current = decision(root, capture.get("intent", {}))
    if current.get("decision") != "DENY" or current.get("execution_adapter") != "MOCK_ONLY":
        raise AlphaEvidenceError("Current preflight did not fail closed")

    open_stops = [stop for stop in _current_stop_heads(stop_versions) if stop["status"] == "OPEN"]
    if [stop["id"] for stop in open_stops] != sorted(controls["current_open_stop_ids"]):
        raise AlphaEvidenceError("OPEN STOP identities contradict the manifest")
    if (
        bankroll["live_status"] != controls["live_status"]
        or bankroll["live_deployable_minor"] != controls["live_deployable_minor"]
        or risk_policy["kill_switch"] != controls["kill_switch"]
        or risk_policy["live_enabled"] is not controls["live_enabled"]
    ):
        raise AlphaEvidenceError("Capital controls contradict the manifest")
    reviewed_capital = risk.get("capital", {})
    if (
        reviewed_capital.get("live_status") != bankroll["live_status"]
        or reviewed_capital.get("live_deployable_minor") != bankroll["live_deployable_minor"]
        or reviewed_capital.get("kill_status") != risk_policy["kill_switch"]
        or reviewed_capital.get("capital_moved") is not False
    ):
        raise AlphaEvidenceError("Reviewed Risk evidence contradicts current locked controls")
    if any(
        skeptic.get("regression", {}).get(field) is not False
        for field in (
            "positive_operational_authorization",
            "positive_paper_authorization",
            "positive_live_authorization",
            "positive_risk_approval",
        )
    ):
        raise AlphaEvidenceError("Skeptic evidence unexpectedly claims authorization")

    return {
        "schema_version": 1,
        "alpha_status": "COMPLETED_NON_OPERATIONAL_DEMO",
        "sample": {
            "id": manifest["sample_id"],
            "title": manifest["title"],
            "scenario": manifest["scenario"],
            "evidence_mode": "RETAINED_SYNTHETIC_AND_MOCK_ONLY",
        },
        "outcome": {
            "edge_conclusion": "NO_DEMONSTRATED_EDGE",
            "workflow_disposition": "BLOCKED",
            "scientific_approval": False,
            "paper_authorization": False,
            "live_authorization": False,
            "capital_moved": False,
        },
        "stages": [
            {
                "role": "00 Director",
                "status": "HISTORICAL_MOCK_ONLY_CAPTURE_CURRENTLY_DENIED",
                "contribution": "Resolved a repository task into a retained MOCK_ONLY preflight decision without executing it.",
                "evidence": {
                    "historical_decision": historical["decision"],
                    "historical_operation": historical["operation"],
                    "execution_adapter": historical["execution_adapter"],
                    "current_decision": current["decision"],
                    "current_reason": current["reason"],
                },
                "uncertainty": "The historical dispatch is not current authority or an authenticated operational receipt.",
            },
            {
                "role": "01 Data",
                "status": "PROVENANCE_VALIDATED_ACCESS_UNKNOWN",
                "contribution": "Validated a synthetic observation's source, raw-content, parser, normalizer, availability, and timestamp lineage.",
                "evidence": {
                    "source_id": source["id"],
                    "source_type": source["source_type"],
                    "access_status": source["access_status"],
                    "observation_id": observation["id"],
                    "available_at": observation["available_at"],
                    "unknown_reason": observation["unknown_reason"],
                },
                "uncertainty": "Fixture-only source access is UNKNOWN; Data remains BLOCKED and no external ingestion is authorized.",
            },
            {
                "role": "03 Research",
                "status": "SYNTHETIC_PREREGISTRATION_VALIDATED",
                "contribution": "Validated a pre-results hypothesis freeze, disclosed exploratory ancestry, and an unexamined holdout custody reference.",
                "evidence": {
                    "hypothesis_id": hypothesis["id"],
                    "mode": hypothesis["mode"],
                    "preregistration_id": preregistration["id"],
                    "frozen_at": preregistration["frozen_at"],
                    "scope": preregistration["scope"],
                },
                "uncertainty": "The hypothesis and threshold are synthetic protocol fixtures, not a sports-market edge claim.",
            },
            {
                "role": "04 Quant",
                "status": "BOUNDED_CONTROL_EVIDENCE",
                "contribution": "Demonstrated timestamp and evidence-integrity rejection behavior for a retained synthetic Quant package.",
                "evidence": {
                    "verdict": quant["verdict"],
                    "owner_methods_passed": quant["focused"]["quant_owner"]["passed"],
                    "future_timestamp_rejected": quant["q03"]["future_timestamp_rejected"],
                    "authority_authenticity": quant["risk_boundary"]["authority_authenticity"],
                },
                "uncertainty": "No odds, ROI, confidence interval, robustness estimate, or out-of-sample sports result exists in this sample.",
            },
            {
                "role": "05 Skeptic",
                "status": "FOCUSED_REVIEW_READY_FOR_DIRECTOR_GATE",
                "contribution": "Independently challenged the retained Quant timestamp repair and recorded explicit non-authorization boundaries.",
                "evidence": {
                    "verdict": skeptic["verdict"],
                    "new_findings": skeptic["new_findings"],
                    "positive_operational_authorization": skeptic["regression"]["positive_operational_authorization"],
                    "authority_authenticity": skeptic["authority_boundary"]["authority_authenticity"],
                },
                "uncertainty": "This focused historical review is not formal acceptance of the alpha or the project.",
            },
            {
                "role": "06 Risk & Execution",
                "status": "DENY_NEW_EXPOSURE",
                "contribution": "Reconciled the reviewed synthetic Risk boundary with current bankroll and kill-switch controls.",
                "evidence": {
                    "conceptual_minor": bankroll["total_minor"],
                    "live_deployable_minor": bankroll["live_deployable_minor"],
                    "live_status": bankroll["live_status"],
                    "kill_switch": risk_policy["kill_switch"],
                    "failure_action": risk_policy["failure_action"],
                },
                "uncertainty": "No paper sizing policy, live approval, venue truth, cross-system atomicity, or complete sports-correlation model is established.",
            },
        ],
        "controls": {
            "open_stops": [
                {
                    "id": stop["id"],
                    "severity": stop["severity"],
                    "reason": stop["reason"],
                    "affected_components": stop["affected_components"],
                }
                for stop in open_stops
            ],
            "capital": {
                "currency": bankroll["currency"],
                "basis": bankroll["basis"],
                "conceptual_minor": bankroll["total_minor"],
                "live_deployable_minor": bankroll["live_deployable_minor"],
                "reserved_minor": bankroll["reserved_minor"],
                "live_status": bankroll["live_status"],
                "kill_switch": risk_policy["kill_switch"],
            },
        },
        "known_limitations": [
            "Developer alpha only; no formal release, scientific, paper, live, source-access, or capital approval.",
            "Historical MOCK_ONLY DISPATCH is retained evidence; current repository preflight is DENY.",
            "Data remains BLOCKED; both current STOPs remain OPEN; M0 is blocked and M1 is unreleased.",
            "The sample contains no real sport, market, odds, performance, or profitability evidence.",
            "Production repository validation remains separately blocked by the H-M0-080.v4 exact self-cycle.",
        ],
        "provenance": sorted(provenance, key=lambda item: item["path"]),
    }


def render_text(report: dict[str, Any]) -> str:
    lines = [
        "EdgeLab developer alpha",
        "=======================",
        f"Sample: {report['sample']['title']} ({report['sample']['id']})",
        f"Outcome: {report['outcome']['edge_conclusion']} / {report['outcome']['workflow_disposition']}",
        "",
        "Workflow",
        "--------",
    ]
    for stage in report["stages"]:
        lines.extend([
            f"{stage['role']}: {stage['status']}",
            f"  {stage['contribution']}",
            f"  Uncertainty: {stage['uncertainty']}",
        ])
    capital = report["controls"]["capital"]
    lines.extend([
        "",
        "Safety controls",
        "---------------",
        f"Capital: {capital['currency']} {capital['conceptual_minor'] / 100:.2f} conceptual; "
        f"{capital['currency']} {capital['live_deployable_minor'] / 100:.2f} deployable",
        f"Live: {capital['live_status']} | Kill switch: {capital['kill_switch']}",
    ])
    for stop in report["controls"]["open_stops"]:
        lines.append(f"OPEN {stop['id']} ({stop['severity']}): {stop['reason']}")
    lines.extend([
        "",
        "Limitations",
        "-----------",
        *(f"- {item}" for item in report["known_limitations"]),
        "",
        f"Content-bound artifacts: {len(report['provenance'])}",
    ])
    return "\n".join(lines) + "\n"


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# EdgeLab developer alpha",
        "",
        f"**Sample:** {report['sample']['title']} (`{report['sample']['id']}`)",
        "",
        f"**Outcome:** `{report['outcome']['edge_conclusion']}` / "
        f"`{report['outcome']['workflow_disposition']}`",
        "",
        "## Workflow",
        "",
        "| Role | Status | Contribution | Uncertainty |",
        "|---|---|---|---|",
    ]
    for stage in report["stages"]:
        cells = [
            stage["role"],
            stage["status"],
            stage["contribution"],
            stage["uncertainty"],
        ]
        lines.append("| " + " | ".join(str(cell).replace("|", "\\|") for cell in cells) + " |")
    capital = report["controls"]["capital"]
    lines.extend([
        "",
        "## Safety controls",
        "",
        f"- Capital: {capital['currency']} {capital['conceptual_minor'] / 100:.2f} conceptual; "
        f"{capital['currency']} {capital['live_deployable_minor'] / 100:.2f} deployable.",
        f"- Live: `{capital['live_status']}`; kill switch: `{capital['kill_switch']}`.",
    ])
    for stop in report["controls"]["open_stops"]:
        lines.append(f"- `{stop['id']}` is **OPEN** ({stop['severity']}): {stop['reason']}")
    lines.extend(["", "## Known limitations", ""])
    lines.extend(f"- {item}" for item in report["known_limitations"])
    lines.extend(["", "## Provenance", ""])
    lines.extend(
        f"- `{item['path']}` — `{item['sha256']}`"
        for item in report["provenance"]
    )
    return "\n".join(lines) + "\n"


def _serialize(report: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(report, indent=2, sort_keys=True) + "\n"
    if output_format == "markdown":
        return render_markdown(report)
    return render_text(report)


def _write_output(path: Path, rendered: str, root: Path = ROOT) -> None:
    """Create a new report outside the repository; never overwrite or alias."""
    resolved = path.resolve(strict=False)
    if resolved.is_relative_to(root.resolve()):
        raise AlphaEvidenceError("Output path must be outside the EdgeLab repository")
    try:
        with path.open("x", encoding="utf-8") as stream:
            stream.write(rendered)
    except FileExistsError as error:
        raise AlphaEvidenceError("Refusing to overwrite an existing output file") from error


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--format", choices=("text", "json", "markdown"), default="text")
    parser.add_argument(
        "--output",
        type=Path,
        help="Create a new report outside the repository (existing files are never overwritten)",
    )
    parser.add_argument("--manifest", type=Path, help="Use an alternate alpha manifest (testing only)")
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        report = build_report(ROOT, args.manifest)
        rendered = _serialize(report, args.format)
        if args.output:
            _write_output(args.output, rendered)
        else:
            sys.stdout.write(rendered)
        return 0
    except Exception as error:
        print(f"EdgeLab alpha denied: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
