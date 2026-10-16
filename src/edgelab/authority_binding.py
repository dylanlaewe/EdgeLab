"""Seal a trusted historical decision to an observed runtime subject, DENY-only.

This module deliberately has no positive currentness or authorization branch.
It composes fixed repository sources with the locked runtime reader and returns
either a sealed historical candidate or an unavailable denial.
"""
from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, RefResolver
from tools.generate_persisted_authentic_capture import CAPTURE_FILE, generate
from tools.verify_authentic_history import verify_authentic_history
from tools.verify_trusted_authentic_capture import capture_entry, load_trust

from .locked_authority import read_locked_authority
from .transactional_scheduler import Scheduler, digest


MAPPING_ID = "M0.3A-AUTHORITY-SOURCE-MAPPING"
MAPPING_VERSION = 1
CANONICAL_ROOT = Path(__file__).resolve().parents[2]
MAPPING_PATH = Path("docs/M0.3A_AUTHORITY_SOURCE_MAPPING.v1.md")
TRUST_PATH = Path("docs/M0.2_STAGE1_TRUST_ROOT.v1.json")
CAPTURE_ROOT_PATH = Path("docs/M0.2_HISTORICAL_CAPTURE_ROOT.v1.json")
TRUST_SCHEMA_PATH = Path("schemas/m0-2-stage1-trust-root.v1.schema.json")
SEAL_SCHEMA_PATH = Path("schemas/m0-3a-historical-decision-seal.v1.schema.json")
CANDIDATE_SCHEMA_PATH = Path("schemas/m0-3a-authority-binding-candidate.v1.schema.json")

# Exact source-byte pins are filled from the reviewed repository files. They are
# independent of each JSON root's internal canonical self digest.
_PINNED_SOURCE_SHA256 = {
    "mapping": "31cd83df463560217bd6e2eb0d3f019adc7f6d89756e6ac9e36a6c0fd7494a72",
    "trust": "5000110166a5c0e55aab3656002f3413ffd2e445efc15a528a43f3c4b238f5dd",
    "capture_root": "769dd9ff9731824d401cba3f8f13e74f0ba6ffe288fe4199aa406c27e0e52e99",
}
_PINNED_TRUST_PROJECTION = {
    "id": "M0-2-STAGE1-TRUST-ROOT-V1",
    "sha256": "3b5c653e955a6f1be71c454e86339f39de1f1c864dbfeb71b43f993f9d6b3461",
    "freeze_commit": "bc3a40924ca580ca6eddc4c24e32ff99ddd95330",
    "entrypoint": "edgelab.orchestration.decision",
}
_PINNED_CAPTURE_ROOT_PROJECTION = {
    "id": "M0-2-HISTORICAL-CAPTURE-ROOT-V1",
    "sha256": "7e2e36c17c742c21c45c5d962dcf2119260148ed30b0a3080029622316857490",
}

_LIMITATIONS = (
    "diagnostic historical binding only; never authorizes scheduler, executor, paper, live, or capital action",
    "positive currentness, generation equality, and active repository equality are not established",
    "stored decision_receipt_digest remains caller-supplied and non-authoritative",
    "candidate is neither persisted nor consumed by any scheduler transition",
    "project, STOP, assignment, handoff, dependency, capability, and reachability mappings remain absent",
    "every result is structurally DENY-only and cannot express CURRENT, PASS, generation match, or ALLOW",
)


class _BindingFailure(RuntimeError):
    def __init__(self, code: str, verification: dict[str, Any] | None = None):
        super().__init__(code)
        self.code = code
        self.verification = verification


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _closed_verification(*, historical_valid: bool = False, compatible: bool = False) -> dict[str, Any]:
    return {
        "historical_status": "VALID" if historical_valid else "INVALID",
        "currentness_status": "UNKNOWN",
        "runtime_compatible": compatible,
        "verifier_status": "FAIL",
        "generation_match": False,
        "authorizing_use": "DENY",
        "reason_code": "VERIFIER_FAILURE" if historical_valid else "HISTORICAL_INVALID",
    }


def _candidate(
    capture_id: str,
    task_id: str,
    *,
    attempt: int | None = None,
    seal: dict[str, Any] | None = None,
    authority_sha256: str | None = None,
    evidence_class: str | None = None,
    failure: str | None = None,
    verification: dict[str, Any] | None = None,
) -> dict[str, Any]:
    record = {
        "schema_version": 1,
        "status": "BOUND_DENY_ONLY" if seal is not None else "UNAVAILABLE",
        "capture_id": capture_id,
        "task_id": task_id,
        "attempt": attempt,
        "historical_seal": seal,
        "locked_authority_sha256": authority_sha256,
        "evidence_class": evidence_class,
        "failure_reason": failure,
        "verification": verification or _closed_verification(),
        "limitations": list(_LIMITATIONS),
        "candidate_sha256": "",
    }
    record["candidate_sha256"] = digest(
        {key: value for key, value in record.items() if key != "candidate_sha256"}
    )
    return record


def _validator(path: Path) -> Draft202012Validator:
    schema = json.loads(path.read_text(encoding="utf-8"))
    store: dict[str, Any] = {}
    seal_path = path.parent / SEAL_SCHEMA_PATH.name
    if seal_path.is_file():
        seal_schema = json.loads(seal_path.read_text(encoding="utf-8"))
        store[seal_schema["$id"]] = seal_schema
        store[seal_path.as_uri()] = seal_schema
    return Draft202012Validator(
        schema,
        resolver=RefResolver(path.parent.as_uri() + "/", schema, store=store),
    )


def _validate(path: Path, record: dict[str, Any]) -> None:
    _validator(path).validate(record)


def _checked_unavailable(
    capture_id: str,
    task_id: str,
    failure: str,
    verification: dict[str, Any] | None = None,
) -> dict[str, Any]:
    record = _candidate(
        capture_id,
        task_id,
        failure=failure,
        verification=verification,
    )
    try:
        _validate(CANONICAL_ROOT / CANDIDATE_SCHEMA_PATH, record)
        return record
    except Exception:
        return _candidate(capture_id, task_id, failure="INTERNAL_FAILURE")


def _regular_bytes(root: Path, relative: Path) -> bytes:
    path = root / relative
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise _BindingFailure("SOURCE_INVALID")
    resolved = path.resolve(strict=True)
    if resolved != path or not resolved.is_relative_to(root):
        raise _BindingFailure("SOURCE_INVALID")
    return path.read_bytes()


def _source_bytes(root: Path, fixture: Path | None = None) -> dict[str, bytes]:
    paths = {
        "mapping": MAPPING_PATH,
        "trust": TRUST_PATH,
        "capture_root": CAPTURE_ROOT_PATH,
    }
    if fixture is not None:
        paths["sidecar"] = (fixture / CAPTURE_FILE).relative_to(root)
    return {key: _regular_bytes(root, path) for key, path in paths.items()}


def _verify_pinned_sources(sources: dict[str, bytes]) -> None:
    if any(_sha256_bytes(sources[key]) != expected for key, expected in _PINNED_SOURCE_SHA256.items()):
        raise _BindingFailure("SOURCE_INVALID")


def _seal(
    *,
    mapping_sha256: str,
    trust: dict[str, Any],
    capture_root: dict[str, Any],
    entry: dict[str, Any],
    sidecar: dict[str, Any],
    historical: dict[str, Any],
) -> dict[str, Any]:
    result = sidecar["result"]
    decision = dict(result)
    verification = {
        "status": historical["status"],
        "capture_id": historical["capture_id"],
        "trusted_root_id": historical["trusted_root_id"],
        "replay_completed": historical["replay"]["completed"],
        "raw_result_match": historical["replay"]["raw_result_match"],
        "frozen_commit": historical["evidence"]["frozen_commit"],
        "replay_root": historical["evidence"]["replay_root"],
        "raw_result_sha256": historical["evidence"]["raw_result_sha256"],
        "decision_id": historical["evidence"]["decision_id"],
    }
    capture = {
        "capture_id": entry["capture_id"],
        "fixture_path": entry["fixture_path"],
        "sidecar_sha256": entry["sidecar_sha256"],
        "graph_sha256": entry["graph_sha256"],
        "repository_inventory_sha256": entry["repository_inventory_sha256"],
    }
    mapping = {"id": MAPPING_ID, "version": MAPPING_VERSION, "sha256": mapping_sha256}
    trusted = {
        "id": trust["root_id"],
        "sha256": trust["root_sha256"],
        "freeze_commit": trust["freeze_commit"],
        "entrypoint": trust["entrypoint"],
    }
    capture_root_projection = {
        "id": capture_root["root_id"],
        "sha256": capture_root["root_sha256"],
    }
    subject = dict(sidecar["intent"])
    raw_result_sha256 = digest(result)
    source_projection = {
        "mapping_contract": mapping,
        "trusted_root": trusted,
        "capture_root": capture_root_projection,
        "capture": capture,
        "subject": subject,
        "decision": decision,
        "raw_result_sha256": raw_result_sha256,
    }
    source_projection_sha256 = digest(source_projection)
    record = {
        "schema_version": 1,
        "seal_id": "HS-" + source_projection_sha256[:32],
        **source_projection,
        "historical_verification": verification,
        "stable_projection_sha256": digest(verification),
        "source_projection_sha256": source_projection_sha256,
        "seal_sha256": "",
    }
    record["seal_sha256"] = digest(
        {key: value for key, value in record.items() if key != "seal_sha256"}
    )
    return record


def verify_binding_integrity(record: dict[str, Any]) -> bool:
    """Verify shape, cross-field bindings, and every locally derivable digest.

    This verifies a returned record, not its historical source or live runtime.
    Only ``compose_authority_binding`` performs those observations.
    """
    try:
        _validate(CANONICAL_ROOT / CANDIDATE_SCHEMA_PATH, record)
        if record["candidate_sha256"] != digest(
            {key: value for key, value in record.items() if key != "candidate_sha256"}
        ):
            return False
        if record["status"] == "UNAVAILABLE":
            return True

        seal = record["historical_seal"]
        _validate(CANONICAL_ROOT / SEAL_SCHEMA_PATH, seal)
        if seal["seal_sha256"] != digest(
            {key: value for key, value in seal.items() if key != "seal_sha256"}
        ):
            return False
        decision = seal["decision"]
        historical = seal["historical_verification"]
        source_projection = {
            "mapping_contract": seal["mapping_contract"],
            "trusted_root": seal["trusted_root"],
            "capture_root": seal["capture_root"],
            "capture": seal["capture"],
            "subject": seal["subject"],
            "decision": decision,
            "raw_result_sha256": seal["raw_result_sha256"],
        }
        source_digest = digest(source_projection)
        expected_class = (
            "R_GATE_CANDIDATE_EVIDENCE"
            if decision["decision"] == "DISPATCH"
            else "NON_AUTHORIZING_EVIDENCE"
        )
        return all(
            (
                record["task_id"] == seal["subject"]["task_id"] == decision["task_id"],
                record["capture_id"] == seal["capture"]["capture_id"] == historical["capture_id"],
                record["attempt"] == seal["subject"]["attempt"],
                record["evidence_class"] == expected_class,
                seal["mapping_contract"]
                == {
                    "id": MAPPING_ID,
                    "version": MAPPING_VERSION,
                    "sha256": _PINNED_SOURCE_SHA256["mapping"],
                },
                seal["trusted_root"] == _PINNED_TRUST_PROJECTION,
                seal["capture_root"] == _PINNED_CAPTURE_ROOT_PROJECTION,
                seal["trusted_root"]["id"] == historical["trusted_root_id"],
                seal["trusted_root"]["freeze_commit"] == historical["frozen_commit"],
                historical["replay_root"] == "persisted-graph:" + seal["capture"]["graph_sha256"],
                seal["raw_result_sha256"] == historical["raw_result_sha256"] == digest(decision),
                decision["decision_id"] == historical["decision_id"],
                seal["stable_projection_sha256"] == digest(historical),
                seal["source_projection_sha256"] == source_digest,
                seal["seal_id"] == "HS-" + source_digest[:32],
            )
        )
    except Exception:
        return False


def compose_authority_binding(
    scheduler: Scheduler,
    task_id: str,
    capture_id: str,
) -> dict[str, Any]:
    """Return a sealed historical/runtime subject candidate that always denies."""
    root = scheduler.root
    verification: dict[str, Any] | None = None
    try:
        if not isinstance(task_id, str) or not task_id or not isinstance(capture_id, str) or not capture_id:
            raise _BindingFailure("INPUT_INVALID")
        if root != CANONICAL_ROOT:
            raise _BindingFailure("SOURCE_INVALID")

        initial_sources = _source_bytes(root)
        _verify_pinned_sources(initial_sources)
        parsed_trust = json.loads(initial_sources["trust"])
        parsed_capture_root = json.loads(initial_sources["capture_root"])
        _validate(root / TRUST_SCHEMA_PATH, parsed_trust)
        _validate(root / "schemas/m0-2-historical-capture-root.v1.schema.json", parsed_capture_root)
        trust, capture_root = load_trust(root / TRUST_PATH, root / CAPTURE_ROOT_PATH)
        if trust != parsed_trust or capture_root != parsed_capture_root:
            raise _BindingFailure("SOURCE_INVALID")
        try:
            entry = capture_entry(capture_id, capture_root)
        except ValueError as error:
            raise _BindingFailure("CAPTURE_UNKNOWN") from error

        fixture = (root / entry["fixture_path"]).resolve()
        if not fixture.is_relative_to(root) or fixture != root / entry["fixture_path"] or not fixture.is_dir():
            raise _BindingFailure("SOURCE_INVALID")
        initial_sources.update(_source_bytes(root, fixture))
        if _sha256_bytes(initial_sources["sidecar"]) != entry["sidecar_sha256"]:
            raise _BindingFailure("SOURCE_INVALID")
        sidecar = json.loads(initial_sources["sidecar"])
        if sidecar.get("capture_id") != capture_id:
            raise _BindingFailure("SOURCE_INVALID")

        historical = verify_authentic_history(
            fixture,
            trusted_root=root / TRUST_PATH,
            capture_trust_root=root / CAPTURE_ROOT_PATH,
        )
        verification = historical.get("authorization_result")
        if (
            historical.get("status") != "HISTORICALLY_VALID"
            or historical.get("capture_id") != capture_id
            or historical.get("trusted_root_id") != trust["root_id"]
            or historical.get("replay") != {"completed": True, "raw_result_match": True}
            or not isinstance(verification, dict)
            or verification.get("authorizing_use") != "DENY"
        ):
            raise _BindingFailure("HISTORICAL_INVALID", verification)

        graph = generate(fixture)
        if graph.get("self_sha256") != entry["graph_sha256"] or graph.get("capture") != sidecar:
            raise _BindingFailure("SOURCE_INVALID", verification)
        result = sidecar.get("result")
        intent = sidecar.get("intent")
        if not isinstance(result, dict) or not isinstance(intent, dict):
            raise _BindingFailure("SOURCE_INVALID", verification)
        decision = result.get("decision")
        operation = result.get("operation")
        if (
            decision not in {"DISPATCH", "DENY"}
            or result.get("execution_adapter") != "MOCK_ONLY"
            or (decision == "DISPATCH" and (not isinstance(operation, str) or not operation))
            or (decision == "DENY" and operation is not None)
            or digest(result) != historical["evidence"].get("raw_result_sha256")
            or result.get("decision_id") != historical["evidence"].get("decision_id")
            or historical["evidence"].get("frozen_commit") != trust["freeze_commit"]
            or historical["evidence"].get("replay_root") != "persisted-graph:" + entry["graph_sha256"]
        ):
            raise _BindingFailure("SOURCE_INVALID", verification)

        first = read_locked_authority(scheduler, task_id)
        if first.get("observation_status") != "COHERENT_DENY_ONLY" or not first.get("authority_sha256"):
            raise _BindingFailure("RUNTIME_UNAVAILABLE", verification)
        authority = first["authority"]
        attempt = authority["task"]["tuple"]["attempt_no"]
        if (
            intent.get("task_id") != task_id
            or result.get("task_id") != task_id
            or type(intent.get("attempt")) is not int
            or intent["attempt"] < 1
            or intent["attempt"] != attempt
            or authority["task"]["task_id"] != task_id
        ):
            raise _BindingFailure("SUBJECT_MISMATCH", verification)

        final_sources = _source_bytes(root, fixture)
        _verify_pinned_sources(final_sources)
        final_trust, final_capture_root = load_trust(root / TRUST_PATH, root / CAPTURE_ROOT_PATH)
        parsed_final_trust = json.loads(final_sources["trust"])
        parsed_final_capture_root = json.loads(final_sources["capture_root"])
        second = read_locked_authority(scheduler, task_id)
        if (
            initial_sources != final_sources
            or trust != final_trust
            or capture_root != final_capture_root
            or final_trust != parsed_final_trust
            or final_capture_root != parsed_final_capture_root
        ):
            raise _BindingFailure("RACE_DETECTED", verification)
        if (
            second.get("observation_status") != "COHERENT_DENY_ONLY"
            or second.get("authority_sha256") != first["authority_sha256"]
        ):
            raise _BindingFailure("RACE_DETECTED", verification)

        seal = _seal(
            mapping_sha256=_sha256_bytes(initial_sources["mapping"]),
            trust=trust,
            capture_root=capture_root,
            entry=entry,
            sidecar=sidecar,
            historical=historical,
        )
        _validate(root / SEAL_SCHEMA_PATH, seal)
        bound_verification = _closed_verification(historical_valid=True, compatible=True)
        record = _candidate(
            capture_id,
            task_id,
            attempt=attempt,
            seal=seal,
            authority_sha256=first["authority_sha256"],
            evidence_class=(
                "R_GATE_CANDIDATE_EVIDENCE"
                if decision == "DISPATCH"
                else "NON_AUTHORIZING_EVIDENCE"
            ),
            verification=bound_verification,
        )
        _validate(root / CANDIDATE_SCHEMA_PATH, record)
        if not verify_binding_integrity(record):
            raise _BindingFailure("INTERNAL_FAILURE", bound_verification)
        return record
    except _BindingFailure as error:
        return _checked_unavailable(
            capture_id if isinstance(capture_id, str) else "",
            task_id if isinstance(task_id, str) else "",
            error.code,
            error.verification,
        )
    except Exception:
        return _checked_unavailable(
            capture_id if isinstance(capture_id, str) else "",
            task_id if isinstance(task_id, str) else "",
            "INTERNAL_FAILURE",
            verification,
        )
