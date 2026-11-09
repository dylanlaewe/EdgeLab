"""Pure, non-authorizing verifier for M0.3A proof-candidate packages."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
from typing import Any


REGISTRY_RAW_SHA256 = "874eecc433f27d16fae5c9f565b03dc85aa264fd8fbe7ca5519576499a77bae1"
CLOSURE_RAW_SHA256 = "0adcabed5124579a8a322b30cc2a0fe802686e274f5ed319f66a7f2e60dd33c3"
DISCOVERY_RAW_SHA256 = "9914da2984589f7ded860656be4cbfdb88cf7d106ce52856860ed756dfe8725f"
CLASSIFICATION_RAW_SHA256 = "c82365a11a5cce64c91422151c4b38052ea78f2ed43d4848802734e6d2fe5ad1"
CANDIDATE_RAW_SHA256 = "1412fd869c8247d5a0fe27834c8ef386c1356f5ea73550f4235ad24c7ec2c073"
CANDIDATE_BYTE_LENGTH = 602_682
WITNESS_LEDGER_SHA256 = "f011a87b6342100b2f500ebe79c26a9b30f07f878531ce98360759de99589be0"
COMPILER_OUTPUT_SHA256 = "8c72e6be16266c22f1bc47d83b9a4580a182580494036d5f57bfbc1c4862e100"
RULE_DOMAIN = "EDGELAB\0M0_3A_PROOF_COMPILER_RULE\0V1\0"
REGISTRY_DOMAIN = "EDGELAB\0M0_3A_PROOF_COMPILER_RULE_REGISTRY\0V1\0"
CLOSURE_DOMAIN = "EDGELAB\0M0_3A_PROOF_COMPILER_CLOSURE\0V1\0"
LEDGER_DOMAIN = "EDGELAB\0M0_3A_MINLENGTH_CANDIDATE_WITNESS_LEDGER\0V1\0"
OUTPUT_DOMAIN = "EDGELAB\0M0_3A_MINLENGTH_PROOF_COMPILER_OUTPUT\0V1\0"


@dataclass(frozen=True, slots=True)
class PackageFile:
    path: str
    raw: bytes


@dataclass(frozen=True, slots=True)
class CandidatePackage:
    registry: bytes
    closure: bytes
    compiler_output: bytes
    files: tuple[PackageFile, ...]


@dataclass(frozen=True, order=True, slots=True)
class CandidateFinding:
    code: str
    coordinate: str


@dataclass(frozen=True, slots=True)
class CandidatePackageResult:
    status: str
    findings: tuple[CandidateFinding, ...]
    witness_ledger_sha256: str | None = None
    candidate_only_site_count: int | None = None
    schema_version: int = field(default=1, init=False)
    verifier_id: str = field(
        default="EDGELAB_M0_3A_PROOF_CANDIDATE_PACKAGE_VERIFIER_V1",
        init=False,
    )
    governance_equivalence: str = field(default="NOT_ESTABLISHED", init=False)
    accepted_classification_change: bool = field(default=False, init=False)
    authorizing_use: str = field(default="DENY", init=False)

    def __post_init__(self) -> None:
        if self.status not in {"VALID_CANDIDATE", "INVALID"}:
            raise ValueError("closed candidate verifier status")
        if tuple(sorted(set(self.findings))) != self.findings:
            raise ValueError("findings must be unique and sorted")
        if self.status == "VALID_CANDIDATE" and self.findings:
            raise ValueError("valid candidate cannot contain findings")
        if self.status == "INVALID" and not self.findings:
            raise ValueError("invalid candidate requires findings")

    def __bool__(self) -> bool:
        raise TypeError("candidate package results are not authorization booleans")

    def as_mapping(self) -> dict[str, Any]:
        mapping = asdict(self)
        mapping["findings"] = [asdict(item) for item in self.findings]
        return mapping


class _Invalid(ValueError):
    def __init__(self, code: str, coordinate: str = "/") -> None:
        self.code = code
        self.coordinate = coordinate
        super().__init__(f"{code}:{coordinate}")


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as error:
        raise _Invalid("CANONICAL_JSON") from error


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _domain_digest(domain: str, value: Any) -> str:
    return _sha256(domain.encode("ascii") + _canonical(value))


def _parse(raw: Any, coordinate: str, *, canonical_line: bool = False) -> Any:
    if type(raw) is not bytes:
        raise _Invalid("HOST_BYTES", coordinate)

    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise _Invalid("DUPLICATE_JSON_KEY", coordinate)
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=no_duplicates)
    except _Invalid:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise _Invalid("INVALID_JSON", coordinate) from error
    if canonical_line and _canonical(value) + b"\n" != raw:
        raise _Invalid("NONCANONICAL_JSON", coordinate)
    return value


def _verify_registry(raw: bytes) -> dict[str, Any]:
    if _sha256(raw) != REGISTRY_RAW_SHA256:
        raise _Invalid("REGISTRY_RAW_SHA256", "/registry")
    registry = _parse(raw, "/registry")
    if type(registry) is not dict or registry.get("registry_sha256") != _domain_digest(
        REGISTRY_DOMAIN,
        {key: value for key, value in registry.items() if key != "registry_sha256"},
    ):
        raise _Invalid("REGISTRY_SELF_DIGEST", "/registry_sha256")
    if (
        registry.get("status") != "CANDIDATE_ONLY"
        or registry.get("authorizing_use") != "DENY"
        or registry.get("governance_equivalence") != "NOT_ESTABLISHED"
    ):
        raise _Invalid("REGISTRY_AUTHORITY", "/registry")
    rules = registry.get("rules")
    if type(rules) is not list or len(rules) != 1 or type(rules[0]) is not dict:
        raise _Invalid("REGISTRY_RULE_CARDINALITY", "/rules")
    rule = rules[0]
    if rule.get("rule_sha256") != _domain_digest(
        RULE_DOMAIN,
        {key: value for key, value in rule.items() if key != "rule_sha256"},
    ):
        raise _Invalid("RULE_SELF_DIGEST", "/rules/0/rule_sha256")
    if (
        rule.get("family_id") != "DRAFT_2020_12_EXACT_LOCATION_MINLENGTH_V1"
        or rule.get("status") != "CANDIDATE_ONLY"
        or rule.get("authorizing_use") != "DENY"
        or rule.get("keyword") != "minLength"
        or rule.get("metric") != "UNICODE_CODE_POINT_COUNT"
        or rule.get("operator") != ">="
        or rule.get("unit") != "UNICODE_CODE_POINTS"
    ):
        raise _Invalid("RULE_SEMANTICS", "/rules/0")
    return registry


def _verify_closure(raw: bytes, registry: dict[str, Any]) -> dict[str, Any]:
    if _sha256(raw) != CLOSURE_RAW_SHA256:
        raise _Invalid("CLOSURE_RAW_SHA256", "/closure")
    closure = _parse(raw, "/closure")
    if type(closure) is not dict or closure.get("closure_sha256") != _domain_digest(
        CLOSURE_DOMAIN,
        {key: value for key, value in closure.items() if key != "closure_sha256"},
    ):
        raise _Invalid("CLOSURE_SELF_DIGEST", "/closure_sha256")
    if (
        closure.get("status") != "CANDIDATE_ONLY"
        or closure.get("authorizing_use") != "DENY"
        or closure.get("governance_equivalence") != "NOT_ESTABLISHED"
        or closure.get("registry", {}).get("raw_sha256") != REGISTRY_RAW_SHA256
        or closure.get("registry", {}).get("registry_sha256")
        != registry.get("registry_sha256")
    ):
        raise _Invalid("CLOSURE_BOUNDARY", "/closure")
    return closure


def _verify_files(files: Any, closure: dict[str, Any]) -> None:
    if type(files) is not tuple or any(type(item) is not PackageFile for item in files):
        raise _Invalid("PACKAGE_FILE_HOST_TYPE", "/files")
    paths = [item.path for item in files]
    if len(paths) != len(set(paths)):
        raise _Invalid("PACKAGE_FILE_DUPLICATE", "/files")
    if paths != sorted(paths):
        raise _Invalid("PACKAGE_FILE_ORDER", "/files")
    expected = closure.get("files")
    if type(expected) is not list:
        raise _Invalid("CLOSURE_FILE_SHAPE", "/closure/files")
    expected_by_path = {item.get("path"): item for item in expected if type(item) is dict}
    if len(expected_by_path) != len(expected) or set(paths) != set(expected_by_path):
        raise _Invalid("PACKAGE_FILE_SET", "/files")
    for item in files:
        if type(item.path) is not str or type(item.raw) is not bytes:
            raise _Invalid("PACKAGE_FILE_HOST_TYPE", "/files")
        pin = expected_by_path[item.path]
        if len(item.raw) != pin.get("byte_length") or _sha256(item.raw) != pin.get("raw_sha256"):
            raise _Invalid("PACKAGE_FILE_IDENTITY", item.path)


def _verify_candidate(raw: bytes, registry: dict[str, Any], closure: dict[str, Any]) -> dict[str, Any]:
    if len(raw) != CANDIDATE_BYTE_LENGTH or _sha256(raw) != CANDIDATE_RAW_SHA256:
        raise _Invalid("CANDIDATE_RAW_IDENTITY", "/compiler_output")
    candidate = _parse(raw, "/compiler_output", canonical_line=True)
    if type(candidate) is not dict:
        raise _Invalid("CANDIDATE_SHAPE", "/compiler_output")
    if (
        candidate.get("status") != "VALID_CANDIDATE_ONLY"
        or candidate.get("authorizing_use") != "DENY"
        or candidate.get("governance_equivalence") != "NOT_ESTABLISHED"
        or candidate.get("accepted_classification_manifest", {}).get("accepted_count_changed")
        is not False
    ):
        raise _Invalid("CANDIDATE_AUTHORITY", "/compiler_output")
    if candidate.get("witness_ledger_sha256") != _domain_digest(
        LEDGER_DOMAIN, candidate.get("witnesses")
    ) or candidate.get("witness_ledger_sha256") != WITNESS_LEDGER_SHA256:
        raise _Invalid("CANDIDATE_LEDGER_DIGEST", "/witness_ledger_sha256")
    if candidate.get("compiler_output_sha256") != _domain_digest(
        OUTPUT_DOMAIN,
        {key: value for key, value in candidate.items() if key != "compiler_output_sha256"},
    ) or candidate.get("compiler_output_sha256") != COMPILER_OUTPUT_SHA256:
        raise _Invalid("CANDIDATE_OUTPUT_DIGEST", "/compiler_output_sha256")
    witnesses = candidate.get("witnesses")
    if type(witnesses) is not list or len(witnesses) != 721:
        raise _Invalid("CANDIDATE_WITNESS_CARDINALITY", "/witnesses")
    keys = [
        f"{item.get('namespace')}:{item.get('site_id')}"
        for item in witnesses if type(item) is dict
    ]
    if len(keys) != 721 or len(keys) != len(set(keys)) or keys != sorted(keys):
        raise _Invalid("CANDIDATE_WITNESS_IDENTITY", "/witnesses")
    if any(item.get("authorizing_use") != "DENY" for item in witnesses):
        raise _Invalid("CANDIDATE_WITNESS_AUTHORITY", "/witnesses")
    dispositions = {
        name: sum(
            item.get("rule_evaluation", {}).get("disposition") == name
            for item in witnesses
        )
        for name in (
            "ACCEPTED_REFERENCE_MATCH", "CANDIDATE_ONLY", "AMBIGUOUS", "NONMATCHING"
        )
    }
    expected_counts = registry["rules"][0]["expected_counts"]
    if dispositions != {
        "ACCEPTED_REFERENCE_MATCH": expected_counts["accepted_reference_match"],
        "CANDIDATE_ONLY": expected_counts["candidate_only"],
        "AMBIGUOUS": expected_counts["ambiguous"],
        "NONMATCHING": expected_counts["nonmatching"],
    }:
        raise _Invalid("CANDIDATE_DISPOSITION_COUNTS", "/witnesses")
    frozen = candidate.get("frozen_census", {})
    accepted = candidate.get("accepted_classification_manifest", {})
    closure_inputs = closure.get("frozen_inputs", {})
    if (
        frozen.get("raw_sha256") != DISCOVERY_RAW_SHA256
        or accepted.get("raw_sha256") != CLASSIFICATION_RAW_SHA256
        or closure_inputs.get("discovery_raw_sha256") != DISCOVERY_RAW_SHA256
        or closure_inputs.get("classification_raw_sha256") != CLASSIFICATION_RAW_SHA256
        or registry["frozen_inputs"]["discovery"]["raw_sha256"] != DISCOVERY_RAW_SHA256
        or registry["frozen_inputs"]["accepted_classification"]["raw_sha256"]
        != CLASSIFICATION_RAW_SHA256
    ):
        raise _Invalid("CANDIDATE_FROZEN_BINDING", "/frozen_census")
    expected_output = registry["rules"][0]["expected_output"]
    if expected_output != {
        "raw_sha256": CANDIDATE_RAW_SHA256,
        "byte_length": CANDIDATE_BYTE_LENGTH,
        "witness_ledger_sha256": WITNESS_LEDGER_SHA256,
        "compiler_output_sha256": COMPILER_OUTPUT_SHA256,
    } or closure.get("expected_output") != expected_output:
        raise _Invalid("CANDIDATE_EXPECTED_OUTPUT", "/expected_output")
    return candidate


def verify_candidate_package(package: CandidatePackage) -> CandidatePackageResult:
    """Verify one exact candidate package; never accept classifications."""
    try:
        if type(package) is not CandidatePackage:
            raise _Invalid("PACKAGE_HOST_TYPE")
        registry = _verify_registry(package.registry)
        closure = _verify_closure(package.closure, registry)
        _verify_files(package.files, closure)
        candidate = _verify_candidate(
            package.compiler_output, registry, closure
        )
        return CandidatePackageResult(
            "VALID_CANDIDATE",
            (),
            witness_ledger_sha256=candidate["witness_ledger_sha256"],
            candidate_only_site_count=candidate["coverage"]["candidate_only_site_count"],
        )
    except _Invalid as error:
        return CandidatePackageResult(
            "INVALID", (CandidateFinding(error.code, error.coordinate),)
        )
    except (AttributeError, KeyError, TypeError, ValueError):
        return CandidatePackageResult(
            "INVALID", (CandidateFinding("INTERNAL_INVALID", "/"),)
        )
