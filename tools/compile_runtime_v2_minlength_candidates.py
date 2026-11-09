#!/usr/bin/env python3
"""Compile a complete, non-authorizing candidate ledger for schema minLength.

The compiler consumes the already frozen runtime-v2 resource census through
the production readiness inventory.  It never updates the accepted
classification manifest and cannot express release or operational authority.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import stat
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.check_runtime_v2_release_readiness import build_report


DISCOVERY_PATH = "docs/M0.3A_RUNTIME_V2_RESOURCE_DISCOVERY.v8.json"
DISCOVERY_RAW_SHA256 = "9914da2984589f7ded860656be4cbfdb88cf7d106ce52856860ed756dfe8725f"
CLASSIFICATION_PATH = "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v55.json"
CLASSIFICATION_RAW_SHA256 = "c82365a11a5cce64c91422151c4b38052ea78f2ed43d4848802734e6d2fe5ad1"
RULE_REGISTRY_PATH = "docs/M0.3A_PROOF_COMPILER_RULE_REGISTRY.v1.json"
RULE_REGISTRY_RAW_SHA256 = "874eecc433f27d16fae5c9f565b03dc85aa264fd8fbe7ca5519576499a77bae1"
RULE_REGISTRY_SCHEMA_PATH = "schemas/m0-3a-proof-compiler-rule-registry.v1.schema.json"
RULE_REGISTRY_SCHEMA_RAW_SHA256 = "7fb037878e704d4d79e0b842cf7b045122a5f93b4d7ba5616d4b162dc6d8a75e"
DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema"
SOURCE_SITES_DOMAIN = "EDGELAB\0RUNTIME_V2_SOURCE_BOUND_SITES\0V7\0"
SCHEMA_SITES_DOMAIN = "EDGELAB\0RUNTIME_V2_SCHEMA_BOUND_SITES\0V2\0"
SOURCE_INPUTS_DOMAIN = "EDGELAB\0RUNTIME_V2_RESOURCE_SOURCE_INPUTS\0V1\0"
SCHEMA_INPUTS_DOMAIN = "EDGELAB\0RUNTIME_V2_RESOURCE_SCHEMA_INPUTS\0V1\0"
CONTAINING_SUBSCHEMA_DOMAIN = (
    "EDGELAB\0RUNTIME_V2_SCHEMA_CONTAINING_SUBSCHEMA\0V1\0"
)
LEDGER_DOMAIN = "EDGELAB\0M0_3A_MINLENGTH_CANDIDATE_WITNESS_LEDGER\0V1\0"
OUTPUT_DOMAIN = "EDGELAB\0M0_3A_MINLENGTH_PROOF_COMPILER_OUTPUT\0V1\0"
RULE_DOMAIN = "EDGELAB\0M0_3A_PROOF_COMPILER_RULE\0V1\0"
REGISTRY_DOMAIN = "EDGELAB\0M0_3A_PROOF_COMPILER_RULE_REGISTRY\0V1\0"


class ProofCompilerError(RuntimeError):
    """A frozen input or candidate-output invariant failed closed."""

    def __init__(self, code: str, coordinate: str = "/") -> None:
        self.code = code
        self.coordinate = coordinate
        super().__init__(f"{code}:{coordinate}")


@dataclass(frozen=True, slots=True)
class CandidateVerification:
    status: str
    witness_ledger_sha256: str
    inspected_site_count: int
    candidate_only_site_count: int
    authorizing_use: str = "DENY"

    def __bool__(self) -> bool:
        raise TypeError("candidate verification is not an authorization boolean")

    def as_mapping(self) -> dict[str, Any]:
        return asdict(self)


def canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as error:
        raise ProofCompilerError("CANONICAL_JSON") from error


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _domain_digest(domain: str, value: Any) -> str:
    return _sha256(domain.encode("ascii") + canonical_json(value))


def _parse_json(raw: bytes, coordinate: str) -> Any:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ProofCompilerError("DUPLICATE_JSON_KEY", coordinate)
            result[key] = value
        return result

    try:
        return json.loads(raw, object_pairs_hook=no_duplicates)
    except ProofCompilerError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProofCompilerError("INVALID_JSON", coordinate) from error


def _read_pinned_json(root: Path, relative: str, expected_sha256: str) -> Any:
    path = root / relative
    try:
        mode = path.lstat().st_mode
        raw = path.read_bytes()
    except OSError as error:
        raise ProofCompilerError("PINNED_INPUT_UNAVAILABLE", relative) from error
    if path.is_symlink() or not stat.S_ISREG(mode):
        raise ProofCompilerError("PINNED_INPUT_SHAPE", relative)
    if _sha256(raw) != expected_sha256:
        raise ProofCompilerError("PINNED_INPUT_STALE", relative)
    return _parse_json(raw, relative)


def _load_rule_registry(root: Path) -> dict[str, Any]:
    registry = _read_pinned_json(root, RULE_REGISTRY_PATH, RULE_REGISTRY_RAW_SHA256)
    schema_raw = (root / RULE_REGISTRY_SCHEMA_PATH).read_bytes()
    if _sha256(schema_raw) != RULE_REGISTRY_SCHEMA_RAW_SHA256:
        raise ProofCompilerError("RULE_REGISTRY_SCHEMA_STALE")
    if type(registry) is not dict or registry.get("registry_sha256") != _domain_digest(
        REGISTRY_DOMAIN,
        {key: value for key, value in registry.items() if key != "registry_sha256"},
    ):
        raise ProofCompilerError("RULE_REGISTRY_DIGEST")
    if (
        registry.get("status") != "CANDIDATE_ONLY"
        or registry.get("authorizing_use") != "DENY"
        or registry.get("governance_equivalence") != "NOT_ESTABLISHED"
        or registry.get("schema") != {
            "path": RULE_REGISTRY_SCHEMA_PATH,
            "raw_sha256": RULE_REGISTRY_SCHEMA_RAW_SHA256,
        }
    ):
        raise ProofCompilerError("RULE_REGISTRY_BOUNDARY")
    rules = registry.get("rules")
    if type(rules) is not list or len(rules) != 1 or type(rules[0]) is not dict:
        raise ProofCompilerError("RULE_REGISTRY_CARDINALITY")
    rule = rules[0]
    if rule.get("rule_sha256") != _domain_digest(
        RULE_DOMAIN,
        {key: value for key, value in rule.items() if key != "rule_sha256"},
    ):
        raise ProofCompilerError("RULE_REGISTRY_RULE_DIGEST")
    expected = {
        "family_id": "DRAFT_2020_12_EXACT_LOCATION_MINLENGTH_V1",
        "version": 1,
        "status": "CANDIDATE_ONLY",
        "authorizing_use": "DENY",
        "census_namespace": "SCHEMA",
        "dialect": DRAFT_2020_12,
        "keyword": "minLength",
        "bound_type": "NON_BOOLEAN_NONNEGATIVE_INTEGER",
        "instance_domain": "STRING",
        "metric": "UNICODE_CODE_POINT_COUNT",
        "operator": ">=",
        "unit": "UNICODE_CODE_POINTS",
        "applicability": "EXACT_PINNED_SCHEMA_LOCATION_ONLY",
        "non_domain_behavior": "NO_ASSERTION_FROM_THIS_KEYWORD",
    }
    if any(rule.get(key) != value for key, value in expected.items()):
        raise ProofCompilerError("RULE_REGISTRY_SEMANTICS")
    return registry


def _decode_pointer(pointer: str) -> list[str]:
    if pointer == "":
        return []
    if not pointer.startswith("/"):
        raise ProofCompilerError("POINTER_SYNTAX", pointer)
    tokens: list[str] = []
    for encoded in pointer[1:].split("/"):
        decoded: list[str] = []
        index = 0
        while index < len(encoded):
            if encoded[index] != "~":
                decoded.append(encoded[index])
                index += 1
            elif index + 1 < len(encoded) and encoded[index + 1] in "01":
                decoded.append("~" if encoded[index + 1] == "0" else "/")
                index += 2
            else:
                raise ProofCompilerError("POINTER_SYNTAX", pointer)
        tokens.append("".join(decoded))
    return tokens


def _resolve_pointer(document: Any, pointer: str) -> Any:
    value = document
    for token in _decode_pointer(pointer):
        if type(value) is dict and token in value:
            value = value[token]
        elif (
            type(value) is list
            and token.isascii()
            and token.isdigit()
            and (token == "0" or not token.startswith("0"))
            and int(token) < len(value)
        ):
            value = value[int(token)]
        else:
            raise ProofCompilerError("POINTER_MISSING", pointer)
    return value


def _ancestor_context(document: Any, containing_pointer: str) -> dict[str, Any]:
    encoded_tokens = [] if containing_pointer == "" else containing_pointer[1:].split("/")
    pointers = [""]
    for encoded in encoded_tokens:
        pointers.append(f"{pointers[-1]}/{encoded}")
    sequence = []
    for index, pointer in enumerate(pointers):
        _resolve_pointer(document, pointer)
        sequence.append({"index": index, "pointer": pointer})
    return {
        "binding": "FULL_SCHEMA_DOCUMENT_RAW_SHA256",
        "ordered_pointer_sequence": sequence,
    }


def _schema_ambiguities(document: Any, expected_schema_id: str) -> list[str]:
    """Return unsupported local-proof conditions, never positive semantics."""
    reasons: set[str] = set()
    if type(document) is not dict:
        return ["SCHEMA_ROOT_NOT_OBJECT"]
    if document.get("$schema") != DRAFT_2020_12:
        reasons.add("SCHEMA_DIALECT_UNSUPPORTED")
    if document.get("$id") != expected_schema_id:
        reasons.add("SCHEMA_ROOT_ID_MISMATCH")

    def walk(value: Any, pointer: str) -> None:
        if type(value) is dict:
            if pointer and "$id" in value:
                reasons.add("NESTED_SCHEMA_ID")
            if pointer and "$schema" in value:
                reasons.add("NESTED_SCHEMA_DIALECT")
            if "$dynamicRef" in value or "$recursiveRef" in value:
                reasons.add("DYNAMIC_REFERENCE_UNSUPPORTED")
            reference = value.get("$ref")
            if reference is not None:
                if type(reference) is not str or not (
                    reference == "#" or reference.startswith("#/")
                ) or "%" in reference:
                    reasons.add("NONLOCAL_REFERENCE_UNSUPPORTED")
                elif type(reference) is str:
                    try:
                        _resolve_pointer(document, reference[1:])
                    except ProofCompilerError:
                        reasons.add("LOCAL_REFERENCE_UNRESOLVED")
            for key in sorted(value):
                escaped = key.replace("~", "~0").replace("/", "~1")
                walk(value[key], f"{pointer}/{escaped}")
        elif type(value) is list:
            for index, child in enumerate(value):
                walk(child, f"{pointer}/{index}")

    walk(document, "")
    return sorted(reasons)


def _frozen_inventory(
    root: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    discovery_pin = _read_pinned_json(root, DISCOVERY_PATH, DISCOVERY_RAW_SHA256)
    accepted = _read_pinned_json(
        root, CLASSIFICATION_PATH, CLASSIFICATION_RAW_SHA256
    )
    report = build_report(root)
    if report.get("status") != "BLOCKED" or report.get("authorizing_use") != "DENY":
        raise ProofCompilerError("READINESS_BOUNDARY")
    inventory = report.get("inventory")
    if type(inventory) is not dict:
        raise ProofCompilerError("READINESS_INVENTORY")
    discovery = inventory.get("resource_inventory_discovery")
    current = inventory.get("resource_inventory_classification")
    if type(discovery) is not dict or type(current) is not dict:
        raise ProofCompilerError("READINESS_INVENTORY")

    source_sites = discovery.get("source_bound_sites")
    schema_sites = discovery.get("schema_bound_sites")
    source_inputs = discovery.get("source_inputs")
    schema_inputs = discovery.get("schema_inputs")
    if not all(type(value) is list for value in (
        source_sites, schema_sites, source_inputs, schema_inputs
    )):
        raise ProofCompilerError("CENSUS_SHAPE")
    all_keys = [
        f"SOURCE:{item.get('site_id')}" for item in source_sites
    ] + [f"SCHEMA:{item.get('site_id')}" for item in schema_sites]
    if len(all_keys) != len(set(all_keys)):
        raise ProofCompilerError("CENSUS_DUPLICATE")
    if len(source_sites) != 425 or len(schema_sites) != 296:
        raise ProofCompilerError("FROZEN_CENSUS_CARDINALITY")

    source_identity = [
        {key: value for key, value in item.items() if key != "line"}
        for item in source_sites
    ]
    checks = (
        (
            "FROZEN_SOURCE_SITES",
            _domain_digest(SOURCE_SITES_DOMAIN, source_identity),
            discovery_pin.get("source_bound_sites_sha256"),
        ),
        (
            "FROZEN_SCHEMA_SITES",
            _domain_digest(SCHEMA_SITES_DOMAIN, schema_sites),
            discovery_pin.get("schema_bound_sites_sha256"),
        ),
        (
            "FROZEN_SOURCE_INPUTS",
            _domain_digest(SOURCE_INPUTS_DOMAIN, source_inputs),
            discovery_pin.get("source_inputs_sha256"),
        ),
        (
            "FROZEN_SCHEMA_INPUTS",
            _domain_digest(SCHEMA_INPUTS_DOMAIN, schema_inputs),
            discovery_pin.get("schema_inputs_sha256"),
        ),
    )
    for code, observed, expected in checks:
        if observed != expected:
            raise ProofCompilerError(code)
    if (
        discovery.get("profile_id") != discovery_pin.get("profile_id")
        or discovery_pin.get("source_bound_site_count") != 425
        or discovery_pin.get("schema_bound_site_count") != 296
    ):
        raise ProofCompilerError("FROZEN_DISCOVERY_BINDING")
    if (
        accepted.get("schema_version") != 55
        or accepted.get("classified_site_count") != 87
        or accepted.get("unclassified_site_count") != 634
        or accepted.get("coverage_status") != "INCOMPLETE"
        or accepted.get("generation_disposition") != "DENY"
        or accepted.get("source_bound_sites_sha256")
        != discovery_pin.get("source_bound_sites_sha256")
        or accepted.get("schema_bound_sites_sha256")
        != discovery_pin.get("schema_bound_sites_sha256")
        or current.get("classified_site_count") != 87
        or current.get("unclassified_site_count") != 634
        or current.get("generation_disposition") != "DENY"
    ):
        raise ProofCompilerError("ACCEPTED_V55_BINDING")
    return discovery_pin, accepted, discovery


def _accepted_sets(accepted: dict[str, Any]) -> tuple[set[str], set[str], dict[str, dict[str, Any]]]:
    source_ids: set[str] = set()
    schema_ids: set[str] = set()
    family: dict[str, dict[str, Any]] = {}
    constraints = accepted.get("constraints")
    if type(constraints) is not list:
        raise ProofCompilerError("ACCEPTED_CONSTRAINTS")
    for constraint in constraints:
        if type(constraint) is not dict:
            raise ProofCompilerError("ACCEPTED_CONSTRAINTS")
        if constraint.get("classification") == "SCHEMA_DECLARATIVE_BOUND":
            site_id = constraint.get("schema_site_id")
            if type(site_id) is not str or site_id in schema_ids:
                raise ProofCompilerError("ACCEPTED_SCHEMA_DUPLICATE")
            schema_ids.add(site_id)
            addressed = constraint.get("addressed_site", {})
            if addressed.get("keyword") == "minLength":
                family[site_id] = constraint
        else:
            for field in ("definition_site_ids", "enforcement_site_ids"):
                values = constraint.get(field)
                if type(values) is not list:
                    raise ProofCompilerError("ACCEPTED_SOURCE_SHAPE")
                for site_id in values:
                    if type(site_id) is not str:
                        raise ProofCompilerError("ACCEPTED_SOURCE_SHAPE")
                    source_ids.add(site_id)
    if len(source_ids) != 71 or len(schema_ids) != 16 or len(family) != 10:
        raise ProofCompilerError("ACCEPTED_V55_COUNTS")
    if source_ids & schema_ids:
        raise ProofCompilerError("ACCEPTED_NAMESPACE_COLLISION")
    return source_ids, schema_ids, family


def _schema_projection(
    root: Path,
    site: dict[str, Any],
    schema_input: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    path = site["path"]
    raw = (root / path).read_bytes()
    if (
        len(raw) != schema_input.get("byte_length")
        or _sha256(raw) != schema_input.get("raw_sha256")
    ):
        raise ProofCompilerError("SCHEMA_INPUT_STALE", path)
    document = _parse_json(raw, path)
    observed = _resolve_pointer(document, site["json_pointer"])
    if type(observed) is not int or observed != site["value"]:
        raise ProofCompilerError("SCHEMA_SITE_MISMATCH", site["site_id"])
    containing_pointer = site["json_pointer"].rsplit("/", 1)[0]
    containing = _resolve_pointer(document, containing_pointer)
    if type(containing) is not dict:
        raise ProofCompilerError("SCHEMA_CONTAINER_MISMATCH", site["site_id"])
    ambiguities = _schema_ambiguities(document, site["schema_id"])
    context = {
        "dialect": DRAFT_2020_12,
        "schema_document_byte_length": len(raw),
        "schema_document_raw_sha256": _sha256(raw),
        "schema_document_root_id": site["schema_id"],
        "containing_subschema_pointer": containing_pointer,
        "containing_subschema_digest": _domain_digest(
            CONTAINING_SUBSCHEMA_DOMAIN, containing
        ),
        "applicability": "EXACT_PINNED_SCHEMA_LOCATION_ONLY",
        "instance_domain": "STRING",
        "ancestor_context": _ancestor_context(document, containing_pointer),
        "required_sibling_pointers": [],
        "non_domain_behavior": "NO_ASSERTION_FROM_THIS_KEYWORD",
    }
    return context, ambiguities


def compile_candidate_ledger(root: Path = ROOT) -> dict[str, Any]:
    """Compile the complete frozen census into a DENY-only witness ledger."""
    root = root.resolve()
    if root != ROOT:
        raise ProofCompilerError("NONCANONICAL_ROOT", str(root))
    registry = _load_rule_registry(root)
    discovery_pin, accepted, discovery = _frozen_inventory(root)
    accepted_source, accepted_schema, manual_family = _accepted_sets(accepted)
    source_inputs = {item["path"]: item for item in discovery["source_inputs"]}
    schema_inputs = {item["path"]: item for item in discovery["schema_inputs"]}
    if (
        len(source_inputs) != len(discovery["source_inputs"])
        or len(schema_inputs) != len(discovery["schema_inputs"])
    ):
        raise ProofCompilerError("INPUT_PATH_DUPLICATE")

    witnesses: list[dict[str, Any]] = []
    for site in discovery["source_bound_sites"]:
        source_input = source_inputs.get(site["path"])
        if source_input is None:
            raise ProofCompilerError("SOURCE_INPUT_MISSING", site["path"])
        coordinate = {"path": site["path"]}
        for key in ("qualname", "line", "occurrence", "table_name", "row_index"):
            if key in site:
                coordinate[key] = site[key]
        observed_syntax = {
            key: value for key, value in site.items()
            if key not in {
                "classification", "site_id", "path", "qualname", "line",
                "occurrence", "table_name", "row_index",
            }
        }
        witnesses.append({
            "namespace": "SOURCE",
            "site_id": site["site_id"],
            "coordinate": coordinate,
            "source": {
                "byte_length": source_input["byte_length"],
                "raw_sha256": source_input["raw_sha256"],
            },
            "observed_syntax": observed_syntax,
            "rule_evaluation": {
                "disposition": "NONMATCHING",
                "reason_codes": ["SOURCE_NAMESPACE_OUTSIDE_SCHEMA_MINLENGTH_FAMILY"],
                "derived_semantics": None,
            },
            "accepted_reference": (
                "ACCEPTED_OUTSIDE_RULE_FAMILY"
                if site["site_id"] in accepted_source else "UNCLASSIFIED"
            ),
            "authorizing_use": "DENY",
        })

    manual_matches: list[str] = []
    for site in discovery["schema_bound_sites"]:
        schema_input = schema_inputs.get(site["path"])
        if schema_input is None:
            raise ProofCompilerError("SCHEMA_INPUT_MISSING", site["path"])
        base = {
            "namespace": "SCHEMA",
            "site_id": site["site_id"],
            "coordinate": {
                "path": site["path"],
                "schema_id": site["schema_id"],
                "json_pointer": site["json_pointer"],
            },
            "source": {
                "byte_length": schema_input["byte_length"],
                "raw_sha256": schema_input["raw_sha256"],
            },
            "observed_syntax": {
                "keyword": site["keyword"],
                "value": site["value"],
            },
            "accepted_reference": (
                "ACCEPTED_OUTSIDE_RULE_FAMILY"
                if site["site_id"] in accepted_schema else "UNCLASSIFIED"
            ),
            "authorizing_use": "DENY",
        }
        if site["keyword"] != "minLength":
            base["rule_evaluation"] = {
                "disposition": "NONMATCHING",
                "reason_codes": ["KEYWORD_NOT_MINLENGTH"],
                "derived_semantics": None,
            }
            witnesses.append(base)
            continue

        context, ambiguities = _schema_projection(root, site, schema_input)
        semantics = {
            "semantic_subject": "SCHEMA_DECLARATIVE_MIN_LENGTH_AT_EXACT_PINNED_LOCATION",
            "instance_domain": "STRING",
            "metric": "UNICODE_CODE_POINT_COUNT",
            "operator": ">=",
            "bound": site["value"],
            "unit": "UNICODE_CODE_POINTS",
            "non_domain_behavior": "NO_ASSERTION_FROM_THIS_KEYWORD",
            "schema_context": context,
        }
        if ambiguities:
            if site["site_id"] in manual_family:
                raise ProofCompilerError("ACCEPTED_SITE_AMBIGUOUS", site["site_id"])
            base["rule_evaluation"] = {
                "disposition": "AMBIGUOUS",
                "reason_codes": ambiguities,
                "derived_semantics": None,
            }
        elif site["site_id"] in manual_family:
            manual = manual_family[site["site_id"]]
            expected_manual = {
                "addressed_site": site,
                "semantic_subject": semantics["semantic_subject"],
                "unit": semantics["unit"],
                "declarative_equation": {
                    "metric": semantics["metric"],
                    "operator": semantics["operator"],
                    "bound": semantics["bound"],
                },
                "schema_context": context,
            }
            observed_manual = {
                key: manual.get(key) for key in expected_manual
            }
            if observed_manual != expected_manual:
                raise ProofCompilerError("MANUAL_SEMANTICS_MISMATCH", site["site_id"])
            base["accepted_reference"] = {
                "status": "EXACT_SEMANTIC_MATCH",
                "constraint_id": manual["constraint_id"],
            }
            base["rule_evaluation"] = {
                "disposition": "ACCEPTED_REFERENCE_MATCH",
                "reason_codes": [],
                "derived_semantics": semantics,
            }
            manual_matches.append(site["site_id"])
        else:
            base["rule_evaluation"] = {
                "disposition": "CANDIDATE_ONLY",
                "reason_codes": [],
                "derived_semantics": semantics,
            }
        witnesses.append(base)

    witnesses.sort(key=lambda item: (item["namespace"], item["site_id"]))
    keys = [f"{item['namespace']}:{item['site_id']}" for item in witnesses]
    expected_keys = {
        *(
            f"SOURCE:{item['site_id']}"
            for item in discovery["source_bound_sites"]
        ),
        *(
            f"SCHEMA:{item['site_id']}"
            for item in discovery["schema_bound_sites"]
        ),
    }
    if len(witnesses) != 721 or len(keys) != len(set(keys)):
        raise ProofCompilerError("LEDGER_UNIQUENESS")
    if set(keys) != expected_keys:
        raise ProofCompilerError("LEDGER_BIDIRECTIONAL_COVERAGE")
    if len(manual_matches) != len(set(manual_matches)) or set(manual_matches) != set(manual_family):
        raise ProofCompilerError("MANUAL_FAMILY_COVERAGE")

    disposition_counts = {
        disposition: sum(
            item["rule_evaluation"]["disposition"] == disposition
            for item in witnesses
        )
        for disposition in (
            "ACCEPTED_REFERENCE_MATCH", "CANDIDATE_ONLY", "AMBIGUOUS", "NONMATCHING"
        )
    }
    if disposition_counts != {
        "ACCEPTED_REFERENCE_MATCH": 10,
        "CANDIDATE_ONLY": 25,
        "AMBIGUOUS": 0,
        "NONMATCHING": 686,
    }:
        raise ProofCompilerError("MEASURED_FAMILY_COUNTS")
    rule = registry["rules"][0]
    if (
        rule["expected_counts"] != {
            "inspected": 721,
            "accepted_reference_match": 10,
            "candidate_only": 25,
            "ambiguous": 0,
            "nonmatching": 686,
        }
        or sorted(manual_matches) != rule["calibration_site_ids"]
    ):
        raise ProofCompilerError("RULE_REGISTRY_CALIBRATION")

    result = {
        "schema_version": 1,
        "compiler_id": "EDGELAB_M0_3A_SCHEMA_MINLENGTH_PROOF_COMPILER_V1",
        "status": "VALID_CANDIDATE_ONLY",
        "authorizing_use": "DENY",
        "governance_equivalence": "NOT_ESTABLISHED",
        "accepted_classification_manifest": {
            "path": CLASSIFICATION_PATH,
            "raw_sha256": CLASSIFICATION_RAW_SHA256,
            "schema_version": 55,
            "accepted_site_count": 87,
            "accepted_family_site_count": 10,
            "accepted_count_changed": False,
        },
        "frozen_census": {
            "path": DISCOVERY_PATH,
            "raw_sha256": DISCOVERY_RAW_SHA256,
            "profile_id": discovery_pin["profile_id"],
            "source_site_count": 425,
            "schema_site_count": 296,
            "inspected_site_count": 721,
            "source_bound_sites_sha256": discovery_pin["source_bound_sites_sha256"],
            "schema_bound_sites_sha256": discovery_pin["schema_bound_sites_sha256"],
            "source_inputs_sha256": discovery_pin["source_inputs_sha256"],
            "schema_inputs_sha256": discovery_pin["schema_inputs_sha256"],
        },
        "rule": {
            "family": "DRAFT_2020_12_EXACT_LOCATION_MINLENGTH",
            "keyword": "minLength",
            "dialect": DRAFT_2020_12,
            "instance_domain": "STRING",
            "metric": "UNICODE_CODE_POINT_COUNT",
            "operator": ">=",
            "unit": "UNICODE_CODE_POINTS",
            "applicability": "EXACT_PINNED_SCHEMA_LOCATION_ONLY",
            "non_domain_behavior": "NO_ASSERTION_FROM_THIS_KEYWORD",
        },
        "coverage": {
            "inspected_site_count": 721,
            "accepted_total_site_count": 87,
            "currently_unclassified_site_count": 634,
            "accepted_family_site_count": 10,
            "candidate_only_site_count": 25,
            "ambiguous_site_count": 0,
            "nonmatching_site_count": 686,
            "unclassified_without_family_candidate_count": 609,
            "bidirectional_coverage": "EXACT",
            "unique_site_identities": True,
        },
        "manual_evidence_comparison": {
            "status": "EXACT_MATCH",
            "matched_site_count": 10,
            "matched_site_ids": sorted(manual_matches),
            "mismatched_site_ids": [],
        },
        "witnesses": witnesses,
        "nonclaims": [
            "NO_ACCEPTED_CLASSIFICATION_CHANGE",
            "NO_GOVERNANCE_EQUIVALENCE",
            "NO_FORMAL_SKEPTIC_APPROVAL",
            "NO_STOP_CLEARANCE",
            "NO_RELEASE_CLOSURE",
            "NO_PUBLIC_VERIFIER_ATTACHMENT",
            "NO_EXECUTION_AUTHORITY",
            "NO_LIVE_OR_CAPITAL_AUTHORITY",
        ],
        "witness_ledger_sha256": "",
        "compiler_output_sha256": "",
    }
    result["witness_ledger_sha256"] = _domain_digest(LEDGER_DOMAIN, witnesses)
    result["compiler_output_sha256"] = _domain_digest(
        OUTPUT_DOMAIN,
        {key: value for key, value in result.items() if key != "compiler_output_sha256"},
    )
    return result


def verify_candidate_ledger(
    candidate: dict[str, Any], root: Path = ROOT
) -> CandidateVerification:
    """Verify a candidate against a fresh compilation; never authorize it."""
    if type(candidate) is not dict:
        raise ProofCompilerError("OUTPUT_NOT_OBJECT")
    if candidate.get("authorizing_use") != "DENY":
        raise ProofCompilerError("OUTPUT_AUTHORITY")
    if candidate.get("status") != "VALID_CANDIDATE_ONLY":
        raise ProofCompilerError("OUTPUT_STATUS")
    if candidate.get("governance_equivalence") != "NOT_ESTABLISHED":
        raise ProofCompilerError("OUTPUT_GOVERNANCE")
    witnesses = candidate.get("witnesses")
    if type(witnesses) is not list or len(witnesses) != 721:
        raise ProofCompilerError("OUTPUT_CARDINALITY")
    keys = [
        f"{item.get('namespace')}:{item.get('site_id')}"
        for item in witnesses if type(item) is dict
    ]
    if len(keys) != 721:
        raise ProofCompilerError("OUTPUT_WITNESS_SHAPE")
    if len(keys) != len(set(keys)):
        raise ProofCompilerError("OUTPUT_DUPLICATE")
    if keys != sorted(keys):
        raise ProofCompilerError("OUTPUT_ORDER")
    if any(item.get("authorizing_use") != "DENY" for item in witnesses):
        raise ProofCompilerError("OUTPUT_WITNESS_AUTHORITY")
    if candidate.get("witness_ledger_sha256") != _domain_digest(
        LEDGER_DOMAIN, witnesses
    ):
        raise ProofCompilerError("OUTPUT_LEDGER_DIGEST")
    if candidate.get("compiler_output_sha256") != _domain_digest(
        OUTPUT_DOMAIN,
        {key: value for key, value in candidate.items() if key != "compiler_output_sha256"},
    ):
        raise ProofCompilerError("OUTPUT_DIGEST")
    expected = compile_candidate_ledger(root)
    if canonical_json(candidate) != canonical_json(expected):
        raise ProofCompilerError("OUTPUT_MISMATCH")
    return CandidateVerification(
        "VALID_CANDIDATE_ONLY",
        candidate["witness_ledger_sha256"],
        candidate["coverage"]["inspected_site_count"],
        candidate["coverage"]["candidate_only_site_count"],
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--verify",
        type=Path,
        help="verify a previously compiled JSON candidate instead of compiling",
    )
    args = parser.parse_args(argv)
    if args.verify is None:
        sys.stdout.buffer.write(canonical_json(compile_candidate_ledger()) + b"\n")
    else:
        candidate = _parse_json(args.verify.read_bytes(), str(args.verify))
        sys.stdout.buffer.write(
            canonical_json(verify_candidate_ledger(candidate).as_mapping()) + b"\n"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
