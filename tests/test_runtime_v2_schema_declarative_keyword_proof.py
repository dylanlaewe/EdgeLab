"""Executable adversarial contract tests for schema declarative bounds."""
from __future__ import annotations

from collections import Counter
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from jsonschema import Draft202012Validator

from src.edgelab.validate import ROOT
from tools.check_runtime_v2_release_readiness import (
    CLASSIFIED_RESOURCE_SITE_IDS,
    RESOURCE_CLASSIFICATION_MANIFEST,
    SCHEMA_CONTAINING_SUBSCHEMA_DOMAIN,
    SCHEMA_DECLARATIVE_KEYWORD_PROOF_PROFILE,
    SCHEMA_DECLARATIVE_KEYWORD_PROOF_SCHEMA,
    SCHEMA_RESOURCE_SITE_IDENTITY_DOMAIN,
    ReadinessError,
    _address_schema_bound_inventory,
    _domain_digest,
    _json_pointer_tokens,
    _resolve_json_pointer,
    _schema_ancestor_context,
    _schema_declarative_keyword_semantics,
    _schema_declarative_proof_profile_inventory,
    _validate_schema_declarative_keyword_proof,
    build_report,
)


FIXTURE_PATH = "schemas/declarative-proof-fixture.schema.json"
FIXTURE_ID = "urn:edgelab:test:schema-declarative-proof-fixture:1"
BOUND_KEYWORDS = {
    "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum",
    "minLength", "maxLength", "minItems", "maxItems",
    "minProperties", "maxProperties", "minContains", "maxContains",
}


def _fixture_document() -> dict[str, object]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": FIXTURE_ID,
        "$defs": {
            "numeric": {
                "minimum": -3,
                "maximum": 9,
                "exclusiveMinimum": -4,
                "exclusiveMaximum": 10**80,
            },
        },
        "allOf": [
            {"$ref": "#/$defs/numeric"},
            {
                "if": {"minLength": 1},
                "then": {"maxLength": 5},
                "else": {"minItems": 1},
            },
            {
                "oneOf": [
                    {"maxItems": 5},
                    {"minProperties": 1},
                    {"maxProperties": 4},
                ],
            },
            {
                "contains": {"type": "integer"},
                "minContains": 1,
                "maxContains": 3,
            },
        ],
    }


def _schema_records(document: object) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []

    def walk(value: object, pointer: str) -> None:
        if type(value) is dict:
            for key, child in value.items():
                token = key.replace("~", "~0").replace("/", "~1")
                child_pointer = f"{pointer}/{token}"
                if key in BOUND_KEYWORDS and type(child) is int:
                    records.append({
                        "classification": "UNCLASSIFIED",
                        "json_pointer": child_pointer,
                        "keyword": key,
                        "path": FIXTURE_PATH,
                        "schema_id": FIXTURE_ID,
                        "value": child,
                    })
                walk(child, child_pointer)
        elif type(value) is list:
            for index, child in enumerate(value):
                walk(child, f"{pointer}/{index}")

    walk(document, "")
    return sorted(records, key=lambda item: (item["path"], item["json_pointer"]))


class SchemaDeclarativeKeywordProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = build_report(ROOT)
        cls.discovery = cls.report["inventory"]["resource_inventory_discovery"]
        cls.schema = json.loads(
            (ROOT / SCHEMA_DECLARATIVE_KEYWORD_PROOF_SCHEMA["path"]).read_text(
                encoding="ascii"
            )
        )
        Draft202012Validator.check_schema(cls.schema)
        cls.validator = Draft202012Validator(cls.schema)

    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        document = _fixture_document()
        schema_raw = (json.dumps(document, indent=2, ensure_ascii=True) + "\n").encode(
            "ascii"
        )
        schema_path = root / FIXTURE_PATH
        schema_path.parent.mkdir(parents=True)
        schema_path.write_bytes(schema_raw)
        evidence_raw = (b"declarative proof design\n", b"adversarial proof tests\n")
        evidence_paths = ("docs/evidence-a.md", "tests/evidence-b.py")
        evidence_inputs = []
        for relative, raw in zip(evidence_paths, evidence_raw, strict=True):
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            evidence_inputs.append({
                "byte_length": len(raw),
                "path": relative,
                "raw_sha256": hashlib.sha256(raw).hexdigest(),
            })
        addressed = _address_schema_bound_inventory(_schema_records(document))
        schema_sites = {item["site_id"]: item for item in addressed}
        schema_inputs = [{
            "byte_length": len(schema_raw),
            "path": FIXTURE_PATH,
            "raw_sha256": hashlib.sha256(schema_raw).hexdigest(),
        }]
        return (
            temporary, root, document, schema_raw, evidence_inputs,
            addressed, schema_sites, schema_inputs,
        )

    def proof_for(
        self,
        site: dict[str, object],
        document: dict[str, object],
        schema_raw: bytes,
        evidence_inputs: list[dict[str, object]],
    ) -> dict[str, object]:
        semantics = {
            item["keyword"]: item
            for item in _schema_declarative_keyword_semantics()
        }[site["keyword"]]
        pointer = site["json_pointer"]
        containing_pointer = pointer.rsplit("/", 1)[0]
        containing = _resolve_json_pointer(document, containing_pointer, FIXTURE_PATH)
        required_siblings = (
            [f"{containing_pointer}/contains"]
            if site["keyword"] in {"minContains", "maxContains"}
            else []
        )
        return {
            "proof_kind": "SCHEMA_DECLARATIVE_KEYWORD_V1",
            "constraint_id": (
                f"SCHEMA_DECLARATIVE_{site['keyword'].upper()}_"
                f"{site['site_id'].upper()}"
            ),
            "classification": "SCHEMA_DECLARATIVE_BOUND",
            "semantic_subject": semantics["semantic_subject"],
            "schema_site_id": site["site_id"],
            "addressed_site": dict(site),
            "schema_context": {
                "dialect": "https://json-schema.org/draft/2020-12/schema",
                "schema_document_byte_length": len(schema_raw),
                "schema_document_raw_sha256": hashlib.sha256(schema_raw).hexdigest(),
                "schema_document_root_id": FIXTURE_ID,
                "containing_subschema_pointer": containing_pointer,
                "containing_subschema_digest": _domain_digest(
                    SCHEMA_CONTAINING_SUBSCHEMA_DOMAIN, containing
                ),
                "applicability": "EXACT_PINNED_SCHEMA_LOCATION_ONLY",
                "instance_domain": semantics["instance_domain"],
                "ancestor_context": _schema_ancestor_context(
                    document, containing_pointer, FIXTURE_PATH
                ),
                "required_sibling_pointers": required_siblings,
                "non_domain_behavior": "NO_ASSERTION_FROM_THIS_KEYWORD",
            },
            "declarative_equation": {
                "metric": semantics["metric"],
                "operator": semantics["operator"],
                "bound": site["value"],
            },
            "unit": semantics["unit"],
            "evidence_inputs": copy.deepcopy(evidence_inputs),
        }

    def test_all_twelve_keyword_contracts_validate_with_unique_per_site_ids(self):
        fixture = self.fixture()
        temporary, root, document, raw, evidence, sites, site_map, inputs = fixture
        self.addCleanup(temporary.cleanup)
        self.assertEqual({item["keyword"] for item in sites}, BOUND_KEYWORDS)
        proof_ids = set()
        for site in sites:
            with self.subTest(keyword=site["keyword"]):
                proof = self.proof_for(site, document, raw, evidence)
                self.assertEqual(list(self.validator.iter_errors(proof)), [])
                result = _validate_schema_declarative_keyword_proof(
                    root, proof, {}, site_map, inputs
                )
                proof_ids.add(result["constraint_id"])
        self.assertEqual(len(proof_ids), 12)

    def test_profile_is_closed_declarative_only_and_v44_is_zero_rebase(self):
        summary = _schema_declarative_proof_profile_inventory(ROOT, set())
        self.assertEqual(summary["keyword_count"], 12)
        self.assertEqual(summary["runtime_enforcement_roles"], [])
        profile = json.loads(
            (ROOT / SCHEMA_DECLARATIVE_KEYWORD_PROOF_PROFILE["path"])
            .read_text(encoding="ascii")
        )
        self.assertEqual(profile["runtime_enforcement_roles"], [])
        self.assertEqual(profile["nested_dialect_or_id"], "DENY")
        self.assertEqual(
            profile["reference_semantics"],
            "LOCAL_DOCUMENT_RAW_RFC6901_POINTER_ONLY_NO_PERCENT_ENCODING_"
            "ALL_RESOLVE_NO_DYNAMIC_OR_RECURSIVE_REFERENCE",
        )
        self.assertEqual(profile["nonclaims"], [
            "NO_RUNTIME_VALIDATOR_BEHAVIOR",
            "NO_PUBLIC_REACHABILITY",
            "NO_ROOT_APPLICABILITY_BEYOND_EXACT_LOCAL_CONTEXT",
            "NO_FULL_SCHEMA_VALIDITY",
            "NO_DEPLOYED_VALIDATOR_CONFORMANCE",
            "NO_ACCEPTANCE_AUTHORITY",
            "NO_STOP_CLEARANCE",
            "NO_RELEASE_AUTHORITY",
            "NO_EXECUTION_AUTHORITY",
            "NO_CAPITAL_AUTHORITY",
        ])
        self.assertEqual(
            self.report["inventory"]["schema_declarative_keyword_proof_profile"],
            summary,
        )
        current = json.loads(
            (ROOT / RESOURCE_CLASSIFICATION_MANIFEST[1]).read_text(encoding="ascii")
        )
        predecessor = json.loads(
            (ROOT / "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v43.json")
            .read_text(encoding="ascii")
        )
        self.assertEqual(current["constraints"], predecessor["constraints"])
        self.assertEqual(len(current["constraints"]), 38)
        self.assertEqual(current["classified_site_count"], 71)
        self.assertEqual(current["unclassified_site_count"], 650)
        schema_ids = {item["site_id"] for item in self.discovery["schema_bound_sites"]}
        self.assertTrue(CLASSIFIED_RESOURCE_SITE_IDS.isdisjoint(schema_ids))
        self.assertEqual(len(self.discovery["source_bound_sites"]), 425)
        self.assertEqual(len(self.discovery["schema_bound_sites"]), 296)
        self.assertNotIn(
            SCHEMA_DECLARATIVE_KEYWORD_PROOF_SCHEMA["path"],
            {item["path"] for item in self.discovery["schema_inputs"]},
        )
        self.assertEqual(self.report["authorizing_use"], "DENY")

    def test_closed_profile_and_contract_schema_bytes_are_pinned(self):
        for expected, code in (
            (SCHEMA_DECLARATIVE_KEYWORD_PROOF_SCHEMA, "SCHEMA_DECLARATIVE_PROOF_SCHEMA"),
            (SCHEMA_DECLARATIVE_KEYWORD_PROOF_PROFILE, "SCHEMA_DECLARATIVE_PROOF_PROFILE"),
        ):
            with self.subTest(path=expected["path"]):
                with tempfile.TemporaryDirectory() as name:
                    root = Path(name)
                    for artifact in (
                        SCHEMA_DECLARATIVE_KEYWORD_PROOF_SCHEMA,
                        SCHEMA_DECLARATIVE_KEYWORD_PROOF_PROFILE,
                    ):
                        target = root / artifact["path"]
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes((ROOT / artifact["path"]).read_bytes())
                    target = root / expected["path"]
                    target.write_bytes(target.read_bytes() + b" \n")
                    with self.assertRaises(ReadinessError) as caught:
                        _schema_declarative_proof_profile_inventory(root, set())
                self.assertEqual(caught.exception.code, code)

    def test_real_census_ancestor_partition_and_local_reference_profile(self):
        partition = Counter()
        reference_count = 0
        for site in self.discovery["schema_bound_sites"]:
            tokens = _json_pointer_tokens(site["json_pointer"], site["path"])[0:-1]
            if "$defs" in tokens:
                partition["$defs-only"] += 1
            elif "oneOf" in tokens:
                partition["oneOf-only"] += 1
            elif "allOf" in tokens:
                suffix = tokens[tokens.index("allOf") + 2:]
                edge = next((name for name in ("if", "then", "else") if name in suffix), None)
                partition[f"allOf-{edge}" if edge else "allOf-only"] += 1
            else:
                partition["edge-none"] += 1
        self.assertEqual(partition, Counter({
            "edge-none": 66,
            "$defs-only": 95,
            "allOf-only": 102,
            "allOf-if": 6,
            "allOf-then": 18,
            "allOf-else": 1,
            "oneOf-only": 8,
        }))
        for item in self.discovery["schema_inputs"]:
            document = json.loads((ROOT / item["path"]).read_text(encoding="utf-8"))
            self.assertEqual(
                document["$schema"], "https://json-schema.org/draft/2020-12/schema"
            )
            stack = [(document, True)]
            while stack:
                value, is_root = stack.pop()
                if type(value) is dict:
                    if not is_root:
                        self.assertNotIn("$id", value)
                        self.assertNotIn("$schema", value)
                    if "$ref" in value:
                        reference_count += 1
                        self.assertTrue(value["$ref"].startswith("#/"))
                    stack.extend((child, False) for child in value.values())
                elif type(value) is list:
                    stack.extend((child, False) for child in value)
        self.assertEqual(reference_count, 354)
        contains_sites = [
            item for item in self.discovery["schema_bound_sites"]
            if item["keyword"] in {"minContains", "maxContains"}
        ]
        self.assertEqual(Counter(item["keyword"] for item in contains_sites), Counter({
            "minContains": 56,
            "maxContains": 56,
        }))
        self.assertEqual(
            {
                (item["path"], item["json_pointer"].rsplit("/", 1)[0])
                for item in contains_sites if item["keyword"] == "minContains"
            },
            {
                (item["path"], item["json_pointer"].rsplit("/", 1)[0])
                for item in contains_sites if item["keyword"] == "maxContains"
            },
        )
        self.assertTrue(all(type(item["value"]) is int for item in self.discovery["schema_bound_sites"]))

    def test_semantic_context_and_identity_mutations_fail_closed(self):
        fixture = self.fixture()
        temporary, root, document, raw, evidence, sites, site_map, inputs = fixture
        self.addCleanup(temporary.cleanup)
        site = next(item for item in sites if item["keyword"] == "minLength")
        baseline = self.proof_for(site, document, raw, evidence)
        attacks = []
        for field, value in (
            ("classification", "RESOURCE_MINIMUM"),
            ("semantic_subject", "SCHEMA_DECLARATIVE_WRONG"),
            ("unit", "BYTES"),
        ):
            attacked = copy.deepcopy(baseline)
            attacked[field] = value
            attacks.append(attacked)
        for field, value in (
            ("metric", "ARRAY_ITEM_COUNT"),
            ("operator", ">"),
            ("bound", 99),
        ):
            attacked = copy.deepcopy(baseline)
            attacked["declarative_equation"][field] = value
            attacks.append(attacked)
        for field, value in (
            ("instance_domain", "ARRAY"),
            ("containing_subschema_pointer", ""),
            ("containing_subschema_digest", "0" * 64),
            ("schema_document_root_id", "urn:wrong"),
        ):
            attacked = copy.deepcopy(baseline)
            attacked["schema_context"][field] = value
            attacks.append(attacked)
        attacked = copy.deepcopy(baseline)
        attacked["schema_context"]["ancestor_context"]["ordered_pointer_sequence"].reverse()
        attacks.append(attacked)
        attacked = copy.deepcopy(baseline)
        attacked["addressed_site"]["value"] = 2
        attacks.append(attacked)
        for attacked in attacks:
            with self.subTest(attack=attacked):
                with self.assertRaises(ReadinessError):
                    _validate_schema_declarative_keyword_proof(
                        root, attacked, {}, site_map, inputs
                    )
        terminal_attack = dict(site)
        terminal_attack["json_pointer"] = "/allOf/1/then/maxLength"
        terminal_attack["value"] = 5
        preimage = {
            key: terminal_attack[key]
            for key in ("json_pointer", "keyword", "path", "schema_id", "value")
        }
        terminal_attack["site_id"] = _domain_digest(
            SCHEMA_RESOURCE_SITE_IDENTITY_DOMAIN, preimage
        )
        terminal_proof = self.proof_for(terminal_attack, document, raw, evidence)
        with self.assertRaises(ReadinessError) as caught:
            _validate_schema_declarative_keyword_proof(
                root,
                terminal_proof,
                {},
                {terminal_attack["site_id"]: terminal_attack},
                inputs,
            )
        self.assertEqual(caught.exception.code, "SCHEMA_DECLARATIVE_KEYWORD_POINTER")

    def test_contains_source_dispatch_evidence_and_schema_shape_attacks_deny(self):
        fixture = self.fixture()
        temporary, root, document, raw, evidence, sites, site_map, inputs = fixture
        self.addCleanup(temporary.cleanup)
        site = next(item for item in sites if item["keyword"] == "minContains")
        baseline = self.proof_for(site, document, raw, evidence)
        source_id = "f" * 64
        source_record = {"site_id": source_id}
        attacked = copy.deepcopy(baseline)
        attacked["schema_site_id"] = source_id
        with self.assertRaises(ReadinessError) as caught:
            _validate_schema_declarative_keyword_proof(
                root, attacked, {source_id: source_record}, site_map, inputs
            )
        self.assertEqual(caught.exception.code, "SCHEMA_DECLARATIVE_SOURCE_SITE")
        for mutation in ("missing", "wrong-level", "wrong-type"):
            with self.subTest(mutation=mutation):
                changed = copy.deepcopy(document)
                container = changed["allOf"][3]
                if mutation == "missing":
                    del container["contains"]
                elif mutation == "wrong-level":
                    changed["contains"] = container.pop("contains")
                else:
                    container["contains"] = 7
                changed_raw = (
                    json.dumps(changed, indent=2, ensure_ascii=True) + "\n"
                ).encode("ascii")
                (root / FIXTURE_PATH).write_bytes(changed_raw)
                changed_inputs = [{
                    "byte_length": len(changed_raw),
                    "path": FIXTURE_PATH,
                    "raw_sha256": hashlib.sha256(changed_raw).hexdigest(),
                }]
                proof = self.proof_for(site, document, changed_raw, evidence)
                with self.assertRaises(ReadinessError):
                    _validate_schema_declarative_keyword_proof(
                        root, proof, {}, site_map, changed_inputs
                    )
        (root / FIXTURE_PATH).write_bytes(raw)
        duplicate_evidence = copy.deepcopy(baseline)
        duplicate_evidence["evidence_inputs"][1] = copy.deepcopy(
            duplicate_evidence["evidence_inputs"][0]
        )
        with self.assertRaises(ReadinessError):
            _validate_schema_declarative_keyword_proof(
                root, duplicate_evidence, {}, site_map, inputs
            )
        schema_as_evidence = copy.deepcopy(baseline)
        schema_as_evidence["evidence_inputs"][1] = copy.deepcopy(inputs[0])
        with self.assertRaises(ReadinessError) as caught:
            _validate_schema_declarative_keyword_proof(
                root, schema_as_evidence, {}, site_map, inputs
            )
        self.assertEqual(
            caught.exception.code, "SCHEMA_DECLARATIVE_EVIDENCE_DUPLICATE"
        )
        alias_proof = copy.deepcopy(baseline)
        second_path = root / alias_proof["evidence_inputs"][1]["path"]
        second_path.unlink()
        second_path.hardlink_to(root / alias_proof["evidence_inputs"][0]["path"])
        alias_raw = second_path.read_bytes()
        alias_proof["evidence_inputs"][1]["byte_length"] = len(alias_raw)
        alias_proof["evidence_inputs"][1]["raw_sha256"] = hashlib.sha256(
            alias_raw
        ).hexdigest()
        with self.assertRaises(ReadinessError) as caught:
            _validate_schema_declarative_keyword_proof(
                root, alias_proof, {}, site_map, inputs
            )
        self.assertEqual(caught.exception.code, "SCHEMA_DECLARATIVE_EVIDENCE_ALIAS")
        forbidden = copy.deepcopy(baseline)
        forbidden["enforcement_site_ids"] = []
        self.assertNotEqual(list(self.validator.iter_errors(forbidden)), [])
        with self.assertRaises(ReadinessError):
            _validate_schema_declarative_keyword_proof(
                root, forbidden, {}, site_map, inputs
            )

    def test_nested_dialect_external_unresolved_ref_and_negative_count_deny(self):
        fixture = self.fixture()
        temporary, root, document, raw, evidence, sites, _, _ = fixture
        self.addCleanup(temporary.cleanup)
        mutations = (
            (
                lambda value: value["$defs"]["numeric"].__setitem__(
                    "$id", "urn:nested"
                ),
                "SCHEMA_DECLARATIVE_NESTED_DIALECT",
            ),
            (
                lambda value: value["$defs"]["numeric"].__setitem__(
                    "$schema", "https://json-schema.org/draft/2020-12/schema"
                ),
                "SCHEMA_DECLARATIVE_NESTED_DIALECT",
            ),
            (
                lambda value: value["allOf"][0].__setitem__(
                    "$ref", "https://example/x"
                ),
                "SCHEMA_DECLARATIVE_REFERENCE",
            ),
            (
                lambda value: value["allOf"][0].__setitem__(
                    "$ref", "#/$defs/missing"
                ),
                "SCHEMA_DECLARATIVE_POINTER_MISSING",
            ),
            (
                lambda value: value["allOf"][0].__setitem__(
                    "$dynamicRef", "#/$defs/numeric"
                ),
                "SCHEMA_DECLARATIVE_UNSUPPORTED_REFERENCE",
            ),
            (
                lambda value: value["allOf"][0].__setitem__(
                    "$recursiveRef", "#/$defs/numeric"
                ),
                "SCHEMA_DECLARATIVE_UNSUPPORTED_REFERENCE",
            ),
        )
        for mutation, expected_code in mutations:
            changed = copy.deepcopy(document)
            mutation(changed)
            changed_raw = (
                json.dumps(changed, indent=2, ensure_ascii=True) + "\n"
            ).encode("ascii")
            (root / FIXTURE_PATH).write_bytes(changed_raw)
            changed_sites = _address_schema_bound_inventory(_schema_records(changed))
            site_map = {item["site_id"]: item for item in changed_sites}
            site = next(item for item in changed_sites if item["keyword"] == "minimum")
            proof = self.proof_for(site, changed, changed_raw, evidence)
            inputs = [{
                "byte_length": len(changed_raw),
                "path": FIXTURE_PATH,
                "raw_sha256": hashlib.sha256(changed_raw).hexdigest(),
            }]
            with self.assertRaises(ReadinessError) as caught:
                _validate_schema_declarative_keyword_proof(
                    root, proof, {}, site_map, inputs
                )
            self.assertEqual(caught.exception.code, expected_code)
        changed = copy.deepcopy(document)
        changed["$defs"]["a b"] = {"type": "integer"}
        changed["allOf"][0]["$ref"] = "#/$defs/a%20b"
        changed_raw = (json.dumps(changed, indent=2) + "\n").encode("ascii")
        (root / FIXTURE_PATH).write_bytes(changed_raw)
        changed_sites = _address_schema_bound_inventory(_schema_records(changed))
        site_map = {item["site_id"]: item for item in changed_sites}
        site = next(item for item in changed_sites if item["keyword"] == "minimum")
        proof = self.proof_for(site, changed, changed_raw, evidence)
        inputs = [{
            "byte_length": len(changed_raw),
            "path": FIXTURE_PATH,
            "raw_sha256": hashlib.sha256(changed_raw).hexdigest(),
        }]
        with self.assertRaises(ReadinessError) as caught:
            _validate_schema_declarative_keyword_proof(
                root, proof, {}, site_map, inputs
            )
        self.assertEqual(
            caught.exception.code, "SCHEMA_DECLARATIVE_REFERENCE_ENCODING"
        )
        changed = copy.deepcopy(document)
        changed["allOf"][1]["if"]["minLength"] = -1
        changed_raw = (json.dumps(changed, indent=2) + "\n").encode("ascii")
        (root / FIXTURE_PATH).write_bytes(changed_raw)
        changed_sites = _address_schema_bound_inventory(_schema_records(changed))
        site_map = {item["site_id"]: item for item in changed_sites}
        site = next(item for item in changed_sites if item["keyword"] == "minLength")
        proof = self.proof_for(site, changed, changed_raw, evidence)
        inputs = [{
            "byte_length": len(changed_raw),
            "path": FIXTURE_PATH,
            "raw_sha256": hashlib.sha256(changed_raw).hexdigest(),
        }]
        with self.assertRaises(ReadinessError) as caught:
            _validate_schema_declarative_keyword_proof(
                root, proof, {}, site_map, inputs
            )
        self.assertEqual(caught.exception.code, "SCHEMA_DECLARATIVE_NONNEGATIVE_BOUND")


if __name__ == "__main__":
    unittest.main()
