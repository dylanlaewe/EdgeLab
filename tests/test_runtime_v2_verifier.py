"""Boundary tests for the deliberately incomplete pure v2 verifier."""
import ast
from dataclasses import FrozenInstanceError
import hashlib
import json
from pathlib import Path
import unittest
from unittest import mock

from jsonschema import Draft202012Validator

from src.edgelab.runtime_v2_codec import canonical_json, storage_schema_digest
import src.edgelab.runtime_v2_verifier as verifier_module
from src.edgelab.runtime_v2_verifier import (
    MAX_SCHEMA_DOCUMENT_BYTES,
    RUNTIME_MANIFEST_SCHEMA_SHA256,
    SCHEMA_DOCUMENT_PINS,
    SCHEMA_REGISTRY_SHA256,
    SCHEMA_REGISTRY_SCHEMA_SHA256,
    STORAGE_DESCRIPTOR_SCHEMA_SHA256,
    STORAGE_DESCRIPTOR_SHA256,
    RuntimeImage,
    SchemaDocumentRecord,
    VerificationFinding,
    VerificationResult,
    verify_runtime_image,
)


ROOT = Path(__file__).resolve().parents[1]


class RuntimeV2VerifierTests(unittest.TestCase):
    def descriptor_bytes(self):
        return canonical_json(json.loads(
            (ROOT / "schemas" / "m0-3a-runtime-storage.v2.json").read_text()
        ))

    def schema_bundle(self):
        registry = json.loads((
            ROOT / "schemas" / "m0-3a-schema-registry.v2.json"
        ).read_text())
        by_id = {}
        for path in (ROOT / "schemas").glob("m0-3a-*.schema.json"):
            document = json.loads(path.read_text())
            if "$id" in document:
                by_id[document["$id"]] = document
        records = tuple(
            SchemaDocumentRecord(
                entry["schema_id"], entry["document_sha256"],
                canonical_json(by_id[entry["schema_id"]]),
            )
            for entry in registry["documents"]
        )
        return canonical_json(registry), records

    def test_published_descriptor_is_unsupported_never_consistent(self):
        result = verify_runtime_image(RuntimeImage(self.descriptor_bytes()))
        self.assertEqual(result.status, "UNSUPPORTED")
        self.assertEqual(
            (result.anchor_status, result.currentness_status, result.authorizing_use),
            ("UNANCHORED", "UNKNOWN", "DENY"),
        )
        self.assertEqual(
            [finding.code for finding in result.findings],
            sorted(finding.code for finding in result.findings),
        )
        with self.assertRaises(TypeError):
            bool(result)

    def test_compiled_descriptor_and_schema_pins_match_published_bytes(self):
        descriptor = json.loads(self.descriptor_bytes())
        schema_bytes = (
            ROOT / "schemas" / "m0-3a-runtime-storage-descriptor.v2.schema.json"
        ).read_bytes()
        self.assertEqual(storage_schema_digest(descriptor), STORAGE_DESCRIPTOR_SHA256)
        self.assertEqual(
            hashlib.sha256(schema_bytes).hexdigest(),
            STORAGE_DESCRIPTOR_SCHEMA_SHA256,
        )
        self.assertEqual(
            hashlib.sha256((
                ROOT / "schemas" / "m0-3a-schema-registry.v2.schema.json"
            ).read_bytes()).hexdigest(),
            SCHEMA_REGISTRY_SCHEMA_SHA256,
        )
        self.assertEqual(
            hashlib.sha256((
                ROOT / "schemas" / "m0-3a-runtime-manifest.v2.schema.json"
            ).read_bytes()).hexdigest(),
            RUNTIME_MANIFEST_SCHEMA_SHA256,
        )
        registry_bytes, records = self.schema_bundle()
        from src.edgelab.runtime_v2_codec import schema_registry_digest
        self.assertEqual(
            schema_registry_digest(json.loads(registry_bytes)),
            SCHEMA_REGISTRY_SHA256,
        )
        self.assertEqual(
            tuple((record.schema_id, record.document_sha256) for record in records),
            SCHEMA_DOCUMENT_PINS,
        )

    def test_exact_schema_bundle_is_supported_but_reducer_remains_unsupported(self):
        registry, documents = self.schema_bundle()
        result = verify_runtime_image(RuntimeImage(
            self.descriptor_bytes(), schema_registry=registry,
            schema_documents=documents,
        ))
        self.assertEqual(result.status, "UNSUPPORTED")
        codes = {finding.code for finding in result.findings}
        self.assertNotIn("SCHEMA_BUNDLE_REQUIRED", codes)
        self.assertIn("REDUCER_UNIMPLEMENTED", codes)

    def test_schema_bundle_is_exact_closed_and_resource_bounded(self):
        registry, documents = self.schema_bundle()
        cases = []
        altered = list(documents)
        altered[0], altered[1] = altered[1], altered[0]
        cases.append((registry, tuple(altered), "SCHEMA_DOCUMENT_ID_MISMATCH"))
        changed = json.loads(documents[0].canonical_json)
        changed["$ref"] = "https://attacker.invalid/schema"
        altered = list(documents)
        altered[0] = SchemaDocumentRecord(
            altered[0].schema_id, altered[0].document_sha256,
            canonical_json(changed),
        )
        cases.append((registry, tuple(altered), "SCHEMA_REF_OUTSIDE_PROFILE"))
        oversized = list(documents)
        oversized[0] = SchemaDocumentRecord(
            oversized[0].schema_id, oversized[0].document_sha256,
            b" " * (MAX_SCHEMA_DOCUMENT_BYTES + 1),
        )
        cases.append((registry, tuple(oversized), "SCHEMA_DOCUMENT_TOO_LARGE"))
        cases.append((registry, documents[:-1], "SCHEMA_DOCUMENT_INVENTORY"))
        for registry_bytes, records, expected in cases:
            with self.subTest(expected=expected):
                result = verify_runtime_image(RuntimeImage(
                    self.descriptor_bytes(), schema_registry=registry_bytes,
                    schema_documents=records,
                ))
                self.assertEqual(result.status, "INVALID")
                self.assertIn(expected, {finding.code for finding in result.findings})

    def test_schema_registry_and_documents_must_arrive_together(self):
        registry, documents = self.schema_bundle()
        for values in (
            {"schema_registry": registry},
            {"schema_documents": documents},
        ):
            result = verify_runtime_image(RuntimeImage(self.descriptor_bytes(), **values))
            self.assertEqual(result.status, "INVALID")
            self.assertIn(
                "SCHEMA_BUNDLE_INCOMPLETE",
                {finding.code for finding in result.findings},
            )

    def test_malformed_schema_record_host_types_fail_closed(self):
        registry, documents = self.schema_bundle()
        malformed = list(documents)
        malformed[0] = SchemaDocumentRecord(
            [], malformed[0].document_sha256, malformed[0].canonical_json
        )
        result = verify_runtime_image(RuntimeImage(
            self.descriptor_bytes(), schema_registry=registry,
            schema_documents=tuple(malformed),
        ))
        self.assertEqual(result.status, "INVALID")
        self.assertIn(
            "SCHEMA_DOCUMENT_ID_TYPE",
            {finding.code for finding in result.findings},
        )

    def test_untrusted_schema_id_cannot_amplify_diagnostics(self):
        registry, documents = self.schema_bundle()
        malformed = list(documents)
        malformed[0] = SchemaDocumentRecord(
            "x" * 1_000_000,
            malformed[0].document_sha256,
            malformed[0].canonical_json,
        )
        result = verify_runtime_image(RuntimeImage(
            self.descriptor_bytes(), schema_registry=registry,
            schema_documents=tuple(malformed),
        ))
        self.assertEqual(result.status, "INVALID")
        self.assertIn(
            "SCHEMA_DOCUMENT_ID_MISMATCH",
            {finding.code for finding in result.findings},
        )
        serialized = json.dumps(result.as_mapping(), separators=(",", ":"))
        self.assertLess(len(serialized), 16_384)
        self.assertNotIn("x" * 1024, serialized)

    def test_untrusted_schema_paths_cannot_amplify_diagnostics(self):
        registry, documents = self.schema_bundle()
        changed = json.loads(documents[0].canonical_json)
        node = changed
        hostile_key = "$" + ("x" * 4_000)
        for index in range(60):
            child = {}
            node[f"{hostile_key}{index}"] = child
            node = child
        altered = list(documents)
        altered[0] = SchemaDocumentRecord(
            altered[0].schema_id, altered[0].document_sha256,
            canonical_json(changed),
        )
        result = verify_runtime_image(RuntimeImage(
            self.descriptor_bytes(), schema_registry=registry,
            schema_documents=tuple(altered),
        ))
        self.assertEqual(result.status, "INVALID")
        serialized = json.dumps(result.as_mapping(), separators=(",", ":"))
        self.assertLess(len(serialized), 131_072)
        self.assertTrue(all(len(item.coordinate) <= 512 for item in result.findings))

    def test_schema_diagnostic_work_stops_at_finding_limit(self):
        registry, documents = self.schema_bundle()
        changed = json.loads(documents[0].canonical_json)
        changed["properties"] = {
            f"field{index}": {f"$unsafe{index}": True}
            for index in range(4_000)
        }
        altered = list(documents)
        altered[0] = SchemaDocumentRecord(
            altered[0].schema_id, altered[0].document_sha256,
            canonical_json(changed),
        )
        with mock.patch.object(
            verifier_module, "_finding", wraps=verifier_module._finding
        ) as finding_spy:
            result = verify_runtime_image(RuntimeImage(
                self.descriptor_bytes(), schema_registry=registry,
                schema_documents=tuple(altered),
            ))
        self.assertEqual(result.status, "INVALID")
        self.assertIn("FINDINGS_TRUNCATED", {item.code for item in result.findings})
        self.assertLessEqual(finding_spy.call_count, 140)

    def test_schema_definitions_are_walked_once_without_hiding_late_cycles(self):
        registry, documents = self.schema_bundle()
        changed = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": documents[0].schema_id,
            "$defs": {
            **{
                f"node{index}": {f"$unsafe{index}": True}
                for index in range(100)
            },
            "zcycle": {"$ref": "#/$defs/zcycle"},
            },
        }
        altered = list(documents)
        altered[0] = SchemaDocumentRecord(
            altered[0].schema_id, altered[0].document_sha256,
            canonical_json(changed),
        )
        result = verify_runtime_image(RuntimeImage(
            self.descriptor_bytes(), schema_registry=registry,
            schema_documents=tuple(altered),
        ))
        codes = {item.code for item in result.findings}
        self.assertEqual(result.status, "INVALID")
        self.assertIn("SCHEMA_REF_CYCLE", codes)
        self.assertNotIn("FINDINGS_TRUNCATED", codes)

    def test_duplicate_cycle_diagnostics_do_not_consume_unique_budget(self):
        registry, documents = self.schema_bundle()
        changed = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": documents[0].schema_id,
            "$defs": {
                "a": {
                    "allOf": [
                        {"$ref": f"#/$defs/b{index}"}
                        for index in range(200)
                    ]
                },
                **{
                    f"b{index}": {"$ref": "#/$defs/a"}
                    for index in range(200)
                },
            },
        }
        altered = list(documents)
        altered[0] = SchemaDocumentRecord(
            altered[0].schema_id, altered[0].document_sha256,
            canonical_json(changed),
        )
        with mock.patch.object(
            verifier_module, "_finding", wraps=verifier_module._finding
        ) as finding_spy:
            result = verify_runtime_image(RuntimeImage(
                self.descriptor_bytes(), schema_registry=registry,
                schema_documents=tuple(altered),
            ))
        codes = {item.code for item in result.findings}
        self.assertEqual(result.status, "INVALID")
        self.assertIn("SCHEMA_REF_CYCLE", codes)
        self.assertNotIn("FINDINGS_TRUNCATED", codes)
        self.assertLessEqual(finding_spy.call_count, 16)

    def test_long_acyclic_schema_ref_graph_does_not_recurse(self):
        registry, documents = self.schema_bundle()
        changed = json.loads(documents[0].canonical_json)
        changed["$defs"] = {
            f"node{index}": (
                {"$ref": f"#/$defs/node{index + 1}"}
                if index < 1199 else {"type": "null"}
            )
            for index in range(1200)
        }
        altered = list(documents)
        altered[0] = SchemaDocumentRecord(
            altered[0].schema_id, altered[0].document_sha256,
            canonical_json(changed),
        )
        result = verify_runtime_image(RuntimeImage(
            self.descriptor_bytes(), schema_registry=registry,
            schema_documents=tuple(altered),
        ))
        self.assertEqual(result.status, "INVALID")
        self.assertIn(
            "SCHEMA_DOCUMENT_DIGEST_MISMATCH",
            {finding.code for finding in result.findings},
        )

    def test_schema_safety_profile_rejects_cycles_aliases_and_keywords(self):
        registry, documents = self.schema_bundle()
        mutations = (
            ({"$defs": {"a": {"$ref": "#/$defs/a"}}}, "SCHEMA_REF_CYCLE"),
            ({"$defs": {"a": {}, "b": {"$ref": "#/$defs/a~1b"}}}, "SCHEMA_REF_OUTSIDE_PROFILE"),
            ({"properties": {"x": {"$schema": "https://json-schema.org/draft/2020-12/schema"}}}, "SCHEMA_NESTED_DIALECT"),
            ({"properties": {"x": {"$unknown": True}}}, "SCHEMA_UNKNOWN_KEYWORD"),
        )
        for mutation, expected in mutations:
            with self.subTest(expected=expected):
                changed = json.loads(documents[0].canonical_json)
                changed.update(mutation)
                altered = list(documents)
                altered[0] = SchemaDocumentRecord(
                    altered[0].schema_id, altered[0].document_sha256,
                    canonical_json(changed),
                )
                result = verify_runtime_image(RuntimeImage(
                    self.descriptor_bytes(), schema_registry=registry,
                    schema_documents=tuple(altered),
                ))
                self.assertEqual(result.status, "INVALID")
                self.assertIn(expected, {finding.code for finding in result.findings})

    def test_schema_bundle_aggregate_limit_and_finding_truncation_are_explicit(self):
        registry, documents = self.schema_bundle()
        oversized = tuple(
            SchemaDocumentRecord(record.schema_id, record.document_sha256, b" " * 240_000)
            for record in documents
        )
        result = verify_runtime_image(RuntimeImage(
            self.descriptor_bytes(), schema_registry=registry,
            schema_documents=oversized,
        ))
        self.assertEqual(result.status, "INVALID")
        self.assertIn("SCHEMA_BUNDLE_TOO_LARGE", {item.code for item in result.findings})

        changed = json.loads(documents[0].canonical_json)
        changed["properties"] = {
            f"field{index}": {f"$unknown{index}": True}
            for index in range(150)
        }
        altered = list(documents)
        altered[0] = SchemaDocumentRecord(
            altered[0].schema_id, altered[0].document_sha256,
            canonical_json(changed),
        )
        result = verify_runtime_image(RuntimeImage(
            self.descriptor_bytes(), schema_registry=registry,
            schema_documents=tuple(altered),
        ))
        self.assertEqual(len(result.findings), 128)
        self.assertIn("FINDINGS_TRUNCATED", {item.code for item in result.findings})

    def test_result_mapping_validates_closed_deny_only_schema(self):
        result = verify_runtime_image(RuntimeImage(self.descriptor_bytes()))
        schema = json.loads((
            ROOT / "schemas" / "m0-3a-runtime-v2-verification-result.v1.schema.json"
        ).read_text())
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(result.as_mapping())
        altered = result.as_mapping()
        altered["authorizing_use"] = "ALLOW"
        self.assertTrue(list(Draft202012Validator(schema).iter_errors(altered)))

    def test_noncanonical_or_wrong_descriptor_is_invalid(self):
        noncanonical = RuntimeImage(b'{"runtime_format_version": 2}')
        self.assertEqual(verify_runtime_image(noncanonical).status, "INVALID")
        descriptor = json.loads(self.descriptor_bytes())
        descriptor["tables"].pop()
        result = verify_runtime_image(RuntimeImage(canonical_json(descriptor)))
        self.assertEqual(result.status, "INVALID")
        self.assertIn("DESCRIPTOR_TABLE_INVENTORY", {
            finding.code for finding in result.findings
        })

    def test_any_descriptor_mutation_denies_even_with_same_table_names(self):
        for mutate in (
            lambda value: value["tables"][0].__setitem__(
                "sql", value["tables"][0]["sql"] + " "
            ),
            lambda value: value["indexes"][0].__setitem__(
                "unique", not value["indexes"][0]["unique"]
            ),
            lambda value: value["root_projections"][0]["row_order"].append(
                "head_event_id"
            ),
        ):
            with self.subTest(mutate=mutate):
                descriptor = json.loads(self.descriptor_bytes())
                mutate(descriptor)
                result = verify_runtime_image(
                    RuntimeImage(canonical_json(descriptor))
                )
                self.assertEqual(result.status, "INVALID")
                self.assertIn(
                    "DESCRIPTOR_DIGEST_MISMATCH",
                    {finding.code for finding in result.findings},
                )

    def test_all_unpublished_runtime_image_inputs_must_remain_empty(self):
        values = {
            "manifest": b"{}",
            "attachment": b"{}",
            "blobs": (("digest", b"{}"),),
            "events": (b"{}",),
            "table_snapshots": (("events", ()),),
            "checkpoints": (b"{}",),
            "selector_history": (b"{}",),
            "legacy_evidence": (("archive", b"{}"),),
        }
        for field, value in values.items():
            with self.subTest(field=field):
                result = verify_runtime_image(RuntimeImage(
                    self.descriptor_bytes(), **{field: value}
                ))
                self.assertEqual(result.status, "INVALID")
                self.assertEqual(result.authorizing_use, "DENY")
                self.assertIn(
                    ("UNSUPPORTED_INPUT_MUST_BE_EMPTY", field),
                    {(finding.code, finding.artifact) for finding in result.findings},
                )
        for field, value in (("manifest", None), ("events", [])):
            with self.subTest(field=field, wrong_type=True):
                result = verify_runtime_image(RuntimeImage(
                    self.descriptor_bytes(), **{field: value}
                ))
                self.assertEqual(result.status, "INVALID")

    def test_result_type_cannot_represent_success_or_authority(self):
        finding = (VerificationFinding("X", "x", "/"),)
        for status in ("CONSISTENT", "VALID", "BOGUS"):
            with self.subTest(status=status), self.assertRaises(ValueError):
                VerificationResult(status, finding)
        with self.assertRaises(ValueError):
            VerificationResult("INVALID", ())
        with self.assertRaises(TypeError):
            VerificationResult("INVALID", finding, authorizing_use="ALLOW")
        result = VerificationResult("INVALID", finding)
        with self.assertRaises(FrozenInstanceError):
            result.authorizing_use = "ALLOW"

    def test_verifier_has_no_io_or_authority_imports(self):
        path = ROOT / "src" / "edgelab" / "runtime_v2_verifier.py"
        tree = ast.parse(path.read_text())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        self.assertTrue(imported.isdisjoint({
            "pathlib", "os", "sqlite3", "subprocess", "socket", "time",
            "datetime", "urllib", "requests", "transactional_scheduler",
            "locked_authority", "authority_binding", "risk_controls",
            "runtime_v2_initial", "runtime_v2_closure", "runtime_v2_group",
            "runtime_v2_transition",
        }))
        calls = {node.func.id for node in ast.walk(tree)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
        self.assertTrue(calls.isdisjoint({"open", "exec", "eval", "compile"}))


if __name__ == "__main__":
    unittest.main()
