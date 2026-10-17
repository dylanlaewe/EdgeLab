"""Boundary tests for the deliberately incomplete pure v2 verifier."""
import ast
from dataclasses import FrozenInstanceError
import hashlib
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator

from src.edgelab.runtime_v2_codec import canonical_json, storage_schema_digest
from src.edgelab.runtime_v2_verifier import (
    STORAGE_DESCRIPTOR_SCHEMA_SHA256,
    STORAGE_DESCRIPTOR_SHA256,
    RuntimeImage,
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
            "schema_registry": b"{}",
            "schema_documents": (("schema", b"{}"),),
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
        }))
        calls = {node.func.id for node in ast.walk(tree)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
        self.assertTrue(calls.isdisjoint({"open", "exec", "eval", "compile"}))


if __name__ == "__main__":
    unittest.main()
