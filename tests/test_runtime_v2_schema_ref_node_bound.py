"""Additive boundary evidence for the runtime-v2 schema reference graph."""
from __future__ import annotations

import json
from pathlib import Path
import unittest
from unittest import mock

from src.edgelab.runtime_v2_codec import canonical_json
import src.edgelab.runtime_v2_verifier as verifier_module
from src.edgelab.runtime_v2_verifier import (
    MAX_SCHEMA_BUNDLE_BYTES,
    MAX_SCHEMA_DOCUMENT_BYTES,
    MAX_SCHEMA_REF_NODES,
    RuntimeImage,
    SchemaDocumentRecord,
    VerificationFinding,
    verify_runtime_image,
)


ROOT = Path(__file__).resolve().parents[1]


class RuntimeV2SchemaReferenceGraphBoundTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        registry = json.loads((
            ROOT / "schemas" / "m0-3a-schema-registry.v2.json"
        ).read_text(encoding="utf-8"))
        by_id = {}
        for path in (ROOT / "schemas").glob("m0-3a-*.schema.json"):
            document = json.loads(path.read_text(encoding="utf-8"))
            if "$id" in document:
                by_id[document["$id"]] = document
        cls.registry = canonical_json(registry)
        cls.documents = tuple(
            SchemaDocumentRecord(
                entry["schema_id"],
                entry["document_sha256"],
                canonical_json(by_id[entry["schema_id"]]),
            )
            for entry in registry["documents"]
        )
        cls.schema_id = cls.documents[0].schema_id
        cls.descriptor = canonical_json(json.loads((
            ROOT / "schemas" / "m0-3a-runtime-storage.v2.json"
        ).read_text(encoding="utf-8")))
        cls.values = {
            count: cls.schema_value(count)
            for count in (
                MAX_SCHEMA_REF_NODES - 1,
                MAX_SCHEMA_REF_NODES,
                MAX_SCHEMA_REF_NODES + 1,
            )
        }
        cls.bodies = {
            count: canonical_json(value)
            for count, value in cls.values.items()
        }

    @classmethod
    def schema_value(cls, count: int) -> dict[str, object]:
        return {
            "$schema": verifier_module._DRAFT_2020_12,
            "$id": cls.schema_id,
            "$defs": {
                f"n{index:04d}": {"type": "null"}
                for index in range(count)
            },
        }

    @classmethod
    def verifier_image(cls, body: bytes) -> tuple[RuntimeImage, int]:
        documents = list(cls.documents)
        first = documents[0]
        documents[0] = SchemaDocumentRecord(
            first.schema_id, first.document_sha256, body
        )
        bundle_bytes = len(cls.registry) + sum(
            len(record.canonical_json) for record in documents
        )
        return RuntimeImage(
            cls.descriptor,
            schema_registry=cls.registry,
            schema_documents=tuple(documents),
        ), bundle_bytes

    def test_direct_boundary_is_inclusive_with_exact_findings_and_bytes(self):
        expected_body_bytes = {
            MAX_SCHEMA_REF_NODES - 1: 98_392,
            MAX_SCHEMA_REF_NODES: 98_416,
            MAX_SCHEMA_REF_NODES + 1: 98_440,
        }
        for count in (
            MAX_SCHEMA_REF_NODES - 1,
            MAX_SCHEMA_REF_NODES,
        ):
            with self.subTest(count=count):
                body = self.bodies[count]
                self.assertEqual(len(body), expected_body_bytes[count])
                self.assertLessEqual(len(body), MAX_SCHEMA_DOCUMENT_BYTES)
                self.assertEqual(
                    verifier_module._schema_safety_findings(
                        self.schema_id, self.values[count]
                    ),
                    [],
                )

        count = MAX_SCHEMA_REF_NODES + 1
        body = self.bodies[count]
        self.assertEqual(len(body), expected_body_bytes[count])
        self.assertLessEqual(len(body), MAX_SCHEMA_DOCUMENT_BYTES)
        self.assertEqual(
            verifier_module._schema_safety_findings(
                self.schema_id, self.values[count]
            ),
            [
                VerificationFinding(
                    "SCHEMA_REF_GRAPH_TOO_LARGE",
                    self.schema_id,
                    "/$defs",
                )
            ],
        )

    def test_public_verifier_boundary_is_exact_invalid_deny_and_non_boolean(self):
        expected_bundle_bytes = {
            MAX_SCHEMA_REF_NODES - 1: 150_378,
            MAX_SCHEMA_REF_NODES: 150_402,
            MAX_SCHEMA_REF_NODES + 1: 150_426,
        }
        digest_finding = VerificationFinding(
            "SCHEMA_DOCUMENT_DIGEST_MISMATCH", self.schema_id, "/0"
        )
        graph_finding = VerificationFinding(
            "SCHEMA_REF_GRAPH_TOO_LARGE", self.schema_id, "/$defs"
        )
        for count in (
            MAX_SCHEMA_REF_NODES - 1,
            MAX_SCHEMA_REF_NODES,
            MAX_SCHEMA_REF_NODES + 1,
        ):
            with self.subTest(count=count):
                image, bundle_bytes = self.verifier_image(self.bodies[count])
                self.assertEqual(bundle_bytes, expected_bundle_bytes[count])
                self.assertLessEqual(bundle_bytes, MAX_SCHEMA_BUNDLE_BYTES)
                result = verify_runtime_image(image)
                expected = (
                    (digest_finding, graph_finding)
                    if count == MAX_SCHEMA_REF_NODES + 1
                    else (digest_finding,)
                )
                self.assertEqual(result.findings, expected)
                self.assertEqual(result.status, "INVALID")
                self.assertEqual(result.authorizing_use, "DENY")
                with self.assertRaises(TypeError):
                    bool(result)

    def test_invalid_names_and_dangling_targets_do_not_add_graph_nodes(self):
        invalid_name_value = self.schema_value(MAX_SCHEMA_REF_NODES)
        invalid_name_value["$defs"]["1invalid"] = {"type": "null"}
        self.assertEqual(
            verifier_module._schema_safety_findings(
                self.schema_id, invalid_name_value
            ),
            [VerificationFinding("SCHEMA_DEF_NAME", self.schema_id, "/$defs")],
        )

        dangling_value = self.schema_value(MAX_SCHEMA_REF_NODES)
        dangling_value["$defs"]["n0000"] = {
            "$ref": "#/$defs/missing"
        }
        self.assertEqual(
            verifier_module._schema_safety_findings(
                self.schema_id, dangling_value
            ),
            [
                VerificationFinding(
                    "SCHEMA_REF_DANGLING",
                    self.schema_id,
                    "/$defs/n0000/$ref",
                )
            ],
        )

    def test_diagnostic_budget_short_circuits_before_graph_cardinality(self):
        value = {
            "$schema": verifier_module._DRAFT_2020_12,
            "$id": self.schema_id,
            "$unknown": True,
            "$defs": self.values[MAX_SCHEMA_REF_NODES + 1]["$defs"],
        }
        self.assertEqual(
            verifier_module._schema_safety_findings(
                self.schema_id, value, limit=1
            ),
            [
                VerificationFinding(
                    "SCHEMA_UNKNOWN_KEYWORD", self.schema_id, "/$unknown"
                )
            ],
        )

    def test_oversized_graph_returns_before_dfs_sorting(self):
        with mock.patch(
            "builtins.sorted",
            side_effect=AssertionError("DFS sorting must not be reached"),
        ):
            findings = verifier_module._schema_safety_findings(
                self.schema_id,
                self.values[MAX_SCHEMA_REF_NODES + 1],
            )
        self.assertEqual(
            findings,
            [
                VerificationFinding(
                    "SCHEMA_REF_GRAPH_TOO_LARGE",
                    self.schema_id,
                    "/$defs",
                )
            ],
        )


if __name__ == "__main__":
    unittest.main()
