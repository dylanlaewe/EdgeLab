"""Boundary evidence for the duplicated runtime-v2 schema-registry byte cap."""
from __future__ import annotations

import json
from pathlib import Path
import unittest

from src.edgelab.runtime_v2_codec import canonical_json
from src.edgelab.runtime_v2_image import (
    MAX_SCHEMA_REGISTRY_BYTES as IMAGE_MAX_SCHEMA_REGISTRY_BYTES,
    RuntimeImage as HostRuntimeImage,
    SchemaDocumentRecord as HostSchemaDocumentRecord,
    TABLE_NAMES,
    TableSnapshot,
    inspect_runtime_image_host,
)
from src.edgelab.runtime_v2_verifier import (
    MAX_SCHEMA_DOCUMENT_BYTES,
    MAX_SCHEMA_REGISTRY_BYTES as VERIFIER_MAX_SCHEMA_REGISTRY_BYTES,
    RuntimeImage as VerifierRuntimeImage,
    SchemaDocumentRecord as VerifierSchemaDocumentRecord,
    verify_runtime_image,
)


ROOT = Path(__file__).resolve().parents[1]


class RuntimeV2SchemaRegistryByteBoundTests(unittest.TestCase):
    def host_image(self, registry: object) -> HostRuntimeImage:
        return HostRuntimeImage(
            storage_descriptor=b"{}",
            verifier_dependency_closure=b"{}",
            manifest=b"{}",
            attachment=b"{}",
            schema_registry=registry,
            schema_documents=tuple(
                HostSchemaDocumentRecord(
                    f"schema-{index}", f"digest-{index}", b"{}"
                )
                for index in range(9)
            ),
            blobs=(),
            events=(),
            table_snapshots=tuple(
                TableSnapshot(name, ()) for name in TABLE_NAMES
            ),
            checkpoint_copies=(),
            selector_history=(b"{}", b"{}"),
            legacy_evidence=None,
        )

    @classmethod
    def verifier_inputs(cls):
        registry = json.loads((
            ROOT / "schemas" / "m0-3a-schema-registry.v2.json"
        ).read_text(encoding="utf-8"))
        by_id = {}
        for path in (ROOT / "schemas").glob("m0-3a-*.schema.json"):
            document = json.loads(path.read_text(encoding="utf-8"))
            if "$id" in document:
                by_id[document["$id"]] = document
        documents = tuple(
            VerifierSchemaDocumentRecord(
                entry["schema_id"],
                entry["document_sha256"],
                canonical_json(by_id[entry["schema_id"]]),
            )
            for entry in registry["documents"]
        )
        descriptor = canonical_json(json.loads((
            ROOT / "schemas" / "m0-3a-runtime-storage.v2.json"
        ).read_text(encoding="utf-8")))
        return descriptor, documents

    def test_both_implementations_fix_the_same_exact_maximum(self):
        self.assertEqual(IMAGE_MAX_SCHEMA_REGISTRY_BYTES, 262_144)
        self.assertEqual(
            IMAGE_MAX_SCHEMA_REGISTRY_BYTES,
            VERIFIER_MAX_SCHEMA_REGISTRY_BYTES,
        )

    def test_host_boundary_is_inclusive_retained_and_deny_only(self):
        maximum = IMAGE_MAX_SCHEMA_REGISTRY_BYTES
        for size in (maximum - 1, maximum, maximum + 1):
            with self.subTest(size=size):
                supplied = b"x" * size
                report = inspect_runtime_image_host(self.host_image(supplied))
                self.assertEqual(report.authorizing_use, "DENY")
                with self.assertRaises(TypeError):
                    bool(report)

                if size <= maximum:
                    self.assertEqual(report.violations, ())
                    self.assertIsNotNone(report.image)
                    self.assertIs(report.image.schema_registry, supplied)
                    self.assertEqual(report.image.schema_registry, supplied)
                    self.assertEqual(len(report.image.schema_registry), size)
                else:
                    self.assertEqual(
                        [
                            (
                                finding.code,
                                finding.artifact,
                                finding.coordinate,
                            )
                            for finding in report.violations
                        ],
                        [("IMAGE_ITEM_BYTE_LIMIT", "schema_registry", "/")],
                    )
                    self.assertIsNone(report.image)
                    self.assertIsNotNone(report.total_accounted_input_bytes)

    def test_host_exact_type_guard_precedes_length_and_accounting(self):
        class LengthMustNotRun:
            def __len__(self):
                raise AssertionError("non-bytes registry length was inspected")

        report = inspect_runtime_image_host(self.host_image(LengthMustNotRun()))
        self.assertEqual(
            [
                (finding.code, finding.artifact, finding.coordinate)
                for finding in report.violations
            ],
            [("IMAGE_FIELD_TYPE", "schema_registry", "/")],
        )
        self.assertIsNone(report.image)
        self.assertIsNone(report.total_accounted_input_bytes)
        self.assertEqual(report.authorizing_use, "DENY")
        with self.assertRaises(TypeError):
            bool(report)

    def test_verifier_boundary_is_inclusive_invalid_and_deny_only(self):
        descriptor, documents = self.verifier_inputs()
        maximum = VERIFIER_MAX_SCHEMA_REGISTRY_BYTES
        for size in (maximum - 1, maximum, maximum + 1):
            with self.subTest(size=size):
                supplied = b" " * size
                result = verify_runtime_image(VerifierRuntimeImage(
                    descriptor,
                    schema_registry=supplied,
                    schema_documents=documents,
                ))
                expected = (
                    "SCHEMA_REGISTRY_CANONICAL_JSON"
                    if size <= maximum
                    else "SCHEMA_REGISTRY_TOO_LARGE"
                )
                self.assertEqual(
                    [
                        (
                            finding.code,
                            finding.artifact,
                            finding.coordinate,
                        )
                        for finding in result.findings
                    ],
                    [(expected, "schema_registry", "/")],
                )
                self.assertEqual(result.status, "INVALID")
                self.assertEqual(result.authorizing_use, "DENY")
                self.assertIsNone(result.runtime_id)
                self.assertIsNone(result.chain_id)
                self.assertIsNone(result.event_count)
                with self.assertRaises(TypeError):
                    bool(result)

    def test_verifier_presence_and_type_guards_precede_length(self):
        descriptor, documents = self.verifier_inputs()

        class LengthMustNotRun:
            def __len__(self):
                raise AssertionError("non-bytes registry length was inspected")

        cases = (
            (LengthMustNotRun(), (), "SCHEMA_REGISTRY_TYPE", "schema_registry"),
            (
                LengthMustNotRun(),
                documents,
                "SCHEMA_BUNDLE_INCOMPLETE",
                "schema_bundle",
            ),
            (b"", documents, "SCHEMA_BUNDLE_INCOMPLETE", "schema_bundle"),
        )
        for registry, supplied_documents, code, artifact in cases:
            with self.subTest(code=code, artifact=artifact):
                result = verify_runtime_image(VerifierRuntimeImage(
                    descriptor,
                    schema_registry=registry,
                    schema_documents=supplied_documents,
                ))
                self.assertEqual(
                    [
                        (
                            finding.code,
                            finding.artifact,
                            finding.coordinate,
                        )
                        for finding in result.findings
                    ],
                    [(code, artifact, "/")],
                )
                self.assertEqual(result.status, "INVALID")
                self.assertEqual(result.authorizing_use, "DENY")

    def test_verifier_size_guard_precedes_inventory_aggregate_and_parse(self):
        descriptor, documents = self.verifier_inputs()
        oversized_registry = b"x" * (VERIFIER_MAX_SCHEMA_REGISTRY_BYTES + 1)
        oversized_documents = tuple(
            VerifierSchemaDocumentRecord(
                record.schema_id,
                record.document_sha256,
                b"x" * (MAX_SCHEMA_DOCUMENT_BYTES + 1),
            )
            for record in documents
        )
        cases = (
            documents[:-1],
            oversized_documents,
        )
        for supplied_documents in cases:
            with self.subTest(document_count=len(supplied_documents)):
                result = verify_runtime_image(VerifierRuntimeImage(
                    descriptor,
                    schema_registry=oversized_registry,
                    schema_documents=supplied_documents,
                ))
                self.assertEqual(
                    [
                        (
                            finding.code,
                            finding.artifact,
                            finding.coordinate,
                        )
                        for finding in result.findings
                    ],
                    [("SCHEMA_REGISTRY_TOO_LARGE", "schema_registry", "/")],
                )
                self.assertEqual(result.status, "INVALID")
                self.assertEqual(result.authorizing_use, "DENY")
                with self.assertRaises(TypeError):
                    bool(result)


if __name__ == "__main__":
    unittest.main()
