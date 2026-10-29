"""Boundary evidence for the duplicated runtime-v2 schema-document byte cap."""
from __future__ import annotations

import json
from pathlib import Path
import unittest

from src.edgelab.runtime_v2_codec import canonical_json
from src.edgelab.runtime_v2_image import (
    MAX_SCHEMA_DOCUMENT_BYTES as IMAGE_MAX_SCHEMA_DOCUMENT_BYTES,
    RuntimeImage as HostRuntimeImage,
    SchemaDocumentRecord as HostSchemaDocumentRecord,
    TABLE_NAMES,
    TableSnapshot,
    inspect_runtime_image_host,
)
from src.edgelab.runtime_v2_verifier import (
    MAX_SCHEMA_DOCUMENT_BYTES as VERIFIER_MAX_SCHEMA_DOCUMENT_BYTES,
    RuntimeImage as VerifierRuntimeImage,
    SchemaDocumentRecord as VerifierSchemaDocumentRecord,
    verify_runtime_image,
)


ROOT = Path(__file__).resolve().parents[1]


def _exact_json_object(size: int) -> bytes:
    prefix = b'{"value":"'
    suffix = b'"}'
    if size < len(prefix) + len(suffix):
        raise ValueError("requested canonical JSON body is too short")
    return prefix + (b"x" * (size - len(prefix) - len(suffix))) + suffix


class RuntimeV2SchemaDocumentBoundTests(unittest.TestCase):
    def host_image(self, body: bytes) -> HostRuntimeImage:
        documents = [
            HostSchemaDocumentRecord(f"schema-{index}", f"digest-{index}", b"{}")
            for index in range(9)
        ]
        documents[0] = HostSchemaDocumentRecord("schema-0", "digest-0", body)
        return HostRuntimeImage(
            storage_descriptor=b"{}",
            verifier_dependency_closure=b"{}",
            manifest=b"{}",
            attachment=b"{}",
            schema_registry=b"{}",
            schema_documents=tuple(documents),
            blobs=(),
            events=(),
            table_snapshots=tuple(TableSnapshot(name, ()) for name in TABLE_NAMES),
            checkpoint_copies=(),
            selector_history=(b"{}", b"{}"),
            legacy_evidence=None,
        )

    def verifier_bundle(self, body: bytes):
        registry = json.loads((
            ROOT / "schemas" / "m0-3a-schema-registry.v2.json"
        ).read_text(encoding="utf-8"))
        by_id = {}
        for path in (ROOT / "schemas").glob("m0-3a-*.schema.json"):
            document = json.loads(path.read_text(encoding="utf-8"))
            if "$id" in document:
                by_id[document["$id"]] = document
        documents = [
            VerifierSchemaDocumentRecord(
                entry["schema_id"],
                entry["document_sha256"],
                canonical_json(by_id[entry["schema_id"]]),
            )
            for entry in registry["documents"]
        ]
        first = documents[0]
        documents[0] = VerifierSchemaDocumentRecord(
            first.schema_id, first.document_sha256, body
        )
        descriptor = canonical_json(json.loads((
            ROOT / "schemas" / "m0-3a-runtime-storage.v2.json"
        ).read_text(encoding="utf-8")))
        return descriptor, canonical_json(registry), tuple(documents)

    def test_host_preflight_boundary_is_inclusive_and_deny_only(self):
        self.assertEqual(
            IMAGE_MAX_SCHEMA_DOCUMENT_BYTES, VERIFIER_MAX_SCHEMA_DOCUMENT_BYTES
        )
        maximum = IMAGE_MAX_SCHEMA_DOCUMENT_BYTES
        for size in (maximum - 1, maximum):
            with self.subTest(size=size):
                body = _exact_json_object(size)
                self.assertEqual(len(body), size)
                report = inspect_runtime_image_host(self.host_image(body))
                self.assertEqual(report.violations, ())
                self.assertIsNotNone(report.image)
                self.assertEqual(
                    report.image.schema_documents[0].canonical_json, body
                )
                self.assertEqual(report.authorizing_use, "DENY")
        oversized_body = _exact_json_object(maximum + 1)
        self.assertEqual(len(oversized_body), maximum + 1)
        report = inspect_runtime_image_host(self.host_image(oversized_body))
        self.assertEqual(
            [(item.code, item.artifact, item.coordinate) for item in report.violations],
            [("IMAGE_ITEM_BYTE_LIMIT", "schema_documents", "/0/canonical_json")],
        )
        self.assertNotIn(
            "SCHEMA_BUNDLE_BYTE_LIMIT", {item.code for item in report.violations}
        )
        self.assertNotIn(
            "TOTAL_ACCOUNTED_INPUT_LIMIT", {item.code for item in report.violations}
        )
        self.assertIsNone(report.image)
        self.assertEqual(report.authorizing_use, "DENY")

    def test_verifier_boundary_is_inclusive_invalid_and_deny_only(self):
        maximum = VERIFIER_MAX_SCHEMA_DOCUMENT_BYTES
        for size in (maximum - 1, maximum):
            with self.subTest(size=size):
                body = _exact_json_object(size)
                self.assertEqual(len(body), size)
                descriptor, registry, documents = self.verifier_bundle(
                    body
                )
                result = verify_runtime_image(VerifierRuntimeImage(
                    descriptor, schema_registry=registry,
                    schema_documents=documents,
                ))
                self.assertEqual(
                    [item.code for item in result.findings],
                    [
                        "SCHEMA_DIALECT",
                        "SCHEMA_DOCUMENT_DIGEST_MISMATCH",
                        "SCHEMA_ID_MISMATCH",
                    ],
                )
                self.assertEqual(result.status, "INVALID")
                self.assertEqual(result.authorizing_use, "DENY")
        oversized_body = _exact_json_object(maximum + 1)
        self.assertEqual(len(oversized_body), maximum + 1)
        descriptor, registry, documents = self.verifier_bundle(oversized_body)
        result = verify_runtime_image(VerifierRuntimeImage(
            descriptor, schema_registry=registry, schema_documents=documents,
        ))
        self.assertEqual(
            [(item.code, item.artifact, item.coordinate) for item in result.findings],
            [("SCHEMA_DOCUMENT_TOO_LARGE", "schema_documents", "/0/canonical_json")],
        )
        self.assertNotIn(
            "SCHEMA_BUNDLE_TOO_LARGE", {item.code for item in result.findings}
        )
        self.assertEqual(result.status, "INVALID")
        self.assertEqual(result.authorizing_use, "DENY")
        with self.assertRaises(TypeError):
            bool(result)


if __name__ == "__main__":
    unittest.main()
