"""Adversarial boundary evidence for the shared schema-bundle byte ceiling."""
from dataclasses import replace
import unittest

import src.edgelab.runtime_v2_image as host
import src.edgelab.runtime_v2_verifier as verifier


MAXIMUM = 2_097_152
DOCUMENT_COUNT = 9


def _sizes(total: int, count: int = DOCUMENT_COUNT) -> tuple[int, ...]:
    """Distribute a total without exceeding the per-document byte ceiling."""
    sizes = []
    remaining = total
    for _ in range(count):
        size = min(remaining, host.MAX_SCHEMA_DOCUMENT_BYTES)
        sizes.append(size)
        remaining -= size
    if remaining:
        raise AssertionError("requested aggregate is not representable")
    return tuple(sizes)


class _ExplosiveLength:
    def __len__(self):
        raise AssertionError("len() must not inspect a non-bytes value")

    def __bool__(self):
        return True


class RuntimeV2SchemaBundleByteBoundTests(unittest.TestCase):
    def host_documents(self, body_total: int):
        return tuple(
            host.SchemaDocumentRecord(
                f"schema-{index}", f"digest-{index}", b" " * size,
            )
            for index, size in enumerate(_sizes(body_total))
        )

    def host_image(self, *, registry=b"r", documents=None, descriptor=b"{}"):
        if documents is None:
            documents = self.host_documents(0)
        return host.RuntimeImage(
            storage_descriptor=descriptor,
            verifier_dependency_closure=b"{}",
            manifest=b"{}",
            attachment=b"{}",
            schema_registry=registry,
            schema_documents=documents,
            blobs=(),
            events=(),
            table_snapshots=tuple(
                host.TableSnapshot(name, ()) for name in host.TABLE_NAMES
            ),
            checkpoint_copies=(),
            selector_history=(b"{}", b"{}"),
            legacy_evidence=None,
        )

    def verifier_documents(self, body_total: int):
        return tuple(
            verifier.SchemaDocumentRecord(schema_id, digest, b" " * size)
            for (schema_id, digest), size in zip(
                verifier.SCHEMA_DOCUMENT_PINS, _sizes(body_total), strict=True,
            )
        )

    @staticmethod
    def host_codes(report):
        return tuple(item.code for item in report.violations)

    @staticmethod
    def verifier_codes(report):
        return tuple(item.code for item in report.findings)

    def test_both_implementations_fix_the_same_inclusive_maximum(self):
        self.assertEqual(host.MAX_SCHEMA_BUNDLE_BYTES, MAXIMUM)
        self.assertEqual(verifier.MAX_SCHEMA_BUNDLE_BYTES, MAXIMUM)
        self.assertLess(MAXIMUM, 9 * host.MAX_SCHEMA_DOCUMENT_BYTES + 2)

    def test_host_aggregate_boundary_is_inclusive_and_deny_only(self):
        for aggregate, rejected in (
            (MAXIMUM - 1, False),
            (MAXIMUM, False),
            (MAXIMUM + 1, True),
        ):
            with self.subTest(aggregate=aggregate):
                registry = b"r"
                candidate = self.host_image(
                    registry=registry,
                    documents=self.host_documents(aggregate - len(registry)),
                )
                original_bodies = tuple(
                    record.canonical_json for record in candidate.schema_documents
                )
                first = host.inspect_runtime_image_host(candidate)
                second = host.inspect_runtime_image_host(candidate)
                self.assertEqual(first, second)
                self.assertEqual(first.authorizing_use, "DENY")
                self.assertEqual(
                    "SCHEMA_BUNDLE_BYTE_LIMIT" in self.host_codes(first), rejected,
                )
                self.assertEqual(first.image is None, rejected)
                self.assertEqual(
                    tuple(record.canonical_json for record in candidate.schema_documents),
                    original_bodies,
                )
                with self.assertRaises(TypeError):
                    bool(first)

    def test_verifier_aggregate_boundary_is_inclusive_and_deny_only(self):
        for aggregate, rejected in (
            (MAXIMUM - 1, False),
            (MAXIMUM, False),
            (MAXIMUM + 1, True),
        ):
            with self.subTest(aggregate=aggregate):
                registry = b"r"
                documents = self.verifier_documents(aggregate - len(registry))
                candidate = verifier.RuntimeImage(
                    b"{}", schema_registry=registry,
                    schema_documents=documents,
                )
                first = verifier.verify_runtime_image(candidate)
                second = verifier.verify_runtime_image(candidate)
                self.assertEqual(first, second)
                self.assertEqual(first.status, "INVALID")
                self.assertEqual(
                    (first.anchor_status, first.currentness_status,
                     first.authorizing_use),
                    ("UNANCHORED", "UNKNOWN", "DENY"),
                )
                self.assertEqual(
                    "SCHEMA_BUNDLE_TOO_LARGE" in self.verifier_codes(first),
                    rejected,
                )
                with self.assertRaises(TypeError):
                    bool(first)

    def test_storage_descriptor_boundary_precedes_parsing_and_is_deny_only(self):
        for size, rejected in (
            (MAXIMUM - 1, False),
            (MAXIMUM, False),
            (MAXIMUM + 1, True),
        ):
            with self.subTest(size=size):
                result = verifier.verify_runtime_image(
                    verifier.RuntimeImage(b" " * size)
                )
                codes = self.verifier_codes(result)
                self.assertEqual(result.status, "INVALID")
                self.assertEqual(result.authorizing_use, "DENY")
                self.assertEqual("DESCRIPTOR_TOO_LARGE" in codes, rejected)
                self.assertEqual(
                    "DESCRIPTOR_CANONICAL_JSON" in codes, not rejected,
                )

    def test_host_accumulates_only_exact_bytes_bodies_of_exact_records(self):
        class RecordSubclass(host.SchemaDocumentRecord):
            pass

        bodies = [host.MAX_SCHEMA_DOCUMENT_BYTES] * 8 + [0]
        exact = [
            host.SchemaDocumentRecord(f"schema-{index}", f"digest-{index}", b" " * size)
            for index, size in enumerate(bodies)
        ]
        self.assertGreater(1 + sum(bodies), MAXIMUM)

        wrong_record = list(exact)
        item = wrong_record[0]
        wrong_record[0] = RecordSubclass(
            item.schema_id, item.document_sha256, item.canonical_json,
        )
        report = host.inspect_runtime_image_host(self.host_image(
            documents=tuple(wrong_record),
        ))
        self.assertIn("IMAGE_RECORD_TYPE", self.host_codes(report))
        self.assertNotIn("SCHEMA_BUNDLE_BYTE_LIMIT", self.host_codes(report))

        wrong_body = list(exact)
        item = wrong_body[0]
        wrong_body[0] = host.SchemaDocumentRecord(
            item.schema_id, item.document_sha256, bytearray(item.canonical_json),
        )
        report = host.inspect_runtime_image_host(self.host_image(
            documents=tuple(wrong_body),
        ))
        self.assertIn("IMAGE_RECORD_FIELD_TYPE", self.host_codes(report))
        self.assertNotIn("SCHEMA_BUNDLE_BYTE_LIMIT", self.host_codes(report))

    def test_verifier_accumulates_only_exact_bytes_bodies_of_exact_records(self):
        class RecordSubclass(verifier.SchemaDocumentRecord):
            pass

        bodies = [verifier.MAX_SCHEMA_DOCUMENT_BYTES] * 8 + [0]
        exact = [
            verifier.SchemaDocumentRecord(schema_id, digest, b" " * size)
            for (schema_id, digest), size in zip(
                verifier.SCHEMA_DOCUMENT_PINS, bodies, strict=True,
            )
        ]
        self.assertGreater(1 + sum(bodies), MAXIMUM)

        wrong_record = list(exact)
        item = wrong_record[0]
        wrong_record[0] = RecordSubclass(
            item.schema_id, item.document_sha256, item.canonical_json,
        )
        result = verifier.verify_runtime_image(verifier.RuntimeImage(
            b"{}", schema_registry=b"r", schema_documents=tuple(wrong_record),
        ))
        self.assertIn("SCHEMA_DOCUMENT_RECORD_TYPE", self.verifier_codes(result))
        self.assertNotIn("SCHEMA_BUNDLE_TOO_LARGE", self.verifier_codes(result))

        wrong_body = list(exact)
        item = wrong_body[0]
        wrong_body[0] = verifier.SchemaDocumentRecord(
            item.schema_id, item.document_sha256, bytearray(item.canonical_json),
        )
        result = verifier.verify_runtime_image(verifier.RuntimeImage(
            b"{}", schema_registry=b"r", schema_documents=tuple(wrong_body),
        ))
        self.assertIn("SCHEMA_DOCUMENT_BYTES_TYPE", self.verifier_codes(result))
        self.assertNotIn("SCHEMA_BUNDLE_TOO_LARGE", self.verifier_codes(result))

    def test_exact_type_guards_precede_length_and_descriptor_parse(self):
        explosive = _ExplosiveLength()
        host_report = host.inspect_runtime_image_host(self.host_image(
            registry=explosive,
        ))
        self.assertIn("IMAGE_FIELD_TYPE", self.host_codes(host_report))
        self.assertNotIn("SCHEMA_BUNDLE_BYTE_LIMIT", self.host_codes(host_report))

        verifier_report = verifier.verify_runtime_image(verifier.RuntimeImage(
            b"{}", schema_registry=explosive,
            schema_documents=self.verifier_documents(0),
        ))
        self.assertIn("SCHEMA_BUNDLE_INCOMPLETE", self.verifier_codes(verifier_report))
        self.assertNotIn("SCHEMA_BUNDLE_TOO_LARGE", self.verifier_codes(verifier_report))

        descriptor_report = verifier.verify_runtime_image(
            verifier.RuntimeImage(explosive)
        )
        self.assertIn("DESCRIPTOR_BYTES_TYPE", self.verifier_codes(descriptor_report))
        self.assertNotIn("DESCRIPTOR_TOO_LARGE", self.verifier_codes(descriptor_report))

    def test_unrelated_input_size_does_not_change_schema_bundle_decision(self):
        candidate = self.host_image(
            registry=b"r",
            documents=self.host_documents(MAXIMUM - 1),
        )
        baseline = host.inspect_runtime_image_host(candidate)
        changed = host.inspect_runtime_image_host(replace(
            candidate, manifest=b"x" * (host.MAX_BOOTSTRAP_DOCUMENT_BYTES + 1),
        ))
        self.assertNotIn("SCHEMA_BUNDLE_BYTE_LIMIT", self.host_codes(baseline))
        self.assertNotIn("SCHEMA_BUNDLE_BYTE_LIMIT", self.host_codes(changed))
        self.assertIn("IMAGE_ITEM_BYTE_LIMIT", self.host_codes(changed))
        self.assertEqual(changed.authorizing_use, "DENY")


if __name__ == "__main__":
    unittest.main()
