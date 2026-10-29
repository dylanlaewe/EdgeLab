"""Boundary evidence for the runtime-v2 per-event byte cap."""
from __future__ import annotations

import unittest

from src.edgelab.runtime_v2_image import (
    MAX_EVENT_BYTES,
    MAX_EVENTS,
    RuntimeImage,
    SchemaDocumentRecord,
    TABLE_NAMES,
    TableSnapshot,
    inspect_runtime_image_host,
)


class RuntimeV2EventByteBoundTests(unittest.TestCase):
    def image(self, events: tuple[object, ...]) -> RuntimeImage:
        return RuntimeImage(
            storage_descriptor=b"{}",
            verifier_dependency_closure=b"{}",
            manifest=b"{}",
            attachment=b"{}",
            schema_registry=b"{}",
            schema_documents=tuple(
                SchemaDocumentRecord(
                    f"schema-{index}", f"digest-{index}", b"{}"
                )
                for index in range(9)
            ),
            blobs=(),
            events=events,
            table_snapshots=tuple(
                TableSnapshot(name, ()) for name in TABLE_NAMES
            ),
            checkpoint_copies=(),
            selector_history=(b"{}", b"{}"),
            legacy_evidence=None,
        )

    def test_exact_one_member_boundary_matrix_at_index_zero(self):
        for size in (
            MAX_EVENT_BYTES - 1,
            MAX_EVENT_BYTES,
            MAX_EVENT_BYTES + 1,
        ):
            with self.subTest(size=size):
                body = b"{" + (b"x" * (size - 2)) + b"}"
                self.assertEqual(len(body), size)
                report = inspect_runtime_image_host(self.image((body,)))
                self.assertEqual(report.authorizing_use, "DENY")
                with self.assertRaises(TypeError):
                    bool(report)

                if size <= MAX_EVENT_BYTES:
                    self.assertEqual(report.violations, ())
                    self.assertIsNotNone(report.image)
                    self.assertEqual(report.image.events, (body,))
                    self.assertIs(report.image.events[0], body)
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
                        [("IMAGE_ITEM_BYTE_LIMIT", "events", "/0")],
                    )
                    self.assertIsNone(report.image)
                    self.assertIsNotNone(report.total_accounted_input_bytes)

    def test_inclusive_boundary_retains_exact_bytes_without_truncation(self):
        for size in (MAX_EVENT_BYTES - 1, MAX_EVENT_BYTES):
            with self.subTest(size=size):
                body = b"{" + (b"x" * (size - 2)) + b"}"
                self.assertEqual(len(body), size)
                supplied = (b"prefix", body)
                report = inspect_runtime_image_host(self.image(supplied))
                self.assertEqual(report.violations, ())
                self.assertIsNotNone(report.image)
                self.assertEqual(report.image.events, supplied)
                self.assertIs(report.image.events[1], body)
                self.assertEqual(len(report.image.events[1]), size)
                self.assertEqual(report.authorizing_use, "DENY")
                with self.assertRaises(TypeError):
                    bool(report)

    def test_oversized_event_at_nonzero_index_denies_exactly(self):
        oversized = b"{" + (b"x" * (MAX_EVENT_BYTES - 1)) + b"}"
        self.assertEqual(len(oversized), MAX_EVENT_BYTES + 1)
        report = inspect_runtime_image_host(
            self.image((b"first", oversized))
        )
        self.assertEqual(
            [
                (finding.code, finding.artifact, finding.coordinate)
                for finding in report.violations
            ],
            [("IMAGE_ITEM_BYTE_LIMIT", "events", "/1")],
        )
        self.assertIsNone(report.image)
        self.assertIsNotNone(report.total_accounted_input_bytes)
        self.assertEqual(report.authorizing_use, "DENY")
        with self.assertRaises(TypeError):
            bool(report)

    def test_non_bytes_event_is_rejected_before_size_inspection(self):
        class LengthMustNotRun:
            def __len__(self):
                raise AssertionError("non-bytes event length was inspected")

        report = inspect_runtime_image_host(
            self.image((b"first", LengthMustNotRun()))
        )
        self.assertEqual(
            [
                (finding.code, finding.artifact, finding.coordinate)
                for finding in report.violations
            ],
            [("IMAGE_RECORD_TYPE", "events", "/1")],
        )
        self.assertIsNone(report.image)
        self.assertIsNone(report.total_accounted_input_bytes)
        self.assertEqual(report.authorizing_use, "DENY")

    def test_invalid_cardinality_skips_per_item_size_inspection(self):
        oversized = b"x" * (MAX_EVENT_BYTES + 1)
        events = (oversized,) + ((b"",) * MAX_EVENTS)
        self.assertEqual(len(events), MAX_EVENTS + 1)
        report = inspect_runtime_image_host(self.image(events))
        self.assertEqual(
            [
                (finding.code, finding.artifact, finding.coordinate)
                for finding in report.violations
            ],
            [("IMAGE_CARDINALITY_LIMIT", "events", "/")],
        )
        self.assertNotIn(
            "IMAGE_ITEM_BYTE_LIMIT",
            {finding.code for finding in report.violations},
        )
        self.assertIsNone(report.image)
        self.assertIsNone(report.total_accounted_input_bytes)
        self.assertEqual(report.authorizing_use, "DENY")
        with self.assertRaises(TypeError):
            bool(report)


if __name__ == "__main__":
    unittest.main()
