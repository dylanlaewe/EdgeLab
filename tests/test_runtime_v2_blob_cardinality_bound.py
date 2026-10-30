"""Boundary evidence for the runtime-v2 top-level blob-count maximum."""
from __future__ import annotations

import unittest

from src.edgelab import runtime_v2_image as image_module
from src.edgelab.runtime_v2_image import (
    BlobRecord,
    ImageViolation,
    MAX_BLOBS,
    MAX_BLOB_BYTES,
    MAX_EVENTS,
    RuntimeImage,
    SchemaDocumentRecord,
    TABLE_NAMES,
    TableSnapshot,
    inspect_runtime_image_host,
)


class RuntimeV2BlobCardinalityBoundTests(unittest.TestCase):
    def image(self, **changes: object) -> RuntimeImage:
        values = {
            "storage_descriptor": b"{}",
            "verifier_dependency_closure": b"{}",
            "manifest": b"{}",
            "attachment": b"{}",
            "schema_registry": b"{}",
            "schema_documents": tuple(
                SchemaDocumentRecord(
                    f"schema-{index}", f"digest-{index}", b"{}"
                )
                for index in range(9)
            ),
            "blobs": (),
            "events": (),
            "table_snapshots": tuple(
                TableSnapshot(name, ()) for name in TABLE_NAMES
            ),
            "checkpoint_copies": (),
            "selector_history": (b"{}", b"{}"),
            "legacy_evidence": None,
        }
        values.update(changes)
        return RuntimeImage(**values)

    def assert_deny_only(self, report) -> None:
        self.assertEqual(report.authorizing_use, "DENY")
        with self.assertRaises(TypeError):
            bool(report)

    def test_exact_constant_is_the_inclusive_300000_item_maximum(self):
        self.assertEqual(MAX_BLOBS, 300_000)

    def test_zero_maximum_minus_one_and_maximum_are_admitted(self):
        baseline = inspect_runtime_image_host(self.image())
        self.assertEqual(baseline.violations, ())
        empty = BlobRecord("", "", b"")
        first = BlobRecord("first", "schema-a", b"a")
        last = BlobRecord("last", "schema-b", b"b")
        for count in (0, MAX_BLOBS - 1, MAX_BLOBS):
            with self.subTest(count=count):
                supplied = (
                    ()
                    if count == 0
                    else (first,) + (empty,) * (count - 2) + (last,)
                )
                candidate = self.image(blobs=supplied)
                report = inspect_runtime_image_host(candidate)
                self.assertEqual(report.violations, ())
                self.assertIsNotNone(report.image)
                self.assertEqual(len(report.image.blobs), count)
                self.assertIs(candidate.blobs, supplied)
                if count:
                    self.assertEqual(report.image.blobs[0], first)
                    self.assertEqual(report.image.blobs[-1], last)
                expected_member_bytes = 0 if count == 0 else 27
                self.assertEqual(
                    report.total_accounted_input_bytes,
                    baseline.total_accounted_input_bytes + expected_member_bytes,
                )
                self.assertEqual(
                    report.final_supplied_root_work_bytes,
                    baseline.final_supplied_root_work_bytes,
                )
                self.assert_deny_only(report)

    def test_maximum_plus_one_emits_exact_root_finding_and_withholds(self):
        member = BlobRecord("", "", b"")
        supplied = (member,) * (MAX_BLOBS + 1)
        candidate = self.image(blobs=supplied)
        report = inspect_runtime_image_host(candidate)
        self.assertEqual(
            report.violations,
            (ImageViolation("IMAGE_CARDINALITY_LIMIT", "blobs", "/"),),
        )
        self.assertEqual(candidate.blobs, supplied)
        self.assertIsNone(report.image)
        self.assertIsNone(report.total_accounted_input_bytes)
        self.assertIsNone(report.final_supplied_root_work_bytes)
        self.assert_deny_only(report)

    def test_exact_tuple_guard_precedes_caller_selected_length(self):
        class LengthMustNotRun:
            def __len__(self):
                raise AssertionError("non-tuple blob length was inspected")

        supplied = LengthMustNotRun()
        report = inspect_runtime_image_host(self.image(blobs=supplied))
        self.assertEqual(
            report.violations,
            (ImageViolation("IMAGE_FIELD_TYPE", "blobs", "/"),),
        )
        self.assertIsNone(report.image)
        self.assertIsNone(report.total_accounted_input_bytes)
        self.assertIsNone(report.final_supplied_root_work_bytes)
        self.assert_deny_only(report)

    def test_tuple_subclass_is_rejected_before_cardinality(self):
        class TupleSubclass(tuple):
            pass

        supplied = TupleSubclass((BlobRecord("", "", b""),))
        report = inspect_runtime_image_host(self.image(blobs=supplied))
        self.assertEqual(
            report.violations,
            (ImageViolation("IMAGE_FIELD_TYPE", "blobs", "/"),),
        )
        self.assertNotIn(
            "IMAGE_CARDINALITY_LIMIT",
            {finding.code for finding in report.violations},
        )
        self.assertIsNone(report.image)
        self.assertIsNone(report.total_accounted_input_bytes)
        self.assertIsNone(report.final_supplied_root_work_bytes)
        self.assert_deny_only(report)

    def test_invalid_cardinality_skips_blob_record_inspection(self):
        class MemberMustNotRun:
            def __getattribute__(self, name):
                raise AssertionError("over-count blob member was inspected")

        member = MemberMustNotRun()
        supplied = (member,) * (MAX_BLOBS + 1)
        report = inspect_runtime_image_host(self.image(blobs=supplied))
        self.assertEqual(
            report.violations,
            (ImageViolation("IMAGE_CARDINALITY_LIMIT", "blobs", "/"),),
        )
        self.assertNotIn(
            "IMAGE_RECORD_TYPE",
            {finding.code for finding in report.violations},
        )
        self.assertIsNone(report.image)
        self.assertIsNone(report.total_accounted_input_bytes)
        self.assertIsNone(report.final_supplied_root_work_bytes)
        self.assert_deny_only(report)

    def test_valid_cardinality_still_runs_separate_blob_record_validation(self):
        supplied = (object(),)
        candidate = self.image(blobs=supplied)
        report = inspect_runtime_image_host(candidate)
        self.assertEqual(
            report.violations,
            (ImageViolation("IMAGE_RECORD_TYPE", "blobs", "/0"),),
        )
        self.assertNotIn(
            "IMAGE_CARDINALITY_LIMIT",
            {finding.code for finding in report.violations},
        )
        self.assertEqual(candidate.blobs, supplied)
        self.assertIsNone(report.image)
        self.assertIsNone(report.total_accounted_input_bytes)
        self.assertIsNone(report.final_supplied_root_work_bytes)
        self.assert_deny_only(report)

    def test_member_byte_limit_and_accounting_are_separate(self):
        baseline = inspect_runtime_image_host(self.image())
        oversized = b"x" * (MAX_BLOB_BYTES + 1)
        supplied = (BlobRecord("", "", oversized),)
        report = inspect_runtime_image_host(self.image(blobs=supplied))
        self.assertEqual(
            report.violations,
            (ImageViolation(
                "IMAGE_ITEM_BYTE_LIMIT", "blobs", "/0/canonical_json"
            ),),
        )
        self.assertNotIn(
            "IMAGE_CARDINALITY_LIMIT",
            {finding.code for finding in report.violations},
        )
        self.assertEqual(
            report.total_accounted_input_bytes,
            baseline.total_accounted_input_bytes + len(oversized),
        )
        self.assertEqual(
            report.final_supplied_root_work_bytes,
            baseline.final_supplied_root_work_bytes,
        )
        self.assertIsNone(report.image)
        self.assert_deny_only(report)

    def test_maximum_with_one_oversized_member_only_reports_member_limit(self):
        baseline = inspect_runtime_image_host(self.image())
        empty = BlobRecord("", "", b"")
        oversized = b"x" * (MAX_BLOB_BYTES + 1)
        supplied = (empty,) * (MAX_BLOBS - 1) + (
            BlobRecord("", "", oversized),
        )
        report = inspect_runtime_image_host(self.image(blobs=supplied))
        self.assertEqual(
            report.violations,
            (ImageViolation(
                "IMAGE_ITEM_BYTE_LIMIT",
                "blobs",
                f"/{MAX_BLOBS - 1}/canonical_json",
            ),),
        )
        self.assertEqual(
            report.total_accounted_input_bytes,
            baseline.total_accounted_input_bytes + len(oversized),
        )
        self.assertEqual(
            report.final_supplied_root_work_bytes,
            baseline.final_supplied_root_work_bytes,
        )
        self.assertIsNone(report.image)
        self.assert_deny_only(report)

    def test_maximum_plus_one_with_oversized_member_skips_member_accounting(self):
        empty = BlobRecord("", "", b"")
        oversized = BlobRecord("", "", b"x" * (MAX_BLOB_BYTES + 1))
        supplied = (empty,) * MAX_BLOBS + (oversized,)
        report = inspect_runtime_image_host(self.image(blobs=supplied))
        self.assertEqual(
            report.violations,
            (ImageViolation("IMAGE_CARDINALITY_LIMIT", "blobs", "/"),),
        )
        self.assertNotIn(
            "IMAGE_ITEM_BYTE_LIMIT",
            {finding.code for finding in report.violations},
        )
        self.assertIsNone(report.image)
        self.assertIsNone(report.total_accounted_input_bytes)
        self.assertIsNone(report.final_supplied_root_work_bytes)
        self.assert_deny_only(report)

    def test_transport_table_member_and_sibling_limits_are_independent(self):
        blob_spec = next(
            spec for spec in image_module._TABLE_SPECS if spec.name == "blobs"
        )
        self.assertEqual(blob_spec.max_rows, MAX_BLOBS)
        self.assertNotEqual(MAX_BLOB_BYTES, MAX_BLOBS)

        blob_over = inspect_runtime_image_host(self.image(
            blobs=(BlobRecord("", "", b""),) * (MAX_BLOBS + 1),
            events=(),
        ))
        self.assertEqual(
            blob_over.violations,
            (ImageViolation("IMAGE_CARDINALITY_LIMIT", "blobs", "/"),),
        )
        self.assert_deny_only(blob_over)

        snapshots = list(self.image().table_snapshots)
        blob_table_index = TABLE_NAMES.index("blobs")
        snapshots[blob_table_index] = TableSnapshot(
            "blobs", (("", "", ""),) * (MAX_BLOBS + 1)
        )
        table_over = inspect_runtime_image_host(self.image(
            blobs=(),
            table_snapshots=tuple(snapshots),
        ))
        self.assertEqual(
            table_over.violations,
            (ImageViolation(
                "TABLE_ROW_LIMIT",
                "table_snapshots",
                f"/{blob_table_index}/rows",
            ),),
        )
        self.assertNotIn(
            "IMAGE_CARDINALITY_LIMIT",
            {finding.code for finding in table_over.violations},
        )
        self.assert_deny_only(table_over)

        event_over = inspect_runtime_image_host(self.image(
            blobs=(),
            events=(b"",) * (MAX_EVENTS + 1),
        ))
        self.assertEqual(
            event_over.violations,
            (ImageViolation("IMAGE_CARDINALITY_LIMIT", "events", "/"),),
        )
        self.assert_deny_only(event_over)


if __name__ == "__main__":
    unittest.main()
