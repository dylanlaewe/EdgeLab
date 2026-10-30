"""Boundary evidence for the runtime-v2 checkpoint-copy count maximum."""
from __future__ import annotations

import unittest

from src.edgelab.runtime_v2_image import (
    ImageViolation,
    MAX_BOOTSTRAP_DOCUMENT_BYTES,
    MAX_CHECKPOINT_COPIES,
    RuntimeImage,
    SchemaDocumentRecord,
    TABLE_NAMES,
    TableSnapshot,
    inspect_runtime_image_host,
)


class RuntimeV2CheckpointCopyCardinalityBoundTests(unittest.TestCase):
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

    def test_exact_constant_is_the_inclusive_49999_item_maximum(self):
        self.assertEqual(MAX_CHECKPOINT_COPIES, 49_999)

    def test_zero_maximum_minus_one_and_maximum_are_admitted(self):
        baseline = inspect_runtime_image_host(self.image())
        self.assertEqual(baseline.violations, ())
        for count in (0, MAX_CHECKPOINT_COPIES - 1, MAX_CHECKPOINT_COPIES):
            with self.subTest(count=count):
                supplied = (b"",) * count
                candidate = self.image(checkpoint_copies=supplied)
                report = inspect_runtime_image_host(candidate)
                self.assertEqual(report.violations, ())
                self.assertIsNotNone(report.image)
                self.assertIs(report.image.checkpoint_copies, supplied)
                self.assertEqual(candidate.checkpoint_copies, supplied)
                self.assertEqual(
                    report.total_accounted_input_bytes,
                    baseline.total_accounted_input_bytes,
                )
                self.assertEqual(
                    report.final_supplied_root_work_bytes,
                    baseline.final_supplied_root_work_bytes,
                )
                self.assert_deny_only(report)

    def test_maximum_plus_one_emits_exact_root_finding_and_withholds(self):
        supplied = (b"",) * (MAX_CHECKPOINT_COPIES + 1)
        candidate = self.image(checkpoint_copies=supplied)
        report = inspect_runtime_image_host(candidate)
        self.assertEqual(
            report.violations,
            (ImageViolation(
                "IMAGE_CARDINALITY_LIMIT", "checkpoint_copies", "/"
            ),),
        )
        self.assertEqual(candidate.checkpoint_copies, supplied)
        self.assertIsNone(report.image)
        self.assertIsNone(report.total_accounted_input_bytes)
        self.assertIsNone(report.final_supplied_root_work_bytes)
        self.assert_deny_only(report)

    def test_exact_tuple_guard_precedes_caller_selected_length(self):
        class LengthMustNotRun:
            def __len__(self):
                raise AssertionError("non-tuple checkpoint length was inspected")

        supplied = LengthMustNotRun()
        report = inspect_runtime_image_host(self.image(
            checkpoint_copies=supplied,
        ))
        self.assertEqual(
            report.violations,
            (ImageViolation("IMAGE_FIELD_TYPE", "checkpoint_copies", "/"),),
        )
        self.assertIsNone(report.image)
        self.assertIsNone(report.total_accounted_input_bytes)
        self.assertIsNone(report.final_supplied_root_work_bytes)
        self.assert_deny_only(report)

    def test_tuple_subclass_is_rejected_before_cardinality(self):
        class TupleSubclass(tuple):
            pass

        supplied = TupleSubclass((b"",))
        report = inspect_runtime_image_host(self.image(
            checkpoint_copies=supplied,
        ))
        self.assertEqual(
            report.violations,
            (ImageViolation("IMAGE_FIELD_TYPE", "checkpoint_copies", "/"),),
        )
        self.assertNotIn(
            "IMAGE_CARDINALITY_LIMIT",
            {finding.code for finding in report.violations},
        )
        self.assertIsNone(report.image)
        self.assertIsNone(report.total_accounted_input_bytes)
        self.assertIsNone(report.final_supplied_root_work_bytes)
        self.assert_deny_only(report)

    def test_invalid_cardinality_skips_member_inspection(self):
        class LengthMustNotRun:
            def __len__(self):
                raise AssertionError("over-count checkpoint member was inspected")

        member = LengthMustNotRun()
        supplied = (member,) * (MAX_CHECKPOINT_COPIES + 1)
        report = inspect_runtime_image_host(self.image(
            checkpoint_copies=supplied,
        ))
        self.assertEqual(
            report.violations,
            (ImageViolation(
                "IMAGE_CARDINALITY_LIMIT", "checkpoint_copies", "/"
            ),),
        )
        self.assertNotIn(
            "IMAGE_RECORD_TYPE",
            {finding.code for finding in report.violations},
        )
        self.assertIsNone(report.image)
        self.assertIsNone(report.total_accounted_input_bytes)
        self.assertIsNone(report.final_supplied_root_work_bytes)
        self.assert_deny_only(report)

    def test_member_byte_limit_and_accounting_are_separate(self):
        baseline = inspect_runtime_image_host(self.image())
        oversized = b"x" * (MAX_BOOTSTRAP_DOCUMENT_BYTES + 1)
        supplied = (oversized,)
        report = inspect_runtime_image_host(self.image(
            checkpoint_copies=supplied,
        ))
        self.assertEqual(
            report.violations,
            (ImageViolation(
                "IMAGE_ITEM_BYTE_LIMIT", "checkpoint_copies", "/0"
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
        oversized = b"x" * (MAX_BOOTSTRAP_DOCUMENT_BYTES + 1)
        supplied = (b"",) * (MAX_CHECKPOINT_COPIES - 1) + (oversized,)
        report = inspect_runtime_image_host(self.image(
            checkpoint_copies=supplied,
        ))
        self.assertEqual(
            report.violations,
            (ImageViolation(
                "IMAGE_ITEM_BYTE_LIMIT",
                "checkpoint_copies",
                f"/{MAX_CHECKPOINT_COPIES - 1}",
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
        oversized = b"x" * (MAX_BOOTSTRAP_DOCUMENT_BYTES + 1)
        supplied = (b"",) * MAX_CHECKPOINT_COPIES + (oversized,)
        report = inspect_runtime_image_host(self.image(
            checkpoint_copies=supplied,
        ))
        self.assertEqual(
            report.violations,
            (ImageViolation(
                "IMAGE_CARDINALITY_LIMIT", "checkpoint_copies", "/"
            ),),
        )
        self.assertNotIn(
            "IMAGE_ITEM_BYTE_LIMIT",
            {finding.code for finding in report.violations},
        )
        self.assertIsNone(report.total_accounted_input_bytes)
        self.assertIsNone(report.final_supplied_root_work_bytes)
        self.assertIsNone(report.image)
        self.assert_deny_only(report)

    def test_checkpoint_and_selector_cardinalities_are_independent(self):
        checkpoint_maximum = (b"",) * MAX_CHECKPOINT_COPIES
        valid = inspect_runtime_image_host(self.image(
            checkpoint_copies=checkpoint_maximum,
            selector_history=(b"", b""),
        ))
        self.assertEqual(valid.violations, ())
        self.assertIsNotNone(valid.image)
        self.assert_deny_only(valid)

        checkpoint_over = inspect_runtime_image_host(self.image(
            checkpoint_copies=checkpoint_maximum + (b"",),
            selector_history=(b"", b""),
        ))
        self.assertEqual(
            checkpoint_over.violations,
            (ImageViolation(
                "IMAGE_CARDINALITY_LIMIT", "checkpoint_copies", "/"
            ),),
        )
        self.assert_deny_only(checkpoint_over)

        selector_under = inspect_runtime_image_host(self.image(
            checkpoint_copies=checkpoint_maximum,
            selector_history=(b"",),
        ))
        self.assertEqual(
            selector_under.violations,
            (ImageViolation(
                "IMAGE_CARDINALITY_LIMIT", "selector_history", "/"
            ),),
        )
        self.assert_deny_only(selector_under)


if __name__ == "__main__":
    unittest.main()
