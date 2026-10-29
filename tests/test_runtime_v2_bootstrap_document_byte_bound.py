"""Boundary evidence for every runtime-v2 bootstrap-document byte branch."""
from __future__ import annotations

import unittest

from src.edgelab.runtime_v2_image import (
    MAX_BOOTSTRAP_DOCUMENT_BYTES,
    MAX_CHECKPOINT_COPIES,
    RuntimeImage,
    SchemaDocumentRecord,
    TABLE_NAMES,
    TableSnapshot,
    inspect_runtime_image_host,
)


FIELD_BRANCHES = (
    "verifier_dependency_closure",
    "manifest",
    "attachment",
)
COLLECTION_BRANCHES = (
    "checkpoint_copies",
    "selector_history",
)
ALL_BRANCHES = FIELD_BRANCHES + COLLECTION_BRANCHES


class RuntimeV2BootstrapDocumentByteBoundTests(unittest.TestCase):
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

    @staticmethod
    def supplied(branch: str, body: object) -> object:
        if branch == "checkpoint_copies":
            return (body,)
        if branch == "selector_history":
            return (body, b"peer")
        return body

    @staticmethod
    def retained(report, branch: str):
        value = getattr(report.image, branch)
        return value[0] if branch in COLLECTION_BRANCHES else value

    @staticmethod
    def findings(report):
        return [
            (finding.code, finding.artifact, finding.coordinate)
            for finding in report.violations
        ]

    def assert_deny_only(self, report) -> None:
        self.assertEqual(report.authorizing_use, "DENY")
        with self.assertRaises(TypeError):
            bool(report)

    def test_exact_constant_is_the_inclusive_one_mebibyte_maximum(self):
        self.assertEqual(MAX_BOOTSTRAP_DOCUMENT_BYTES, 1_048_576)

    def test_all_five_branch_boundary_matrices_retain_or_withhold_exactly(self):
        maximum = MAX_BOOTSTRAP_DOCUMENT_BYTES
        for branch in ALL_BRANCHES:
            coordinate = "/0" if branch in COLLECTION_BRANCHES else "/"
            for size in (maximum - 1, maximum, maximum + 1):
                with self.subTest(branch=branch, size=size):
                    body = b"x" * size
                    report = inspect_runtime_image_host(self.image(
                        **{branch: self.supplied(branch, body)}
                    ))
                    self.assert_deny_only(report)
                    if size <= maximum:
                        self.assertEqual(report.violations, ())
                        self.assertIsNotNone(report.image)
                        self.assertIs(self.retained(report, branch), body)
                        self.assertEqual(self.retained(report, branch), body)
                        self.assertEqual(len(self.retained(report, branch)), size)
                    else:
                        self.assertEqual(
                            self.findings(report),
                            [("IMAGE_ITEM_BYTE_LIMIT", branch, coordinate)],
                        )
                        self.assertIsNone(report.image)
                        self.assertIsNotNone(report.total_accounted_input_bytes)

    def test_nonzero_collection_index_is_reported_without_reordering(self):
        maximum = MAX_BOOTSTRAP_DOCUMENT_BYTES
        oversized = b"x" * (maximum + 1)
        cases = {
            "checkpoint_copies": (b"first", oversized),
            "selector_history": (b"first", oversized),
        }
        for branch, supplied in cases.items():
            with self.subTest(branch=branch):
                report = inspect_runtime_image_host(self.image(
                    **{branch: supplied}
                ))
                self.assertEqual(
                    self.findings(report),
                    [("IMAGE_ITEM_BYTE_LIMIT", branch, "/1")],
                )
                self.assertIsNone(report.image)
                self.assert_deny_only(report)

    def test_field_type_guards_precede_length_and_accounting(self):
        class LengthMustNotRun:
            def __len__(self):
                raise AssertionError("non-bytes field length was inspected")

        for branch in FIELD_BRANCHES:
            with self.subTest(branch=branch):
                report = inspect_runtime_image_host(self.image(
                    **{branch: LengthMustNotRun()}
                ))
                self.assertEqual(
                    self.findings(report),
                    [("IMAGE_FIELD_TYPE", branch, "/")],
                )
                self.assertIsNone(report.image)
                self.assertIsNone(report.total_accounted_input_bytes)
                self.assert_deny_only(report)

    def test_collection_type_and_member_type_guards_precede_length(self):
        class LengthMustNotRun:
            def __len__(self):
                raise AssertionError("invalid collection value length was inspected")

        for branch in COLLECTION_BRANCHES:
            with self.subTest(branch=branch, invalid="collection"):
                report = inspect_runtime_image_host(self.image(
                    **{branch: LengthMustNotRun()}
                ))
                self.assertEqual(
                    self.findings(report),
                    [("IMAGE_FIELD_TYPE", branch, "/")],
                )
                self.assertIsNone(report.image)
                self.assertIsNone(report.total_accounted_input_bytes)
                self.assert_deny_only(report)

            supplied = (
                (LengthMustNotRun(),)
                if branch == "checkpoint_copies"
                else (LengthMustNotRun(), b"peer")
            )
            with self.subTest(branch=branch, invalid="member"):
                report = inspect_runtime_image_host(self.image(
                    **{branch: supplied}
                ))
                self.assertEqual(
                    self.findings(report),
                    [("IMAGE_RECORD_TYPE", branch, "/0")],
                )
                self.assertIsNone(report.image)
                self.assertIsNone(report.total_accounted_input_bytes)
                self.assert_deny_only(report)

    def test_invalid_collection_cardinality_skips_member_size_inspection(self):
        oversized = b"x" * (MAX_BOOTSTRAP_DOCUMENT_BYTES + 1)
        cases = {
            "checkpoint_copies": (
                (oversized,) + ((b"",) * MAX_CHECKPOINT_COPIES)
            ),
            "selector_history": (oversized,),
        }
        for branch, supplied in cases.items():
            with self.subTest(branch=branch):
                report = inspect_runtime_image_host(self.image(
                    **{branch: supplied}
                ))
                self.assertEqual(
                    self.findings(report),
                    [("IMAGE_CARDINALITY_LIMIT", branch, "/")],
                )
                self.assertNotIn(
                    "IMAGE_ITEM_BYTE_LIMIT",
                    {finding.code for finding in report.violations},
                )
                self.assertIsNone(report.image)
                self.assertIsNone(report.total_accounted_input_bytes)
                self.assert_deny_only(report)

    def test_equal_valued_siblings_are_independent_per_subject_limits(self):
        maximum = MAX_BOOTSTRAP_DOCUMENT_BYTES
        body = b"x" * maximum
        at_maximum = {
            "verifier_dependency_closure": body,
            "manifest": body,
            "attachment": body,
            "checkpoint_copies": (body,),
            "selector_history": (body, body),
        }
        report = inspect_runtime_image_host(self.image(**at_maximum))
        self.assertEqual(report.violations, ())
        self.assertIsNotNone(report.image)
        for branch in FIELD_BRANCHES:
            self.assertIs(getattr(report.image, branch), body)
        for branch in COLLECTION_BRANCHES:
            for retained in getattr(report.image, branch):
                self.assertIs(retained, body)
        self.assert_deny_only(report)

        oversized = b"x" * (maximum + 1)
        for branch in ALL_BRANCHES:
            with self.subTest(oversized_branch=branch):
                supplied = dict(at_maximum)
                supplied[branch] = self.supplied(branch, oversized)
                report = inspect_runtime_image_host(self.image(**supplied))
                coordinate = "/0" if branch in COLLECTION_BRANCHES else "/"
                self.assertEqual(
                    self.findings(report),
                    [("IMAGE_ITEM_BYTE_LIMIT", branch, coordinate)],
                )
                self.assertIsNone(report.image)
                self.assert_deny_only(report)


if __name__ == "__main__":
    unittest.main()
