"""Adversarial evidence for the deny-only Discovery V5 events binding."""
from __future__ import annotations

import unittest

import src.edgelab.runtime_v2_image as host
import tools.check_runtime_v2_release_readiness as checker


class _TupleSubclass(tuple):
    pass


class RuntimeV2TopLevelEventCardinalityDiscoveryTests(unittest.TestCase):
    MAXIMUM = 100_000

    @staticmethod
    def image(events: object) -> host.RuntimeImage:
        return host.RuntimeImage(
            storage_descriptor=b"{}",
            verifier_dependency_closure=b"{}",
            manifest=b"{}",
            attachment=b"{}",
            schema_registry=b"{}",
            schema_documents=tuple(
                host.SchemaDocumentRecord(
                    f"schema-{index}", f"digest-{index}", b"{}"
                )
                for index in range(9)
            ),
            blobs=(),
            events=events,
            table_snapshots=tuple(
                host.TableSnapshot(name, ()) for name in host.TABLE_NAMES
            ),
            checkpoint_copies=(),
            selector_history=(b"{}", b"{}"),
            legacy_evidence=None,
        )

    @staticmethod
    def derive(source_bytes):
        ordinary = checker._source_bound_inventory(source_bytes)
        v2 = checker._source_bound_binding_inventory(source_bytes, ordinary)
        v3 = checker._source_bound_cardinality_binding_inventory(
            source_bytes,
            sorted(ordinary + v2, key=lambda item: (item["path"], item["site_id"])),
        )
        v4 = checker._source_bound_table_row_cap_binding_inventory(
            source_bytes,
            sorted(
                ordinary + v2 + v3,
                key=lambda item: (item["path"], item["site_id"]),
            ),
        )
        predecessor = sorted(
            ordinary + v2 + v3 + v4,
            key=lambda item: (item["path"], item["site_id"]),
        )
        return checker._source_bound_top_level_cardinality_maximum_inventory(
            source_bytes, predecessor
        )

    def test_v5_record_binds_only_the_host_preflight_events_maximum(self):
        _, _, source_bytes = checker._source_inventory(checker.ROOT)
        records = self.derive(source_bytes)
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(
            record["site_id"],
            "0788e261996efdb32e9fdca233db8d5e809fdb533da89d835357ab1f2c9f1fa4",
        )
        self.assertEqual(
            record["kind"], "BOUND_TOP_LEVEL_CARDINALITY_MAXIMUM_BINDING"
        )
        self.assertEqual(record["binding"], "cardinality_maxima:events")
        self.assertEqual(record["maximum"], self.MAXIMUM)
        self.assertEqual(record["unit"], "ITEMS")
        self.assertEqual(record["subject_binding"], "captured['events']")
        self.assertEqual(
            record["selection_semantics"],
            "HOST_PREFLIGHT_TOP_LEVEL_EVENTS_MAXIMUM_ONLY",
        )
        self.assertEqual(record["classification"], "UNCLASSIFIED")
        self.assertEqual(
            record["definition_site_id"],
            "2dcbb43b767e41adb2cb59c64d6b3bfab8e9dbb8e583eebc5801d93668b7b43f",
        )
        self.assertEqual(
            record["branch_cardinality_site_id"],
            "fd2933fa143fb9fb2d6a9d6f375f1f6b1e0aae26e447e9fea4ad3b9d7c2b92a1",
        )
        self.assertIn("INITIAL_REDUCER_EVENT_CARDINALITY", record["excluded_semantics"])
        self.assertIn("TRANSITION_COLLECTION_CARDINALITY", record["excluded_semantics"])
        self.assertIn("EVENTS_TABLE_ROW_CARDINALITY", record["excluded_semantics"])

    def test_inclusive_boundaries_are_exact_and_deny_only(self):
        for count, rejected in (
            (0, False),
            (99_999, False),
            (100_000, False),
            (100_001, True),
        ):
            with self.subTest(count=count):
                report = host.inspect_runtime_image_host(
                    self.image((b"",) * count)
                )
                findings = tuple(
                    item for item in report.violations
                    if item.artifact == "events"
                )
                self.assertEqual(
                    any(item.code == "IMAGE_CARDINALITY_LIMIT" for item in findings),
                    rejected,
                )
                self.assertEqual(report.authorizing_use, "DENY")
                self.assertEqual(report.image is None, rejected)
                with self.assertRaises(TypeError):
                    bool(report)

    def test_exact_tuple_guard_rejects_subclass_before_cardinality(self):
        report = host.inspect_runtime_image_host(self.image(_TupleSubclass()))
        self.assertIn(
            host.ImageViolation("IMAGE_FIELD_TYPE", "events", "/"),
            report.violations,
        )
        self.assertNotIn(
            host.ImageViolation("IMAGE_CARDINALITY_LIMIT", "events", "/"),
            report.violations,
        )
        self.assertIsNone(report.image)
        self.assertIsNone(report.total_accounted_input_bytes)

    def test_at_limit_members_are_inspected_but_plus_one_skips_members(self):
        at_limit = (b"",) * (self.MAXIMUM - 1) + (object(),)
        report = host.inspect_runtime_image_host(self.image(at_limit))
        self.assertIn(
            host.ImageViolation(
                "IMAGE_RECORD_TYPE", "events", f"/{self.MAXIMUM - 1}"
            ),
            report.violations,
        )
        self.assertNotIn(
            host.ImageViolation("IMAGE_CARDINALITY_LIMIT", "events", "/"),
            report.violations,
        )
        self.assertIsNone(report.total_accounted_input_bytes)
        self.assertIsNone(report.image)

        plus_one = host.inspect_runtime_image_host(
            self.image((object(),) * (self.MAXIMUM + 1))
        )
        self.assertIn(
            host.ImageViolation("IMAGE_CARDINALITY_LIMIT", "events", "/"),
            plus_one.violations,
        )
        self.assertFalse(any(
            item.code == "IMAGE_RECORD_TYPE" and item.artifact == "events"
            for item in plus_one.violations
        ))
        self.assertIsNone(plus_one.total_accounted_input_bytes)
        self.assertIsNone(plus_one.image)

    def test_events_table_row_cap_is_an_independent_positional_constraint(self):
        report = host.inspect_runtime_image_host(self.image(()))
        self.assertFalse(any(
            item.code == "IMAGE_CARDINALITY_LIMIT" and item.artifact == "events"
            for item in report.violations
        ))
        self.assertFalse(any(item.code == "TABLE_ROW_LIMIT" for item in report.violations))
        self.assertNotEqual(
            "0788e261996efdb32e9fdca233db8d5e809fdb533da89d835357ab1f2c9f1fa4",
            "9138c0111059d3e29b19bcacd451fa8cedf572d56ea6f4d04fdbc405cf8b00ed",
        )

    def test_semantic_mutations_fail_closed(self):
        _, _, baseline = checker._source_inventory(checker.ROOT)
        path = "src/edgelab/runtime_v2_image.py"
        attacks = {
            "same-valued-expression": (b"MAX_EVENTS = 100_000", b"MAX_EVENTS = 50_000 + 50_000"),
            "literal-substitution": (
                b'("events", 0, MAX_EVENTS),', b'("events", 0, 100_000),'
            ),
            "import-alias": (
                b"from typing import TypeAlias\n", b"from typing import TypeAlias\nimport builtins as _builtins\n"
            ),
            "extra-load": (
                b"MAX_EVENTS = 100_000\n", b"MAX_EVENTS = 100_000\n_MAX_EVENTS_COPY = MAX_EVENTS\n"
            ),
            "local-shadow": (
                b'    cardinalities = (\n', b'    MAX_EVENTS = 100_000\n    cardinalities = (\n'
            ),
            "subject-substitution": (
                b'("events", captured["events"]),',
                b'("events", captured["checkpoint_copies"]),',
            ),
            "nonzero-minimum": (
                b'("events", 0, MAX_EVENTS),', b'("events", 1, MAX_EVENTS),'
            ),
            "comparator-bypass": (
                b"        valid = minimum <= len(value) <= maximum\n",
                b"        valid = minimum <= len(value) < maximum\n",
            ),
            "diagnostic-bypass": (
                b'            findings.add("IMAGE_CARDINALITY_LIMIT", name, "/")\n',
                b'            findings.add("IMAGE_CARDINALITY_LIMIT_IGNORED", name, "/")\n',
            ),
            "accounting-bypass": (
                b'            findings.add("IMAGE_CARDINALITY_LIMIT", name, "/")\n            accounting_complete = False\n',
                b'            findings.add("IMAGE_CARDINALITY_LIMIT", name, "/")\n            accounting_complete = True\n',
            ),
            "continue-bypass": (
                b"            cardinality_valid[name] = False\n            continue\n",
                b"            cardinality_valid[name] = False\n            pass\n",
            ),
            "member-gate-bypass": (
                b"        if not cardinality_valid.get(name, False):\n            continue\n        for index, value in enumerate(values):\n",
                b"        if not cardinality_valid.get(name, False):\n            pass\n        for index, value in enumerate(values):\n",
            ),
            "sanitized-release": (
                b"    if not violations:\n        sanitized_image = RuntimeImage(\n",
                b"    if violations:\n        sanitized_image = RuntimeImage(\n",
            ),
        }
        for name, (old, new) in attacks.items():
            with self.subTest(attack=name):
                hostile = dict(baseline)
                self.assertEqual(hostile[path].count(old), 1)
                hostile[path] = hostile[path].replace(old, new)
                with self.assertRaises(checker.ReadinessError):
                    self.derive(hostile)

    def test_raw_definition_predecessor_occurrence_is_exact(self):
        _, _, source_bytes = checker._source_inventory(checker.ROOT)
        ordinary = checker._source_bound_inventory(source_bytes)
        v2 = checker._source_bound_binding_inventory(source_bytes, ordinary)
        v3 = checker._source_bound_cardinality_binding_inventory(
            source_bytes,
            sorted(ordinary + v2, key=lambda item: (item["path"], item["site_id"])),
        )
        v4 = checker._source_bound_table_row_cap_binding_inventory(
            source_bytes,
            sorted(
                ordinary + v2 + v3,
                key=lambda item: (item["path"], item["site_id"]),
            ),
        )
        predecessors = [dict(item) for item in ordinary + v2 + v3 + v4]
        target = next(
            item for item in predecessors
            if item["site_id"]
            == "2dcbb43b767e41adb2cb59c64d6b3bfab8e9dbb8e583eebc5801d93668b7b43f"
        )
        self.assertEqual(target["occurrence"], 1)
        target["occurrence"] = 2
        with self.assertRaises(checker.ReadinessError) as caught:
            checker._source_bound_top_level_cardinality_maximum_inventory(
                source_bytes,
                sorted(
                    predecessors,
                    key=lambda item: (item["path"], item["site_id"]),
                ),
            )
        self.assertEqual(
            caught.exception.code,
            "RESOURCE_TOP_LEVEL_CARDINALITY_DEFINITION_SITE",
        )


if __name__ == "__main__":
    unittest.main()
