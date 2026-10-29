import ast
import dataclasses
import json
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

from src.edgelab.runtime_v2_codec import canonical_json
import src.edgelab.runtime_v2_image as image_module
from src.edgelab.runtime_v2_image import (
    BlobRecord,
    INT64_MAX,
    INT64_MIN,
    MAX_BLOB_BYTES,
    MAX_EVENT_BYTES,
    MAX_EVENTS,
    MAX_TOTAL_ACCOUNTED_INPUT_BYTES,
    MAX_TOTAL_ROOT_WORK_BYTES,
    RuntimeImage,
    SchemaDocumentRecord,
    TABLE_NAMES,
    TableSnapshot,
    inspect_runtime_image_host,
)


ROOT = Path(__file__).resolve().parents[1]


class RuntimeV2ImageTests(unittest.TestCase):
    def schema_documents(self):
        return tuple(
            SchemaDocumentRecord(f"schema-{index}", f"digest-{index}", b"{}")
            for index in range(9)
        )

    def snapshots(self):
        return tuple(TableSnapshot(name, ()) for name in TABLE_NAMES)

    def image(self, **changes):
        values = {
            "storage_descriptor": b"{}",
            "verifier_dependency_closure": b"{}",
            "manifest": b"{}",
            "attachment": b"{}",
            "schema_registry": b"{}",
            "schema_documents": self.schema_documents(),
            "blobs": (),
            "events": (),
            "table_snapshots": self.snapshots(),
            "checkpoint_copies": (),
            "selector_history": (b"{}", b"{}"),
            "legacy_evidence": None,
        }
        values.update(changes)
        return RuntimeImage(**values)

    def codes(self, report):
        return {finding.code for finding in report.violations}

    def row(self, table, *, key="key"):
        spec = next(item for item in image_module._TABLE_SPECS if item.name == table)
        cells = []
        for index, column in enumerate(spec.columns):
            if column.nullable:
                cells.append(None)
            elif column.storage_type == "TEXT":
                cells.append(key if index in spec.primary_key else "value")
            else:
                cells.append(0)
        return tuple(cells)

    def with_rows(self, image, table, rows):
        snapshots = list(image.table_snapshots)
        index = TABLE_NAMES.index(table)
        snapshots[index] = TableSnapshot(table, tuple(rows))
        return replace(image, table_snapshots=tuple(snapshots))

    def test_exact_transport_is_frozen_slotted_and_has_no_defaults(self):
        for record_type in (SchemaDocumentRecord, BlobRecord, TableSnapshot, RuntimeImage):
            with self.subTest(record_type=record_type.__name__):
                self.assertTrue(hasattr(record_type, "__slots__"))
                for item in dataclasses.fields(record_type):
                    self.assertIs(item.default, dataclasses.MISSING)
                    self.assertIs(item.default_factory, dataclasses.MISSING)
        candidate = self.image()
        with self.assertRaises(FrozenInstanceError):
            candidate.manifest = b"changed"

    def test_minimal_host_image_passes_only_private_preflight(self):
        candidate = self.image()
        report = inspect_runtime_image_host(candidate)
        self.assertEqual(report.violations, ())
        self.assertEqual(report.image, candidate)
        self.assertIsNot(report.image, candidate)
        self.assertGreater(report.total_accounted_input_bytes, 0)
        self.assertGreater(report.final_supplied_root_work_bytes, 0)
        self.assertEqual(report.authorizing_use, "DENY")
        with self.assertRaises(TypeError):
            bool(report)

        original_document = candidate.schema_documents[0]
        object.__setattr__(candidate, "events", (bytearray(b"changed"),))
        object.__setattr__(original_document, "schema_id", "changed")
        self.assertEqual(report.image.events, ())
        self.assertEqual(report.image.schema_documents[0].schema_id, "schema-0")

    def test_exact_type_instances_with_missing_slots_deny_without_raising(self):
        report = inspect_runtime_image_host(object.__new__(RuntimeImage))
        self.assertIn("IMAGE_FIELD_MISSING", self.codes(report))
        self.assertIsNone(report.image)

        missing_document = object.__new__(SchemaDocumentRecord)
        documents = list(self.schema_documents())
        documents[0] = missing_document
        report = inspect_runtime_image_host(self.image(
            schema_documents=tuple(documents),
        ))
        self.assertIn("IMAGE_RECORD_FIELD_MISSING", self.codes(report))
        self.assertIsNone(report.image)

        missing_blob = object.__new__(BlobRecord)
        report = inspect_runtime_image_host(self.image(blobs=(missing_blob,)))
        self.assertIn("IMAGE_RECORD_FIELD_MISSING", self.codes(report))
        self.assertIsNone(report.image)

        missing_snapshot = object.__new__(TableSnapshot)
        snapshots = list(self.snapshots())
        snapshots[0] = missing_snapshot
        report = inspect_runtime_image_host(self.image(
            table_snapshots=tuple(snapshots),
        ))
        self.assertIn("TABLE_SNAPSHOT_FIELD_MISSING", self.codes(report))
        self.assertIsNone(report.image)

    def test_top_level_exact_type_and_field_types(self):
        class RuntimeImageSubclass(RuntimeImage):
            pass

        base = self.image()
        subclass = RuntimeImageSubclass(*(
            getattr(base, item.name) for item in dataclasses.fields(RuntimeImage)
        ))
        report = inspect_runtime_image_host(subclass)
        self.assertEqual(self.codes(report), {"IMAGE_TYPE"})
        cases = {
            "storage_descriptor": bytearray(b"{}"),
            "verifier_dependency_closure": memoryview(b"{}"),
            "manifest": None,
            "schema_documents": [],
            "blobs": [],
            "events": [],
            "table_snapshots": [],
            "checkpoint_copies": [],
            "selector_history": [],
        }
        for field_name, value in cases.items():
            with self.subTest(field=field_name):
                report = inspect_runtime_image_host(replace(base, **{field_name: value}))
                self.assertIn("IMAGE_FIELD_TYPE", self.codes(report))
                self.assertIsNone(report.image)
        report = inspect_runtime_image_host(replace(base, legacy_evidence=()))
        self.assertIn("IMAGE_LEGACY_EVIDENCE", self.codes(report))

    def test_nested_records_require_exact_types_and_fields(self):
        class SchemaSubclass(SchemaDocumentRecord):
            pass

        docs = list(self.schema_documents())
        docs[0] = SchemaSubclass("schema", "digest", b"{}")
        report = inspect_runtime_image_host(self.image(schema_documents=tuple(docs)))
        self.assertIn("IMAGE_RECORD_TYPE", self.codes(report))

        docs = list(self.schema_documents())
        docs[0] = SchemaDocumentRecord(1, "digest", b"{}")
        report = inspect_runtime_image_host(self.image(schema_documents=tuple(docs)))
        self.assertIn("IMAGE_RECORD_FIELD_TYPE", self.codes(report))

        report = inspect_runtime_image_host(self.image(blobs=(BlobRecord("x", "s", bytearray()),)))
        self.assertIn("IMAGE_RECORD_FIELD_TYPE", self.codes(report))

    def test_cardinality_and_item_byte_limits(self):
        base = self.image()
        report = inspect_runtime_image_host(replace(base, selector_history=(b"{}",)))
        self.assertIn("IMAGE_CARDINALITY_LIMIT", self.codes(report))
        report = inspect_runtime_image_host(replace(base, events=(b"",) * (MAX_EVENTS + 1)))
        self.assertIn("IMAGE_CARDINALITY_LIMIT", self.codes(report))

        report = inspect_runtime_image_host(replace(base, events=(b"x" * MAX_EVENT_BYTES,)))
        self.assertNotIn("IMAGE_ITEM_BYTE_LIMIT", self.codes(report))
        report = inspect_runtime_image_host(replace(base, events=(b"x" * (MAX_EVENT_BYTES + 1),)))
        self.assertIn("IMAGE_ITEM_BYTE_LIMIT", self.codes(report))

        report = inspect_runtime_image_host(self.image(blobs=(BlobRecord("", "", b"x" * MAX_BLOB_BYTES),)))
        self.assertNotIn("IMAGE_ITEM_BYTE_LIMIT", self.codes(report))
        report = inspect_runtime_image_host(self.image(blobs=(BlobRecord("", "", b"x" * (MAX_BLOB_BYTES + 1)),)))
        self.assertIn("IMAGE_ITEM_BYTE_LIMIT", self.codes(report))

    def test_table_inventory_types_width_cells_and_int64(self):
        base = self.image()
        reordered = list(base.table_snapshots)
        reordered[0], reordered[1] = reordered[1], reordered[0]
        report = inspect_runtime_image_host(replace(base, table_snapshots=tuple(reordered)))
        self.assertIn("TABLE_INVENTORY", self.codes(report))

        valid = self.with_rows(base, "tasks", (self.row("tasks"),))
        self.assertEqual(inspect_runtime_image_host(valid).violations, ())
        index = TABLE_NAMES.index("tasks")
        snapshots = list(base.table_snapshots)
        snapshots[index] = TableSnapshot("tasks", (["not-a-tuple"],))
        self.assertIn(
            "TABLE_ROW_TYPE",
            self.codes(inspect_runtime_image_host(replace(base, table_snapshots=tuple(snapshots)))),
        )

        row = self.row("tasks")
        for altered, code in (
            (row[:-1], "TABLE_ROW_WIDTH"),
            ((True,) + row[1:], "TABLE_CELL_TYPE"),
            ((None,) + row[1:], "TABLE_CELL_NULLABILITY"),
            (("key", INT64_MAX + 1) + row[2:], "TABLE_CELL_INT64"),
            (("key", INT64_MIN - 1) + row[2:], "TABLE_CELL_INT64"),
        ):
            with self.subTest(code=code, altered=altered[:2]):
                report = inspect_runtime_image_host(self.with_rows(base, "tasks", (altered,)))
                self.assertIn(code, self.codes(report))

        huge_integer = ("key", 10 ** 10_000) + row[2:]
        report = inspect_runtime_image_host(
            self.with_rows(base, "tasks", (huge_integer,))
        )
        self.assertIn("TABLE_CELL_INT64", self.codes(report))

    def test_primary_key_duplicates_and_binary_row_order_deny(self):
        base = self.image()
        duplicate = self.row("tasks", key="same")
        report = inspect_runtime_image_host(self.with_rows(base, "tasks", (duplicate, duplicate)))
        self.assertIn("TABLE_PRIMARY_KEY_DUPLICATE", self.codes(report))
        self.assertIn("TABLE_ROW_ORDER", self.codes(report))

        descending = (self.row("tasks", key="b"), self.row("tasks", key="a"))
        report = inspect_runtime_image_host(self.with_rows(base, "tasks", descending))
        self.assertIn("TABLE_ROW_ORDER", self.codes(report))

        first = list(self.row("snapshots", key="id-b"))
        second = list(self.row("snapshots", key="id-a"))
        first[1:3] = ["CHECKPOINT", 0]
        second[1:3] = ["CHECKPOINT", 1]
        report = inspect_runtime_image_host(
            self.with_rows(base, "snapshots", (tuple(first), tuple(second)))
        )
        self.assertNotIn("TABLE_ROW_ORDER", self.codes(report))

    def test_snapshot_size_counter_matches_canonical_codec(self):
        values = (
            None,
            INT64_MIN,
            INT64_MAX,
            "plain",
            "quote\"slash\\controls\b\f\n\r\t\u0001",
            "café \U0001f680",
        )
        snapshot = TableSnapshot("table-\U0001f680", (values, ()))
        expected = len(canonical_json({
            "table": snapshot.table,
            "rows": [list(row) for row in snapshot.rows],
        }))
        self.assertEqual(image_module._canonical_snapshot_size(snapshot), expected)

        candidate = self.image()
        report = inspect_runtime_image_host(candidate)
        expected_root_work = sum(
            len(image_module._TABLE_ROOT_PREFIX)
            + len(snapshot.table.encode("utf-8"))
            + 1
            + len(canonical_json([list(row) for row in snapshot.rows]))
            for snapshot in candidate.table_snapshots
        )
        self.assertEqual(report.final_supplied_root_work_bytes, expected_root_work)
        self.assertLessEqual(expected_root_work, MAX_TOTAL_ROOT_WORK_BYTES)

    def test_unpaired_surrogate_denies_without_guessing_accounting(self):
        row = list(self.row("tasks"))
        row[0] = "bad\ud800"
        report = inspect_runtime_image_host(self.with_rows(self.image(), "tasks", (tuple(row),)))
        self.assertIn("TABLE_CELL_UNICODE", self.codes(report))
        self.assertIsNone(report.total_accounted_input_bytes)
        self.assertIsNone(report.final_supplied_root_work_bytes)

    def test_total_accounting_boundary_and_plus_one_without_gigabyte_allocation(self):
        base_records = tuple(BlobRecord("", "", b"") for _ in range(64))
        baseline = inspect_runtime_image_host(self.image(blobs=base_records))
        self.assertEqual(baseline.violations, ())
        fixed = baseline.total_accounted_input_bytes
        self.assertIsNotNone(fixed)
        remaining = MAX_TOTAL_ACCOUNTED_INPUT_BYTES - fixed
        full_count, tail_size = divmod(remaining, MAX_BLOB_BYTES)
        self.assertLessEqual(full_count, len(base_records))
        large = b"x" * MAX_BLOB_BYTES
        records = [BlobRecord("", "", large)] * full_count
        if tail_size:
            records.append(BlobRecord("", "", b"y" * tail_size))
        records.extend(BlobRecord("", "", b"") for _ in range(64 - len(records)))
        at_limit = inspect_runtime_image_host(self.image(blobs=tuple(records)))
        self.assertEqual(at_limit.total_accounted_input_bytes, MAX_TOTAL_ACCOUNTED_INPUT_BYTES)
        self.assertNotIn("TOTAL_ACCOUNTED_INPUT_LIMIT", self.codes(at_limit))

        records[full_count] = BlobRecord("", "", b"y" * (tail_size + 1))
        over = inspect_runtime_image_host(self.image(blobs=tuple(records)))
        self.assertEqual(over.total_accounted_input_bytes, MAX_TOTAL_ACCOUNTED_INPUT_BYTES + 1)
        self.assertIn("TOTAL_ACCOUNTED_INPUT_LIMIT", self.codes(over))

    def test_findings_are_bounded_unique_and_sorted(self):
        report = inspect_runtime_image_host(self.image(events=(None,) * 200))
        self.assertEqual(len(report.violations), 128)
        self.assertEqual(report.violations, tuple(sorted(set(report.violations))))
        self.assertIn("FINDINGS_TRUNCATED", self.codes(report))

    def test_compiled_table_specs_match_pinned_descriptor(self):
        descriptor = json.loads((ROOT / "schemas" / "m0-3a-runtime-storage.v2.json").read_text())
        projections = {item["table"]: item for item in descriptor["root_projections"]}
        observed = []
        for table in descriptor["tables"]:
            columns = tuple((item[0], item[1], not item[2]) for item in table["columns"])
            primary_key = tuple(
                index for _, index in sorted(
                    (item[3], index) for index, item in enumerate(table["columns"]) if item[3]
                )
            )
            names = [item[0] for item in table["columns"]]
            row_order = tuple(names.index(name) for name in projections[table["name"]]["row_order"])
            observed.append((table["name"], columns, primary_key, row_order))
        compiled = [
            (
                spec.name,
                tuple((column.name, column.storage_type, column.nullable) for column in spec.columns),
                spec.primary_key,
                spec.row_order,
            )
            for spec in image_module._TABLE_SPECS
        ]
        self.assertEqual(compiled, observed)
        self.assertEqual(
            {spec.name: spec.max_rows for spec in image_module._TABLE_SPECS},
            {
                "attempts": 100_000,
                "blobs": 300_000,
                "claims": 100_000,
                "events": 100_000,
                "idempotency": 100_000,
                "legacy_archive": 1,
                "metadata": 1,
                "migrations": 0,
                "remediation_links": 100_000,
                "reviews": 100_000,
                "schema_documents": 9,
                "schema_registry": 1,
                "seals": 1,
                "snapshots": 100_000,
                "tasks": 100_000,
            },
        )

    def test_module_is_no_io_and_public_verifier_remains_disconnected(self):
        path = ROOT / "src" / "edgelab" / "runtime_v2_image.py"
        tree = ast.parse(path.read_text())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        self.assertTrue(imported.isdisjoint({
            "pathlib", "os", "sqlite3", "subprocess", "socket", "time",
            "datetime", "urllib", "requests", "runtime_v2_verifier",
            "transactional_scheduler", "locked_authority", "risk_controls",
        }))
        calls = {
            node.func.id for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        self.assertTrue(calls.isdisjoint({"open", "exec", "eval", "compile"}))
        public_source = (ROOT / "src" / "edgelab" / "runtime_v2_verifier.py").read_text()
        self.assertNotIn("runtime_v2_image", public_source)
        self.assertNotIn("runtime_v2_initial", public_source)
        self.assertNotIn("runtime_v2_closure", public_source)
        self.assertNotIn("runtime_v2_group", public_source)
        self.assertNotIn("runtime_v2_transition", public_source)


if __name__ == "__main__":
    unittest.main()
