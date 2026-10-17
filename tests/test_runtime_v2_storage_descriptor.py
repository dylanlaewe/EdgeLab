"""Executable structural checks for the frozen format-2 storage descriptor."""
import json
from pathlib import Path
import re
import sqlite3
import tempfile
import unittest

from jsonschema import Draft202012Validator

from src.edgelab.runtime_v2_codec import (
    sqlite_compile_options_digest,
    sqlite_structure_digest,
    storage_schema_digest,
)


ROOT = Path(__file__).resolve().parents[1]
DESCRIPTOR_PATH = ROOT / "schemas" / "m0-3a-runtime-storage.v2.json"
SCHEMA_PATH = ROOT / "schemas" / "m0-3a-runtime-storage-descriptor.v2.schema.json"


class RuntimeV2StorageDescriptorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.descriptor = json.loads(DESCRIPTOR_PATH.read_text())
        cls.schema = json.loads(SCHEMA_PATH.read_text())

    def _build(self, descriptor, database):
        connection = sqlite3.connect(database)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            f"PRAGMA application_id={descriptor['sqlite']['application_id']}"
        )
        connection.execute(
            f"PRAGMA user_version={descriptor['sqlite']['user_version']}"
        )
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        for table in descriptor["tables"]:
            connection.execute(table["sql"])
        for index in descriptor["indexes"]:
            connection.execute(index["sql"])
        return connection

    def _structural_observation(self, connection, descriptor):
        table_names = {table["name"] for table in descriptor["tables"]}
        table_list = [list(row) for row in connection.execute("PRAGMA table_list")]
        tables = []
        for name in sorted(table_names):
            index_list = [
                list(row) for row in connection.execute(f"PRAGMA index_list({name})")
            ]
            tables.append({
                "name": name,
                "table_xinfo": [
                    list(row) for row in connection.execute(
                        f"PRAGMA table_xinfo({name})"
                    )
                ],
                "foreign_key_list": [
                    list(row) for row in connection.execute(
                        f"PRAGMA foreign_key_list({name})"
                    )
                ],
                "index_list": index_list,
                "index_xinfo": [{
                    "name": row[1],
                    "rows": [
                        list(item) for item in connection.execute(
                            f"PRAGMA index_xinfo({row[1]})"
                        )
                    ],
                } for row in index_list],
            })
        return {
            "sqlite_version": sqlite3.sqlite_version,
            "sqlite_source_id": connection.execute(
                "SELECT sqlite_source_id()"
            ).fetchone()[0],
            "pragmas": {
                "application_id": connection.execute(
                    "PRAGMA application_id"
                ).fetchone()[0],
                "user_version": connection.execute(
                    "PRAGMA user_version"
                ).fetchone()[0],
                "encoding": connection.execute("PRAGMA encoding").fetchone()[0],
                "foreign_keys": connection.execute(
                    "PRAGMA foreign_keys"
                ).fetchone()[0],
                "journal_mode": connection.execute(
                    "PRAGMA journal_mode"
                ).fetchone()[0],
                "synchronous": connection.execute(
                    "PRAGMA synchronous"
                ).fetchone()[0],
            },
            "schema_objects": [
                list(row) for row in connection.execute(
                    "SELECT 'main',type,name,tbl_name,sql FROM sqlite_schema "
                    "WHERE name NOT LIKE 'sqlite_stat%' UNION ALL "
                    "SELECT 'temp',type,name,tbl_name,sql FROM sqlite_temp_schema "
                    "WHERE name NOT LIKE 'sqlite_stat%' ORDER BY 1,2,3"
                )
            ],
            "table_list": table_list,
            "tables": tables,
        }

    def test_descriptor_schema_and_identity_are_closed(self):
        Draft202012Validator.check_schema(self.schema)
        Draft202012Validator(self.schema).validate(self.descriptor)
        self.assertEqual(self.descriptor["anchor_status"], "UNANCHORED")
        self.assertEqual(self.descriptor["currentness_status"], "UNKNOWN")
        self.assertEqual(self.descriptor["authorizing_use"], "DENY")
        self.assertRegex(storage_schema_digest(self.descriptor), r"^[0-9a-f]{64}$")

    def test_inventories_are_sorted_unique_and_exact(self):
        tables = [table["name"] for table in self.descriptor["tables"]]
        indexes = [index["name"] for index in self.descriptor["indexes"]]
        roots = [root["root_name"] for root in self.descriptor["root_projections"]]
        self.assertEqual(tables, sorted(set(tables)))
        self.assertEqual(indexes, sorted(set(indexes)))
        self.assertEqual(roots, sorted(set(roots)))
        self.assertEqual(len(tables), 15)
        self.assertEqual(len(roots), 15)
        self.assertEqual(set(tables), set(roots))

    def test_exact_ddl_builds_and_matches_structural_inventory(self):
        self.assertEqual(sqlite3.sqlite_version, self.descriptor["sqlite"]["version"])
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "runtime.v2.sqlite"
            connection = self._build(self.descriptor, database)
            try:
                self.assertEqual(
                    connection.execute("SELECT sqlite_source_id()").fetchone()[0],
                    self.descriptor["sqlite"]["source_id"],
                )
                observed_tables = [row[0] for row in connection.execute(
                    "SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name"
                )]
                self.assertEqual(
                    observed_tables,
                    [table["name"] for table in self.descriptor["tables"]],
                )
                observed_explicit_indexes = [row[0] for row in connection.execute(
                    "SELECT name FROM sqlite_schema "
                    "WHERE type='index' AND sql IS NOT NULL ORDER BY name"
                )]
                self.assertEqual(
                    observed_explicit_indexes,
                    [index["name"] for index in self.descriptor["indexes"]],
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT count(*) FROM sqlite_schema "
                        "WHERE type IN ('view','trigger')"
                    ).fetchone()[0],
                    0,
                )
                for table in self.descriptor["tables"]:
                    observed = [
                        [row[1], row[2], bool(row[3]), row[5]]
                        for row in connection.execute(
                            f"PRAGMA table_xinfo({table['name']})"
                        )
                    ]
                    self.assertEqual(observed, table["columns"], table["name"])
                    self.assertTrue(all(
                        row[6] == 0 for row in connection.execute(
                            f"PRAGMA table_xinfo({table['name']})"
                        )
                    ))
                for index in self.descriptor["indexes"]:
                    index_list_row = next(
                        row for row in connection.execute(
                            f"PRAGMA index_list({index['table']})"
                        ) if row[1] == index["name"]
                    )
                    self.assertEqual(bool(index_list_row[2]), index["unique"])
                    self.assertEqual(bool(index_list_row[4]), index["partial"])
                    index_rows = list(connection.execute(
                        f"PRAGMA index_xinfo({index['name']})"
                    ))
                    key_columns = [row[2] for row in index_rows if row[5] == 1]
                    self.assertEqual(key_columns, index["columns"], index["name"])
                self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
                self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
                observation = self._structural_observation(
                    connection, self.descriptor
                )
                self.assertEqual(
                    sqlite_structure_digest(observation),
                    self.descriptor["structural_observation_sha256"],
                )
                compile_options = sorted(
                    row[0] for row in connection.execute("PRAGMA compile_options")
                )
                self.assertEqual(
                    sqlite_compile_options_digest(compile_options),
                    self.descriptor["sqlite"]["compile_options_sha256"],
                )
            finally:
                connection.close()

    def test_structural_hash_detects_executable_ddl_mutation(self):
        altered = json.loads(json.dumps(self.descriptor))
        altered["tables"][0]["sql"] = altered["tables"][0]["sql"].replace(
            "CREATE TABLE attempts(", "CREATE TABLE attempts (", 1
        )
        with tempfile.TemporaryDirectory() as directory:
            connection = self._build(altered, Path(directory) / "altered.sqlite")
            try:
                self.assertNotEqual(
                    sqlite_structure_digest(
                        self._structural_observation(connection, altered)
                    ),
                    self.descriptor["structural_observation_sha256"],
                )
            finally:
                connection.close()

    def test_structural_hash_detects_temp_extra_and_pragma_mutations(self):
        mutations = (
            "CREATE TEMP TABLE attacker_temp(x TEXT)",
            "CREATE VIEW attacker_view AS SELECT 1 AS x",
            "CREATE TABLE attacker_generated(x INTEGER,y INTEGER GENERATED ALWAYS AS (x+1)) STRICT",
            "PRAGMA foreign_keys=OFF",
        )
        for statement in mutations:
            with self.subTest(statement=statement), tempfile.TemporaryDirectory() as directory:
                connection = self._build(
                    self.descriptor, Path(directory) / "mutated.sqlite"
                )
                try:
                    connection.execute(statement)
                    self.assertNotEqual(
                        sqlite_structure_digest(
                            self._structural_observation(connection, self.descriptor)
                        ),
                        self.descriptor["structural_observation_sha256"],
                    )
                finally:
                    connection.close()

    def test_compile_options_digest_detects_any_option_change(self):
        with tempfile.TemporaryDirectory() as directory:
            connection = self._build(
                self.descriptor, Path(directory) / "compile.sqlite"
            )
            try:
                options = sorted(
                    row[0] for row in connection.execute("PRAGMA compile_options")
                )
                self.assertNotEqual(
                    sqlite_compile_options_digest(options + ["ATTACKER_OPTION"]),
                    self.descriptor["sqlite"]["compile_options_sha256"],
                )
            finally:
                connection.close()

    def test_foreign_key_projection_matches_exact_ddl(self):
        pattern = re.compile(
            r"FOREIGN KEY\(([^)]+)\) REFERENCES ([a-z][a-z0-9_]*)\(([^)]+)\)"
            r" ON UPDATE RESTRICT ON DELETE RESTRICT( DEFERRABLE INITIALLY DEFERRED)?"
        )
        for table in self.descriptor["tables"]:
            projected = []
            for match in pattern.finditer(table["sql"]):
                projected.append({
                    "columns": match.group(1).split(","),
                    "references_table": match.group(2),
                    "references_columns": match.group(3).split(","),
                    "deferred": match.group(4) is not None,
                })
            self.assertEqual(projected, table["foreign_keys"], table["name"])

    def test_root_order_is_an_ascending_binary_unique_key(self):
        with tempfile.TemporaryDirectory() as directory:
            connection = self._build(self.descriptor, Path(directory) / "roots.sqlite")
            try:
                for root in self.descriptor["root_projections"]:
                    candidates = []
                    for index_row in connection.execute(
                        f"PRAGMA index_list({root['table']})"
                    ):
                        if not bool(index_row[2]) or bool(index_row[4]):
                            continue
                        xinfo = list(connection.execute(
                            f"PRAGMA index_xinfo({index_row[1]})"
                        ))
                        key_rows = [row for row in xinfo if row[5] == 1]
                        candidates.append([row[2] for row in key_rows])
                    self.assertTrue(
                        any(
                            set(candidate).issubset(root["row_order"])
                            for candidate in candidates
                        ),
                        root["root_name"],
                    )
                    columns = {
                        column[0]: column[1]
                        for table in self.descriptor["tables"]
                        if table["name"] == root["table"]
                        for column in table["columns"]
                    }
                    table_sql = next(
                        table["sql"] for table in self.descriptor["tables"]
                        if table["name"] == root["table"]
                    )
                    for column in root["row_order"]:
                        if columns[column] == "TEXT":
                            self.assertIn(
                                f"{column} TEXT COLLATE BINARY", table_sql
                            )
            finally:
                connection.close()

    def test_root_projection_columns_and_order_keys_exist(self):
        tables = {table["name"]: [column[0] for column in table["columns"]]
                  for table in self.descriptor["tables"]}
        for root in self.descriptor["root_projections"]:
            self.assertEqual(root["columns"], tables[root["table"]])
            self.assertTrue(set(root["row_order"]).issubset(root["columns"]))

    def test_descriptor_mutations_fail_schema_or_executable_contract(self):
        altered = json.loads(json.dumps(self.descriptor))
        altered["sqlite"]["application_id"] = 0
        self.assertTrue(list(Draft202012Validator(self.schema).iter_errors(altered)))
        altered = json.loads(json.dumps(self.descriptor))
        altered["tables"].append(altered["tables"][0])
        self.assertTrue(list(Draft202012Validator(self.schema).iter_errors(altered)))
        altered = json.loads(json.dumps(self.descriptor))
        altered["semantic_predicates"][0] += " weakened"
        self.assertTrue(list(Draft202012Validator(self.schema).iter_errors(altered)))


if __name__ == "__main__":
    unittest.main()
