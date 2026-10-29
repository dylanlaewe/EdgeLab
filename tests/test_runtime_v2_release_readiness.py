"""Adversarial tests for the offline release-readiness audit."""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import tools.check_runtime_v2_release_readiness as readiness_checker
from tools.check_runtime_v2_release_readiness import (
    BOOTSTRAP_SCHEMAS,
    BOOTSTRAP_DOCUMENT_RESOURCE_EVIDENCE,
    BLOB_RESOURCE_EVIDENCE,
    CLOSURE_SCHEMA,
    CONTENT_ASSETS,
    EVENT_BYTE_RESOURCE_EVIDENCE,
    PIN_BEGIN_MARKER,
    PIN_END_MARKER,
    PIN_REPLACEMENT,
    RESOURCE_CLASSIFICATION_DOMAIN,
    RESOURCE_CLASSIFICATION_ANCESTORS,
    RESOURCE_CLASSIFICATION_EVIDENCE,
    RESOURCE_CLASSIFICATION_MANIFEST,
    RESOURCE_CLASSIFICATION_PREDECESSOR_MANIFEST,
    RESOURCE_CLASSIFICATION_PREDECESSOR_SCHEMA,
    RESOURCE_CLASSIFICATION_SCHEMA,
    RESOURCE_DISCOVERY_DOMAIN,
    RESOURCE_DISCOVERY_MANIFEST,
    RESOURCE_DISCOVERY_SCHEMA,
    RESOURCE_DISCOVERY_V1_ID,
    RESOURCE_DISCOVERY_V2_ID,
    RESOURCE_SOURCE_BOUND_SITES_V2_DOMAIN,
    RESOURCE_SOURCE_BOUND_SITES_V2_SHA256,
    RESOURCE_SOURCE_INPUT_DOMAIN,
    RETAINED_SCHEMAS,
    SCHEMA_REF_NODE_RESOURCE_EVIDENCE,
    SCHEMA_REGISTRY_RESOURCE_EVIDENCE,
    ReadinessError,
    _domain_digest,
    _source_bound_inventory,
    _source_bound_binding_inventory,
    _source_inventory,
    build_report,
    elide_pin_block,
)


ROOT = Path(__file__).resolve().parents[1]


class RuntimeV2ReleaseReadinessTests(unittest.TestCase):
    def copy_inputs(self) -> Path:
        temporary = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, temporary)
        shutil.copytree(ROOT / "src", temporary / "src")
        (temporary / "schemas").mkdir()
        paths = {
            path for _, _, path in BOOTSTRAP_SCHEMAS + RETAINED_SCHEMAS
        } | {path for _, _, path in CONTENT_ASSETS} | {
            CLOSURE_SCHEMA[1], RESOURCE_CLASSIFICATION_SCHEMA[1],
            RESOURCE_CLASSIFICATION_MANIFEST[1],
            RESOURCE_DISCOVERY_SCHEMA[1], RESOURCE_DISCOVERY_MANIFEST[1],
            RESOURCE_CLASSIFICATION_PREDECESSOR_MANIFEST["path"],
            RESOURCE_CLASSIFICATION_PREDECESSOR_SCHEMA["path"],
            *(item["path"] for item in RESOURCE_CLASSIFICATION_ANCESTORS),
            *(item["path"] for item in RESOURCE_CLASSIFICATION_EVIDENCE),
        }
        for relative in paths:
            source = ROOT / relative
            target = temporary / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        return temporary

    def rewrite_manifest(self, root: Path, mutate) -> None:
        path = root / RESOURCE_CLASSIFICATION_MANIFEST[1]
        manifest = json.loads(path.read_text(encoding="ascii"))
        mutate(manifest)
        digest_value = dict(manifest)
        digest_value.pop("classification_manifest_sha256")
        manifest["classification_manifest_sha256"] = hashlib.sha256(
            RESOURCE_CLASSIFICATION_DOMAIN.encode("ascii")
            + json.dumps(
                digest_value, sort_keys=True, separators=(",", ":"),
                ensure_ascii=True,
            ).encode("ascii")
        ).hexdigest()
        path.write_text(json.dumps(manifest), encoding="ascii")

    def refresh_source_bindings(self, root: Path) -> None:
        source, _, source_bytes = _source_inventory(root)
        predecessor_sites = _source_bound_inventory(source_bytes)
        source_sites = sorted(
            predecessor_sites + _source_bound_binding_inventory(
                source_bytes, predecessor_sites
            ),
            key=lambda item: (item["path"], item["site_id"]),
        )
        source_identity = [
            {key: value for key, value in item.items() if key != "line"}
            for item in source_sites
        ]
        source_inputs = [
            {
                "byte_length": item["byte_length"],
                "module": item["module"],
                "path": item["path"],
                "raw_sha256": item["raw_sha256"],
            }
            for item in source["local_artifacts"]
        ]

        def refresh(manifest):
            manifest["source_input_count"] = len(source_inputs)
            manifest["source_inputs_sha256"] = _domain_digest(
                RESOURCE_SOURCE_INPUT_DOMAIN, source_inputs
            )
            manifest["source_bound_site_count"] = len(source_sites)
            manifest["source_bound_sites_sha256"] = _domain_digest(
                "EDGELAB\0RUNTIME_V2_SOURCE_BOUND_SITES\0V2\0",
                source_identity,
            )
            manifest["unclassified_site_count"] = (
                len(source_sites) + manifest["schema_bound_site_count"] - 22
            )

        self.rewrite_manifest(root, refresh)

    def build_with_refreshed_ordinary_source_bindings(
        self, root: Path, binding_sites: list[dict[str, object]]
    ) -> dict[str, object]:
        """Model an attacker refreshing the ordinary V2 census after source drift."""
        source, _, source_bytes = _source_inventory(root)
        predecessor_sites = _source_bound_inventory(source_bytes)
        source_sites = sorted(
            predecessor_sites + binding_sites,
            key=lambda item: (item["path"], item["site_id"]),
        )
        source_identity = [
            {key: value for key, value in item.items() if key != "line"}
            for item in source_sites
        ]
        source_inputs = [
            {
                "byte_length": item["byte_length"],
                "module": item["module"],
                "path": item["path"],
                "raw_sha256": item["raw_sha256"],
            }
            for item in source["local_artifacts"]
        ]
        source_digest = _domain_digest(
            RESOURCE_SOURCE_BOUND_SITES_V2_DOMAIN, source_identity
        )

        def refresh(manifest):
            manifest["source_input_count"] = len(source_inputs)
            manifest["source_inputs_sha256"] = _domain_digest(
                RESOURCE_SOURCE_INPUT_DOMAIN, source_inputs
            )
            manifest["source_bound_site_count"] = len(source_sites)
            manifest["source_bound_sites_sha256"] = source_digest
            manifest["unclassified_site_count"] = (
                len(source_sites) + manifest["schema_bound_site_count"] - 22
            )

        self.rewrite_manifest(root, refresh)
        with (
            mock.patch.object(
                readiness_checker,
                "_source_bound_binding_inventory",
                return_value=binding_sites,
            ),
            mock.patch.object(
                readiness_checker,
                "RESOURCE_SOURCE_BOUND_SITES_V2_SHA256",
                source_digest,
            ),
        ):
            return build_report(root)

    def rewrite_versioned_classification_manifest(
        self, root: Path, expected: dict[str, object], version: int, mutate
    ) -> dict[str, object]:
        path = root / str(expected["path"])
        manifest = json.loads(path.read_text(encoding="ascii"))
        mutate(manifest)
        digest_value = dict(manifest)
        digest_value.pop("classification_manifest_sha256")
        domain = f"EDGELAB\0RUNTIME_V2_RESOURCE_CLASSIFICATION\0V{version}\0"
        manifest["classification_manifest_sha256"] = hashlib.sha256(
            domain.encode("ascii")
            + json.dumps(
                digest_value, sort_keys=True, separators=(",", ":"),
                ensure_ascii=True,
            ).encode("ascii")
        ).hexdigest()
        raw = json.dumps(manifest).encode("ascii")
        path.write_bytes(raw)
        return {
            "byte_length": len(raw),
            "classification_manifest_sha256": manifest[
                "classification_manifest_sha256"
            ],
            "path": expected["path"],
            "raw_sha256": hashlib.sha256(raw).hexdigest(),
        }

    def test_current_inventory_is_deterministic_blocked_and_deny_only(self):
        first = build_report(ROOT)
        second = build_report(ROOT)
        self.assertEqual(first, second)
        self.assertEqual(first["status"], "BLOCKED")
        self.assertEqual(first["authorizing_use"], "DENY")
        self.assertFalse(first["release_artifacts_written"])
        self.assertEqual(
            [item["code"] for item in first["blockers"]],
            [
                "ACCEPTANCE_MATRIX_INCOMPLETE",
                "PUBLIC_ENTRYPOINT_DISCONNECTED",
                "RESOURCE_INVENTORY_INCOMPLETE",
                "V1_BRIDGE_UNSUPPORTED",
            ],
        )
        self.assertEqual(first["public_result_vocabulary"], ["INVALID", "UNSUPPORTED"])
        for prohibited in (
            "verifier_dependency_closure_sha256", "closure_candidate",
            "carrier_candidate", "positive_status",
            "release_generation_permitted",
        ):
            self.assertNotIn(prohibited, first)

    def test_exact_current_source_and_content_inventory_is_derived(self):
        inventory = build_report(ROOT)["inventory"]
        sources = inventory["source_closure"]
        self.assertEqual(
            [item["module"] for item in sources["local_artifacts"]],
            sorted({
                "edgelab",
                "edgelab.runtime_v2_bootstrap",
                "edgelab.runtime_v2_closure",
                "edgelab.runtime_v2_codec",
                "edgelab.runtime_v2_genesis",
                "edgelab.runtime_v2_group",
                "edgelab.runtime_v2_image",
                "edgelab.runtime_v2_initial",
                "edgelab.runtime_v2_transition",
                "edgelab.runtime_v2_verifier",
            }),
        )
        self.assertEqual(
            sources["standard_library_modules"],
            ["dataclasses", "hashlib", "json", "re", "typing"],
        )
        self.assertEqual(sources["external_import_modules"], [])
        self.assertEqual(sources["compiler_directives_excluded"], ["__future__"])
        self.assertEqual(len(inventory["bootstrap_schemas"]), 5)
        self.assertEqual(len(inventory["retained_schema_documents"]), 9)
        self.assertEqual(len(inventory["content_assets"]), 2)
        discovery = inventory["resource_inventory_discovery"]
        self.assertEqual(discovery["classification_status"], "UNCLASSIFIED")
        self.assertEqual(discovery["coverage_status"], "INCOMPLETE")
        self.assertEqual(len(discovery["source_bound_sites"]), 401)
        self.assertEqual(len(discovery["schema_bound_sites"]), 296)
        self.assertEqual(len(discovery["schema_inputs"]), 15)
        self.assertEqual(len(discovery["source_inputs"]), 10)
        classification = inventory["resource_inventory_classification"]
        self.assertEqual(classification["classified_constraint_count"], 7)
        self.assertEqual(classification["classified_site_count"], 22)
        self.assertEqual(classification["unclassified_site_count"], 675)
        self.assertEqual(classification["coverage_status"], "INCOMPLETE")
        self.assertEqual(classification["generation_disposition"], "DENY")
        expected_schema_paths = {
            path for _, _, path in BOOTSTRAP_SCHEMAS + RETAINED_SCHEMAS
        } | {CLOSURE_SCHEMA[1]}
        self.assertEqual(
            {item["path"] for item in discovery["schema_inputs"]},
            expected_schema_paths,
        )
        expected_schema_input_digest = hashlib.sha256(
            b"EDGELAB\0RUNTIME_V2_RESOURCE_SCHEMA_INPUTS\0V1\0"
            + json.dumps(
                discovery["schema_inputs"],
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("ascii")
        ).hexdigest()
        self.assertEqual(
            discovery["schema_inputs_sha256"], expected_schema_input_digest
        )
        self.assertTrue(
            expected_schema_paths.isdisjoint({path for _, _, path in CONTENT_ASSETS})
        )
        defaults = [
            item for item in discovery["source_bound_sites"]
            if item["kind"] == "FUNCTION_DEFAULT"
        ]
        self.assertTrue(defaults)
        self.assertTrue(all(item["qualname"] != "<module>" for item in defaults))
        self.assertTrue(all(item["binding"].startswith("parameter:") for item in defaults))
        self.assertEqual(
            {item["classification"] for item in discovery["source_bound_sites"]},
            {"UNCLASSIFIED"},
        )
        self.assertEqual(
            {item["classification"] for item in discovery["schema_bound_sites"]},
            {"UNCLASSIFIED"},
        )
        self.assertEqual(
            inventory["tested_runtime_assumptions"],
            [
                {"expected": "CPython", "name": "PYTHON_IMPLEMENTATION"},
                {"expected": "3.13", "name": "PYTHON_VERSION"},
            ],
        )
        domain_names = {item["name"] for item in inventory["digest_domains"]}
        self.assertTrue({
            "blob", "event", "event_task_predecessor", "table",
            "verifier_dependency_closure",
        }.issubset(domain_names))
        limit_names = {item["name"] for item in inventory["resource_limits"]}
        self.assertTrue({
            "CANONICAL_JSON_MAX_DEPTH", "CLOSURE_INTEGER_TOKEN_MAX_DIGITS",
            "MAX_SCHEMA_REF_NODES",
            "MAX_TOTAL_ACCOUNTED_INPUT_BYTES", "MAX_TOTAL_ROOT_WORK_BYTES",
            "TABLE_TASKS_ROWS",
        }.issubset(limit_names))
        for namespace_name in (
            "bootstrap_schemas", "content_assets", "retained_schema_documents",
        ):
            namespace = inventory[namespace_name]
            for item in namespace:
                raw = (ROOT / item["path"]).read_bytes()
                self.assertEqual(item["byte_length"], len(raw))
                self.assertEqual(item["raw_sha256"], hashlib.sha256(raw).hexdigest())

    def test_resource_discovery_v2_preserves_v1_and_adds_exact_bindings(self):
        discovery = build_report(ROOT)["inventory"]["resource_inventory_discovery"]
        self.assertEqual(discovery["profile_id"], RESOURCE_DISCOVERY_V2_ID)
        self.assertEqual(len(discovery["source_bound_sites"]), 401)
        self.assertEqual(len(discovery["schema_bound_sites"]), 296)
        self.assertEqual(
            len(discovery["source_bound_sites"])
            + len(discovery["schema_bound_sites"]),
            697,
        )
        self.assertEqual(discovery["legacy_source_bound_site_count"], 394)
        self.assertEqual(discovery["derived_binding_site_count"], 7)
        self.assertEqual(
            discovery["source_bound_sites_sha256"],
            RESOURCE_SOURCE_BOUND_SITES_V2_SHA256,
        )
        self.assertEqual(
            discovery["predecessor_discovery"],
            {
                "profile_id": RESOURCE_DISCOVERY_V1_ID,
                "schema_bound_site_count": 296,
                "schema_bound_sites_sha256": (
                    "00b27a32303836f9d9910663e6bd2f76a7ca6d8c7cd614e5f22346b53cd104de"
                ),
                "schema_input_count": 15,
                "schema_inputs_sha256": (
                    "14ccff50a49f337336f01b5a40b845e5011218063d2cdfa68f0b73b1a3c94239"
                ),
                "source_bound_site_count": 394,
                "source_bound_sites_sha256": (
                    "f4bc353d75ec07b18adc5038ee505985adb692c6890d95b1c6feed843bd00d8f"
                ),
                "source_input_count": 10,
                "source_inputs_sha256": (
                    "b22a453f6b2f5f44281054752bf9bce5e259d6a60ae22fe7b190383292e4ba2a"
                ),
            },
        )
        bindings = [
            item for item in discovery["source_bound_sites"]
            if item["kind"] == "BOUND_TABLE_COMPARISON_BINDING"
        ]
        self.assertEqual(
            {item["site_id"] for item in bindings},
            {
                "55746a75fc2eb842245ba7bcdad51086efbc304200a958f592b064757c9b9f1c",
                "82ac9bd0ba24bed59304ea8a2aad0cbaa7bdf92db3e332e58b661285512990b6",
                "7ea348002f2b6caf5e341cc7739453f80b8e576f18a354da8cccd1432ad3a6cc",
                "a5edf2e2129f2918e47e765f74655da1e97a725f42015d1e38dbb7e6a92b50e4",
                "8a65115a6e18d3b2a23dc717ac5500638641dc0fe90a227554e9b4b500464534",
                "9a911b0807e818c67215b24ca2aef14d904826e042c65cfb5d74f51f989ef275",
                "4da76883b64b45ef3e46ca843d83de74162b42fc5649008a595c806277a47a99",
            },
        )
        self.assertTrue(all(item["classification"] == "UNCLASSIFIED" for item in bindings))
        self.assertTrue(all(set(item) == {
            "ast_sha256", "binding", "branch_key", "classification",
            "comparator_site_id", "expression", "kind", "line",
            "loop_ast_sha256", "maximum_expression", "path", "qualname",
            "row_index", "site_id", "subject_expression",
            "table_assignment_ast_sha256", "table_name",
        } for item in bindings))

        _, _, source_bytes = _source_inventory(ROOT)
        predecessor = _source_bound_inventory(source_bytes)
        self.assertEqual(
            _source_bound_binding_inventory(source_bytes, predecessor),
            bindings,
        )

    def test_resource_discovery_v2_evidence_artifacts_fail_closed(self):
        root = self.copy_inputs()
        schema = root / RESOURCE_DISCOVERY_SCHEMA[1]
        schema.write_bytes(schema.read_bytes() + b"\n")
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "RESOURCE_DISCOVERY_SCHEMA_IDENTITY")

        root = self.copy_inputs()
        manifest_path = root / RESOURCE_DISCOVERY_MANIFEST[1]
        manifest = json.loads(manifest_path.read_text(encoding="ascii"))
        manifest["coverage_status"] = "COMPLETE"
        digest_value = dict(manifest)
        digest_value.pop("discovery_manifest_sha256")
        manifest["discovery_manifest_sha256"] = _domain_digest(
            RESOURCE_DISCOVERY_DOMAIN, digest_value
        )
        manifest_path.write_text(json.dumps(manifest), encoding="ascii")
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "RESOURCE_DISCOVERY_MANIFEST_BINDING")
        self.assertEqual(caught.exception.coordinate, "coverage_status")

        root = self.copy_inputs()
        manifest_path = root / RESOURCE_DISCOVERY_MANIFEST[1]
        manifest = json.loads(manifest_path.read_text(encoding="ascii"))
        manifest["discovery_manifest_sha256"] = "0" * 64
        manifest_path.write_text(json.dumps(manifest), encoding="ascii")
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(
            caught.exception.code, "RESOURCE_DISCOVERY_MANIFEST_SELF_DIGEST"
        )

        root = self.copy_inputs()
        manifest_path = root / RESOURCE_DISCOVERY_MANIFEST[1]
        manifest_path.unlink()
        manifest_path.hardlink_to(root / RESOURCE_DISCOVERY_SCHEMA[1])
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "HARDLINK_INPUT_ALIAS")

    def test_resource_discovery_v2_table_bindings_fail_closed_on_drift(self):
        manifest_row = (
            b'        ("manifest", captured["manifest"], '
            b'MAX_BOOTSTRAP_DOCUMENT_BYTES),\n'
        )
        attachment_row = (
            b'        ("attachment", captured["attachment"], '
            b'MAX_BOOTSTRAP_DOCUMENT_BYTES),\n'
        )
        attacks = (
            (manifest_row, manifest_row.replace(b'"manifest"', b'"wrong"', 1),
             "RESOURCE_BINDING_ASSIGNMENT_AST"),
            (manifest_row, manifest_row.replace(b'captured["manifest"]', b'captured["attachment"]'),
             "RESOURCE_BINDING_ASSIGNMENT_AST"),
            (manifest_row, manifest_row.replace(b"MAX_BOOTSTRAP_DOCUMENT_BYTES", b"MAX_SCHEMA_REGISTRY_BYTES"),
             "RESOURCE_BINDING_ASSIGNMENT_AST"),
            (manifest_row, manifest_row + manifest_row,
             "RESOURCE_BINDING_ASSIGNMENT_AST"),
            (manifest_row, b"", "RESOURCE_BINDING_ASSIGNMENT_AST"),
            (manifest_row + attachment_row, attachment_row + manifest_row,
             "RESOURCE_BINDING_ASSIGNMENT_AST"),
            (manifest_row, b"        *(" + manifest_row.strip().rstrip(b",") + b",),\n",
             "RESOURCE_BINDING_ASSIGNMENT_AST"),
            (b"for name, value, maximum in byte_fields:",
             b"for name, value, maximum in tuple(byte_fields):",
             "RESOURCE_BINDING_LOOP"),
            (b"for name, value, maximum in byte_fields:",
             b"for branch, value, maximum in byte_fields:",
             "RESOURCE_BINDING_LOOP_AST"),
            (b"if maximum is not None and len(value) > maximum:",
             b"if maximum is not None and len(value) >= maximum:",
             "RESOURCE_BINDING_LOOP_AST"),
            (b"for name, values, maximum in byte_collections:",
             b"for name, values, maximum in tuple(byte_collections):",
             "RESOURCE_BINDING_LOOP"),
            (b"if len(value) > maximum:\n",
             b"if len(value) >= maximum:\n",
             "RESOURCE_BINDING_LOOP_AST"),
        )
        for old, new, expected_code in attacks:
            with self.subTest(attack=old[:50]):
                root = self.copy_inputs()
                source = root / "src/edgelab/runtime_v2_image.py"
                original = source.read_bytes()
                mutated = original.replace(old, new, 1)
                self.assertNotEqual(mutated, original)
                source.write_bytes(mutated)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(caught.exception.code, expected_code)

        root = self.copy_inputs()
        source = root / "src/edgelab/runtime_v2_image.py"
        original = source.read_bytes()
        mutated = original.replace(
            b"    byte_fields = (", b"    byte_fields_alias = (", 1
        ).replace(
            b"for name, value, maximum in byte_fields:",
            b"for name, value, maximum in byte_fields_alias:",
            1,
        )
        self.assertNotEqual(mutated, original)
        source.write_bytes(mutated)
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "RESOURCE_BINDING_TABLE_NAME")

    def test_cli_emits_one_canonical_json_line_and_refuses_release(self):
        command = [
            str(ROOT / ".venv" / "bin" / "python"),
            str(ROOT / "tools" / "check_runtime_v2_release_readiness.py"),
        ]
        completed = subprocess.run(
            command, cwd=ROOT, capture_output=True, check=False
        )
        self.assertEqual(completed.returncode, 1, completed.stderr.decode())
        self.assertEqual(completed.stderr, b"")
        self.assertEqual(completed.stdout.count(b"\n"), 1)
        value = json.loads(completed.stdout)
        expected = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii") + b"\n"
        self.assertEqual(completed.stdout, expected)
        self.assertEqual(value, build_report(ROOT))

        denied = subprocess.run(
            command + ["--root", "/tmp"],
            cwd=ROOT,
            capture_output=True,
            check=False,
        )
        self.assertEqual(denied.returncode, 2)
        denied_value = json.loads(denied.stdout)
        self.assertEqual(denied_value["status"], "INVALID")
        self.assertEqual(denied_value["error"]["code"], "CLI_ARGUMENTS_DENIED")

    def test_pin_elision_is_exactly_one_complete_inclusive_block(self):
        raw = b"prefix\n" + PIN_BEGIN_MARKER + b"generated\n" + PIN_END_MARKER + b"suffix\n"
        self.assertEqual(
            elide_pin_block(raw), b"prefix\n" + PIN_REPLACEMENT + b"suffix\n"
        )
        changed = b"changed\n" + raw
        self.assertNotEqual(elide_pin_block(changed), elide_pin_block(raw))
        hostile = (
            b"no markers",
            PIN_BEGIN_MARKER + b"partial",
            PIN_END_MARKER + b"reversed" + PIN_BEGIN_MARKER,
            b"attached" + PIN_BEGIN_MARKER + b"body\n" + PIN_END_MARKER,
            PIN_BEGIN_MARKER + b"body\nattached" + PIN_END_MARKER,
            raw + raw,
            PIN_BEGIN_MARKER + PIN_BEGIN_MARKER + PIN_END_MARKER + PIN_END_MARKER,
        )
        for candidate in hostile:
            with self.subTest(candidate=candidate), self.assertRaises(ReadinessError):
                elide_pin_block(candidate)

    def test_external_or_dynamic_imports_fail_closed(self):
        for injected in (
            b"\nimport requests\n",
            b"\n__import__('json')\n",
            b"\n_dynamic_loader = __import__\n_dynamic_loader('json')\n",
            b"\ngetattr(__builtins__, '__import__')('json')\n",
            b'\ngetattr(__builtins__, "__im" + "port__")("json")\n',
        ):
            with self.subTest(injected=injected):
                root = self.copy_inputs()
                path = root / "src" / "edgelab" / "runtime_v2_initial.py"
                path.write_bytes(path.read_bytes() + injected)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                expected = (
                    "EXTERNAL_IMPORTS_PRESENT"
                    if b"requests" in injected else "DYNAMIC_EXECUTION"
                )
                self.assertEqual(caught.exception.code, expected)

    def test_hardcoded_limits_are_derived_from_exact_comparison_shapes(self):
        root = self.copy_inputs()
        path = root / "src" / "edgelab" / "runtime_v2_initial.py"
        raw = path.read_bytes().replace(b"50_001", b"50_002")
        raw += b"\nif False:\n    _readiness_decoy = 50_001\n"
        path.write_bytes(raw)
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "RESOURCE_DISCOVERY_V1_CARDINALITY")
        self.assertEqual(caught.exception.coordinate, "source_bound_sites")

    def test_symlink_hardlink_and_duplicate_json_inputs_deny(self):
        root = self.copy_inputs()
        path = root / "src" / "edgelab" / "runtime_v2_codec.py"
        real = path.with_name("runtime_v2_codec_real.py")
        path.rename(real)
        path.symlink_to(real.name)
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "SYMLINK_INPUT")

        root = self.copy_inputs()
        first = root / "docs/M0.3A_DEPENDENCY_CLOSURE_SHAPE.v1.md"
        second = root / "tests/test_runtime_v2_closure.py"
        second.unlink()
        second.hardlink_to(first)
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "HARDLINK_INPUT_ALIAS")

        root = self.copy_inputs()
        source = root / BOOTSTRAP_SCHEMAS[0][2]
        target = root / BOOTSTRAP_SCHEMAS[1][2]
        target.unlink()
        target.hardlink_to(source)
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "HARDLINK_INPUT_ALIAS")

        root = self.copy_inputs()
        path = root / CONTENT_ASSETS[0][2]
        path.write_bytes(b'{"x":1,"x":2}')
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "DUPLICATE_JSON_KEY")

    def test_unreachable_or_case_aliased_runtime_module_denies(self):
        for name in ("runtime_v2_extra.py", "RUNTIME_V2_EXTRA.py"):
            with self.subTest(name=name):
                root = self.copy_inputs()
                (root / "src" / "edgelab" / name).write_text(
                    "# unreachable runtime module\n", encoding="utf-8"
                )
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertIn(caught.exception.code, {
                    "RUNTIME_MODULE_INVENTORY", "RUNTIME_MODULE_CASE_ALIAS",
                })

        root = self.copy_inputs()
        extra = root / "src" / "edgelab" / "runtime_v2_extra.py"
        extra.symlink_to("missing-runtime-module.py")
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "RUNTIME_MODULE_INPUT")

    def test_dangling_or_case_aliased_carrier_denies(self):
        for name in ("_runtime_v2_release.py", "_RUNTIME_V2_RELEASE.PY"):
            with self.subTest(name=name):
                root = self.copy_inputs()
                carrier = root / "src" / "edgelab" / name
                carrier.symlink_to("missing-generated-carrier.py")
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(caught.exception.code, "PREMATURE_PIN_CARRIER")

    def test_source_mutation_changes_inventory_without_creating_authority(self):
        root = self.copy_inputs()
        baseline = build_report(root)
        path = root / "src" / "edgelab" / "runtime_v2_codec.py"
        path.write_bytes(path.read_bytes() + b"\n# post-freeze mutation\n")
        self.assertEqual(baseline["authorizing_use"], "DENY")
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "RESOURCE_CLASSIFICATION_BINDING")
        self.assertEqual(caught.exception.coordinate, "source_inputs_sha256")

    def test_resource_discovery_detects_source_schema_and_regex_bound_drift(self):
        root = self.copy_inputs()
        baseline = build_report(root)["inventory"]["resource_inventory_discovery"]

        source = root / "src" / "edgelab" / "runtime_v2_codec.py"
        source.write_bytes(
            source.read_bytes() + b"\nif len(()) > 777:\n    pass\n"
        )
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "RESOURCE_DISCOVERY_V1_CARDINALITY")
        self.assertEqual(caught.exception.coordinate, "source_bound_sites")

        root = self.copy_inputs()
        closure_schema = root / CLOSURE_SCHEMA[1]
        closure_schema.write_bytes(
            closure_schema.read_bytes().replace(
                b'"maximum": 9223372036854775807',
                b'"maximum": 9223372036854775806',
                1,
            )
        )
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "RESOURCE_CLASSIFICATION_BINDING")
        self.assertIn(caught.exception.coordinate, {
            "schema_bound_sites_sha256", "schema_inputs_sha256",
        })

        root = self.copy_inputs()
        regex_source = root / "src" / "edgelab" / "runtime_v2_group.py"
        regex_source.write_bytes(
            regex_source.read_bytes().replace(b"{0,127}", b"{0,126}", 1)
        )
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "RESOURCE_DISCOVERY_V2_IDENTITY")
        self.assertEqual(caught.exception.coordinate, "source_bound_sites_sha256")

    def test_resource_discovery_ignores_comments_but_source_hash_does_not(self):
        root = self.copy_inputs()
        baseline = build_report(root)
        source = root / "src" / "edgelab" / "runtime_v2_codec.py"
        source.write_bytes(
            b"# nonsemantic 999 bound note\n" + source.read_bytes()
        )
        before_discovery = baseline["inventory"]["resource_inventory_discovery"]
        self.assertEqual(len(before_discovery["source_bound_sites"]), 401)
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "RESOURCE_CLASSIFICATION_BINDING")
        self.assertEqual(caught.exception.coordinate, "source_inputs_sha256")

    def test_partial_classification_schema_manifest_and_self_digest_are_exact(self):
        from jsonschema import Draft202012Validator

        schema = json.loads((ROOT / RESOURCE_CLASSIFICATION_SCHEMA[1]).read_text())
        manifest = json.loads((ROOT / RESOURCE_CLASSIFICATION_MANIFEST[1]).read_text())
        Draft202012Validator.check_schema(schema)
        self.assertEqual(list(Draft202012Validator(schema).iter_errors(manifest)), [])
        digest_value = dict(manifest)
        claimed = digest_value.pop("classification_manifest_sha256")
        expected = hashlib.sha256(
            RESOURCE_CLASSIFICATION_DOMAIN.encode("ascii")
            + json.dumps(
                digest_value, sort_keys=True, separators=(",", ":"),
                ensure_ascii=True,
            ).encode("ascii")
        ).hexdigest()
        self.assertEqual(claimed, expected)
        self.assertEqual(
            claimed,
            "a2b112dfec65b15cda67ea6d14a1199305a3614cfe2174966894afb32ca261e7",
        )
        self.assertEqual(
            hashlib.sha256((ROOT / RESOURCE_CLASSIFICATION_SCHEMA[1]).read_bytes()).hexdigest(),
            "decde7f7f5927a4809d21077848bfcb31dde68daf4df2e51c8cfcfb5e34a97cb",
        )
        self.assertEqual(
            hashlib.sha256((ROOT / RESOURCE_CLASSIFICATION_MANIFEST[1]).read_bytes()).hexdigest(),
            "32aa72a70f77e9d0a43969b8471e3374ebd3adfd108283a65a1d9f263f2de1b7",
        )
        self.assertEqual(manifest["coverage_status"], "INCOMPLETE")
        self.assertEqual(manifest["generation_disposition"], "DENY")
        self.assertEqual(manifest["schema_version"], 8)
        self.assertEqual(
            manifest["profile_id"],
            "EDGELAB_RUNTIME_V2_RESOURCE_CLASSIFICATION_V8",
        )
        self.assertEqual(manifest["classified_site_count"], 22)
        self.assertEqual(manifest["unclassified_site_count"], 675)
        self.assertEqual(
            [item["constraint_id"] for item in manifest["constraints"]],
            [
                "MAX_BLOB_BYTES",
                "MAX_DEPENDENCY_CLOSURE_BYTES",
                "MAX_EVENT_BYTES",
                "MAX_SCHEMA_DOCUMENT_BYTES",
                "MAX_SCHEMA_REF_NODES",
                "MAX_SCHEMA_REGISTRY_BYTES",
                "MAX_BOOTSTRAP_DOCUMENT_BYTES",
            ],
        )
        event_constraint = manifest["constraints"][2]
        self.assertEqual(event_constraint["unit"], "BYTES")
        self.assertEqual(event_constraint["maximum"], 1_048_576)
        self.assertEqual(
            event_constraint["semantic_subject"],
            "EXACT_BUILTIN_BYTES_MEMBERS_OF_CAPTURED_RUNTIME_IMAGE_EVENTS",
        )
        self.assertEqual(
            event_constraint["definition_site_ids"],
            ["7db6dd7c8847d19d5b451a58dc88346ff1d16db0d6c1b2dc62eec0b0780f662a"],
        )
        self.assertEqual(
            event_constraint["enforcement_site_ids"],
            ["8a65115a6e18d3b2a23dc717ac5500638641dc0fe90a227554e9b4b500464534"],
        )
        self.assertEqual(
            event_constraint["semantic_function_ast_sha256"],
            "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f",
        )
        self.assertEqual(
            event_constraint["semantic_module_ast_sha256"],
            "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857",
        )
        self.assertEqual(
            event_constraint["evidence_inputs"],
            [dict(item) for item in EVENT_BYTE_RESOURCE_EVIDENCE],
        )
        self.assertEqual(
            schema["properties"]["constraints"]["const"][2], event_constraint
        )
        ref_constraint = manifest["constraints"][4]
        self.assertEqual(ref_constraint["unit"], "NODES")
        self.assertEqual(ref_constraint["maximum"], 4_096)
        self.assertEqual(
            ref_constraint["semantic_subject"],
            "VALID_ROOT_SCHEMA_DEFINITION_OWNER_KEYS_ADMITTED_TO_CYCLE_TRAVERSAL",
        )
        self.assertEqual(
            ref_constraint["definition_site_ids"],
            [
                "61d3dcc5d5ed733e6d561edeb43ddcc00"
                "ab2aa8fc899b09353733877ea76a721"
            ],
        )
        self.assertEqual(
            ref_constraint["enforcement_site_ids"],
            [
                "4650c76c2ae3e065cd5767e97b8a59d9"
                "17415ba1dfc73f79f0efd8b09f4f3eef"
            ],
        )
        self.assertEqual(
            ref_constraint["semantic_function_ast_sha256"],
            "e445bd1a06dfbee91a6ed8146a6524874a84dbcc0439b06e3667d31a8e49f60d",
        )
        self.assertEqual(
            ref_constraint["semantic_module_ast_sha256"],
            "4cf60eb1416f7cfe080bd68653d748431084e04a17790a4244317834158acdfc",
        )
        self.assertEqual(
            ref_constraint["evidence_inputs"],
            [dict(item) for item in SCHEMA_REF_NODE_RESOURCE_EVIDENCE],
        )
        self.assertEqual(
            schema["properties"]["constraints"]["const"][4], ref_constraint
        )
        registry_constraint = manifest["constraints"][5]
        self.assertEqual(registry_constraint["unit"], "BYTES")
        self.assertEqual(registry_constraint["maximum"], 262_144)
        self.assertEqual(
            registry_constraint["semantic_subject"],
            "EXACT_BUILTIN_BYTES_SCHEMA_REGISTRY_FIELDS_SUPPLIED_TO_HOST_"
            "PREFLIGHT_OR_VERIFIER_BUNDLE_INSPECTION",
        )
        self.assertEqual(
            registry_constraint["definition_site_ids"],
            [
                "4c9346726487e13663e822fd8b63e995c6066a487dfbe2b6350e051ce2440384",
                "cc9e6904b1fdb98deea9fd35ddc4ae864aa572cbf5d963addbf8cc42beae4522",
            ],
        )
        self.assertEqual(
            registry_constraint["enforcement_site_ids"],
            [
                "a5edf2e2129f2918e47e765f74655da1e97a725f42015d1e38dbb7e6a92b50e4",
                "d02eb8dbac3f0359f160e1fb6259b5a438ec699a64cca7cd05d94c5ab86b1683",
            ],
        )
        self.assertEqual(
            [item["semantic_function_ast_sha256"]
             for item in registry_constraint["semantic_bindings"]],
            [
                "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f",
                "054e65a5e37bf65c79c2390dcdc6b0ed4b20683496159ad5d2cae04502f2c14e",
            ],
        )
        self.assertEqual(
            [item["semantic_module_ast_sha256"]
             for item in registry_constraint["semantic_bindings"]],
            [
                "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857",
                "4cf60eb1416f7cfe080bd68653d748431084e04a17790a4244317834158acdfc",
            ],
        )
        self.assertEqual(
            registry_constraint["evidence_inputs"],
            [dict(item) for item in SCHEMA_REGISTRY_RESOURCE_EVIDENCE],
        )
        self.assertEqual(
            schema["properties"]["constraints"]["const"][5],
            registry_constraint,
        )
        bootstrap_constraint = manifest["constraints"][6]
        self.assertEqual(bootstrap_constraint["unit"], "BYTES")
        self.assertEqual(bootstrap_constraint["maximum"], 1_048_576)
        self.assertEqual(
            bootstrap_constraint["semantic_subject"],
            "EXACT_BUILTIN_BYTES_BOOTSTRAP_FIELDS_OR_COLLECTION_MEMBERS_"
            "ADMITTED_BY_HOST_PREFLIGHT",
        )
        self.assertEqual(
            bootstrap_constraint["definition_site_ids"],
            [
                "8927485f8c04590dc06fa8d3bffde6e82517d898ec72637dbf758e21a56996d8"
            ],
        )
        self.assertEqual(
            bootstrap_constraint["enforcement_site_ids"],
            [
                "55746a75fc2eb842245ba7bcdad51086efbc304200a958f592b064757c9b9f1c",
                "82ac9bd0ba24bed59304ea8a2aad0cbaa7bdf92db3e332e58b661285512990b6",
                "7ea348002f2b6caf5e341cc7739453f80b8e576f18a354da8cccd1432ad3a6cc",
                "9a911b0807e818c67215b24ca2aef14d904826e042c65cfb5d74f51f989ef275",
                "4da76883b64b45ef3e46ca843d83de74162b42fc5649008a595c806277a47a99",
            ],
        )
        self.assertEqual(
            bootstrap_constraint["semantic_function_ast_sha256"],
            "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f",
        )
        self.assertEqual(
            bootstrap_constraint["semantic_module_ast_sha256"],
            "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857",
        )
        self.assertEqual(
            bootstrap_constraint["evidence_inputs"],
            [dict(item) for item in BOOTSTRAP_DOCUMENT_RESOURCE_EVIDENCE],
        )
        self.assertEqual(
            schema["properties"]["constraints"]["const"][6],
            bootstrap_constraint,
        )
        self.assertEqual(
            manifest["predecessor_manifest"]["path"],
            "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v7.json",
        )
        self.assertEqual(
            manifest["predecessor_schema"]["path"],
            "schemas/m0-3a-runtime-v2-resource-classification.v7.schema.json",
        )
        self.assertEqual(
            [item["path"] for item in RESOURCE_CLASSIFICATION_ANCESTORS],
            [
                "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v6.json",
                "schemas/m0-3a-runtime-v2-resource-classification.v6.schema.json",
                "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v5.json",
                "schemas/m0-3a-runtime-v2-resource-classification.v5.schema.json",
                "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v4.json",
                "schemas/m0-3a-runtime-v2-resource-classification.v4.schema.json",
                "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v3.json",
                "schemas/m0-3a-runtime-v2-resource-classification.v3.schema.json",
                "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v2.json",
                "schemas/m0-3a-runtime-v2-resource-classification.v2.schema.json",
                "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v1.json",
                "schemas/m0-3a-runtime-v2-resource-classification.v1.schema.json",
            ],
        )

    def test_partial_classification_rejects_hostile_manifest_mutations(self):
        mutations = (
            ("coverage_status", "COMPLETE"),
            ("generation_disposition", "ALLOW"),
            ("classified_site_count", 690),
            ("unclassified_site_count", 0),
            ("source_inputs_sha256", "0" * 64),
        )
        for key, value in mutations:
            with self.subTest(key=key):
                root = self.copy_inputs()
                path = root / RESOURCE_CLASSIFICATION_MANIFEST[1]
                self.rewrite_manifest(
                    root, lambda manifest: manifest.__setitem__(key, value)
                )
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code, "RESOURCE_CLASSIFICATION_BINDING"
                )

        root = self.copy_inputs()
        path = root / RESOURCE_CLASSIFICATION_MANIFEST[1]
        raw = path.read_bytes().replace(
            b'"schema_version": 8', b'"schema_version": 8, "schema_version": 8'
        )
        path.write_bytes(raw)
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "DUPLICATE_JSON_KEY")

        root = self.copy_inputs()
        path = root / RESOURCE_CLASSIFICATION_MANIFEST[1]
        manifest = json.loads(path.read_text(encoding="ascii"))
        manifest["classification_manifest_sha256"] = "0" * 64
        path.write_text(json.dumps(manifest), encoding="ascii")
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "RESOURCE_CLASSIFICATION_SELF_DIGEST")

        ref_constraint_mutations = (
            ("unit", "BYTES"),
            ("maximum", 4_095),
            ("semantic_function_ast_sha256", "0" * 64),
            ("semantic_module_ast_sha256", "1" * 64),
            (
                "definition_site_ids",
                ["2" * 64],
            ),
            (
                "enforcement_site_ids",
                ["3" * 64],
            ),
        )
        for field, hostile_value in ref_constraint_mutations:
            with self.subTest(ref_constraint=field):
                root = self.copy_inputs()

                def alter_ref_constraint(manifest):
                    manifest["constraints"][4][field] = hostile_value

                self.rewrite_manifest(root, alter_ref_constraint)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code, "RESOURCE_CLASSIFICATION_CONSTRAINT"
                )

        bootstrap_constraint_mutations = (
            ("maximum", 1_048_575),
            ("definition_site_ids", ["4" * 64]),
            ("enforcement_site_ids", ["5" * 64]),
            ("semantic_function_ast_sha256", "6" * 64),
            ("semantic_module_ast_sha256", "7" * 64),
            ("semantic_proof", {}),
            ("evidence_inputs", []),
        )
        for field, hostile_value in bootstrap_constraint_mutations:
            with self.subTest(bootstrap_constraint=field):
                root = self.copy_inputs()

                def alter_bootstrap_constraint(manifest):
                    manifest["constraints"][6][field] = hostile_value

                self.rewrite_manifest(root, alter_bootstrap_constraint)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code, "RESOURCE_CLASSIFICATION_CONSTRAINT"
                )

        root = self.copy_inputs()
        self.rewrite_manifest(
            root,
            lambda manifest: manifest["constraints"][0].__setitem__(
                "maximum", 16_777_215
            ),
        )
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "RESOURCE_CLASSIFICATION_CONSTRAINT")

        for mutation in ("reordered", "duplicated"):
            with self.subTest(constraints=mutation):
                root = self.copy_inputs()

                def alter(manifest):
                    constraints = manifest["constraints"]
                    manifest["constraints"] = (
                        list(reversed(constraints))
                        if mutation == "reordered"
                        else [constraints[0], constraints[0]]
                    )

                self.rewrite_manifest(root, alter)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code,
                    (
                        "RESOURCE_CLASSIFICATION_CONSTRAINT_KEYS"
                        if mutation == "reordered"
                        else "RESOURCE_CLASSIFICATION_CONSTRAINTS"
                    ),
                )

    def test_partial_classification_binds_schema_and_evidence_bytes(self):
        root = self.copy_inputs()
        schema = root / RESOURCE_CLASSIFICATION_SCHEMA[1]
        schema.write_bytes(schema.read_bytes().replace(
            b'"const": "INCOMPLETE"',
            b'"const": "COMPLETE"',
            1,
        ))
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(
            caught.exception.code, "RESOURCE_CLASSIFICATION_SCHEMA_IDENTITY"
        )

        for evidence_path in (item["path"] for item in RESOURCE_CLASSIFICATION_EVIDENCE):
            with self.subTest(evidence=evidence_path):
                root = self.copy_inputs()
                evidence = root / evidence_path
                evidence.write_bytes(evidence.read_bytes() + b"\nmutation")
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code,
                    "RESOURCE_CLASSIFICATION_EVIDENCE_IDENTITY",
                )

        root = self.copy_inputs()
        evidence = root / "docs/M0.3A_DEPENDENCY_CLOSURE_SHAPE.v1.md"
        evidence.unlink()
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "PATH_CASE_ALIAS")

        root = self.copy_inputs()
        evidence = root / "tests/test_runtime_v2_closure.py"
        real = evidence.with_name("test_runtime_v2_closure_real.py")
        evidence.rename(real)
        evidence.symlink_to(real.name)
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "SYMLINK_INPUT")

        for predecessor in (
            RESOURCE_CLASSIFICATION_PREDECESSOR_MANIFEST,
            RESOURCE_CLASSIFICATION_PREDECESSOR_SCHEMA,
            *RESOURCE_CLASSIFICATION_ANCESTORS,
        ):
            with self.subTest(predecessor=predecessor["path"]):
                root = self.copy_inputs()
                path = root / predecessor["path"]
                path.write_bytes(path.read_bytes() + b"\n")
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code,
                    "RESOURCE_CLASSIFICATION_PREDECESSOR_IDENTITY",
                )

        root = self.copy_inputs()
        first = root / BLOB_RESOURCE_EVIDENCE[0]["path"]
        second = root / BLOB_RESOURCE_EVIDENCE[1]["path"]
        second.unlink()
        second.hardlink_to(first)
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "HARDLINK_INPUT_ALIAS")

        root = self.copy_inputs()
        first = root / SCHEMA_REF_NODE_RESOURCE_EVIDENCE[0]["path"]
        second = root / SCHEMA_REF_NODE_RESOURCE_EVIDENCE[1]["path"]
        second.unlink()
        second.hardlink_to(first)
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "HARDLINK_INPUT_ALIAS")

    def test_partial_classification_binds_full_enforcement_function_context(self):
        for old, new in (
            (
                b"    if type(raw) is not bytes:\n        _fail(\"BYTES_REQUIRED\", \"/\")\n",
                b"",
            ),
            (
                b"    if len(raw) > MAX_DEPENDENCY_CLOSURE_BYTES:\n"
                b"        _fail(\"BYTE_LIMIT\", \"/\")\n",
                b"    if False:\n"
                b"        if len(raw) > MAX_DEPENDENCY_CLOSURE_BYTES:\n"
                b"            _fail(\"BYTE_LIMIT\", \"/\")\n",
            ),
        ):
            with self.subTest(mutation=old[:30]):
                root = self.copy_inputs()
                baseline = build_report(root)
                source = root / "src/edgelab/runtime_v2_closure.py"
                mutated = source.read_bytes().replace(old, new, 1)
                self.assertNotEqual(mutated, source.read_bytes())
                source.write_bytes(mutated)
                source_inputs = [
                    dict(item) for item in baseline["inventory"][
                        "resource_inventory_discovery"
                    ]["source_inputs"]
                ]
                for item in source_inputs:
                    if item["path"] == "src/edgelab/runtime_v2_closure.py":
                        item["byte_length"] = len(mutated)
                        item["raw_sha256"] = hashlib.sha256(mutated).hexdigest()
                refreshed = hashlib.sha256(
                    RESOURCE_SOURCE_INPUT_DOMAIN.encode("ascii")
                    + json.dumps(
                        source_inputs, sort_keys=True, separators=(",", ":"),
                        ensure_ascii=True,
                    ).encode("ascii")
                ).hexdigest()
                self.rewrite_manifest(
                    root,
                    lambda manifest: manifest.__setitem__(
                        "source_inputs_sha256", refreshed
                    ),
                )
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code,
                    "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
                )

        for old, new in (
            (
                b"def _fail(code: str, coordinate: str) -> None:\n"
                b"    raise ClosureValidationError(code, coordinate)\n",
                b"def _fail(code: str, coordinate: str) -> None:\n"
                b"    return None\n",
            ),
            (b"\n__all__ = (", b"\nlen = lambda value: False\n\n__all__ = ("),
        ):
            with self.subTest(transitive_mutation=old[:30]):
                root = self.copy_inputs()
                baseline = build_report(root)
                source = root / "src/edgelab/runtime_v2_closure.py"
                mutated = source.read_bytes().replace(old, new, 1)
                self.assertNotEqual(mutated, source.read_bytes())
                source.write_bytes(mutated)
                source_inputs = [
                    dict(item) for item in baseline["inventory"][
                        "resource_inventory_discovery"
                    ]["source_inputs"]
                ]
                for item in source_inputs:
                    if item["path"] == "src/edgelab/runtime_v2_closure.py":
                        item["byte_length"] = len(mutated)
                        item["raw_sha256"] = hashlib.sha256(mutated).hexdigest()
                refreshed = _domain_digest(
                    RESOURCE_SOURCE_INPUT_DOMAIN, source_inputs
                )
                self.rewrite_manifest(
                    root,
                    lambda manifest: manifest.__setitem__(
                        "source_inputs_sha256", refreshed
                    ),
                )
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code,
                    "RESOURCE_CLASSIFICATION_MODULE_SHAPE",
                )

    def test_partial_classification_rejects_refreshed_census_cardinality(self):
        root = self.copy_inputs()
        source_path = root / "src/edgelab/runtime_v2_codec.py"
        source_path.write_bytes(
            source_path.read_bytes() + b"\nif len(()) > 777:\n    pass\n"
        )
        self.refresh_source_bindings(root)
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "RESOURCE_DISCOVERY_V1_CARDINALITY")
        self.assertEqual(caught.exception.coordinate, "source_bound_sites")

    def test_blob_classification_binds_site_function_and_module_semantics(self):
        attacks = (
            (
                b"if len(body) > MAX_BLOB_BYTES:",
                b"if len(body) >= MAX_BLOB_BYTES:",
                "RESOURCE_DISCOVERY_V2_IDENTITY",
            ),
            (
                b'findings.add("IMAGE_ITEM_BYTE_LIMIT", "blobs", ',
                b'findings.add("WRONG_LIMIT", "blobs", ',
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
            ),
            (
                b"\n__all__ = (",
                b"\nlen = lambda value: False\n\n__all__ = (",
                "RESOURCE_CLASSIFICATION_MODULE_SHAPE",
            ),
            (
                b"if len(body) > MAX_BLOB_BYTES:",
                b"if False and len(body) > MAX_BLOB_BYTES:",
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
            ),
            (
                b"        finding = ImageViolation(code, artifact, coordinate)\n",
                b"        return\n        finding = ImageViolation(code, artifact, coordinate)\n",
                "RESOURCE_CLASSIFICATION_MODULE_SHAPE",
            ),
            (
                b"        items = list(self._items)\n",
                b"        return ()\n        items = list(self._items)\n",
                "RESOURCE_CLASSIFICATION_MODULE_SHAPE",
            ),
            (
                b"    if not violations:\n",
                b"    if True:\n",
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
            ),
            (
                b'            body = record_values["canonical_json"]\n'
                b'            if type(body) is not bytes:\n'
                b'                findings.add("IMAGE_RECORD_FIELD_TYPE", "blobs",',
                b'            body = record_values["canonical_json"]\n'
                b'            body = body[:True]\n'
                b'            if type(body) is not bytes:\n'
                b'                findings.add("IMAGE_RECORD_FIELD_TYPE", "blobs",',
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
            ),
            (
                b'    authorizing_use: str = field(default="DENY", init=False)\n',
                b'    authorizing_use: str = field(default="ALLOW", init=False)\n',
                "RESOURCE_CLASSIFICATION_MODULE_SHAPE",
            ),
        )
        for old, new, expected_code in attacks:
            with self.subTest(attack=old[:32]):
                root = self.copy_inputs()
                source = root / "src/edgelab/runtime_v2_image.py"
                mutated = source.read_bytes().replace(old, new, 1)
                self.assertNotEqual(mutated, source.read_bytes())
                source.write_bytes(mutated)
                self.refresh_source_bindings(root)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(caught.exception.code, expected_code)

    def test_event_byte_classification_binds_definition_binding_and_evidence(self):
        _, _, baseline_source_bytes = _source_inventory(ROOT)
        baseline_predecessor_sites = _source_bound_inventory(
            baseline_source_bytes
        )
        baseline_binding_sites = _source_bound_binding_inventory(
            baseline_source_bytes, baseline_predecessor_sites
        )

        root = self.copy_inputs()
        source = root / "src/edgelab/runtime_v2_image.py"
        original = source.read_bytes()
        mutated = original.replace(
            b"MAX_EVENT_BYTES = 1_048_576",
            b"MAX_EVENT_BYTES = 1_048_575",
            1,
        )
        self.assertNotEqual(mutated, original)
        source.write_bytes(mutated)
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "RESOURCE_BINDING_MAXIMUM")

        root = self.copy_inputs()
        source = root / "src/edgelab/runtime_v2_image.py"
        original = source.read_bytes()
        mutated = original.replace(
            b'("events", captured["events"], MAX_EVENT_BYTES)',
            b'("events", captured["events"], MAX_BOOTSTRAP_DOCUMENT_BYTES)',
            1,
        )
        self.assertNotEqual(mutated, original)
        source.write_bytes(mutated)
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "RESOURCE_BINDING_ASSIGNMENT_AST")

        # Even if an attacker refreshes the ordinary V2 census and the V8
        # manifest after semantic source drift, the classification's exact
        # definition and enforcement-site identities remain independently
        # pinned.
        root = self.copy_inputs()
        source = root / "src/edgelab/runtime_v2_image.py"
        original = source.read_bytes()
        mutated = original.replace(
            b"MAX_EVENT_BYTES = 1_048_576",
            b"MAX_EVENT_BYTES = 1_048_575 + 1",
            1,
        )
        self.assertNotEqual(mutated, original)
        source.write_bytes(mutated)
        with self.assertRaises(ReadinessError) as caught:
            self.build_with_refreshed_ordinary_source_bindings(
                root, baseline_binding_sites
            )
        self.assertEqual(
            caught.exception.code, "RESOURCE_CLASSIFICATION_SITE_MISSING"
        )

        root = self.copy_inputs()
        source = root / "src/edgelab/runtime_v2_image.py"
        original = source.read_bytes()
        mutated = original.replace(
            b'("events", captured["events"], MAX_EVENT_BYTES)',
            b'("events", captured["events"], MAX_BOOTSTRAP_DOCUMENT_BYTES)',
            1,
        )
        self.assertNotEqual(mutated, original)
        source.write_bytes(mutated)
        hostile_binding_sites = [dict(item) for item in baseline_binding_sites]
        hostile_event_site = next(
            item for item in hostile_binding_sites
            if item.get("branch_key") == "events"
        )
        hostile_event_site.update({
            "ast_sha256": "f" * 64,
            "expression": (
                "('events', captured['events'], "
                "MAX_BOOTSTRAP_DOCUMENT_BYTES)"
            ),
            "maximum_expression": "MAX_BOOTSTRAP_DOCUMENT_BYTES",
            "site_id": "e" * 64,
            "table_assignment_ast_sha256": "d" * 64,
        })
        with self.assertRaises(ReadinessError) as caught:
            self.build_with_refreshed_ordinary_source_bindings(
                root, hostile_binding_sites
            )
        self.assertEqual(
            caught.exception.code, "RESOURCE_CLASSIFICATION_SITE_MISSING"
        )

        for suffix in (
            b"\n\ndef _event_limit_extra_read():\n"
            b"    return MAX_EVENT_BYTES\n",
            b"\n\ndef _event_limit_extra_store():\n"
            b"    MAX_EVENT_BYTES = 1\n"
            b"    return None\n",
        ):
            with self.subTest(name_cardinality=suffix.splitlines()[2]):
                root = self.copy_inputs()
                source = root / "src/edgelab/runtime_v2_image.py"
                source.write_bytes(source.read_bytes() + suffix)
                self.refresh_source_bindings(root)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code,
                    "RESOURCE_CLASSIFICATION_NAME_CARDINALITY",
                )

        semantic_attacks = (
            (
                b'            if len(value) > maximum:\n'
                b'                findings.add("IMAGE_ITEM_BYTE_LIMIT", name, coordinate)\n',
                b'            if len(value) > maximum:\n'
                b'                findings.add("WRONG_EVENT_LIMIT", name, coordinate)\n',
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
                True,
            ),
            (
                b"    if not violations:\n",
                b"    if True:\n",
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
                False,
            ),
            (
                b'    authorizing_use: str = field(default="DENY", init=False)\n',
                b'    authorizing_use: str = field(default="ALLOW", init=False)\n',
                "RESOURCE_CLASSIFICATION_MODULE_SHAPE",
                False,
            ),
        )
        for old, new, expected_code, binding_extractor_drift in semantic_attacks:
            with self.subTest(event_semantics=old[:32]):
                root = self.copy_inputs()
                source = root / "src/edgelab/runtime_v2_image.py"
                original = source.read_bytes()
                mutated = original.replace(old, new, 1)
                self.assertNotEqual(mutated, original)
                source.write_bytes(mutated)
                with self.assertRaises(ReadinessError) as caught:
                    if binding_extractor_drift:
                        self.build_with_refreshed_ordinary_source_bindings(
                            root, baseline_binding_sites
                        )
                    else:
                        self.refresh_source_bindings(root)
                        build_report(root)
                self.assertEqual(caught.exception.code, expected_code)

        for field, hostile_value in (
            (
                "semantic_proof",
                {
                    "function_coordinate": "wrong",
                    "input_binding": "wrong",
                    "enforcement_order": "wrong",
                    "rejection_action": "wrong",
                },
            ),
            ("evidence_inputs", []),
        ):
            with self.subTest(manifest_field=field):
                root = self.copy_inputs()

                def alter(manifest):
                    manifest["constraints"][2][field] = hostile_value

                self.rewrite_manifest(root, alter)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code, "RESOURCE_CLASSIFICATION_CONSTRAINT"
                )

    def test_bootstrap_document_classification_binds_all_five_branches(self):
        _, _, baseline_source_bytes = _source_inventory(ROOT)
        baseline_predecessor_sites = _source_bound_inventory(
            baseline_source_bytes
        )
        baseline_binding_sites = _source_bound_binding_inventory(
            baseline_source_bytes, baseline_predecessor_sites
        )

        image_source = baseline_source_bytes[
            "src/edgelab/runtime_v2_image.py"
        ]
        tree = ast.parse(image_source)
        stores = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Name)
            and node.id == "MAX_BOOTSTRAP_DOCUMENT_BYTES"
            and isinstance(node.ctx, ast.Store)
        ]
        loads = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Name)
            and node.id == "MAX_BOOTSTRAP_DOCUMENT_BYTES"
            and isinstance(node.ctx, ast.Load)
        ]
        self.assertEqual(len(stores), 1)
        self.assertEqual(len(loads), 5)

        root = self.copy_inputs()
        source = root / "src/edgelab/runtime_v2_image.py"
        original = source.read_bytes()
        mutated = original.replace(
            b"MAX_BOOTSTRAP_DOCUMENT_BYTES = 1_048_576",
            b"MAX_BOOTSTRAP_DOCUMENT_BYTES = 1_048_575 + 1",
            1,
        )
        self.assertNotEqual(mutated, original)
        source.write_bytes(mutated)
        with self.assertRaises(ReadinessError) as caught:
            self.build_with_refreshed_ordinary_source_bindings(
                root, baseline_binding_sites
            )
        self.assertEqual(
            caught.exception.code, "RESOURCE_CLASSIFICATION_SITE_MISSING"
        )

        row_attacks = (
            (
                "verifier_dependency_closure",
                b'("verifier_dependency_closure", '
                b'captured["verifier_dependency_closure"], '
                b'MAX_BOOTSTRAP_DOCUMENT_BYTES)',
                b'("verifier_dependency_closure", '
                b'captured["verifier_dependency_closure"], MAX_EVENT_BYTES)',
                "byte_fields",
            ),
            (
                "manifest",
                b'("manifest", captured["manifest"], '
                b'MAX_BOOTSTRAP_DOCUMENT_BYTES)',
                b'("manifest", captured["manifest"], MAX_EVENT_BYTES)',
                "byte_fields",
            ),
            (
                "attachment",
                b'("attachment", captured["attachment"], '
                b'MAX_BOOTSTRAP_DOCUMENT_BYTES)',
                b'("attachment", captured["attachment"], MAX_EVENT_BYTES)',
                "byte_fields",
            ),
            (
                "checkpoint_copies",
                b'("checkpoint_copies", captured["checkpoint_copies"], '
                b'MAX_BOOTSTRAP_DOCUMENT_BYTES)',
                b'("checkpoint_copies", captured["checkpoint_copies"], '
                b'MAX_EVENT_BYTES)',
                "byte_collections",
            ),
            (
                "selector_history",
                b'("selector_history", captured["selector_history"], '
                b'MAX_BOOTSTRAP_DOCUMENT_BYTES)',
                b'("selector_history", captured["selector_history"], '
                b'MAX_EVENT_BYTES)',
                "byte_collections",
            ),
        )
        for branch, old, new, table_name in row_attacks:
            with self.subTest(row=branch):
                root = self.copy_inputs()
                source = root / "src/edgelab/runtime_v2_image.py"
                original = source.read_bytes()
                mutated = original.replace(old, new, 1)
                self.assertNotEqual(mutated, original)
                source.write_bytes(mutated)
                hostile_sites = [dict(item) for item in baseline_binding_sites]
                for index, item in enumerate(hostile_sites):
                    if item.get("table_name") != table_name:
                        continue
                    item["site_id"] = hashlib.sha256(
                        f"bootstrap-{branch}-{index}".encode("ascii")
                    ).hexdigest()
                    item["table_assignment_ast_sha256"] = hashlib.sha256(
                        f"bootstrap-table-{branch}".encode("ascii")
                    ).hexdigest()
                hostile = next(
                    item for item in hostile_sites
                    if item.get("branch_key") == branch
                )
                hostile.update({
                    "ast_sha256": hashlib.sha256(
                        f"bootstrap-row-{branch}".encode("ascii")
                    ).hexdigest(),
                    "expression": hostile["expression"].replace(
                        "MAX_BOOTSTRAP_DOCUMENT_BYTES", "MAX_EVENT_BYTES"
                    ),
                    "maximum_expression": "MAX_EVENT_BYTES",
                })
                with self.assertRaises(ReadinessError) as caught:
                    self.build_with_refreshed_ordinary_source_bindings(
                        root, hostile_sites
                    )
                self.assertEqual(
                    caught.exception.code,
                    "RESOURCE_CLASSIFICATION_SITE_MISSING",
                )

        structural_attacks = (
            (
                "byte_fields_comparator",
                b"if maximum is not None and len(value) > maximum:",
                b"if maximum is not None and len(value) >= maximum:",
                "byte_fields",
            ),
            (
                "byte_collections_comparator",
                b"if len(value) > maximum:",
                b"if len(value) >= maximum:",
                "byte_collections",
            ),
            (
                "byte_fields_loop",
                b"for name, value, maximum in byte_fields:",
                b"for name, value, maximum in tuple(byte_fields):",
                "byte_fields",
            ),
            (
                "byte_collections_loop",
                b"for name, values, maximum in byte_collections:",
                b"for name, values, maximum in tuple(byte_collections):",
                "byte_collections",
            ),
        )
        for label, old, new, table_name in structural_attacks:
            with self.subTest(structure=label):
                root = self.copy_inputs()
                source = root / "src/edgelab/runtime_v2_image.py"
                original = source.read_bytes()
                mutated = original.replace(old, new, 1)
                self.assertNotEqual(mutated, original)
                source.write_bytes(mutated)
                hostile_sites = [dict(item) for item in baseline_binding_sites]
                for index, item in enumerate(hostile_sites):
                    if item.get("table_name") != table_name:
                        continue
                    item.update({
                        "comparator_site_id": hashlib.sha256(
                            f"{label}-comparator".encode("ascii")
                        ).hexdigest(),
                        "loop_ast_sha256": hashlib.sha256(
                            f"{label}-loop".encode("ascii")
                        ).hexdigest(),
                        "site_id": hashlib.sha256(
                            f"{label}-site-{index}".encode("ascii")
                        ).hexdigest(),
                    })
                with self.assertRaises(ReadinessError) as caught:
                    self.build_with_refreshed_ordinary_source_bindings(
                        root, hostile_sites
                    )
                self.assertEqual(
                    caught.exception.code,
                    "RESOURCE_CLASSIFICATION_SITE_MISSING",
                )

        for suffix in (
            b"\n\ndef _bootstrap_limit_extra_read():\n"
            b"    return MAX_BOOTSTRAP_DOCUMENT_BYTES\n",
            b"\n\ndef _bootstrap_limit_extra_store():\n"
            b"    MAX_BOOTSTRAP_DOCUMENT_BYTES = 1\n"
            b"    return None\n",
        ):
            with self.subTest(name_cardinality=suffix.splitlines()[2]):
                root = self.copy_inputs()
                source = root / "src/edgelab/runtime_v2_image.py"
                source.write_bytes(source.read_bytes() + suffix)
                self.refresh_source_bindings(root)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code,
                    "RESOURCE_CLASSIFICATION_NAME_CARDINALITY",
                )

        semantic_attacks = (
            (
                b'            findings.add("IMAGE_ITEM_BYTE_LIMIT", name, "/")\n',
                b'            findings.add("WRONG_BOOTSTRAP_LIMIT", name, "/")\n',
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
            ),
            (
                b'                findings.add("IMAGE_ITEM_BYTE_LIMIT", name, coordinate)\n',
                b'                findings.add("WRONG_BOOTSTRAP_LIMIT", name, coordinate)\n',
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
            ),
            (
                b"    if not violations:\n",
                b"    if True:\n",
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
            ),
            (
                b'    authorizing_use: str = field(default="DENY", init=False)\n',
                b'    authorizing_use: str = field(default="ALLOW", init=False)\n',
                "RESOURCE_CLASSIFICATION_MODULE_SHAPE",
            ),
        )
        for old, new, expected_code in semantic_attacks:
            with self.subTest(semantic_attack=old[:40]):
                root = self.copy_inputs()
                source = root / "src/edgelab/runtime_v2_image.py"
                original = source.read_bytes()
                mutated = original.replace(old, new, 1)
                self.assertNotEqual(mutated, original)
                source.write_bytes(mutated)
                with self.assertRaises(ReadinessError) as caught:
                    self.build_with_refreshed_ordinary_source_bindings(
                        root, baseline_binding_sites
                    )
                self.assertEqual(caught.exception.code, expected_code)

    def test_schema_registry_classification_binds_both_implementations(self):
        _, _, baseline_source_bytes = _source_inventory(ROOT)
        baseline_predecessor_sites = _source_bound_inventory(
            baseline_source_bytes
        )
        baseline_binding_sites = _source_bound_binding_inventory(
            baseline_source_bytes, baseline_predecessor_sites
        )

        # Equal-valued rewrites must not acquire semantic authority merely by
        # refreshing the ordinary discovery census and classification digest.
        for relative in (
            "src/edgelab/runtime_v2_image.py",
            "src/edgelab/runtime_v2_verifier.py",
        ):
            with self.subTest(same_value_definition=relative):
                root = self.copy_inputs()
                source = root / relative
                original = source.read_bytes()
                mutated = original.replace(
                    b"MAX_SCHEMA_REGISTRY_BYTES = 262_144",
                    b"MAX_SCHEMA_REGISTRY_BYTES = 131_072 + 131_072",
                    1,
                )
                self.assertNotEqual(mutated, original)
                source.write_bytes(mutated)
                with self.assertRaises(ReadinessError) as caught:
                    self.build_with_refreshed_ordinary_source_bindings(
                        root, baseline_binding_sites
                    )
                self.assertEqual(
                    caught.exception.code,
                    "RESOURCE_CLASSIFICATION_SITE_MISSING",
                )

        root = self.copy_inputs()
        source = root / "src/edgelab/runtime_v2_image.py"
        original = source.read_bytes()
        mutated = original.replace(
            b'("schema_registry", captured["schema_registry"], '
            b'MAX_SCHEMA_REGISTRY_BYTES)',
            b'("schema_registry", captured["schema_registry"], '
            b'MAX_SCHEMA_DOCUMENT_BYTES)',
            1,
        )
        self.assertNotEqual(mutated, original)
        source.write_bytes(mutated)
        hostile_binding_sites = [dict(item) for item in baseline_binding_sites]
        for index, item in enumerate(hostile_binding_sites):
            if item.get("table_name") != "byte_fields":
                continue
            item["site_id"] = hashlib.sha256(
                f"hostile-registry-row-{index}".encode("ascii")
            ).hexdigest()
            item["table_assignment_ast_sha256"] = "c" * 64
        hostile_registry_site = next(
            item for item in hostile_binding_sites
            if item.get("branch_key") == "schema_registry"
        )
        hostile_registry_site.update({
            "ast_sha256": "a" * 64,
            "expression": (
                "('schema_registry', captured['schema_registry'], "
                "MAX_SCHEMA_DOCUMENT_BYTES)"
            ),
            "maximum_expression": "MAX_SCHEMA_DOCUMENT_BYTES",
            "site_id": "b" * 64,
        })
        with self.assertRaises(ReadinessError) as caught:
            self.build_with_refreshed_ordinary_source_bindings(
                root, hostile_binding_sites
            )
        self.assertEqual(
            caught.exception.code, "RESOURCE_CLASSIFICATION_SITE_MISSING"
        )

        root = self.copy_inputs()
        source = root / "src/edgelab/runtime_v2_image.py"
        original = source.read_bytes()
        mutated = original.replace(
            b"if maximum is not None and len(value) > maximum:",
            b"if maximum is not None and len(value) >= maximum:",
            1,
        )
        self.assertNotEqual(mutated, original)
        source.write_bytes(mutated)
        refreshed_comparator_sites = [
            dict(item) for item in baseline_binding_sites
        ]
        for index, item in enumerate(refreshed_comparator_sites):
            if item.get("table_name") != "byte_fields":
                continue
            item.update({
                "comparator_site_id": f"{index + 1:x}" * 64,
                "loop_ast_sha256": f"{index + 2:x}" * 64,
                "site_id": f"{index + 3:x}" * 64,
            })
        with self.assertRaises(ReadinessError) as caught:
            self.build_with_refreshed_ordinary_source_bindings(
                root, refreshed_comparator_sites
            )
        self.assertEqual(
            caught.exception.code, "RESOURCE_CLASSIFICATION_SITE_MISSING"
        )

        verifier_site_attacks = (
            (
                b"len(image.schema_registry) > MAX_SCHEMA_REGISTRY_BYTES",
                b"len(image.schema_registry) > MAX_SCHEMA_DOCUMENT_BYTES",
            ),
            (
                b"len(image.schema_registry) > MAX_SCHEMA_REGISTRY_BYTES",
                b"len(image.schema_registry) >= MAX_SCHEMA_REGISTRY_BYTES",
            ),
        )
        for old, new in verifier_site_attacks:
            with self.subTest(verifier_enforcement=new):
                root = self.copy_inputs()
                source = root / "src/edgelab/runtime_v2_verifier.py"
                original = source.read_bytes()
                mutated = original.replace(old, new, 1)
                self.assertNotEqual(mutated, original)
                source.write_bytes(mutated)
                with self.assertRaises(ReadinessError) as caught:
                    self.build_with_refreshed_ordinary_source_bindings(
                        root, baseline_binding_sites
                    )
                self.assertEqual(
                    caught.exception.code,
                    "RESOURCE_CLASSIFICATION_SITE_MISSING",
                )

        for relative, suffix in (
            (
                "src/edgelab/runtime_v2_image.py",
                b"\n\ndef _registry_limit_extra_read():\n"
                b"    return MAX_SCHEMA_REGISTRY_BYTES\n",
            ),
            (
                "src/edgelab/runtime_v2_image.py",
                b"\n\ndef _registry_limit_extra_store():\n"
                b"    MAX_SCHEMA_REGISTRY_BYTES = 1\n"
                b"    return None\n",
            ),
            (
                "src/edgelab/runtime_v2_verifier.py",
                b"\n\ndef _registry_limit_extra_read():\n"
                b"    return MAX_SCHEMA_REGISTRY_BYTES\n",
            ),
            (
                "src/edgelab/runtime_v2_verifier.py",
                b"\n\ndef _registry_limit_extra_store():\n"
                b"    MAX_SCHEMA_REGISTRY_BYTES = 1\n"
                b"    return None\n",
            ),
        ):
            with self.subTest(name_cardinality=(relative, suffix.splitlines()[2])):
                root = self.copy_inputs()
                source = root / relative
                source.write_bytes(source.read_bytes() + suffix)
                self.refresh_source_bindings(root)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code,
                    "RESOURCE_CLASSIFICATION_NAME_CARDINALITY",
                )

        semantic_attacks = (
            (
                "src/edgelab/runtime_v2_image.py",
                b"if maximum is not None and len(value) > maximum:",
                b"if maximum is not None and len(value) >= maximum:",
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
                True,
            ),
            (
                "src/edgelab/runtime_v2_image.py",
                b"        if maximum is not None and len(value) > maximum:\n"
                b'            findings.add("IMAGE_ITEM_BYTE_LIMIT", name, "/")\n',
                b"        if maximum is not None and len(value) > maximum:\n"
                b'            findings.add("WRONG_REGISTRY_LIMIT", name, "/")\n',
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
                True,
            ),
            (
                "src/edgelab/runtime_v2_image.py",
                b"    if not violations:\n",
                b"    if True:\n",
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
                False,
            ),
            (
                "src/edgelab/runtime_v2_image.py",
                b'    authorizing_use: str = field(default="DENY", init=False)\n',
                b'    authorizing_use: str = field(default="ALLOW", init=False)\n',
                "RESOURCE_CLASSIFICATION_MODULE_SHAPE",
                False,
            ),
            (
                "src/edgelab/runtime_v2_verifier.py",
                b'_finding("SCHEMA_REGISTRY_TOO_LARGE", "schema_registry", "/")',
                b'_finding("WRONG_REGISTRY_LIMIT", "schema_registry", "/")',
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
                False,
            ),
            (
                "src/edgelab/runtime_v2_verifier.py",
                b'        findings.append(_finding("SCHEMA_REGISTRY_TOO_LARGE", '
                b'"schema_registry", "/"))\n'
                b"        return findings, False\n",
                b'        findings.append(_finding("SCHEMA_REGISTRY_TOO_LARGE", '
                b'"schema_registry", "/"))\n',
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
                False,
            ),
            (
                "src/edgelab/runtime_v2_verifier.py",
                b'    authorizing_use: str = field(default="DENY", init=False)\n',
                b'    authorizing_use: str = field(default="ALLOW", init=False)\n',
                "RESOURCE_CLASSIFICATION_MODULE_SHAPE",
                False,
            ),
        )
        for relative, old, new, expected_code, binding_extractor_drift in (
            semantic_attacks
        ):
            with self.subTest(registry_semantics=(relative, old[:32])):
                root = self.copy_inputs()
                source = root / relative
                original = source.read_bytes()
                mutated = original.replace(old, new, 1)
                self.assertNotEqual(mutated, original)
                source.write_bytes(mutated)
                with self.assertRaises(ReadinessError) as caught:
                    if binding_extractor_drift:
                        self.build_with_refreshed_ordinary_source_bindings(
                            root, baseline_binding_sites
                        )
                    else:
                        self.refresh_source_bindings(root)
                        build_report(root)
                self.assertEqual(caught.exception.code, expected_code)

        for field, hostile_value in (
            ("semantic_bindings", []),
            ("evidence_inputs", []),
        ):
            with self.subTest(manifest_field=field):
                root = self.copy_inputs()

                def alter(manifest):
                    manifest["constraints"][5][field] = hostile_value

                self.rewrite_manifest(root, alter)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code, "RESOURCE_CLASSIFICATION_CONSTRAINT"
                )

    def test_schema_document_classification_binds_both_implementations(self):
        attacks = (
            (
                "src/edgelab/runtime_v2_image.py",
                b"if body_size > MAX_SCHEMA_DOCUMENT_BYTES:",
                b"if body_size >= MAX_SCHEMA_DOCUMENT_BYTES:",
                "RESOURCE_DISCOVERY_V2_IDENTITY",
            ),
            (
                "src/edgelab/runtime_v2_verifier.py",
                b"if len(record.canonical_json) > MAX_SCHEMA_DOCUMENT_BYTES:",
                b"if len(record.canonical_json) >= MAX_SCHEMA_DOCUMENT_BYTES:",
                "RESOURCE_DISCOVERY_V2_IDENTITY",
            ),
            (
                "src/edgelab/runtime_v2_image.py",
                b"if body_size > MAX_SCHEMA_DOCUMENT_BYTES:\n",
                b"if False and body_size > MAX_SCHEMA_DOCUMENT_BYTES:\n",
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
            ),
            (
                "src/edgelab/runtime_v2_verifier.py",
                b"if len(record.canonical_json) > MAX_SCHEMA_DOCUMENT_BYTES:\n",
                b"if False and len(record.canonical_json) > MAX_SCHEMA_DOCUMENT_BYTES:\n",
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
            ),
            (
                "src/edgelab/runtime_v2_image.py",
                b'findings.add("IMAGE_ITEM_BYTE_LIMIT", "schema_documents", ',
                b'findings.add("WRONG_LIMIT", "schema_documents", ',
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
            ),
            (
                "src/edgelab/runtime_v2_verifier.py",
                b'_finding("SCHEMA_DOCUMENT_TOO_LARGE", "schema_documents", ',
                b'_finding("WRONG_LIMIT", "schema_documents", ',
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
            ),
            (
                "src/edgelab/runtime_v2_image.py",
                b"                body_size = len(body)\n",
                b"                body_size = len(body[:True])\n",
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
            ),
            (
                "src/edgelab/runtime_v2_verifier.py",
                b"    if findings:\n        return findings, False\n",
                b"    if False:\n        return findings, False\n",
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
            ),
            (
                "src/edgelab/runtime_v2_verifier.py",
                b"    findings.extend(bundle_findings)\n",
                b"    findings.extend(())\n",
                "RESOURCE_CLASSIFICATION_MODULE_SHAPE",
            ),
            (
                "src/edgelab/runtime_v2_verifier.py",
                b'    authorizing_use: str = field(default="DENY", init=False)\n',
                b'    authorizing_use: str = field(default="ALLOW", init=False)\n',
                "RESOURCE_CLASSIFICATION_MODULE_SHAPE",
            ),
            (
                "src/edgelab/runtime_v2_verifier.py",
                b"\n_REQUIRED_DESCRIPTOR_TABLES = (",
                b"\nlen = lambda value: value.__len__()\n\n_REQUIRED_DESCRIPTOR_TABLES = (",
                "RESOURCE_CLASSIFICATION_MODULE_SHAPE",
            ),
        )
        for relative, old, new, expected_code in attacks:
            with self.subTest(path=relative, attack=old[:36]):
                root = self.copy_inputs()
                source = root / relative
                mutated = source.read_bytes().replace(old, new, 1)
                self.assertNotEqual(mutated, source.read_bytes())
                source.write_bytes(mutated)
                self.refresh_source_bindings(root)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(caught.exception.code, expected_code)

        for relative in (
            "src/edgelab/runtime_v2_image.py",
            "src/edgelab/runtime_v2_verifier.py",
        ):
            with self.subTest(path=relative, attack="constant divergence"):
                root = self.copy_inputs()
                source = root / relative
                mutated = source.read_bytes().replace(
                    b"MAX_SCHEMA_DOCUMENT_BYTES = 262_144",
                    b"MAX_SCHEMA_DOCUMENT_BYTES = 262_143",
                    1,
                )
                self.assertNotEqual(mutated, source.read_bytes())
                source.write_bytes(mutated)
                self.refresh_source_bindings(root)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code, "RESOURCE_LIMIT_CONFLICT"
                )

        for relative in (
            "src/edgelab/runtime_v2_image.py",
            "src/edgelab/runtime_v2_verifier.py",
        ):
            with self.subTest(path=relative, attack="extra constant read"):
                root = self.copy_inputs()
                source = root / relative
                source.write_bytes(
                    source.read_bytes()
                    + b"\ndef _extra_limit_read():\n"
                    + b"    return MAX_SCHEMA_DOCUMENT_BYTES\n"
                )
                self.refresh_source_bindings(root)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code,
                    "RESOURCE_CLASSIFICATION_NAME_CARDINALITY",
                )

    def test_schema_ref_node_classification_binds_exact_semantics(self):
        attacks = (
            (
                b"if len(edges) > MAX_SCHEMA_REF_NODES:",
                b"if len(edges) >= MAX_SCHEMA_REF_NODES:",
                "RESOURCE_DISCOVERY_V2_IDENTITY",
            ),
            (
                b"if len(edges) > MAX_SCHEMA_REF_NODES:\n",
                b"if False and len(edges) > MAX_SCHEMA_REF_NODES:\n",
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
            ),
            (
                b"if len(edges) > MAX_SCHEMA_REF_NODES:",
                b"if len(definitions) > MAX_SCHEMA_REF_NODES:",
                "RESOURCE_DISCOVERY_V2_IDENTITY",
            ),
            (
                b"    if len(edges) > MAX_SCHEMA_REF_NODES:\n",
                b"    edges.clear()\n"
                b"    if len(edges) > MAX_SCHEMA_REF_NODES:\n",
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
            ),
            (
                b'        add("SCHEMA_REF_GRAPH_TOO_LARGE", "/$defs")\n',
                b'        add("WRONG_GRAPH_LIMIT", "/$defs")\n',
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
            ),
            (
                b"        add(\"SCHEMA_REF_GRAPH_TOO_LARGE\", \"/$defs\")\n"
                b"        return findings\n",
                b"        add(\"SCHEMA_REF_GRAPH_TOO_LARGE\", \"/$defs\")\n"
                b"        pass\n",
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
            ),
            (
                b"    for start in sorted(edges):\n",
                b"    for start in ():\n",
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
            ),
            (
                b"    findings.extend(bundle_findings)\n",
                b"    findings.extend(())\n",
                "RESOURCE_CLASSIFICATION_MODULE_SHAPE",
            ),
            (
                b'    authorizing_use: str = field(default="DENY", init=False)\n',
                b'    authorizing_use: str = field(default="ALLOW", init=False)\n',
                "RESOURCE_CLASSIFICATION_MODULE_SHAPE",
            ),
            (
                b"\n_REQUIRED_DESCRIPTOR_TABLES = (",
                b"\nlen = lambda value: value.__len__()\n\n_REQUIRED_DESCRIPTOR_TABLES = (",
                "RESOURCE_CLASSIFICATION_MODULE_SHAPE",
            ),
        )
        for old, new, expected_code in attacks:
            with self.subTest(attack=old[:48]):
                root = self.copy_inputs()
                source = root / "src/edgelab/runtime_v2_verifier.py"
                original = source.read_bytes()
                mutated = original.replace(old, new, 1)
                self.assertNotEqual(mutated, original)
                source.write_bytes(mutated)
                self.refresh_source_bindings(root)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(caught.exception.code, expected_code)

        root = self.copy_inputs()
        source = root / "src/edgelab/runtime_v2_verifier.py"
        original = source.read_bytes()
        mutated = original.replace(
            b"MAX_SCHEMA_REF_NODES = 4_096",
            b"MAX_SCHEMA_REF_NODES = 4_095",
            1,
        )
        self.assertNotEqual(mutated, original)
        source.write_bytes(mutated)
        self.refresh_source_bindings(root)
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(
            caught.exception.code, "RESOURCE_DISCOVERY_V2_IDENTITY"
        )

        root = self.copy_inputs()
        source = root / "src/edgelab/runtime_v2_verifier.py"
        source.write_bytes(
            source.read_bytes()
            + b"\ndef _extra_schema_ref_limit_read():\n"
            + b"    return MAX_SCHEMA_REF_NODES\n"
        )
        self.refresh_source_bindings(root)
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(
            caught.exception.code, "RESOURCE_CLASSIFICATION_NAME_CARDINALITY"
        )

    def test_v8_classification_binds_predecessor_link_records(self):
        attacks = (
            ("predecessor_manifest", "raw_sha256", "0" * 64),
            ("predecessor_manifest", "classification_manifest_sha256", "1" * 64),
            (
                "predecessor_schema",
                "path",
                "schemas/m0-3a-runtime-v2-resource-classification.v0.schema.json",
            ),
        )
        for record, field, hostile_value in attacks:
            with self.subTest(record=record, field=field):
                root = self.copy_inputs()

                def alter(manifest):
                    manifest[record][field] = hostile_value

                self.rewrite_manifest(root, alter)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code, "RESOURCE_CLASSIFICATION_BINDING"
                )

    def test_v8_classification_binds_v7_v6_and_v5_ancestor_links(self):
        for record, field in (
            ("predecessor_manifest", "raw_sha256"),
            ("predecessor_schema", "raw_sha256"),
        ):
            with self.subTest(manifest="v7", record=record, field=field):
                root = self.copy_inputs()

                def mutate_v7(manifest):
                    manifest[record][field] = "0" * 64

                v7_expected = self.rewrite_versioned_classification_manifest(
                    root,
                    RESOURCE_CLASSIFICATION_PREDECESSOR_MANIFEST,
                    7,
                    mutate_v7,
                )
                with mock.patch.dict(
                    RESOURCE_CLASSIFICATION_PREDECESSOR_MANIFEST,
                    v7_expected,
                    clear=True,
                ):
                    with self.assertRaises(ReadinessError) as caught:
                        build_report(root)
                self.assertEqual(
                    caught.exception.code,
                    "RESOURCE_CLASSIFICATION_ANCESTOR_BINDING",
                )

        for record, field in (
            ("predecessor_manifest", "raw_sha256"),
            ("predecessor_schema", "raw_sha256"),
        ):
            with self.subTest(manifest="v6", record=record, field=field):
                root = self.copy_inputs()

                def mutate_v6(manifest):
                    manifest[record][field] = "0" * 64

                v6_expected = self.rewrite_versioned_classification_manifest(
                    root,
                    RESOURCE_CLASSIFICATION_ANCESTORS[0],
                    6,
                    mutate_v6,
                )

                def link_v7_to_mutated_v6(manifest):
                    manifest["predecessor_manifest"] = dict(v6_expected)

                v7_expected = self.rewrite_versioned_classification_manifest(
                    root,
                    RESOURCE_CLASSIFICATION_PREDECESSOR_MANIFEST,
                    7,
                    link_v7_to_mutated_v6,
                )
                with mock.patch.dict(
                    RESOURCE_CLASSIFICATION_PREDECESSOR_MANIFEST,
                    v7_expected,
                    clear=True,
                ), mock.patch.dict(
                    RESOURCE_CLASSIFICATION_ANCESTORS[0],
                    v6_expected,
                    clear=True,
                ):
                    with self.assertRaises(ReadinessError) as caught:
                        build_report(root)
                self.assertEqual(
                    caught.exception.code,
                    "RESOURCE_CLASSIFICATION_ANCESTOR_BINDING",
                )

    def test_checker_source_has_no_write_network_git_or_package_metadata_path(self):
        path = ROOT / "tools" / "check_runtime_v2_release_readiness.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imports = {
            alias.name.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        } | {
            (node.module or "").split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        }
        self.assertTrue(imports.isdisjoint({
            "importlib", "requests", "socket", "subprocess", "urllib",
        }))
        attributes = {
            node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
        }
        self.assertTrue(attributes.isdisjoint({
            "write_bytes", "write_text", "rename", "replace", "unlink",
        }))
        source = path.read_text(encoding="utf-8")
        for token in ("git ", ".git", "importlib.metadata", "urlopen("):
            self.assertNotIn(token, source)


if __name__ == "__main__":
    unittest.main()
