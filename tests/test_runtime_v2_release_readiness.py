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

from tools.check_runtime_v2_release_readiness import (
    BOOTSTRAP_SCHEMAS,
    CONTENT_ASSETS,
    PIN_BEGIN_MARKER,
    PIN_END_MARKER,
    PIN_REPLACEMENT,
    RETAINED_SCHEMAS,
    ReadinessError,
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
        } | {path for _, _, path in CONTENT_ASSETS}
        for relative in paths:
            source = ROOT / relative
            target = temporary / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        return temporary

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
        limits = {
            item["name"]: item["value"]
            for item in build_report(root)["inventory"]["resource_limits"]
        }
        self.assertEqual(limits["INITIAL_SELECTOR_MAXIMUM"], 50_002)

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
        changed = build_report(root)
        self.assertNotEqual(
            baseline["inventory"]["source_closure"],
            changed["inventory"]["source_closure"],
        )
        self.assertEqual(changed["authorizing_use"], "DENY")
        self.assertEqual(changed["status"], "BLOCKED")

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
