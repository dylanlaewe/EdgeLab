"""Feasibility and adversarial tests for the candidate-only proof compiler."""
from __future__ import annotations

import ast
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator

from src.edgelab.validate import ROOT
import src.edgelab.proof_candidate_verifier as candidate_verifier
from src.edgelab.proof_candidate_verifier import (
    CandidatePackage,
    PackageFile,
    verify_candidate_package,
)
import tools.compile_runtime_v2_minlength_candidates as compiler
from tools.compile_runtime_v2_minlength_candidates import (
    ProofCompilerError,
    canonical_json,
    compile_candidate_ledger,
    verify_candidate_ledger,
)
from tools.verify_runtime_v2_candidate_package import (
    PACKAGE_PATHS,
    build_package,
)


class RuntimeV2ProofCompilerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.output = compile_candidate_ledger()
        cls.package = build_package()

    def reseal(self, value):
        value["witness_ledger_sha256"] = compiler._domain_digest(
            compiler.LEDGER_DOMAIN, value["witnesses"]
        )
        value["compiler_output_sha256"] = compiler._domain_digest(
            compiler.OUTPUT_DOMAIN,
            {key: item for key, item in value.items() if key != "compiler_output_sha256"},
        )

    def test_exact_coverage_counts_and_deny_only_boundary(self):
        output = self.output
        self.assertEqual(output["frozen_census"]["inspected_site_count"], 721)
        self.assertEqual(output["frozen_census"]["source_site_count"], 425)
        self.assertEqual(output["frozen_census"]["schema_site_count"], 296)
        self.assertEqual(
            output["coverage"],
            {
                "inspected_site_count": 721,
                "accepted_total_site_count": 87,
                "currently_unclassified_site_count": 634,
                "accepted_family_site_count": 10,
                "candidate_only_site_count": 25,
                "ambiguous_site_count": 0,
                "nonmatching_site_count": 686,
                "unclassified_without_family_candidate_count": 609,
                "bidirectional_coverage": "EXACT",
                "unique_site_identities": True,
            },
        )
        self.assertEqual(len(output["witnesses"]), 721)
        self.assertEqual(output["authorizing_use"], "DENY")
        self.assertEqual(output["governance_equivalence"], "NOT_ESTABLISHED")
        self.assertFalse(
            output["accepted_classification_manifest"]["accepted_count_changed"]
        )
        self.assertTrue(all(
            witness["authorizing_use"] == "DENY"
            for witness in output["witnesses"]
        ))

    def test_manual_minlength_evidence_is_reproduced_exactly(self):
        comparison = self.output["manual_evidence_comparison"]
        self.assertEqual(comparison["status"], "EXACT_MATCH")
        self.assertEqual(comparison["matched_site_count"], 10)
        self.assertEqual(comparison["mismatched_site_ids"], [])
        accepted = [
            witness for witness in self.output["witnesses"]
            if witness["rule_evaluation"]["disposition"]
            == "ACCEPTED_REFERENCE_MATCH"
        ]
        self.assertEqual(len(accepted), 10)
        self.assertTrue(all(
            witness["accepted_reference"]["status"] == "EXACT_SEMANTIC_MATCH"
            and witness["rule_evaluation"]["derived_semantics"]["metric"]
            == "UNICODE_CODE_POINT_COUNT"
            and witness["rule_evaluation"]["derived_semantics"]["operator"] == ">="
            for witness in accepted
        ))

    def test_new_sites_are_candidate_only_and_never_accepted(self):
        candidates = [
            witness for witness in self.output["witnesses"]
            if witness["rule_evaluation"]["disposition"] == "CANDIDATE_ONLY"
        ]
        self.assertEqual(len(candidates), 25)
        self.assertTrue(all(
            witness["namespace"] == "SCHEMA"
            and witness["observed_syntax"]["keyword"] == "minLength"
            and witness["accepted_reference"] == "UNCLASSIFIED"
            and witness["authorizing_use"] == "DENY"
            for witness in candidates
        ))

    def test_compilation_and_cli_bytes_are_deterministic(self):
        first = canonical_json(self.output) + b"\n"
        second = canonical_json(compile_candidate_ledger()) + b"\n"
        self.assertEqual(first, second)
        completed = subprocess.run(
            [sys.executable, str(ROOT / "tools/compile_runtime_v2_minlength_candidates.py")],
            cwd=ROOT,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertEqual(completed.stdout, first)

    def test_exact_candidate_verifies_without_boolean_authority(self):
        result = verify_candidate_ledger(copy.deepcopy(self.output))
        self.assertEqual(result.status, "VALID_CANDIDATE_ONLY")
        self.assertEqual(result.authorizing_use, "DENY")
        self.assertEqual(result.inspected_site_count, 721)
        self.assertEqual(result.candidate_only_site_count, 25)
        with self.assertRaises(TypeError):
            bool(result)

    def test_forged_semantics_and_positive_authority_reject(self):
        forged = copy.deepcopy(self.output)
        candidate = next(
            witness for witness in forged["witnesses"]
            if witness["rule_evaluation"]["disposition"] == "CANDIDATE_ONLY"
        )
        candidate["rule_evaluation"]["derived_semantics"]["operator"] = "<="
        self.reseal(forged)
        with self.assertRaisesRegex(ProofCompilerError, "OUTPUT_MISMATCH"):
            verify_candidate_ledger(forged)

        positive = copy.deepcopy(self.output)
        positive["authorizing_use"] = "ALLOW"
        self.reseal(positive)
        with self.assertRaisesRegex(ProofCompilerError, "OUTPUT_AUTHORITY"):
            verify_candidate_ledger(positive)

    def test_duplicate_omission_and_reordering_reject(self):
        duplicate = copy.deepcopy(self.output)
        duplicate["witnesses"][-1] = copy.deepcopy(duplicate["witnesses"][0])
        self.reseal(duplicate)
        with self.assertRaisesRegex(ProofCompilerError, "OUTPUT_DUPLICATE"):
            verify_candidate_ledger(duplicate)

        omitted = copy.deepcopy(self.output)
        omitted["witnesses"].pop()
        self.reseal(omitted)
        with self.assertRaisesRegex(ProofCompilerError, "OUTPUT_CARDINALITY"):
            verify_candidate_ledger(omitted)

        reordered = copy.deepcopy(self.output)
        reordered["witnesses"][0], reordered["witnesses"][1] = (
            reordered["witnesses"][1], reordered["witnesses"][0]
        )
        self.reseal(reordered)
        with self.assertRaisesRegex(ProofCompilerError, "OUTPUT_ORDER"):
            verify_candidate_ledger(reordered)

    def test_stale_or_forged_frozen_census_rejects(self):
        real_report = compiler.build_report(ROOT)
        stale = copy.deepcopy(real_report)
        discovery = stale["inventory"]["resource_inventory_discovery"]
        discovery["source_inputs"][0]["raw_sha256"] = "0" * 64
        with patch.object(compiler, "build_report", return_value=stale):
            with self.assertRaisesRegex(ProofCompilerError, "FROZEN_SOURCE_INPUTS"):
                compile_candidate_ledger()

        forged = copy.deepcopy(real_report)
        sites = forged["inventory"]["resource_inventory_discovery"]["schema_bound_sites"]
        sites[0]["value"] += 1
        with patch.object(compiler, "build_report", return_value=forged):
            with self.assertRaisesRegex(ProofCompilerError, "FROZEN_SCHEMA_SITES"):
                compile_candidate_ledger()

    def test_ambiguous_schema_conditions_are_explicit_and_cannot_be_forged(self):
        ambiguous_document = {
            "$schema": compiler.DRAFT_2020_12,
            "$id": "urn:test",
            "$defs": {"x": {"$dynamicRef": "#x"}},
        }
        self.assertEqual(
            compiler._schema_ambiguities(ambiguous_document, "urn:test"),
            ["DYNAMIC_REFERENCE_UNSUPPORTED"],
        )
        forged = copy.deepcopy(self.output)
        witness = next(
            item for item in forged["witnesses"]
            if item["rule_evaluation"]["disposition"] == "NONMATCHING"
        )
        witness["rule_evaluation"] = {
            "disposition": "AMBIGUOUS",
            "reason_codes": ["INVENTED_AMBIGUITY"],
            "derived_semantics": None,
        }
        self.reseal(forged)
        with self.assertRaisesRegex(ProofCompilerError, "OUTPUT_MISMATCH"):
            verify_candidate_ledger(forged)

    def test_cli_verifies_saved_candidate_as_deny_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.json"
            path.write_bytes(canonical_json(self.output))
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "tools/compile_runtime_v2_minlength_candidates.py"),
                    "--verify",
                    str(path),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        verification = json.loads(completed.stdout)
        self.assertEqual(verification["status"], "VALID_CANDIDATE_ONLY")
        self.assertEqual(verification["authorizing_use"], "DENY")

    def test_rule_registry_and_closure_are_strict_self_bound_candidates(self):
        registry_schema = json.loads((
            ROOT / "schemas/m0-3a-proof-compiler-rule-registry.v1.schema.json"
        ).read_text())
        closure_schema = json.loads((
            ROOT / "schemas/m0-3a-proof-compiler-closure.v1.schema.json"
        ).read_text())
        registry = json.loads(self.package.registry)
        closure = json.loads(self.package.closure)
        Draft202012Validator.check_schema(registry_schema)
        Draft202012Validator.check_schema(closure_schema)
        Draft202012Validator(registry_schema).validate(registry)
        Draft202012Validator(closure_schema).validate(closure)
        self.assertEqual(
            registry["registry_sha256"],
            compiler._domain_digest(
                compiler.REGISTRY_DOMAIN,
                {key: value for key, value in registry.items() if key != "registry_sha256"},
            ),
        )
        self.assertEqual(
            closure["closure_sha256"],
            candidate_verifier._domain_digest(
                candidate_verifier.CLOSURE_DOMAIN,
                {key: value for key, value in closure.items() if key != "closure_sha256"},
            ),
        )
        self.assertEqual(registry["status"], "CANDIDATE_ONLY")
        self.assertEqual(closure["status"], "CANDIDATE_ONLY")
        self.assertEqual(registry["authorizing_use"], "DENY")
        self.assertEqual(closure["authorizing_use"], "DENY")
        self.assertEqual(len(registry["rules"]), 1)
        self.assertEqual(registry["rules"][0]["keyword"], "minLength")

    def test_candidate_package_verifies_but_cannot_authorize(self):
        result = verify_candidate_package(self.package)
        self.assertEqual(result.status, "VALID_CANDIDATE")
        self.assertEqual(result.findings, ())
        self.assertEqual(result.authorizing_use, "DENY")
        self.assertEqual(result.governance_equivalence, "NOT_ESTABLISHED")
        self.assertFalse(result.accepted_classification_change)
        self.assertEqual(result.candidate_only_site_count, 25)
        with self.assertRaises(TypeError):
            bool(result)
        self.assertNotIn("ACCEPTED", {
            "VALID_CANDIDATE", "INVALID"
        })
        result_schema = json.loads((
            ROOT / "schemas/m0-3a-proof-candidate-package-result.v1.schema.json"
        ).read_text())
        Draft202012Validator.check_schema(result_schema)
        Draft202012Validator(result_schema).validate(result.as_mapping())

    def test_candidate_package_cli_is_deterministic_and_deny_only(self):
        command = [
            sys.executable,
            str(ROOT / "tools/verify_runtime_v2_candidate_package.py"),
        ]
        first = subprocess.run(
            command, cwd=ROOT, text=True, capture_output=True, check=False
        )
        second = subprocess.run(
            command, cwd=ROOT, text=True, capture_output=True, check=False
        )
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(first.stdout, second.stdout)
        result = json.loads(first.stdout)
        self.assertEqual(result["status"], "VALID_CANDIDATE")
        self.assertEqual(result["authorizing_use"], "DENY")
        self.assertEqual(result["governance_equivalence"], "NOT_ESTABLISHED")
        self.assertFalse(result["accepted_classification_change"])

    def test_candidate_package_rejects_registry_closure_and_file_substitution(self):
        registry_attack = CandidatePackage(
            self.package.registry + b" ",
            self.package.closure,
            self.package.compiler_output,
            self.package.files,
        )
        self.assertEqual(
            verify_candidate_package(registry_attack).findings[0].code,
            "REGISTRY_RAW_SHA256",
        )
        closure_attack = CandidatePackage(
            self.package.registry,
            self.package.closure + b" ",
            self.package.compiler_output,
            self.package.files,
        )
        self.assertEqual(
            verify_candidate_package(closure_attack).findings[0].code,
            "CLOSURE_RAW_SHA256",
        )
        attacked_files = list(self.package.files)
        attacked_files[0] = PackageFile(
            attacked_files[0].path, attacked_files[0].raw + b"forged"
        )
        file_attack = CandidatePackage(
            self.package.registry,
            self.package.closure,
            self.package.compiler_output,
            tuple(attacked_files),
        )
        self.assertEqual(
            verify_candidate_package(file_attack).findings[0].code,
            "PACKAGE_FILE_IDENTITY",
        )

    def test_candidate_package_rejects_duplicate_omitted_reordered_and_positive_output(self):
        duplicate = CandidatePackage(
            self.package.registry,
            self.package.closure,
            self.package.compiler_output,
            (*self.package.files[:-1], self.package.files[0]),
        )
        self.assertEqual(
            verify_candidate_package(duplicate).findings[0].code,
            "PACKAGE_FILE_DUPLICATE",
        )
        omitted = CandidatePackage(
            self.package.registry,
            self.package.closure,
            self.package.compiler_output,
            self.package.files[:-1],
        )
        self.assertEqual(
            verify_candidate_package(omitted).findings[0].code,
            "PACKAGE_FILE_SET",
        )
        reordered = CandidatePackage(
            self.package.registry,
            self.package.closure,
            self.package.compiler_output,
            tuple(reversed(self.package.files)),
        )
        self.assertEqual(
            verify_candidate_package(reordered).findings[0].code,
            "PACKAGE_FILE_ORDER",
        )
        positive = copy.deepcopy(self.output)
        positive["authorizing_use"] = "ALLOW"
        self.reseal(positive)
        output_attack = CandidatePackage(
            self.package.registry,
            self.package.closure,
            canonical_json(positive) + b"\n",
            self.package.files,
        )
        self.assertEqual(
            verify_candidate_package(output_attack).findings[0].code,
            "CANDIDATE_RAW_IDENTITY",
        )

    def test_candidate_package_file_set_matches_closure_and_raw_identities(self):
        closure = json.loads(self.package.closure)
        expected = {item["path"]: item for item in closure["files"]}
        self.assertEqual(tuple(sorted(expected)), PACKAGE_PATHS)
        self.assertEqual(
            tuple(item.path for item in self.package.files), PACKAGE_PATHS
        )
        for item in self.package.files:
            self.assertEqual(len(item.raw), expected[item.path]["byte_length"])
            self.assertEqual(
                hashlib.sha256(item.raw).hexdigest(),
                expected[item.path]["raw_sha256"],
            )

    def test_candidate_verifier_is_pure_and_has_closed_result_vocabulary(self):
        source = (
            ROOT / "src/edgelab/proof_candidate_verifier.py"
        ).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imports = {
            alias.name.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        } | {
            node.module.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        }
        self.assertTrue(imports <= {"__future__", "dataclasses", "hashlib", "json", "typing"})
        self.assertNotIn("open", {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)})
        with self.assertRaises(ValueError):
            candidate_verifier.CandidatePackageResult("ACCEPTED", ())


if __name__ == "__main__":
    unittest.main()
