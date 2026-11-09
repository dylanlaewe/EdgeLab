#!/usr/bin/env python3
"""Verify the exact M0.3A proof candidate package without authorizing it."""
from __future__ import annotations

import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.edgelab.proof_candidate_verifier import (
    CandidatePackage,
    PackageFile,
    verify_candidate_package,
)
from tools.compile_runtime_v2_minlength_candidates import (
    canonical_json,
    compile_candidate_ledger,
)


REGISTRY_PATH = "docs/M0.3A_PROOF_COMPILER_RULE_REGISTRY.v1.json"
CLOSURE_PATH = "docs/M0.3A_PROOF_COMPILER_CLOSURE.v1.json"
PACKAGE_PATHS = (
    "docs/M0.3A_PROOF_COMPILER_RULE_REGISTRY.v1.json",
    "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v55.json",
    "docs/M0.3A_RUNTIME_V2_RESOURCE_DISCOVERY.v8.json",
    "reports/H-M0-180-automated-proof-compiler-feasibility.v1.md",
    "schemas/m0-3a-proof-compiler-rule-registry.v1.schema.json",
    "tests/test_runtime_v2_proof_compiler.py",
    "tools/check_runtime_v2_release_readiness.py",
    "tools/compile_runtime_v2_minlength_candidates.py",
)


def build_package(root: Path = ROOT) -> CandidatePackage:
    root = root.resolve()
    if root != ROOT:
        raise ValueError("candidate package requires canonical repository root")
    return CandidatePackage(
        registry=(root / REGISTRY_PATH).read_bytes(),
        closure=(root / CLOSURE_PATH).read_bytes(),
        compiler_output=canonical_json(compile_candidate_ledger(root)) + b"\n",
        files=tuple(
            PackageFile(path, (root / path).read_bytes())
            for path in PACKAGE_PATHS
        ),
    )


def main() -> int:
    result = verify_candidate_package(build_package())
    print(json.dumps(result.as_mapping(), sort_keys=True, separators=(",", ":")))
    return 0 if result.status == "VALID_CANDIDATE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
