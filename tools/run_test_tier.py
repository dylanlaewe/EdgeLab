#!/usr/bin/env python3
"""Run EdgeLab test tiers serially in isolated Python processes.

The historical corpus performs expensive Git reconstruction and uses retained
fixture trees. Running multiple discovery processes concurrently can create
resource contention and unreliable results, so this runner holds a repository-
specific cooperative lock and executes one module at a time.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import os
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable, Iterator


ROOT = Path(__file__).resolve().parents[1]
FAST_MODULES = (
    "tests.test_alpha",
    "tests.test_foundation",
    "tests.test_orchestration",
    "tests.test_orchestration_final",
    "tests.test_runtime_v2_bootstrap",
    "tests.test_runtime_v2_closure",
    "tests.test_runtime_v2_codec",
    "tests.test_runtime_v2_image",
    "tests.test_runtime_v2_initial",
    "tests.test_runtime_v2_legacy_amendment",
    "tests.test_runtime_v2_storage_descriptor",
    "tests.test_runtime_v2_transition",
    "tests.test_runtime_v2_verifier",
    "tests.test_successor_runtime_contract",
    "tests.test_test_tiers",
    "tests.test_transactional_scheduler",
    "tests.test_web",
)
DOMAIN_MODULES = (
    "tests.test_data_integrity",
    "tests.test_quant_protocol",
    "tests.test_research_history_v2",
    "tests.test_risk_controls",
)
HISTORICAL_MODULES = (
    "tests.test_authentic_dependency_currentness",
    "tests.test_authentic_dependency_source_graph",
    "tests.test_authentic_stage1_replay",
    "tests.test_authoritative_currentness",
    "tests.test_composed_authentic_history",
    "tests.test_currentness_reference",
    "tests.test_m0_2_decision_evidence_v12_conformance",
    "tests.test_non_dependency_currentness",
    "tests.test_reconstructed_module_origins",
    "tests.test_reconstructed_package_origins",
    "tests.test_research_protocol",
    "tests.test_skeptic_adversarial",
    "tests.test_skeptic_authentic_stage1_plan_v13",
    "tests.test_skeptic_decision_envelope_plan_v10",
    "tests.test_skeptic_decision_envelope_plan_v2",
    "tests.test_skeptic_decision_envelope_plan_v3",
    "tests.test_skeptic_decision_envelope_plan_v4",
    "tests.test_skeptic_decision_envelope_plan_v5",
    "tests.test_skeptic_decision_envelope_plan_v6",
    "tests.test_skeptic_decision_envelope_plan_v7",
    "tests.test_skeptic_decision_envelope_plan_v8",
    "tests.test_skeptic_decision_envelope_plan_v9",
    "tests.test_skeptic_decision_evidence_plan_v12",
    "tests.test_skeptic_final_evidence_plan_v15",
    "tests.test_skeptic_history_v4",
    "tests.test_skeptic_orchestration_v1",
    "tests.test_skeptic_orchestration_v2",
    "tests.test_skeptic_orchestration_v3",
    "tests.test_skeptic_orchestration_v4",
    "tests.test_skeptic_orchestration_v5",
    "tests.test_skeptic_orchestration_v6",
    "tests.test_skeptic_orchestration_v7",
    "tests.test_skeptic_orchestration_v8",
    "tests.test_skeptic_quant_v5",
    "tests.test_skeptic_quant_v6",
    "tests.test_skeptic_quant_v7",
    "tests.test_skeptic_research_v3",
    "tests.test_skeptic_risk_v1",
    "tests.test_skeptic_risk_v2",
    "tests.test_skeptic_risk_v3",
    "tests.test_skeptic_semantic_v2",
    "tests.test_skeptic_trusted_evidence_plan_v14",
    "tests.test_trusted_authentic_capture",
)
TIER_ORDER = ("fast", "domain", "historical")


def discover_modules(root: Path = ROOT) -> tuple[str, ...]:
    return tuple(
        f"tests.{path.stem}"
        for path in sorted((root / "tests").glob("test_*.py"))
        if path.is_file()
    )


def tiers(root: Path = ROOT) -> dict[str, tuple[str, ...]]:
    discovered = discover_modules(root)
    configured = {
        "fast": FAST_MODULES,
        "domain": DOMAIN_MODULES,
        "historical": HISTORICAL_MODULES,
    }
    assigned = tuple(module for name in TIER_ORDER for module in configured[name])
    known = set(assigned)
    missing = known - set(discovered)
    if missing:
        raise RuntimeError(f"Configured test modules are missing: {sorted(missing)}")
    if len(assigned) != len(known):
        duplicates = sorted({module for module in assigned if assigned.count(module) > 1})
        raise RuntimeError(f"Test modules appear in multiple tiers: {duplicates}")
    unclassified = set(discovered) - known
    if unclassified:
        raise RuntimeError(f"Unclassified test modules: {sorted(unclassified)}")
    return configured


def selected_modules(tier: str, root: Path = ROOT) -> tuple[str, ...]:
    configured = tiers(root)
    if tier == "all":
        return tuple(module for name in TIER_ORDER for module in configured[name])
    return configured[tier]


def lock_path(root: Path = ROOT) -> Path:
    identity = hashlib.sha256(str(root.resolve()).encode("utf-8")).hexdigest()[:16]
    return Path(tempfile.gettempdir()) / f"edgelab-tests-{identity}.lock"


@contextmanager
def exclusive_run(root: Path = ROOT) -> Iterator[None]:
    path = lock_path(root)
    with path.open("a+", encoding="utf-8") as stream:
        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError(
                "Another EdgeLab tiered test run is active; concurrent runs are denied"
            ) from error
        try:
            yield
        finally:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def unittest_command(module: str, *, verbosity: int = 2) -> list[str]:
    """Return an isolated discovery command compatible with legacy imports."""
    pattern = f"{module.rsplit('.', 1)[-1]}.py"
    return [
        sys.executable,
        "-m",
        "unittest",
        "discover",
        "-s",
        "tests",
        "-p",
        pattern,
        f"-{'v' * verbosity}",
    ]


def continues_after_failure(module: str) -> bool:
    """Historical modules are audit evidence and must all be observed."""
    return module in HISTORICAL_MODULES


def run(tier: str, *, verbosity: int = 2, root: Path = ROOT) -> int:
    modules = selected_modules(tier, root)
    environment = {
        **os.environ,
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "TZ": "UTC",
    }
    started = time.monotonic()
    failures: list[tuple[str, int]] = []
    print(f"EdgeLab test tier: {tier} ({len(modules)} isolated modules)", flush=True)
    with exclusive_run(root):
        for index, module in enumerate(modules, 1):
            print(f"\n[{index}/{len(modules)}] {module}", flush=True)
            command = unittest_command(module, verbosity=verbosity)
            module_started = time.monotonic()
            result = subprocess.run(command, cwd=root, env=environment, check=False)
            elapsed = time.monotonic() - module_started
            print(f"{module}: exit {result.returncode} in {elapsed:.3f}s", flush=True)
            if result.returncode:
                failures.append((module, result.returncode))
                if continues_after_failure(module):
                    continue
                print(
                    f"Tier {tier} stopped at {module}; later modules were not run.",
                    file=sys.stderr,
                )
                return result.returncode
    elapsed = time.monotonic() - started
    if failures:
        print(f"\nTier {tier} completed with failures in {elapsed:.3f}s:", file=sys.stderr)
        for module, returncode in failures:
            print(f"  {module}: exit {returncode}", file=sys.stderr)
        return 1
    print(f"\nTier {tier} passed: {len(modules)} modules in {elapsed:.3f}s", flush=True)
    return 0


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tier", choices=(*TIER_ORDER, "all"), nargs="?", default="fast")
    parser.add_argument("--list", action="store_true", help="List module assignments without running tests")
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        configured = tiers(ROOT)
        if args.list:
            for name in TIER_ORDER:
                print(f"{name}:")
                for module in configured[name]:
                    print(f"  {module}")
            return 0
        return run(args.tier)
    except RuntimeError as error:
        print(f"EdgeLab test runner denied: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
