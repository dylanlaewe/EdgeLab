#!/usr/bin/env python3
"""Composed, fail-closed historical verifier for the H-M0-080 scope."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.generate_persisted_authentic_capture import CAPTURE_FILE, cj, generate
from tools.reconstruct_persisted_history import deserialize, reconstruct
from tools.verify_trusted_authentic_capture import (
    capture_entry,
    load_trust,
    verify as trusted_verify,
)


TRUST_ROOT = ROOT / "docs/M0.2_STAGE1_TRUST_ROOT.v1.json"
CAPTURE_ROOT = ROOT / "docs/M0.2_HISTORICAL_CAPTURE_ROOT.v1.json"
EXPECTED_REMOTE = "https://github.com/dylanlaewe/EdgeLab.git"
PACKAGE_IMPORTS = {
    "attrs": ("attr", "attrs"),
    "jsonschema": ("jsonschema",),
    "jsonschema-specifications": ("jsonschema_specifications",),
    "referencing": ("referencing",),
    "rpds-py": ("rpds",),
}


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _empty_evidence() -> dict[str, Any]:
    return {
        "frozen_commit": "unknown",
        "replay_root": "unavailable",
        "raw_result_sha256": "",
        "decision_id": None,
        "module_origins": [],
        "schema_origins": [],
        "package_origins": [],
        "python": {},
        "git": {},
        "environment_sha256": "",
    }


def result(
    status: str,
    reasons: list[str],
    capture_id: str = "UNKNOWN",
    root_id: str = "M0-2-STAGE1-TRUST-ROOT-V1",
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    valid = status == "HISTORICALLY_VALID"
    incompatible = status == "INCOMPATIBLE_RUNTIME"
    if valid:
        projection = {
            "historical_status": "VALID",
            "currentness_status": "UNKNOWN",
            "runtime_compatible": True,
            "verifier_status": "FAIL",
            "generation_match": False,
            "authorizing_use": "DENY",
            "reason_code": "VERIFIER_FAILURE",
        }
    elif incompatible:
        projection = {
            "historical_status": "INVALID",
            "currentness_status": "UNKNOWN",
            "runtime_compatible": False,
            "verifier_status": "FAIL",
            "generation_match": False,
            "authorizing_use": "DENY",
            "reason_code": "INCOMPATIBLE_RUNTIME",
        }
    else:
        projection = {
            "historical_status": "INVALID",
            "currentness_status": "UNKNOWN",
            "runtime_compatible": True,
            "verifier_status": "FAIL",
            "generation_match": False,
            "authorizing_use": "DENY",
            "reason_code": "HISTORICAL_INVALID",
        }
    return {
        "schema_version": 1,
        "status": status,
        "capture_id": capture_id,
        "trusted_root_id": root_id,
        "reason_codes": sorted(set(reasons)),
        "authorization_result": projection,
        "replay": {"completed": valid, "raw_result_match": valid},
        "evidence": evidence if evidence is not None else _empty_evidence(),
    }


def _runtime(
    trust: dict[str, Any], git_executable: str | None = None
) -> tuple[bool, dict[str, Any], dict[str, Any]]:
    boundary = trust["host_boundary"]
    executable = git_executable or shutil.which("git")
    python_evidence = {
        "implementation": platform.python_implementation(),
        "version": platform.python_version(),
        "cache_tag": sys.implementation.cache_tag,
        "abiflags": getattr(sys, "abiflags", ""),
        "platform": platform.system(),
        "architecture": platform.machine(),
    }
    git_evidence: dict[str, Any] = {
        "model": "host-git-checked",
        "executable": str(Path(executable).resolve()) if executable else "",
        "version": "",
    }
    if executable:
        completed = subprocess.run(
            [executable, "--version"], text=True, capture_output=True, check=False
        )
        git_evidence["version"] = completed.stdout.strip()
    compatible = bool(
        executable
        and python_evidence["implementation"] == boundary["python_implementation"]
        and python_evidence["version"].startswith(boundary["python_major_minor"] + ".")
        and python_evidence["platform"] == boundary["platform"]
        and python_evidence["architecture"] == boundary["architecture"]
        and git_evidence["model"] == boundary["git_model"]
        and git_evidence["version"].startswith("git version ")
    )
    return compatible, python_evidence, git_evidence


def _run_git(git: str, arguments: list[str], *, environment: dict[str, str]) -> str:
    completed = subprocess.run(
        [git, *arguments],
        text=True,
        capture_output=True,
        check=True,
        env=environment,
    )
    return completed.stdout.strip()


def replay_reconstructed(
    graph: dict[str, Any], trust: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    compatible, python_evidence, git_evidence = _runtime(trust)
    if not compatible:
        raise RuntimeError("runtime boundary incompatible")
    git = git_evidence["executable"]
    temporary, root = reconstruct(graph)
    try:
        repository = root / "repository"
        capture = json.loads((root / CAPTURE_FILE).read_text())
        git_environment = {
            "PATH": str(Path(git).parent),
            "LC_ALL": "C.UTF-8",
            "TZ": "UTC",
            "GIT_AUTHOR_DATE": "2000-01-01T00:00:00Z",
            "GIT_COMMITTER_DATE": "2000-01-01T00:00:00Z",
        }
        _run_git(git, ["init", "-q", str(repository)], environment=git_environment)
        _run_git(
            git,
            ["-C", str(repository), "config", "user.email", "replay@example.invalid"],
            environment=git_environment,
        )
        _run_git(
            git,
            ["-C", str(repository), "config", "user.name", "replay"],
            environment=git_environment,
        )
        _run_git(git, ["-C", str(repository), "add", "."], environment=git_environment)
        _run_git(
            git, ["-C", str(repository), "commit", "-qm", "replay"], environment=git_environment
        )
        _run_git(
            git,
            ["-C", str(repository), "remote", "add", "origin", EXPECTED_REMOTE],
            environment=git_environment,
        )
        _run_git(
            git,
            ["-C", str(repository), "update-ref", "refs/remotes/origin/main", "HEAD"],
            environment=git_environment,
        )
        replay_commit = _run_git(
            git, ["-C", str(repository), "rev-parse", "HEAD"], environment=git_environment
        )

        package_paths = [str(root / item["path"]) for item in capture["packages"]]
        imported_names = [
            name for package in capture["packages"] for name in PACKAGE_IMPORTS[package["name"]]
        ]
        code = f'''from pathlib import Path
import hashlib
import importlib
import json
import platform
import sys
import edgelab.orchestration as orchestration
import edgelab.validate as validate
import edgelab.data_integrity as data_integrity

read_paths = []
schema_root = (Path("repository") / "schemas").resolve()
original_read = validate.read
def recording_read(path):
    resolved = Path(path).resolve()
    if resolved.is_relative_to(schema_root):
        read_paths.append(str(resolved))
    return original_read(path)
validate.read = recording_read
orchestration.read = recording_read
for name in {imported_names!r}:
    importlib.import_module(name)
result = orchestration.decision(Path("repository"), json.loads({cj(capture['intent'])!r}))
prefixes = ("edgelab", "jsonschema", "jsonschema_specifications", "attr", "attrs", "referencing", "rpds")
origins = {{}}
for name, module in sorted(sys.modules.items()):
    if name in prefixes or name.startswith(tuple(prefix + "." for prefix in prefixes)):
        location = getattr(module, "__file__", None)
        if location:
            origins[name] = str(Path(location).resolve())
print(json.dumps({{
    "result": result,
    "origins": origins,
    "schemas": sorted(set(read_paths)),
    "python": {{
        "implementation": platform.python_implementation(),
        "version": platform.python_version(),
        "cache_tag": sys.implementation.cache_tag,
        "abiflags": getattr(sys, "abiflags", ""),
        "platform": platform.system(),
        "architecture": platform.machine(),
    }},
}}, sort_keys=True))'''
        child_environment = {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            "LC_ALL": "C.UTF-8",
            "TZ": "UTC",
            "PYTHONIOENCODING": "utf-8",
            "PYTHONPATH": os.pathsep.join([str(repository / "src"), *package_paths]),
            "PATH": str(Path(git).parent),
        }
        if set(child_environment) != set(trust["host_boundary"]["environment_allowlist"]):
            raise RuntimeError("environment allowlist mismatch")
        output = subprocess.check_output(
            [sys.executable, "-S", "-c", code],
            cwd=root,
            env=child_environment,
            text=True,
        )
        observed = json.loads(output)
        if observed["python"] != python_evidence:
            raise RuntimeError("child runtime drift")

        root_real = root.resolve()
        package_roots = {
            item["name"]: (root / item["path"]).resolve() for item in capture["packages"]
        }
        module_origins: list[str] = []
        package_origins: list[str] = []
        seen_packages: set[str] = set()
        for name, raw_path in sorted(observed["origins"].items()):
            path = Path(raw_path).resolve()
            if not path.is_relative_to(root_real) or not path.is_file():
                raise RuntimeError("ambient module origin")
            relative = path.relative_to(root_real).as_posix()
            identity = f"{name}:{relative}:{_sha256(path.read_bytes())}"
            if name == "edgelab" or name.startswith("edgelab."):
                if not path.is_relative_to((repository / "src").resolve()):
                    raise RuntimeError("ambient first-party module")
                module_origins.append(identity)
            else:
                matches = [package for package, base in package_roots.items() if path.is_relative_to(base)]
                if len(matches) != 1:
                    raise RuntimeError("undeclared package origin")
                seen_packages.add(matches[0])
                package_origins.append(identity)
        if seen_packages != set(package_roots):
            raise RuntimeError("incomplete imported package closure")

        schema_origins: list[str] = []
        for raw_path in observed["schemas"]:
            path = Path(raw_path).resolve()
            if not path.is_relative_to((repository / "schemas").resolve()) or not path.is_file():
                raise RuntimeError("ambient schema origin")
            relative = path.relative_to(root_real).as_posix()
            schema_origins.append(f"{relative}:{_sha256(path.read_bytes())}")
        schema_origins = sorted(set(schema_origins))

        normalized_environment = {
            key: value.replace(str(root_real), "<RECONSTRUCTED>")
            for key, value in sorted(child_environment.items())
        }
        git_evidence.update(
            {
                "replay_commit": replay_commit,
                "origin_url": EXPECTED_REMOTE,
                "freeze_commit": graph["git"]["freeze_commit"],
            }
        )
        evidence = {
            "frozen_commit": graph["git"]["freeze_commit"],
            "replay_root": f"persisted-graph:{graph['self_sha256']}",
            "raw_result_sha256": _sha256(cj(observed["result"]).encode()),
            "decision_id": observed["result"].get("decision_id"),
            "module_origins": sorted(module_origins),
            "schema_origins": schema_origins,
            "package_origins": sorted(package_origins),
            "python": python_evidence,
            "git": git_evidence,
            "environment_sha256": _sha256(cj(normalized_environment).encode()),
        }
        return observed["result"], evidence
    finally:
        temporary.cleanup()


def _reason_for_trusted_failure(message: str) -> str:
    lowered = message.lower()
    if "package" in lowered:
        return "PACKAGE_DIGEST_MISMATCH"
    if "schema" in lowered or "repository inventory" in lowered:
        return "SCHEMA_DIGEST_MISMATCH"
    if "freeze" in lowered or "root" in lowered or "capture" in lowered:
        return "TRUSTED_ROOT_MISMATCH"
    return "GRAPH_INVALID"


def verify_authentic_history(
    capture_root: str | Path,
    trusted_root: str | Path = TRUST_ROOT,
    capture_trust_root: str | Path = CAPTURE_ROOT,
) -> dict[str, Any]:
    root = Path(capture_root)
    capture_id = "UNKNOWN"
    trusted_root_id = "M0-2-STAGE1-TRUST-ROOT-V1"
    try:
        trust, capture_trust = load_trust(trusted_root, capture_trust_root)
        trusted_root_id = trust["root_id"]
    except Exception:
        return result("INVALID", ["TRUSTED_ROOT_MISMATCH"], capture_id, trusted_root_id)

    compatible, _, _ = _runtime(trust)
    if not compatible:
        return result(
            "INCOMPATIBLE_RUNTIME", ["RUNTIME_INCOMPATIBLE"], capture_id, trusted_root_id
        )
    try:
        capture = json.loads((root / CAPTURE_FILE).read_text())
        capture_id = capture.get("capture_id", "UNKNOWN")
        entry = capture_entry(capture_id, capture_trust)
    except Exception:
        return result("INVALID", ["GRAPH_INVALID"], capture_id, trusted_root_id)

    trusted_status = trusted_verify(
        root, trusted_root=trusted_root, capture_root=capture_trust_root
    )
    if trusted_status != "HISTORICALLY_VALID":
        return result(
            "INVALID",
            [_reason_for_trusted_failure(trusted_status)],
            capture_id,
            trusted_root_id,
        )

    try:
        generated = generate(root)
        graph = deserialize(cj(generated).encode())
    except Exception:
        return result("INVALID", ["GRAPH_INVALID"], capture_id, trusted_root_id)
    if graph["self_sha256"] != entry["graph_sha256"]:
        return result("INVALID", ["TRUSTED_ROOT_MISMATCH"], capture_id, trusted_root_id)

    try:
        actual, evidence = replay_reconstructed(graph, trust)
    except Exception:
        return result("INVALID", ["RECONSTRUCTED_REPLAY_FAILED"], capture_id, trusted_root_id)
    if actual != graph["capture"]["result"]:
        return result(
            "INVALID",
            ["RECONSTRUCTED_RESULT_MISMATCH"],
            capture_id,
            trusted_root_id,
            evidence,
        )
    return result("HISTORICALLY_VALID", [], capture_id, trusted_root_id, evidence)


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 1:
        raise SystemExit("usage: verify_authentic_history.py CAPTURE_ROOT")
    print(cj(verify_authentic_history(arguments[0])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
