#!/usr/bin/env python3
"""Verify retained capture bytes against repository-authoritative trust records."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, RefResolver

from tools.generate_persisted_authentic_capture import CAPTURE_FILE, cj


ROOT = Path(__file__).resolve().parents[1]
TRUST_ROOT = "docs/M0.2_STAGE1_TRUST_ROOT.v1.json"
CAPTURE_ROOT = "docs/M0.2_HISTORICAL_CAPTURE_ROOT.v1.json"


def h(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def package_digest(path: Path) -> str:
    members = []
    for item in path.rglob("*"):
        if item.is_symlink():
            raise ValueError("symlink in package closure")
        if item.is_file():
            members.append((item.relative_to(path).as_posix() + ":" + h(item)).encode())
        elif not item.is_dir():
            raise ValueError("non-regular package member")
    return hashlib.sha256(b"".join(sorted(members))).hexdigest()


def repository_inventory(path: Path) -> str:
    members = []
    for item in path.rglob("*"):
        if item.is_symlink():
            raise ValueError("symlink in repository closure")
        if item.is_file() and ".git" not in item.parts and "__pycache__" not in item.parts:
            members.append((item.relative_to(path).as_posix() + ":" + h(item)).encode())
        elif not item.is_file() and not item.is_dir():
            raise ValueError("non-regular repository member")
    return hashlib.sha256(b"".join(sorted(members))).hexdigest()


def _validate_schema(record: dict[str, Any], schema_path: Path) -> None:
    schema = json.loads(schema_path.read_text())
    resolver = RefResolver(schema_path.parent.as_uri() + "/", schema)
    errors = list(Draft202012Validator(schema, resolver=resolver).iter_errors(record))
    if errors:
        raise ValueError("schema validation failed")


def load_trust(
    trusted_root: str | Path | None = None,
    capture_root: str | Path | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    trust_path = Path(trusted_root) if trusted_root is not None else ROOT / TRUST_ROOT
    capture_path = Path(capture_root) if capture_root is not None else ROOT / CAPTURE_ROOT
    trust = json.loads(trust_path.read_text())
    capture_trust = json.loads(capture_path.read_text())
    if trust["root_sha256"] != hashlib.sha256(
        cj({key: value for key, value in trust.items() if key != "root_sha256"}).encode()
    ).hexdigest():
        raise ValueError("trusted root self digest")
    _validate_schema(
        capture_trust, ROOT / "schemas/m0-2-historical-capture-root.v1.schema.json"
    )
    if capture_trust["root_sha256"] != hashlib.sha256(
        cj({key: value for key, value in capture_trust.items() if key != "root_sha256"}).encode()
    ).hexdigest():
        raise ValueError("historical capture root self digest")
    if (
        capture_trust["base_trusted_root_id"] != trust["root_id"]
        or capture_trust["base_trusted_root_sha256"] != trust["root_sha256"]
    ):
        raise ValueError("historical capture root base mismatch")
    ids = [item["capture_id"] for item in capture_trust["captures"]]
    paths = [item["fixture_path"] for item in capture_trust["captures"]]
    if len(ids) != len(set(ids)) or len(paths) != len(set(paths)):
        raise ValueError("duplicate capture trust entry")
    closure = trust["dependency_closure"]
    closure_path = ROOT / closure["path"]
    if not closure_path.is_file() or h(closure_path) != closure["sha256"]:
        raise ValueError("dependency closure digest")
    closure_record = json.loads(closure_path.read_text())
    if (
        closure_record["closure_id"] != closure["closure_id"]
        or closure_record["version"] != closure["version"]
        or closure_record["freeze_commit"] != trust["freeze_commit"]
    ):
        raise ValueError("dependency closure identity")
    unsigned_closure = {key: value for key, value in closure_record.items() if key != "closure_sha256"}
    if closure_record["closure_sha256"] != hashlib.sha256(cj(unsigned_closure).encode()).hexdigest():
        raise ValueError("dependency closure self digest")
    return trust, capture_trust


def capture_entry(capture_id: str, capture_trust: dict[str, Any]) -> dict[str, Any]:
    matches = [item for item in capture_trust["captures"] if item["capture_id"] == capture_id]
    if len(matches) != 1:
        raise ValueError("untrusted capture identity")
    return matches[0]


def verify(
    fixture: str | Path,
    *,
    trusted_root: str | Path | None = None,
    capture_root: str | Path | None = None,
) -> str:
    try:
        trust, capture_trust = load_trust(trusted_root, capture_root)
        root = Path(fixture)
        sidecar = root / CAPTURE_FILE
        capture = json.loads(sidecar.read_text())
        _validate_schema(capture, ROOT / "schemas/m0-2-authentic-capture.v1.schema.json")
        entry = capture_entry(capture["capture_id"], capture_trust)
        if h(sidecar) != entry["sidecar_sha256"]:
            return "INVALID: capture sidecar digest mismatch"
        if capture["trusted_root_id"] != trust["root_id"]:
            return "INVALID: trusted root mismatch"
        if capture["freeze_commit"] != trust["freeze_commit"]:
            return "INVALID: trusted freeze mismatch"
        if capture["entrypoint"] != trust["entrypoint"]:
            return "INVALID: entrypoint mismatch"
        repository = root / "repository"
        if repository_inventory(repository) != entry["repository_inventory_sha256"]:
            return "INVALID: repository inventory digest mismatch"
        for record in trust["modules"] + trust["schemas"]:
            path = repository / record["path"]
            if not path.is_file() or h(path) != record["sha256"]:
                return "INVALID: trusted root digest mismatch"

        closure = json.loads((ROOT / trust["dependency_closure"]["path"]).read_text())
        for schema_name in closure["schemas"]:
            if not (repository / "schemas" / schema_name).is_file():
                return "INVALID: dependency closure schema missing"

        if capture["packages"] != entry["packages"]:
            return "INVALID: trusted package metadata mismatch"
        declared_paths = {record["path"] for record in entry["packages"]}
        actual_paths = {
            path.relative_to(root).as_posix()
            for path in (root / "packages").iterdir()
            if path.is_dir() and not path.is_symlink()
        }
        if actual_paths != declared_paths:
            return "INVALID: package directory closure mismatch"
        seen: set[tuple[str, str]] = set()
        for record in entry["packages"]:
            identity = (record["name"], record["version"])
            if identity in seen:
                return "INVALID: duplicate package identity"
            seen.add(identity)
            package = root / record["path"]
            if not package.is_dir() or package.is_symlink():
                return "INVALID: missing package"
            if package_digest(package) != record["files_sha256"]:
                return "INVALID: package digest mismatch"
        return "HISTORICALLY_VALID"
    except Exception as error:
        return "INVALID: " + str(error)


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 1:
        raise SystemExit("usage: verify_trusted_authentic_capture.py CAPTURE_ROOT")
    print(verify(arguments[0]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
