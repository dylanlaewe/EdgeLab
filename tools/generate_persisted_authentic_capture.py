#!/usr/bin/env python3
"""Build the deterministic persisted graph used by the H-M0-080 verifier."""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


CAPTURE_FILE = "authentic-capture.v1.json"
EXPECTED_REMOTE = "https://github.com/dylanlaewe/EdgeLab.git"


def cj(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _regular_files(directory: Path) -> list[Path]:
    files: list[Path] = []
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"symlink is not retained evidence: {path}")
        if path.is_file():
            files.append(path)
        elif not path.is_dir():
            raise ValueError(f"non-regular retained evidence: {path}")
    return files


def generate(capture_root: str | Path) -> dict[str, Any]:
    root = Path(capture_root)
    sidecar = root / CAPTURE_FILE
    capture = json.loads(sidecar.read_text())
    artifacts: list[dict[str, Any]] = []
    blob_by_id: dict[str, dict[str, Any]] = {}
    directories: list[dict[str, Any]] = []

    paths = [sidecar]
    for base in (root / "repository", root / "packages"):
        if not base.is_dir() or base.is_symlink():
            raise ValueError(f"missing retained directory: {base}")
        paths.extend(_regular_files(base))

    for path in sorted(paths):
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"non-regular retained file: {path}")
        relative = path.relative_to(root).as_posix()
        payload = path.read_bytes()
        digest = sha256_bytes(payload)
        blob_id = f"B:{digest}"
        artifact_id = f"FILE:{relative}"
        artifacts.append(
            {
                "id": artifact_id,
                "kind": "FILE",
                "path": relative,
                "blob_id": blob_id,
                "byte_length": len(payload),
                "sha256": digest,
            }
        )
        blob = {
            "id": blob_id,
            "sha256": digest,
            "byte_length": len(payload),
            "bytes_b64": base64.b64encode(payload).decode("ascii"),
        }
        if blob_id in blob_by_id and blob_by_id[blob_id] != blob:
            raise ValueError("conflicting content-addressed blob")
        blob_by_id[blob_id] = blob

    artifact_by_path = {item["path"]: item for item in artifacts}
    for relative_root in ("repository", "packages"):
        prefix = relative_root + "/"
        members = sorted(
            item["id"] for path, item in artifact_by_path.items() if path.startswith(prefix)
        )
        directories.append(
            {
                "id": f"DIRECTORY:{relative_root}",
                "path": relative_root,
                "members": members,
                "sha256": sha256_bytes(cj(members).encode()),
            }
        )

    raw_result = cj(capture["result"])
    graph: dict[str, Any] = {
        "schema_version": 1,
        "trusted_root_id": capture["trusted_root_id"],
        "capture_id": capture["capture_id"],
        "capture": capture,
        "artifacts": artifacts,
        "blobs": [blob_by_id[key] for key in sorted(blob_by_id)],
        "directories": directories,
        "source_manifest": sorted(item["id"] for item in artifacts),
        "packages": capture["packages"],
        "git": {
            "freeze_commit": capture["freeze_commit"],
            "model": "host-git-checked",
            "origin_url": EXPECTED_REMOTE,
        },
        "raw_result": {
            "canonical_json": raw_result,
            "sha256": sha256_bytes(raw_result.encode()),
        },
        "self_sha256": "",
    }
    graph["self_sha256"] = sha256_bytes(
        cj({key: value for key, value in graph.items() if key != "self_sha256"}).encode()
    )
    return graph


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 1:
        raise SystemExit("usage: generate_persisted_authentic_capture.py CAPTURE_ROOT")
    print(cj(generate(arguments[0])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
