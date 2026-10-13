#!/usr/bin/env python3
"""Validate and reconstruct an H-M0-080 persisted capture graph."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

from jsonschema import Draft202012Validator, RefResolver

from tools.generate_persisted_authentic_capture import CAPTURE_FILE, cj


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas/m0-2-persisted-authentic-capture.v1.schema.json"


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _path(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value or ".." in path.parts or "." in path.parts:
        raise ValueError("noncanonical persisted path")
    if value != CAPTURE_FILE and path.parts[0] not in {"repository", "packages"}:
        raise ValueError("persisted path outside retained roots")
    return path


def _schema_validate(graph: dict[str, Any]) -> None:
    schema = json.loads(SCHEMA.read_text())
    resolver = RefResolver((ROOT / "schemas").as_uri() + "/", schema)
    errors = sorted(
        Draft202012Validator(schema, resolver=resolver).iter_errors(graph),
        key=lambda error: (list(error.absolute_path), error.message),
    )
    if errors:
        raise ValueError("persisted graph schema: " + errors[0].message)


def validate_graph(graph: dict[str, Any]) -> dict[str, bytes]:
    _schema_validate(graph)
    unsigned = {key: value for key, value in graph.items() if key != "self_sha256"}
    if graph["self_sha256"] != _sha256(cj(unsigned).encode()):
        raise ValueError("persisted graph self digest")

    if graph["capture_id"] != graph["capture"]["capture_id"]:
        raise ValueError("capture identity mismatch")
    if graph["trusted_root_id"] != graph["capture"]["trusted_root_id"]:
        raise ValueError("trusted root identity mismatch")
    if graph["packages"] != graph["capture"]["packages"]:
        raise ValueError("package metadata mismatch")
    if graph["git"]["freeze_commit"] != graph["capture"]["freeze_commit"]:
        raise ValueError("freeze identity mismatch")

    canonical_result = cj(graph["capture"]["result"])
    if graph["raw_result"] != {
        "canonical_json": canonical_result,
        "sha256": _sha256(canonical_result.encode()),
    }:
        raise ValueError("raw result mismatch")

    blobs: dict[str, bytes] = {}
    for blob in graph["blobs"]:
        if blob["id"] in blobs:
            raise ValueError("duplicate blob identity")
        try:
            payload = base64.b64decode(blob["bytes_b64"], validate=True)
        except (binascii.Error, ValueError) as error:
            raise ValueError("invalid blob base64") from error
        digest = _sha256(payload)
        if blob["id"] != f"B:{digest}" or blob["sha256"] != digest:
            raise ValueError("blob digest mismatch")
        if blob["byte_length"] != len(payload):
            raise ValueError("blob length mismatch")
        blobs[blob["id"]] = payload

    artifacts: dict[str, dict[str, Any]] = {}
    paths: set[str] = set()
    used_blobs: set[str] = set()
    for artifact in graph["artifacts"]:
        path = _path(artifact["path"])
        if artifact["id"] != f"FILE:{path.as_posix()}":
            raise ValueError("artifact identity mismatch")
        if artifact["id"] in artifacts or artifact["path"] in paths:
            raise ValueError("duplicate artifact identity or path")
        if artifact["blob_id"] not in blobs:
            raise ValueError("missing artifact blob")
        payload = blobs[artifact["blob_id"]]
        if artifact["sha256"] != _sha256(payload) or artifact["byte_length"] != len(payload):
            raise ValueError("artifact digest or length mismatch")
        artifacts[artifact["id"]] = artifact
        paths.add(artifact["path"])
        used_blobs.add(artifact["blob_id"])

    if set(blobs) != used_blobs:
        raise ValueError("orphan persisted blob")
    if graph["source_manifest"] != sorted(artifacts):
        raise ValueError("source manifest mismatch")

    expected_directories: dict[str, list[str]] = {}
    for directory in ("repository", "packages"):
        prefix = directory + "/"
        expected_directories[directory] = sorted(
            artifact_id
            for artifact_id, artifact in artifacts.items()
            if artifact["path"].startswith(prefix)
        )
    seen_directories: set[str] = set()
    for directory in graph["directories"]:
        path = directory["path"]
        if directory["id"] != f"DIRECTORY:{path}" or path in seen_directories:
            raise ValueError("directory identity mismatch")
        members = expected_directories[path]
        if directory["members"] != members:
            raise ValueError("directory members mismatch")
        if directory["sha256"] != _sha256(cj(members).encode()):
            raise ValueError("directory digest mismatch")
        seen_directories.add(path)
    if seen_directories != set(expected_directories):
        raise ValueError("missing directory evidence")

    sidecar_id = f"FILE:{CAPTURE_FILE}"
    if sidecar_id not in artifacts:
        raise ValueError("missing reconstructed capture sidecar")
    sidecar = json.loads(blobs[artifacts[sidecar_id]["blob_id"]].decode("utf-8"))
    if sidecar != graph["capture"]:
        raise ValueError("capture sidecar mismatch")
    return blobs


def deserialize(payload: bytes) -> dict[str, Any]:
    graph = json.loads(payload.decode("utf-8"))
    if not isinstance(graph, dict):
        raise ValueError("persisted graph must be an object")
    validate_graph(graph)
    return graph


def reconstruct(graph: dict[str, Any]) -> tuple[tempfile.TemporaryDirectory[str], Path]:
    blobs = validate_graph(graph)
    temporary = tempfile.TemporaryDirectory()
    root = Path(temporary.name)
    for artifact in graph["artifacts"]:
        target = root.joinpath(*PurePosixPath(artifact["path"]).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(blobs[artifact["blob_id"]])
    return temporary, root
