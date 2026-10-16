"""Build a read-only, fail-closed snapshot for the local laboratory observatory.

The snapshot reports governed repository state. It is visibility, not a
currentness receipt, scientific assessment, approval, or execution authority.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from .validate import CHECKER, GATES, ROOT


PROJECT_STATE = Path("docs/project-state.json")
BANKROLL = Path("portfolio/bankroll.json")
RISK_POLICY = Path("portfolio/risk-policy.json")
STATUS_SCHEMA = Path("schemas/local-observatory-status.v1.schema.json")
PROJECT_SCHEMA = Path("schemas/project-state.schema.json")
BANKROLL_SCHEMA = Path("schemas/bankroll.schema.json")
RISK_SCHEMA = Path("schemas/risk-policy.schema.json")
STOP_SCHEMA = Path("schemas/stop.schema.json")
STATIC_PATHS = (
    PROJECT_STATE,
    BANKROLL,
    RISK_POLICY,
    PROJECT_SCHEMA,
    BANKROLL_SCHEMA,
    RISK_SCHEMA,
    STOP_SCHEMA,
    STATUS_SCHEMA,
)
EXPECTED_LIMIT_KEYS = {
    "position_minor",
    "daily_exposure_minor",
    "correlated_exposure_minor",
    "strategy_exposure_minor",
    "source_concentration_minor",
    "max_drawdown_minor",
}
STOP_PATTERN = re.compile(r"^(STOP-.+)\.v([1-9][0-9]*)\.json$")


class StatusUnavailable(ValueError):
    """The governed status snapshot could not be built without ambiguity."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StatusUnavailable("duplicate JSON key")
        result[key] = value
    return result


def _parse(value: bytes) -> dict[str, Any]:
    def invalid_constant(raw: str) -> None:
        raise StatusUnavailable(f"nonfinite JSON number: {raw}")

    record = json.loads(
        value.decode("utf-8"),
        object_pairs_hook=_unique_object,
        parse_constant=invalid_constant,
    )
    if not isinstance(record, dict):
        raise StatusUnavailable("record must be an object")
    return record


def _file_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return value.st_dev, value.st_ino, value.st_mode, value.st_nlink, value.st_size, value.st_mtime_ns


def _directory_identity(value: os.stat_result) -> tuple[int, int, int, int]:
    return value.st_dev, value.st_ino, value.st_mode, value.st_mtime_ns


class _PinnedRepository:
    """Hold no-follow directory descriptors across one complete observation."""

    directory_paths = tuple(sorted({path.parent for path in STATIC_PATHS} | {Path("reports/stops")}, key=lambda item: item.as_posix()))

    def __init__(self, root: Path):
        self.root = root.resolve()
        directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        self._directory_flags = directory_flags
        self.root_fd = os.open(self.root, directory_flags)
        root_metadata = os.fstat(self.root_fd)
        current_root = self.root.lstat()
        if not stat.S_ISDIR(root_metadata.st_mode) or _directory_identity(root_metadata) != _directory_identity(current_root):
            os.close(self.root_fd)
            raise StatusUnavailable("repository root identity mismatch")
        self.root_identity = _directory_identity(root_metadata)
        self.directories: dict[Path, int] = {}
        self.directory_identities: dict[Path, tuple[int, int, int, int]] = {}
        try:
            for relative in self.directory_paths:
                descriptor = self._open_directory(relative)
                self.directories[relative] = descriptor
                self.directory_identities[relative] = _directory_identity(os.fstat(descriptor))
        except Exception:
            self.close()
            raise

    def __enter__(self) -> "_PinnedRepository":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

    def close(self) -> None:
        for descriptor in getattr(self, "directories", {}).values():
            try:
                os.close(descriptor)
            except OSError:
                pass
        self.directories = {}
        root_fd = getattr(self, "root_fd", -1)
        if root_fd >= 0:
            try:
                os.close(root_fd)
            except OSError:
                pass
            self.root_fd = -1

    def _open_directory(self, relative: Path) -> int:
        descriptor = os.dup(self.root_fd)
        try:
            for part in relative.parts:
                next_descriptor = os.open(part, self._directory_flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = next_descriptor
                if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
                    raise StatusUnavailable("source directory is unavailable")
            return descriptor
        except Exception:
            os.close(descriptor)
            raise

    def stop_paths(self) -> tuple[Path, ...]:
        directory = self.directories[Path("reports/stops")]
        paths: list[Path] = []
        for name in sorted(os.listdir(directory)):
            if name == "README.md":
                continue
            if STOP_PATTERN.fullmatch(name) is None:
                raise StatusUnavailable("unexpected STOP inventory member")
            paths.append(Path("reports/stops") / name)
        if not paths:
            raise StatusUnavailable("STOP inventory is empty")
        return tuple(paths)

    def _read(self, relative: Path) -> bytes:
        if relative.is_absolute() or ".." in relative.parts or relative.parent not in self.directories:
            raise StatusUnavailable("source path is outside the pinned inventory")
        directory = self.directories[relative.parent]
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(relative.name, flags, dir_fd=directory)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise StatusUnavailable("source is not a single-link regular file")
            chunks: list[bytes] = []
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            after = os.fstat(descriptor)
            current = os.stat(relative.name, dir_fd=directory, follow_symlinks=False)
        finally:
            os.close(descriptor)
        if (
            stat.S_ISLNK(current.st_mode)
            or _file_identity(before) != _file_identity(after)
            or _file_identity(after) != _file_identity(current)
        ):
            raise StatusUnavailable("source identity changed during read")
        return b"".join(chunks)

    def read_sources(self, stop_paths: tuple[Path, ...]) -> dict[Path, bytes]:
        paths = (*STATIC_PATHS, *stop_paths)
        return {path: self._read(path) for path in paths}

    def verify_directories(self) -> None:
        current_root = self.root.lstat()
        if self.root_identity != _directory_identity(os.fstat(self.root_fd)) or self.root_identity != _directory_identity(current_root):
            raise StatusUnavailable("repository root changed during observation")
        for relative, expected in self.directory_identities.items():
            if _directory_identity(os.fstat(self.directories[relative])) != expected:
                raise StatusUnavailable("held source directory changed during observation")
            reopened = self._open_directory(relative)
            try:
                if _directory_identity(os.fstat(reopened)) != expected:
                    raise StatusUnavailable("source directory identity changed during observation")
            finally:
                os.close(reopened)


def _stop_paths(root: Path) -> tuple[Path, ...]:
    with _PinnedRepository(root) as repository:
        paths = repository.stop_paths()
        repository.verify_directories()
        return paths


def _read_sources(root: Path, stop_paths: tuple[Path, ...]) -> dict[Path, bytes]:
    with _PinnedRepository(root) as repository:
        sources = repository.read_sources(stop_paths)
        repository.verify_directories()
        return sources


def _validate(record: dict[str, Any], schema: dict[str, Any]) -> None:
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=CHECKER).validate(record)


def _current_stop_heads(stops: list[tuple[Path, dict[str, Any]]]) -> list[tuple[Path, dict[str, Any]]]:
    heads: dict[str, tuple[Path, dict[str, Any]]] = {}
    versions: dict[str, set[int]] = {}
    identities: set[tuple[str, int]] = set()
    for path, stop in stops:
        identity = (stop["id"], stop["version"])
        expected_name = f"{stop['id']}.v{stop['version']}.json"
        if path.name != expected_name or identity in identities:
            raise StatusUnavailable("STOP filename or identity mismatch")
        identities.add(identity)
        versions.setdefault(stop["id"], set()).add(stop["version"])
        current = heads.get(stop["id"])
        if current is None or stop["version"] > current[1]["version"]:
            heads[stop["id"]] = (path, stop)
    for observed in versions.values():
        if observed != set(range(1, max(observed) + 1)):
            raise StatusUnavailable("STOP version history has a gap")
    return [heads[key] for key in sorted(heads)]


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _build_status(repository: _PinnedRepository) -> dict[str, Any]:
    stop_paths = repository.stop_paths()
    initial = repository.read_sources(stop_paths)

    state = _parse(initial[PROJECT_STATE])
    bankroll = _parse(initial[BANKROLL])
    risk = _parse(initial[RISK_POLICY])
    stop_records = [(path, _parse(initial[path])) for path in stop_paths]
    project_schema = _parse(initial[PROJECT_SCHEMA])
    bankroll_schema = _parse(initial[BANKROLL_SCHEMA])
    risk_schema = _parse(initial[RISK_SCHEMA])
    stop_schema = _parse(initial[STOP_SCHEMA])
    status_schema = _parse(initial[STATUS_SCHEMA])

    _validate(state, project_schema)
    _validate(bankroll, bankroll_schema)
    _validate(risk, risk_schema)
    for _, stop in stop_records:
        _validate(stop, stop_schema)
        if (stop["status"] == "RESOLVED") != (stop["resolution_event_ref"] is not None):
            raise StatusUnavailable("STOP resolution state is contradictory")
    if set(risk["live_gate_requirements"]) != GATES:
        raise StatusUnavailable("risk gate inventory is incomplete")

    heads = _current_stop_heads(stop_records)
    open_heads = [(path, stop) for path, stop in heads if stop["status"] == "OPEN"]
    open_refs = [path.as_posix() for path, _ in open_heads]
    if state["active_stop_refs"] != open_refs:
        raise StatusUnavailable("project STOP references do not match current OPEN heads")
    if (
        state["phase"] != "M0"
        or state["status"] != "BLOCKED_FOR_APPROVAL_REMEDIATION_ALLOWED"
        or state["live_status"] != "LOCKED"
        or state["demonstrated_edge"] is not False
        or state["active_strategies"] != 0
        or bankroll["live_status"] != "LOCKED"
        or bankroll["live_deployable_minor"] != 0
        or bankroll["reserved_minor"] != 0
        or risk["phase"] != "M0"
        or risk["live_enabled"] is not False
        or risk["kill_switch"] != "ENGAGED"
        or risk["failure_action"] != "DENY_NEW_EXPOSURE"
        or set(risk["limits"]) != EXPECTED_LIMIT_KEYS
        or any(value != 0 for value in risk["limits"].values())
        or not open_heads
    ):
        raise StatusUnavailable("M0 safety state is contradictory")

    final_paths = repository.stop_paths()
    final = repository.read_sources(final_paths)
    repository.verify_directories()
    if stop_paths != final_paths or initial != final:
        raise StatusUnavailable("repository status changed during observation")

    report = {
        "schema_version": 1,
        "observatory_status": "VERIFIED_READ_ONLY_SNAPSHOT",
        "project": {
            "phase": state["phase"],
            "increment": state["increment"],
            "status": state["status"],
            "updated_at": state["updated_at"],
            "demonstrated_edge": state["demonstrated_edge"],
            "active_strategies": state["active_strategies"],
        },
        "safety": {
            "live_status": bankroll["live_status"],
            "kill_switch": risk["kill_switch"],
            "failure_action": risk["failure_action"],
            "currency": bankroll["currency"],
            "capital_basis": bankroll["basis"],
            "conceptual_minor": bankroll["total_minor"],
            "deployable_minor": bankroll["live_deployable_minor"],
            "paper_capital_minor": bankroll["paper_capital_minor"],
            "live_enabled": risk["live_enabled"],
            "all_m0_limits_minor": dict(risk["limits"]),
        },
        "open_stops": [
            {
                "id": stop["id"],
                "version": stop["version"],
                "severity": stop["severity"],
                "issued_at": stop["issued_at"],
                "issuer": stop["issuer"],
                "reason": stop["reason"],
                "affected_components": list(stop["affected_components"]),
                "remediation_required": list(stop["remediation_required"]),
                "path": path.as_posix(),
            }
            for path, stop in open_heads
        ],
        "progress": {
            "completed_scope": list(state["completed_scope"]),
            "remaining_m0": list(state["remaining_m0"]),
            "blockers": list(state["blockers"]),
            "next_assignment": state["next_assignment"],
            "open_findings": list(state["open_findings"]),
        },
        "evidence": {
            "freshness": "UNVERIFIED_OR_STALE",
            "currentness": "UNKNOWN",
            "authorizing_use": "DENY",
            "reason": "Positive authoritative currentness and an authenticated receipt/R-gate are not implemented.",
        },
        "capabilities": {
            "read_only": True,
            "repository_mutation": False,
            "scheduler_transition": False,
            "paper_execution": False,
            "live_execution": False,
            "capital_movement": False,
        },
        "source_digests": [
            {"path": path.as_posix(), "sha256": _sha256(initial[path])}
            for path in sorted(initial, key=lambda item: item.as_posix())
        ],
    }
    Draft202012Validator.check_schema(status_schema)
    Draft202012Validator(status_schema, format_checker=CHECKER).validate(report)
    return report


def build_status(root: Path = ROOT) -> dict[str, Any]:
    """Return one internally consistent repository status snapshot or deny."""
    with _PinnedRepository(root) as repository:
        return _build_status(repository)
