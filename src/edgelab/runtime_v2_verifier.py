"""Pure, non-authorizing runtime-v2 verification boundary.

The full reducer and retained event-content schemas are not published yet, so
this verifier deliberately cannot return CONSISTENT.  It validates the closed
storage descriptor, rejects all not-yet-supported runtime content, reports
missing prerequisites, and performs no I/O, selection, recovery, migration, or
mutation.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .runtime_v2_codec import (
    CanonicalJsonError,
    parse_canonical_json,
    storage_schema_digest,
)


STORAGE_DESCRIPTOR_SHA256 = (
    "d4da1ac30f9bd5cc32653138633e84ef1e90dabd389f2205be00ac8a73f11394"
)
STORAGE_DESCRIPTOR_SCHEMA_SHA256 = (
    "dc057e47c379ef73125fadde93c31bf7d2f6b031134d7fcb5055e09b7587ac84"
)


@dataclass(frozen=True, order=True, slots=True)
class VerificationFinding:
    code: str
    artifact: str
    coordinate: str


@dataclass(frozen=True, slots=True)
class RuntimeImage:
    storage_descriptor: bytes
    manifest: bytes = b""
    attachment: bytes = b""
    schema_registry: bytes = b""
    schema_documents: tuple[tuple[str, bytes], ...] = ()
    blobs: tuple[tuple[str, bytes], ...] = ()
    events: tuple[bytes, ...] = ()
    table_snapshots: tuple[tuple[str, tuple[tuple[Any, ...], ...]], ...] = ()
    checkpoints: tuple[bytes, ...] = ()
    selector_history: tuple[bytes, ...] = ()
    legacy_evidence: tuple[tuple[str, bytes], ...] | None = None


@dataclass(frozen=True, slots=True)
class VerificationResult:
    status: str
    findings: tuple[VerificationFinding, ...]
    runtime_id: str | None = None
    chain_id: str | None = None
    event_count: int | None = None
    head_event_id: str | None = None
    head_event_sha256: str | None = None
    schema_version: int = field(default=1, init=False)
    verifier_version: int = field(default=1, init=False)
    anchor_status: str = field(default="UNANCHORED", init=False)
    currentness_status: str = field(default="UNKNOWN", init=False)
    authorizing_use: str = field(default="DENY", init=False)

    def __post_init__(self) -> None:
        if self.status not in {"INVALID", "UNSUPPORTED"}:
            raise ValueError("unsupported verifier status")
        if not self.findings or tuple(sorted(set(self.findings))) != self.findings:
            raise ValueError("findings must be nonempty, unique, and sorted")

    def __bool__(self) -> bool:
        raise TypeError("verification results are not authorization booleans")

    def as_mapping(self) -> dict[str, Any]:
        mapping = asdict(self)
        mapping["findings"] = [asdict(finding) for finding in self.findings]
        return mapping


_REQUIRED_DESCRIPTOR_TABLES = (
    "attempts", "blobs", "claims", "events", "idempotency",
    "legacy_archive", "metadata", "migrations", "remediation_links",
    "reviews", "schema_documents", "schema_registry", "seals", "snapshots",
    "tasks",
)


def _finding(code: str, artifact: str, coordinate: str) -> VerificationFinding:
    return VerificationFinding(code, artifact, coordinate)


def _descriptor_findings(value: Any) -> list[VerificationFinding]:
    findings: list[VerificationFinding] = []
    if type(value) is not dict:
        return [_finding("DESCRIPTOR_NOT_OBJECT", "storage_descriptor", "/")]
    try:
        digest = storage_schema_digest(value)
    except CanonicalJsonError:
        return [_finding("DESCRIPTOR_VALUE_INVALID", "storage_descriptor", "/")]
    if digest != STORAGE_DESCRIPTOR_SHA256:
        findings.append(
            _finding("DESCRIPTOR_DIGEST_MISMATCH", "storage_descriptor", "/")
        )
    exact = {
        "schema_version": 1,
        "runtime_format_version": 2,
        "descriptor_id": "urn:edgelab:m0-3a-runtime-storage:2",
        "anchor_status": "UNANCHORED",
        "currentness_status": "UNKNOWN",
        "authorizing_use": "DENY",
    }
    for key, expected in exact.items():
        if type(value.get(key)) is not type(expected) or value.get(key) != expected:
            findings.append(_finding("DESCRIPTOR_IDENTITY_MISMATCH", "storage_descriptor", f"/{key}"))
    tables = value.get("tables")
    if type(tables) is not list:
        findings.append(_finding("DESCRIPTOR_TABLES_MISSING", "storage_descriptor", "/tables"))
    else:
        names = tuple(
            table.get("name") if type(table) is dict else None for table in tables
        )
        if names != _REQUIRED_DESCRIPTOR_TABLES:
            findings.append(_finding("DESCRIPTOR_TABLE_INVENTORY", "storage_descriptor", "/tables"))
    return findings


def verify_runtime_image(image: RuntimeImage) -> VerificationResult:
    """Verify only published pure prerequisites; always remain DENY-only."""
    if type(image) is not RuntimeImage:
        return VerificationResult(
            "INVALID", (_finding("IMAGE_TYPE", "runtime_image", "/"),)
        )
    findings: list[VerificationFinding] = []
    try:
        descriptor = parse_canonical_json(image.storage_descriptor)
        findings.extend(_descriptor_findings(descriptor))
    except CanonicalJsonError:
        findings.append(
            _finding("DESCRIPTOR_CANONICAL_JSON", "storage_descriptor", "/")
        )
    byte_inputs = (
        ("manifest", image.manifest),
        ("attachment", image.attachment),
        ("schema_registry", image.schema_registry),
    )
    tuple_inputs = (
        ("schema_documents", image.schema_documents),
        ("blobs", image.blobs),
        ("events", image.events),
        ("table_snapshots", image.table_snapshots),
        ("checkpoints", image.checkpoints),
        ("selector_history", image.selector_history),
    )
    for artifact, value in byte_inputs:
        if type(value) is not bytes or len(value) != 0:
            findings.append(
                _finding("UNSUPPORTED_INPUT_MUST_BE_EMPTY", artifact, "/")
            )
    for artifact, value in tuple_inputs:
        if type(value) is not tuple or len(value) != 0:
            findings.append(
                _finding("UNSUPPORTED_INPUT_MUST_BE_EMPTY", artifact, "/")
            )
    if image.legacy_evidence is not None:
        findings.append(
            _finding("UNSUPPORTED_INPUT_MUST_BE_EMPTY", "legacy_evidence", "/")
        )
    if findings:
        return VerificationResult("INVALID", tuple(sorted(set(findings))))
    unsupported = (
        _finding("ATTACHMENT_SCHEMA_UNPUBLISHED", "contract", "/attachment"),
        _finding("EVENT_CONTENT_SCHEMAS_UNPUBLISHED", "contract", "/schema_registry"),
        _finding("REDUCER_SEMANTICS_UNPUBLISHED", "contract", "/events"),
        _finding("RUNTIME_IMAGE_SCHEMA_UNPUBLISHED", "contract", "/"),
    )
    return VerificationResult("UNSUPPORTED", tuple(sorted(unsupported)))
