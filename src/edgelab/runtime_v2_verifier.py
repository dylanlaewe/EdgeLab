"""Pure, non-authorizing runtime-v2 verification boundary.

This verifier pins and validates the closed storage descriptor and retained
event-content schema bundle.  The reducer is not implemented, so the result
vocabulary deliberately remains only INVALID or UNSUPPORTED.  It performs no
I/O, selection, recovery, migration, mutation, or authority decision.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from hashlib import sha256
from typing import Any

from .runtime_v2_codec import (
    CanonicalJsonError,
    parse_canonical_json,
    schema_document_digest,
    schema_registry_digest,
    storage_schema_digest,
)


STORAGE_DESCRIPTOR_SHA256 = (
    "8a588ce0bd23a10ea984fa656b2f172dcc4b0ede501c501d414a662d17c60a63"
)
STORAGE_DESCRIPTOR_SCHEMA_SHA256 = (
    "cb54877057a81440fa8510111a984ba2cbd528b48842066fb49a3a92cd7a6193"
)
SCHEMA_REGISTRY_SCHEMA_SHA256 = (
    "b31a025add8419bfc1db2bee579d2511a3e93c59dcea47cd832655affc03d630"
)
RUNTIME_MANIFEST_SCHEMA_SHA256 = (
    "dcec875b3bb65178fc58e19d84c7fed5d85df97f44f501b3e4aa3c1c44b791de"
)
SCHEMA_REGISTRY_SHA256 = (
    "6b68797766e10c5ff8260d9d7b6cb31759466765287e7a23c377bd781a97bfd6"
)
SCHEMA_DOCUMENT_PINS = (
    ("urn:edgelab:m0-3a-command-request:2", "8c7b7cf050700f696e44d89899365bdc80620dd1071dad7aa08707c91f88388e"),
    ("urn:edgelab:m0-3a-event-envelope:2", "ae3655e0b94610e54ad00b514de1eeb78e9abd54f5828fd93387583b76f2b553"),
    ("urn:edgelab:m0-3a-event-payload:2", "1b26427cde4998e23ec503df3a46b527893a2f40c27e7d0efdadf5474e8e30e4"),
    ("urn:edgelab:m0-3a-legacy-v1-projection:1", "15689e50b3abe3895c546ddc606fe9b754ab993804b13aedd85e8e789374ba53"),
    ("urn:edgelab:m0-3a-legacy-v1-row-archive:1", "fcd734fdda399047738bb139ed3971e5906eaaa7063435f4902a259d2a9d3a9c"),
    ("urn:edgelab:m0-3a-response-projection:2", "9a01e5c47f628c4a80082f6ac1276ecae345c47c42923789d0743d4fd41f0a61"),
    ("urn:edgelab:m0-3a-runtime-checkpoint:2", "2c9fc0fed41a49342ec91a8b5d17dd3f3e23e7612a07257af5f1d6acd6d4c05a"),
    ("urn:edgelab:m0-3a-runtime-export:2", "c9b345e83d99173f41c52fd818471b428ff0a7503ce9340e76531d7cb58b079a"),
    ("urn:edgelab:m0-3a-task-state:2", "c8b9a47df5b91ae467f3008c8c7c27bdf2df089a3fbc25d684f53e56bc37ede8"),
)
MAX_SCHEMA_DOCUMENT_BYTES = 262_144
MAX_SCHEMA_REGISTRY_BYTES = 262_144
MAX_SCHEMA_BUNDLE_BYTES = 2_097_152
MAX_FINDINGS = 128
MAX_FINDING_ARTIFACT_CHARS = 256
MAX_FINDING_COORDINATE_CHARS = 512
MAX_SCHEMA_REF_NODES = 4_096
_DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema"
_FORBIDDEN_SCHEMA_KEYWORDS = {
    "$anchor", "$dynamicAnchor", "$dynamicRef", "$recursiveAnchor",
    "$recursiveRef", "$vocabulary",
}
_ALLOWED_SCHEMA_KEYWORDS = {"$schema", "$id", "$defs", "$ref"}


@dataclass(frozen=True, order=True, slots=True)
class VerificationFinding:
    code: str
    artifact: str
    coordinate: str


@dataclass(frozen=True, slots=True)
class SchemaDocumentRecord:
    schema_id: str
    document_sha256: str
    canonical_json: bytes


@dataclass(frozen=True, slots=True)
class BlobRecord:
    sha256: str
    schema_id: str
    canonical_json: bytes


@dataclass(frozen=True, slots=True)
class RuntimeImage:
    storage_descriptor: bytes
    manifest: bytes = b""
    attachment: bytes = b""
    schema_registry: bytes = b""
    schema_documents: tuple[SchemaDocumentRecord, ...] = ()
    blobs: tuple[BlobRecord, ...] = ()
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
    def bounded(value: str, maximum: int) -> str:
        if len(value) <= maximum:
            return value
        suffix = f"#sha256={sha256(value.encode('utf-8')).hexdigest()}"
        return value[:maximum - len(suffix)] + suffix

    return VerificationFinding(
        code,
        bounded(artifact, MAX_FINDING_ARTIFACT_CHARS),
        bounded(coordinate, MAX_FINDING_COORDINATE_CHARS),
    )


def _closed_result(status: str, findings: list[VerificationFinding] | tuple[VerificationFinding, ...]) -> VerificationResult:
    ordered = tuple(sorted(set(findings)))
    if len(ordered) > MAX_FINDINGS:
        ordered = tuple(sorted(
            (*ordered[:MAX_FINDINGS - 1],
             _finding("FINDINGS_TRUNCATED", "verifier", "/findings"))
        ))
    closed = ordered
    return VerificationResult(status, closed)


def _schema_safety_findings(
    schema_id: str, value: Any, limit: int = MAX_FINDINGS
) -> list[VerificationFinding]:
    findings: list[VerificationFinding] = []
    seen: set[tuple[str, str]] = set()

    def add(code: str, coordinate: str) -> None:
        key = (code, coordinate)
        if key in seen or len(findings) >= limit:
            return
        seen.add(key)
        findings.append(_finding(code, schema_id, coordinate))

    def full() -> bool:
        return len(findings) >= limit

    if limit <= 0:
        return findings
    if type(value) is not dict:
        return [_finding("SCHEMA_DOCUMENT_NOT_OBJECT", schema_id, "/")]
    if value.get("$schema") != _DRAFT_2020_12:
        add("SCHEMA_DIALECT", "/$schema")
    if value.get("$id") != schema_id:
        add("SCHEMA_ID_MISMATCH", "/$id")
    edges: dict[str, set[str]] = {}
    definitions = value.get("$defs", {})
    if type(definitions) is not dict:
        add("SCHEMA_DEFS_NOT_OBJECT", "/$defs")
        definitions = {}

    def walk(node: Any, path: str, owner: str | None = None) -> None:
        if full():
            return
        if type(node) is dict:
            for key, child in node.items():
                if full():
                    return
                child_path = f"{path}/{key}"
                if key == "$id" and path != "":
                    add("SCHEMA_NESTED_ID", child_path)
                if key == "$schema" and path != "":
                    add("SCHEMA_NESTED_DIALECT", child_path)
                if key in _FORBIDDEN_SCHEMA_KEYWORDS:
                    add("SCHEMA_FORBIDDEN_KEYWORD", child_path)
                if key.startswith("$") and key not in _ALLOWED_SCHEMA_KEYWORDS and key not in _FORBIDDEN_SCHEMA_KEYWORDS:
                    add("SCHEMA_UNKNOWN_KEYWORD", child_path)
                if path == "" and key == "$defs":
                    # Root definitions are walked exactly once below with their
                    # graph owner, avoiding duplicate diagnostics and work.
                    continue
                if key == "$ref":
                    token = child[8:] if type(child) is str and child.startswith("#/$defs/") else ""
                    if (
                        not token
                        or len(token) > 64
                        or not token[0].isalpha()
                        or not all(character.isascii() and (character.isalnum() or character in "_-") for character in token)
                    ):
                        add("SCHEMA_REF_OUTSIDE_PROFILE", child_path)
                    else:
                        target = token
                        if target not in definitions:
                            add("SCHEMA_REF_DANGLING", child_path)
                        if owner is not None:
                            edges.setdefault(owner, set()).add(target)
                walk(child, child_path, owner)
        elif type(node) is list:
            for index, child in enumerate(node):
                if full():
                    return
                walk(child, f"{path}/{index}", owner)

    walk(value, "")
    if full():
        return findings
    for name, definition in definitions.items():
        if full():
            return findings
        if (
            type(name) is not str
            or not name
            or len(name) > 64
            or not name[0].isalpha()
            or not all(character.isascii() and (character.isalnum() or character in "_-") for character in name)
        ):
            add("SCHEMA_DEF_NAME", "/$defs")
            continue
        edges.setdefault(name, set())
        walk(definition, f"/$defs/{name}", name)
    if len(edges) > MAX_SCHEMA_REF_NODES:
        add("SCHEMA_REF_GRAPH_TOO_LARGE", "/$defs")
        return findings
    colors: dict[str, int] = {}
    for start in sorted(edges):
        if full():
            return findings
        if colors.get(start, 0) != 0:
            continue
        colors[start] = 1
        stack: list[tuple[str, int, tuple[str, ...]]] = [
            (start, 0, tuple(sorted(edges[start])))
        ]
        while stack:
            if full():
                return findings
            name, index, targets = stack[-1]
            if index == len(targets):
                colors[name] = 2
                stack.pop()
                continue
            target = targets[index]
            stack[-1] = (name, index + 1, targets)
            if target not in edges:
                continue
            color = colors.get(target, 0)
            if color == 1:
                add("SCHEMA_REF_CYCLE", f"/$defs/{target}")
            elif color == 0:
                colors[target] = 1
                stack.append((target, 0, tuple(sorted(edges[target]))))
    return findings


def _schema_bundle_findings(image: RuntimeImage) -> tuple[list[VerificationFinding], bool]:
    findings: list[VerificationFinding] = []
    registry_present = type(image.schema_registry) is bytes and bool(image.schema_registry)
    documents_present = type(image.schema_documents) is tuple and bool(image.schema_documents)
    if not registry_present and not documents_present:
        if type(image.schema_registry) is not bytes:
            findings.append(_finding("SCHEMA_REGISTRY_TYPE", "schema_registry", "/"))
        if type(image.schema_documents) is not tuple:
            findings.append(_finding("SCHEMA_DOCUMENTS_TYPE", "schema_documents", "/"))
        return findings, False
    if not registry_present or not documents_present:
        findings.append(_finding("SCHEMA_BUNDLE_INCOMPLETE", "schema_bundle", "/"))
        return findings, False
    if len(image.schema_registry) > MAX_SCHEMA_REGISTRY_BYTES:
        findings.append(_finding("SCHEMA_REGISTRY_TOO_LARGE", "schema_registry", "/"))
        return findings, False
    if len(image.schema_documents) != len(SCHEMA_DOCUMENT_PINS):
        findings.append(_finding("SCHEMA_DOCUMENT_INVENTORY", "schema_documents", "/"))
        return findings, False
    raw_total = len(image.schema_registry)
    for index, record in enumerate(image.schema_documents):
        if type(record) is not SchemaDocumentRecord:
            findings.append(_finding("SCHEMA_DOCUMENT_RECORD_TYPE", "schema_documents", f"/{index}"))
            continue
        expected_schema_id, _ = SCHEMA_DOCUMENT_PINS[index]
        if type(record.schema_id) is not str or not record.schema_id:
            findings.append(_finding("SCHEMA_DOCUMENT_ID_TYPE", "schema_documents", f"/{index}/schema_id"))
        elif record.schema_id != expected_schema_id:
            findings.append(_finding("SCHEMA_DOCUMENT_ID_MISMATCH", "schema_documents", f"/{index}/schema_id"))
        if (
            type(record.document_sha256) is not str
            or len(record.document_sha256) != 64
            or any(character not in "0123456789abcdef" for character in record.document_sha256)
        ):
            findings.append(_finding("SCHEMA_DOCUMENT_DIGEST_TYPE", "schema_documents", f"/{index}/document_sha256"))
        if type(record.canonical_json) is not bytes:
            findings.append(_finding("SCHEMA_DOCUMENT_BYTES_TYPE", "schema_documents", f"/{index}/canonical_json"))
            continue
        raw_total += len(record.canonical_json)
        if len(record.canonical_json) > MAX_SCHEMA_DOCUMENT_BYTES:
            findings.append(_finding("SCHEMA_DOCUMENT_TOO_LARGE", "schema_documents", f"/{index}/canonical_json"))
    if raw_total > MAX_SCHEMA_BUNDLE_BYTES:
        findings.append(_finding("SCHEMA_BUNDLE_TOO_LARGE", "schema_bundle", "/"))
    if findings:
        return findings, False
    try:
        registry = parse_canonical_json(image.schema_registry)
    except CanonicalJsonError:
        return [_finding("SCHEMA_REGISTRY_CANONICAL_JSON", "schema_registry", "/")], False
    if type(registry) is not dict:
        return [_finding("SCHEMA_REGISTRY_NOT_OBJECT", "schema_registry", "/")], False
    try:
        registry_digest = schema_registry_digest(registry)
    except CanonicalJsonError:
        return [_finding("SCHEMA_REGISTRY_VALUE_INVALID", "schema_registry", "/")], False
    if registry_digest != SCHEMA_REGISTRY_SHA256:
        findings.append(_finding("SCHEMA_REGISTRY_DIGEST_MISMATCH", "schema_registry", "/"))
    observed_inventory = tuple(
        (record.schema_id, record.document_sha256)
        for record in image.schema_documents
    )
    if observed_inventory != SCHEMA_DOCUMENT_PINS:
        findings.append(_finding("SCHEMA_DOCUMENT_INVENTORY", "schema_documents", "/"))
    registry_inventory = registry.get("documents")
    if type(registry_inventory) is not list or tuple(
        (item.get("schema_id"), item.get("document_sha256"))
        if type(item) is dict else (None, None)
        for item in registry_inventory
    ) != SCHEMA_DOCUMENT_PINS:
        findings.append(_finding("SCHEMA_REGISTRY_DOCUMENTS", "schema_registry", "/documents"))
    for index, record in enumerate(image.schema_documents):
        expected_schema_id, _ = SCHEMA_DOCUMENT_PINS[index]
        try:
            document = parse_canonical_json(record.canonical_json)
        except CanonicalJsonError:
            findings.append(_finding("SCHEMA_DOCUMENT_CANONICAL_JSON", expected_schema_id, "/"))
            continue
        if type(document) is not dict:
            findings.append(_finding("SCHEMA_DOCUMENT_NOT_OBJECT", expected_schema_id, "/"))
            continue
        try:
            digest = schema_document_digest(document)
        except CanonicalJsonError:
            findings.append(_finding("SCHEMA_DOCUMENT_VALUE_INVALID", expected_schema_id, "/"))
            continue
        if digest != record.document_sha256:
            findings.append(_finding("SCHEMA_DOCUMENT_DIGEST_MISMATCH", expected_schema_id, f"/{index}"))
        remaining = max(0, MAX_FINDINGS + 1 - len(findings))
        findings.extend(
            _schema_safety_findings(expected_schema_id, document, remaining)
        )
    return findings, not findings


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
        return _closed_result(
            "INVALID", [_finding("IMAGE_TYPE", "runtime_image", "/")]
        )
    findings: list[VerificationFinding] = []
    if type(image.storage_descriptor) is not bytes:
        findings.append(_finding("DESCRIPTOR_BYTES_TYPE", "storage_descriptor", "/"))
    elif len(image.storage_descriptor) > MAX_SCHEMA_BUNDLE_BYTES:
        findings.append(_finding("DESCRIPTOR_TOO_LARGE", "storage_descriptor", "/"))
    else:
        try:
            descriptor = parse_canonical_json(image.storage_descriptor)
            findings.extend(_descriptor_findings(descriptor))
        except CanonicalJsonError:
            findings.append(
                _finding("DESCRIPTOR_CANONICAL_JSON", "storage_descriptor", "/")
            )
    bundle_findings, bundle_valid = _schema_bundle_findings(image)
    findings.extend(bundle_findings)
    byte_inputs = (
        ("manifest", image.manifest),
        ("attachment", image.attachment),
    )
    tuple_inputs = (
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
        return _closed_result("INVALID", findings)
    unsupported = [
        _finding("ATTACHMENT_VERIFICATION_UNIMPLEMENTED", "contract", "/attachment"),
        _finding("REDUCER_UNIMPLEMENTED", "contract", "/events"),
        _finding("RUNTIME_IMAGE_SCHEMA_UNPUBLISHED", "contract", "/"),
    ]
    if not bundle_valid:
        unsupported.append(
            _finding("SCHEMA_BUNDLE_REQUIRED", "contract", "/schema_registry")
        )
    return _closed_result("UNSUPPORTED", unsupported)
