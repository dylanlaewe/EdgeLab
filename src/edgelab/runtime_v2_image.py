"""Private, pure host preflight for candidate runtime-format-2 images.

This module deliberately is not connected to the public verifier.  It checks
only exact immutable host transport types, bounded resource use, and supplied
table shape/order.  It does not parse retained JSON, reduce events, establish
local consistency, select a runtime, or grant authority.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TypeAlias


JsonCell: TypeAlias = type(None) | str | int

INT64_MIN = -9_223_372_036_854_775_808
INT64_MAX = 9_223_372_036_854_775_807
MAX_FINDINGS = 128
MAX_EVENTS = 100_000
MAX_BLOBS = 300_000
MAX_EVENT_BYTES = 1_048_576
MAX_BOOTSTRAP_DOCUMENT_BYTES = 1_048_576
MAX_CHECKPOINT_COPIES = 49_999
MAX_SELECTORS = 50_001
MIN_SELECTORS = 2
MAX_BLOB_BYTES = 16_777_216
MAX_SCHEMA_DOCUMENT_BYTES = 262_144
MAX_SCHEMA_REGISTRY_BYTES = 262_144
MAX_SCHEMA_BUNDLE_BYTES = 2_097_152
MAX_TOTAL_ACCOUNTED_INPUT_BYTES = 1_073_741_824
MAX_TOTAL_ROOT_WORK_BYTES = 1_073_741_824
_TABLE_ROOT_PREFIX = b"EDGELAB\0TABLE\0V2\0"
_SIZE_CEILING = MAX_TOTAL_ACCOUNTED_INPUT_BYTES + 1
_MISSING = object()


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
class TableSnapshot:
    table: str
    rows: tuple[tuple[JsonCell, ...], ...]


@dataclass(frozen=True, slots=True)
class RuntimeImage:
    storage_descriptor: bytes
    verifier_dependency_closure: bytes
    manifest: bytes
    attachment: bytes
    schema_registry: bytes
    schema_documents: tuple[SchemaDocumentRecord, ...]
    blobs: tuple[BlobRecord, ...]
    events: tuple[bytes, ...]
    table_snapshots: tuple[TableSnapshot, ...]
    checkpoint_copies: tuple[bytes, ...]
    selector_history: tuple[bytes, ...]
    legacy_evidence: None


@dataclass(frozen=True, order=True, slots=True)
class ImageViolation:
    code: str
    artifact: str
    coordinate: str


@dataclass(frozen=True, slots=True)
class RuntimeImagePreflight:
    """A non-authorizing report suitable only for entering reduction."""

    image: RuntimeImage | None
    violations: tuple[ImageViolation, ...]
    total_accounted_input_bytes: int | None
    final_supplied_root_work_bytes: int | None
    authorizing_use: str = field(default="DENY", init=False)

    def __bool__(self) -> bool:
        raise TypeError("runtime image preflight is not an authorization boolean")


@dataclass(frozen=True, slots=True)
class _ColumnSpec:
    name: str
    storage_type: str
    nullable: bool


@dataclass(frozen=True, slots=True)
class _TableSpec:
    name: str
    columns: tuple[_ColumnSpec, ...]
    primary_key: tuple[int, ...]
    row_order: tuple[int, ...]
    max_rows: int


def _c(name: str, storage_type: str, nullable: bool = False) -> _ColumnSpec:
    return _ColumnSpec(name, storage_type, nullable)


_TABLE_SPECS = (
    _TableSpec("attempts", (_c("task_id", "TEXT"), _c("attempt", "INTEGER"), _c("predecessor_attempt", "INTEGER", True), _c("origin_event_id", "TEXT"), _c("head_task_sequence", "INTEGER"), _c("head_event_id", "TEXT"), _c("head_event_sha256", "TEXT")), (0, 1), (0, 1), 100_000),
    _TableSpec("blobs", (_c("sha256", "TEXT"), _c("schema_id", "TEXT"), _c("canonical_json", "TEXT")), (0,), (0,), 300_000),
    _TableSpec("claims", (_c("claim_id", "TEXT"), _c("task_id", "TEXT"), _c("attempt", "INTEGER"), _c("fence", "INTEGER"), _c("status", "TEXT"), _c("actor", "TEXT"), _c("opened_event_id", "TEXT"), _c("closed_event_id", "TEXT", True)), (0,), (0,), 100_000),
    _TableSpec("events", (_c("global_sequence", "INTEGER"), _c("event_id", "TEXT"), _c("event_sha256", "TEXT"), _c("canonical_json", "TEXT")), (0,), (0,), 100_000),
    _TableSpec("idempotency", (_c("operation_key", "TEXT"), _c("transaction_id", "TEXT"), _c("request_sha256", "TEXT"), _c("response_sha256", "TEXT"), _c("commit_event_id", "TEXT"), _c("commit_global_sequence", "INTEGER"), _c("committed_at", "TEXT")), (0,), (0,), 100_000),
    _TableSpec("legacy_archive", (_c("singleton", "TEXT"), _c("source_runtime_id", "TEXT"), _c("source_assurance", "TEXT"), _c("source_attachment_sha256", "TEXT"), _c("source_storage_inventory_sha256", "TEXT"), _c("source_backup_sha256", "TEXT"), _c("source_global_head_id", "TEXT"), _c("source_global_head_sha256", "TEXT"), _c("source_row_archive_sha256", "TEXT"), _c("source_projection_sha256", "TEXT"), _c("migration_plan_sha256", "TEXT"), _c("frozen_verifier_commit", "TEXT"), _c("frozen_verifier_closure_sha256", "TEXT"), _c("source_repository_bundle_sha256", "TEXT"), _c("archive_blob_sha256", "TEXT"), _c("projection_blob_sha256", "TEXT")), (0,), (0,), 1),
    _TableSpec("metadata", (_c("singleton", "TEXT"), _c("runtime_id", "TEXT"), _c("chain_id", "TEXT"), _c("runtime_format_version", "INTEGER"), _c("event_format_version", "INTEGER"), _c("source_kind", "TEXT"), _c("created_at", "TEXT"), _c("manifest_sha256", "TEXT"), _c("attachment_sha256", "TEXT"), _c("storage_schema_sha256", "TEXT"), _c("schema_registry_sha256", "TEXT"), _c("genesis_event_id", "TEXT"), _c("genesis_event_sha256", "TEXT"), _c("repository_generation", "INTEGER"), _c("repository_bundle_sha256", "TEXT"), _c("global_head_sequence", "INTEGER"), _c("global_head_event_id", "TEXT"), _c("global_head_event_sha256", "TEXT"), _c("latest_checkpoint_sha256", "TEXT", True), _c("active_selector_generation", "INTEGER"), _c("active_selector_sha256", "TEXT"), _c("selector_history_sha256", "TEXT"), _c("authority_binding_sha256", "TEXT", True), _c("anchor_status", "TEXT"), _c("currentness_status", "TEXT"), _c("authorizing_use", "TEXT")), (0,), (0,), 1),
    _TableSpec("migrations", (_c("migration_id", "TEXT"), _c("migration_sequence", "INTEGER"), _c("event_id", "TEXT"), _c("payload_sha256", "TEXT"), _c("created_at", "TEXT")), (0,), (1, 0), 0),
    _TableSpec("remediation_links", (_c("link_id", "TEXT"), _c("source_task_id", "TEXT"), _c("source_attempt", "INTEGER"), _c("child_task_id", "TEXT"), _c("child_attempt", "INTEGER"), _c("source_event_id", "TEXT"), _c("child_event_id", "TEXT"), _c("decision_sha256", "TEXT"), _c("link_sha256", "TEXT")), (0,), (0,), 100_000),
    _TableSpec("reviews", (_c("assignment_id", "TEXT"), _c("task_id", "TEXT"), _c("attempt", "INTEGER"), _c("actor", "TEXT"), _c("role", "TEXT"), _c("status", "TEXT"), _c("opened_event_id", "TEXT"), _c("closed_event_id", "TEXT", True)), (0,), (0,), 100_000),
    _TableSpec("schema_documents", (_c("schema_id", "TEXT"), _c("document_sha256", "TEXT"), _c("canonical_json", "TEXT")), (0,), (0,), 9),
    _TableSpec("schema_registry", (_c("singleton", "TEXT"), _c("schema_registry_sha256", "TEXT"), _c("canonical_json", "TEXT")), (0,), (0,), 1),
    _TableSpec("seals", (_c("seal_id", "TEXT"), _c("runtime_id", "TEXT"), _c("chain_id", "TEXT"), _c("seal_type", "TEXT"), _c("attachment_sha256", "TEXT"), _c("genesis_event_id", "TEXT"), _c("genesis_event_sha256", "TEXT"), _c("manifest_sha256", "TEXT"), _c("source_event_id", "TEXT"), _c("created_at", "TEXT")), (0,), (0,), 1),
    _TableSpec("snapshots", (_c("snapshot_id", "TEXT"), _c("snapshot_kind", "TEXT"), _c("snapshot_sequence", "INTEGER"), _c("event_id", "TEXT"), _c("document_sha256", "TEXT"), _c("document_blob_sha256", "TEXT"), _c("through_global_sequence", "INTEGER"), _c("head_event_id", "TEXT"), _c("head_event_sha256", "TEXT"), _c("prior_document_sha256", "TEXT", True), _c("created_at", "TEXT")), (0,), (1, 2, 0), 100_000),
    _TableSpec("tasks", (_c("task_id", "TEXT"), _c("attempt", "INTEGER"), _c("workflow", "TEXT"), _c("execution", "TEXT"), _c("review", "TEXT"), _c("scheduler_generation", "INTEGER"), _c("dispatch_generation", "INTEGER"), _c("task_fence", "INTEGER"), _c("active_claim_id", "TEXT", True), _c("reviewer_assignment_id", "TEXT", True), _c("continuation_count", "INTEGER"), _c("repository_generation", "INTEGER"), _c("decision_receipt_digest", "TEXT"), _c("owner", "TEXT"), _c("owner_role", "TEXT"), _c("reviewer", "TEXT", True), _c("predecessor_task", "TEXT", True), _c("successor_task", "TEXT", True)), (0,), (0,), 100_000),
)

TABLE_NAMES = tuple(spec.name for spec in _TABLE_SPECS)


class _FindingSink:
    __slots__ = ("_items", "_seen", "_truncated")

    def __init__(self) -> None:
        self._items: list[ImageViolation] = []
        self._seen: set[ImageViolation] = set()
        self._truncated = False

    def add(self, code: str, artifact: str, coordinate: str) -> None:
        finding = ImageViolation(code, artifact, coordinate)
        if finding in self._seen:
            return
        if len(self._items) >= MAX_FINDINGS - 1:
            self._truncated = True
            return
        self._seen.add(finding)
        self._items.append(finding)

    def result(self) -> tuple[ImageViolation, ...]:
        items = list(self._items)
        if self._truncated:
            items.append(ImageViolation("FINDINGS_TRUNCATED", "preflight", "/findings"))
        return tuple(sorted(items))


def _read_slot(value: object, name: str) -> object:
    try:
        return object.__getattribute__(value, name)
    except AttributeError:
        return _MISSING


def _bounded_add(total: int, amount: int) -> int:
    return min(_SIZE_CEILING, total + amount)


def _utf8_size(
    value: str,
    cache: dict[int, tuple[str, int | None]] | None = None,
) -> int | None:
    identity = id(value)
    if cache is not None:
        cached = cache.get(identity)
        if cached is not None and cached[0] is value:
            return cached[1]
    total = 0
    for character in value:
        codepoint = ord(character)
        if 0xD800 <= codepoint <= 0xDFFF:
            total = -1
            break
        if codepoint <= 0x7F:
            total = _bounded_add(total, 1)
        elif codepoint <= 0x7FF:
            total = _bounded_add(total, 2)
        elif codepoint <= 0xFFFF:
            total = _bounded_add(total, 3)
        else:
            total = _bounded_add(total, 4)
        if total == _SIZE_CEILING:
            break
    result = None if total < 0 else total
    if cache is not None:
        cache[identity] = (value, result)
    return result


def _canonical_string_size(
    value: str,
    cache: dict[int, tuple[str, int | None]] | None = None,
) -> int | None:
    identity = id(value)
    if cache is not None:
        cached = cache.get(identity)
        if cached is not None and cached[0] is value:
            return cached[1]
    total = 2
    for character in value:
        codepoint = ord(character)
        if 0xD800 <= codepoint <= 0xDFFF:
            total = -1
            break
        if character in {'"', "\\"}:
            total = _bounded_add(total, 2)
        elif codepoint in {8, 9, 10, 12, 13}:
            total = _bounded_add(total, 2)
        elif codepoint < 0x20:
            total = _bounded_add(total, 6)
        elif codepoint <= 0x7F:
            total = _bounded_add(total, 1)
        elif codepoint <= 0xFFFF:
            total = _bounded_add(total, 6)
        else:
            total = _bounded_add(total, 12)
        if total == _SIZE_CEILING:
            break
    result = None if total < 0 else total
    if cache is not None:
        cache[identity] = (value, result)
    return result


def _canonical_cell_size(
    value: JsonCell,
    string_cache: dict[int, tuple[str, int | None]] | None = None,
) -> int | None:
    if value is None:
        return 4
    if type(value) is int:
        if value < INT64_MIN or value > INT64_MAX:
            return None
        return len(str(value))
    if type(value) is str:
        return _canonical_string_size(value, string_cache)
    return None


def _canonical_rows_size(
    rows: tuple[tuple[JsonCell, ...], ...],
    string_cache: dict[int, tuple[str, int | None]] | None = None,
) -> int | None:
    total = 2 + max(0, len(rows) - 1)
    for row in rows:
        if type(row) is not tuple:
            return None
        total = _bounded_add(total, 2 + max(0, len(row) - 1))
        for value in row:
            size = _canonical_cell_size(value, string_cache)
            if size is None:
                return None
            total = _bounded_add(total, size)
            if total == _SIZE_CEILING:
                return total
    return total


def _canonical_snapshot_size(
    snapshot: TableSnapshot,
    string_cache: dict[int, tuple[str, int | None]] | None = None,
) -> int | None:
    table_size = _canonical_string_size(snapshot.table, string_cache)
    rows_size = _canonical_rows_size(snapshot.rows, string_cache)
    if table_size is None or rows_size is None:
        return None
    # canonical key order is "rows", then "table"
    total = _bounded_add(len(b'{"rows":'), rows_size)
    total = _bounded_add(total, len(b',"table":'))
    total = _bounded_add(total, table_size)
    return _bounded_add(total, 1)


def _ordered_key(row: tuple[JsonCell, ...], indexes: tuple[int, ...]) -> tuple[object, ...] | None:
    result: list[object] = []
    for index in indexes:
        value = row[index]
        if type(value) is str:
            # For Unicode scalar strings, code-point order and UTF-8 binary
            # order are identical. Validation rejects surrogates first, so no
            # potentially huge encoded copy is required here.
            result.append(value)
        elif type(value) is int:
            result.append(value)
        else:
            return None
    return tuple(result)


def inspect_runtime_image_host(candidate: object) -> RuntimeImagePreflight:
    """Inspect only the closed immutable host transport and resource bounds."""
    findings = _FindingSink()
    if type(candidate) is not RuntimeImage:
        findings.add("IMAGE_TYPE", "runtime_image", "/")
        return RuntimeImagePreflight(None, findings.result(), None, None)
    field_names = (
        "storage_descriptor",
        "verifier_dependency_closure",
        "manifest",
        "attachment",
        "schema_registry",
        "schema_documents",
        "blobs",
        "events",
        "table_snapshots",
        "checkpoint_copies",
        "selector_history",
        "legacy_evidence",
    )
    captured: dict[str, object] = {}
    for name in field_names:
        value = _read_slot(candidate, name)
        if value is _MISSING:
            findings.add("IMAGE_FIELD_MISSING", name, "/")
        else:
            captured[name] = value
    if len(captured) != len(field_names):
        return RuntimeImagePreflight(None, findings.result(), None, None)

    accounting_complete = True
    total_accounted = 0
    utf8_cache: dict[int, tuple[str, int | None]] = {}
    canonical_string_cache: dict[int, tuple[str, int | None]] = {}

    byte_fields = (
        ("storage_descriptor", captured["storage_descriptor"], None),
        ("verifier_dependency_closure", captured["verifier_dependency_closure"], MAX_BOOTSTRAP_DOCUMENT_BYTES),
        ("manifest", captured["manifest"], MAX_BOOTSTRAP_DOCUMENT_BYTES),
        ("attachment", captured["attachment"], MAX_BOOTSTRAP_DOCUMENT_BYTES),
        ("schema_registry", captured["schema_registry"], MAX_SCHEMA_REGISTRY_BYTES),
    )
    for name, value, maximum in byte_fields:
        if type(value) is not bytes:
            findings.add("IMAGE_FIELD_TYPE", name, "/")
            accounting_complete = False
            continue
        total_accounted = _bounded_add(total_accounted, len(value))
        if maximum is not None and len(value) > maximum:
            findings.add("IMAGE_ITEM_BYTE_LIMIT", name, "/")

    tuple_fields = (
        ("schema_documents", captured["schema_documents"]),
        ("blobs", captured["blobs"]),
        ("events", captured["events"]),
        ("table_snapshots", captured["table_snapshots"]),
        ("checkpoint_copies", captured["checkpoint_copies"]),
        ("selector_history", captured["selector_history"]),
    )
    tuple_valid: dict[str, bool] = {}
    for name, value in tuple_fields:
        valid = type(value) is tuple
        tuple_valid[name] = valid
        if not valid:
            findings.add("IMAGE_FIELD_TYPE", name, "/")
            accounting_complete = False
    if captured["legacy_evidence"] is not None:
        findings.add("IMAGE_LEGACY_EVIDENCE", "legacy_evidence", "/")
        accounting_complete = False

    cardinality_valid: dict[str, bool] = {}
    cardinalities = (
        ("schema_documents", 9, 9),
        ("blobs", 0, MAX_BLOBS),
        ("events", 0, MAX_EVENTS),
        ("table_snapshots", len(_TABLE_SPECS), len(_TABLE_SPECS)),
        ("checkpoint_copies", 0, MAX_CHECKPOINT_COPIES),
        ("selector_history", MIN_SELECTORS, MAX_SELECTORS),
    )
    for name, minimum, maximum in cardinalities:
        if not tuple_valid.get(name, False):
            cardinality_valid[name] = False
            continue
        value = captured[name]
        valid = minimum <= len(value) <= maximum
        cardinality_valid[name] = valid
        if not valid:
            findings.add("IMAGE_CARDINALITY_LIMIT", name, "/")
            accounting_complete = False

    schema_bundle_bytes = (
        len(captured["schema_registry"])
        if type(captured["schema_registry"]) is bytes else 0
    )
    clean_schema_documents: list[SchemaDocumentRecord] = []
    if cardinality_valid.get("schema_documents", False):
        for index, record in enumerate(captured["schema_documents"]):
            coordinate = f"/{index}"
            if type(record) is not SchemaDocumentRecord:
                findings.add("IMAGE_RECORD_TYPE", "schema_documents", coordinate)
                accounting_complete = False
                continue
            record_values = {
                name: _read_slot(record, name)
                for name in ("schema_id", "document_sha256", "canonical_json")
            }
            missing = [
                name for name, value in record_values.items()
                if value is _MISSING
            ]
            if missing:
                for name in missing:
                    findings.add(
                        "IMAGE_RECORD_FIELD_MISSING",
                        "schema_documents",
                        f"{coordinate}/{name}",
                    )
                accounting_complete = False
                continue
            for field_name in ("schema_id", "document_sha256"):
                value = record_values[field_name]
                if type(value) is not str:
                    findings.add("IMAGE_RECORD_FIELD_TYPE", "schema_documents", f"{coordinate}/{field_name}")
                    accounting_complete = False
                elif total_accounted < _SIZE_CEILING:
                    size = _utf8_size(value, utf8_cache)
                    if size is None:
                        findings.add("IMAGE_RECORD_FIELD_TYPE", "schema_documents", f"{coordinate}/{field_name}")
                        accounting_complete = False
                    else:
                        total_accounted = _bounded_add(total_accounted, size)
            body = record_values["canonical_json"]
            if type(body) is not bytes:
                findings.add("IMAGE_RECORD_FIELD_TYPE", "schema_documents", f"{coordinate}/canonical_json")
                accounting_complete = False
            else:
                body_size = len(body)
                total_accounted = _bounded_add(total_accounted, body_size)
                schema_bundle_bytes += body_size
                if body_size > MAX_SCHEMA_DOCUMENT_BYTES:
                    findings.add("IMAGE_ITEM_BYTE_LIMIT", "schema_documents", f"{coordinate}/canonical_json")
            if (
                type(record_values["schema_id"]) is str
                and type(record_values["document_sha256"]) is str
                and type(body) is bytes
            ):
                clean_schema_documents.append(SchemaDocumentRecord(
                    record_values["schema_id"],
                    record_values["document_sha256"],
                    body,
                ))
    if schema_bundle_bytes > MAX_SCHEMA_BUNDLE_BYTES:
        findings.add("SCHEMA_BUNDLE_BYTE_LIMIT", "schema_bundle", "/")

    clean_blobs: list[BlobRecord] = []
    if cardinality_valid.get("blobs", False):
        for index, record in enumerate(captured["blobs"]):
            coordinate = f"/{index}"
            if type(record) is not BlobRecord:
                findings.add("IMAGE_RECORD_TYPE", "blobs", coordinate)
                accounting_complete = False
                continue
            record_values = {
                name: _read_slot(record, name)
                for name in ("sha256", "schema_id", "canonical_json")
            }
            missing = [
                name for name, value in record_values.items()
                if value is _MISSING
            ]
            if missing:
                for name in missing:
                    findings.add(
                        "IMAGE_RECORD_FIELD_MISSING",
                        "blobs",
                        f"{coordinate}/{name}",
                    )
                accounting_complete = False
                continue
            for field_name in ("sha256", "schema_id"):
                value = record_values[field_name]
                if type(value) is not str:
                    findings.add("IMAGE_RECORD_FIELD_TYPE", "blobs", f"{coordinate}/{field_name}")
                    accounting_complete = False
                elif total_accounted < _SIZE_CEILING:
                    size = _utf8_size(value, utf8_cache)
                    if size is None:
                        findings.add("IMAGE_RECORD_FIELD_TYPE", "blobs", f"{coordinate}/{field_name}")
                        accounting_complete = False
                    else:
                        total_accounted = _bounded_add(total_accounted, size)
            body = record_values["canonical_json"]
            if type(body) is not bytes:
                findings.add("IMAGE_RECORD_FIELD_TYPE", "blobs", f"{coordinate}/canonical_json")
                accounting_complete = False
            else:
                total_accounted = _bounded_add(total_accounted, len(body))
                if len(body) > MAX_BLOB_BYTES:
                    findings.add("IMAGE_ITEM_BYTE_LIMIT", "blobs", f"{coordinate}/canonical_json")
            if (
                type(record_values["sha256"]) is str
                and type(record_values["schema_id"]) is str
                and type(body) is bytes
            ):
                clean_blobs.append(BlobRecord(
                    record_values["sha256"],
                    record_values["schema_id"],
                    body,
                ))

    byte_collections = (
        ("events", captured["events"], MAX_EVENT_BYTES),
        ("checkpoint_copies", captured["checkpoint_copies"], MAX_BOOTSTRAP_DOCUMENT_BYTES),
        ("selector_history", captured["selector_history"], MAX_BOOTSTRAP_DOCUMENT_BYTES),
    )
    for name, values, maximum in byte_collections:
        if not cardinality_valid.get(name, False):
            continue
        for index, value in enumerate(values):
            coordinate = f"/{index}"
            if type(value) is not bytes:
                findings.add("IMAGE_RECORD_TYPE", name, coordinate)
                accounting_complete = False
                continue
            total_accounted = _bounded_add(total_accounted, len(value))
            if len(value) > maximum:
                findings.add("IMAGE_ITEM_BYTE_LIMIT", name, coordinate)

    snapshot_sizes: list[int] = []
    clean_snapshots: list[TableSnapshot] = []
    if cardinality_valid.get("table_snapshots", False):
        for index, (snapshot, spec) in enumerate(zip(
            captured["table_snapshots"], _TABLE_SPECS, strict=True,
        )):
            coordinate = f"/{index}"
            if type(snapshot) is not TableSnapshot:
                findings.add("TABLE_SNAPSHOT_TYPE", "table_snapshots", coordinate)
                accounting_complete = False
                continue
            table = _read_slot(snapshot, "table")
            rows = _read_slot(snapshot, "rows")
            if table is _MISSING:
                findings.add(
                    "TABLE_SNAPSHOT_FIELD_MISSING", "table_snapshots",
                    f"{coordinate}/table",
                )
            if rows is _MISSING:
                findings.add(
                    "TABLE_SNAPSHOT_FIELD_MISSING", "table_snapshots",
                    f"{coordinate}/rows",
                )
            if table is _MISSING or rows is _MISSING:
                accounting_complete = False
                continue
            if type(table) is not str or table != spec.name:
                findings.add("TABLE_INVENTORY", "table_snapshots", f"{coordinate}/table")
                accounting_complete = False
            if type(rows) is not tuple:
                findings.add("TABLE_ROWS_TYPE", "table_snapshots", f"{coordinate}/rows")
                accounting_complete = False
                continue
            if len(rows) > spec.max_rows:
                findings.add("TABLE_ROW_LIMIT", "table_snapshots", f"{coordinate}/rows")
                accounting_complete = False
                continue
            clean_snapshot = TableSnapshot(table, rows) if type(table) is str else None
            supplied_size = (
                _canonical_snapshot_size(clean_snapshot, canonical_string_cache)
                if clean_snapshot is not None else None
            )
            if supplied_size is not None:
                total_accounted = _bounded_add(total_accounted, supplied_size)
            if total_accounted == _SIZE_CEILING:
                findings.add(
                    "TOTAL_ACCOUNTED_INPUT_LIMIT", "runtime_image", "/",
                )
                continue

            table_valid = type(table) is str and table == spec.name
            prior_order: tuple[object, ...] | None = None
            primary_keys: set[tuple[object, ...]] = set()
            for row_index, row in enumerate(rows):
                row_coordinate = f"{coordinate}/rows/{row_index}"
                if type(row) is not tuple:
                    findings.add("TABLE_ROW_TYPE", "table_snapshots", row_coordinate)
                    table_valid = False
                    continue
                if len(row) != len(spec.columns):
                    findings.add("TABLE_ROW_WIDTH", "table_snapshots", row_coordinate)
                    table_valid = False
                    continue
                row_valid = True
                for cell_index, (cell, column) in enumerate(zip(row, spec.columns, strict=True)):
                    cell_coordinate = f"{row_coordinate}/{cell_index}"
                    if cell is None:
                        if not column.nullable:
                            findings.add("TABLE_CELL_NULLABILITY", "table_snapshots", cell_coordinate)
                            row_valid = False
                    elif column.storage_type == "TEXT":
                        if type(cell) is not str:
                            findings.add("TABLE_CELL_TYPE", "table_snapshots", cell_coordinate)
                            row_valid = False
                        elif _canonical_string_size(
                            cell, canonical_string_cache,
                        ) is None:
                            findings.add("TABLE_CELL_UNICODE", "table_snapshots", cell_coordinate)
                            row_valid = False
                    elif type(cell) is not int:
                        findings.add("TABLE_CELL_TYPE", "table_snapshots", cell_coordinate)
                        row_valid = False
                    elif cell < INT64_MIN or cell > INT64_MAX:
                        findings.add("TABLE_CELL_INT64", "table_snapshots", cell_coordinate)
                        row_valid = False
                if not row_valid:
                    table_valid = False
                    continue
                primary_key = _ordered_key(row, spec.primary_key)
                order_key = _ordered_key(row, spec.row_order)
                if primary_key is None or order_key is None:
                    table_valid = False
                    continue
                if primary_key in primary_keys:
                    findings.add("TABLE_PRIMARY_KEY_DUPLICATE", "table_snapshots", row_coordinate)
                    table_valid = False
                else:
                    primary_keys.add(primary_key)
                if prior_order is not None and order_key <= prior_order:
                    findings.add("TABLE_ROW_ORDER", "table_snapshots", row_coordinate)
                    table_valid = False
                prior_order = order_key
            if table_valid and supplied_size is not None:
                snapshot_sizes.append(supplied_size)
                clean_snapshots.append(clean_snapshot)
            else:
                if supplied_size is None:
                    findings.add("TABLE_CELL_UNICODE", "table_snapshots", coordinate)
                accounting_complete = False

    final_root_work: int | None = None
    if len(snapshot_sizes) == len(_TABLE_SPECS):
        final_root_work = 0
        for spec, snapshot in zip(_TABLE_SPECS, clean_snapshots, strict=True):
            rows_size = _canonical_rows_size(
                snapshot.rows, canonical_string_cache,
            )
            if rows_size is None:
                final_root_work = None
                accounting_complete = False
                break
            charge = len(_TABLE_ROOT_PREFIX) + len(spec.name) + 1
            charge = _bounded_add(charge, rows_size)
            final_root_work = _bounded_add(final_root_work, charge)
        if final_root_work is not None and final_root_work > MAX_TOTAL_ROOT_WORK_BYTES:
            findings.add("FINAL_SUPPLIED_ROOT_WORK_LIMIT", "table_snapshots", "/")

    accounted_result: int | None = total_accounted if accounting_complete else None
    if accounted_result is not None and accounted_result > MAX_TOTAL_ACCOUNTED_INPUT_BYTES:
        findings.add("TOTAL_ACCOUNTED_INPUT_LIMIT", "runtime_image", "/")

    violations = findings.result()
    sanitized_image = None
    if not violations:
        sanitized_image = RuntimeImage(
            storage_descriptor=captured["storage_descriptor"],
            verifier_dependency_closure=captured["verifier_dependency_closure"],
            manifest=captured["manifest"],
            attachment=captured["attachment"],
            schema_registry=captured["schema_registry"],
            schema_documents=tuple(clean_schema_documents),
            blobs=tuple(clean_blobs),
            events=tuple(captured["events"]),
            table_snapshots=tuple(clean_snapshots),
            checkpoint_copies=tuple(captured["checkpoint_copies"]),
            selector_history=tuple(captured["selector_history"]),
            legacy_evidence=None,
        )
    return RuntimeImagePreflight(
        sanitized_image,
        violations,
        accounted_result,
        final_root_work if accounting_complete else None,
    )


__all__ = (
    "BlobRecord",
    "ImageViolation",
    "JsonCell",
    "RuntimeImage",
    "RuntimeImagePreflight",
    "SchemaDocumentRecord",
    "TABLE_NAMES",
    "TableSnapshot",
    "inspect_runtime_image_host",
)
