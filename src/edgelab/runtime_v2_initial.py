"""Private pure reducer for a runtime-format-2 NEW initial image.

This module is deliberately disconnected from the public verifier.  It
validates the presently compiled NEW-genesis inputs and derives selectors and
all fifteen supplied tables for comparison.  It cannot validate the complete
dependency-closure shape or identity until the generated closure is frozen and
compiled, so it never exposes derived identity from an unsupported candidate.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any, Callable

from .runtime_v2_bootstrap import (
    BootstrapValidationError,
    SUPPORTED_SCHEMA_REGISTRY_SHA256,
    SUPPORTED_STORAGE_DESCRIPTOR_SHA256,
    validate_attachment,
    validate_manifest,
    validate_selector,
    validate_supported_schema_registry,
    validate_supported_storage_descriptor,
)
from .runtime_v2_codec import (
    CanonicalJsonError,
    attachment_digest,
    blob_digest,
    canonical_json,
    event_digest,
    manifest_digest,
    parse_canonical_json,
    schema_document_digest,
    selector_digest,
    selector_history_digest,
    verifier_dependency_closure_digest,
)
from .runtime_v2_genesis import (
    GenesisValidationError,
    PAYLOAD_SCHEMA_ID,
    REQUEST_SCHEMA_ID,
    RESPONSE_SCHEMA_ID,
    validate_new_genesis_request,
    validate_new_genesis_response,
    validate_runtime_genesis_envelope,
    validate_runtime_genesis_payload,
)
from .runtime_v2_image import RuntimeImage, TableSnapshot, inspect_runtime_image_host


MAX_FINDINGS = 128
SCHEMA_DOCUMENT_PINS = (
    (
        "urn:edgelab:m0-3a-command-request:2",
        "8c7b7cf050700f696e44d89899365bdc80620dd1071dad7aa08707c91f88388e",
    ),
    (
        "urn:edgelab:m0-3a-event-envelope:2",
        "ae3655e0b94610e54ad00b514de1eeb78e9abd54f5828fd93387583b76f2b553",
    ),
    (
        "urn:edgelab:m0-3a-event-payload:2",
        "1b26427cde4998e23ec503df3a46b527893a2f40c27e7d0efdadf5474e8e30e4",
    ),
    (
        "urn:edgelab:m0-3a-legacy-v1-projection:1",
        "15689e50b3abe3895c546ddc606fe9b754ab993804b13aedd85e8e789374ba53",
    ),
    (
        "urn:edgelab:m0-3a-legacy-v1-row-archive:1",
        "fcd734fdda399047738bb139ed3971e5906eaaa7063435f4902a259d2a9d3a9c",
    ),
    (
        "urn:edgelab:m0-3a-response-projection:2",
        "9a01e5c47f628c4a80082f6ac1276ecae345c47c42923789d0743d4fd41f0a61",
    ),
    (
        "urn:edgelab:m0-3a-runtime-checkpoint:2",
        "2c9fc0fed41a49342ec91a8b5d17dd3f3e23e7612a07257af5f1d6acd6d4c05a",
    ),
    (
        "urn:edgelab:m0-3a-runtime-export:2",
        "c9b345e83d99173f41c52fd818471b428ff0a7503ce9340e76531d7cb58b079a",
    ),
    (
        "urn:edgelab:m0-3a-task-state:2",
        "c8b9a47df5b91ae467f3008c8c7c27bdf2df089a3fbc25d684f53e56bc37ede8",
    ),
)
_EXPECTED_BLOB_ROLES = frozenset({
    REQUEST_SCHEMA_ID, RESPONSE_SCHEMA_ID, PAYLOAD_SCHEMA_ID,
})


@dataclass(frozen=True, order=True, slots=True)
class InitialViolation:
    code: str
    artifact: str
    coordinate: str


@dataclass(frozen=True, slots=True)
class InitialReductionReport:
    """A closed deny-only result from private NEW-image reduction."""

    status: str
    violations: tuple[InitialViolation, ...]
    authorizing_use: str = field(default="DENY", init=False)

    def __post_init__(self) -> None:
        if self.status not in {"INVALID", "UNSUPPORTED"}:
            raise ValueError("unsupported initial reduction status")
        if not self.violations or tuple(sorted(set(self.violations))) != self.violations:
            raise ValueError("violations must be nonempty, unique, and sorted")

    def __bool__(self) -> bool:
        raise TypeError("initial reduction reports are not authorization booleans")


class _Sink:
    __slots__ = ("_items", "_truncated")

    def __init__(self) -> None:
        self._items: set[InitialViolation] = set()
        self._truncated = False

    def add(self, code: str, artifact: str, coordinate: str) -> None:
        def bounded(value: str, maximum: int) -> str:
            if len(value) <= maximum:
                return value
            suffix = f"#sha256={sha256(value.encode('utf-8')).hexdigest()}"
            return value[:maximum - len(suffix)] + suffix

        finding = InitialViolation(
            bounded(code, 128),
            bounded(artifact, 256),
            bounded(coordinate, 512),
        )
        if finding in self._items:
            return
        if len(self._items) >= MAX_FINDINGS - 1:
            self._truncated = True
            return
        self._items.add(finding)

    def result(self) -> tuple[InitialViolation, ...]:
        items = set(self._items)
        if self._truncated:
            items.add(InitialViolation("FINDINGS_TRUNCATED", "reducer", "/findings"))
        return tuple(sorted(items))


def _invalid(sink: _Sink) -> InitialReductionReport:
    findings = sink.result()
    if not findings:
        findings = (InitialViolation("INVALID", "reducer", "/"),)
    return InitialReductionReport("INVALID", findings)


def _parse(raw: bytes, artifact: str, sink: _Sink) -> Any | None:
    try:
        return parse_canonical_json(raw)
    except CanonicalJsonError:
        sink.add("CANONICAL_JSON", artifact, "/")
        return None


def _validate(
    value: Any,
    artifact: str,
    validator: Callable[[Any], None],
    sink: _Sink,
) -> None:
    try:
        validator(value)
    except (BootstrapValidationError, GenesisValidationError) as error:
        sink.add(error.code, artifact, error.coordinate)


def _bind(actual: Any, expected: Any, artifact: str, coordinate: str, sink: _Sink) -> None:
    if type(actual) is not type(expected) or actual != expected:
        sink.add("BINDING_MISMATCH", artifact, coordinate)


def _digest_match(actual: Any, expected: str, artifact: str, coordinate: str, sink: _Sink) -> None:
    if type(actual) is not str or actual != expected:
        sink.add("DIGEST_MISMATCH", artifact, coordinate)


def _schema_bundle(image: RuntimeImage, registry: Any, sink: _Sink) -> None:
    observed = tuple(
        (record.schema_id, record.document_sha256)
        for record in image.schema_documents
    )
    if observed != SCHEMA_DOCUMENT_PINS:
        sink.add("SCHEMA_DOCUMENT_INVENTORY", "schema_documents", "/")
    documents = registry.get("documents") if type(registry) is dict else None
    registry_inventory = (
        tuple(
            (item.get("schema_id"), item.get("document_sha256"))
            if type(item) is dict else (None, None)
            for item in documents
        )
        if type(documents) is list else None
    )
    if registry_inventory != SCHEMA_DOCUMENT_PINS:
        sink.add("SCHEMA_REGISTRY_DOCUMENTS", "schema_registry", "/documents")
    for index, record in enumerate(image.schema_documents):
        document = _parse(record.canonical_json, record.schema_id, sink)
        if document is None:
            continue
        try:
            observed_digest = schema_document_digest(document)
        except CanonicalJsonError:
            sink.add("SCHEMA_DOCUMENT_VALUE", record.schema_id, "/")
            continue
        expected_id, expected_digest = SCHEMA_DOCUMENT_PINS[index]
        if record.schema_id != expected_id:
            sink.add("SCHEMA_DOCUMENT_ID", "schema_documents", f"/{index}/schema_id")
        if record.document_sha256 != expected_digest or observed_digest != expected_digest:
            sink.add("SCHEMA_DOCUMENT_DIGEST", record.schema_id, "/")


def _closure_digest(closure: Any, sink: _Sink) -> str | None:
    if type(closure) is not dict:
        sink.add("OBJECT_REQUIRED", "verifier_dependency_closure", "/")
        return None
    supplied = closure.get("verifier_dependency_closure_sha256")
    if (
        type(supplied) is not str
        or len(supplied) != 64
        or any(character not in "0123456789abcdef" for character in supplied)
    ):
        sink.add(
            "CLOSURE_DIGEST_FIELD",
            "verifier_dependency_closure",
            "/verifier_dependency_closure_sha256",
        )
        return None
    try:
        derived = verifier_dependency_closure_digest(closure)
    except CanonicalJsonError:
        sink.add("CLOSURE_VALUE", "verifier_dependency_closure", "/")
        return None
    if supplied != derived:
        sink.add(
            "CLOSURE_SELF_DIGEST_MISMATCH",
            "verifier_dependency_closure",
            "/verifier_dependency_closure_sha256",
        )
    return derived


def _blob_values(image: RuntimeImage, sink: _Sink) -> dict[str, tuple[Any, str]]:
    values: dict[str, tuple[Any, str]] = {}
    if len(image.blobs) != 3:
        sink.add("GENESIS_BLOB_CARDINALITY", "blobs", "/")
    for index, record in enumerate(image.blobs):
        if record.schema_id not in _EXPECTED_BLOB_ROLES:
            sink.add("GENESIS_BLOB_ROLE", "blobs", f"/{index}/schema_id")
            continue
        if record.schema_id in values:
            sink.add("GENESIS_BLOB_ROLE_DUPLICATE", "blobs", f"/{index}/schema_id")
            continue
        value = _parse(record.canonical_json, record.schema_id, sink)
        if value is None:
            continue
        try:
            derived = blob_digest(value)
        except CanonicalJsonError:
            sink.add("BLOB_VALUE", record.schema_id, "/")
            continue
        _digest_match(record.sha256, derived, record.schema_id, "/sha256", sink)
        values[record.schema_id] = (value, derived)
    if values.keys() != _EXPECTED_BLOB_ROLES:
        sink.add("GENESIS_BLOB_INVENTORY", "blobs", "/")
    return values


def _expected_tables(
    *,
    image: RuntimeImage,
    request: dict[str, Any],
    request_sha: str,
    response: dict[str, Any],
    response_sha: str,
    payload: dict[str, Any],
    payload_sha: str,
    event: dict[str, Any],
    event_sha: str,
    manifest_sha: str,
    attachment_sha: str,
    selector1_sha: str,
    history_sha: str,
) -> dict[str, tuple[tuple[Any, ...], ...]]:
    runtime_id = event["runtime_id"]
    chain_id = event["chain_id"]
    created_at = event["occurred_at"]
    event_id = event["event_id"]
    repository_bundle = event["repository_bundle_sha256"]
    blobs = sorted((
        (request_sha, REQUEST_SCHEMA_ID, canonical_json(request).decode("ascii")),
        (response_sha, RESPONSE_SCHEMA_ID, canonical_json(response).decode("ascii")),
        (payload_sha, PAYLOAD_SCHEMA_ID, canonical_json(payload).decode("ascii")),
    ))
    schema_rows = tuple(
        (
            record.schema_id,
            record.document_sha256,
            record.canonical_json.decode("ascii"),
        )
        for record in image.schema_documents
    )
    rows: dict[str, tuple[tuple[Any, ...], ...]] = {
        name: () for name in (
            "attempts", "blobs", "claims", "events", "idempotency",
            "legacy_archive", "metadata", "migrations", "remediation_links",
            "reviews", "schema_documents", "schema_registry", "seals",
            "snapshots", "tasks",
        )
    }
    rows["blobs"] = tuple(blobs)
    rows["events"] = ((
        0, event_id, event_sha, canonical_json(event).decode("ascii"),
    ),)
    rows["metadata"] = ((
        "runtime", runtime_id, chain_id, 2, 2, "NEW", created_at,
        manifest_sha, attachment_sha, SUPPORTED_STORAGE_DESCRIPTOR_SHA256,
        SUPPORTED_SCHEMA_REGISTRY_SHA256, event_id, event_sha, 0,
        repository_bundle, 0, event_id, event_sha, None, 1, selector1_sha,
        history_sha, None, "UNANCHORED", "UNKNOWN", "DENY",
    ),)
    rows["schema_documents"] = schema_rows
    rows["schema_registry"] = ((
        "registry", SUPPORTED_SCHEMA_REGISTRY_SHA256,
        image.schema_registry.decode("ascii"),
    ),)
    rows["seals"] = ((
        "RUNTIME_GENESIS_IDENTITY", runtime_id, chain_id,
        "RUNTIME_GENESIS_IDENTITY", attachment_sha, event_id, event_sha,
        manifest_sha, event_id, created_at,
    ),)
    return rows


def reduce_initial_runtime_image(candidate: object) -> InitialReductionReport:
    """Reduce a candidate NEW genesis image without ever authorizing it."""
    sink = _Sink()
    preflight = inspect_runtime_image_host(candidate)
    for violation in preflight.violations:
        sink.add(violation.code, violation.artifact, violation.coordinate)
    if preflight.image is None:
        return _invalid(sink)
    image = preflight.image

    storage = _parse(image.storage_descriptor, "storage_descriptor", sink)
    closure = _parse(image.verifier_dependency_closure, "verifier_dependency_closure", sink)
    manifest = _parse(image.manifest, "manifest", sink)
    attachment = _parse(image.attachment, "attachment", sink)
    registry = _parse(image.schema_registry, "schema_registry", sink)

    if storage is not None:
        _validate(storage, "storage_descriptor", validate_supported_storage_descriptor, sink)
    if registry is not None:
        _validate(registry, "schema_registry", validate_supported_schema_registry, sink)
        _schema_bundle(image, registry, sink)
    if attachment is not None:
        _validate(attachment, "attachment", validate_attachment, sink)
    if manifest is not None:
        _validate(manifest, "manifest", validate_manifest, sink)
    closure_sha = _closure_digest(closure, sink) if closure is not None else None

    if sink.result():
        return _invalid(sink)
    assert type(manifest) is dict
    if manifest["source_kind"] != "NEW":
        return InitialReductionReport(
            "UNSUPPORTED",
            (InitialViolation("V1_MIGRATION_NOT_SUPPORTED", "manifest", "/source_kind"),),
        )
    if image.checkpoint_copies:
        sink.add("GENESIS_CHECKPOINT_COPY", "checkpoint_copies", "/")
    if len(image.events) != 1:
        sink.add("GENESIS_EVENT_CARDINALITY", "events", "/")
    if len(image.selector_history) != 2:
        sink.add("GENESIS_SELECTOR_CARDINALITY", "selector_history", "/")

    blobs = _blob_values(image, sink)
    event = _parse(image.events[0], "events", sink) if len(image.events) == 1 else None
    selectors = tuple(
        _parse(raw, f"selector_history[{index}]", sink)
        for index, raw in enumerate(image.selector_history)
    ) if len(image.selector_history) == 2 else ()
    if sink.result():
        return _invalid(sink)

    request, request_sha = blobs[REQUEST_SCHEMA_ID]
    response, response_sha = blobs[RESPONSE_SCHEMA_ID]
    payload, payload_sha = blobs[PAYLOAD_SCHEMA_ID]
    selector0, selector1 = selectors
    _validate(request, "request", validate_new_genesis_request, sink)
    _validate(response, "response", validate_new_genesis_response, sink)
    _validate(payload, "payload", validate_runtime_genesis_payload, sink)
    _validate(event, "event", validate_runtime_genesis_envelope, sink)
    _validate(selector0, "selector_history[0]", validate_selector, sink)
    _validate(selector1, "selector_history[1]", validate_selector, sink)
    if sink.result():
        return _invalid(sink)

    assert all(type(value) is dict for value in (
        storage, closure, manifest, attachment, registry, request, response,
        payload, event, selector0, selector1,
    ))
    assert closure_sha is not None
    runtime_id = event["runtime_id"]
    chain_id = event["chain_id"]
    repository_bundle = event["repository_bundle_sha256"]
    payload_data = payload["data"]
    attachment_sha = attachment_digest(attachment)
    manifest_sha = manifest_digest(manifest)
    derived_event_sha = event_digest(event)

    for artifact, value in (
        ("attachment", attachment), ("manifest", manifest), ("request", request),
        ("response", response), ("payload", payload_data),
    ):
        _bind(value["runtime_id"], runtime_id, artifact, "/runtime_id", sink)
        _bind(value["chain_id"], chain_id, artifact, "/chain_id", sink)
    for artifact, value in (("request", request), ("payload", payload_data), ("event", event)):
        _bind(value["repository_generation"], 0, artifact, "/repository_generation", sink)
        _bind(
            value["repository_bundle_sha256"], repository_bundle,
            artifact, "/repository_bundle_sha256", sink,
        )
    for artifact, values in (
        ("request", request["arguments"]), ("payload", payload_data), ("manifest", manifest),
    ):
        _digest_match(
            values["attachment_sha256"], attachment_sha,
            artifact, "/attachment_sha256", sink,
        )
        _digest_match(
            values["storage_schema_sha256"], SUPPORTED_STORAGE_DESCRIPTOR_SHA256,
            artifact, "/storage_schema_sha256", sink,
        )
        _digest_match(
            values["schema_registry_sha256"], SUPPORTED_SCHEMA_REGISTRY_SHA256,
            artifact, "/schema_registry_sha256", sink,
        )
    _digest_match(
        payload_data["verifier_dependency_closure_sha256"], closure_sha,
        "payload", "/data/verifier_dependency_closure_sha256", sink,
    )
    _digest_match(
        event["transaction"]["request_sha256"], request_sha,
        "event", "/transaction/request_sha256", sink,
    )
    _digest_match(
        event["transaction"]["response_sha256"], response_sha,
        "event", "/transaction/response_sha256", sink,
    )
    _digest_match(
        event["payload_ref"]["sha256"], payload_sha,
        "event", "/payload_ref/sha256", sink,
    )
    _digest_match(event["event_sha256"], derived_event_sha, "event", "/event_sha256", sink)
    _bind(manifest["genesis_event_id"], event["event_id"], "manifest", "/genesis_event_id", sink)
    _digest_match(
        manifest["genesis_event_sha256"], derived_event_sha,
        "manifest", "/genesis_event_sha256", sink,
    )
    for artifact, coordinate, timestamp in (
        ("attachment", "/created_at", attachment["created_at"]),
        ("manifest", "/created_at", manifest["created_at"]),
        ("selector_history[1]", "/written_at", selector1["written_at"]),
    ):
        _bind(timestamp, event["occurred_at"], artifact, coordinate, sink)

    selector0_sha = selector_digest(selector0)
    _digest_match(
        selector0["selector_sha256"], selector0_sha,
        "selector_history[0]", "/selector_sha256", sink,
    )
    expected_selector1 = {
        "schema_version": 1,
        "selector_format_version": 1,
        "selector_generation": 1,
        "active_runtime_format_version": 2,
        "active_runtime_id": runtime_id,
        "active_database_path": "runtime.v2.sqlite",
        "active_attachment_path": "attachment.v2.json",
        "active_manifest_path": "runtime.v2.manifest.json",
        "active_manifest_sha256": manifest_sha,
        "latest_v2_checkpoint_sha256": None,
        "selector_history_path": "selectors/00000000000000000001.json",
        "prior_selector_path": "selectors/00000000000000000000.json",
        "prior_selector_sha256": selector0_sha,
        "cutover_state": "V2_ACTIVE",
        "currentness_status": "UNKNOWN",
        "authorizing_use": "DENY",
        "written_at": event["occurred_at"],
        "selector_sha256": selector1["selector_sha256"],
    }
    expected_selector1["selector_sha256"] = selector_digest(expected_selector1)
    if selector1 != expected_selector1:
        sink.add("SELECTOR_DERIVATION", "selector_history[1]", "/")
    selector1_sha = expected_selector1["selector_sha256"]
    history_sha = selector_history_digest([selector0, selector1])

    if sink.result():
        return _invalid(sink)
    expected_rows = _expected_tables(
        image=image,
        request=request,
        request_sha=request_sha,
        response=response,
        response_sha=response_sha,
        payload=payload,
        payload_sha=payload_sha,
        event=event,
        event_sha=derived_event_sha,
        manifest_sha=manifest_sha,
        attachment_sha=attachment_sha,
        selector1_sha=selector1_sha,
        history_sha=history_sha,
    )
    for snapshot in image.table_snapshots:
        assert type(snapshot) is TableSnapshot
        expected = expected_rows[snapshot.table]
        if snapshot.rows != expected:
            sink.add("TABLE_DERIVATION", snapshot.table, "/rows")
    if sink.result():
        return _invalid(sink)

    return InitialReductionReport(
        status="UNSUPPORTED",
        violations=(InitialViolation(
            "CLOSURE_NOT_COMPILED",
            "verifier_dependency_closure",
            "/",
        ),),
    )


__all__ = (
    "InitialReductionReport",
    "InitialViolation",
    "SCHEMA_DOCUMENT_PINS",
    "reduce_initial_runtime_image",
)
