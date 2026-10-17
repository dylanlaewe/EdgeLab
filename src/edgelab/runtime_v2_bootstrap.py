"""Pure, non-authorizing validators for runtime-v2 bootstrap documents.

The constants below pin the raw bytes of the three published JSON Schema
files.  The schema bytes themselves are not compiled into this module.  These
validators apply the versioned conservative bootstrap profile to
already-parsed canonical JSON without reading ambient files or consulting
runtime state.  The profile intentionally uses whole-string patterns and
asserted Gregorian UTC-second timestamps; those rules are stricter than a
Draft 2020-12 implementation that treats ``pattern`` as a substring search or
``format`` as annotation.

Successful validation returns ``None``.  It is not an authenticity,
currentness, consistency, selection, execution, or capital decision.
"""
from __future__ import annotations

import re
from typing import Any


RUNTIME_ATTACHMENT_SCHEMA_SHA256 = (
    "0623e1706d3a18a2b06043c72f444bd8bad9d798248ff62c83a901a36c1dbb9c"
)
RUNTIME_MANIFEST_SCHEMA_SHA256 = (
    "dcec875b3bb65178fc58e19d84c7fed5d85df97f44f501b3e4aa3c1c44b791de"
)
ACTIVE_RUNTIME_SELECTOR_SCHEMA_SHA256 = (
    "5398ccf55ce90159d9da34f9a29863a856f1e6e38fdb9ab498b8bd71bb5badf9"
)
BOOTSTRAP_VALIDATION_PROFILE = "EDGELAB_RUNTIME_V2_BOOTSTRAP_STRICT_V1"


class BootstrapValidationError(ValueError):
    """A parsed value is outside the closed bootstrap schema profile."""

    def __init__(self, code: str, coordinate: str) -> None:
        self.code = code
        self.coordinate = coordinate
        super().__init__(f"{code}:{coordinate}")


_UUID4 = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_UTC_SECOND = re.compile(
    r"^([0-9]{4})-([0-9]{2})-([0-9]{2})T"
    r"([0-9]{2}):([0-9]{2}):([0-9]{2})Z$"
)
_SELECTOR_PATH = re.compile(r"^selectors/[0-9]{20}\.json$")

_ATTACHMENT_KEYS = frozenset({
    "attachment_schema_version", "runtime_format_version", "runtime_id",
    "chain_id", "canonical_project_id", "repository_root_realpath",
    "expected_remote", "git_common_dir_identity", "repository_marker_sha256",
    "checkout_nonce", "created_at", "anchor_status", "currentness_status",
    "authorizing_use",
})
_MANIFEST_KEYS = frozenset({
    "schema_version", "runtime_format_version", "event_format_version",
    "runtime_id", "chain_id", "canonicalization", "digest_algorithm",
    "sqlite_application_id", "sqlite_user_version", "storage_schema_sha256",
    "schema_registry_sha256", "genesis_event_id", "genesis_event_sha256",
    "attachment_sha256", "source_kind", "legacy_bridge", "authority_binding",
    "anchor_status", "currentness_status", "authorizing_use", "created_at",
})
_LEGACY_BRIDGE_KEYS = frozenset({
    "source_runtime_format_version", "source_assurance", "source_runtime_id",
    "source_attachment_sha256", "source_storage_inventory_sha256",
    "source_backup_sha256", "source_global_head_id",
    "source_global_head_sha256", "source_row_archive_sha256",
    "source_projection_sha256", "migration_plan_sha256",
    "frozen_verifier_commit", "frozen_verifier_closure_sha256",
    "source_repository_bundle_sha256",
})
_SELECTOR_KEYS = frozenset({
    "schema_version", "selector_format_version", "selector_generation",
    "active_runtime_format_version", "active_runtime_id",
    "active_database_path", "active_attachment_path", "active_manifest_path",
    "active_manifest_sha256", "latest_v2_checkpoint_sha256",
    "selector_history_path", "prior_selector_path", "prior_selector_sha256",
    "cutover_state", "currentness_status", "authorizing_use", "written_at",
    "selector_sha256",
})


def _fail(code: str, coordinate: str) -> None:
    raise BootstrapValidationError(code, coordinate)


def _object(value: Any, keys: frozenset[str], coordinate: str) -> dict[str, Any]:
    if type(value) is not dict:
        _fail("OBJECT_REQUIRED", coordinate)
    if any(type(key) is not str for key in value):
        _fail("STRING_KEY_REQUIRED", coordinate)
    if value.keys() != keys:
        _fail("OBJECT_KEYS", coordinate)
    return value


def _string(value: Any, coordinate: str, *, minimum: int = 0,
            maximum: int | None = None) -> str:
    if type(value) is not str:
        _fail("STRING_REQUIRED", coordinate)
    if len(value) < minimum or (maximum is not None and len(value) > maximum):
        _fail("STRING_LENGTH", coordinate)
    return value


def _integer(value: Any, coordinate: str, minimum: int | None = None,
             maximum: int | None = None) -> int:
    if type(value) is not int:
        _fail("INTEGER_REQUIRED", coordinate)
    if minimum is not None and value < minimum:
        _fail("INTEGER_RANGE", coordinate)
    if maximum is not None and value > maximum:
        _fail("INTEGER_RANGE", coordinate)
    return value


def _const(value: Any, expected: Any, coordinate: str) -> None:
    if type(value) is not type(expected) or value != expected:
        _fail("CONST", coordinate)


def _one_of(value: Any, options: tuple[Any, ...], coordinate: str) -> None:
    if not any(type(value) is type(option) and value == option for option in options):
        _fail("ENUM", coordinate)


def _pattern(value: Any, pattern: re.Pattern[str], coordinate: str) -> None:
    text = _string(value, coordinate)
    if pattern.fullmatch(text) is None:
        _fail("PATTERN", coordinate)


def _nullable_pattern(value: Any, pattern: re.Pattern[str], coordinate: str) -> None:
    if value is not None:
        _pattern(value, pattern, coordinate)


def _utc_second(value: Any, coordinate: str) -> None:
    text = _string(value, coordinate)
    match = _UTC_SECOND.fullmatch(text)
    if match is None:
        _fail("UTC_SECOND", coordinate)
    year, month, day, hour, minute, second = (
        int(part) for part in match.groups()
    )
    if year == 0 or month < 1 or month > 12 or hour > 23 or minute > 59 or second > 59:
        _fail("UTC_SECOND", coordinate)
    month_lengths = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
    maximum_day = month_lengths[month - 1]
    if month == 2 and (year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)):
        maximum_day = 29
    if day < 1 or day > maximum_day:
        _fail("UTC_SECOND", coordinate)


def _legacy_bridge(value: Any, coordinate: str) -> None:
    bridge = _object(value, _LEGACY_BRIDGE_KEYS, coordinate)
    _const(bridge["source_runtime_format_version"], 1,
           f"{coordinate}/source_runtime_format_version")
    _const(bridge["source_assurance"], "V16_BOUNDED_REPLAY_ONLY",
           f"{coordinate}/source_assurance")
    _string(bridge["source_runtime_id"], f"{coordinate}/source_runtime_id", minimum=1)
    _string(bridge["source_global_head_id"],
            f"{coordinate}/source_global_head_id", minimum=1)
    for name in (
        "source_attachment_sha256", "source_storage_inventory_sha256",
        "source_backup_sha256", "source_global_head_sha256",
        "source_row_archive_sha256", "source_projection_sha256",
        "migration_plan_sha256", "frozen_verifier_closure_sha256",
        "source_repository_bundle_sha256",
    ):
        _pattern(bridge[name], _SHA256, f"{coordinate}/{name}")
    _pattern(bridge["frozen_verifier_commit"], _SHA1,
             f"{coordinate}/frozen_verifier_commit")


def validate_attachment(value: Any) -> None:
    """Validate one parsed canonical runtime-v2 attachment value."""
    attachment = _object(value, _ATTACHMENT_KEYS, "/")
    _const(attachment["attachment_schema_version"], 2,
           "/attachment_schema_version")
    _const(attachment["runtime_format_version"], 2, "/runtime_format_version")
    _pattern(attachment["runtime_id"], _UUID4, "/runtime_id")
    _pattern(attachment["chain_id"], _SHA256, "/chain_id")
    _const(attachment["canonical_project_id"], "EdgeLab", "/canonical_project_id")
    _string(attachment["repository_root_realpath"], "/repository_root_realpath",
            minimum=1, maximum=4096)
    _const(attachment["expected_remote"],
           "https://github.com/dylanlaewe/EdgeLab.git", "/expected_remote")
    _string(attachment["git_common_dir_identity"], "/git_common_dir_identity",
            minimum=1, maximum=4096)
    _pattern(attachment["repository_marker_sha256"], _SHA256,
             "/repository_marker_sha256")
    _pattern(attachment["checkout_nonce"], _SHA256, "/checkout_nonce")
    _utc_second(attachment["created_at"], "/created_at")
    _const(attachment["anchor_status"], "UNANCHORED", "/anchor_status")
    _const(attachment["currentness_status"], "UNKNOWN", "/currentness_status")
    _const(attachment["authorizing_use"], "DENY", "/authorizing_use")


def validate_manifest(value: Any) -> None:
    """Validate one parsed canonical runtime-v2 manifest value."""
    manifest = _object(value, _MANIFEST_KEYS, "/")
    for name, expected in (
        ("schema_version", 1), ("runtime_format_version", 2),
        ("event_format_version", 2), ("sqlite_application_id", 1162102578),
        ("sqlite_user_version", 2),
    ):
        _const(manifest[name], expected, f"/{name}")
    _pattern(manifest["runtime_id"], _UUID4, "/runtime_id")
    _pattern(manifest["chain_id"], _SHA256, "/chain_id")
    _const(manifest["canonicalization"], "EDGELAB_CANONICAL_JSON_V1",
           "/canonicalization")
    _const(manifest["digest_algorithm"], "SHA-256", "/digest_algorithm")
    for name in (
        "storage_schema_sha256", "schema_registry_sha256",
        "genesis_event_sha256", "attachment_sha256",
    ):
        _pattern(manifest[name], _SHA256, f"/{name}")
    _pattern(manifest["genesis_event_id"], _UUID4, "/genesis_event_id")
    _one_of(manifest["source_kind"], ("NEW", "V1_MIGRATION"), "/source_kind")
    if manifest["source_kind"] == "NEW":
        _const(manifest["legacy_bridge"], None, "/legacy_bridge")
    else:
        _legacy_bridge(manifest["legacy_bridge"], "/legacy_bridge")
    _const(manifest["authority_binding"], None, "/authority_binding")
    _const(manifest["anchor_status"], "UNANCHORED", "/anchor_status")
    _const(manifest["currentness_status"], "UNKNOWN", "/currentness_status")
    _const(manifest["authorizing_use"], "DENY", "/authorizing_use")
    _utc_second(manifest["created_at"], "/created_at")


def validate_selector(value: Any) -> None:
    """Validate one parsed canonical active-runtime selector value."""
    selector = _object(value, _SELECTOR_KEYS, "/")
    _const(selector["schema_version"], 1, "/schema_version")
    _const(selector["selector_format_version"], 1, "/selector_format_version")
    generation = _integer(
        selector["selector_generation"], "/selector_generation",
        minimum=0, maximum=9223372036854775807,
    )
    _one_of(selector["active_runtime_format_version"], (1, 2),
            "/active_runtime_format_version")
    _string(selector["active_runtime_id"], "/active_runtime_id", minimum=1)
    _one_of(selector["active_database_path"],
            ("runtime.sqlite", "runtime.v2.sqlite"), "/active_database_path")
    _one_of(selector["active_attachment_path"],
            ("attachment.json", "attachment.v2.json"), "/active_attachment_path")
    _one_of(selector["active_manifest_path"],
            (None, "runtime.v2.manifest.json"), "/active_manifest_path")
    _nullable_pattern(selector["active_manifest_sha256"], _SHA256,
                      "/active_manifest_sha256")
    _nullable_pattern(selector["latest_v2_checkpoint_sha256"], _SHA256,
                      "/latest_v2_checkpoint_sha256")
    _pattern(selector["selector_history_path"], _SELECTOR_PATH,
             "/selector_history_path")
    _nullable_pattern(selector["prior_selector_path"], _SELECTOR_PATH,
                      "/prior_selector_path")
    _nullable_pattern(selector["prior_selector_sha256"], _SHA256,
                      "/prior_selector_sha256")
    _one_of(selector["cutover_state"], ("V1_ACTIVE", "V2_ACTIVE"),
            "/cutover_state")
    _const(selector["currentness_status"], "UNKNOWN", "/currentness_status")
    _const(selector["authorizing_use"], "DENY", "/authorizing_use")
    _utc_second(selector["written_at"], "/written_at")
    _pattern(selector["selector_sha256"], _SHA256, "/selector_sha256")

    if generation == 0:
        _const(selector["selector_history_path"],
               "selectors/00000000000000000000.json", "/selector_history_path")
        _const(selector["prior_selector_path"], None, "/prior_selector_path")
        _const(selector["prior_selector_sha256"], None, "/prior_selector_sha256")
        _const(selector["active_runtime_format_version"], 1,
               "/active_runtime_format_version")
    else:
        _pattern(selector["active_runtime_id"], _UUID4, "/active_runtime_id")
        _pattern(selector["prior_selector_path"], _SELECTOR_PATH,
                 "/prior_selector_path")
        _pattern(selector["prior_selector_sha256"], _SHA256,
                 "/prior_selector_sha256")
        _const(selector["active_runtime_format_version"], 2,
               "/active_runtime_format_version")

    if generation == 1:
        _const(selector["latest_v2_checkpoint_sha256"], None,
               "/latest_v2_checkpoint_sha256")
    elif generation >= 2:
        _pattern(selector["latest_v2_checkpoint_sha256"], _SHA256,
                 "/latest_v2_checkpoint_sha256")

    if selector["active_runtime_format_version"] == 1:
        expected = {
            "active_database_path": "runtime.sqlite",
            "active_attachment_path": "attachment.json",
            "active_manifest_path": None,
            "active_manifest_sha256": None,
            "latest_v2_checkpoint_sha256": None,
            "cutover_state": "V1_ACTIVE",
        }
    else:
        expected = {
            "active_database_path": "runtime.v2.sqlite",
            "active_attachment_path": "attachment.v2.json",
            "active_manifest_path": "runtime.v2.manifest.json",
            "cutover_state": "V2_ACTIVE",
        }
        _pattern(selector["active_manifest_sha256"], _SHA256,
                 "/active_manifest_sha256")
    for name, expected_value in expected.items():
        _const(selector[name], expected_value, f"/{name}")


__all__ = (
    "ACTIVE_RUNTIME_SELECTOR_SCHEMA_SHA256",
    "BOOTSTRAP_VALIDATION_PROFILE",
    "BootstrapValidationError",
    "RUNTIME_ATTACHMENT_SCHEMA_SHA256",
    "RUNTIME_MANIFEST_SCHEMA_SHA256",
    "validate_attachment",
    "validate_manifest",
    "validate_selector",
)
