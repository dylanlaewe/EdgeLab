"""Contract tests for the additive runtime-v2 legacy bridge amendment."""
import hashlib
import json
from pathlib import Path
import unittest

from src.edgelab.runtime_v2_codec import (
    schema_document_digest,
    schema_registry_digest,
    storage_schema_digest,
)


ROOT = Path(__file__).resolve().parents[1]
AMENDMENT = ROOT / "docs" / "M0.3A_LEGACY_BRIDGE_AMENDMENT.v1.md"

COMPILED_PROFILE_ROWS = (
    "| `meta` | `k:TEXT!, v:TEXT!` | `k` |",
    "| `seals` | `runtime_id:TEXT!, attachment_id:TEXT!, attachment_digest:TEXT!, genesis_digest:TEXT!, created_at:TEXT!, seal_digest:TEXT!` | `runtime_id` |",
    "| `tasks` | `task_id:TEXT!, attempt:INTEGER!, workflow:TEXT!, execution:TEXT!, review:TEXT!, scheduler_generation:INTEGER!, dispatch_generation:INTEGER!, task_fence:INTEGER!, claim_id:TEXT?, reviewer_id:TEXT?, continuations:INTEGER!, repository_generation:INTEGER!, receipt_digest:TEXT!, owner:TEXT!, reviewer:NULL!, predecessor_task:TEXT?, successor_task:TEXT?` | `task_id` |",
    "| `attempts` | `task_id:TEXT!, attempt:INTEGER!, predecessor_attempt:INTEGER?` | `task_id,attempt` |",
    "| `claims` | `claim_id:TEXT!, task_id:TEXT!, attempt:INTEGER!, fence:INTEGER!, status:TEXT!, actor:TEXT!` | `claim_id` |",
    "| `reviews` | `assignment_id:TEXT!, task_id:TEXT!, actor:TEXT!, role:TEXT!, status:TEXT!` | `assignment_id` |",
    "| `idempotency` | `operation_key:TEXT!, request_digest:TEXT!, response:TEXT!` | `operation_key` |",
    "| `runtime_events` | `event_id:TEXT!, global_seq:INTEGER!, event_type:TEXT!, payload:TEXT!, event_digest:TEXT!, prev_id:TEXT!, prev_digest:TEXT!` | `global_seq,event_id` |",
    "| `task_events` | `event_id:TEXT!, task_id:TEXT!, attempt:INTEGER!, task_seq:INTEGER!, global_seq:INTEGER!, event_type:TEXT!, before_json:TEXT!, after_json:TEXT!, payload:TEXT!, event_digest:TEXT!, prev_task_digest:TEXT!, prev_global_digest:TEXT!` | `global_seq,event_id` |",
    "| `remediation_links` | `link_id:TEXT!, source_task:TEXT!, child_task:TEXT!, source_event:TEXT!, child_event:TEXT!, decision_digest:TEXT!, link_digest:TEXT!` | `link_id` |",
    "| `migration_ledger` | `migration_id:TEXT!, from_version:INTEGER!, to_version:INTEGER!, artifact_digest:TEXT!, backup_ref:TEXT!, backup_digest:TEXT!, result:TEXT!, created_at:TEXT!` | `migration_id` |",
    "| `snapshots` | `snapshot_id:TEXT!, digest:TEXT!, generation:INTEGER!, global_head:TEXT!, created_at:TEXT!` | `snapshot_id` |",
)

PINNED_SCHEMA_DOCUMENTS = (
    (
        "m0-3a-command-request.v2.schema.json",
        "520cdbc148f6b3942b47d53708899ab8a8135e7a82850166fd360b26fa39cdbe",
        "8c7b7cf050700f696e44d89899365bdc80620dd1071dad7aa08707c91f88388e",
    ),
    (
        "m0-3a-event-envelope.v2.schema.json",
        "c4132bfe07198be0411feff8b3868f08c07f09bb310db366a4c4911520445f1d",
        "ae3655e0b94610e54ad00b514de1eeb78e9abd54f5828fd93387583b76f2b553",
    ),
    (
        "m0-3a-event-payload.v2.schema.json",
        "c7d3e5087bd7299c1be05a015e072c3b4eceabe690142f5b906c07f6d64f1f0b",
        "1b26427cde4998e23ec503df3a46b527893a2f40c27e7d0efdadf5474e8e30e4",
    ),
    (
        "m0-3a-legacy-v1-projection.v1.schema.json",
        "5222c1bd0975b3e342f4f42719afce2e4e5b82e27fec981612e310810c346164",
        "15689e50b3abe3895c546ddc606fe9b754ab993804b13aedd85e8e789374ba53",
    ),
    (
        "m0-3a-legacy-v1-row-archive.v1.schema.json",
        "507de0b778fce8d4051d30effd57c577f3133b520dba3c1d7d1c0212c19246c9",
        "fcd734fdda399047738bb139ed3971e5906eaaa7063435f4902a259d2a9d3a9c",
    ),
    (
        "m0-3a-response-projection.v2.schema.json",
        "bed7ffc08a0c88b87f70ccfc1342c9f658de089432d3c8fbfe6f8dff006a2363",
        "9a01e5c47f628c4a80082f6ac1276ecae345c47c42923789d0743d4fd41f0a61",
    ),
    (
        "m0-3a-runtime-checkpoint.v2.schema.json",
        "5c25100c14665e2f19ff845a3bfc4783f78c15092c10b81ec4551bc7d56f671d",
        "2c9fc0fed41a49342ec91a8b5d17dd3f3e23e7612a07257af5f1d6acd6d4c05a",
    ),
    (
        "m0-3a-runtime-export.v2.schema.json",
        "4f717185630240176aa35a435a8fb65f50c2da8ae370bfb4b74e86b0ca3cfec2",
        "c9b345e83d99173f41c52fd818471b428ff0a7503ce9340e76531d7cb58b079a",
    ),
    (
        "m0-3a-task-state.v2.schema.json",
        "dc581b64f60c035d5be1fe98a89d105d3ba88af30db42dbbb0e0eee700c937e7",
        "c8b9a47df5b91ae467f3008c8c7c27bdf2df089a3fbc25d684f53e56bc37ede8",
    ),
)

PINNED_CONTROL_DOCUMENTS = (
    (
        "m0-3a-schema-registry.v2.json",
        "ad8160f631fa57317f724d8afed239f9ea79e196edab06a2395dc55b05583bcf",
        "6b68797766e10c5ff8260d9d7b6cb31759466765287e7a23c377bd781a97bfd6",
        schema_registry_digest,
    ),
    (
        "m0-3a-runtime-storage.v2.json",
        "047ce290c747b8adb6689b94a15f7bc3fe82ccf852ed777fead3b03c070176a7",
        "8a588ce0bd23a10ea984fa656b2f172dcc4b0ede501c501d414a662d17c60a63",
        storage_schema_digest,
    ),
)

PINNED_BOOTSTRAP_SCHEMA_RAW = (
    ("m0-3a-runtime-attachment.v2.schema.json", "0623e1706d3a18a2b06043c72f444bd8bad9d798248ff62c83a901a36c1dbb9c"),
    ("m0-3a-runtime-manifest.v2.schema.json", "dcec875b3bb65178fc58e19d84c7fed5d85df97f44f501b3e4aa3c1c44b791de"),
    ("m0-3a-active-runtime-selector.v2.schema.json", "5398ccf55ce90159d9da34f9a29863a856f1e6e38fdb9ab498b8bd71bb5badf9"),
    ("m0-3a-schema-registry.v2.schema.json", "b31a025add8419bfc1db2bee579d2511a3e93c59dcea47cd832655affc03d630"),
    ("m0-3a-runtime-storage-descriptor.v2.schema.json", "cb54877057a81440fa8510111a984ba2cbd528b48842066fb49a3a92cd7a6193"),
)

EXPECTED_DIGEST_BINDINGS = """source_row_archive_sha256
  = projection.row_archive_sha256
  = legacy_archive_digest(archive)

request.arguments.legacy_archive_ref.sha256
  = payload.data.legacy_archive_ref.sha256
  = legacy_archive.archive_blob_sha256
  = blob_digest(archive)

source_projection_sha256
  = projection.projection_sha256
  = legacy_projection_digest(projection_without_projection_sha256)

request.arguments.legacy_projection_ref.sha256
  = payload.data.legacy_projection_ref.sha256
  = legacy_archive.projection_blob_sha256
  = blob_digest(projection)"""


class RuntimeV2LegacyAmendmentTests(unittest.TestCase):
    def test_amendment_is_additive_deny_only_and_keeps_migration_unsupported(self):
        text = AMENDMENT.read_text(encoding="utf-8")
        normalized = " ".join(text.split())
        for statement in (
            "All existing retained schema, schema-registry, storage-descriptor, and raw-file pins remain byte-identical",
            "`V1_MIGRATION` remains unsupported",
            "authorizing_use=\"DENY\"",
            "unverified archival reference coordinates",
            "MUST NOT state that absent bytes were recomputed",
        ):
            with self.subTest(statement=statement):
                self.assertIn(statement, normalized)

    def test_attachment_and_missing_preimage_equations_are_explicit(self):
        text = AMENDMENT.read_text(encoding="utf-8")
        self.assertIn("source_attachment_sha256 = SHA256(A)", text)
        self.assertIn("duplicate-free JSON", text)
        self.assertIn("source_backup_sha256", text)
        self.assertIn("migration_plan_sha256", text)
        self.assertIn("frozen_verifier_closure_sha256", text)
        self.assertIn("They are not typed blob-reachability\nedges", text)
        self.assertIn("`V16_BOUNDED_REPLAY_ONLY` is only", text)
        for coordinate in (
            "raw `runtime.sqlite` bytes",
            "source_backup_sha256",
            "migration_plan_sha256",
            "frozen_verifier_closure_sha256",
            "frozen_verifier_commit",
            "source_repository_bundle_sha256",
        ):
            self.assertIn(coordinate, text)
        self.assertIn(
            "`V1_MIGRATION`\nMUST return `UNSUPPORTED` under the current schemas",
            text,
        )

    def test_legacy_and_blob_digest_domains_are_not_conflated(self):
        text = AMENDMENT.read_text(encoding="utf-8")
        self.assertIn(EXPECTED_DIGEST_BINDINGS, text)

    def test_compiled_profile_closes_all_twelve_tables_and_nullable_columns(self):
        text = AMENDMENT.read_text(encoding="utf-8")
        for row in COMPILED_PROFILE_ROWS:
            with self.subTest(row=row):
                self.assertIn(row, text)
        profile_lines = [line for line in text.splitlines() if line.startswith("| `")]
        self.assertEqual(len(profile_lines), len(COMPILED_PROFILE_ROWS))
        self.assertIn("strictly increasing in the stated total order", text)
        self.assertIn("exactly one `seals` row and zero\n`snapshots` rows", text)
        self.assertIn("`idempotency.operation_key`", text)
        self.assertIn("`migration_ledger.artifact_digest`", text)

    def test_request_payload_wording_matches_pinned_schemas(self):
        request = json.loads((
            ROOT / "schemas" / "m0-3a-command-request.v2.schema.json"
        ).read_text(encoding="utf-8"))
        payload = json.loads((
            ROOT / "schemas" / "m0-3a-event-payload.v2.schema.json"
        ).read_text(encoding="utf-8"))
        self.assertNotIn("verifier_dependency_closure_sha256", request["properties"])
        self.assertNotIn("runtime_format_version", request["properties"])
        self.assertIn(
            "verifier_dependency_closure_sha256",
            payload["$defs"]["genesis"]["properties"],
        )
        self.assertIn(
            "frozen_verifier_closure_sha256",
            payload["$defs"]["bridge"]["properties"],
        )
        text = AMENDMENT.read_text(encoding="utf-8")
        self.assertIn(
            "archive and\nprojection blobs; request, response, and payload; "
            "bridge event; manifest; then\nmetadata, seal, and selectors",
            text,
        )

    def test_all_retained_document_pins_are_literal(self):
        for filename, raw_sha, domain_sha in PINNED_SCHEMA_DOCUMENTS:
            with self.subTest(filename=filename):
                raw = (ROOT / "schemas" / filename).read_bytes()
                self.assertEqual(hashlib.sha256(raw).hexdigest(), raw_sha)
                self.assertEqual(
                    schema_document_digest(json.loads(raw.decode("utf-8"))),
                    domain_sha,
                )
        for filename, raw_sha, domain_sha, digest_function in PINNED_CONTROL_DOCUMENTS:
            with self.subTest(filename=filename):
                raw = (ROOT / "schemas" / filename).read_bytes()
                self.assertEqual(hashlib.sha256(raw).hexdigest(), raw_sha)
                self.assertEqual(digest_function(json.loads(raw)), domain_sha)
        for filename, raw_sha in PINNED_BOOTSTRAP_SCHEMA_RAW:
            with self.subTest(filename=filename):
                self.assertEqual(
                    hashlib.sha256((ROOT / "schemas" / filename).read_bytes()).hexdigest(),
                    raw_sha,
                )


if __name__ == "__main__":
    unittest.main()
