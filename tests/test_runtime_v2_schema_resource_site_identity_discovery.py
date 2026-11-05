"""Adversarial evidence for stable schema-resource site identities."""
from __future__ import annotations

import hashlib
import json
import unittest
from unittest import mock

import tools.check_runtime_v2_release_readiness as readiness
from src.edgelab.validate import ROOT
from tools.check_runtime_v2_release_readiness import (
    CLASSIFIED_RESOURCE_SITE_IDS,
    RESOURCE_CLASSIFICATION_MANIFEST,
    RESOURCE_CLASSIFICATION_V42_REBASED_EVIDENCE,
    RESOURCE_DISCOVERY_MANIFEST,
    RESOURCE_DISCOVERY_SCHEMA,
    RESOURCE_SCHEMA_BOUND_SITES_V2_DOMAIN,
    RESOURCE_SCHEMA_BOUND_SITES_V2_SHA256,
    SCHEMA_RESOURCE_SITE_IDENTITY_DOMAIN,
    ReadinessError,
    _address_schema_bound_inventory,
    _canonical_json,
    _domain_digest,
    _resource_site_maps,
    _validate_classified_resource_site_ids,
    build_report,
)


class SchemaResourceSiteIdentityDiscoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = build_report(ROOT)
        cls.discovery = cls.report["inventory"]["resource_inventory_discovery"]
        cls.classification = cls.report["inventory"][
            "resource_inventory_classification"
        ]
        cls.manifest = json.loads(
            (ROOT / "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v43.json")
            .read_text(encoding="ascii")
        )

    @staticmethod
    def synthetic_records() -> list[dict[str, object]]:
        return [
            {
                "classification": "UNCLASSIFIED",
                "json_pointer": "/arr/0/minItems",
                "keyword": "minItems",
                "path": "schemas/synthetic.schema.json",
                "schema_id": "urn:synthetic",
                "value": 0,
            },
            {
                "classification": "UNCLASSIFIED",
                "json_pointer": "/empty//maxItems",
                "keyword": "maxItems",
                "path": "schemas/synthetic.schema.json",
                "schema_id": "urn:synthetic",
                "value": 1,
            },
            {
                "classification": "UNCLASSIFIED",
                "json_pointer": "/tilde/~0/slash/~1/minLength",
                "keyword": "minLength",
                "path": "schemas/synthetic.schema.json",
                "schema_id": "urn:synthetic",
                "value": 2,
            },
            {
                "classification": "UNCLASSIFIED",
                "json_pointer": "/unicode/é/maximum",
                "keyword": "maximum",
                "path": "schemas/synthetic.schema.json",
                "schema_id": "urn:synthetic",
                "value": -3,
            },
        ]

    def test_v8_has_exact_stable_schema_census_and_known_vectors(self):
        self.assertEqual(
            self.discovery["profile_id"],
            "EDGELAB_RUNTIME_V2_RESOURCE_DISCOVERY_V8",
        )
        self.assertEqual(len(self.discovery["source_bound_sites"]), 425)
        self.assertEqual(len(self.discovery["schema_bound_sites"]), 296)
        self.assertEqual(self.discovery["derived_binding_site_count"], 0)
        self.assertEqual(self.discovery["derived_binding_site_ids"], [])
        self.assertEqual(self.discovery["derived_binding_sites"], [])
        self.assertEqual(
            self.discovery["schema_bound_sites_sha256"],
            RESOURCE_SCHEMA_BOUND_SITES_V2_SHA256,
        )
        self.assertEqual(
            _domain_digest(
                RESOURCE_SCHEMA_BOUND_SITES_V2_DOMAIN,
                self.discovery["schema_bound_sites"],
            ),
            "2ca911e85141b79c5ae6be653bf6a8b038ca90873a731764b27ac2bf0cae3fcf",
        )
        vectors = {
            (
                "schemas/m0-3a-active-runtime-selector.v2.schema.json",
                "/allOf/1/if/properties/selector_generation/minimum",
            ): "6c6fa255c147d0522b1fa3fa9d6f25cbdbf94d7a5fecee274c8084c8588b7069",
            (
                "schemas/m0-3a-active-runtime-selector.v2.schema.json",
                "/allOf/3/if/properties/selector_generation/minimum",
            ): "9cb9def66ac5a0fffd9beaba57d10a0af31471f43de5b1eaea9ccccd09d5ae70",
            (
                "schemas/m0-3a-active-runtime-selector.v2.schema.json",
                "/properties/active_runtime_id/minLength",
            ): "685812b87027cea3e8fc9ce370fd21377b11fc6459c06bf2151261260cd178ea",
            (
                "schemas/m0-3a-verifier-dependency-closure.v1.schema.json",
                "/properties/tested_runtime_assumptions/minItems",
            ): "1f55253f10d716a89afb376a62822f1361ef5d64609c3a2f302c6243f6b72441",
        }
        actual = {
            (item["path"], item["json_pointer"]): item["site_id"]
            for item in self.discovery["schema_bound_sites"]
        }
        for coordinate, site_id in vectors.items():
            self.assertEqual(actual[coordinate], site_id)
        negative = next(
            item for item in self.discovery["schema_bound_sites"]
            if item["value"] == -9223372036854775808
        )
        self.assertEqual(
            negative["site_id"],
            "2d5db059c4d2ccc4b4cd3a012e7c4a743bed2d86d1baed1858c8222131ed193d",
        )

    def test_rfc6901_empty_unicode_and_array_vectors_are_literal_identity_data(self):
        addressed = _address_schema_bound_inventory(self.synthetic_records())
        self.assertEqual(
            [item["site_id"] for item in addressed],
            [
                "06641cbd1ca4720b2673c1650a90c3417f0df1a72de3d4f8dc883ef548dc7ee7",
                "d59c12aef8c7483733204111d5d39cdd5d0235239a08457a9cb80dc4dae6c98c",
                "8caf49f0d787c694ac74682b51ad29969f602f94e3916cd7944755d027532181",
                "38e5f27b51eaa2436168500055cecd96bcf966b3617bbee5439194f4a4b72858",
            ],
        )
        identity = {
            key: self.synthetic_records()[2][key]
            for key in ("json_pointer", "keyword", "path", "schema_id", "value")
        }
        self.assertEqual(
            addressed[2]["site_id"],
            hashlib.sha256(
                SCHEMA_RESOURCE_SITE_IDENTITY_DOMAIN.encode("ascii")
                + _canonical_json(identity)
            ).hexdigest(),
        )

    def test_addressing_rejects_shape_type_order_duplicate_and_collision(self):
        records = self.synthetic_records()
        attacks = []
        extra = [dict(item) for item in records]
        extra[0]["extra"] = 1
        attacks.append((extra, "SCHEMA_RESOURCE_SITE_KEYS"))
        wrong_type = [dict(item) for item in records]
        wrong_type[0]["value"] = True
        attacks.append((wrong_type, "SCHEMA_RESOURCE_SITE_TYPE"))
        bad_escape = [dict(records[0])]
        bad_escape[0]["json_pointer"] = "/bad/~2/minItems"
        attacks.append((bad_escape, "SCHEMA_RESOURCE_SITE_POINTER"))
        trailing_tilde = [dict(records[0])]
        trailing_tilde[0]["json_pointer"] = "/bad/~/minItems"
        attacks.append((trailing_tilde, "SCHEMA_RESOURCE_SITE_POINTER"))
        attacks.append((list(reversed(records)), "SCHEMA_RESOURCE_SITE_ORDER"))
        attacks.append(([records[0], dict(records[0])], "SCHEMA_RESOURCE_SITE_DUPLICATE"))
        for attacked, code in attacks:
            with self.subTest(code=code):
                with self.assertRaises(ReadinessError) as caught:
                    _address_schema_bound_inventory(attacked)
                self.assertEqual(caught.exception.code, code)
        with mock.patch.object(readiness, "_domain_digest", return_value="0" * 64):
            with self.assertRaises(ReadinessError) as caught:
                _address_schema_bound_inventory(records[:2])
        self.assertEqual(caught.exception.code, "SCHEMA_RESOURCE_SITE_COLLISION")

    def test_identity_field_mutation_changes_site_id_and_input_is_not_mutated(self):
        records = self.synthetic_records()
        before = json.loads(json.dumps(records, ensure_ascii=False))
        baseline = _address_schema_bound_inventory(records)[0]["site_id"]
        for field, value in (
            ("json_pointer", "/different/minItems"),
            ("keyword", "maxItems"),
            ("path", "schemas/different.schema.json"),
            ("schema_id", "urn:different"),
            ("value", 99),
        ):
            attacked = [dict(records[0])]
            attacked[0][field] = value
            self.assertNotEqual(_address_schema_bound_inventory(attacked)[0]["site_id"], baseline)
        self.assertEqual(records, before)

    def test_v7_and_v42_are_byte_pinned_predecessors(self):
        pins = (
            ("docs/M0.3A_RUNTIME_V2_RESOURCE_DISCOVERY.v7.json", 4625, "cdcdf26146deb7f9aa3578f62df71517410b16d74a920aff65b381ea857f2c7c"),
            ("schemas/m0-3a-runtime-v2-resource-discovery.v7.schema.json", 6483, "54f0b91eafffd5db8e6f2ee7c0091ccdb946c12ef039a753eb7f626c9aa4a8d3"),
            ("docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v42.json", 93784, "9fda39bf5f1227d99ce2018411b78481a273d56dd18f28cde193d001fe295c3e"),
            ("schemas/m0-3a-runtime-v2-resource-classification.v42.schema.json", 101032, "b2cdb38ef8bfab74dcaf6bfa55d9e70170680a1d214dc15a3044f3a3e176187d"),
        )
        for path, length, digest in pins:
            raw = (ROOT / path).read_bytes()
            self.assertEqual(len(raw), length)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), digest)

    def test_v43_is_v42_census_only_with_exact_two_evidence_rebases(self):
        predecessor = json.loads(
            (ROOT / "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v42.json").read_text(encoding="ascii")
        )
        differences = []
        for successor, historical in zip(
            self.manifest["constraints"], predecessor["constraints"], strict=True
        ):
            self.assertEqual(
                {key: value for key, value in successor.items() if key != "evidence_inputs"},
                {key: value for key, value in historical.items() if key != "evidence_inputs"},
            )
            if successor != historical:
                differences.append((successor, historical))
        self.assertEqual(
            {successor["constraint_id"] for successor, _ in differences},
            set(RESOURCE_CLASSIFICATION_V42_REBASED_EVIDENCE),
        )
        self.assertEqual(len(self.manifest["constraints"]), 38)
        self.assertEqual(self.classification["classified_site_count"], 71)
        self.assertEqual(self.classification["unclassified_site_count"], 650)
        schema_ids = {item["site_id"] for item in self.discovery["schema_bound_sites"]}
        self.assertTrue(CLASSIFIED_RESOURCE_SITE_IDS.isdisjoint(schema_ids))

    def test_separate_namespace_maps_and_schema_classification_attacks_deny(self):
        source_sites, schema_sites = _resource_site_maps(self.discovery)
        self.assertEqual(len(source_sites), 425)
        self.assertEqual(len(schema_sites), 296)
        collision = {
            **self.discovery,
            "schema_bound_sites": [
                {**self.discovery["schema_bound_sites"][0], "site_id": next(iter(source_sites))},
                *self.discovery["schema_bound_sites"][1:],
            ],
        }
        with self.assertRaises(ReadinessError) as caught:
            _resource_site_maps(collision)
        self.assertEqual(caught.exception.code, "RESOURCE_SITE_NAMESPACE_COLLISION")
        schema_id = next(iter(schema_sites))
        with self.assertRaises(ReadinessError) as caught:
            _validate_classified_resource_site_ids(
                {schema_id}, frozenset({schema_id}), source_sites, schema_sites, "/test"
            )
        self.assertEqual(caught.exception.code, "RESOURCE_SCHEMA_SITE_CLASSIFIED")

    def test_v8_schema_manifest_and_blocked_disposition_are_exact(self):
        from jsonschema import Draft202012Validator

        schema = json.loads((ROOT / RESOURCE_DISCOVERY_SCHEMA[1]).read_text(encoding="ascii"))
        manifest = json.loads((ROOT / RESOURCE_DISCOVERY_MANIFEST[1]).read_text(encoding="ascii"))
        Draft202012Validator.check_schema(schema)
        self.assertEqual(list(Draft202012Validator(schema).iter_errors(manifest)), [])
        self.assertEqual(manifest["schema_version"], 8)
        self.assertEqual(manifest["derived_binding_site_count"], 0)
        self.assertEqual(
            [item["code"] for item in self.report["blockers"]],
            [
                "ACCEPTANCE_MATRIX_INCOMPLETE",
                "PUBLIC_ENTRYPOINT_DISCONNECTED",
                "RESOURCE_INVENTORY_INCOMPLETE",
                "V1_BRIDGE_UNSUPPORTED",
            ],
        )
        self.assertEqual(self.report["authorizing_use"], "DENY")


if __name__ == "__main__":
    unittest.main()
