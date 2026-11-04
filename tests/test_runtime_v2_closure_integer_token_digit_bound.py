"""Adversarial evidence for the dependency-closure integer token digit cap."""
from __future__ import annotations

import json
import unittest
from unittest import mock

import src.edgelab.runtime_v2_closure as closure
from src.edgelab.runtime_v2_codec import CanonicalJsonError
from src.edgelab.validate import ROOT
from tools.check_runtime_v2_release_readiness import (
    RESOURCE_CLASSIFICATION_MANIFEST,
    _source_bound_inventory,
    build_report,
)


SIGN_SLICE_SITE = "7b99b5408a023f557be70736b52ecf6a8de4d8594b0da6318cacb3c9680cf5fc"
DIGIT_COMPARISON_SITE = "90292d8f8df61b2ee109adf7df0d0d4e44c2cdf5a6f70c887e7e5228d4cb8657"


class ClosureIntegerTokenDigitBoundTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = build_report(ROOT)
        cls.manifest = json.loads(
            (ROOT / RESOURCE_CLASSIFICATION_MANIFEST[1]).read_text(encoding="ascii")
        )
        cls.source_bytes = {
            item["path"]: (ROOT / item["path"]).read_bytes()
            for item in cls.report["inventory"]["source_closure"]["local_artifacts"]
        }

    def constraint(self) -> dict[str, object]:
        return next(
            item for item in self.manifest["constraints"]
            if item["constraint_id"] == "CLOSURE_INTEGER_TOKEN_MAX_DIGITS"
        )

    def test_positive_and_negative_boundary_matrix(self):
        for digits in (1, 18, 19):
            for sign in ("", "-"):
                with self.subTest(digits=digits, sign=sign):
                    token = sign + "9" * digits
                    self.assertEqual(closure._parse_integer_token(token), int(token))

        for sign in ("", "-"):
            with self.subTest(sign=sign):
                token = sign + "9" * 20
                with self.assertRaisesRegex(
                    CanonicalJsonError, "INTEGER_TOKEN_TOO_LONG"
                ):
                    closure._parse_integer_token(token)

    def test_minus_is_excluded_but_plus_is_not_a_classified_json_behavior(self):
        negative = "-" + "9" * 19
        self.assertEqual(closure._parse_integer_token(negative), int(negative))
        with self.assertRaisesRegex(CanonicalJsonError, "INTEGER_TOKEN_TOO_LONG"):
            closure._parse_integer_token("-" + "9" * 20)

        # The private token parser delegates a plus-prefixed token to int, but
        # JSON never admits that spelling through parse_int. This classification
        # makes no positive plus-sign claim.
        self.assertEqual(closure._parse_integer_token("+1"), 1)
        with self.assertRaisesRegex(CanonicalJsonError, "INVALID_JSON"):
            closure._parse_closure_json(b"+1")

    def test_twenty_digits_reject_before_integer_conversion(self):
        with mock.patch.object(
            closure, "int", side_effect=AssertionError("int called"), create=True
        ) as integer:
            with self.assertRaisesRegex(
                CanonicalJsonError, "INTEGER_TOKEN_TOO_LONG"
            ):
                closure._parse_integer_token("9" * 20)
            integer.assert_not_called()

            with self.assertRaisesRegex(AssertionError, "int called"):
                closure._parse_integer_token("9" * 19)
            integer.assert_called_once_with("9" * 19)

    def test_json_parser_binds_parse_int_to_exact_token_parser(self):
        source = self.source_bytes["src/edgelab/runtime_v2_closure.py"]
        self.assertEqual(source.count(b"parse_int=_parse_integer_token"), 1)
        self.assertEqual(source.count(b"digits = token[1:] if token.startswith(\"-\") else token"), 1)
        self.assertEqual(source.count(b"if len(digits) > 19:"), 1)
        self.assertLess(
            source.index(b"if len(digits) > 19:"),
            source.index(b"return int(token)"),
        )

    def test_source_attack_matrix_changes_bound_site_identity(self):
        path = "src/edgelab/runtime_v2_closure.py"
        original = self.source_bytes[path]
        attacks = (
            (b"token[1:]", b"token[2:]"),
            (b"len(digits) > 19", b"len(digits) >= 19"),
            (b"len(digits) > 19", b"len(digits) > 18"),
            (b"len(digits) > 19", b"len(digits) > 20"),
            (b"len(digits) > 19", b"19 < len(digits)"),
        )
        for old, new in attacks:
            with self.subTest(old=old, new=new):
                self.assertEqual(original.count(old), 1)
                mutated = dict(self.source_bytes)
                mutated[path] = original.replace(old, new)
                site_ids = {
                    item["site_id"] for item in _source_bound_inventory(mutated)
                }
                self.assertFalse(
                    {SIGN_SLICE_SITE, DIGIT_COMPARISON_SITE}.issubset(site_ids)
                )

    def test_parser_conversion_and_caller_are_pinned_separately_from_sites(self):
        source = self.source_bytes["src/edgelab/runtime_v2_closure.py"]
        self.assertEqual(source.count(b"return int(token)"), 1)
        self.assertEqual(source.count(b"parse_int=_parse_integer_token"), 1)
        self.assertEqual(source.count(b'token.startswith("-")'), 1)
        for old, new in (
            (b'token.startswith("-")', b'token.startswith("+")'),
            (b"return int(token)", b"return int(digits)"),
            (b"parse_int=_parse_integer_token", b"parse_int=int"),
        ):
            with self.subTest(old=old, new=new):
                mutated = source.replace(old, new)
                self.assertNotEqual(mutated, source)
                self.assertEqual(mutated.count(new), 1)

    def test_v39_preserves_v38_integer_token_constraint(self):
        predecessor = json.loads(
            (
                ROOT / "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v38.json"
            ).read_text(encoding="ascii")
        )
        for current, historical in zip(
            self.manifest["constraints"][:-1], predecessor["constraints"], strict=True
        ):
            self.assertEqual(
                {key: value for key, value in current.items() if key != "evidence_inputs"},
                {key: value for key, value in historical.items() if key != "evidence_inputs"},
            )
        self.assertEqual(len(self.manifest["constraints"]), 35)

        constraint = self.constraint()
        self.assertEqual(constraint["classification"], "RESOURCE_MAXIMUM")
        self.assertEqual(constraint["unit"], "CHARACTERS")
        self.assertEqual(constraint["maximum"], 19)
        self.assertEqual(constraint["definition_site_ids"], [SIGN_SLICE_SITE])
        self.assertEqual(
            constraint["enforcement_site_ids"], [DIGIT_COMPARISON_SITE]
        )
        self.assertIn("one leading minus sign", constraint["accepted_equation"])

        classification = self.report["inventory"]["resource_inventory_classification"]
        self.assertEqual(classification["classified_constraint_count"], 35)
        self.assertEqual(classification["classified_site_count"], 68)
        self.assertEqual(classification["unclassified_site_count"], 653)
        self.assertEqual(classification["coverage_status"], "INCOMPLETE")
        self.assertEqual(classification["generation_disposition"], "DENY")
        self.assertEqual(
            [item["code"] for item in self.report["blockers"]],
            [
                "ACCEPTANCE_MATRIX_INCOMPLETE",
                "PUBLIC_ENTRYPOINT_DISCONNECTED",
                "RESOURCE_INVENTORY_INCOMPLETE",
                "V1_BRIDGE_UNSUPPORTED",
            ],
        )

    def test_neighboring_integer_and_closure_meanings_remain_unclassified(self):
        classified = {
            site_id
            for constraint in self.manifest["constraints"]
            for key in ("definition_site_ids", "enforcement_site_ids")
            for site_id in constraint[key]
        }
        self.assertEqual(
            classified.intersection({SIGN_SLICE_SITE, DIGIT_COMPARISON_SITE}),
            {SIGN_SLICE_SITE, DIGIT_COMPARISON_SITE},
        )
        for site_id in (
            "97eb3a8f9e3c6b3addbed7a246a5f297d68449b798dc8bb14cc7c7f0bd255427",
            "b794efc2de42ab95a4ad50f579674f637674ca0e3d674af0e182c53c68b3cda4",
        ):
            self.assertNotIn(site_id, classified)


if __name__ == "__main__":
    unittest.main()
