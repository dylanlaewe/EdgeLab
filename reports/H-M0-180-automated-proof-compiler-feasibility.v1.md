# H-M0-180 — Automated proof-compiler feasibility

## Result

The prototype is feasible and useful for one rigorously closed family. The
offline compiler in `tools/compile_runtime_v2_minlength_candidates.py` reads
the exact frozen V8 resource census through the production readiness
inventory, independently checks the pinned V8 and V55 artifacts, and emits a
complete deterministic witness ledger without modifying either artifact.

Selected rule:

- family: Draft 2020-12 exact-location `minLength`;
- instance domain: string;
- metric: Unicode code-point count;
- equation: `UNICODE_CODE_POINT_COUNT >= bound`;
- non-domain behavior: no assertion from this keyword; and
- applicability: the exact pinned schema location and full pinned schema
  document only.

The rule was selected after measuring the frozen census. It has ten manually
accepted calibration examples and 25 additional currently unclassified sites,
so it tests both semantic reproduction and useful new coverage without
broadening the rule.

## Measured coverage

The canonical CLI output is 602,682 bytes with raw SHA-256
`1412fd869c8247d5a0fe27834c8ef386c1356f5ea73550f4235ad24c7ec2c073`.
Its internal witness-ledger digest is
`f011a87b6342100b2f500ebe79c26a9b30f07f878531ce98360759de99589be0` and
its compiler-output digest is
`8c72e6be16266c22f1bc47d83b9a4580a182580494036d5f57bfbc1c4862e100`.

- Census sites inspected: 721, comprising 425 source and 296 schema sites.
- Sites covered by current accepted evidence: 87 overall.
- Accepted sites in the selected family: 10.
- New sites supported by the exact rule: 25, all `CANDIDATE_ONLY`.
- Ambiguous sites: 0.
- Nonmatching sites: 686.
- Current official unclassified count: 634, unchanged.
- Unclassified sites without a candidate from this family: 609.

Every census identity appears exactly once. The ledger contains the namespace,
site identity, coordinate, pinned source digest, observed syntax, rule
disposition, derived semantics where applicable, accepted-reference status,
and explicit `DENY` authority. Set equality is checked in both directions, and
duplicate identities, omissions, and noncanonical order fail closed.

All ten accepted `minLength` records reproduce exactly: addressed census site,
semantic subject, Unicode-code-point unit and equation, full schema digest and
length, containing-subschema digest, ancestor pointer sequence, applicability,
instance domain, and non-domain behavior. There are no mismatches.

## Security and reproducibility

The compiler:

- requires the canonical repository root;
- raw-SHA-pins the V8 discovery and V55 classification manifests;
- independently recomputes frozen source-site, schema-site, source-input, and
  schema-input list digests;
- requires 425 + 296 unique census identities and current V55
  `87 classified / 634 unclassified / INCOMPLETE / DENY` state;
- treats unsupported dialect, nested dialect/ID, dynamic reference, external
  reference, and unresolved local reference conditions as explicit ambiguity;
- compares accepted-family projections field-for-field and refuses any
  accepted ambiguity or semantic mismatch;
- seals the witness ledger and full output separately; and
- recompiles from frozen inputs when verifying a candidate, rather than
  trusting candidate-provided counts or digests.

Focused tests cover deterministic API/CLI bytes, CLI verification, complete
coverage and counts, exact accepted-semantic reproduction, candidate-only
status, non-boolean DENY verification, forged semantics, attempted positive
authority, duplicate/omitted/reordered witnesses, stale input digests, forged
census values, explicit ambiguity detection, and invented ambiguity. Initial
writer run: 10/10 passed in 9.764 seconds.

The separate read-only engineering reviewer returned PASS with no defect,
reproduced 10/10 compiler tests in 9.740 seconds and 13/13 V55-preservation
tests in 1.293 seconds, independently confirmed exact 721-site set equality and
both output digests, and separately reproduced the decisive resealed attacks.
That verdict is engineering review only, not formal Skeptic authority.

## Usefulness and recommendation

Recommendation: **adopt for refinement as a candidate-evidence generator, but
do not count its output yet.** One narrow rule generated 25 complete new
witnesses, covering 3.94% of the 634 currently unclassified sites, while ten
existing proofs acted as exact regression calibrations. If governance later
accepts the compiler contract, those 25 sites could be reviewed as one closed
rule plus an exhaustive machine-generated ledger instead of 25 separately
authored classification milestones. Per-site auditability is retained; only
manual construction is consolidated.

The prototype does not self-certify equivalence. A future versioned amendment
must define the compiler, rule-registry, exhaustive-ledger, adversarial-test,
independent-review, and historical-prefix requirements. That amendment still
requires valid owner authorization and genuinely independent formal review.
Ordinary native engineering review is not formal Skeptic authority.

## Governance and safety boundary

No V56 artifact, accepted proof, classification count, frozen evidence,
release closure, public-verifier attachment, currentness decision, R-gate,
STOP status, or project state is changed. Output status is
`VALID_CANDIDATE_ONLY`, governance equivalence is `NOT_ESTABLISHED`, and
authorizing use is `DENY`.

Data remains BLOCKED; every STOP remains OPEN; M0 remains blocked; M1 remains
unreleased; executor remains `MOCK_ONLY`; live remains `LOCKED`; kill remains
`ENGAGED`; deployable capital remains USD 0.
