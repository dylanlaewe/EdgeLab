# H-M0-182 — Candidate rule registry and package verifier

## Working increment

H-M0-182 turns the H-M0-180 feasibility prototype into a stable,
independently testable candidate package without changing accepted evidence.

The package contains:

- a strict versioned rule-registry schema and one registry containing only
  `DRAFT_2020_12_EXACT_LOCATION_MINLENGTH_V1`;
- a strict compiler-closure schema and manifest binding the compiler,
  production census reconstructor, registry/schema, exact V8/V55 inputs,
  adversarial test module and H-M0-180 feasibility evidence;
- compiler-side verification of the pinned registry and exact calibration
  semantics before candidate generation;
- a pure package verifier with the closed result vocabulary
  `VALID_CANDIDATE` or `INVALID` and fixed `DENY` authority;
- a closed result schema; and
- a CLI adapter over actual repository bytes.

Runnable verification:

```text
.venv/bin/python tools/verify_runtime_v2_candidate_package.py
```

The exact successful result is `VALID_CANDIDATE`, 25 candidate-only sites,
witness-ledger digest
`f011a87b6342100b2f500ebe79c26a9b30f07f878531ce98360759de99589be0`,
`governance_equivalence: NOT_ESTABLISHED`, no accepted classification change,
and `authorizing_use: DENY`. Normal and optimized Python produce identical
output.

## Exact identities

- Rule registry raw SHA-256:
  `874eecc433f27d16fae5c9f565b03dc85aa264fd8fbe7ca5519576499a77bae1`;
  registry self-digest:
  `7d2b1b259cd3f75c2679d458029fbcfcdc2f547b3cab7ef76db7a25da8ec7a71`.
- Rule self-digest:
  `fbb7974723262c27faa4188aa9de5f7accc5f4aee3e7a49dc9144d95f191fd31`.
- Compiler closure raw SHA-256:
  `0adcabed5124579a8a322b30cc2a0fe802686e274f5ed319f66a7f2e60dd33c3`;
  closure self-digest:
  `e293641bc429cfa3f8a6ed0b35b9ffba377c76dc1f6156552139a908e3c5fba2`.
- Candidate compiler output remains byte-identical at 602,682 bytes, raw
  SHA-256
  `1412fd869c8247d5a0fe27834c8ef386c1356f5ea73550f4235ad24c7ec2c073`,
  and compiler-output digest
  `8c72e6be16266c22f1bc47d83b9a4580a182580494036d5f57bfbc1c4862e100`.
- Pure package verifier raw SHA-256:
  `644088789fb622436cd03247f095f2bde1f915b1ce7f592cd7e369e13845497c`.
- CLI adapter raw SHA-256:
  `a86f05787f5756b3f561650377d1a063e6e007b90c034af4a677eb659b44c342`.

## Verification boundary

The pure verifier accepts bytes and has no filesystem, subprocess, network,
clock, environment, compiler or readiness imports. It verifies:

- exact registry and closure raw identities and domain-separated self-digests;
- the single closed rule and its fixed candidate-only/DENY boundary;
- an exact unique ordered file set with byte lengths and raw digests;
- exact V8 census and V55 predecessor identities;
- canonical compiler output and raw identity;
- ledger and compiler-output digests;
- 721 unique ordered witnesses and exact disposition counts;
- DENY on every witness;
- frozen census/predecessor cross-bindings; and
- registry/closure expected-output agreement.

Registry, closure, source file, candidate, authority, duplicate, omission,
reorder, digest, semantic and host-type substitutions fail closed. Result
objects cannot be used as authorization booleans, cannot express `ACCEPTED`,
and validate against the closed result schema.

## Governance status

This is a candidate verification substrate, not the governance-equivalence
amendment or formal review requested by H-M0-181. The registry has exactly one
existing H-M0-180 family. It does not create another family, V56, an accepted
constraint record, a release closure, a runtime public-verifier attachment,
currentness or R-gate behavior.

V55 remains 87 classified / 634 unclassified. The 25 generated witnesses
remain unclassified `CANDIDATE_ONLY` evidence. Data remains BLOCKED; all STOPs
remain OPEN; M0 remains blocked; M1 remains unreleased; authorization remains
`DENY`; executor remains `MOCK_ONLY`; live remains `LOCKED`; kill remains
`ENGAGED`; deployable capital remains USD 0.
