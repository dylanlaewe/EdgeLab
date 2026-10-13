# H-M0-080 native engineering review

## Disposition

`ACCEPTED_FOR_BOUNDED_HISTORICAL_VERIFIER_SCOPE`

This is an independent engineering review of H-M0-080 only. It is not formal
Skeptic approval, does not release Data, does not clear either STOP, and does
not approve currentness, the composed R-gate, or EdgeLab execution.

## Reviewed checkpoints

- Implementation: `6385603ab5b8034bf33c2c6a7efc0ed256f6feb9`
- Fail-closed repair: `9c16242f9803690a76e13a676d0b60dd0def4f68`
- Review base: `d7871b28a24594317ce8c424c9bad77f2eb4f391`

Both checkpoints were pushed to `origin/main`. The round-two reviewer verified
that local `HEAD` and `origin/main` were exactly the repair commit and that the
working tree and diff check were clean.

## Round one

The read-only reviewer independently reproduced the four canonical decision
IDs, wrapper and embedded-v3 schema validity, both CLI forms, reconstructed
origins, malformed graph rejection, and the required forgery families. It
found one in-scope blocker: a self-rehashed Stage-1 trust root with a missing
or wrongly shaped `host_boundary` could raise from `_runtime()` instead of
returning a typed denial.

## Repair and round two

The repair catches malformed runtime-boundary parsing and returns
`INVALID` / `TRUSTED_ROOT_MISMATCH`. A discoverable regression covers both a
missing `host_boundary` and a wrongly typed `python_major_minor`.

The reviewer independently reproduced both cases after the repair. Each
returned a schema-valid historical wrapper and independently valid embedded
v3 projection with `currentness_status: UNKNOWN` and
`authorizing_use: DENY`; no exception escaped.

Round-two focused command:

```text
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest -v tests.test_composed_authentic_history tests.test_trusted_authentic_capture tests.test_reconstructed_module_origins tests.test_reconstructed_package_origins tests.test_skeptic_trusted_evidence_plan_v14 tests.test_skeptic_final_evidence_plan_v15
```

Independent result: 47 tests in 26.862 seconds, all passed.

## Accepted historical evidence

- Four retained capture families reconstruct and replay to their exact stored
  results and decision IDs.
- Coordinated output, module, required-schema, package-byte, package-metadata
  rehash, package-closure, shadow-package, capture, intent, entrypoint, freeze,
  and trust-root mutations deny.
- Persisted graphs have closed schema validation, strict content-addressed
  blobs, deduplication, canonical paths, complete manifests, and fail-closed
  malformed/digest/duplicate/traversal/orphan/directory/source/raw-result
  checks.
- Runtime compatibility and reconstructed module, reached-schema, package,
  Git, Python, and normalized-environment diagnostics are execution-derived.
- Every covered success, invalid, and incompatible-runtime result validates
  against the historical wrapper and embedded v3 schemas and remains
  non-authorizing for current use.
- Historical tests are discoverable with the repository's unittest runner.

## Repository-wide validation disclosure

The pre-handoff full discovery ran 604 tests in 1180.965 seconds and was not
green: 70 failures and 75 errors. The failures include superseded Skeptic
tests that intentionally assert older vulnerabilities and broad copied-state
tests affected by repository governance history. At the time of that run,
`test_foundation.FoundationTests.test_repository` failed because
`docs/handoffs/H-M0-080.v1.json` was future-dated relative to the validator's
clock. This result is disclosed, not hidden or represented as a pass. The
bounded 47-test H-M0-080 acceptance surface is green. A final validator run,
after that timestamp had passed, advanced to the repository's pre-existing
handoff dependency cycle and failed with `Dependency cycle: H-M0-041`.

## Preserved boundaries

Currentness locking and composed R-gate code were not modified. Data remains
BLOCKED. `STOP-M0-001` and `STOP-M0-3A-001` remain OPEN. M0 remains blocked,
M1 remains unreleased, capital remains LOCKED, and no EdgeLab execution was
enabled.
