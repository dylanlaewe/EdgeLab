# H-M0-187 read-only engineering review

## Boundary

This owner-authorized AI engineering review is internal and non-authorizing.
It is not formal 05 Skeptic approval, governance acceptance, STOP clearance,
an authenticated R-gate, or operational release. The reviewer made no
repository or scheduler changes.

## Initial verdict: CHANGES_REQUIRED

The reviewer reproduced 10/10 initial tests and a coherent cold-runtime CLI
result, but demonstrated that the result artifact was not semantically closed.
After recomputing its unkeyed outer digest, schema validation accepted:

- a nested `current_observation.authorization = "ALLOW"` field;
- promotion of `historical_project_stop_equality` from UNKNOWN to VERIFIED; and
- substitution of the authority-source mapping locator and digest.

Required correction: close the nested projection and add semantic integrity
verification for exact dimension partitions, trusted sources, cross-field
bindings, and the result digest.

## First correction and second finding

The implementation embedded the closed authority-binding candidate, closed the
current observation and runtime/task/claim structures with local offline
schemas, and added `verify_diagnostic_integrity`. A temporary cross-schema
reference regression was corrected by eliminating network-resolved references
and keeping the result validator wholly local.

The three original attacks then rejected, but re-review found that resealed
artifacts could still replace the `limitations` and `invalidators` lists.
Although authorization remained DENY, that changed the declared remaining
requirements of a supposedly closed deterministic artifact.

## Final correction and verdict: PASS

Limitations and invalidators are now exact versioned constants enforced by the
producer and semantic verifier. Final reproduced evidence:

- focused suite: 11/11 passed in 28.497 seconds;
- actual separate-process Quant interruption and recovery completed with
  `recovered_from=QUANT`, `INSUFFICIENT_DATA`, and DENY;
- CLI diagnostic returned historical VALID, currentness UNKNOWN, verifier FAIL,
  generation match false, authorization DENY, 10 verified dimensions, and 6
  unknown dimensions;
- actual subject was `T-SYNTHETIC-001`, attempt 1, active claim fence 1;
- canonical Git, project state, and all three active OPEN STOPs were observed;
- all five resealed attacks rejected: nested ALLOW, unknown-dimension promotion,
  trusted-source substitution, limitation replacement, and invalidator
  replacement; and
- `git diff --check` passed.

No remaining implementation defect was demonstrated. The review confirms only
the bounded diagnostic behavior; it does not approve positive currentness or
formal authority.
