# H-M0-183 read-only engineering review

## Authority boundary

This is an internal AI engineering review authorized by the owner. It is not
formal 05 Skeptic approval, governance acceptance, STOP clearance, strategy
promotion, or operational release. The reviewer made no repository changes.

## Initial verdict: FAIL

The reviewer reproduced the original 11/11 focused tests and a byte-identical
fresh JSON CLI result, then demonstrated two linked fail-closed defects:

1. `run_synthetic_research_experiment` treated the result schema as optional.
2. The scheduler projection accepted a substituted lifecycle containing only a
   top-level DENY and one `TASK_INITIALIZED` event.

The substituted run incorrectly returned `INSUFFICIENT_DATA`. Required
remediation was mandatory result-schema validation before scheduler creation,
validation of the complete scheduler projection, and adversarial regressions.

## Correction and re-review: PASS

The implementation now requires the result schema before scheduler activity and
checks the exact seven-event sequence, replay status, historical binding,
public-verifier status, final locked-authority state, and exact DENY
authorization. New tests encode both attacks.

The same reviewer reproduced:

- focused suite: 13/13 passed in 7.428 seconds;
- missing-result-schema attack: rejected with `MISSING_SCHEMA` before runtime
  creation;
- one-event DENY lifecycle substitution: rejected with
  `SCHEDULER_CONTRACT_MISMATCH`;
- fresh `/tmp` JSON CLI: exit 0 and byte-identical to retained result;
- exact seven scheduler events, `INSUFFICIENT_DATA`, formal Skeptic approval
  false, authorization DENY, live LOCKED, kill ENGAGED, and result SHA-256
  `eba4b15dd06159209947d6f9ecec7fc3ea61a4a2f7d94fa28a68515ac51da304`.

No remaining implementation defect was demonstrated. This PASS is engineering
evidence only and cannot cross the formal approval boundary.
