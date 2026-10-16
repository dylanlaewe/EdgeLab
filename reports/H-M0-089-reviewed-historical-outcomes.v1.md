# H-M0-089 — Reviewed historical outcome fingerprint

## Outcome

The complete isolated historical audit at commit
`168e91abd8c2679ec17e8c3e784fabb72d1ff46c` is now represented by an exact,
machine-checked **non-green** outcome baseline. The run observed 43 modules and
484 tests in 773.060 seconds: 25 modules exited zero and 18 exited nonzero.
Across the nonzero modules, the baseline records all 71 failures and 69 errors
by ordered full test identity and normalized diagnostic SHA-256, including
distinct subtest parameters.

This does not make the historical tier green. The original runner still returns
nonzero, and the new verifier says only whether a complete observation matches
the reviewed pattern. No failure was skipped, inverted, or changed into an
expected-success mechanism.

## Review classifications

- 25 `PASS` modules were green in the isolated audit.
- 8 `REVIEWED_PRESERVED_RED` modules contain retained characterizations whose
  unsafe-success assertions now fail after later hardening.
- 4 `REVIEWED_CURRENT_TREE_COUPLING` modules depend on mutable current-tree
  bytes or contracts; these remain test debt and are not closure evidence.
- 6 `REVIEWED_MIXED_RED` modules contain both retained characterization red and
  stale inherited/current-tree fixture coupling.

Every nonzero module has an explicit note in
`tests/fixtures/historical-outcomes.v1.json`. There are no zero-test modules,
unclassified nonzero modules, missing modules, or unexplained outcomes in the
fingerprint. The Research v1/v3 fixtures fail in setup at the mandatory
authoritative-history boundary; their assertions are not reached.

## Fail-closed verifier

`tools/verify_historical_outcomes.py` requires:

- the exact historical-tier banner and aggregate summary;
- all 43 manifest modules exactly once and in order;
- exactly one test count, unittest final summary, and exit trailer per module;
- exact exit, test, failure, error, skip, expected-failure, and unexpected-
  success counts;
- exact ordered full failure/error identities and diagnostic hashes;
- an available full source commit and unchanged runner/test source hashes; and
- optionally, the reviewed raw-log SHA-256.

The exact capture is 259,015 bytes with SHA-256
`d8afa4789b22dd9a6ccfab8b0770271c258b2800610a6873b778e87bd767f12b`.
The normalized baseline is the durable evidence artifact; the raw local log is
identified by this hash and is not treated as an authenticated attestation.

## Executed evidence

- Historical tier: 484 tests across 43 isolated modules; 25 exit-zero and 18
  nonzero modules; aggregate exit 1 in 773.060 seconds.
- Exact-capture verifier with mandatory source checks: matched all 43 modules,
  484 tests, and 18 reviewed nonzero modules.
- Fast tier: 62/62 tests passed across 7 isolated modules in 10.637 seconds.
- Targeted verifier/parser unit tests: 9/9 passed, including incomplete-run,
  count/identity mismatch, and diagnostic-cause checks.
- A mutated diagnostic with unchanged test identity/count was denied, proving
  failure-cause drift is not accepted by the baseline.
- The earlier fixture-isolation milestone separately ran the fast tier (58/58),
  the currentness reference (4/4), orchestration v8 (29/29), Risk v3 (9/9),
  Semantic v2 (12/12), and Risk v2 with exactly its two reviewed preserved
  errors.
- Production validator: 337 records and published history validated; M0 capital
  remained LOCKED and no scientific or operational approval was granted.

## Authority and limitations

The fingerprint is Director engineering review, not independent Skeptic
approval. It does not authenticate who ran the audit, prove the raw log came
from the named commit, or validate production behavior beyond the observed
tests. The baseline does not separately list the ordered identities of passing
tests; their module counts and unchanged test-source hashes constrain that
surface, while every non-pass identity and cause is explicit. Mandatory source
hashes prevent silently applying this baseline to changed runner or test bytes;
outcome and diagnostic verification detect behavioral drift in a new complete
run.

`STOP-M0-001` and `STOP-M0-3A-001` remain OPEN. H-M0-086 remains blocked on a
genuinely distinct trusted Skeptic authority. M0.3A is not accepted, M1 is not
released, no executor exists, live remains LOCKED, the kill switch remains
ENGAGED, deployable capital remains USD 0, and no strategy has demonstrated an
edge.
