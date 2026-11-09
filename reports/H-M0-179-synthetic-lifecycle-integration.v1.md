# H-M0-179 — Non-operational synthetic lifecycle integration

## Working increment

`src/edgelab/synthetic_lifecycle.py` composes four already accepted bounded
components into one executable local test path:

1. the published runtime-v2 descriptor and exact schema bundle are passed to
   the public pure verifier;
2. a fresh out-of-repository transactional scheduler runtime creates
   `T-SYNTHETIC-001`;
3. the frozen M0.2 capture `AUTH-AUTHENTIC-STAGE1-DISPATCH` is reconstructed
   and bound to the actual locked task subject;
4. exact locked-authority observations supply the compare-and-swap tuple,
   repository generation, and stored synthetic receipt for each existing
   scheduler transition;
5. `CLAIM`, `START`, `COMPLETE`, `ASSIGN_REVIEW`, `APPROVE`, and `ROUTE` record
   a seven-event lifecycle ending at
   `DIRECTOR_GATE_READY / EXECUTION_COMPLETED / APPROVED`; and
6. scheduler replay and a final locked-authority read reproduce the recorded
   state.

The CLI is:

```text
.venv/bin/python tools/run_synthetic_lifecycle.py --runtime-dir <new-path-outside-repository>
```

This is deliberately a composition harness, not a second scheduler or a new
state model. The runtime directory must be new and outside the repository.

## Fail-closed boundary

The run proceeds only when the public verifier returns exactly
`UNSUPPORTED / UNANCHORED / UNKNOWN / DENY`, the historical binding returns
`BOUND_DENY_ONLY` with `R_GATE_CANDIDATE_EVIDENCE` and its existing v3
`FAIL / UNKNOWN / generation_match=false / DENY` projection, and each actual
locked-authority read is `COHERENT_DENY_ONLY` with `UNKNOWN / DENY`.

The output seals its own projection and repeats `authorizing_use: DENY`. A
substituted positive public-verifier result is rejected before runtime
creation. A substituted positive binding result is rejected before any claim,
leaving the created task `CLAIMABLE`. The synthetic review state is only a
local scheduler transition; it is not a formal Skeptic acceptance or release
approval.

The private runtime-v2 reducer remains separate from the public verifier. The
stored receipt remains caller-supplied and non-authoritative. No currentness,
composed R-gate, release carrier, executor, live action, or capital action is
implemented or inferred.

## Reproduced tests

- Focused integration: 5/5 passed in 5.010 seconds.
- Scheduler, locked authority, historical binding, public verifier, initial
  private reducer, transition kernel, and transition workspace preservation:
  170/170 passed in 29.526 seconds.
- Narrow current-classification preservation: 13/13 passed in 1.201 seconds,
  including exact V55-on-V54 prefix preservation and all four retained
  blockers.

Final production validation, compilation, diff checks, and independent review
are recorded in the completion handoff.

## Resource-classification assessment

The current STOP already permits either exact per-site proof or a rigorously
closed family, so the remaining work need not be serialized into one manually
authored site per milestone. An equally strong consolidation is technically
possible as a versioned semantic-proof compiler contract. Such a contract
would have to preserve V55 and every accepted predecessor byte-for-byte and
provide all of the following for each closed rule family:

- a pinned rule registry stating the exact semantic predicate and eligible
  source/schema coordinates;
- a deterministic extractor over the frozen 721-site census;
- an exhaustive per-site witness ledger containing site identity, coordinate,
  enclosing-artifact digest, matched syntax, and derived semantics;
- explicit ambiguous/excluded-site output that remains unclassified;
- bidirectional set equality proving that every compiled member is in the
  census and every census member is either covered once or explicitly remains
  unclassified, with no duplicates or evidence rebases;
- pinned compiler and registry identities, adversarial false-positive and
  false-negative tests, and independent review of both the family rule and
  exhaustive output.

Existing permission for rigorously closed families supports this direction,
but it does not by itself establish that generated compiler output is
governance-equivalent to the currently accepted manually published proof
artifacts. Before any generated result can count as classification evidence,
the owner must approve one exact amendment: **a pinned semantic-proof compiler,
rule registry, and exhaustive per-site witness ledger are acceptable as the
versioned proof artifact for only the exact closed family matched, provided an
independent reviewer accepts rule semantics, extractor completeness,
false-positive/negative resistance, bidirectional census coverage, and
historical-prefix preservation.**

Until that decision and independent acceptance exist, no generated site is
counted. V55 remains current at 87 classified and 634 unclassified sites;
`STOP-M0-3A-002.v81` remains OPEN.

## Remaining release barriers

- The public verifier remains disconnected from the private reducer and cannot
  produce positive local consistency.
- No compiled release closure or public carrier exists.
- The authoritative-currentness and composed R-gate paths remain absent; the
  frozen historical binding is not an authenticated positive scheduler
  receipt.
- 634 of 721 resource sites remain unclassified and bidirectional semantic
  coverage is incomplete.
- The V1 migration bridge remains unsupported.
- Independently accepted A-J whole-image release evidence is incomplete.
- Data remains BLOCKED and all STOPs remain OPEN.

## Safety state

This increment does not alter project or operational authority. M0 remains
blocked, M1 remains unreleased, executor capability remains `MOCK_ONLY`, public
authorization remains `DENY`, live remains `LOCKED`, kill remains `ENGAGED`,
and deployable capital remains USD 0.
