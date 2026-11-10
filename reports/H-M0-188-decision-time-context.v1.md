# H-M0-188 decision-time context capture

## Delivered boundary

H-M0-188 adds a read-only capture and comparison workflow for a **new local
synthetic Scheduler v1 task**. It does not modify Scheduler v1/v2, frozen M0.2
evidence, or any public verifier. The retained context is outside the runtime
formats and is always `UNKNOWN / FAIL / generation_match=false / DENY`.

The implementation first executes the accepted H-M0-187 historical diagnostic,
then independently reads actual repository sources and locked SQLite authority
twice. It records the boundary as
`BOUNDED_REPOSITORY_THEN_LOCKED_RUNTIME_READ_RECHECK`; it does not claim an
atomic cross-system snapshot. The full accepted authority-binding candidate is
retained and semantically reverified. The actual frozen M0.2 input closure is
separate from contextual evidence that Stage 1 never consumed.

## Runnable demonstration

```sh
runtime_dir=$(mktemp -d /tmp/edgelab-h188.XXXXXX)
.venv/bin/python tools/run_decision_time_context.py demo \
  --runtime-dir "$runtime_dir/runtime" \
  --artifact reports/currentness/H-M0-188-context.v1.json \
  --comparison reports/currentness/H-M0-188-comparison.v1.json
```

Reopen and compare the retained bytes using the separately pinned raw digest:

```sh
.venv/bin/python tools/run_decision_time_context.py compare \
  --runtime-dir /tmp/edgelab-h188-final.WmaOqg/runtime \
  --artifact reports/currentness/H-M0-188-context.v1.json \
  --expected-sha256 d96ae174396ffaffd4f82009676877a5a3c3484ded251b3832735ac57743647c
```

The retained run at implementation commit
`53ba0e25f8efcea8fa29340aab97b22d20511a2f` captured 94 source records:

- 84 project/STOP records (project state plus the complete 83-file STOP set);
- 4 exact task/assignment/handoff-binding/handoff records;
- 1 resolved capability record and the exact empty dependency closure;
- 3 Git/repository records (HEAD, origin, Scheduler bundle); and
- 2 runtime records (attachment bytes and locked SQLite authority projection).

The actual subject is `T-SYNTHETIC-001`, attempt 1, active claim fence 1,
repository generation 0, scheduler generation 1, and dispatch generation 1.
The unchanged comparison returned `UNCHANGED_CONTEXT_UNKNOWN_DENY`. The
retained context raw SHA-256 is
`d96ae174396ffaffd4f82009676877a5a3c3484ded251b3832735ac57743647c`;
the retained comparison raw SHA-256 is
`dcfc0c2ff78798fa332469941fff946bfe69766743faf6cd76741ab6cb4c8bff`.

## Drift and artifact closure

Disposable actual Git repositories and actual persisted Scheduler v1 runtimes
demonstrate project/STOP, assignment/handoff, dependency/capability, Git HEAD,
repository generation, claim/fence, and scheduler-generation drift. A forced
change between the two observations raises `OBSERVATION_RACE`. Malformed
version-head candidates fail closed, and dependency collection first invokes
the existing dependency/capability validators before recursively retaining
dependency tasks, completion bindings, and transitive capability references.

Tampered raw bytes, missing fields, task substitution, rewritten limitations,
historical-summary substitution, capture substitution, and source-fact
substitution reject even when an attacker recomputes both the internal digest
and caller-presented raw digest. The retained full authority binding, exact
constant projections, current source re-observation, and cross-field equations
provide semantic closure. The raw digest remains an external content pin, not
an authenticated receipt.

## H-M0-187 UNKNOWN dimensions

For **new captures only**, five H-M0-187 gaps now have useful contextual
comparators: project/STOP, assignment/handoff, dependency/capability, exact
Git root/origin/HEAD/bundle, and current runtime/task generation. This does not
make their legacy M0.2 historical-equality dimensions known: frozen Stage 1 did
not read these new observations. Historical Git reachability beyond the exact
fresh observation also remains undefined.

Authenticated receipt binding remains wholly UNKNOWN. Atomic cross-system
snapshot authority also remains absent. Therefore none of H-M0-187's six
historical/R-gate UNKNOWN dimensions is promoted to verified historical
equality; H-M0-188 supplies only future drift evidence for newly captured
synthetic context.

## Validation and review

- Corrected focused H-M0-188 suite: 9/9 passed in 17.008 seconds locally;
  reviewer reproduced 9/9 in 18.365 seconds.
- Final H-M0-188 plus H-M0-187/H-M0-186/H-M0-184/H-M0-183/H-M0-179 and
  Scheduler v1 preservation matrix: 112/112 passed in 111.681 seconds.
- Production validation passed 625 governed records before completion
  artifacts; compilation and `git diff --check` passed.
- Independent read-only engineering re-review returned PASS at `53ba0e2` after
  the Director repaired the demonstrated semantic-resealing and malformed-head
  defects. This is not formal Skeptic approval.

## Remaining authority limits

No authenticated M0.2 receipt, positive currentness resolver, atomic
repository/SQLite snapshot, or R-gate transition consumer exists. Formal
independent approval and STOP clearance remain absent. Data remains BLOCKED;
all STOPs remain OPEN; M0 remains blocked; M1 remains unreleased; executor is
`MOCK_ONLY`; authorization is `DENY`; live is `LOCKED`; kill is `ENGAGED`; and
deployable capital is USD 0.
