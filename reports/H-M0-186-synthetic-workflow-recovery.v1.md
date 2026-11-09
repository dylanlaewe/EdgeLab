# H-M0-186 — Synthetic workflow recovery

## Outcome

H-M0-186 makes the accepted H-M0-184 local synthetic workflow recoverable
after a real process exit without changing Scheduler v1, runtime format 1 or 2,
or the H-M0-185 authority finding. A new process opens the persisted SQLite
runtime through `Scheduler.startup()`, which performs integrity checks and full
event replay, then derives progress from exact task history and locked claim or
review state. Caller-reported stage completion is not accepted.

The final scientific result remains `INSUFFICIENT_DATA`. Authorization remains
`DENY`; this milestone adds no operational worker, public verifier attachment,
paper/live path, or formal approval.

## Runnable cold recovery

```sh
runtime_dir=$(mktemp -d /tmp/edgelab-hm0186.XXXXXX)
rmdir "$runtime_dir"
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python tools/run_recoverable_scheduler_research.py \
  --runtime-dir "$runtime_dir" --interrupt-after RESEARCH --format text
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python tools/run_recoverable_scheduler_research.py \
  --runtime-dir "$runtime_dir" --resume --format text
```

Use `--format json` for the schema-validated machine result. Other exercised
durable interruption points are `QUANT`, `REVIEW_ASSIGNED`, and `RISK_CREATED`.

## Exact recovery capability

The recovery coordinator permits only the following replay-derived paths:

- after Research or Quant, it verifies the exact ordered evidence-prefix,
  obtains the still-active claim ID and fence from the locked authority reader,
  verifies the expected synthetic actor, and continues that same claim;
- during `REVIEWING`, it verifies the exact active synthetic Skeptic assignment
  and continues the decision using its replayed assignment ID;
- after the Risk task is durably created in `CLAIMABLE`, it verifies the
  content-bound pipeline-history receipt before claiming and starting Risk;
- after a completed Pipeline, Risk, or Director task, it verifies the entire
  exact stable history and skips every already committed transition;
- repeated resume of a completed runtime performs no task-event mutation.

The retained after-Research run has exactly 10 Pipeline, 4 Risk, and 4 Director
events. A second resume retains exactly those 18 events. Its nested scientific
result is byte-for-byte the accepted H-M0-184 result with digest
`10e0585d5193fb166d51aa587109b4bf9f22e5ad5dae9a57ec112da71c51c06d`.
The H-M0-186 retained JSON raw SHA-256 is
`5c65935ae49f9f28714ba3f117e38d08f179759de18d6c7a8ab3fc1764e0f9e7`;
its internal result digest is
`00ce4bf8613d51f0532305ead4a932e13a65761a17f071238fabf807ab849a9b`.

Stage functions execute only after the scheduler predecessor is verified. On
recovery, already completed deterministic stages are recomputed only to verify
that current frozen inputs still reproduce the recorded digest; no duplicate
stage event is written.

## Fail-closed boundary

Startup/replay rejects event-chain corruption, missing history, stale claim
materialization, and inconsistent repository generation. The coordinator then
rejects altered evidence digests, out-of-order or duplicate stage history,
unexpected task inventory, wrong actors, wrong review identities, changed
receipts, or incompatible task states before any downstream transition.

A replay-valid `CLAIMED` task is deliberately not reclaimed. Scheduler v1 has a
`RECOVER` operation, but H-M0-186 has no authenticated lease-expiry, process-
death, or liveness authority. Synthesizing a string would be sufficient for the
current implementation's type check but would not prove that fencing an active
worker is valid. Therefore recovery stops with
`CLAIMED_WITHOUT_AUTHENTICATED_LIVENESS` and makes no event or state change.
This is the strongest truthful bounded recovery available under the frozen
contract.

An `IN_PROGRESS` task is not fenced or reclaimed. Recovery is possible only
for this isolated deterministic harness because it continues the exact active
claim and fence reconstructed from verified state. If that identity, actor,
generation, evidence, or history is not exact, recovery denies. This does not
generalize to an operational worker with uncertain external effects.

## Tests and review

- Corrected focused H-M0-186 suite: 12/12 passed in 24.791 seconds.
- Corrected combined H-M0-186, H-M0-184, H-M0-183, H-M0-179, lifecycle, and
  transactional-scheduler preservation matrix: 92/92 passed in 71.610 seconds.
- The independent reviewer reproduced 12/12 in 25.722 seconds and separately
  reproduced the claimed-state denial plus a real two-process Quant recovery,
  2/2 in 4.828 seconds.
- The reviewer previously reproduced the 92/92 preservation matrix in 76.767
  seconds and confirmed the corrected change does not affect those paths.
- Compilation, schema validation, `git diff --check`, and production repository
  validation passed; the completion tree validates 621 governed records and
  published history at the actual clock.

Initial engineering review returned `CHANGES_REQUIRED`: the candidate had
synthesized a liveness digest and automatically invoked `RECOVER` on a
`CLAIMED` task, which could fence a legitimate worker. That path and its
positive test were removed. The corrected path denies without mutation, and
read-only re-review returned `PASS` with no remaining demonstrated defect.
This is engineering review only, not formal 05 Skeptic approval.

## Preserved boundaries

Runtime formats 1 and 2, Scheduler v1 storage and operation vocabulary,
H-M0-179, H-M0-183, H-M0-184, and the H-M0-185 successor-format finding are
unchanged. Scheduler v1 still has no native general scientific dependency edge,
typed evidence table, or authenticated liveness source.

Data remains `BLOCKED`; every STOP remains `OPEN`; M0 remains blocked; M1
remains unreleased; executor remains `MOCK_ONLY`; public authorization remains
`DENY`; live remains `LOCKED`; kill remains `ENGAGED`; deployable capital
remains `$0.00`.
