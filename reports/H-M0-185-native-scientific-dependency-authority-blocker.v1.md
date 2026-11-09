# H-M0-185 — Native scientific dependency authority blocker

## Disposition

`BLOCKED`. No scheduler implementation is retained, committed, or pushed.
H-M0-184 remains unchanged at commit
`83def9a0d341349ef176e796753483c48bed9eb9`.

The requested behavior is technically implementable, and an uncommitted
prototype demonstrated claim-time Research-to-Data gating. The required
read-only review found that landing it would silently revise frozen runtime
format 1. The prototype was removed in full after that finding.

## Governing conflict

- `docs/M0.3A_TRANSACTIONAL_CONTRACT.v16.md` preserves the existing v1 wire
  pending a versioned storage migration and identifies further closure as a
  separately versioned format milestone.
- `docs/M0.3A_SUCCESSOR_RUNTIME_FORMAT.v1.md` defines runtime/event format
  negotiation as exact, states that a runtime format describes tables,
  persistence, and replay closure, and preserves format 1 as evidence.
- Its canonical format-1 archive is a closed table inventory. Scientific
  evidence and dependency tables are not members.
- `docs/M0.3A_CONTENT_REDUCER_CONTRACT.v1.md` closes format 2 to its exact
  schema registry, 25-event inventory, 22 operations, reducer, and
  materializations. New scientific operations/events cannot be inserted into
  that vocabulary without a successor contract.

Therefore neither an optional format-1 table pair nor new format-1 task events
are additive under current authority. Calling the extension optional or
fresh-runtime-only does not resolve the wire/storage identity conflict.

## Exact minimal authority decision required

Director/governance must approve one new, non-operational successor
runtime/event format pair rather than reinterpret format 1 or the closed
format-2 vocabulary. That approval must, at minimum:

1. allocate the exact runtime and event format identifiers and update exact
   negotiation to recognize only that pair;
2. publish a closed storage descriptor including the evidence and dependency
   tables, columns, constraints, indexes, and SQLite structural observations;
3. publish a closed successor command/event/schema-registry vocabulary for
   dependency-bound task creation and typed evidence recording;
4. define the pure reducer, replay-derived materializations, export/checkpoint
   projection, idempotency projection, and repository-generation behavior;
5. state fresh-runtime-only construction or provide a separately reviewed
   side-by-side migration; and
6. preserve `UNANCHORED / UNKNOWN / DENY`, all STOPs, and every operational
   exclusion.

This is the smallest decision that can authorize genuine scheduler
enforcement. Reusing reserved format 2 would instead require an explicit
successor revision of its closed content/reducer contract and completion of
its already-required storage descriptor and verifier prerequisites; it cannot
be inferred from H-M0-184's suggested next action.

## Prototype result and removal

Before the authority finding, the uncommitted prototype had one evidence type,
one atomic Data dependency origin, claim-time verification, event-derived
replay, export inclusion, and tests for absent/incomplete/altered/deleted/wrong
attempt/mismatched identity/idempotency/partial-storage cases. Its focused
suite passed 10/10 and the scientific preservation slice passed 36/36. Those
results are engineering exploration only, not accepted evidence or shipped
behavior.

The reviewer also found a prototype-specific HIGH: repository import could
advance a claimable dependent task without advancing or rejecting its immutable
dependency generation, committing state that the next replay rejected. That
code was removed with the entire prototype and creates no retained defect.

## Preserved validation

- Required read-only reviewer: 10/10 prototype tests passed; corrected
  combined prototype/preservation command passed 90/90; `git diff --check`
  passed. The review disposition remained BLOCKER because tests cannot override
  frozen format authority.
- After complete prototype removal, the H-M0-184/H-M0-183/H-M0-179 and
  transactional-scheduler preservation suite passed 80/80 in 47.243 seconds.
- No operational worker, real data, external service, UI, proof family,
  formal Skeptic authority, or release closure was added.

## Safety state

Data remains `BLOCKED`; every STOP remains `OPEN`; M0 remains blocked; M1
remains unreleased; executor remains `MOCK_ONLY`; public authority remains
`DENY`; live remains `LOCKED`; kill remains `ENGAGED`; deployable capital is
USD 0.
