# H-M0-094 — Read-only local laboratory observatory

## Outcome

Commit `1e63a9c5cfe75db96e8913d4d28da2ab665d1913` adds a loopback-only
laboratory observatory for governed EdgeLab status and the retained synthetic
alpha walkthrough. The surface is visibility only: it cannot mutate the
repository, transition scheduler state, execute paper or live activity, clear a
STOP, move capital, or authorize any use.

The status endpoint reports the project as blocked, both current STOPs as open,
live capital as locked, deployable capital as zero, the kill switch as engaged,
and all authorizing use as `DENY`. Source freshness/currentness is explicitly
`UNVERIFIED_OR_STALE / UNKNOWN`; displaying a coherent snapshot does not create
positive authority.

## Implemented boundary

- `GET` and `HEAD` are the only supported methods; all other methods fail
  closed. No mutation route, form, CORS permission, execution adapter, external
  listener, or credential surface exists.
- `/api/v1/status` rebuilds a governed snapshot on every request from exact
  project-state, bankroll, risk-policy, STOP, and schema sources.
- The snapshot enforces M0's exact blocked project state, zero active
  strategies, no demonstrated edge, locked bankroll, engaged kill switch,
  zero limits, disabled live execution, and the complete current gate set.
- Governed sources and ancestor directories are opened through pinned file
  descriptors with no-follow semantics. Regular-file identity, single-link
  status, directory identity, initial/final bytes, closed STOP inventory, and
  schema validity are checked before a response is emitted.
- Unexpected, hidden, aliased, hard-linked, replaced, malformed, or changing
  governed inputs return a sanitized `503` rather than partial or stale status.
- `/api/v1/alpha` remains the bounded synthetic `MOCK_ONLY` walkthrough and now
  accurately describes structural validation as non-authorizing.
- Responses disable caching and apply a nonce-based Content Security Policy.

## Adversarial review

A separate read-only reviewer first identified final-component symlink races,
schema reads outside the coherent snapshot, incomplete risk-namespace checks,
hidden STOP inventory gaps, and accepted hard links. Repairs added descriptor-
based no-follow reads, schema inclusion, exact risk keys, closed inventory, and
single-link enforcement.

The reviewer then reproduced an ancestor-directory swap where pathname opens
could cross repository identities. The final repair pins the canonical root
and every governed ancestor directory for the full observation, performs
open-at reads relative to those descriptors, and verifies both held and
reopened directory identities. A deterministic swap-to-symlink regression now
fails closed. The final review reported no actionable findings.

## Executed evidence

- Focused observatory suite: 10/10 tests passed.
- Final fast tier: 102/102 tests passed across seven isolated modules in
  26.480 seconds.
- Independent adversarial review: final result clean; HTTP safety, retained
  alpha compatibility, compilation, and diff checks passed.
- Production validator before evidence publication: 345 records and published
  history validated; capital remained LOCKED and no scientific or operational
  approval was granted.
- Production validator after evidence publication: 347 records and published
  history validated with the same locked, blocked, and non-authorizing result.
- The reviewed service was exercised at `http://127.0.0.1:8766`; health,
  governed status, and alpha endpoints responded locally.
- Code commit `1e63a9c` was pushed to `origin/main` without rewriting history.

## Explicit residual gaps

The observatory is not positive currentness, an authenticated receipt, an
R-gate, a scheduler control plane, a strategy dashboard, or a deployment
surface. Its local process and code remain inside the local trust boundary. A
future authority design still requires a separately specified and reviewed
currentness/generation contract.

`STOP-M0-001` and `STOP-M0-3A-001` remain OPEN. H-M0-041 remains BLOCKED and
H-M0-086 still lacks a genuinely distinct trusted Skeptic authority. M0.3A is
not accepted, M1 is not released, live remains LOCKED, the kill switch remains
ENGAGED, deployable capital remains USD 0, and no edge has been demonstrated.
