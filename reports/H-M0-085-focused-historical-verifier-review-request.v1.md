# H-M0-085 focused historical-verifier review request — v1

## Authority disposition

Formal Skeptic review was **not executed** in this Director session.

EdgeLab requires a distinct accountable reviewer, prohibits an author from
reviewing its own work as independent, and states that role labels alone are
insufficient. Reviewer authentication/enforcement remains pending M0. The
current `/root` actor authored H-M0-080, so it cannot issue the formal 05
Skeptic acceptance verdict. A supporting read-only subagent was used only to
challenge the evidence; its conclusions are not formal authority.

The complete bounded request is queued as H-M0-086. No repeated preparation is
needed. A separately accountable 05 Skeptic must claim that request before
writing review artifacts.

## Frozen review subject

- Prior rejection: H-M0-079.v3 and
  `reports/reviews/M0.2-M0.3-final-evidence-plan-rereview.v1.md`, introduced by
  commit `819e925d8aa1e8a2fb734e0bea1a26a6ef271cf4`.
- Historical implementation: `6385603ab5b8034bf33c2c6a7efc0ed256f6feb9`.
- Fail-closed repair: `9c16242f9803690a76e13a676d0b60dd0def4f68`.
- Corrected current handoff: H-M0-080.v5, SHA-256
  `78485aa127c8c6a611bcb22330312baf04df03ba70f4982b1a5d8488762ea96c`.
- Review-preparation base: `586da88a80e1c1ae81db8bca4d9e333ad992c773`.

The implementation, schemas, trust roots, tools, and six focused test modules
have no diff from the H-M0-080 repair checkpoint through the review-preparation
base. H-M0-080.v1 through v4 remain historically preserved, and H-M0-084
corrected only the current dependency representation.

## Prior HIGH disposition candidates

These are Director-side evidence assessments, not formal closures.

| H-M0-079 finding | Candidate disposition for independent review |
|---|---|
| HIGH 1 — self-consistent historical forgery | **Strong candidate for closure, still formally OPEN.** Current tests reject coordinated result/inventory, module, required-schema, package-byte/local-rehash, package-closure, shadow-package, capture, intent, entrypoint, freeze, and trust-root attacks. The formal reviewer must reconstruct original H-M0-079 mutations instead of relying only on owner-edited successor expectations. |
| HIGH 2 — persisted authentic representation | **Core materially remediated; exact closure requires Skeptic disposition.** Persisted graphs carry content-addressed bytes, lengths and hashes; enforce canonical paths, deduplication, manifests and directory closure; reconstruct retained trees; and execute frozen subprocess replay for all four capture families. A residual question remains because legacy `capture.json` Git/result observations are omitted from the graph while current provenance still describes capture Git observations as retained evidence. |
| HIGH 3 — authoritative currentness | **OPEN and out of H-M0-080.** Preserved tests still demonstrate caller-selected JSON authority, a repository A→B race, inconsistent generations, and absence of repository/SQLite locking. |
| HIGH 4 — v3 composition | **Historical embedded-v3 portion is a strong candidate for closure; outer-wrapper closure is not yet demonstrated; composed R-gate remains OPEN.** All exercised verifier paths embed schema-valid `UNKNOWN/DENY` v3 results. The outer wrapper schema accepts arbitrary nested Git/Python fields and contradictory `INVALID`/successful-replay combinations, so formal review must decide whether a bounded schema correction is required. |
| HIGH 5 — runtime/Git/package closure | **Partially evidenced; not predeclared closed.** Package identity/digest/closure, platform, architecture, reconstructed module/schema/package origins, normalized environment, and generic host-Git execution are checked. Exact ABI/cache-tag/abiflags and Git executable/version identity are observed but not pinned by the trust root. Historical HEAD/origin-main observations in legacy `capture.json` are not in the persisted graph. |

## Reproduced evidence

On current review claim `c8dcf14f598387c9a1ca031b48f3d247bb476df0`:

- exact six-module H-M0-080 suite: 47/47 passed in 32.216 seconds;
- `tests.test_data_integrity`: 29/29 passed in 9.261 seconds;
- supporting read-only audit independently ran the exact H-M0-080 suite: 47/47
  passed in 28.646 seconds;
- production repository validator at the actual clock: exit 0, validating 326
  records and published history;
- `compileall` and `git diff --check`: passed.

After adding the completion, audit, and queued-review records, final-tree
production validation exited 0 after validating 329 records and published
history. No new distinct validator failure appeared.

The 47-test suite includes deliberate currentness vulnerability-characterization
tests. Their passing status preserves the boundary; it does not imply that
currentness or the R-gate is fixed.

## Smallest residual reproducers

### Retained Git/result observation not graph-bound

Copy `tests/fixtures/authentic-stage1/dispatch`, change the root
`capture.json` values for `head`, `origin_main`, and `result`, and run
`verify_authentic_history()` on the copy. The reproduced status remains
`HISTORICALLY_VALID`. `generate()` includes `authentic-capture.v1.json`, the
repository tree, and package trees, but not root `capture.json`; its Git object
contains only freeze commit, model, and origin URL. Formal Skeptic must decide
whether `capture.json` was superseded or remains required by the provenance and
format claims. If it remains authoritative, this is a bounded historical
closure defect.

### Outer wrapper accepts contradictory records

Validate a successful verifier output against
`m0-2-historical-verification-result.v1.schema.json` after either mutation:

1. add an arbitrary field under `evidence.git`; or
2. set `status` to `INVALID`, leave `reason_codes` empty, and retain
   `replay.completed == replay.raw_result_match == true`.

Both reproduced with zero schema errors. The implementation constructor emits
safe combinations and the embedded v3 record remains closed and
non-authorizing, but the outer wrapper's claimed closed contract is not
established by the schema.

### Runtime/Git identity question

The trusted host boundary pins CPython major/minor, platform, architecture, a
generic Git model, and the environment key allowlist. It does not pin
`cache_tag`, `abiflags`, the resolved Git executable, or a Git version/digest;
the verifier accepts any executable whose output begins `git version `. This
must receive an explicit HIGH-5 disposition rather than being inferred closed
from diagnostic observation alone.

## Exact formal approval step

1. A separately accountable actor authorized as 05 Skeptic synchronizes to the
   pushed H-M0-086 request and confirms no authorship of H-M0-080 or this
   Director package; any conflict is disclosed.
2. That actor appends and pushes a CLAIMED H-M0-086 successor containing its
   concrete identity, exact base SHA, read-only subject, evidence scope, and
   exact-revision prerequisites.
3. The Skeptic independently reconstructs the original H-M0-079 attack shapes
   from commit `819e925`, runs the 47-test suite and preservation checks, and
   explicitly reproduces or refutes each residual case above.
4. The Skeptic publishes an evidence-linked report, audit event, and completed
   handoff with separate dispositions for historical HIGH 1, HIGH 2,
   historical HIGH 4, and HIGH 5. HIGH 3 and the composed R-gate portion of
   HIGH 4 must remain open.
5. If a residual historical defect is confirmed, the Skeptic returns the
   smallest reproducible case and a bounded remediation request to Director;
   no acceptance is issued for that finding until a new correction and
   independent re-review land.
6. The Skeptic commits and normally pushes its artifacts, verifies remote
   ancestry and a clean tree, after which Director may record the formal
   disposition without clearing either STOP or releasing Data.

## Safety and next milestone

Data remains BLOCKED. STOP-M0-001 and STOP-M0-3A-001 remain OPEN. M0 remains
blocked; M1 remains unreleased; executor remains `MOCK_ONLY`; live remains
`LOCKED`; kill remains `ENGAGED`; USD 50.00 remains conceptual with USD 0.00
deployable.

The immediate next milestone is the one formal H-M0-086 Skeptic review. If it
confirms a historical defect, route only that bounded correction through the
existing writer/re-review workflow. After formal historical acceptance,
authoritative currentness and composed R-gate integration remain the next
separately authorized engineering milestone.
