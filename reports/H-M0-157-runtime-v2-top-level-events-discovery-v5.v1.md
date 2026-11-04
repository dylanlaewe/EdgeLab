# H-M0-157 — Runtime-v2 top-level events discovery V5

Engineering commits `ff562ae` and `c48c9ec` add Discovery V5 and its
census-only Classification V34 rebase. Discovery V5 preserves all 422
Discovery V4 source records and adds exactly one unclassified semantic
composite: `BOUND_TOP_LEVEL_CARDINALITY_MAXIMUM_BINDING` for the host
preflight condition `0 <= len(captured['events']) <= MAX_EVENTS`.

The composite binds the raw `runtime_v2_image.MAX_EVENTS = 100000`
assignment at site
`2dcbb43b767e41adb2cb59c64d6b3bfab8e9dbb8e583eebc5801d93668b7b43f`
with exact occurrence one to the V3 `cardinalities:events` branch at site
`fd2933fa143fb9fb2d6a9d6f375f1f6b1e0aae26e447e9fea4ad3b9d7c2b92a1`.
It pins the exact captured subject, built-in tuple guard, inclusive comparison,
diagnostic, accounting failure, continuation, member gate, sanitized-image
withholding, enclosing function, and source module. Its sole meaning is
`HOST_PREFLIGHT_TOP_LEVEL_EVENTS_MAXIMUM_ONLY`.

The composite remains `UNCLASSIFIED`. It does not classify either predecessor
and explicitly excludes the initial reducer's `1 or 3..MAX_EVENTS` rule, the
separate transition-module `MAX_EVENTS` definition and collection limits, the
positional events table-row cap, per-event bytes, public-verifier acceptance,
execution, or authority. Classification V34 preserves the exact thirty-
constraint V33 prefix and all fifty-seven classified site IDs. The expanded
census contains 423 source sites and 296 schema sites: 719 total, fifty-seven
classified, and 662 unclassified. Coverage therefore remains `INCOMPLETE` and
generation remains `DENY`.

The normalized Discovery V5 manifest raw SHA-256 is
`639ed7839ed7d8086ff21acb53ec41950f5ee35812fb97cee503d138fa6ce929`;
its domain-separated self-digest is
`cf50f95495e52a2171e895e40be1dd6b8cb9877a6a8a03aafb06ef2e5467dd42`;
and its schema raw SHA-256 is
`07032fb401b40546ca77e7828c26652c3b9daade077283cf520dbbaf5b240a42`.
The normalized Classification V34 manifest raw SHA-256 is
`d4c89f461a1cc0f17f18af331529b6f8becd05b219e499586695f6bdaf0394c2`;
its self-digest is
`7c9b02db527a7ec0b87d932e1fa3957d4d75e7f41b41d23af9ab5d1515f6beaa`;
and its schema raw SHA-256 is
`4dc2df18649076c37284200259bae9900018ebe03eae634a753f1c18e7ed5b28`.

Adversarial evidence covers zero, 99,999, 100,000, and 100,001 events;
exact-tuple and tuple-subclass behavior; at-limit member inspection and
accounting versus plus-one member-skip and image withholding; independence
from the equal-valued positional events table cap; same-valued expression and
literal substitution; import aliasing; extra load/store; local shadowing;
subject and nonzero-minimum substitution; comparator, diagnostic, accounting,
continuation, member-gate, and sanitized-image bypasses; exact predecessor
occurrence; and six attacker-refreshed V5-composite mutations. The historical
V4 attacker-refresh harness was strengthened to refresh and byte-bind the V4
predecessor, V5 manifest, census digests, and classification evidence far
enough that the precise classification rejection remains mandatory. No
permissive identity-error fallback remains.

The final focused discovery/readiness set passed seventy-five tests normally
and under optimized Python. The complete fast tier passed 647 tests across 52
isolated modules. Normal and optimized readiness outputs were byte-identical
with SHA-256
`0f0dcddd9c53ebf5c26fa8aad935ade0c0d1a4584a243f7ee2d0d65d2534562e`;
both exited 1, retained `ACCEPTANCE_MATRIX_INCOMPLETE`,
`PUBLIC_ENTRYPOINT_DISCONNECTED`, `RESOURCE_INVENTORY_INCOMPLETE`, and
`V1_BRIDGE_UNSUPPORTED`, and wrote no release artifacts. Independent Skeptic
review returned `ACCEPT` only after the attacker-refresh repair. Before this
governance publication, 530 governed records and published history validated.

This is deny-only discovery engineering, not formal project acceptance. It
does not establish correct runtime content, reducer or transition semantics,
public-verifier connectivity, exact closure, accepted A-J evidence,
authoritative currentness, an authenticated receipt/R-gate, STOP clearance,
paper or live execution, settlement, wagering, or capital authority.
`STOP-M0-3A-002` remains OPEN, live capital remains LOCKED with USD 0
deployable, `live_enabled` remains false, and the kill switch remains ENGAGED.
