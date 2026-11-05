# H-M0-166 — Schema resource-site identity V8 / V43

Engineering commit `6d64623` repairs the architectural blocker that prevented
the 296 schema-bound resource records from entering semantic classification.
Discovery V8 addresses the existing schema census; Classification V43 is a
census-only rebase. Neither successor classifies a schema meaning or changes
runtime source.

Each legacy schema record now receives a stable `site_id` equal to SHA-256 of
the ASCII domain
`EDGELAB\0RUNTIME_V2_SCHEMA_RESOURCE_SITE\0V1\0` followed by canonical JSON
containing exactly `json_pointer`, `keyword`, `path`, `schema_id`, and `value`.
Classification and list position are excluded from the preimage. The addressed
296-record list uses the separate domain
`EDGELAB\0RUNTIME_V2_SCHEMA_BOUND_SITES\0V2\0` and has digest
`2ca911e85141b79c5ae6be653bf6a8b038ca90873a731764b27ac2bf0cae3fcf`.

The legacy discovery walk remains unchanged. Stripping `site_id` from V8
reconstructs the exact V7 schema list and its V1 digest
`00b27a32303836f9d9910663e6bd2f76a7ca6d8c7cd614e5f22346b53cd104de`.
V7 and V42 are byte-pinned immutable predecessors. Addressing rejects shape,
type, Boolean-as-integer, order, duplicate-coordinate, digest-collision,
malformed RFC 6901 escape, and source/schema namespace-collision attacks.

Classification membership now builds separate source and schema maps, rejects
internal and cross-domain collisions, and combines them only after those
checks. V43 enforces that all 71 current classified IDs remain source IDs and
that zero schema IDs are classified. It retains all 38 V42 constraint meanings
and site sets. Exactly the artifact and coordinate finding-string constraints
receive enumerated, byte-pinned evidence-only refreshes; broader changes deny.

Discovery V8 contains 425 source sites and 296 addressed schema sites, 721
total. Classification V43 contains 38 constraints, 71 classified sites, and
650 unclassified sites. Coverage remains `INCOMPLETE`, authorizing use remains
`DENY`, and the same four unconditional blockers remain.

Artifact identities:

- Discovery V8 raw SHA-256:
  `9914da2984589f7ded860656be4cbfdb88cf7d106ce52856860ed756dfe8725f`
- Discovery V8 self-digest:
  `78aed7fd37b6b07204c3462ec12855c21c0cb6da5268744d6957068973d72413`
- Discovery V8 schema raw SHA-256:
  `e10ca59c1bf90a0ebaee0647eb6c49a4e573295ee923411e337dc6e90ced50d1`
- Classification V43 raw SHA-256:
  `4d0c85a2faafc5079989c44a981b4d1356ce3eb4f213abd5729637ee74bbf824`
- Classification V43 self-digest:
  `3e124430a983d305402980cd966f057bad5f9dcedf97c854acf6374ad610da07`
- Classification V43 schema raw SHA-256:
  `92d649b4e32417a6004d3efaf1a253c096aaa798da6aaabf874c9fd3acc97142`

Independent Skeptic review initially found that malformed JSON Pointer escapes
could enter the addressing helper. The implementation was corrected to reject
every `~` not followed by `0` or `1`, with normal and optimized tests covering
dangling `~`, `~2`, valid `~0`, `~1`, `~01`, empty tokens, Unicode, and array
tokens. The re-review returned `PASS` with no remaining mandatory fixes.

The complete fast tier passed 719 tests across 61 isolated modules in
1197.523 seconds. Its release-readiness module passed 77 tests in 1087.698
seconds. Normal and optimized checker outputs were byte-identical with
current-tree SHA-256
`c112e8aee70faf5b12560a509443842c469d702e2fbd061144bb075ff249c6ce`;
both exited 1, retained the same four blockers, and wrote no release artifacts.
Before governance publication, 557 governed records and published history
validated.

Stable addressing is not semantic correctness, JSON Schema enforcement,
schema acceptance, public-entrypoint reachability, coverage completion,
release readiness, STOP clearance, execution authority, or capital authority.
`STOP-M0-3A-002` remains OPEN, live capital remains LOCKED with USD 0
deployable, `live_enabled` remains false, and the kill switch remains ENGAGED.
