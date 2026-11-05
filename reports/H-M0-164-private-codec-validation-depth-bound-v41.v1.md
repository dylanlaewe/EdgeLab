# H-M0-164 — Private codec validation-depth bound V41

Engineering commit `7e3dd9e` advances the deny-only runtime-v2 semantic
classification from V40 to V41 without changing Discovery V7 or runtime
source. Independent inventory proposed an initial-reducer diagnostic bound;
bounded Skeptic review selected the smaller private codec `_validate`
depth-argument guard.

V41 adds exactly one constraint, `CODEC_PRIVATE_VALIDATE_DEPTH_MAXIMUM`. It
binds the overlapping definition and enforcement site for `depth > 128` at
`be6c857e6fce329131b4461868fe22a9f6a710daacc677a63e55a78298dc342c`.
The complete semantic context pins the comparison, enclosing entry guard,
exact `MAX_DEPTH_EXCEEDED` error, private function, codec module, both current
root callers, and the list/dictionary recursive calls.

For this private internal argument only, depth values 127 and 128 pass the
entry guard and 129 rejects before value dispatch or traversal. The default
`depth = 0` site remains unclassified. The constraint does not claim a public
or canonical-JSON structural-depth guarantee, integer or minimum validation,
parser behavior, complete traversal semantics, schema/reducer/image validity,
public-verifier acceptance, STOP clearance, execution authority, or capital
authority.

Classification V41 contains 37 constraints and 70 unique classified sites.
Discovery remains 425 source sites plus 296 schema sites, 721 total; 651 sites
remain unclassified. Coverage remains `INCOMPLETE`, authorizing use remains
`DENY`, and the same four unconditional blockers remain.

The V41 manifest raw SHA-256 is
`50e586829d57bd7e95cf78a69ea722b2c02198ed1c680c05d7ca0831a630458e`;
its domain-separated self-digest is
`23e21a2c8da989a89e578a5456c61894448f7e631c79ccfcea5bb3c09908ce1b`;
and its schema raw SHA-256 is
`ac34532f6f1bb13416319f7417eead72d690fb02b2944728674625a86b4cdb2a`.

V41 preserves every V40 semantic field and site set. Exactly six historical
constraints receive enumerated evidence-only refreshes because their tests
assert the current classification census: top-level events, both
finding-string constraints, closure integer-token, schema-reference token,
and schema-definition name. Their historical V40 evidence records are
byte-pinned; any seventh or broader rewrite is rejected.

The complete fast tier passed 702 tests across 59 isolated modules in 1047.482
seconds. Its embedded release-readiness module passed 76 tests in 979.931
seconds. Dedicated tests passed normally and under optimized Python. Normal
and optimized checker outputs were byte-identical with current-tree SHA-256
`e07a714953b6234800638fc8ae1b38437b6da912b085422a54340bd5f9602c82`;
both exited 1, retained the same four blockers, and wrote no release artifacts.
Before governance publication, 551 governed records and published history
validated.

Independent bounded Skeptic review returned `PASS` with no mandatory fixes
after reproducing dedicated and related tests, schema/instance validation,
checker parity, exact-six evidence-only rebase, default-site exclusion, and
absence of runtime or authority expansion. This is engineering review, not
trusted formal acceptance. `STOP-M0-3A-002` remains OPEN, live capital remains
LOCKED with USD 0 deployable, `live_enabled` remains false, and the kill switch
remains ENGAGED.
