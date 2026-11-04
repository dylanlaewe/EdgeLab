# H-M0-162 — Verifier schema `$ref` token bound V39

Engineering commit `0bb5db2` advances the deny-only runtime-v2 semantic
classification from V38 to V39 without changing Discovery V7. Independent
inventory proposed an initial-reducer diagnostic bound, but the bounded
Skeptic selected the smaller existing-site verifier schema-reference token
ceiling.

V39 adds exactly one constraint,
`VERIFIER_SCHEMA_REF_TOKEN_CHARACTER_MAXIMUM`. It binds the exact
`child[8:]` subject-definition slice at
`6e95fce4ad2ed77d84d5bfaad79566cb4276adc28054fb8bde30b0bbb5c911c5`
and the exact `len(token) > 64` comparison at
`66956e9e92ceed3f5128e1dc746a920e18ce5b51eafd243c43d0500fb9917474`.
Only an exact string beginning with `#/$defs/` produces the sliced token;
otherwise the token is empty. A token of at most 64 Python characters avoids
this length diagnostic only; it is not sufficient for schema-reference
validity or resolution.

The rule does not claim target existence, graph safety, acyclicity,
completeness, schema acceptance, examination after the diagnostic budget is
full, a byte limit, ASCII validity, general identifier validity, parser
rejection, or any operational authority.

Classification V39 contains 35 constraints and 68 unique classified sites.
Discovery remains 425 source sites plus 296 schema sites, 721 total; 653 sites
remain unclassified. Coverage remains `INCOMPLETE`, authorizing use remains
`DENY`, and the same four unconditional blockers remain.

The V39 manifest raw SHA-256 is
`3486368af963e822b6789888b43cd54403433d062f2c1f433e310178b1d1b6cb`;
its domain-separated self-digest is
`667125ba3f0d85eb7729364699f89a74e3b7b079d31dc5da649a51e9058b3972`;
and its schema raw SHA-256 is
`c0a7561ce33a645004222cd4a1b3ca8a1b49d9e019ec904726ec894d64cc540b`.

V39 preserves every V38 semantic field and site set. Exactly four historical
constraints receive enumerated evidence-only refreshes because their tests
assert the current classification census: top-level events, both
finding-string constraints, and the closure integer-token constraint. Their
historical V38 evidence records are byte-pinned; any fifth or broader rewrite
is rejected.

Adversarial evidence covers valid existing definition tokens of lengths 1,
63, and 64; a 65-character diagnostic; exact prefix and eight-character
slice; slice, comparator, literal, reversed-comparison, type-gate,
`startswith`, condition-order, and diagnostic-code attacks; the diagnostic
budget short circuit; adjacent 64-character meanings; and complete
predecessor/ancestor/census history.

The complete fast tier passed 684 tests across 57 isolated modules in 985.109
seconds. Its embedded release-readiness module passed 74 tests in 918.546
seconds. Dedicated tests passed normally and under optimized Python. Normal
and optimized checker outputs were byte-identical with current-tree SHA-256
`679b8325f9073cafd23cbcdc9e8398747fb4523d4b5835b62fe15da9f824241a`;
both exited 1, retained the same four blockers, and wrote no release artifacts.
Before governance publication, 545 governed records and published history
validated.

Bounded Skeptic review returned `ACCEPT` after two audit corrections: the
current-tree checker digest above replaces a stale pre-final-test digest, and
the readiness document now separates artifact/coordinate composite semantics
from the closure integer-token slice/comparison semantics. No runtime source
changed. No scientific, public-verifier, STOP, release, execution, wagering,
or capital authority expanded. `STOP-M0-3A-002` remains OPEN, live capital
remains LOCKED with USD 0 deployable, `live_enabled` remains false, and the
kill switch remains ENGAGED.
