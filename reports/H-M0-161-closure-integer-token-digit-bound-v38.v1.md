# H-M0-161 — Closure integer-token digit bound V38

Engineering commit `4182e37` advances the deny-only runtime-v2 semantic
classification from V37 to V38 without changing Discovery V7. Independent
inventory considered a three-subject diagnostic family, but the bounded
Skeptic selected the smaller and safer complete unit: the dependency-closure
JSON integer-token lexical digit ceiling.

V38 adds exactly one constraint, `CLOSURE_INTEGER_TOKEN_MAX_DIGITS`. It binds
the exact leading-minus removal site
`7b99b5408a023f557be70736b52ecf6a8de4d8594b0da6318cacb3c9680cf5fc`
and enforcement site
`90292d8f8df61b2ee109adf7df0d0d4e44c2cdf5a6f70c887e7e5228d4cb8657`.
The subject is decimal digits in a dependency-closure JSON integer token after
excluding one leading ASCII `-`. Nineteen or fewer characters proceed to
integer conversion; more than nineteen characters raise
`INTEGER_TOKEN_TOO_LONG` before conversion.

This rule is not signed-int64 validation. Some admitted nineteen-digit values
exceed int64. It does not establish field ranges, leading-zero policy,
negative-zero policy, float handling, general canonical JSON validity,
dependency closure correctness, or any authority.

Classification V38 contains 34 constraints and 66 unique classified sites.
Discovery remains 425 source sites plus 296 schema sites, 721 total; 655 sites
remain unclassified. Coverage remains `INCOMPLETE`, authorizing use remains
`DENY`, and the same four unconditional blockers remain.

The V38 manifest raw SHA-256 is
`29b54d7658ba6fd61607f097c0a344106ff10a249136570566e848f1f3683eda`;
its domain-separated self-digest is
`868b3408ba5b1839535dfdc87f0d6f38586f613fd918f68724f1ae4923cfbe2d`;
and its schema raw SHA-256 is
`8877f740ffa9d71c3786dec01568d31f3104ab356da4aea6a541806bdc84989d`.

V38 preserves all V37 semantic fields and site sets. Exactly three historical
constraints receive enumerated evidence-only refreshes because their tests
assert the current classification census: the top-level events constraint and
the two finding-string constraints. Their historical V37 evidence records are
byte-pinned, every non-evidence field is compared exactly, and any fourth or
broader predecessor rewrite is rejected.

Adversarial evidence covers positive and negative one-, eighteen-, nineteen-,
and twenty-digit tokens; exclusion of exactly one leading minus; rejection
before integer conversion; comparator, literal, reversed-comparison, slice,
`lstrip`, absolute-value, sign-counting, and `parse_int` caller attacks; exact
parser/caller/module ASTs; duplicate or substituted sites; refreshed census;
and predecessor/ancestor history.

The complete fast tier passed 676 tests across 56 isolated modules in 953.686
seconds. Its embedded release-readiness module passed 73 tests in 886.878
seconds. Dedicated tests passed normally and under optimized Python. Normal
and optimized checker outputs were byte-identical with current-tree SHA-256
`0903836ee469e18b7e3a9ea70256df6f1921b674ac89ba31a712de4eba14ccf2`;
both exited 1, retained the same four blockers, and wrote no release artifacts.
Before governance publication, 542 governed records and published history
validated.

Fresh bounded Skeptic review returned `ACCEPT WITH EVIDENCE CORRECTION`; the
corrected current-tree checker digest above replaces an earlier pre-final-test
digest and is the only required bookkeeping correction. No runtime source
changed. No scientific, public-verifier, STOP, execution, wagering, or capital
authority expanded. `STOP-M0-3A-002` remains OPEN, live capital remains LOCKED
with USD 0 deployable, `live_enabled` remains false, and the kill switch
remains ENGAGED.
