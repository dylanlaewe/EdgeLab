# H-M0-128 — Runtime-v2 resource binding census

Commit `5c680512d9a3fdb7275b5b70f6e09cfb161966c3` closes a discovery
ambiguity before any further semantic resource classification. The original
source census represented each of the `byte_fields` and `byte_collections`
loops with one generic comparator site even though their literal tables bind
different captured subjects to different named maxima. Discovery v2 preserves
all 394 v1 source records and adds seven branch-specific binding records. The
two generic comparator records remain present and unclassified.

The new records bind the exact table assignment, normalized row tuple, literal
branch key, matching `captured[...]` subject, named maximum, consuming loop,
generic predecessor comparator, row index, enclosing function, and source
path. The extractor rejects aliases, dynamic or starred rows, missing,
duplicate, added, reordered, or mismatched rows, maximum substitution, loop
target or iterable changes, comparator drift, and any assignment/loop AST
change. Diagnostic line numbers are excluded from census identity.

The closed discovery manifest records 401 source sites, 296 schema sites, and
697 total sites under source-census digest
`4a8707fd2ea6b1a398de1207a397f57c7dda9f368259dc58a10dc171352e0864`.
Its self-digest is
`c865ac494361d7ad310464efd19a0bf3d9c79ddfaa7d58e50a4ff9ef449c7725`.
The cumulative classification v5 is deliberately a census-only rebase: its
four constraints and ten classified site IDs are byte-for-byte equal to v4,
and all seven new bindings remain `UNCLASSIFIED`. Its self-digest is
`40d56d4ca27903dc0eab6efc9ea402901dcf5bd4a9dfec28784e17e9ea8606f8`.

Independent implementation-diff and Skeptic reviews returned ACCEPT after
checking exact bindings, same-valued substitutions, predecessor chains,
manifest identities, and authority boundaries. These are bounded engineering
reviews, not authenticated formal STOP-clearance authority.

Validation passed 79 focused readiness, closure, image, verifier,
schema-document, and schema-reference-node tests normally and under
`python -O`; 385 tests passed across the 24-module fast tier; and 443 governed
records validated before publication. The readiness CLI still exits `1` with
`BLOCKED / DENY`, writes no release artifact, and retains all four blockers.

Only ten of 697 census sites are semantically classified; 687 remain
unclassified and coverage remains `INCOMPLETE`. No resource maximum was newly
classified. No closure, carrier, public-verifier connection, STOP clearance,
writer, database, selector cutover, operational authority, or capital path was
added. Capital remains LOCKED with deployable USD 0 and the kill switch
ENGAGED.
