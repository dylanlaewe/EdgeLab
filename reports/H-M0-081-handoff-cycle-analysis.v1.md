# H-M0-081 legacy handoff cycle analysis — v1

## Scope and reproduction

This report is structural governance evidence only. It does not alter or approve
H-M0-080, release Data, clear either STOP, or authorize execution.

The synchronized pre-change repository was
`d19020b37b80bc85915a39166980fbbaad7daaa3`. At the real host time
`2026-10-13T17:24:03Z`, this command reproduced the production failure:

```text
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m src.edgelab.validate
ValueError: Dependency cycle: H-M0-074
```

The reported node depends on deterministic traversal order. The same aggregate
legacy-ID graph had previously reported `Dependency cycle: H-M0-041`.
Strongly-connected-component analysis found these 29 IDs:

```text
H-M0-041 H-M0-050 H-M0-051 H-M0-052 H-M0-053 H-M0-054
H-M0-055 H-M0-056 H-M0-057 H-M0-058 H-M0-059 H-M0-060
H-M0-061 H-M0-062 H-M0-063 H-M0-064 H-M0-065 H-M0-066
H-M0-067 H-M0-068 H-M0-069 H-M0-070 H-M0-072 H-M0-073
H-M0-074 H-M0-075 H-M0-076 H-M0-077 H-M0-078
```

There are six simple return paths from H-M0-041. They are the combinations of:

- entry `H-M0-041 -> H-M0-074`, or
  `H-M0-041 -> H-M0-078 -> H-M0-077 -> H-M0-076 ->`
  either `H-M0-074` or `H-M0-075 -> H-M0-074`;
- the common chain `H-M0-074 -> H-M0-073 -> H-M0-072 -> H-M0-070
  -> H-M0-069 -> H-M0-068 -> H-M0-067 -> H-M0-066 -> H-M0-065
  -> H-M0-064 -> H-M0-063 -> H-M0-062 -> H-M0-061 -> H-M0-060
  -> H-M0-059 -> H-M0-058 -> H-M0-057 -> H-M0-056 -> H-M0-055
  -> H-M0-054 -> H-M0-053 -> H-M0-052`;
- exit `H-M0-052 -> H-M0-050 -> H-M0-041`, or
  `H-M0-052 -> H-M0-051 -> H-M0-050 -> H-M0-041`.

The component also contains the shorter current-ID loop
`H-M0-074 -> H-M0-075 -> H-M0-074`. That is a separate current-head failure,
not the stale edge that returns the long component to H-M0-041.

## Exact edge inventory and meaning

Every row below is the literal `depends_on` edge contributed by the listed
immutable record(s). Each SHA is the commit that first added that record.
“Execution” means an implementation/revision/review needs the prior work product.
“Review” means a revision waits for an independent review disposition. No
cross-ID edge is a supersession edge; supersession occurs through the increasing
versions of the same handoff ID. “Provenance” is context, not prerequisite
completion.

| Edge | Exact source records and introducing SHAs | Meaning |
|---|---|---|
| H-M0-041 -> H-M0-074 | `H-M0-041.v22` @ `06630cf94567ee1ae0ac34caa04de2aa030f8da9` | Execution prerequisite for blocked future Data work. |
| H-M0-041 -> H-M0-078 | `H-M0-041.v23` @ `235c69e2e427ccb1883159a5bfe2913c0e62105b` | Execution prerequisite for blocked future Data work. |
| H-M0-050 -> H-M0-041 | `H-M0-050.v1` @ `9fd115c4bb0e73142292f6bcff227004627912d6` | **Provenance/reference misencoded as a prerequisite.** It cites blocked `H-M0-041.v8`; `H-M0-050.v2` removes this edge and retains later H-M0-041 state only in `evidence_refs`. |
| H-M0-051 -> H-M0-050 | `v1` @ `612d4cf50336ec6e52653825acb6c9e20242e694`; `v2` @ `1e32effa5a5b8b77edb3bf6372902f6db6b707ab`; `v3` @ `320d9372e252de34452e2bf2a8560ea13b749db1` | Execution prerequisite: review consumes H-M0-050 work. |
| H-M0-052 -> H-M0-050 | `v1` @ `179b8099a28ea7b9210d14392ed48b65c6a4e0c9` | Execution prerequisite for the first revision claim. |
| H-M0-052 -> H-M0-051 | `v2` @ `6aaec7f1e0294b6af6379c38017bca0536c34ea2` | Review prerequisite for completed revision. |
| H-M0-053 -> H-M0-052 | `v1` @ `6aaec7f1e0294b6af6379c38017bca0536c34ea2`; `v2` @ `02fe6215341ab2c3cb9417146a91b5d612fbb7f9`; `v3` @ `18eb2c2ca27f27f309635697cdcb0b841b38c7a2` | Execution prerequisite: review consumes H-M0-052. |
| H-M0-054 -> H-M0-053 | `v1` @ `5e95b9440a1bb64fb03af5b3eda78eb25718d74e`; `v2` @ `20c2e9d831687c2fdd9663ce5d636f92f5535d6c` | Review prerequisite for revision. |
| H-M0-055 -> H-M0-054 | `v1` @ `20c2e9d831687c2fdd9663ce5d636f92f5535d6c`; `v2` @ `9c1677ec59a0917a68da2cd50f12dab4e6e8bb80`; `v3` @ `45701beb091697ed205976be3b5a5a9fba91a257` | Execution prerequisite: review consumes H-M0-054. |
| H-M0-056 -> H-M0-055 | `v1` @ `63f787ba41031fb456eae97404b3ab52a2d644ec`; `v2` @ `6345d628fae552c7947599fdf83a8b63f6d55dea` | Review prerequisite for revision. |
| H-M0-057 -> H-M0-056 | `v1` @ `6345d628fae552c7947599fdf83a8b63f6d55dea`; `v2` @ `8a2a1a30a2e4d4352e0397d0b871696867cebc44`; `v3` @ `c653c2613f6a9e2c51ae8669584e34e91479dacd` | Execution prerequisite: review consumes H-M0-056. |
| H-M0-058 -> H-M0-057 | `v1` @ `fc00c4961ceba7d37c7d2efe581c020655689ba3`; `v2` @ `4e99846997e15c63876828c0fb3d9a07c6d898a8` | Review prerequisite for revision. |
| H-M0-059 -> H-M0-058 | `v1` @ `4e99846997e15c63876828c0fb3d9a07c6d898a8`; `v2` @ `22eef8794125905ed47f8e9222c2a45ef90e6ec0`; `v3` @ `027a87d32f3a7543a1c8a43b5b79965154a698b8` | Execution prerequisite: review consumes H-M0-058. |
| H-M0-060 -> H-M0-059 | `v1` @ `76e3c4af511f7df0426d77611ce59c7ed3917859`; `v2` @ `2bfa299c208fe19c5a670e7a8720e9596c98b26e` | Review prerequisite for revision. |
| H-M0-061 -> H-M0-060 | `v1` @ `2bfa299c208fe19c5a670e7a8720e9596c98b26e`; `v2` @ `bd5948a5bfc636cff4d8a141a51b785637db61d3`; `v3` @ `bcfa2fa62fc728e6def6ec25f766cf2a145b98a1` | Execution prerequisite: review consumes H-M0-060. |
| H-M0-062 -> H-M0-061 | `v1` @ `eef5aebb737bda08ba9f9a2753df1aabd917b7e5`; `v2` @ `d54dee2b9de990cc9fb5362aa8457392a592844b` | Review prerequisite for revision. |
| H-M0-063 -> H-M0-062 | `v1` @ `d54dee2b9de990cc9fb5362aa8457392a592844b`; `v2` @ `5f4e3fc72e988cfedbf0de10a201b05ac63b0938`; `v3` @ `bf2f2dbe070fb10e51074015b03c7039f51436b9` | Execution prerequisite: review consumes H-M0-062. |
| H-M0-064 -> H-M0-063 | `v1` @ `e2e59947046a69a4d6f3356174532b2126282443`; `v2` @ `a4d4560f49d97680f6f9582857bfb4d87ccccb90` | Review prerequisite for revision. |
| H-M0-065 -> H-M0-064 | `v1` @ `a4d4560f49d97680f6f9582857bfb4d87ccccb90`; `v2` @ `f5ae4e870a70da031ae4f1c3ac0de52cb72903dc`; `v3` @ `1b8dbf27e3613f887190ee5bae8338085735ce7b` | Execution prerequisite: review consumes H-M0-064. |
| H-M0-066 -> H-M0-065 | `v1` @ `2eec1d5af55d22a7dba952e0720b9ba34cb504ec`; `v2` @ `987ecaddcce89cd35179a74310c2ad0bc4011920` | Review prerequisite for revision. |
| H-M0-067 -> H-M0-066 | `v1` @ `987ecaddcce89cd35179a74310c2ad0bc4011920`; `v2` @ `3ef37c6cbf3269cc23d5850cb76b22c0346db946`; `v3` @ `17a7da165d25e999b38b185424d5d3809063a756` | Execution prerequisite: review consumes H-M0-066. |
| H-M0-068 -> H-M0-067 | `v1` @ `311efcc30c81711d8e50f50d98ffd06f9a1172de`; `v2` @ `b4203351f930c26d63f1fdb7d713c97ae5b9a979` | Review prerequisite for revision. |
| H-M0-069 -> H-M0-068 | `v1` @ `b4203351f930c26d63f1fdb7d713c97ae5b9a979`; `v2` @ `8297e3f3b48f882f774e7a3e4d2a82ee67785001`; `v3` @ `e8e72ef07810bf2665e169e813aa3ef37f6de663` | Execution prerequisite: review consumes H-M0-068. |
| H-M0-070 -> H-M0-069 | `v1` @ `1268cf52f7f7d066b70f8c49b8cd4bdc612f621e`; `v2` @ `b86b963caaab2a7d96bfa349635c07ab78c35781` | Review prerequisite for revision. |
| H-M0-072 -> H-M0-070 | `v1` @ `be9fd915ca710c4d0dc4be86ce7cdfc14c304037`; `v2` @ `2a7122d8e94611710861e223dccdffe833389db8` | Execution prerequisite for golden evidence work. |
| H-M0-073 -> H-M0-072 | `v1` @ `2a7122d8e94611710861e223dccdffe833389db8`; `v2` @ `6ca8b56ea61324f4a0c31584fb9f170204a1a026`; `v3` @ `c9779e66d4116ac2c5c6e137917dc68e9ce431a5` | Execution prerequisite: review consumes H-M0-072. |
| H-M0-074 -> H-M0-073 | `v1` @ `41fb0d966a58a3b67589d9a0d6edc89457c276c5` | Review prerequisite for post-review revision. |
| H-M0-074 -> H-M0-075 | `v2` @ `c459371e866c936c105a8f875e1369d4e19d5d50`; `v3` @ `06630cf94567ee1ae0ac34caa04de2aa030f8da9` | Review prerequisite for repair and completion. |
| H-M0-075 -> H-M0-074 | `v1` @ `670b1df2e7b8f59a739dc4c15bf21c6c2868b966`; `v2` @ `4183c585907d7d8394296a0f84bb24c5d1b9bde6`; `v3` @ `3647a156d95a184ff120b9a256f847f13475a66d` | Execution prerequisite: review consumes the earlier H-M0-074 work. At current-ID heads this conflicts with the preceding edge and remains a separate validator failure. |
| H-M0-076 -> H-M0-074 | `v1` @ `06630cf94567ee1ae0ac34caa04de2aa030f8da9`; `v2` @ `f37b65a664ffc7fce203c7b87042cb8b637f3bb4`; `v3` @ `19fe3a43e1f6f992242384f9f067ad9b2fb983a9` | Execution prerequisite: re-review consumes repaired work. |
| H-M0-076 -> H-M0-075 | same `v1`, `v2`, `v3` and SHAs as preceding row | Review prerequisite: re-review also consumes the earlier review. |
| H-M0-077 -> H-M0-076 | `v1` @ `b38269e9377400997079093f0fb8cd70debc5fe0` | Review prerequisite for the next implementation claim. |
| H-M0-078 -> H-M0-077 | `v1` @ `a7e3afb0a345d74e43d8d323bc2cefdcceb0d87a` | Execution prerequisite for subsequent planning work. |

## Why the correction is permitted

The repository already defines a handoff as a versioned record: claim and
completion create versions (`docs/SPECIFICATIONS.md`), sessions must read the
latest versioned handoffs (`docs/GIT_COORDINATION.md`), and operational handoff
selection rejects any exact handoff with a newer version
(`src/edgelab/orchestration.py::_current_handoff`). Thus the legacy assignment
graph's authoritative state is the highest version for each handoff ID.

The pre-change validator instead unioned `depends_on` from every historical
version. That made a dependency removed by an audited successor remain active
forever. The concrete return edge demonstrates the error:

- `H-M0-050.v1` was a CLAIMED blocker-remediation plan. Its H-M0-041 reference
  was context for why the plan existed, not evidence that blocked H-M0-041 had
  completed as a prerequisite.
- `H-M0-050.v2` is the current COMPLETED record and removes H-M0-041 from
  `depends_on`. It preserves H-M0-041 context through exact `evidence_refs`.

The repair changes only cycle evaluation to use each handoff ID's highest
version. Every historical version remains present and still receives schema,
filename, version-gap, evidence-reference, and orphan-dependency validation.
Current-head cycles are still passed unchanged to the same `acyclic` function.
This neither relabels nor removes any genuine current prerequisite.

## Changed validation outcome

At the real host time `2026-10-13T17:27:45Z`, production validation advanced
past the H-M0-041 return paths and then failed separately:

```text
ValueError: Dependency cycle: H-M0-075
```

The remaining current-head graph contains
`H-M0-074.v3 depends_on H-M0-075` and
`H-M0-075.v3 depends_on H-M0-074`. Both describe genuine review/work ordering
at their respective historical phases. Resolving their current-ID semantics is
outside H-M0-081 and requires a separate policy/record correction; it is not
silently waived here.

H-M0-080 also has historical self-ID `depends_on` entries in v3/v4 that express
same-ID version continuation. They were not reached because the independent
H-M0-074/H-M0-075 current-head cycle fails first. H-M0-081 does not reopen or
alter H-M0-080 evidence.
