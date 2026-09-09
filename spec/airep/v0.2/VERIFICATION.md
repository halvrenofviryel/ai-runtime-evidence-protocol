# Beta verifier and reconciliation interfaces

Use the [quickstart](QUICKSTART.md) for setup. From the repository root:

```bash
python3 -m tools.airep_v02 verify --request request.json \
  --bindings bindings.json --revocation revocation.json
node tools/airep_v02/verify_node.mjs --request request.json \
  --bindings bindings.json --revocation revocation.json
```

The request is the existing closed envelope:

```json
{"artifact": {}, "related_artifacts": []}
```

Replace the empty artifact with a real emitted record. `related_artifacts` is
optional. The optional `head_witness` envelope and signed claim follow the frozen
[r1 contract](class-verification/CLASS_VERIFIER_CONTRACT.md) incorporated by r3.
Both commands accept `--independence-policy`, `--now`, `--freshness-window`, and
`--profile-bases`. Numeric source spelling in witness claims is retained for
the frozen lexical checks. Informative wire `alg` never selects the key or suite.

The Python application also accepts `verify --input artifacts.json` for a
single artifact or array, supplying the others as related records automatically.
Its array result has `verdicts`, sorted by UTF-8 `(chain_id, record_id)`, and
rejects duplicate result identities or empty input before emitting any result.
`--out` on this application batch writes a new file and refuses to overwrite an
existing one. This convenience surface is separate from the historical
`class_verifier.py --corpus … --out …` measurement harness.

| Exit | Meaning |
|---|---|
| 0 | Evaluation completed; reasons and profile FAIL/NOT_EVALUATED still require inspection |
| 1 | Unparseable input, invalid primary artifact, unusable supplied profile basis or invalid run identity; no new result emitted |
| 2 | CLI usage or clock configuration error |

`--help` exits zero with help only. The reference application does not make exit
zero mean acceptance. Reconciliation emits structured negative findings rather
than aborting on each malformed but parseable artifact; unreadable raw run input
still exits one. Its library is `reconcile(list_of_artifacts, ops=…)` and its
schema is [RECONCILIATION.md](RECONCILIATION.md).

## Trusted operator inputs

Bindings, revocation and independence use the accepted contract formats, for
example the reproducible [demo policy builder](../../../examples/v02/run_lifecycle.py).
Every binding contains `subject_identity`, `role`, `public_key_hex`, `suite`,
`trusted`; the store contains `bindings`, `producer_bindings`, `witness_bindings`.
The verifier's operator chooses which bindings to accept. A producer cannot mint
trust by embedding those values in an artifact or profile.

Revocation is a current operator snapshot mapping binding IDs to `active` or
`revoked`. Independence has explicit `independent_pairs` and
`non_independent_pairs`. Each operator file's **exact byte digest** is retained
in `evidence`; bytes with different whitespace have different input identities.
An omitted input is distinguishable from supplied malformed or negative policy.

## Profile validation, r3

`--profile-bases registry.json` supplies:

```json
{"profiles":{"airep.test-profile":{"schema_path":"test-profile.schema.json","basis_digest":"sha256:…"}}}
```

Use the actual complete digest, not the ellipsis. The committed
[test-only basis](../../../examples/v02/profile-basis/) is a runnable example.
Its payload models no external standard. Registry membership does not require an
artifact to carry that profile and cannot apply one identifier's schema to another.

The registry is resolved to its real path; each basis must remain within its
resolved parent, including after symlink resolution. Duplicate members, digest
mismatch, escaping paths, invalid schemas, unresolved fragments, external
references, unsupported dialects and required custom vocabularies invalidate
the entire run. Every declared basis is checked before results are emitted.

The result always includes `profile_evaluations`. Present unknown profiles have
`NOT_EVALUATED`/null digest. Evaluated profiles have `PASS` or `FAIL` with the exact
basis digest. `evidence.profile_bases_digest` identifies the complete registry
snapshot, distinct from each individual basis. None of these changes a class.
`airep.key-trust` self-revocation can still produce an authenticated caveat even
when generic evaluation of that profile is NOT_EVALUATED.

**Editorial clarification of frozen r3 §R3.4.5:** the concluding sentence “None
of these is ever reported as PASS or FAIL” applies to its **rejected/unusable**
probes (3–7). Accepted no-ref and internal-ref bases (1–2) do evaluate payloads,
as required by R3.2/R3.5. The preserved contract is not edited or re-digested.

## Historical reproduction and beta evidence

The r1 Python and Node engines, fixed vectors, 117 schema fixtures, 60 class
cases, official failing/passing runs, and external evidence remain byte-pinned.
Their original commands retain their historical scope. Use the beta commands
above for AD-17 and r3; do not claim the old direct engine implements those
new surfaces. The beta Node adapter supplies an explicit resolved schema path,
including when the clone path contains spaces.

```bash
python3 -m unittest discover -s tests/v02 -v
python3 scripts/check_beta.py --out /tmp/airep-beta-checks
```

The complete checker copies the repository to a fresh temporary directory so
historical regeneration scripts cannot overwrite preserved measurements. It
runs original gates, imported W1 tests and the beta tests, recording every exact
command, working directory, exit code and complete output. A failed check stays
in the evidence output. Node is required; missing Node is never a silent skip.
The first-party beta adapters were developed together, so their parity is **not**
new independent-authoring or external-interoperability evidence.
