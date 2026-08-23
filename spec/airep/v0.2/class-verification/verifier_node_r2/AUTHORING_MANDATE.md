# Authoring mandate — Node class verifier R2 (process record)

> Recorded from the instruction given to the isolated agent that wrote `class_verifier.mjs`.
> R2 is the **clean re-authoring** ordered after the disclosed provenance incident on the
> superseded R1 artifact. Evidence of the mandate given; it makes no stronger claim.

**Base commit:** `8d9f01fca6e6910188bc78f490c1d3a668df194a` (C0-FINAL). This branch descends
directly from C0-FINAL. Neither the Python verifier commit nor the R1 Node commit is an
ancestor (machine-verified with `git merge-base --is-ancestor`).

**Authoring environment:** `/tmp/airep_r2_env/work/node` — a fresh root tree created for this
task alone. Its parent (`work/`) contains only `node/`, and its grandparent
(`airep_r2_env/`) contains only `work/`: a directory listing at any level above the working
directory reveals nothing but the snapshot itself. This directly addresses the R1 incident,
where a listing of a shared scratch directory exposed unrelated filenames and sizes.

**Snapshot contents (byte-identical to the R1 normative snapshot, digest
`a7ebc1a5699142b3cceaa8c70b0769b9a7d6eb724589890662639a7a4d07be82`, 229 files):**
`spec/INTEGRITY.md` (frozen), `spec/CONFORMANCE_CLASS_DESIGN.md`,
`spec/CLASS_VERIFIER_CONTRACT.md` **with §7 physically removed**, `spec/schemas/*.schema.json`,
`corpus/case_index.json`, `corpus/cases/<ID>/{request,bindings?,independence?,revocation?,clock?}.json`,
`v01_verify_reference.mjs` (JCS logic only).

**Physically absent:** every `expected.json`, `build_class_corpus.py`, `KEYS.md`,
`corpus_manifest.json`, the contract's §7 expected appendix, the Python verifier, the R1
verifier, and any prior verifier's output or evidence material (machine-asserted at snapshot
build time).

**Information quarantine (maintainer-ordered):** the R2 author was told nothing about the R1
incident, nothing about any other implementation's output digest, file size, or determinism
result, and nothing about the semantic ambiguities the earlier authors reported. It derived
everything from the frozen §§0–6 alone.

**Prohibitions given:** no read, list, glob, grep, `cd`, or write outside the working
directory — including scratch files, which had to stay inside it; `/mnt/data/claude/ai-runtime-evidence-protocol`
(the source repository) and `/tmp/claude-1000` (the session scratch area) named explicitly,
directory listings included; no attempt to obtain, reconstruct or infer expected verdicts; no
search for another verifier; no commits.

**Build obligations:** contract §§0–6 — single-case CLI with the pinned exit codes plus batch
mode writing the §2 envelope ordered by unsigned UTF-8 byte order (explicitly not JavaScript's
UTF-16 default); stage order and reason-dependency DAG; closed registry with correct
tier/kind; three-condition independence; observer path authenticating the referenced Execution
artifact in its own right; `abs(now − witnessed_at) <= window` boundary-equal fresh with
proleptic-Gregorian integer arithmetic (not `Date.UTC`); evidence digests of operator input
file bytes; §2 consistency invariants. Determinism verified without expected values; no pass
rate reported.

**Author-reported deviations / filesystem accesses:** none. The author attests all reads and
writes stayed inside `/tmp/airep_r2_env/work/node` (`spec/`, `corpus/`,
`v01_verify_reference.mjs`, files it created, and `npm install`'s `node_modules/`,
`package.json`, `package-lock.json`), and that it never touched the repository, the session
scratch area, or any other location, and looked for no other verifier or expected-value
source. Contrast with R1, whose deviation is recorded in `../verifier_node/AUTHORING_MANDATE.md`.

**Dependency:** `ajv@8.20.0` (exact, with `package-lock.json`), Node v20.19.6, used only for
2020-12 schema validation.

## Claim strength (maintainer-pinned wording)

Independence for this artifact is claimed at exactly this level and no higher:
**sanitized filesystem surface + explicit path prohibitions + author attestation + clean commit
ancestry.** No sandbox-enforcement claim is made — this environment has no disposable
container or filesystem namespace, and that limitation is part of the record.
