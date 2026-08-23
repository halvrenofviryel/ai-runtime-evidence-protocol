# Authoring mandate — Python class verifier (process record)

> Recorded from the instruction given to the isolated agent that wrote
> `class_verifier.py`. Evidence of the mandate given; it makes no stronger claim.

**Base commit:** `8d9f01fca6e6910188bc78f490c1d3a668df194a` (C0-FINAL). This branch descends
directly from C0-FINAL and does **not** have the Node verifier's commit as an ancestor.

**Authoring environment:** a sanitized snapshot with **no git metadata**, containing only:
`spec/INTEGRITY.md` (frozen), `spec/CONFORMANCE_CLASS_DESIGN.md`,
`spec/CLASS_VERIFIER_CONTRACT.md` **with §7 physically removed**, `spec/schemas/*.schema.json`,
`corpus/case_index.json`, `corpus/cases/<ID>/{request,bindings?,independence?,revocation?,clock?}.json`,
and `jcs.py`. Snapshot digest (per-file hashes recorded separately):
`567d27460db3a2d8fc28345624e97290f6973abb5629e9e7f064d9993048a4e6`, 229 files.

**Physically absent from the authoring environment:** every `expected.json`,
`build_class_corpus.py`, `KEYS.md`, `corpus_manifest.json`, the contract's §7 expected
appendix, the Node verifier, and any prior verifier's debug/evidence material.

**Prohibitions given:** no access to any path outside the working directory — explicitly
including the source repository `/mnt/data/claude/ai-runtime-evidence-protocol`; no attempt to
obtain, reconstruct or infer expected verdicts from any source; no search for another
verifier; no commits.

**Build obligations:** implement contract §§0–6 — single-case CLI with the pinned exit codes
(0/1/2, `--help` = 0) plus a batch mode over the corpus writing `{"verdicts": [...]}` in the
§2 envelope, ordered by `(chain_id, record_id)` under unsigned UTF-8 byte order; stage order
and reason-dependency DAG; closed reason registry with correct tier/kind; three-condition
independence; observer path authenticating the referenced Execution artifact in its own right;
`abs(now − witnessed_at) <= window` with boundary-equal fresh; evidence digests of operator
input file bytes; §2 consistency invariants. Verify determinism without expected values, and
report no pass rate.

**Disclosed deviation (author-reported, recorded verbatim):** the author wrote three throwaway
mutated-request files to `/tmp/t.json`, `/tmp/t2.json`, `/tmp/x.json` for negative-construction
tests and ran `date -u -d @…` to cross-check civil-date arithmetic. Neither is a repository or
spec source. The author attests it never touched
`/mnt/data/claude/ai-runtime-evidence-protocol`, never searched for another verifier, and never
sought or reconstructed expected outcomes.

**Evidence-boundary note:** the snapshot's *contents* are physically sanitized and that is
machine-checked. Non-access to the wider filesystem rests on the mandate plus the author's
attestation — this environment has no sandbox enforcement, and the claim is stated at exactly
that strength.
