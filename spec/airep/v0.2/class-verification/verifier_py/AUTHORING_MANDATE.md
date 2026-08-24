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

---

# Remediation round 2 (§9 rulings)

> Second, small remediation on my own prior work, following the maintainer's
> `CLASS_VERIFIER_CONTRACT.md` §9 rulings R-1..R-6 (2026-08-24). Scope as
> instructed: fix the stage-6 precedence, verify and probe R-3 and R-4, add
> regression probes, re-run the corpus. No other semantic change.

## Files changed

| File | Change |
|---|---|
| `class_verifier.py` | two hunks — R-2 stage-6 precedence, R-3 binding precedence |
| `selfcheck_s9_round2.py` | **new** sibling probe script (47 assertions + 4 observations) |
| `AUTHORING_MANDATE.md` | this section |

Nothing else was touched. No frozen input was modified.

## R-2 — stage-6 precedence (the one instructed behavioural change)

**BEFORE** (`class_verifier.py` lines 793–825 of the pre-round file): stage 6 ran
the claim-shape gate and the `witnessed_at` gate as *independent, parallel* checks,
and gated resolution/reconciliation on **both**:

```
6a  claim_structurally_valid(...)          -> emit witness-claim-invalid   (no short-circuit)
6b  claim_time_structurally_valid(...)     -> emit witness-time-invalid    (ran ALONGSIDE 6a;
                                              the comment said so explicitly:
                                              "reported alongside 6a rather than suppressed by it")
6c  if claim_ok and time_ok:  resolution -> must-be-primary -> reconciliation
```

Three deviations from R-2:
1. the time gate was **not** suppressed by a failing shape gate, so shape and time
   could both report — exactly what R-2 forbids;
2. the time gate ran **before** resolution/reconciliation rather than after;
3. resolution/reconciliation was gated on `time_ok`, so an invalid timestamp
   suppressed the head reasons instead of the other way round.

**AFTER** (lines 799–831 of the current file), one gate with three dependent
sub-steps, matching R-2 verbatim:

```
6a  claim_structurally_valid(...)   -> witness-claim-invalid ALONE; 6b/6c do not run
    else:
6b  resolve_reference -> must-be-primary -> reconcile (chain_id, sequence, current)
                                    -> witness-head-unresolved | witness-head-mismatch
                                       ALONE; 6c does not run
6c  elif not claim_time_structurally_valid(claim): -> witness-time-invalid
    else: stage6_clean = True
```

6c reads no clock input (its only argument is the claim), so R-2's
"clock inputs play no part in this check" holds structurally, not just by
convention. 6a already type-checks `witnessed_at` as a string, so 6c's former
`isinstance` guard was redundant once 6c moved behind 6a.

## R-3 — binding precedence: my source did **NOT** comply. Second finding, fixed.

**Evidence of non-compliance (measured before the fix).** `lookup_binding` placed
the trust test *first*:

```
line 331 (BEFORE): # Contract 1.1 priority order: not-trusted (definitive negative) before
                   # the structural malformed bucket, then the suite registry.
                   if "trusted" in entry and entry["trusted"] is not True:
                       return binding_id, entry, "binding-not-trusted"
```

The two cases R-3 states *literally* already passed — an unknown member is caught
document-wide by `_binding_maps` (E-4) before `lookup_binding`'s trust test, and a
clean entry with `trusted: false` yields not-trusted. But R-3's **general** rule
("`*-binding-not-trusted` applies only when the input is structurally valid") was
violated for member-closed entries whose *field values* are ill-formed. Six probes
failed on the unfixed source, for both roles:

```
[FAIL] R-3 producer malformed public_key_hex + trusted:false -> producer-binding-malformed ONLY
       observed: authenticated_failures = ['producer-binding-not-trusted']
[FAIL] R-3 producer wrong role + trusted:false                -> ... observed not-trusted
[FAIL] R-3 producer non-namespaced subject_identity + trusted:false -> ... observed not-trusted
[FAIL] R-3 witness  malformed public_key_hex + trusted:false  -> observed witness-binding-not-trusted
[FAIL] R-3 witness  wrong role + trusted:false                -> observed witness-binding-not-trusted
[FAIL] R-3 witness  non-namespaced subject_identity + trusted:false -> observed witness-binding-not-trusted
```

§1.1 puts "malformed key" and "wrong `role`" in the `*-binding-malformed` bucket,
so under R-3 these must report malformed, not the trust negative.

**Fix (minimal).** The trust test was moved *below* every `binding-malformed` test
and *above* the suite-registry test — a relocation of the same three-line
condition, no new logic. Current lines 331–357. Suite ordering was deliberately
left unchanged: R-3 rules on structure vs trust and says nothing about the
registry, so `not-trusted` still precedes `suite-unsupported` as before.

## R-4 — nested closure: my source **already complied**. No fix needed.

Confirmed by measurement (21 probes, all passing on the unfixed source, i.e.
independent of both edits in this round):

- unknown member in `head_witness.head_ref` or `head_witness.signature` ⇒ exit 1,
  no verdict (`parse_request`, closure tests on those two objects only);
- the claim is **not** part of harness closure — `parse_request` performs no
  member-closure and no member-type test on `claim`; an **extra** member, each of
  the five **missing** members, and each of five **wrong-typed** members all reach
  stage 6 and produce `witness-claim-invalid` at exit 0 (11 probes);
- no new requiredness inside `head_ref`: `record_id` absent, wrong-typed, or
  unmatched all yield `witness-head-unresolved` at exit 0;
- no new requiredness inside `signature`: `value` absent, wrong-typed, or
  cryptographically invalid all yield `witness-signature-invalid` at exit 0;
- `signature.alg` is informative-only: removing it, and setting it to another
  suite id, both leave the verdict `AIREP-Witnessed` with all five channels empty.
  The witness preimage takes its suite id from the accepted binding
  (`witness_sig_preimage(head_artifact["airep_version"], w_entry["suite"], claim)`),
  never from the wire, and no witness-side `wire-alg-mismatch` caveat exists.

## Probes added

`selfcheck_s9_round2.py` — a sibling script, run as a subprocess against the CLI,
every fixture constructed in-file by mutating a corpus input **in memory**. Nothing
is written into `corpus/`; no `expected.json` is read anywhere. It resolves the
corpus and schemas in the committed layout (`../corpus`, `../../schemas`).

| Group | Assertions | Content |
|---|---:|---|
| control | 1 | unmutated P2 ⇒ `AIREP-Witnessed`, five empty channels |
| R-2 | 9 | 6a-beats-6c (×2), 6b-beats-6c (unresolved + mismatch), 6a-beats-6b, a **discrimination proof** that 6c is not dead code, clock-independence of 6c, stage-6 failure suppressing all stage 7–10 reasons, and 6c-clean still reaching stages 7–10 |
| R-3 | 16 | per role: clean+`false`⇒not-trusted only; unknown member+`false`⇒malformed only; missing container+`false`⇒malformed only; three ill-formed-field+`false`⇒malformed only; `trusted` absent⇒malformed; `trusted:"true"`⇒not-trusted |
| R-4 | 21 | nested closure ×2; claim extra/missing×5/wrong-typed×5 never run-invalid; `head_ref.record_id` ×3; `signature.value` ×3; `signature.alg` ×2 |
| observations | 4 | whole-`head_witness`-member-absent behaviour, printed but **not asserted** (see FINDING 1) |

The R-2 group is built so it cannot pass vacuously: each precedence probe pairs
two defects that *both* fire on their own, and the accompanying discrimination
probe shows the suppressed sub-step really does report when it is reached.

**Result — final run:** 47 assertions, 47 `ok`, 0 `FAIL`, exit 0.
**Result — before the R-3 fix:** 41 `ok`, 6 `FAIL` (the R-3 rows quoted above);
the R-2 and R-4 groups already passed at that point.

## Corpus re-run

```
python3 class_verifier.py --corpus corpus --out <tmp>/out.json      -> exit 0
45 verdicts emitted, 45 cases; MATCH 45, MISMATCH 0
```

compared field-by-field against every `corpus/cases/<ID>/expected.json` on
`class`, all five reason channels and `observer_assessment`. The results file is
**byte-identical** to the pre-round run (`diff` clean), which is the strongest
available statement that neither R-2 nor R-3 changed any §7 expected value — as
§9 states they should not.

## FINDINGS (observed, deliberately not fixed in this round)

1. **Whole `head_witness` member absent is run-invalid — unruled.** `parse_request`
   requires all four of `head_ref`, `witness_id`, `claim`, `signature`; removing any
   one gives exit 1 with no verdict. R-1 rules on *claim members* and R-4 rules that
   no new requiredness is created *inside* `head_ref`/`signature`; neither states
   what an entirely absent member does. A strict reading of R-1 ("missing claim
   members are never run-invalid") would make an absent `claim` object
   `witness-claim-invalid` instead. This round has no authority to change it, so the
   behaviour is printed as an observation rather than asserted. **Maintainer ruling
   requested.**

2. **Snapshot packaging gap: `jcs` is absent.** `class_verifier.py` imports `jcs`,
   the authoring snapshot carried a `jcs.py`, and this snapshot contains neither it
   nor any vendored copy — so the verifier cannot execute from the snapshot as
   delivered. To satisfy the corpus obligation I fetched the PyPI `jcs` 0.2.1 wheel
   (`jcs.canonicalize(obj) -> bytes`, RFC 8785) into a scratch directory outside the
   spec tree and ran with `PYTHONPATH` pointing at it; the scratch directory was
   deleted afterwards. This was network access, disclosed here at full strength, and
   it is the only external fetch of the round. Every measurement in this section was
   produced under that arrangement. The alternative — hand-writing a JCS
   canonicalizer — would have substituted an unverified construction for a frozen
   one, which is worse.

3. **`selfcheck_errata.py` does not run in the committed layout.** It resolves
   `HERE/corpus/cases` and `HERE/spec/schemas` (the authoring-snapshot layout) and
   copies a sibling `jcs.py`; in the committed layout those are `../corpus/cases`,
   `../../schemas`, and there is no `jcs.py`. It was therefore not re-run this round.
   The new script uses the committed layout. Repairing the old script is a packaging
   change outside this round's scope. **Not fixed.**

4. **Stale §9 vocabulary in comments.** `class_verifier.py`'s module docstring and
   several comments cite the *withdrawn first draft's* errata ids ("E-1..E-6"). The
   normative §9 now numbers its rulings R-1..R-6, and E-4's `claim` clause is
   explicitly WITHDRAWN by R-1. The comments are stale references, not stale
   behaviour — the code matches §9 as measured above. Renumbering would be a
   file-wide cosmetic churn, which this round forbids. **Not fixed.**

5. **No §7 conflict found.** R-2 and R-3 are internally consistent with §7 as far as
   this corpus exercises them: no case expects `witness-time-invalid` at all
   (`grep` over all 45 `expected.json`: zero hits), and the byte-identical re-run
   confirms it. No ruling in §9 was found to conflict with §7 or with another ruling.

## Frozen-input integrity, machine-checked

Every one of the 265 files listed in `corpus_manifest.json` re-hashes to its
recorded SHA-256 (0 mismatches), and the manifest's own `aggregate_sha256`
recomputes to `55d43c5170641b185dc5c95a71e8e336c902d26c556e03a10e248864de2950a4`
under its stated aggregate rule -- so `corpus/` (all 45 `expected.json` included)
is byte-untouched. A filesystem scan of the whole work root shows exactly three
files modified in this round: `class_verifier.py`, `selfcheck_s9_round2.py` and
this file. This is a machine check of *contents*; the non-access attestation
below is a separate and weaker claim.

Determinism was re-checked: two consecutive corpus runs produce byte-identical
results files.

## Attestation

I did not leave `/tmp/wk_qa7/task` for any read, list, stat or glob of repository or
specification material. I did not seek, read, infer or reason about any other
implementation of this contract in any language. I did not run `git`. I did not
search the web; the single network action was the disclosed `pip download jcs`
recorded as FINDING 2. I did not write, run or design any cross-implementation
comparator, and produced no artifact intended for comparison. I modified no frozen
input: `CLASS_VERIFIER_CONTRACT.md`, `corpus/` (including every `expected.json`),
`corpus_manifest.json`, `build_class_corpus.py`, `KEYS.md`, `schemas/`,
`INTEGRITY.md` and `CONFORMANCE_CLASS_DESIGN.md` are untouched — the probe script
mutates corpus inputs only in memory and writes only into a temporary directory it
deletes. This attestation rests on my own record of my actions; the environment
enforces no sandbox, and the claim is stated at exactly that strength.
