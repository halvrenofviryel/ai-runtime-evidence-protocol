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

# Remediation round 3 (R-7 + JCS packaging)

Third and final remediation round on my own prior work, under maintainer ruling
**R-7** and a packaging obligation. Two tasks only; nothing else was touched.

## Files changed

| File | Nature of change |
|---|---|
| `class_verifier.py` | R-7 semantics (3 sites) + repository JCS loader (1 site) |
| `selfcheck_s9_round3.py` | **new** — 63 asserted probes for every R-7 row, both named divergence risks, and the packaging obligation |
| `selfcheck_s9_round2.py` | comment/heading only: the round-2 "OPEN FINDING" block is relabelled as settled by R-7 and cross-referenced to round 3. No assertion added, removed or changed. |
| `selfcheck_errata.py` | path resolution only (see "Every self-check script, re-run" below). No assertion added, removed or changed. |

No frozen input was modified. No reason string, verdict envelope field, CLI
surface or exit-code mapping was changed.

## R-7 — what changed, with line references

R-7's governing distinction: **absence of a KNOWN evidence field fails or
withholds the tier evaluation; structure FOREIGN to the harness invalidates the
run.** My source treated all four `head_witness` members as harness-required and
exited 1 when any was absent. That is the behaviour R-7 overrules.

**1. `parse_request` — `class_verifier.py:652-672`.** The requiredness loop
(`for member in ("head_ref", "witness_id", "claim", "signature"): ... raise
RunInvalid`) is **deleted**. What replaces it:

- Absence is now tested by **membership** (`if "head_witness" in doc`, lines
  659-660), not by `doc.get(...) is None`. This is the decisive detail: the old
  `get`-based test collapsed an explicit `"head_witness": null` into the
  entirely-absent path and would have emitted `no-witness-supplied` where R-7
  requires run-invalid.
- `head_witness` present but null or any non-object ⇒ `RunInvalid` (661-662).
- An unknown member inside `head_witness` ⇒ `RunInvalid` (663-664) — envelope
  closure preserved, unchanged.
- R-4 closure on `head_ref` / `signature` is now applied **only when the member is
  present as an object** (669-672). R-4 creates no requiredness, so an absent or
  non-object value is a semantic defect for its own stage, never harness closure.
  A present *object* carrying an unknown member is still run-invalid — R-4 is
  unchanged, and the round-2 probes that assert it still pass.

**2. Stage 6b — `class_verifier.py:859-861`.** `head_witness["head_ref"]` became
`head_witness.get("head_ref")`. An absent, non-object or `record_id`-less
`head_ref` reaches `resolve_reference` as a non-reference and is `unresolved` ⇒
`witness-head-unresolved` (FAILURE), and only if 6a is clean.

**3. Stage 9 — `class_verifier.py:922-940`.** `head_witness["signature"].get(...)`
raised `KeyError` on an absent `signature` and `AttributeError` on a non-object
one — and `AttributeError` was **not** in the caught set, so a non-object
`signature` would have crashed rather than reporting. It is now read defensively:
`sig_obj = head_witness.get("signature")`, `sig_value = sig_obj.get("value") if
isinstance(sig_obj, dict) else None`, and a non-string `sig_value` fails the gate
closed ⇒ `witness-signature-invalid` (FAILURE), only if stage 7 is clean.

**4. `witness_id` — no code change needed.** Stage 7 already read
`head_witness.get("witness_id")`, and `lookup_binding` already returns
`binding-missing` for a non-string wire id, so an absent or non-string
`witness_id` yields `witness-binding-missing` (**WITHHELD**). Verified by probe
rather than assumed.

### The two pinned divergence risks

- **Channel assignment follows the closed §5 registry.** Checked against §5
  row-by-row, not against intuition: `no-witness-supplied` and
  `witness-binding-missing` are WITHHELD (→ `witnessed_withheld`);
  `witness-claim-invalid`, `witness-head-unresolved` and
  `witness-signature-invalid` are FAILURE (→ `witnessed_failures`). Every probe
  asserts the reason is present in its own channel **and absent from the other**.
  No new reason code was introduced.
- **R-2 precedence still governs.** The emitted reason is the first one
  *reachable* under the stage order. Absent `claim` **and** absent `signature` ⇒
  `witness-claim-invalid` alone; `head_witness = {}` (all four absent) ⇒
  `witness-claim-invalid` alone; absent `head_ref` + `witness_id` + `signature` ⇒
  `witness-head-unresolved` alone; absent `witness_id` + `signature` ⇒
  `witness-binding-missing` alone. Each is paired with a discrimination probe
  showing the suppressed reason really does fire when it is the only defect, so an
  "ALONE" assertion cannot pass merely because a later stage is dead code.

### One behaviour R-7 does not pin, recorded rather than decided

When `witness_id` is absent **and** the binding store is itself malformed,
`lookup_binding` reports `witness-binding-malformed` (its document-level defect)
before it ever inspects the wire id — the same path a *present but unregistered*
`witness_id` takes. Both reasons are WITHHELD in the same channel, and R-7's row
is stated for the ordinary case. I did **not** add a special case: introducing one
would be exactly the intuition-driven divergence R-7 warns against. Recorded here
so the ordering is on the record.

## JCS loader — how it resolves and what I verified before trusting it

`class_verifier.py` previously did a bare `import jcs`. No file in the verifier
directory provided that module, so the verifier **could not execute from the
committed repository**; the previous round resolved it with a package download,
which is now prohibited.

**Resolution — `class_verifier.py:36-74`.** `JCS_RELPATH` (line 50) is
`../../../v0.1/conformance/jcs.py`, joined onto
`os.path.dirname(os.path.abspath(__file__))` and normalised (54-56), so it
resolves from **any** working directory: `verifier_py` → `class-verification` →
`v0.2` → `airep` → `v0.1/conformance/jcs.py`. The module is loaded with
`importlib.util.spec_from_file_location` / `module_from_spec` / `exec_module`
(57-68) under the private name `airep_v0_1_jcs`, and the loader **refuses to
proceed** unless the loaded module exposes a callable `canonicalize` (69-70).
`sys.dont_write_bytecode` is set for the duration of the load (63-68) so the
verifier writes no `__pycache__` into the frozen tree. Nothing is vendored, no
copy is made, and no PyPI dependency was added.

**What I checked about the canonicalizer before wiring it in** (full read of
`spec/airep/v0.1/conformance/jcs.py`, 92 lines, plus executed checks):

1. **Interface match.** Its documented stable API is `canonicalize(obj) -> bytes`;
   its actual signature is `(obj: Any) -> bytes` and it returns `bytes`. My code's
   only call is `jcs.canonicalize(body)` — one positional argument, result
   concatenated with `bytes`. No adaptation was needed, and none was made.
2. **Key ordering.** RFC 8785 orders members by UTF-16 code unit, not code point.
   The module sorts on `k.encode("utf-16-be")`. Probed with a key set that
   separates the two orders (U+1F600, U+FB00, U+FFFF): the emitted order is
   U+1F600, U+FB00, U+FFFF — UTF-16 order, the same order a JavaScript runtime
   produces, and the opposite of code-point order for that set.
3. **Numbers.** ES6 `Number::toString(10)` battery, 13 values including `1.0`,
   `-0.0`, `1e20`, `1e21`, `1e-6`, `1e-7`, `5e-324`, `1.7976931348623157e308`:
   0 mismatches. Ints pass through as `str(n)`; `bool` is rejected as not a JSON
   number.
4. **String escaping.** `"`, backslash, backspace, form-feed, newline, carriage
   return and tab use the short escapes; U+0001 and U+001F are emitted as
   lowercase six-character `\uXXXX` escapes; U+007F is not escaped; non-ASCII is emitted
   literally as UTF-8. This is `JSON.stringify` behaviour, which is what RFC 8785
   specifies.
5. **Fail-closed.** Non-JSON values raise `TypeError`; NaN/Infinity raise
   `ValueError`. Both are already inside the exception sets my hash and signature
   paths catch, so a bad value cannot silently become a passing verdict.
6. **The decisive empirical check.** The frozen `integrity.current` of every
   corpus artifact recomputes exactly, and both Ed25519 signature preimages (the
   record-signature preimage over `current`, and the head-witness preimage over
   the JCS-canonicalized claim) verify — 45/45 verdicts unchanged. If this
   canonicalizer differed from the corpus builder's by a single byte, no artifact
   would reach `AIREP-Core`, let alone `AIREP-Witnessed`.

I found **no** behavioural difference from what my code assumed, so there was
nothing to stop and report on this point.

## Probes added — `selfcheck_s9_round3.py`, all 63 asserted, all pass

Every fixture is built in the file by mutating the P2 corpus inputs **in memory**;
nothing is written into the corpus and no `expected.json` is read.

| Group | Probes | Result |
|---|---|---|
| control (unmutated P2 → `AIREP-Witnessed`, five empty channels) | 1 | pass |
| R-7 row 1 — `head_witness` entirely absent → `no-witness-supplied` (WITHHELD) alone | 1 | pass |
| R-7 row 2 — present as `null` / string / array / number / boolean → run-invalid, exit 1, no verdict | 5 | pass |
| R-7 row 3 — unknown member inside `head_witness` → run-invalid (incl. a foreign member alongside a missing known member) | 2 | pass |
| R-7 row 4 — `claim` absent / null / string / array / number / structurally invalid → `witness-claim-invalid` alone | 6 | pass |
| R-7 row 5 — `head_ref` absent / null / string / array / number / no `record_id` → `witness-head-unresolved` alone; plus 6a-gates-6b | 7 | pass |
| R-7 row 6 — `witness_id` absent / null / number / array / object → `witness-binding-missing` (WITHHELD) alone; plus §4 suppression of stages 8-9 | 6 | pass |
| R-7 row 7 — `signature` absent / null / string / array / number, `value` absent / wrong-typed → `witness-signature-invalid` alone | 7 | pass |
| R-7 row 8 — R-4 nested closure unchanged (`head_ref`/`signature` object + unknown member → run-invalid) | 3 | pass |
| divergence risk A — §5 channel assignment: each reason in its own channel and **not** in the other; each denies `AIREP-Witnessed` | 10 | pass |
| divergence risk B — R-2 precedence over multi-member absence, each with a discrimination probe | 7 | pass |
| R-7 closure — an absent sub-member is never reported as `no-witness-supplied` | 4 | pass |
| packaging — module loaded from `<repo>/spec/airep/v0.1/conformance/jcs.py`, `canonicalize` returns RFC 8785 bytes, verifier runs with `cwd=/` and no `--schema-dir` | 4 | pass |

One observational (non-asserted) line records that `import jcs` fails in this
environment (exit 1) — i.e. no installed package is involved and the repository
loader is the only source of those bytes.

## Every self-check script, re-run

| Script | Exit | Result |
|---|---|---|
| `selfcheck_errata.py` | 0 | **43 ok / 0 FAIL** — "all construction self-checks passed" (after the path fix below) |
| `selfcheck_s9_round2.py` | 0 | **47 ok / 0 FAIL** — "all S9 round-2 probes passed" |
| `selfcheck_s9_round3.py` | 0 | **63 ok / 0 FAIL** — "all S9 round-3 probes passed" |

`selfcheck_errata.py` was carried into round 3 as a **known-broken** script: it was
authored against the snapshot layout (`HERE/corpus/cases`, `HERE/spec/schemas`, a
sibling `jcs.py`) and, run as committed, died at line 101 with
`FileNotFoundError: .../verifier_py/corpus/cases/P2/request.json`. Round 3 repaired
the **paths only** (`selfcheck_errata.py:16-25`: `CVDIR`, `CORPUS`, `SCHEMAS`,
`JCS_SRC`; and the §9 portability fixture at the tail now copies
`class_verifier.py` alone and materialises the frozen canonicalizer at the
repository-relative `v0.1/conformance/jcs.py` that the loader expects). No
assertion in that file was added, removed, weakened or re-worded, and its
portability assertion — that the default `--schema-dir` resolves from
`<v0.2>/class-verification/verifier_py/` — is unchanged and now passes.

## Corpus re-run — 45/45, and R-7 changed no §7 expected value

A results file was produced **before** the R-7 edit (with the JCS loader already in
place, so the two runs differ only by R-7) and again after:

- `--corpus corpus --out ...` exit 0, **45 verdicts for 45 cases**.
- Compared field-by-field against every `cases/<ID>/expected.json` (`class`, both
  authenticated failure/withheld arrays, `authenticated_caveats`, both witnessed
  arrays, `observer_assessment`): **45/45 match, 0 mismatches.**
- The post-R-7 results file is **byte-identical** to the pre-R-7 one. R-7 changed
  no §7 expected value, exactly as the ruling states. Nothing needed adjusting,
  and nothing was adjusted.

This is consistent with the corpus's own shape, checked directly: of the 45
requests, **17 omit `head_witness` entirely** and the other **28 carry all four
members**; none supplies a `head_witness` with a missing sub-member, and none
supplies `"head_witness": null`.

## FINDINGS (observed this round)

1. **`selfcheck_errata.py` was not runnable as committed.** Carried over from
   round 2 as an open finding; **fixed this round** (paths only, no assertion
   touched) and now passes. Recorded here because the round-2 record says "Not
   fixed".

2. **Stale §9 vocabulary in `class_verifier.py` comments — still not fixed.** The
   module docstring and several comments cite the withdrawn first draft's ids
   ("E-1..E-6") where §9 now numbers its rulings R-1..R-7. Stale *references*, not
   stale behaviour: the code matches §9 as measured above. Renumbering is
   file-wide cosmetic churn, which this round forbids. **Not fixed.**

3. **The verifier still imports three PyPI packages by name.** `jsonschema` +
   `referencing` (stage-0 schema validation) and `cryptography` (Ed25519) are not
   supplied by the repository. They happened to be present in this environment, so
   this round did not have to fetch anything — but the packaging obligation this
   round closed for JCS is only *partly* closed for the verifier as a whole: a
   clean machine still needs those three installed. Outside this round's scope
   (the mandate names the JCS import); recorded as a maintainer finding rather
   than silently fixed.

4. **A `__pycache__` remains under `verifier_py/`.** Created by round 3's probe
   script importing `class_verifier` to inspect the loaded JCS module path. The
   script now sets `sys.dont_write_bytecode = True` before that import, and the
   verifier itself sets it around the JCS load, so neither writes bytecode any
   more — but the already-created
   `verifier_py/__pycache__/class_verifier.cpython-312.pyc` could not be removed:
   the environment denied every `rm` I attempted. It is a build artifact, not
   source. **Not removed; disclosed.**

5. **No defect found in the frozen inputs.** R-7 is internally consistent with §0,
   §2, §4, §5 and R-1..R-6 as far as I exercised them, and the
   `spec/airep/v0.1/conformance/jcs.py` canonicalizer behaves exactly as this
   verifier assumed. Nothing to report as a frozen-input defect.

## Frozen-input integrity, machine-checked

All **265** files listed in `corpus_manifest.json` re-hash to their recorded
SHA-256 (**0 mismatches**), and the manifest's `aggregate_sha256` recomputes to
`55d43c5170641b185dc5c95a71e8e336c902d26c556e03a10e248864de2950a4` under its
stated rule (path-sorted `'<sha256>  <relative-path>' + LF` lines) — so `corpus/`,
every `expected.json` included, is byte-untouched. A filesystem scan of the whole
work root shows exactly four source files modified in this round:
`class_verifier.py`, `selfcheck_s9_round3.py` (new), `selfcheck_s9_round2.py` and
`selfcheck_errata.py`, plus this file. Two consecutive corpus runs produce
byte-identical results files (determinism re-checked).

## Attestation

I did not leave `/tmp/wk_hd4/task` for any read, list, stat or glob of repository
or specification material; the only paths I wrote outside it are scratch files in
the session scratchpad (a canonicalizer probe script and the results files used for
the before/after comparison). **I made no network access of any kind** — no `pip`,
no download, no fetch, no web search; the `import jcs` observation in the round-3
probes is a local import attempt, and it fails, which is the point. I did not seek,
read, infer or reason about any other implementation of this contract in any
language. I did not run `git`. I did not write, run or design any
cross-implementation comparator, and produced no artifact intended for comparison.
I modified no frozen input: `CLASS_VERIFIER_CONTRACT.md`, `corpus/` (including
every `expected.json`), `corpus_manifest.json`, `build_class_corpus.py`, `KEYS.md`,
`schemas/`, `INTEGRITY.md`, `CONFORMANCE_CLASS_DESIGN.md` and
`spec/airep/v0.1/conformance/jcs.py` are untouched — the manifest re-hash above is
a machine check of the corpus, and the mtime scan covers the rest. The probe
scripts mutate corpus inputs only in memory and write only into temporary
directories they delete. This attestation rests on my own record of my actions;
the environment enforces no sandbox, and the claim is stated at exactly that
strength.

# Remediation round 4 (R-8)

Scope of this round: implement §9 **R-8** — `witness_id` usability precedes
binding-store resolution at Stage 7 — add regression probes for it, re-run every
self-check script and the corpus, and change nothing else. No rename, no
restructure, no refactor for taste, no new feature, no reason-string change, no
envelope change, and no edit to any stage outside Stage 7.

## R-8 — what changed, with line references

**One file, one function, one hunk:** `class_verifier.py`,
`OperatorInputs.lookup_binding`. The file went from 1207 to 1220 lines (+13, of
which 11 are comment). Nothing else in the file was touched, and no other file's
logic changed.

**Before** (old lines 356–363) — the store was resolved and validated *first*,
and the wire-id usability test was fused into the same condition as the map
lookup, *after* the malformed-store return:

```python
if self.bindings_doc is None:
    return None, None, "binding-missing"
bindings, producer_map, witness_map = self._binding_maps()
role_map = producer_map if role == "producer" else witness_map
if bindings is None or role_map is None:
    return None, None, "binding-malformed"
if not isinstance(wire_id, str) or wire_id not in role_map:
    return None, None, "binding-missing"
```

**After** (new lines 356–376) — the usability test is hoisted above
`_binding_maps()`, and the map-lookup half of the old fused condition stays
below it:

```python
# ... R-8 rationale comment, lines 356-363 ...
if not isinstance(wire_id, str):          # 7a  (line 364-365)
    return None, None, "binding-missing"
if self.bindings_doc is None:             #     (line 366-367)
    return None, None, "binding-missing"
# ... 7b comment, lines 368-370 ...
bindings, producer_map, witness_map = self._binding_maps()   # 7b (line 371)
role_map = producer_map if role == "producer" else witness_map
if bindings is None or role_map is None:
    return None, None, "binding-malformed"
if wire_id not in role_map:               # 7b  (line 375-376)
    return None, None, "binding-missing"
```

Everything from `binding_id = role_map[wire_id]` (line 377) onward — the entry
resolution, the R-3 malformed-before-not-trusted ordering, the suite check — is
byte-unchanged. Stage 7's call sites in `evaluate()` are unchanged: the witness
call still runs only when `stage6_clean` (7a's own precondition), and 7c
(revocation) still runs only after an accepted binding.

### Stage 7 order, before and after

| | Before | After (R-8) |
|---|---|---|
| 1st | binding document present? | **7a — wire id is a usable string?** ⇒ `*-binding-missing` |
| 2nd | store resolution + E-4 closure ⇒ `*-binding-malformed` | binding document present? |
| 3rd | wire id usable **or** present in map ⇒ `*-binding-missing` | **7b —** store resolution + E-4 closure ⇒ `*-binding-malformed` |
| 4th | entry resolution, R-3, suite | **7b —** id present in map? ⇒ `*-binding-missing`; then entry resolution, R-3, suite |
| 5th | revocation (7c) | **7c —** revocation, unchanged |

The governing combination therefore inverts as R-8 requires: absent `witness_id`
+ malformed store was `witness-binding-malformed`, and is now
`witness-binding-missing` alone.

### Why the hoist is unconditional, and why that does not weaken the producer path

The test is not gated on `role`. R-8's rationale — with no usable wire id the
verifier has not determined *which* binding it would evaluate — is stated as a
property of the resolution step, so gating it on the role would encode the
witness path's accident rather than the rule. It is observably a no-op for the
producer path: the producer's wire id is `artifact.subject.producer`, which
`common.schema.json` declares **required** and typed `"string"` inside a
`"additionalProperties": false` `subject` object, and stage 0 runs full
jsonschema validation before stage 2 — so by the time `lookup_binding("producer",
...)` is called the id is always a string and control always reaches 7b. That is
asserted, not assumed: two probes below drive the producer path across the same
malformed stores and still get `producer-binding-malformed`.

## Probes added — `selfcheck_s9_round4.py`, 19 asserted, all pass

New sibling script (the three earlier ones were left untouched). Same discipline
as rounds 2–3: every fixture is built **in the file** by mutating the P2 corpus
inputs *in memory*; nothing is written into `corpus/`; **no `expected.json` is
read anywhere**; temporary request/operator files go into a `TemporaryDirectory`
that is deleted. Two structurally different malformed stores are used — one with
an unknown top-level member (E-4 closure) and one with the `witness_bindings`
container deleted — so the result does not rest on a single malformation shape.

| # | Probe | Result |
|---|---|---|
| 1 | control: unmutated P2 + unmutated store ⇒ `AIREP-Witnessed`, all five channels empty | ok |
| 2 | **absent `witness_id` + malformed store ⇒ `witness-binding-missing` ALONE** (governing combination) | ok |
| 3 | absent `witness_id` + malformed store (missing container) ⇒ same | ok |
| 4 | `witness_id: null` + malformed store ⇒ `witness-binding-missing` alone | ok |
| 5 | `witness_id` integer + malformed store ⇒ same | ok |
| 6 | `witness_id` float + malformed store ⇒ same | ok |
| 7 | `witness_id` bool + malformed store ⇒ same | ok |
| 8 | `witness_id` array + malformed store ⇒ same | ok |
| 9 | `witness_id` object + malformed store ⇒ same | ok |
| 10 | **discrimination:** malformed store + valid present `witness_id` ⇒ `witness-binding-malformed` | ok |
| 11 | discrimination, second malformation shape ⇒ `witness-binding-malformed` | ok |
| 12 | **producer path:** malformed store, no `head_witness` ⇒ `producer-binding-malformed` | ok |
| 13 | producer path, second malformation shape ⇒ `producer-binding-malformed` | ok |
| 14 | **7b intact:** well-formed store, present usable id, `witness_bindings` empty ⇒ `witness-binding-missing`, producer channels clean, `AIREP-Authenticated` | ok |
| 15 | 7b intact: well-formed store, present unknown id ⇒ `witness-binding-missing` | ok |
| 16 | 7a with a well-formed store: absent id ⇒ `witness-binding-missing` (unchanged, pinned) | ok |
| 17 | 7a with a well-formed store: `null` id ⇒ `witness-binding-missing` (pinned) | ok |
| 18 | dependency: stage-6 failure + absent id + malformed store ⇒ `witness-claim-invalid` alone, no stage-7 reason | ok |
| 19 | 7c: absent id + malformed store + witness-less revocation snapshot ⇒ `witness-binding-missing` alone, **no** revocation reason | ok |

Every probe also asserts the *other* four channels and the class, so a probe
cannot pass while a second reason leaks into the same or a neighbouring channel.
In probes 2–13 the authenticated channel is asserted to carry exactly
`producer-binding-malformed` and the class to be `AIREP-Core`; in 14–17 the
authenticated channels are asserted empty and the class `AIREP-Authenticated`.

### The probes were shown to discriminate

A probe suite that passes both before and after a fix measures nothing. So the
same 19 probes were run against the **pre-R-8** source (the hunk temporarily
reverted in place, then restored from a byte copy taken before the revert, and
the restored file re-verified by re-running the suite):

- **pre-R-8: 9 FAIL / 10 ok**, exit 1. The nine failures are exactly the
  R-8-governed rows — probes 2–9 and 19 — each reporting
  `witnessed_withheld: ['witness-binding-malformed']` where R-8 requires
  `['witness-binding-missing']`.
- **post-R-8: 19 ok / 0 FAIL**, exit 0.

The ten rows that pass in both states are the ones R-8 leaves alone (control,
discrimination, producer path, 7b, well-formed-store 7a, stage-6 dependency) —
which is the evidence that the fix did not simply disable the malformed path.

## Every self-check script, re-run

Run with `PYTHONDONTWRITEBYTECODE=1`; `selfcheck_s9_round4.py` additionally sets
`sys.dont_write_bytecode = True` and passes `PYTHONDONTWRITEBYTECODE=1` into every
subprocess it spawns.

| Script | Exit | Asserted | Result |
|---|---|---|---|
| `selfcheck_errata.py` | 0 | 43 | all construction self-checks passed |
| `selfcheck_s9_round2.py` | 0 | 47 | all S9 round-2 probes passed |
| `selfcheck_s9_round3.py` | 0 | 63 | all S9 round-3 probes passed |
| `selfcheck_s9_round4.py` | 0 | 19 | all S9 round-4 probes passed |

**0 failures across 172 assertions.** No earlier probe regressed under R-8 —
including round 2's observation rows on an absent `witness_id`, which record the
*witnessed_failures* channel (empty then, empty now: the reason is WITHHELD).

## Corpus re-run — 45/45, and R-8 changed no §7 expected value

- Baseline, **before** the edit: `--corpus corpus --out <tmp>/before.json` exit 0,
  45 verdicts; compared field-by-field against every `cases/<ID>/expected.json`
  (`class`, `authenticated_failures`, `authenticated_withheld`,
  `authenticated_caveats`, `witnessed_failures`, `witnessed_withheld`,
  `observer_assessment`): **MATCH 45, MISMATCH 0**.
- **After** the edit: exit 0, 45 verdicts, **MATCH 45, MISMATCH 0**.
- The two results files are **byte-identical** (`cmp` clean). R-8 changed no §7
  expected value, exactly as the ruling states. Nothing needed adjusting, and
  nothing was adjusted. Two consecutive post-edit runs are also byte-identical
  (determinism re-checked).

This is consistent with the corpus's own shape, checked directly: the only two
cases that expect a `*-binding-malformed` (PB4, WB4) both carry a **structurally
complete** store whose malformation is inside a `bindings` entry, and both supply
a present, usable wire id — PB4 has no `head_witness` at all, WB4's `witness_id`
is `"NOTARY-WITNESS #1"`. No case combines an absent or non-string `witness_id`
with a malformed store, so no case can move. The one case expecting
`witness-binding-missing` (WB2) is the 7b leg — well-formed store, present id,
empty `witness_bindings` — and is unaffected by 7a.

## FINDINGS (observed this round)

1. **Stale §9 vocabulary in `class_verifier.py` comments — still not fixed.**
   Carried from round 3. The module docstring and several comments still cite the
   withdrawn first draft's ids ("E-1..E-6") where §9 now numbers its rulings
   R-1..R-8. Stale *references*, not stale behaviour. The new hunk cites R-8 and
   R-3 correctly; renumbering the rest is file-wide cosmetic churn, which this
   round forbids. **Not fixed.**

2. **The verifier still imports three PyPI packages by name.** Carried from
   round 3, unchanged: `jsonschema` + `referencing` (stage-0 validation) and
   `cryptography` (Ed25519) are not supplied by the repository; they were present
   in this environment, so nothing was fetched. A clean machine still needs them.
   Outside this round's scope. **Not fixed.**

3. **No `__pycache__` this round.** Round 3's finding #4 (an unremovable
   `verifier_py/__pycache__/class_verifier.cpython-312.pyc`) does **not** appear
   in this snapshot, and none was created: a scan of the whole work root for
   `__pycache__` / `*.pyc` after all runs returns nothing. Closed for this round;
   whether the round-3 artifact still exists in the maintainer's copy is not
   something this round can see.

4. **A wording ambiguity in `corpus_manifest.json.aggregate_rule`, not a defect.**
   The rule says "concatenated ASCII-sorted UTF-8 lines `'<sha256>  <relative-path>\n'`".
   Sorting the *assembled lines* (i.e. by hash, since the hash is the prefix)
   yields `277368162a79cb89…` and does **not** reproduce the recorded aggregate;
   sorting by *relative path* yields `55d43c5170641b18…`, which matches. Both
   readings are available from the sentence. Reported, not changed — the manifest
   is frozen, the recorded aggregate is reproducible under the path-sorted
   reading, and this affects no verdict.

5. **No defect found in the frozen inputs.** R-8 is internally consistent with
   §3's stage table, §4's dependency graph, §5's registry channels and R-1..R-7
   as far as I exercised them. Nothing else to report.

## Frozen-input integrity, machine-checked

All **265** files listed in `corpus_manifest.json` re-hash to their recorded
SHA-256 (**0 mismatches**), and the manifest's `aggregate_sha256` recomputes to
`55d43c5170641b185dc5c95a71e8e336c902d26c556e03a10e248864de2950a4` under the
path-sorted reading of its stated rule — so `corpus/`, every `expected.json`
included, is byte-untouched. An mtime scan of the whole work root shows the only
files written in this round are `class_verifier.py` (edited),
`selfcheck_s9_round4.py` (new) and this file; every frozen document
(`CLASS_VERIFIER_CONTRACT.md`, `INTEGRITY.md`, `CONFORMANCE_CLASS_DESIGN.md`, the
five schemas, `build_class_corpus.py`, `KEYS.md`, `corpus_manifest.json`,
`spec/airep/v0.1/conformance/jcs.py`) still carries its snapshot-delivery
timestamp, earlier than my first write.

## Attestation

I did not leave `/tmp/wk_tq2/task` for any read, list, stat or glob of repository
or specification material; the only files I wrote outside the two deliverables and
this document are scratch files inside the work root
(`/tmp/wk_tq2/task/.r4scratch/`: the before/after corpus results, the per-case
comparator, the captured self-check outputs and the byte copy of the patched
source used to restore it after the discrimination run), and they are deleted at
the end of the round. **I made no network access of any kind** — no `pip`, no
download, no fetch, no web search. I did not seek, read, infer or reason about any
other implementation of this contract in any language; R-8's mention of "both
implementations" was read only as the maintainer's account of why the ruling
exists. I did not run `git`. I did not write, run or design any
cross-implementation comparator, and produced no artifact intended for comparison
against another implementation — the per-case comparator named above compares this
verifier's output against the frozen `expected.json` files only. I modified no
frozen input: the manifest re-hash above is a machine check of the corpus, and the
mtime scan covers the rest. The probe script mutates corpus inputs only in memory
and writes only into a temporary directory it deletes. This attestation rests on
my own record of my actions; the environment enforces no sandbox, and the claim is
stated at exactly that strength.
