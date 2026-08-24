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

## Remediation round 2 (§9 rulings)

Second, small remediation round against `CLASS_VERIFIER_CONTRACT.md` **§9 "Source-review
rulings — normative" (maintainer, 2026-08-24)**. §9 supersedes the earlier draft errata this
source was written against. Scope was surgical: R-1, the R-2 stage-6 precedence, removal of
the batch workaround, and verification-plus-probes for R-3 and R-4. Nothing else was renamed,
restructured, or re-tuned.

### R-1 — the `claim` closure removed

The withdrawn draft clause was implemented literally in `loadRequest`. **Removed verbatim**
(previously at lines 522–524, immediately after the `head_ref` closure check):

```js
      if (isPlainObject(h.claim) && !onlyKeys(h.claim, CLAIM_MEMBERS)) {
        throw new InvalidRunError("head_witness.claim carries an unknown member (closed envelope)");
      }
```

The surrounding comment was rewritten to state the narrowed rule (now lines 517–521). The
`head_ref` and `signature` closure checks are untouched (lines 522–528). `CLAIM_MEMBERS` is
still used, by `claimStructurallyValid`.

**Resulting WM1 verdict** (`--request corpus/cases/WM1/request.json` with that case's three
operator inputs and `--now 2026-08-23T12:00:00Z --freshness-window 3600`), exit `0`:

```
class                  AIREP-Authenticated
authenticated_*        [] / [] / []
witnessed_failures     ["witness-claim-invalid"]
witnessed_withheld     []
observer_assessment    not_applicable
```

WM1's claim carries an extra `"note": "extra"` member; it now flows into stage 6a and yields
`witness-claim-invalid` alone. WM1 is the 45th verdict again — `cv-chain-wm1 / cv-rec-wm1` is
present in the batch results file.

### R-2 — stage-6 precedence: before and after

**BEFORE** (lines 678–711 of the pre-round file). Three checks in one flat block, with the
head resolution running unconditionally and the timestamp check sequenced *second*:

1. `resolveRef(hw.head_ref, pool)` computed up front (old line 685);
2. `claimOk` computed; `witness-claim-invalid` pushed on failure (old lines 686–687);
3. **`witnessed_at` validity gated on `claimOk` only** — `witness-time-invalid` pushed here,
   *before* any head reason (old lines 691–695);
4. head resolution / must-be-primary / reconciliation, reported *after* the time check and
   *independently of* it, with `stage6Clean` set from `reconciles && timeOk` (old lines
   696–710).

Two deviations from R-2 followed. (a) 6b ran even when 6a had failed, so a claim defect
combined with an unresolvable or non-reconciling head could report two reasons. (b) 6c ran
*before* 6b and independently of it, so a bad head plus a bad `witnessed_at` reported both.

**AFTER** (lines 678–720). One dependent chain, each sub-step reporting alone:

- lines 684–685 — `hw === null` ⇒ `no-witness-supplied` (unchanged);
- lines 686–690 — **6a** `claimStructurallyValid(...)` false ⇒ `witness-claim-invalid`, and
  the `else` chain means 6b and 6c do not run;
- lines 691–710 — **6b** resolution → must-be-primary → reconciliation, setting a local
  `headOk`; on failure `witness-head-unresolved` or `witness-head-mismatch` (R-5) is the only
  reason and `headOk` stays false;
- lines 711–719 — **6c** `parseWitnessedAt(...)`, reached **only when `headOk`**;
  `witness-time-invalid` on failure, `stage6Clean = true` otherwise. No clock input is read.

Stages 7–10 and the §4 dependency wiring are unchanged; they still key off `stage6Clean`, which
is now true only when 6a, 6b and 6c all pass. Stage 10 remains recency only.

### WM1-specific handling removed

The batch runner (`runBatch`) carried a per-case `try { … } catch (e) { if (!(e instanceof
InvalidRunError)) throw e; … invalidCases++ }` around the per-case evaluate, plus an
`invalidCases` counter and a `return invalidCases > 0 ? 1 : 0`. That is what let the run emit
44 verdicts and still finish. It is no longer needed and has been removed: the three
statements now run unguarded (lines 999–1003) and `runBatch` returns `0` (line 1012). A
genuinely invalid run still propagates its `InvalidRunError` to `main()`, which reports
`invalid: …` on stderr and exits `1` — generic behaviour, with no reference to WM1 or to any
case id anywhere in the source.

*Honest limitation:* this round has no VCS access (running `git` is prohibited), so I cannot
show from history that this block was introduced for WM1. What is observable is that it was
the only per-case `InvalidRunError` handling in the file, it is what produced the 44-verdict
run, and nothing in the corpus needs it now.

### R-3 — binding precedence: already compliant, no fix needed

`resolveBinding` (lines 397–422) already orders the checks the way R-3 requires. Evidence, by
reading: the closed-member check `onlyKeys(entry, [...])` (line 411) and the type/`role`/key
checks (lines 412–415) all return `{status:"malformed"}` **before** `trusted` is examined; the
`trusted` presence check (line 416) returns `malformed`; only then does line 417 return
`{status:"not_trusted"}` for a present-but-not-`true` `trusted`. A malformed required
container short-circuits even earlier (line 399). So unknown member + `trusted:false` ⇒
`*-binding-malformed` only, and a clean entry + `trusted:false` ⇒ `*-binding-not-trusted` only.
Five probes now prove it on both the producer and the witness side (below). **No source change
was made for R-3.**

### R-4 — nested behaviour: already compliant for the members R-4 names

By reading, and now by probe: `head_ref` and `signature` retain their closure checks (lines
522–528); nothing else in `head_witness` is closed. No requiredness is created on their
members — `resolveRef` (line 539) returns `unresolved` when `record_id` is absent or not a
string, so it reaches `witness-head-unresolved`; `verifyEd25519` (line 235) returns `false` for
a non-string or non-hex `value`, so a missing/wrong-typed/forged `signature.value` reaches
`witness-signature-invalid`; `signature.alg` is read nowhere on the witness path (the
`wire-alg-mismatch` caveat reads `artifact.integrity.signature.alg`, a different field), so its
absence or a foreign value changes neither the cryptography nor the class. **No source change
was made for R-4.** See the FINDING below for the one adjacent behaviour R-4 does not settle.

### Probes added

New sibling script `rulings_check.mjs` (25 assertions, all inputs constructed inside
`tmp_rulingscheck/` from `corpus/cases/P2` bytes and deleted afterwards; the frozen corpus is
never added to or altered, and no `expected.json` is read). It opens with a control asserting
that untouched P2 is a clean `AIREP-Witnessed`, then:

- **R-1 ×3** — unknown / missing / wrong-typed claim member ⇒ exit 0 and
  `witnessed_failures == ["witness-claim-invalid"]`, `witnessed_withheld == []`.
- **R-2 ×6** — each injects *two* defects so only the earlier sub-step may speak:
  claim defect + unresolvable head ⇒ `["witness-claim-invalid"]`; claim defect + bad
  `witnessed_at` ⇒ `["witness-claim-invalid"]`; unresolvable head + bad `witnessed_at` ⇒
  `["witness-head-unresolved"]`; non-reconciling head + bad `witnessed_at` ⇒
  `["witness-head-mismatch"]`; bad `witnessed_at` alone ⇒ `["witness-time-invalid"]` **both
  with and without clock inputs**; and a valid-but-stale `witnessed_at` ⇒
  `["witness-freshness-outside-window", "witness-signature-invalid"]`, showing stage 6 clean
  and stages 7–10 all reached (rewriting `witnessed_at` also rewrites the signed claim, so
  stage 9 legitimately reports too).
- **R-3 ×5** — witness unknown member + `trusted:false` ⇒ `["witness-binding-malformed"]`
  withheld with empty failures; witness clean + `trusted:false` ⇒
  `["witness-binding-not-trusted"]` failures with empty withheld; the same pair on the producer
  side; and a malformed required container + `trusted:false` ⇒
  `["producer-binding-malformed"]`.
- **R-4 ×8** — unknown member in `head_ref` and in `signature` still exit `1`; `head_ref.record_id`
  absent and wrong-typed ⇒ `["witness-head-unresolved"]`; `signature.value` absent, wrong-typed
  and forged ⇒ `["witness-signature-invalid"]`; `signature.alg` absent, and `signature.alg`
  naming another suite, ⇒ `AIREP-Witnessed` with all five channels empty.

`exitcode_check.mjs`: the two lines asserting `unknown member in head_witness.claim ⇒ exit 1`
were removed (the ruling withdrew that clause) and the E-4 comment above the block was
rewritten to state the narrowed R-4 closure. Its `head_ref` and `signature` exit-1 cases stay.

Packaging-only edit to three scripts (`preimage_check.mjs`, `errata_check.mjs`,
`exitcode_check.mjs`): the corpus and schema path constants pointed at the authoring
snapshot's layout (`corpus/cases/…`, `spec/schemas`) and did not resolve in the committed
repository location. They now read `../corpus/cases/…` and `../../schemas`, run from this
directory. No assertion was changed by that edit. (§9 portability note, non-normative.)

### Results

All run from `spec/airep/v0.2/class-verification/verifier_node_r2/` on Node v20.19.6 with the
pinned `ajv@8.20.0`:

| Check | Result |
|---|---|
| `node rulings_check.mjs` | `RULINGS SELF-CHECK: clean` (exit 0) |
| `node errata_check.mjs` | `ERRATA SELF-CHECK: clean` (exit 0) |
| `node exitcode_check.mjs` | `EXIT-CODE SELF-CHECK: clean` (exit 0) |
| `node preimage_check.mjs` | `CONSTRUCTION SELF-CHECK: clean` (exit 0) |
| `node selfcheck.mjs` | `ENVELOPE SELF-CHECK: clean (45 verdicts, 31 registry reasons)` |
| `node class_verifier.mjs --corpus ../corpus --out out_run1.json` | exit `0`, **45 verdicts**, byte-identical on a second run |
| corpus vs `expected.json`, all 45 cases single-case | `cases=45 aborted=0 mismatching=0 clean=45` |

Before this round the same corpus comparison read `cases=45 aborted=1 mismatching=0 clean=44`,
the abort being `WM1: exit 1 :: head_witness.claim carries an unknown member`. No §7 expected
value was unmet after the rulings, so no blocking finding on that axis.

### FINDING (observed, not fixed)

`loadRequest` requires all four `head_witness` members — `head_ref`, `witness_id`, `claim`,
`signature` — to be *present*, and throws `InvalidRunError` (exit 1) when any is absent.
Measured: deleting each in turn from P2 gives exit `1` with `head_witness is missing <member>`
in all four cases. This predates §9 and I did not change it, because it is a §0 envelope-shape
reading rather than part of E-4's closure, and neither R-1 nor R-4 speaks to it: R-1's "extra,
missing or wrong-typed **claim members**" reads most naturally as members *of* the claim (which
now correctly yield `witness-claim-invalid` — probed), and R-4's "no new requiredness" is
scoped to `head_ref.record_id`, `signature.value` and `signature.alg` (all three probed
compliant). If the maintainer intends an absent `claim` / `head_ref` / `signature` to be a
class reason rather than a run-invalid abort, that is a further ruling and a further edit; I
have not made it unilaterally.

### Attestation

- Every read and write in this round stayed inside `/tmp/wk_zm3/task`, **with one disclosed
  exception**: while checking whether the pinned dependency was available I ran a
  filesystem-wide `find / -maxdepth 6 -name "2020.js" -path "*ajv/dist*"`, which listed one
  path outside the work root (`/usr/share/nodejs/ajv/dist/2020.js`, a distribution package).
  Nothing from that path was read, imported or used; the dependency was instead installed from
  `package.json` / `package-lock.json` into `./node_modules` with the npm cache directed inside
  the work root. I report it rather than conceal it. No other path outside `/tmp/wk_zm3/task`
  was read, listed, stat'ed or globbed.
- I did not seek, read, infer about, or reason about any other implementation of this contract
  in any language, and wrote and ran no cross-implementation comparator or comparison artifact.
- I did not search the web.
- I ran no `git` command.
- No frozen input was modified. Files changed this round, all inside `verifier_node_r2/`:
  `class_verifier.mjs`, `exitcode_check.mjs`, `errata_check.mjs`, `preimage_check.mjs`,
  this file, and the new `rulings_check.mjs`. `node_modules/` was created by `npm install`.
  The contract, the corpus (every `expected.json` included), `corpus_manifest.json`,
  `build_class_corpus.py`, `KEYS.md`, the schemas, `INTEGRITY.md` and
  `CONFORMANCE_CLASS_DESIGN.md` were read only.
