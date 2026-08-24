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

---

## Remediation round 3 (R-7)

Third and final remediation round on my own prior work, against the new normative ruling
**§9 R-7** of `CLASS_VERIFIER_CONTRACT.md`. R-7 closes the finding this file recorded at the
end of round 2: `loadRequest` treated all four `head_witness` members as harness-required and
exited 1 when any was absent, while §0 declares only the `head_witness` object itself optional.
The governing distinction R-7 states — *absence of a KNOWN evidence field fails or withholds
the tier evaluation; structure FOREIGN to the harness invalidates the run* — is what the code
now implements. R-1..R-6 were re-read and are unchanged; nothing else was touched.

### What changed — two edits, both in `class_verifier.mjs`

**Edit 1 — `loadRequest`, `class_verifier.mjs:512-533` (the §0 envelope reader).**

- **Deleted** the five-line requiredness loop that stood immediately after the `head_witness`
  closure check and threw `InvalidRunError("head_witness is missing <member>")` when any of
  `head_ref` / `witness_id` / `claim` / `signature` was absent. This was the exact defect R-7
  names. In its place stands a comment block (`:512-521`) recording the four known-field
  dispositions and that R-2 decides which is reachable.
- **Changed** `class_verifier.mjs:531` from a two-statement form —
  `if (!isPlainObject(h.signature)) throw …;` followed by an unconditional
  `if (!onlyKeys(h.signature, …)) throw …;` — to the single guarded form
  `if (isPlainObject(h.signature) && !onlyKeys(h.signature, ["alg", "value"])) throw …;`.
  An absent or non-object `signature` is now a known-field absence that reaches stage 9; an
  unknown member inside a `signature` **object** is still run-invalid. This makes `signature`
  read exactly like `head_ref` already did at `:528`.
- **Deliberately unchanged** in the same function: `:508` (`head_witness` present but
  null/non-object ⇒ `InvalidRunError`), `:509-511` (unknown member inside `head_witness` ⇒
  `InvalidRunError`), and `:528-530` (unknown member inside a `head_ref` object ⇒
  `InvalidRunError`). R-7 rows 2, 3 and 8 require all three to stay as they are.

**Edit 2 — stage 9, `class_verifier.mjs:773-777` (witness signature verification).**

The old line read `verifyEd25519(preimage, hw.signature.value, …)`, which throws a `TypeError`
— not a class reason — the moment `hw.signature` is absent, because edit 1 now lets that case
reach stage 9. It is replaced by
`const sigValue = isPlainObject(hw.signature) ? hw.signature.value : undefined;` followed by
`verifyEd25519(preimage, sigValue, …)`. `verifyEd25519` already returns `false` for any
non-string, so an absent or non-object `signature` yields `witness-signature-invalid`, exactly
as an absent or wrong-typed `signature.value` already did under R-4.

**No other change.** No reason string, no verdict envelope member, no channel mapping, no stage
order, no rename, no refactor. The other four stages needed no edit and got none: `hw.claim`
already flows into `claimStructurallyValid` (`:642`, non-object ⇒ `false`), `hw.head_ref` into
`resolveRef` (`:544`, non-object ⇒ `unresolved`), and `hw.witness_id` into `resolveBinding`
(`:400`, non-string ⇒ `missing`) — all three were already absence-tolerant, and the round did
not touch them.

### Probes added — `rulings_check.mjs:252-415`, one section per R-7 row

Every probe builds its own input by mutating a parsed copy of `corpus/cases/P2/request.json`
in memory and writing it under `tmp_rulingscheck/`. The frozen corpus is never added to or
altered, and no `expected.json` is read anywhere in this file. Each probe asserts the **exact**
five channel arrays (or the exact exit code), so a reason landing in the wrong array fails.

| Probe group | R-7 row / risk | Probes | Result |
|---|---|---|---|
| `head_witness` entirely absent | row 1 | 1 | ok — `no-witness-supplied` in `witnessed_withheld`, `witnessed_failures` empty |
| `head_witness` as `null`, `[]`, string, number, boolean | row 2 | 5 | ok — run-invalid, exit 1, all five |
| unknown member inside `head_witness` | row 3 | 1 | ok — run-invalid, exit 1 |
| `claim` absent; `claim` as string / array / null / number | row 4 | 5 | ok — `witness-claim-invalid` in `witnessed_failures` |
| `head_ref` absent; `head_ref` as string / array / null | row 5 | 4 | ok — `witness-head-unresolved` in `witnessed_failures` |
| `witness_id` absent; as number / null / object | row 6 | 4 | ok — `witness-binding-missing` in `witnessed_**withheld**` |
| `signature` absent; as string / array / null / number | row 7 | 5 | ok — `witness-signature-invalid` in `witnessed_failures` |
| unknown member in `head_ref` / `signature` object | row 8 | 2 | ok — still run-invalid, exit 1 (R-4 unchanged) |
| **Divergence risk 1** — channel per closed §5 registry | 5 reasons | 5 | ok — see below |
| **Divergence risk 2** — R-2 precedence over absences | 6 | 6 | ok — see below |

**Divergence risk 1 (channel assignment).** Each of the five reasons R-7 names was checked
against the §5 table by hand and then measured, asserting the reason present in its own array
**and** the other array empty: `no-witness-supplied` WITHHELD, `witness-binding-missing`
WITHHELD, `witness-claim-invalid` FAILURE, `witness-head-unresolved` FAILURE,
`witness-signature-invalid` FAILURE. The `witness_id` row is the trap — a *missing* known field
whose reason is nevertheless WITHHELD while its neighbours on both sides are FAILURE — and it
is probed twice, once in row 6 and once here. `selfcheck.mjs` independently re-checks every
emitted reason against the in-source registry kind, so a channel error has two detectors.

**Divergence risk 2 (R-2 precedence).** Six probes remove two or more known members at once and
demand the first *reachable* reason **alone**:

- `claim` + `signature` absent ⇒ `witness-claim-invalid` alone (the case R-7 pins by name);
- all four members absent ⇒ `witness-claim-invalid` alone;
- `head_witness` as `{}` ⇒ `witness-claim-invalid` alone;
- `head_ref` + `witness_id` absent ⇒ `witness-head-unresolved` alone;
- `witness_id` + `signature` absent ⇒ `witness-binding-missing` alone;
- `witness_id` absent with no clock ⇒ `witness-binding-missing` **and**
  `freshness-inputs-missing` both present — stage 10 does not depend on stage 7, so this probe
  pins that R-7 suppressed nothing beyond its own prerequisite chain.

`rulings_check.mjs` totals **63 probes, 63 ok, 0 fail** — 38 R-7 probes added this round, 25
pre-existing R-1..R-4 probes still green.

### Results — every check script, final state

Run from `spec/airep/v0.2/class-verification/verifier_node_r2/` on Node v20.19.6 with the
pinned `ajv@8.20.0` already present in `./node_modules` (no install, no network this round).

| Check | Result | Exit |
|---|---|---|
| `node class_verifier.mjs --schema-dir ../../schemas --corpus ../corpus --out out_run1.json` | 45 verdicts written | `0` |
| `node class_verifier.mjs … --out out_run2.json` | 45 verdicts written | `0` |
| determinism: `cmp out_run1.json out_run2.json` | **byte-identical**, both `sha256 556ab69a6f86d942fa68abdd1a3ce5423e2604d8813f92ff7b3c0f6b2644f735` | `0` |
| `node selfcheck.mjs` | `ENVELOPE SELF-CHECK: clean (45 verdicts, 31 registry reasons)` | `0` |
| `node rulings_check.mjs` | `RULINGS SELF-CHECK: clean` — 63/63 probes ok | `0` |
| `node errata_check.mjs` | `ERRATA SELF-CHECK: clean` | `0` |
| `node exitcode_check.mjs` | `EXIT-CODE SELF-CHECK: clean` — 19/19 exit-code cases ok | `0` |
| `node preimage_check.mjs` | `CONSTRUCTION SELF-CHECK: clean` | `0` |
| `node corpus_compare.mjs` | `cases=45 aborted=0 mismatching=0 clean=45` | `0` |

**`selfcheck.mjs` is NOT self-contained, stated plainly.** It reads `out_run1.json` from the
working directory — the output of a *prior* batch run — and does not invoke the verifier at
all. Run alone against a stale or absent `out_run1.json` it either checks the wrong bytes or
throws `ENOENT`. The batch above was therefore run **first**, and `selfcheck.mjs` immediately
after, so its "45 verdicts" describes this round's final binary. It also checks structure only
— envelope shape, registry membership, channel kind, §2 consistency invariants, dedup, ASCII
ordering, UTF-8 tuple ordering, duplicate tuples. It asserts **no** expected value and reports
no pass rate; it cannot detect a wrong-but-well-formed verdict.

`corpus_compare.mjs` is **new this round** and is a regression harness, **not a probe**: it is
the one script that reads `expected.json`, deliberately, because §7 regression is what it
measures. It runs the verifier once per case in single-case mode with that case's own operator
inputs and clock, and compares all seven expected members.

### Corpus: 45/45, and R-7 provably moved nothing

`corpus_compare.mjs` reports `cases=45 aborted=0 mismatching=0 clean=45` — every case produces
a verdict, and all seven `expected.json` members match on all 45.

The requirement was that R-7 change no §7 expected value. Rather than assert that from the
45/45 alone, I measured it: I reconstructed the **pre-R-7** verifier into a throwaway file by
reverse-applying both edits, ran the full corpus batch on it, and compared bytes.

```
pre-R-7  tmp_pre_r7_out.json  sha256 556ab69a6f86d942fa68abdd1a3ce5423e2604d8813f92ff7b3c0f6b2644f735
post-R-7 out_run1.json        sha256 556ab69a6f86d942fa68abdd1a3ce5423e2604d8813f92ff7b3c0f6b2644f735
```

Byte-identical: R-7 changed no corpus verdict at all, as the ruling predicts ("no corpus case
supplies a `head_witness` with a missing sub-member"). The throwaway file and its output were
deleted immediately after the measurement. No blocking finding on this axis.

### FINDINGS (observed, not fixed)

1. **`witness_id` absence vs a malformed bindings document — an unruled interaction.** R-7 row
   6 says an absent/non-string `witness_id` yields `witness-binding-missing`. `resolveBinding`
   (`class_verifier.mjs:397-402`) tests the *store* before the wire id: a `null` store returns
   `missing` and a structurally malformed store returns `malformed`, both before the
   `typeof wireId !== "string"` test. So with a **malformed** bindings document *and* an absent
   `witness_id`, the emitted reason is `witness-binding-malformed`, not
   `witness-binding-missing`. I did not reorder these tests. R-7's row describes the
   head_witness-side defect in isolation, while E-4 makes operator-document malformation
   fail-closed and takes precedence; both reasons are WITHHELD, so no channel is at stake, and
   reordering would change behaviour for a case R-7 does not rule on. Recording it because two
   implementations could plausibly order these two tests differently. Not a defect I can
   resolve without a ruling.
2. **The round-2 finding is closed.** The finding recorded at the end of round 2 — the four
   required `head_witness` members — is exactly what R-7 ruled on and what edit 1 removes. It
   is no longer open.

No other finding. No frozen input appeared defective this round.

### Attestation

- Every read, write and command in this round stayed inside `/tmp/wk_ns8/task`, **with one
  disclosed exception**: while running the four check scripts I mistyped a shell redirect as
  `> /tmp_out` (intended as a scratch file inside the work root). The redirect targeted a path
  outside the root. I did not read, list, `stat` or glob that path, before or after, and I did
  not inspect or remove it afterwards, because doing so would itself be a touch outside the
  root; I report it rather than conceal it. Nothing outside the work root was read, and nothing
  from outside it entered this work. The round-2 `find /` incident was **not** repeated: no
  filesystem-wide search of any kind was run this round.
- I did not access the network in any form — no `npm install`, no fetch, no web search. `ajv`
  was used exactly as already installed in `./node_modules`.
- I did not seek, read, infer about, or reason about any other implementation of this contract
  in any language. I wrote, ran and designed no cross-implementation comparator and no artifact
  intended for comparison against another implementation; parity remains on hold.
- I ran no `git` command.
- No frozen input was modified. `CLASS_VERIFIER_CONTRACT.md`, `corpus/` (every `expected.json`
  included), `corpus_manifest.json`, `build_class_corpus.py`, `KEYS.md`, the schemas,
  `INTEGRITY.md`, `CONFORMANCE_CLASS_DESIGN.md`, `package.json` and `package-lock.json` were
  read only. Files written this round, all inside `verifier_node_r2/`: `class_verifier.mjs`
  (the two edits above), `rulings_check.mjs` (R-7 probe section appended), the new
  `corpus_compare.mjs`, this file, and the run outputs `out_run1.json` / `out_run2.json`.
- I am the sole author of this implementation and this round; nothing here was independently
  reviewed, and this record is implementer evidence, not acceptance.

## Remediation round 4 (R-8)

Fourth and final semantic remediation round on my own prior work, following maintainer ruling
**R-8** in `CLASS_VERIFIER_CONTRACT.md` §9. R-1..R-7 are unchanged and still bind. Scope was
R-8 only: no rename, restructure, taste refactor, new feature, reason-string change, envelope
change, or edit to any stage outside Stage 7.

**What R-8 rules.** Stage 7 is three dependent sub-steps — **7a** witness identifier usability
→ **7b** binding-store resolution → **7c** witness revocation. When stage 6 is clean, an absent
or non-string `witness_id` emits `witness-binding-missing` (WITHHELD) and stage 7 **stops
there**, even when the binding store is itself malformed, because with no `witness_id` the
verifier has not determined *which* binding it would evaluate and the store-resolution gate is
never reached. R-8 explicitly notes this **inverts** the order both implementations had, and
that the same malformed store may still produce `producer-binding-malformed` on the producer
path, which resolves its own wire id and does reach the gate.

### Stage 7 order — before and after

| | Order actually executed |
|---|---|
| **Before (pre-R-8)** | `resolveBinding()` was called immediately on entering stage 7, and inside it the tests ran: (1) store absent ⇒ `missing`; (2) **store not well-formed ⇒ `malformed`**; (3) **`typeof wireId !== "string"` ⇒ `missing`**; (4) map lookup; (5) entry structure; (6) trust; (7) suite. So the store gate (2) preceded the wire-id gate (3): an absent `witness_id` with a malformed store reported `witness-binding-malformed`. |
| **After (R-8)** | **7a** `typeof hw.witness_id !== "string"` is tested *in the stage-7 caller, before the store is consulted at all* ⇒ `witness-binding-missing`, stage 7 stops. **7b** only otherwise: `resolveBinding()` unchanged (store → map → entry → trust → suite, R-3 intact). **7c** revocation only after an accepted binding. |

`resolveBinding()` itself was **not** modified — that is what keeps the producer path's store
gate reachable and `producer-binding-malformed` alive. Its internal `typeof wireId !== "string"`
test is now unreachable from the witness caller and still live for the producer caller; leaving
it in place was the smaller edit than threading a role-conditional through the function.

### Edits

**1. `class_verifier.mjs` lines 727–763** (`evaluateWitnessTier`, the Stage 7 block) — the sole
behavioural edit. The former body

```
  if (stage6Clean) {
    witRes = resolveBinding(policy.bindings, "witness", hw.witness_id);
    switch (witRes.status) { ... }
    if (witBindingAccepted) { ...revocation... }
  }
```

is wrapped in a 7a guard: `if (typeof hw.witness_id !== "string") { witWithheld.push("witness-binding-missing"); } else { ...the former body, unchanged... }`, with the
existing revocation branch labelled `7c` and the two sub-steps commented against R-8. The
switch arms, the reason strings, the revocation branch, and every channel push are byte-for-byte
the previous ones; only the guard, the comments and the indentation of the moved block changed.
No other stage was touched.

**2. `class_verifier.mjs` line 519** — comment only, no behaviour: the R-7 member map now reads
`witness_id absent/non-string => witness-binding-missing (stage 7a)` instead of `(stage 7)`.

**3. `rulings_check.mjs` lines 418–545** — an R-8 probe section appended before the teardown,
plus line 2 of the header comment updated to name R-7 and R-8 alongside R-1..R-4. Probes build
every input themselves from case P2's bytes into `tmp_rulingscheck/`, which is deleted at the
end. No corpus file was added to or altered, and no `expected.json` is read by this script.

### R-8 probes and results — 18 new probes, all passing

All probes run with the P2 clock and P2 operator inputs unless stated. "Malformed store" means
one of two **store-level** malformations built from P2's `bindings.json`: (A) the required
`witness_bindings` container deleted, (B) an unknown top-level member added. (A) is exactly the
input that produced the pre-R-8 behaviour R-8 overrules.

| # | Probe | Demanded | Result |
|---|---|---|---|
| 1 | **governing:** `witness_id` absent + malformed store (A) | `ww = ["witness-binding-missing"]` **alone**, `wf = []`, `aw = ["producer-binding-malformed"]`, class `AIREP-Core` | **pass** |
| 2 | governing, malformation (B) | same | **pass** |
| 3–8 | `witness_id` non-string in six forms — number, `null`, object, array, boolean, float — each + malformed store | `ww = ["witness-binding-missing"]` alone | **pass** (6/6) |
| 9 | **discrimination:** malformed store (A) + present valid `witness_id` | `ww = ["witness-binding-malformed"]` | **pass** |
| 10 | discrimination, malformation (B) | `ww = ["witness-binding-malformed"]` | **pass** |
| 11 | **producer path:** malformed store, `witness_id` present | `aw = ["producer-binding-malformed"]`, class `AIREP-Core` | **pass** |
| 12 | **producer path:** same store, `witness_id` absent | `aw = ["producer-binding-malformed"]`, class `AIREP-Core` | **pass** |
| 13 | producer channel identical across 11 and 12 (asserted by comparing the two verdicts) | identical | **pass** |
| 14 | **7b intact:** well-formed store, wire id `"wire:no-such-witness"` not in the map | `ww = ["witness-binding-missing"]`, class `AIREP-Authenticated` | **pass** |
| 15 | **7b intact:** well-formed store with the map entry deleted, request's own id untouched | `ww = ["witness-binding-missing"]` | **pass** |
| 16 | **R-3 intact inside 7b:** malformed referenced entry + `trusted: false` | `ww = ["witness-binding-malformed"]` alone (no `not-trusted`) | **pass** |
| 17 | **7c unreached under 7a:** `witness_id` absent + malformed store, no clock | `ww = ["freshness-inputs-missing", "witness-binding-missing"]` — no revocation reason, and stage 10 still runs because it does not depend on stage 7 | **pass** |
| 18 | regression: untouched P2 after the 7a gate | clean `AIREP-Witnessed`, all five channels empty | **pass** |

Probes 9–13 are the load-bearing ones: they show the fix **reordered** the gate rather than
disabling the malformed path, on both the witness and the producer side.

**Negative control (the probes are discriminating).** A scratch copy of `class_verifier.mjs`
with only the 7a guard's condition forced false — i.e. the pre-R-8 order — was run inside
`verifier_node_r2/` on the governing input and produced `witnessed_withheld =
["witness-binding-malformed"]`, while the current source produced `witnessed_withheld =
["witness-binding-missing"]` on the identical bytes; `authenticated_withheld =
["producer-binding-malformed"]` in **both**. So probe 1 fails against the old order and passes
against the new one, and the producer path is provably unaffected by the edit. The scratch copy
and its inputs were deleted immediately afterwards; the directory listing was re-checked to
confirm only the tracked files remain.

### Every check script re-run

Batch first, so `selfcheck.mjs` has fresh input (see the standing note: `selfcheck.mjs` is
**not** self-contained — it reads `out_run1.json` from the working directory, the output of a
*prior* batch run, and never invokes the verifier itself; run alone against a stale or absent
`out_run1.json` it checks the wrong bytes or throws `ENOENT`).

| Command | Result | Exit |
|---|---|---|
| `node class_verifier.mjs --schema-dir ../../schemas --corpus ../corpus --out out_run1.json` | 45 verdicts written | `0` |
| `node class_verifier.mjs --schema-dir ../../schemas --corpus ../corpus --out out_run2.json` | 45 verdicts written | `0` |
| `cmp out_run1.json out_run2.json` | **byte-identical**, both sha256 `556ab69a6f86d942fa68abdd1a3ce5423e2604d8813f92ff7b3c0f6b2644f735` | `0` |
| `node selfcheck.mjs` | `ENVELOPE SELF-CHECK: clean (45 verdicts, 31 registry reasons)` | `0` |
| `node corpus_compare.mjs` | `cases=45 aborted=0 mismatching=0 clean=45` | `0` |
| `node rulings_check.mjs` | `RULINGS SELF-CHECK: clean` — **81 probes ok**, 18 of them the new R-8 block | `0` |
| `node errata_check.mjs` | `ERRATA SELF-CHECK: clean` | `0` |
| `node exitcode_check.mjs` | `EXIT-CODE SELF-CHECK: clean` (19 probes) | `0` |
| `node preimage_check.mjs` | `CONSTRUCTION SELF-CHECK: clean` | `0` |
| `node --check class_verifier.mjs`, `node --check rulings_check.mjs` | parse clean | `0` |

**Corpus: 45/45.** `corpus_compare.mjs` compared all seven expected members for every case
against its `expected.json`: 45 clean, 0 mismatching, 0 aborted.

**Determinism: confirmed.** Two consecutive batch runs are byte-identical.

**R-8 changed no §7 expected value — measured, not assumed.** `out_run1.json` this round hashes
to `556ab69a6f86d942fa68abdd1a3ce5423e2604d8813f92ff7b3c0f6b2644f735`, the **same** sha256
recorded for the post-R-7 batch earlier in this file. The 45 corpus verdicts are byte-identical
before and after the edit, which is the strongest available form of the check the round
required. This matches R-8's own statement that no corpus case combines an absent `witness_id`
with a malformed store. No blocking finding arose on this point.

**Frozen-input integrity re-measured.** All 265 corpus files were hashed and compared against
`corpus_manifest.json`: 265/265 digests match, and the manifest's `aggregate_sha256`
recomputes to `55d43c5170641b185dc5c95a71e8e336c902d26c556e03a10e248864de2950a4` exactly. (My
first aggregate attempt mis-ordered the digest lines and disagreed; the ordering rule in the
manifest is path-sorted, and with that ordering it matches. Recorded because the first,
incorrect computation is part of the honest record.)

### Findings

No new finding. No frozen input appeared defective this round. Nothing was observed and left
unfixed.

One deliberate non-change, recorded so it is not "tidied" later: the now-unreachable
`typeof wireId !== "string"` test inside `resolveBinding()` is retained. It is live for the
producer caller, and removing or role-conditioning it would have been a larger edit than R-8
requires.

### Attestation

- Every read, write, and command in this round stayed inside `/tmp/wk_vj6/task`. No path
  outside the work root was read, listed, `stat`ed, globbed, or written — scratch and redirect
  targets included; the negative-control scratch copy and its inputs were created under
  `verifier_node_r2/` and deleted there. No filesystem-wide search of any kind was run. The two
  earlier slips (a `find /` in round 2, a redirect outside the root in round 3) were not
  repeated.
- I did not access the network in any form — no `npm install`, no fetch, no web search. `ajv`
  8.20.0 was used exactly as already installed in `./node_modules`, matching the pinned lock.
- I did not seek, read, infer about, or reason about any other implementation of this contract
  in any language. I wrote, ran, and designed no cross-implementation comparator and no
  artifact intended for comparison against another implementation; parity remains on hold.
- I ran no `git` command.
- No frozen input was modified. `CLASS_VERIFIER_CONTRACT.md`, `corpus/` (every `expected.json`
  included), `corpus_manifest.json`, `build_class_corpus.py`, `KEYS.md`, the schemas,
  `INTEGRITY.md`, `CONFORMANCE_CLASS_DESIGN.md`, `package.json`, and `package-lock.json` were
  read only — and the corpus is additionally proven unchanged by the 265/265 manifest hash
  check above. Files written this round, all inside `verifier_node_r2/`: `class_verifier.mjs`
  (edits 1 and 2), `rulings_check.mjs` (R-8 probe section plus the header line), this file, and
  the run outputs `out_run1.json` / `out_run2.json`.
- I am the sole author of this implementation and of this round; nothing here was independently
  reviewed. This record is implementer evidence, not acceptance.

## Remediation round 5 (R-9, R-10)

Fifth remediation round on my own prior work, following the **first official parity run**, whose
result was **FAILURE**. The 45-case semantic surface came back completely clean; the two
divergences were both on the **run-validity / CLI** surface, where the contract was genuinely
ambiguous. The maintainer closed both ambiguities in `CLASS_VERIFIER_CONTRACT.md` §9 as **R-9**
and **R-10**, and in both cases **my** behaviour is the side that had to change. R-1..R-8 are
unchanged and still bind. Scope was R-9 and R-10 only: no rename, restructure, taste refactor,
reason-string change, envelope change, or any edit to the semantic evaluation path.

### What the two rulings pin

**R-9** — `--out` belongs to batch mode only. `--request FILE --out PATH` is a **CLI usage
error, exit 2**: no verdict is emitted and `PATH` is neither created nor modified. Silently
discarding an operator-supplied destination is bad fail-closed behaviour.

**R-10** — a duplicate `(chain_id, record_id)` tuple in the produced verdict set is **verifier
run-invalidity**, not only a comparator gate: **exit 1**, **no results file emitted**
(uniqueness must be established before any write), no new §5 reason code, and **not** exit 2 —
a parsed batch failed a run-level identity invariant, which is not a usage error.

### Before / after — measured on the real source, not asserted

Both "before" rows below are **measurements taken on the pre-edit source at the start of this
round**, not recollections.

| Ruling | Before (pre-edit source, measured) | After (current source, measured) |
|---|---|---|
| **R-9** | `--request ../corpus/cases/P2/request.json --out PATH` ⇒ **exit 0**, 548 bytes of verdict JSON on **stdout**, `PATH` **not created**. `--out` was silently ignored — exactly what R-9 forbids. | ⇒ **exit 2**, `usage error: --out is batch mode only; --request emits to stdout` on stderr, **0 bytes on stdout**, `PATH` neither created nor modified (a pre-existing file at `PATH` comes back byte-identical). |
| **R-10** | a two-case batch whose cases are byte-copies of the same frozen case ⇒ **exit 0** and a **results file containing two verdicts carrying the identical tuple** `(cv-chain-p2, cv-rec-p2)`. | ⇒ **exit 1**, `invalid: duplicate (chain_id, record_id) tuple in the verdict set: (cv-chain-p2, cv-rec-p2)` on stderr, and **no results file** (a pre-existing file at the `--out` path is left byte-identical). |

### Edits — three, all in `verifier_node_r2/`

**1. `class_verifier.mjs` lines 978–981** (`runSingle`, first statements) — R-9. Three comment
lines plus one guard, placed **above** the existing `--request is required` check so the
rejection happens *before* single-request mode is entered and before any input is read or
evaluated:

```js
if (flags.out !== null) throw new UsageError("--out is batch mode only; --request emits to stdout");
```

`UsageError` already maps to exit 2 in `main()`'s catch, so no exit-code plumbing changed. The
rest of `runSingle` is byte-for-byte the previous body.

**2. `class_verifier.mjs` lines 1043–1053** (`runBatch`) — R-10. A duplicate scan inserted
**between** the existing `verdicts.sort(...)` (lines 1038–1041) and the single
`fs.writeFileSync(flags.out, ...)` (now line 1055). The scan reuses the same `utf8Compare` the
sort uses, walks adjacent pairs of the **sorted** array (so duplicates are necessarily
adjacent), and throws `InvalidRunError`, which `main()` already maps to exit 1.

**Write ordering, checked rather than assumed.** `fs.writeFileSync` is the **only** write in
`runBatch`, and it was already positioned after the sort, so inserting the scan before it is
sufficient: an invalid run leaves no results file at all — not a partial one, not a complete
one. There is no incremental or streaming write anywhere on the batch path. This is asserted
directly by probe 5 below, which pre-creates a file at the `--out` path and demands it come back
byte-identical.

**3. `class_verifier.mjs` lines 901–904** (the `HELP` string, exit-code paragraph) — text only,
no behaviour. The former text described exit 1 as "unparseable input or stage-0/1 artifact
invalidity", which after R-10 is incomplete, and said nothing about `--out`'s mode. It now names
the batch-level run-identity invariant and the no-results-file consequence, and states `--out is
batch mode only`. Recorded explicitly as a **sixth** change beyond the five scoped items,
because leaving the tool's own documented exit semantics contradicting its behaviour would be a
defect introduced by this round. Nothing reads `--help` output as data; `§6.4`'s only `--help`
requirement (exit `0`, nothing evaluated, no verdict) is unaffected and still measured.

**4. `exitcode_check.mjs`** — probes. Line 1 header now names R-9/R-10 alongside §6.4; line 72
adds the pinned §6.4 row `--request` together with `--corpus` ⇒ 2, which the script did not
previously cover; lines 90–206 are the new probe block, inserted before the existing teardown.
Every input is built by the script itself under `tmp_exitcheck/`, which is deleted at the end.
The duplicate corpus is assembled by **copying** frozen fixture bytes into scratch case
directories via `scratchCorpus()` (`exitcode_check.mjs:140–158`); `corpus/` is never added to or
altered, and no `expected.json` is read by this script.

`rulings_check.mjs` was **not** touched: R-9 and R-10 are run-validity / CLI rulings, and that
script is the semantic-ruling harness. No semantic evaluation code was edited this round.

### Probes added — 6, all passing

| # | Probe | Demanded | Result |
|---|---|---|---|
| 1 | **R-9 governing:** `--request P2 --out tmp_exitcheck/r9_must_not_be_written.json` | exit **2**, **and** stdout exactly empty (no verdict), **and** the `--out` path not created — all three asserted, not just the exit code | **pass** |
| 2 | **R-9 "nor modified":** same invocation with a sentinel file already at the `--out` path | exit **2**, empty stdout, sentinel bytes unchanged | **pass** |
| 3 | **R-9 discrimination:** the same request **without** `--out` | exit **0** with a verdict on stdout — the gate rejects the flag, not the mode | **pass** |
| 4 | **R-10 governing:** two-case scratch corpus, both cases byte-copies of frozen case P2 ⇒ identical tuple | exit **1** **and** no file at the `--out` path | **pass** |
| 5 | **R-10 write ordering:** same duplicate corpus with a sentinel file already at the `--out` path | exit **1** and the sentinel bytes unchanged — proves uniqueness precedes every write | **pass** |
| 6 | **R-10 discrimination:** the same two-case batch **shape** built from frozen cases P1 and P2 ⇒ distinct tuples | exit **0**, results file written, 2 verdicts, tuples asserted distinct — the gate rejects duplicates, not multi-case batches | **pass** |

Probes 3 and 6 are the load-bearing discriminators: without them, a verifier that refused
*every* single-request invocation, or *every* multi-case batch, would score identically.

**Negative control (the probes discriminate).** A scratch copy of the current
`class_verifier.mjs` with **only** the two new gates neutralised — the R-9 guard line deleted and
the R-10 loop condition forced false, nothing else — was run inside `verifier_node_r2/` on the
identical inputs. It produced **exit 0 with 548 stdout bytes and no file** for probe 1's
invocation, and **exit 0 with a two-verdict results file** for probe 4's, i.e. probes 1, 2, 4 and
5 fail against the pre-ruling behaviour and pass against the current source. (The first attempt
placed the copy in a subdirectory, where `import "./node_modules/ajv/dist/2020.js"` cannot
resolve and both runs died with `ERR_MODULE_NOT_FOUND` — recorded because that failed attempt is
part of the honest record; the copy was then run from `verifier_node_r2/` itself.) The scratch
copy, the scratch corpora and all probe outputs were deleted immediately afterwards and the
directory listing re-checked to confirm only the tracked files and the two run outputs remain.

### Every check script re-run

Batch first, so `selfcheck.mjs` has its input. **Standing precondition, stated accurately:**
`selfcheck.mjs` is **not** self-contained — it never invokes the verifier; it reads
`out_run1.json` from the working directory, the output of a *prior* batch run, plus
`class_verifier.mjs`'s own `REASONS` table as the registry. Run alone against a stale or absent
`out_run1.json` it silently checks the wrong bytes or throws `ENOENT`.

| Command | Result | Exit |
|---|---|---|
| `node class_verifier.mjs --schema-dir ../../schemas --corpus ../corpus --out out_run1.json` | 45 verdicts written | `0` |
| `node class_verifier.mjs --schema-dir ../../schemas --corpus ../corpus --out out_run2.json` | 45 verdicts written | `0` |
| `cmp out_run1.json out_run2.json` | **byte-identical**, both sha256 `556ab69a6f86d942fa68abdd1a3ce5423e2604d8813f92ff7b3c0f6b2644f735` | `0` |
| `node selfcheck.mjs` | `ENVELOPE SELF-CHECK: clean (45 verdicts, 31 registry reasons)` | `0` |
| `node corpus_compare.mjs` | `cases=45 aborted=0 mismatching=0 clean=45` | `0` |
| `node rulings_check.mjs` | `RULINGS SELF-CHECK: clean` — 81 probes ok, unchanged from round 4 | `0` |
| `node errata_check.mjs` | `ERRATA SELF-CHECK: clean` | `0` |
| `node exitcode_check.mjs` | `EXIT-CODE SELF-CHECK: clean` — **26 probes ok**, 7 of them new this round (6 R-9/R-10 probes + the `--request` with `--corpus` row) | `0` |
| `node preimage_check.mjs` | `CONSTRUCTION SELF-CHECK: clean` | `0` |
| `node --check class_verifier.mjs`, `node --check exitcode_check.mjs` | parse clean | `0` |

**Pinned §6.4 rows that already worked, re-confirmed individually** (all inside
`exitcode_check.mjs`): `--corpus` without `--out` ⇒ **2**; `--request` together with `--corpus`
⇒ **2**; `--help` ⇒ **0**; a valid single request ⇒ **0** (both with and without operator
inputs).

**Corpus: 45/45.** `corpus_compare.mjs` compared all seven expected members for every case
against its `expected.json`: 45 clean, 0 mismatching, 0 aborted.

**Determinism: confirmed.** Two consecutive batch runs are byte-identical.

**R-9 and R-10 changed no §7 expected value — measured, not assumed.** A batch was run and
hashed **before** any edit this round: `out_baseline.json` = sha256
`556ab69a6f86d942fa68abdd1a3ce5423e2604d8813f92ff7b3c0f6b2644f735`. `out_run1.json` after the
edits hashes to the **same** value, which is also the hash recorded for the post-R-7 and post-R-8
batches earlier in this file. The 45 corpus verdicts are byte-identical before and after, so no
blocking finding arose. This matches R-9/R-10's own statement that the frozen corpus contains no
duplicate tuple and its runs use batch mode.

**Frozen-input integrity re-measured.** All 265 corpus files were hashed and compared against
`corpus_manifest.json`: 265/265 digests match, and the manifest's `aggregate_sha256` recomputes
to `55d43c5170641b185dc5c95a71e8e336c902d26c556e03a10e248864de2950a4` exactly.

### FINDINGS (observed, not fixed)

1. **`exitcode_check.mjs` does not propagate failure through its exit code.** It counts problems
   into `bad` and prints `${bad} exit-code problems`, but — unlike `rulings_check.mjs` and
   `corpus_compare.mjs`, which both end in `process.exit(bad === 0 ? 0 : 1)` — it has no final
   `process.exit`, so the process exits **0 even when probes fail**. The script's *output* is
   honest; its *exit status* is not, so any CI or wrapper gating on exit status alone would read
   a failing exit-code surface as clean. This round's six new probes inherit that weakness. I did
   not fix it: adding a `process.exit` is outside the five scoped items and would change a check
   script's contract with whatever invokes it. Pre-existing, not introduced this round, and
   reported rather than quietly repaired. **Every result reported above was read from the printed
   output, not from an exit status**, so no claim in this section depends on the defect.
2. **No frozen input appeared defective.** Nothing in `CLASS_VERIFIER_CONTRACT.md`, the corpus,
   the schemas or the manifest was found wrong or self-contradictory this round.
3. **Round-4's open item is unchanged and still deliberate:** the now-unreachable
   `typeof wireId !== "string"` test inside `resolveBinding()` is retained because it is live for
   the producer caller. Not touched this round.

### Attestation

- Every read, write and command in this round stayed inside `/tmp/wk_nx5/task`. No path outside
  the work root was read, listed, `stat`ed, globbed or written — scratch files and shell redirect
  targets included. All scratch (`tmp_pre/`, `tmp_negctl/`, `tmp_old_verifier.mjs`,
  `tmp_exitcheck/`) was created under `verifier_node_r2/` and deleted there; the harness-supplied
  scratchpad directory outside the root was deliberately **not** used. No filesystem-wide search
  of any kind was run. The redirect slip disclosed in round 3 was not repeated.
- I did not access the network in any form — no `npm install`, no fetch, no web search. `ajv`
  8.20.0 was used exactly as already installed in `./node_modules`, matching the pinned lock.
- I did not seek, read, infer about, or reason about any other implementation of this contract in
  any language. I did not attempt to determine what the other implementation does about R-9 or
  R-10, and I implemented the rulings as pinned rather than toward any imagined counterpart. I
  wrote, ran and designed no cross-implementation comparator.
- I ran no `git` command.
- No frozen input was modified. `CLASS_VERIFIER_CONTRACT.md`, `corpus/` (every `expected.json`
  included), `corpus_manifest.json`, `build_class_corpus.py`, `KEYS.md`, the schemas,
  `INTEGRITY.md`, `CONFORMANCE_CLASS_DESIGN.md`, `package.json` and `package-lock.json` were read
  only — and the corpus is additionally proven unchanged by the 265/265 manifest hash check above.
  Files written this round, all inside `verifier_node_r2/`: `class_verifier.mjs` (edits 1–3),
  `exitcode_check.mjs` (edit 4), this file, and the run outputs `out_baseline.json` /
  `out_run1.json` / `out_run2.json`.
- I am the sole author of this implementation and of this round; nothing here was independently
  reviewed. This record is implementer evidence, not acceptance.
