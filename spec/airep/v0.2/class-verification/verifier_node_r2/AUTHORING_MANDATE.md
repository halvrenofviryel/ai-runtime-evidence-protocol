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
