# Node reference interop evaluator

The Node lane of `INTEROP_REFERENCE_EVALUATOR_CONTRACT.md` (AD15-IR-2). Authored and remediated
in isolation from the Python lane: no shared reconciliation code, no shared helper, no port, and
no sight of the peer lane's source or output.

Contract basis: the canonical post-Erratum-5 head
`e95713e546bd49e47669526aa241227ea678dd66`, with both canonical contracts asserted before any
source was edited:

| File | sha256 |
|---|---|
| `INTEROP_REFERENCE_EVALUATOR_CONTRACT.md` | `f1ca998c375b7a0ffc42aefc996d25ef254cfecc2e2d435c76f430f1b7c038bf` |
| `INTEROP_CORPUS_CONTRACT.md` | `ac15ec39dd738d5c4ab6cba03aad92682a0f1b3af1d613ff88b26f2f4587d8bd` |

Lineage, frozen as evidence and never rewritten: `da22e066a6aceaa72b9bda2fb8813205120fe0ff`
(pre-Erratum-1), `801a1dc1a056ab65e20d735c83cf04a28c1fb45d` (Erratum-2 candidate),
`4b14328d67ea36f7657db8b3b4765bf3e187e639` (pre-Erratum-3 micro-remediation candidate),
`c801d5058c5538de0fd0fb414a68041538806f0e` (post-Erratum-3 final candidate, r1),
`7c873428f54d2707d414492eeb931e565a3f04bc` (post-Erratum-4 candidate, r2). None of those is
an official evaluator identity; the ref named `w1/interop-eval-node-official` predates its
demotion to evidence, which is why this lane lives on `w1/interop-eval-node-final`.

```
node interop_eval.mjs --bundle DIR
                      [--bindings FILE] [--independence-policy FILE] [--revocation FILE]
                      [--verifier FILE] [--verifier-contract FILE]
```

One invocation evaluates one bundle and writes one JSON result object. No case discovery. The
aggregate harness — not this program — performs the twelve fixed invocations and the five
run-level duties of §8.1.

## Exit and stdout (§8.5)

The dividing line is **whether bundle identity was established**, and nothing else.

| Exit | stdout | Condition |
|---|---|---|
| `0` | one result object, `MEASURED`, `level1` populated | the bundle was measured |
| `1` | empty | bundle identity could not be established under §5's **direct-read** identity boundary, and only that (Erratum 4): the bundle root cannot be accessed · `manifest.json` is not found · it is found but cannot be opened or read · its bytes do not parse as strict JSON · no registered `scenario_id` can be obtained |
| `2` | empty | CLI usage error |
| `3` | one result object, `MEASUREMENT_INVALID` or `ERROR`, `level1: null`, `predicates: null`, `nonmeasurement` populated | identity established, scenario not measured |

`--help` is outside this table entirely (Erratum 3): it is a **CLI meta-action, not an
evaluation** — exit `0`, human-readable help on stdout, no result object, no `--bundle` required,
and the aggregate harness never invokes it.

Erratum 4 pins how wide that carve-out is: **one exact invocation, not one concept.** The
meta-action is the **single-token invocation `--help` and nothing else**. `-h` is **not** an alias
— it is a CLI usage error, exit `2`, no result object. `--help` alongside any other argument,
however valid that argument is, is likewise a usage error at exit `2`. Help text content and byte
length are **not** a parity requirement, so nothing compares them across lanes. Every other CLI
usage error remains exit `2` with empty stdout.

Diagnostics go to stderr, carry no semantics, and are never parsed — by this program or by the
harness. Frozen-verifier stderr is hashed for audit only.

**`exit 0` with empty stdout is unacceptable under every condition** (`NODE-IMP-1`). Three
mechanisms hold that line: direct-invocation detection that cannot be defeated by percent-encoding,
a synchronous complete write of the result object rather than an async `process.stdout.write` that
a subsequent `process.exit()` could truncate, and a process-exit invariant that converts a silent
zero into exit `3` with a diagnostic. The invariant is **keyed on invocation kind**, so `--help`
did not relax it: an evaluation exiting `0` must still have written a *result object*, exactly as
before Erratum 3, while the meta-action must have written help. Both branches are regressed. Both defect routes and their regressions are set out under
[`NODE-IMP-1` — both routes](#node-imp-1--both-routes-and-how-each-is-regressed) below.

## Frozen verifier

Invoked as a subprocess; never imported, vendored, re-implemented or modified. Its digest and the
digest of `CLASS_VERIFIER_CONTRACT.md` are asserted before use and emitted as **this lane's own
two entries** (§8.2.1):

```jsonc
{ "class_verifier": "sha256:…", "class_verifier_contract": "sha256:…" }
```

**Frozen-identity preflight order (Erratum 5, E5-4).** The read is pinned to run **immediately
after bundle identity, before any other post-identity preflight**:

1. bundle identity is established by the §5 direct read of the root manifest;
2. immediately afterwards, this lane's own frozen pair is read and SHA-256'd;
3. if **either cannot be read** → exit `3`, `frozen-identity-unreadable`,
   **`verifier_digests: null`**, `artifacts: []`;
4. if both are read, the exact two-entry object is built from the **recomputed** values;
5. if a recomputed value does not match its pin → `verifier-digest-mismatch`, and the **actual
   recomputed** two-entry object is **retained** — a reader needs to see what was actually there,
   not what was expected;
6. only then do bundle traversal and the remaining preflight begin.

Because step 2 precedes all other post-identity work, **every other post-identity result carries a
populated `verifier_digests`**, and no placeholder is ever emitted. `null` is reserved for
`frozen-identity-unreadable` **alone**.

This supersedes what this lane did before: the assertion ran at the *end* of preflight, so every
manifest, layout, shape or numeric failure emitted `verifier_digests: null`, and an unreadable
frozen file was reported as a **mismatch** carrying a two-entry object with `null` members. Both
halves were wrong — it fabricated a placeholder for a file it never read, and asserted a
comparison it never performed.

**The Python lane's verifier digest appears nowhere** — not in the output, and not as a constant
in this source. §3 forbids this lane from reading the peer verifier, so it cannot assert a digest
for it; cross-lane verifier identity is the aggregate harness's duty, and the harness legitimately
sees both trees. `selftest.mjs` asserts the absence in both the source and the output.

Cross-lane envelope-digest comparison is **not** implemented, by ruling `AD15-IR-4`. This program
emits only its own `request_envelope_digest`, per artifact.

## Ordering

Full bundle preflight completes before any frozen verifier is invoked (§8.3.1): manifest, symlink
and path rules, disk/manifest closure both ways, digests, JSON parseability, bundle shape,
operator-input composition, numeric envelope. The **frozen-verifier identity read is no longer
last** — Erratum 5 moved it to step 2, immediately after bundle identity. A failure during
preflight is a pre-invocation `ERROR` carrying `artifacts: []` — an empty array, never entries
with placeholder fields. Once invocation begins, `artifacts[]` carries an entry for each
invocation that produced an exit code, and no more.

### One ordering key, everywhere (`AD15-IR-5` + `AD15-IR-6`)

| Layer | Ordered by | Pinned in |
|---|---|---|
| `artifacts[]` result entries | UTF-8 byte order of **`artifact_path`** | §8.3.1, §8.4 |
| aggregate cross-lane comparison key | **`(scenario_id, artifact_path)`** | §8.1 duty 2 |
| `related_artifacts` inside a request envelope | UTF-8 byte order of **`artifact_path`** | §5.1, **`AD15-IR-6`** |

`AD15-IR-6` moved the last `record_id`-keyed surface — envelope ordering — onto `artifact_path`,
so there is now **one comparator** rather than two. This lane's Erratum-2 candidate deliberately
kept them apart, on the reading that `AD15-IR-5` had left §5.1 alone, and sorted an artifact with
no usable `record_id` under an empty key with an `artifact_path` tiebreak. That resolution is
**superseded**: it was one of two defensible readings across the two isolated lanes, and neither
was cross-lane safe, because a differing `related_artifacts` order changes
`request_envelope_digest` — precisely what aggregate duty 2 compares. `compareByRecordId` is
therefore **deleted**, not left unused.

Why `artifact_path` is the right key: the manifest lists every file and `files[]` forbids a
duplicate path, so it always exists and is unique. No tiebreak is needed or permitted, and the
envelope is **always defined** — including for an artifact carrying no `record_id` at all, which
under the superseded rule had no defined envelope and therefore no defined
`request_envelope_digest`.

The self-test asserts this against a four-artifact fixture whose `record_id` rank is the **exact
reverse** of its `artifact_path` rank, so the two orders disagree for *every* choice of primary,
plus a per-primary control proving the two orderings really do yield different envelope bytes. An
earlier arrangement of that fixture left the other three artifacts coincidentally in the same
order when the record_id outlier was primary — the control caught it, and it was fixed rather than
accepted.

**R-A is unchanged**: reference resolution still matches on `record_id`, additionally `chain_id`
where carried, and `resolveRef` is the only remaining reader of `record_id`. The manifest path is
harness and result identity only — never wire semantics.

`artifact_path` is required and always exists, because the manifest lists every file.
`artifact_ref` is an object when a usable `record_id` exists and **`null`** when it does not.
**No `record_id` is ever synthesized**, for any reason: an artifact that must be rejected at
stage 0 now reaches that stage-0 evaluation instead of being converted into this evaluator's own
preflight failure.

## Running

**Official evidence command** — both lines, in this order, as a non-root user:

```
python3 ../../class-verification/offline-node-deps/materialize_node_modules.py   # frozen verifier deps, offline
node selftest.mjs
```

`node_modules/` is generated and git-ignored; it is never committed.

### The summary is three numbers (contract §13 step 5)

```
961 passed / 0 failed / 0 skipped
```

A block whose precondition this machine cannot produce is **not measured**. It is neither a pass
nor a failure, so it is reported beside them rather than deducted from the denominator, and every
skipped block is named:

```
807 passed / 0 failed / 2 skipped
NOT MEASURED (2): live frozen-verifier checks (section 13 / AD15-IR-6 fixture); E5-5 end-to-end scenario-independence
```

| Exit | Meaning |
|---|---|
| `0` | everything that ran passed, and everything ran |
| `1` | something ran and **failed** — the stronger finding, so it outranks an unmeasured block |
| `2` | everything that ran passed, but some block was **not measured** (default mode), or the arguments were not understood |

`--allow-skips` makes an unmeasured block non-fatal. It is **developer-only**: an official count is
a claim about every block, and that flag is exactly the licence to make the claim while some of
them did not run. **The official evidence command above must not use it.**

**Why this exists.** This file previously reported `X/Y checks passed` with skipped blocks absent
from *both* numbers, so a run missing its dependencies printed green — `774/774` on the inherited
candidate — while the entire live frozen-verifier block, the `AD15-IR-6` reverse-ranking fixture
included, never executed. Erratum 6's evidence-narrowing note records that against this lane's own
earlier counts. A green summary that omits what it did not measure is the failure class the whole
contract is built to prevent, so the summary now cannot omit it.

Two conditions make blocks unmeasurable here and are worth knowing before reading a count:
running as **root** (euid 0 defeats the permission bits several filesystem conditions are built
from) and **unmaterialized frozen-verifier dependencies**.

`selftest.mjs` uses synthetic inputs constructed inside the file. It creates no corpus bytes and
no scenario bundle artifacts; corpus construction is on hold (contract §13).

**Not covered by the self-test, stated plainly:** the `MEASURED` end-to-end path over sealed,
signed, bound artifacts — a clean `ACCEPT`, the three reconciliation-negative verdicts, and
`IOP-B-EXE`'s Authenticated-tier failure — cannot be exercised until the corpus exists. What is
covered is the CLI/exit table, the pinned manifest encoding, bundle and operator-input shape, the
numeric preflight including its mandatory JSON Pointer, the closed `nonmeasurement` registry and
its status pairing, envelope construction and ordering, the §7.2 causal guard in both directions,
reference resolution, all three predicates, the Level-1 mapping order, the Erratum 2 rulings
(§14 bundle layout, §15 both frozen-run bands, and `AD15-IR-5` identity and ordering inside §13),
the four Erratum 3 rulings (`AD15-IR-6` envelope ordering and the `record_id`-less artifact in
§13, the four-way filesystem reason boundary in §14b, no-manifest-discovery in §14c, and the
`--help` meta-action in §10/§11), the four Erratum 4 rulings (the narrowed help carve-out in
§10/§11, the direct-read identity boundary in §14d, `bundle-directory-unreadable` in §14e, and
`AD15-IR-7` in §14f), the Erratum 5 closures (§17a frozen-identity read-vs-match and preflight
order, §17b `bundle-entry-uninspectable`, §17c `AD15-IR-8` monotonic identity, §17d
scenario-independent `authenticated_withheld`), the two Erratum 6 rulings measured in §18
(`AD15-IR-10` run-validity-before-tier-withheld and `AD15-IR-11` spawn-failure entries), and
**both** `NODE-IMP-1` routes (§12 path, §16 pipe truncation).

`AD15-IR-9` needs no behavioural change in this lane: `walkBundle` already performs an explicit
`lstat` per enumerated entry and never reads a kind off the `Dirent`, and §17b measures that on a
constructed `0o444` directory. Its discrimination was verified by mutation — trusting the `Dirent`
kind yields `bundle-file-unreadable` instead of `bundle-entry-uninspectable`, which is exactly the
cross-lane divergence the ruling pins.

§18 replaces **the frozen verifier subprocess and nothing else**: the module under test is the
real `interop_eval.mjs`, entered through its real exported `main()`, with the real preflight and
the real frozen-identity digest assertion against the genuine frozen files. Both rulings are
unreachable through an ordinary run — this lane spawns `process.execPath` with the verifier as an
argument, so a spawn that *fails* cannot arise from a missing verifier, and no real verifier emits
a withheld channel and an impermissible exit on the same bundle on demand.

Several of those sections carry their own controls, because a regression that cannot fail proves
nothing: §16 first measures that the buggy write pattern really does truncate on this platform;
§13's four-artifact fixture is built so `artifact_path` order and `record_id` order **disagree**
for every choice of primary, and each envelope check is paired with a control asserting the two
orderings really do yield different bytes; §14b asserts that the four filesystem reasons are
**pairwise distinct**, which fails if any two collapse even though each individual assertion would
still pass; §14b's unreadable case first verifies the file genuinely cannot be read before the
assertion is allowed to count, and skips rather than fakes where the platform cannot produce the
condition — every such skip being counted and named in the summary, never absorbed; and §14c uses a byte-for-byte *valid* manifest under a wrong name, so it discriminates
discovery rather than mere absence.

§14d skips rather than fakes each permission-dependent identity condition, and asserts a control
that the condition was really produced first; §14e does the same for the unenumerable directory
and then requires `bundle-directory-unreadable`, `manifest-invalid`, `bundle-file-missing` and
`bundle-file-unreadable` to be **pairwise distinct**, with a negative control that a *readable*
nested directory yields no directory reason at all; §14f pairs the duplicate-`record_id` bundle
with an otherwise identical unique-`record_id` control, so the assertion is about the absence of a
gate rather than about some other property of the fixture.

§17a requires the unreadable and mismatch cases to differ in **`verifier_digests` nullability**,
not merely in the reason string, and sweeps seven distinct post-identity failures to assert each
carries a populated member — the assertion that actually measures the preflight-order move. §17b
and §17c measure the permission condition they depend on before asserting anything, and skip
rather than fake it; §17b additionally requires `bundle-entry-uninspectable`,
`bundle-directory-unreadable` and `manifest-invalid` to be pairwise distinct, with a negative
control that an ordinary bundle never yields the new reason. §17d carries a control that the probe
artifact really reaches the Authenticated tier with a non-empty withheld channel and **no**
failures, and a negative control in which a resolved producer binding leaves
`authenticated_withheld` empty while `witnessed_withheld` stays populated — which must be a
`MEASURED` `REJECT`, not a measurement failure. Without that pair, an implementation treating *any*
withheld channel as invalid would pass.

Beyond those in-suite controls, each Erratum 3, Erratum 4 and Erratum 5 fix was
**mutation-tested**: the fix was reverted in turn and the corresponding checks confirmed to fail. A test that passes both with
and without the fix measures nothing, and that is not assumed here.

One limit of that coverage, stated because it would otherwise be overclaimed: the envelope-digest
checks recompute their expected value with this module's own `jcs()` and `byteCompare()`, so they
prove the *pipeline* around the canonicalizer, not the canonicalizer. Exactly one check does not —
a canonical byte string and digest produced outside this module (Python
`json.dumps(sort_keys=True, separators=(",", ":"))`, which coincides with RFC 8785 for ASCII keys
and integer numbers) is asserted as a literal. Envelope-byte equality across lanes is the property
`AD15-IR-4` hands to the aggregate harness, and that is where it is actually measured.

## Bundle manifest

The encoding is now pinned exactly by §5 and is no longer an assumption. `manifest.json` in the
bundle root.

**No manifest discovery is performed** (Erratum 3). The lookup is a single
`path.join(bundleDir, "manifest.json")` — no fallback name, no search, no walk for a
manifest-shaped file. If the root manifest is absent, bundle identity is not established, so the
result is exit `1` with empty stdout, never `manifest-invalid` — that reason would require a
`scenario_id` the evaluator does not have. A wrongly-named or misplaced file sitting *beside* a
valid root manifest needs no special rule: it is an unlisted regular file, or a listed entry with
an invalid `role`, and the ordinary layout rules make it `manifest-invalid`.

**The identity boundary is a direct read** (Erratum 4). That `readFileSync` is the *first*
filesystem operation performed on the bundle: nothing is enumerated, stat-ed or listed beforehand,
and `walkBundle()` does not run until a usable `scenario_id` exists. That ordering is what makes
an inaccessible bundle root, an absent manifest and an unreadable manifest collapse into the same
exit-`1` band — they are indistinguishable *to the evaluator* precisely because none of them
yields an identity to name a reason against. **A root manifest that cannot be read never yields
`bundle-file-unreadable`:** the root manifest is not a `files[]` entry, and a reason belongs to a
result object that has no scenario to be about.

```jsonc
{
  "manifest_version": "1",
  "scenario_id": "IOP-R-CLEAN",
  "files": [
    { "path": "artifacts/decision.json", "role": "artifact", "sha256": "<64 lowercase hex>" }
  ]
}
```

Enforced: the object is closed to exactly three members; each `files[]` entry is closed to exactly
`path` / `role` / `sha256`; `sha256` is bare 64 lowercase hex, never the `sha256:…` wire form;
`role` comes from the closed set `artifact` · `bindings` · `independence_policy` · `revocation` ·
`clock`; `files` is sorted strictly ascending by `path` in UTF-8 byte order; paths are
bundle-relative and normalized, with no absolute path, `..` segment, backslash or duplicate;
`files` covers every regular file under the bundle **except the root `manifest.json`**, in both
directions; symbolic links are forbidden anywhere under the bundle, including one whose target
resolves inside it.

Bundle shape: `IOP-P-*` and `IOP-B-*` carry exactly one artifact, `IOP-R-*` exactly four — one
each of Decision, Control, Execution and Effect. Operator inputs, official W1: exactly one
`bindings`, one `independence_policy`, one `revocation`, and no `clock`. `head_witness` is absent
from every official W1 bundle and the closed role set has no way to carry one, so the request
envelope never contains one.

The optional operator-input flags are **assertions**, not substitutions: each must name the
bundle's own file already carrying that role, and a disagreement is a usage error. There is no
route by which foreign operator bytes reach the frozen verifier.

## Erratum 2 — what changed in this lane

Three rulings landed on this evaluator. Each replaced a place where this lane had recorded an
open ambiguity rather than inventing a resolution, which is why the changes are small.

| Ruling | Was (recorded as ambiguity) | Now |
|---|---|---|
| **E2-1** bundle layout | `manifest-invalid` chosen by this lane, flagged as "a dedicated reason would be clearer" | normative: `manifest-invalid` covers the whole bundle-layout surface, enumerated |
| **E2-2** abnormal frozen runs | `verifier-run-invalid` chosen by this lane, flagged as "no other registry value fits" | normative: `verifier-run-invalid`; `verifier-not-invocable` narrowed to *could not be spawned at all*; `internal-error` narrowed to *this evaluator's own fault* |
| **E2-3** / `AD15-IR-5` | `artifact_ref` assumed a `record_id`; this lane omitted the member and sorted under an empty key | `artifact_path` required and is the identity; `artifact_ref` is `object \| null`; ordering by `artifact_path` |

**One behavioural change came out of E2-1**, not merely a wording change: a `files[]` entry whose
target is present on disk but is **the wrong kind** — a directory above all — was previously
reported as `bundle-file-missing`. Nothing is missing in that case, so it is now
`manifest-invalid`. A `files[]` entry with nothing on disk at all remains `bundle-file-missing`;
the enumeration did not swallow that row, and the self-test asserts both directions.

**E2-2 changed the process band.** `spawnSync` reports an unspawnable binary *and* a process that
started and was then killed through the same `error` member, so a classifier keyed on `error`
puts both in one band — the collapse E2-2 forbids. The discriminator is `pid`, and the shapes were
**measured on this runtime rather than assumed**: a spawn that never happened returns `pid 0` with
`ENOENT`, while a process killed for exceeding `maxBuffer` (`ENOBUFS`), one killed by a timeout
(`ETIMEDOUT`) and one killed by a signal all carry a real pid. Those three started, so they moved
from `verifier-not-invocable` to `verifier-run-invalid`.

Both bands are now pure exported functions (`classifyProcessShape`, `classifyVerdictStdout`).
That is not tidiness: reaching a misbehaving stub verifier *through* the evaluator is impossible
by design, because the frozen digest assertion runs first and rejects any stub, so the bands would
otherwise be untestable.

## `NODE-IMP-1` — both routes, and how each is regressed

The erratum records two independent routes to the same forbidden output, **exit `0` with empty or
incomplete stdout**. Both are closed, and each has a regression that is demonstrably able to catch
it.

1. **Literal-space path** (§12). `new URL(import.meta.url).pathname` is percent-encoded, so on a
   repository path containing a literal space — or `#`, or any non-ASCII character — the
   direct-invocation guard compared an encoded string against a decoded one, evaluated false, and
   the program did nothing at all.

   `isDirectInvocation()` now tests three ways, and a failure of any one is not a failure of the
   guard:

   1. `pathToFileURL(process.argv[1]).href === import.meta.url` — both sides are produced by
      Node's own URL machinery, so their escaping is symmetric by construction. This is the
      comparison the original defect had backwards.
   2. `path.resolve(argv[1])` against `fileURLToPath(import.meta.url)` — decoded on both sides.
   3. `fs.realpathSync` of both — catches a symlinked or otherwise differently spelled entry
      point.

   §12 runs the evaluator from directories named `dir with space`, `dir#with#hash`, `dizin ünlü`
   and `dir with  two  spaces`, asserting the full exit/stdout table in each and asserting
   directly that no invocation exits `0` with empty stdout.
2. **Pipe-backed truncation** (§16). `process.stdout.write` is asynchronous on a pipe, so a
   following `process.exit()` truncates or drops the payload. Closed by `writeStdoutSync` looping
   on `fs.writeSync`, and by the entry point setting `process.exitCode` rather than calling
   `process.exit()`.

§16 opens with a **control**: it first measures that the *buggy* pattern really does truncate on
the host platform. On this machine 2,000,000 bytes arrive as 219,264 with exit `0`. Without that
control a green truncation regression would prove nothing, so if the platform ever stops
exhibiting the defect the section reports itself as unable to discriminate instead of passing
quietly.

**`exit 0` with empty stdout remains unacceptable under every condition**, and the process-exit
invariant converts a silent zero into exit `3` with a diagnostic.

## Erratum 3 — what changed in this lane

Four rulings landed. Two of them closed ambiguities this lane had **recorded rather than
invented**, which is why those changes are small; the other two corrected behaviour.

| Ruling | Change here |
|---|---|
| **E3-1** (`AD15-IR-6`) | `related_artifacts` now ordered by `artifact_path`. `compareByRecordId` deleted; the deliberate two-comparator split is **collapsed on purpose**. Closes recorded ambiguity 3. |
| **E3-2** | New reason `bundle-file-unreadable`. A listed file that is present and a permitted regular file but whose bytes will not read is no longer reported as `bundle-file-missing` — which said something false about the bundle. A definite `ENOENT` still means missing. |
| **E3-3** | The Erratum-2 enumeration comment no longer lists "a manifest with the wrong name or location" under `manifest-invalid`. No manifest discovery is performed and none was: the lookup is a single `path.join(bundleDir, "manifest.json")`. A bundle whose only manifest-shaped file is wrongly named exits `1` with empty stdout. |
| **E3-4** | `--help` is a CLI meta-action: exit `0`, help on stdout, no result object, no `--bundle` required. Closes recorded ambiguity 7, which this lane had resolved the other way because the pre-erratum §8.5 made exit `0` unsatisfiable for a help screen. |

Each ruling has a self-test that **discriminates it specifically** — verified by reverting each
fix in turn and confirming the corresponding checks fail, rather than by assuming the tests have
teeth. The `NODE-IMP-1` regressions (both routes) are preserved unchanged and still pass,
including the control that measures the buggy async-write-then-exit pattern actually truncating on
the host platform.

## Erratum 4 — what changed in this lane

Four rulings landed. Two changed behaviour here, one changed a reason code, and one **confirmed**
that a gate this lane never had must never be added.

| Ruling | Change here |
|---|---|
| **E4-1** help carve-out | The meta-action is now the **single-token invocation `--help`** and nothing else. `-h` is no longer an alias and is an ordinary usage error at exit `2`; `--help` alongside any other argument is likewise exit `2`. Help content is explicitly not a parity requirement, so nothing asserts its bytes. |
| **E4-2** identity boundary | No behavioural change — the lookup was already a direct read of `DIR/manifest.json` before anything was enumerated — but the five conditions are now enumerated in the source and each is regressed, including the two that discriminate an enumerate-first implementation. |
| **E4-3** `bundle-directory-unreadable` | New registry row. A directory that cannot be enumerated after identity is established is no longer reported as `manifest-invalid`. Closes recorded ambiguity 5. |
| **E4-4** / `AD15-IR-7` | No change: this lane has never carried a duplicate-`record_id` preflight gate. The ruling is now regressed so one cannot be added silently, and `resolveRef` — where the condition belongs — is asserted to report **ambiguous** rather than picking a match. |

**E4-1 is the one with a measured cost.** The erratum records a real cross-lane divergence on
`-h`: one lane refused it, one accepted it, both from the same sentence. **This lane was the one
that accepted it.** That divergence is unreachable by the official harness, which never invokes
help, so it would never have made a run non-qualifying — but it was still two implementations
behaving differently under a rule both had read, which is exactly what the isolated-lane exercise
exists to surface.

**E4-3 closes an ambiguity this lane recorded rather than invented.** The pre-Erratum-4 source
reported `manifest-invalid` for an unenumerable directory and said in the same comment that this
was arguably the same shape Erratum 3 had just closed one level down — "the layout violates a
rule" is as questionable a thing to say about a faulty medium as "the file is missing" was.
Resolving it unilaterally would have meant adding a registry row, which needs an erratum. It got
one.

**The `NODE-IMP-1` regressions are preserved unchanged and still pass**, both routes, including
the control that measures the buggy async-write-then-exit pattern actually truncating on this
platform. E4-1 narrows *what counts as the meta-action*, and the process-exit invariant guard is
keyed on **invocation kind** rather than on stdout in general, so narrowing the help spelling did
not weaken what an evaluation exiting `0` must satisfy: it must still have written a result
object.

## Erratum 5 — what changed in this lane

Five closures landed. Three changed behaviour here, one added a registry row, and one closed a
recorded ambiguity by pinning the reading this lane had already taken.

| Closure | Change here |
|---|---|
| **E5-1** / `AD15-IR-8` identity is monotonic | No behavioural change — this lane already resolved the `0o111` overlap to exit `3` with `bundle-directory-unreadable`, on §8.5's dividing-line sentence. The ruling pins it, so **recorded ambiguity 8 is closed and the case is now regressed** rather than deliberately left unasserted. |
| **E5-3** `bundle-entry-uninspectable` | New registry row, and a real behavioural change. Entry kind is now determined by an **explicit `lstat`**, not read off the `Dirent`. An entry whose name was enumerated but whose kind could not be inspected is no longer folded into `manifest-invalid`. |
| **E5-4** frozen-identity preflight | Behavioural change on two axes: the read **moved to step 2**, and **unreadable is separated from mismatch**, with `verifier_digests: null` reserved for the former. **Closes recorded ambiguity 1.** |
| **E5-5** scenario-independent withheld | No behavioural change — this lane never had an expected-tier table — but the rule is now **structurally** unable to reach one: the decision is a pure function taking only the withheld records, with no `scenario_id` parameter. |
| **E5-2** | Contract text only; nothing here. |

**E5-3 is the one with a measured surprise.** `readdirSync(..., { withFileTypes: true })` populates
a `Dirent`'s kind from the directory's `d_type`, and on a readable-but-non-searchable directory
(mode `0o444`) it still reports "regular file" while `lstat` on the same entry fails `EACCES`.
Trusting `d_type` would therefore claim to have learned a kind that was never established — and
would make the new reason unreachable on exactly the filesystems that populate `d_type`, so the
behaviour would depend on the filesystem rather than on the bundle. The explicit `lstat` makes
kind determination uniform. Measured here, not assumed:

```
readdir OK, names: [ 'f.txt' ]   Dirent.isFile() = true
lstat  f.txt -> EACCES
```

**E5-5 removes an oracle rather than a behaviour.** The superseded wording made the rule depend on
what a scenario *expected*, which requires a per-scenario expected-tier table no evaluator has and
none should have — consulting an expected-outcome oracle is what a measuring instrument must not
do. The self-test measures the removal two ways: the decision function's arity is asserted, and the
same artifact under **all eight** single-artifact scenario ids is required to give **one** outcome.
Under a reintroduced oracle the four `IOP-B-*` bundles return `MEASURED` / `level1: ACCEPT` at exit
`0` — a qualifying green result laundered from a tier that was never evaluated, which is precisely
the failure §7.1 exists to prevent.

**The `NODE-IMP-1` regressions are preserved unchanged and still pass**, both routes, including the
control that measures the buggy async-write-then-exit pattern actually truncating on this platform.
The `AD15-IR-6` reverse-ranking fixture is likewise preserved: `record_id` rank remains the exact
reverse of `artifact_path` rank, so no choice of primary lets the two orderings coincide.

## Recorded ambiguities — not resolved here

Erratum 2 closed three of the eight this lane carried, Erratum 3 closed two more (3 and 7 below,
struck through) while surfacing a new one (5), Erratum 4 closed that one in turn while surfacing
one more (8), and Erratum 5 closed both 1 and 8. **Three remain**, recorded rather than invented,
and each is marked at the point of use in the source.

1. ~~**`verifier_digests` before or across a failed assertion.**~~ **CLOSED by E5-4.** The gap
   recorded here — that §8.2.1 pinned the shape as two strings but not what to emit when the
   assertion had not run, or when a file could not be read at all — is now pinned in full: a
   dedicated `frozen-identity-unreadable` reason with `verifier_digests: null`, the recomputed
   two-entry object retained across a mismatch, and a preflight order that puts the read
   immediately after identity so **every other** post-identity result carries a populated member.
   This lane's earlier resolution — `null` members inside a two-entry object, reported as a
   mismatch — is superseded on both counts.
2. **An invocation attempted but never spawned.** §8.3.1 says `artifacts[]` carries an entry for
   each invocation attempted, but every field except `artifact_ref` is a product of an invocation.
   A spawn that produced no exit code has no representable entry, so it is omitted and named in
   `nonmeasurement.detail` — following that section's own rule that no implementer invents an exit
   code, and its principle that absence is represented by absence. E2-2 narrowed the reason for
   this case to `verifier-not-invocable` but did not pin the `artifacts[]` shape.
3. ~~**`related_artifacts` ordering when an artifact carries no usable `record_id`.**~~
   **CLOSED by `AD15-IR-6` (E3-1).** §5.1 now orders `related_artifacts` by `artifact_path`, which
   always exists, so the envelope is always defined and the empty-key resolution this lane had
   recorded is superseded. The concern recorded here — that the choice was *not cross-lane safe* —
   was exactly right: the peer lane resolved it differently, and the erratum ruled rather than
   letting either stand.
4. **An unexpected fault before identity is established.** `internal-error` is defined as a fault
   *after* identity. Before it there is no scenario to name, so the exit-`1` band applies, per
   §8.5's statement that the dividing line is whether identity was established and nothing else.
   The enumeration in the exit-`1` row does not list this case.
5. ~~**An unreadable bundle DIRECTORY.**~~ **CLOSED by E4-3.** The concern recorded here — that
   reporting `manifest-invalid` for a faulty medium is the same shape E3-2 closed one level down —
   was upheld, and the peer lane recorded the same discomfort independently. The registry now
   carries `bundle-directory-unreadable`, which says the layout could not be *measured* rather
   than that it is *wrong*. The file-level distinctions are unchanged.
6. **Duplicate member names inside `manifest.json`.** "not parseable as strict JSON" is not pinned
   to reject them. `JSON.parse` keeps the last occurrence, as most JSON libraries do, so the
   closure check sees one member. This is left as the library default deliberately: tightening it
   unilaterally would be a rule the peer lane has no reason to share.
7. ~~**`--help`.**~~ **CLOSED by E3-4.** The contradiction recorded here — the frozen contract
   pinning exit `0` while §8.5 owed a result object at exit `0` — is resolved by putting `--help`
   outside the evaluation exit table altogether. This lane's earlier resolution (exit `2`, usage
   on stderr) is superseded; it now matches the frozen lane: exit `0`, help on stdout, no result
   object.
8. ~~**A bundle root that can be traversed but not enumerated.**~~ **CLOSED by `AD15-IR-8`
   (E5-1).** The reading this lane took is now the pinned one, and the erratum records that both
   isolated lanes reached it independently and were measured returning identical results on the
   same bundle — convergence **under a rule**, which is stronger than convergence from silence.
   The note below is retained as the record of how it was resolved here; the one thing that has
   changed is the last paragraph: **the case is now regressed.** Identity establishment is
   monotonic, so no later traversal failure can retroactively unestablish it.

   E4-2 lists "the bundle root itself
   cannot be accessed" as an exit-`1` identity condition; E4-3 says a directory that cannot be
   enumerated *after identity is established* is `bundle-directory-unreadable` at exit `3`. On a
   POSIX filesystem those two overlap for one concrete case: a bundle directory with mode
   `0o111`, where `open(DIR/manifest.json)` succeeds because traverse permission is granted but
   `readdir(DIR)` fails `EACCES` because read permission is not. Read from the erratum text alone,
   both readings are defensible.

   **This lane resolves it to exit `3` with `bundle-directory-unreadable`**, and does so on the
   contract's own words rather than on preference: §8.5 states that "the dividing line is
   **whether bundle identity was established**, and nothing else", and identity *was* established
   — the manifest read succeeded and yielded a registered `scenario_id`, so there is a scenario to
   name a reason after. E4-2's condition 1 is then read as covering the cases where the root's
   inaccessibility makes the manifest read itself fail, which is how all five of its conditions
   behave uniformly.

   Measured, not assumed:

   ```
   mode 0o111: manifest readable = true | root enumerable = false
   exit: 3   reason: bundle-directory-unreadable   scenario_id: IOP-P-DEC
   ```

   **Now pinned, and now regressed.** The earlier note said no self-test asserted this case,
   deliberately, because the resolution followed from §8.5's dividing-line sentence rather than
   from anything E4-2 or E4-3 said directly. `AD15-IR-8` states it outright, so the reason to hold
   back is gone: the self-test now measures both halves of the overlap (manifest readable, root
   unenumerable) as controls before asserting exit `3` with `bundle-directory-unreadable`, and
   skips rather than fakes where the platform cannot produce the mode.
