# Node reference interop evaluator

The Node lane of `INTEROP_REFERENCE_EVALUATOR_CONTRACT.md` (AD15-IR-2). Authored and remediated
in isolation from the Python lane: no shared reconciliation code, no shared helper, no port, and
no sight of the peer lane's source or output.

Contract basis: the canonical post-Erratum-2 head
`b325fb2e9e6ed7fae690b4953aed4e5d1ce6c278`, `INTEROP_REFERENCE_EVALUATOR_CONTRACT.md` sha256
`42e350d09b28cb79a7e59f91fe55af96968925bf8615c8818f5c45d42c2b2fa2`, asserted before any source
was edited. Pre-Erratum-2 remediation lineage: `801a1dc1a056ab65e20d735c83cf04a28c1fb45d`, frozen
as evidence and not rewritten.

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
| `1` | empty | bundle identity could not be established: `manifest.json` absent, not parseable as strict JSON, or carrying no usable `scenario_id` from the registered twelve |
| `2` | empty | CLI usage error (`--help` included: nothing is evaluated) |
| `3` | one result object, `MEASUREMENT_INVALID` or `ERROR`, `level1: null`, `predicates: null`, `nonmeasurement` populated | identity established, scenario not measured |

Diagnostics go to stderr, carry no semantics, and are never parsed — by this program or by the
harness. Frozen-verifier stderr is hashed for audit only.

**`exit 0` with empty stdout is unacceptable under every condition** (`NODE-IMP-1`). Three
mechanisms hold that line: direct-invocation detection that cannot be defeated by percent-encoding,
a synchronous complete write of the result object rather than an async `process.stdout.write` that
a subsequent `process.exit()` could truncate, and a process-exit invariant that converts a silent
zero into exit `3` with a diagnostic. Both defect routes and their regressions are set out under
[`NODE-IMP-1` — both routes](#node-imp-1--both-routes-and-how-each-is-regressed) below.

## Frozen verifier

Invoked as a subprocess; never imported, vendored, re-implemented or modified. Its digest and the
digest of `CLASS_VERIFIER_CONTRACT.md` are asserted before use and emitted as **this lane's own
two entries** (§8.2.1):

```jsonc
{ "class_verifier": "sha256:…", "class_verifier_contract": "sha256:…" }
```

**The Python lane's verifier digest appears nowhere** — not in the output, and not as a constant
in this source. §3 forbids this lane from reading the peer verifier, so it cannot assert a digest
for it; cross-lane verifier identity is the aggregate harness's duty, and the harness legitimately
sees both trees. `selftest.mjs` asserts the absence in both the source and the output.

Cross-lane envelope-digest comparison is **not** implemented, by ruling `AD15-IR-4`. This program
emits only its own `request_envelope_digest`, per artifact.

## Ordering

Full bundle preflight completes before any frozen verifier is invoked (§8.3.1): manifest, symlink
and path rules, disk/manifest closure both ways, digests, JSON parseability, bundle shape,
operator-input composition, numeric envelope, frozen-verifier digest assertions. A failure during
preflight is a pre-invocation `ERROR` carrying `artifacts: []` — an empty array, never entries
with placeholder fields. Once invocation begins, `artifacts[]` carries an entry for each
invocation that produced an exit code, and no more.

### Two orderings, deliberately not the same function (`AD15-IR-5`)

| Layer | Ordered by | Pinned in |
|---|---|---|
| `artifacts[]` result entries | UTF-8 byte order of **`artifact_path`** | §8.3.1, §8.4 |
| `related_artifacts` inside a request envelope | UTF-8 byte order of **`record_id`** | §5.1, **unchanged** |

`AD15-IR-5` moved *result identity* to the manifest path; it did **not** touch §5.1. Collapsing
the two into one comparator would change the request-envelope bytes and break the cross-lane
envelope equality the aggregate harness checks (`AD15-IR-4`), so `compareByPath` and
`compareByRecordId` are separate functions and the self-test asserts them against a four-artifact
fixture whose path order and `record_id` order **disagree**. R-A is unchanged: reference
resolution still matches on `record_id`, additionally `chain_id` where carried. The manifest path
is harness and result identity only — never wire semantics.

`artifact_path` is required and always exists, because the manifest lists every file.
`artifact_ref` is an object when a usable `record_id` exists and **`null`** when it does not.
**No `record_id` is ever synthesized**, for any reason: an artifact that must be rejected at
stage 0 now reaches that stage-0 evaluation instead of being converted into this evaluator's own
preflight failure.

## Running

```
python3 ../../class-verification/offline-node-deps/materialize_node_modules.py   # frozen verifier deps, offline
node selftest.mjs
```

`node_modules/` is generated and git-ignored; it is never committed.

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
and **both** `NODE-IMP-1` routes (§12 path, §16 pipe truncation).

Two of those sections carry their own controls, because a regression that cannot fail proves
nothing: §16 first measures that the buggy write pattern really does truncate on this platform,
and §13's four-artifact fixture is built so `artifact_path` order and `record_id` order
**disagree** — otherwise no check there could tell `AD15-IR-5` from the §5.1 rule it must leave
alone.

One limit of that coverage, stated because it would otherwise be overclaimed: the envelope-digest
checks recompute their expected value with this module's own `jcs()` and `byteCompare()`, so they
prove the *pipeline* around the canonicalizer, not the canonicalizer. Exactly one check does not —
a canonical byte string and digest produced outside this module (Python
`json.dumps(sort_keys=True, separators=(",", ":"))`, which coincides with RFC 8785 for ASCII keys
and integer numbers) is asserted as a literal. Envelope-byte equality across lanes is the property
`AD15-IR-4` hands to the aggregate harness, and that is where it is actually measured.

## Bundle manifest

The encoding is now pinned exactly by §5 and is no longer an assumption. `manifest.json` in the
bundle root; the evaluator searches for no other name or location.

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

## Recorded ambiguities — not resolved here

Erratum 2 closed three of the eight this lane carried. These six remain, recorded rather than
invented, and each is marked at the point of use in the source.

1. **`verifier_digests` before or across a failed assertion.** §8.2.1 pins the shape as two
   strings but not what to emit when the assertion has not yet run, or when a file could not be
   read at all. This lane emits `null` for the whole member before the assertion runs, the
   **observed** digest (not the pinned one) when it has, and `null` for an individual member whose
   file was unreadable. A `null` records "not computed"; emitting the pinned constant would assert
   something that was never measured.
2. **An invocation attempted but never spawned.** §8.3.1 says `artifacts[]` carries an entry for
   each invocation attempted, but every field except `artifact_ref` is a product of an invocation.
   A spawn that produced no exit code has no representable entry, so it is omitted and named in
   `nonmeasurement.detail` — following that section's own rule that no implementer invents an exit
   code, and its principle that absence is represented by absence. E2-2 narrowed the reason for
   this case to `verifier-not-invocable` but did not pin the `artifacts[]` shape.
3. **`related_artifacts` ordering when an artifact carries no usable `record_id`.** This is the
   residue of the old ambiguity 6 after `AD15-IR-5`. That ruling moved *result* identity and
   ordering to `artifact_path`, but §5.1 still orders the **envelope**'s `related_artifacts` by
   `record_id`, and it does not say what to do when one is absent. This lane sorts such an
   artifact under an empty key with `artifact_path` as a deterministic tiebreak. The choice is
   **not** cross-lane safe on its own — a peer lane could tiebreak differently and produce
   different envelope bytes — but it cannot arise in an official W1 bundle, because a four-artifact
   `IOP-R-*` fixture is built to be individually sound. Recorded rather than resolved, because
   resolving it would mean amending §5.1.
4. **An unexpected fault before identity is established.** `internal-error` is defined as a fault
   *after* identity. Before it there is no scenario to name, so the exit-`1` band applies, per
   §8.5's statement that the dividing line is whether identity was established and nothing else.
   The enumeration in the exit-`1` row does not list this case.
5. **Duplicate member names inside `manifest.json`.** "not parseable as strict JSON" is not pinned
   to reject them. `JSON.parse` keeps the last occurrence, as most JSON libraries do, so the
   closure check sees one member. This is left as the library default deliberately: tightening it
   unilaterally would be a rule the peer lane has no reason to share.
6. **`--help`.** The evaluator contract pins no behaviour for it, and the frozen class-verifier
   contract pins `--help` to exit `0` — which §8.5 here forbids, since exit `0` owes a result
   object. Treated as a usage error (exit `2`, usage text on stderr). The two lanes have no shared
   basis to agree on this until it is pinned.
