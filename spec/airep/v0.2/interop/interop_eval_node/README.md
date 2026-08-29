# Node reference interop evaluator

The Node lane of `INTEROP_REFERENCE_EVALUATOR_CONTRACT.md` (AD15-IR-2). Authored and remediated
in isolation from the Python lane: no shared reconciliation code, no shared helper, no port, and
no sight of the peer lane's source or output.

Contract basis for this remediation: commit `930b9457db00c1d66e2d355f59a6cf5811d52d3a`,
`INTEROP_REFERENCE_EVALUATOR_CONTRACT.md` sha256
`ea705ec2b8775a37aa4bdbf387a5eb5295c0e8bd8a000ad443104c3a24a6c63a`.

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
mechanisms hold that line: direct-invocation detection that cannot be defeated by percent-encoding
(§ below), a synchronous complete write of the result object rather than an async
`process.stdout.write` that a subsequent `process.exit()` could truncate, and a process-exit
invariant that converts a silent zero into exit `3` with a diagnostic.

## `NODE-IMP-1` — the recorded defect and what closes it

`new URL(import.meta.url).pathname` is percent-encoded. On a repository path containing a literal
space (or `#`, or any non-ASCII character) the direct-invocation guard compared an encoded string
against a decoded one, evaluated false, and the program exited `0` with empty stdout — the one
output the §8.5 table cannot defend against, since exit `0` asserts a measured result while stdout
carries none.

`isDirectInvocation()` now tests three ways, and a failure of any one is not a failure of the
guard:

1. `pathToFileURL(process.argv[1]).href === import.meta.url` — both sides are produced by Node's
   own URL machinery, so their escaping is symmetric by construction. This is the comparison the
   original defect had backwards.
2. `path.resolve(argv[1])` against `fileURLToPath(import.meta.url)` — decoded on both sides.
3. `fs.realpathSync` of both — catches a symlinked or otherwise differently spelled entry point.

`selftest.mjs` §12 runs the evaluator from directories named `dir with space`,
`dir#with#hash`, `dizin ünlü` and `dir with  two  spaces`, asserting the full exit/stdout table in
each and asserting directly that no invocation exits `0` with empty stdout.

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
reference resolution, all three predicates, the Level-1 mapping order, and the `NODE-IMP-1` path
regression.

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

## Recorded ambiguities — not resolved here

The erratum closed the ten ambiguities the pre-erratum lineage carried. These are what remains,
recorded rather than invented. Each is marked at the point of use in the source.

1. **`verifier_digests` before or across a failed assertion.** §8.2.1 pins the shape as two
   strings but not what to emit when the assertion has not yet run, or when a file could not be
   read at all. This lane emits `null` for the whole member before the assertion runs, the
   **observed** digest (not the pinned one) when it has, and `null` for an individual member whose
   file was unreadable. A `null` records "not computed"; emitting the pinned constant would assert
   something that was never measured.
2. **No registry reason for a bundle-layout violation.** §8.2.2's registry has no value for a
   symlink under the bundle, a regular file on disk absent from `files[]`, or a non-regular file
   (fifo, socket, device). All three are §5 bundle/manifest rules, so they are raised as
   `manifest-invalid` with the cause named in `detail`. A dedicated reason would be clearer.
3. **An invocation attempted but never spawned.** §8.3.1 says `artifacts[]` carries an entry for
   each invocation attempted, but every field except `artifact_ref` is a product of an invocation.
   A spawn that produced no exit code has no representable entry, so it is omitted and named in
   `nonmeasurement.detail` — following that section's own rule that no implementer invents an exit
   code, and its principle that absence is represented by absence.
4. **An unexpected fault before identity is established.** `internal-error` is defined as a fault
   *after* identity. Before it there is no scenario to name, so the exit-`1` band applies, per
   §8.5's statement that the dividing line is whether identity was established and nothing else.
   The enumeration in the exit-`1` row does not list this case.
5. **Duplicate member names inside `manifest.json`.** "not parseable as strict JSON" is not pinned
   to reject them. `JSON.parse` keeps the last occurrence, as most JSON libraries do, so the
   closure check sees one member. This is left as the library default deliberately: tightening it
   unilaterally would be a rule the peer lane has no reason to share.
6. **An artifact with no usable `record_id`.** Ordering (§8.4) and `artifact_ref` (§8.3) both
   assume one. Rather than refusing to evaluate such a bundle, the member is omitted from
   `artifact_ref` and the artifact sorts under an empty key with `path` as a deterministic
   tiebreak. Refusing would score a genuine stage-0 detection as this evaluator's own fault, which
   is the inversion §7.2 exists to prevent. In an official bundle the tiebreak never fires.
7. **A frozen exit code that is neither `0` nor `1`, and a frozen `exit 0` carrying no usable
   verdict.** §8.2.2's `verifier-run-invalid` row names only "frozen `exit 1` outside §7.2's two
   qualifying conditions", and §7.2's table enumerates only causes of `exit 1`. A frozen `exit 2`
   (its CLI/config-error band), any other non-zero code, and an `exit 0` whose stdout is not a
   shape-valid verdict object all leave the run invalid with no verdict, so they are raised as
   `verifier-run-invalid` with the cause in `detail`. No other registry value fits, and inventing
   one would need an erratum.
8. **`--help`.** The evaluator contract pins no behaviour for it, and the frozen class-verifier
   contract pins `--help` to exit `0` — which §8.5 here forbids, since exit `0` owes a result
   object. Treated as a usage error (exit `2`, usage text on stderr). The two lanes have no shared
   basis to agree on this until it is pinned.
