# Node reference interop evaluator

The Node lane of `INTEROP_REFERENCE_EVALUATOR_CONTRACT.md` (AD15-IR-2). Authored in
isolation from the Python lane: no shared reconciliation code, no shared helper, no port.

```
node interop_eval.mjs --bundle DIR
                      [--bindings FILE] [--independence-policy FILE]
                      [--revocation FILE] [--now STR] [--freshness-window N]
                      [--verifier FILE] [--verifier-contract FILE]
```

One invocation evaluates one bundle and writes one JSON result object. No case discovery.

| Exit | stdout | Condition |
|---|---|---|
| `0` | one result object, `MEASURED`, with a Level-1 verdict | the bundle was measured |
| `1` | empty | manifest missing/unparseable, bundle identity unknown, a listed file absent |
| `2` | empty | CLI usage error (`--help` included: nothing is evaluated) |
| `3` | one result object, `MEASUREMENT_INVALID` or `ERROR`, `level1: null` | identity parsed, scenario unmeasurable |

Diagnostics go to stderr and carry no semantics.

The frozen Node class verifier is invoked as a subprocess and is never imported, vendored or
modified. Its digest and the digest of `CLASS_VERIFIER_CONTRACT.md` are asserted before use.
The Python lane's verifier is never invoked and never read (contract §3): its pinned digest is
recorded in the output with `asserted: false`.

Cross-lane envelope-digest comparison is **not** implemented, by ruling `AD15-IR-4`. This
program emits only its own `request_envelope_digest`.

## Running

```
python3 ../../class-verification/offline-node-deps/materialize_node_modules.py   # frozen verifier deps
node selftest.mjs
```

`selftest.mjs` uses synthetic inputs constructed inside the file. It creates no corpus bytes and
no scenario bundle artifacts; corpus construction is on hold (contract §12).

**Not covered by the self-test, stated plainly:** the `MEASURED` end-to-end path over sealed,
signed artifacts — a clean `ACCEPT`, the three reconciliation-negative verdicts, and
`IOP-B-EXE`'s Authenticated-tier failure — cannot be exercised until the corpus exists. What is
covered is the CLI/exit table, manifest verification, numeric preflight, envelope construction
and ordering, the §7.2 causal guard in both directions, reference resolution, all three
predicates, and the Level-1 mapping order.

One limit of that coverage, stated because it would otherwise be overclaimed: the envelope-digest
checks recompute their expected value with this module's own `jcs()` and `byteCompare()`, so they
prove the *pipeline* around the canonicalizer, not the canonicalizer. Exactly one check does not —
a canonical byte string and digest produced outside this module (Python
`json.dumps(sort_keys=True, separators=(",", ":"))`, which coincides with RFC 8785 for ASCII keys
and integer numbers) is asserted as a literal. Envelope-byte equality is the property AD15-IR-4
hands to the aggregate harness, and that is where it is actually measured.

## Assumed bundle manifest shape — flagged for maintainer pinning

The evaluator contract fixes what the manifest must **carry** (§5: `scenario_id`, plus every
shipped file with a `sha256` over its original bytes) but pins no **encoding**. The shape below
was chosen to match the house style of the existing corpus manifests in this repository
(`files` as a path → 64-lowercase-hex map) and is an assumption, not a contract reading.

```jsonc
{
  "scenario_id": "IOP-R-CLEAN",
  "files": { "<bundle-relative path>": "<64 lowercase hex>" },   // every shipped file
  "artifacts": ["<path>", ...],                                   // which files are artifacts
  "operator_inputs": {                                            // optional
    "bindings": "<path>",
    "independence_policy": "<path>",
    "revocation": "<path>"
  },
  "clock": { "now": "<str>", "freshness_window_seconds": "<str>" },  // optional; BOTH strings
  "head_witness": "<path>"                                        // optional
}
```

Rules the evaluator enforces on it: unknown members are rejected; paths must be normalized,
relative and inside the bundle; every referenced path must be listed in `files`; a manifest that
violates any of these exits `1`, because a manifest that cannot be trusted cannot establish
bundle identity.

`clock.freshness_window_seconds` is a **string**, not a number, so it reaches the frozen verifier
as the bundle spelled it. Parsing a JSON number and re-emitting it would be the "synthesize /
re-emit" §5.1 forbids, and two runtimes have no reason to re-spell one float identically.

Operator inputs may be declared in the manifest, named on the command line, or both — when both,
they must agree. A command-line operator input must live inside the bundle and be covered by the
manifest, so "the bundle's own operator-input bytes" (§5.1) stays an auditable statement.

**If the maintainer pins a different manifest encoding, this evaluator needs a corresponding
change.** It is deliberately the only part of the program that rests on an assumption.

## Recorded ambiguities — not resolved here

Carried in full in the branch's delivery report. In the source they are marked at the point of
use.

1. **§7.2 condition 1 vs ruling AD15-IR-4.** §7.2 makes "both lanes produced identical envelope
   bytes" a precondition for reading frozen `exit 1` as `REJECT`, while AD15-IR-4 rules that a
   single evaluator cannot observe the other lane's digest. The unobservable half is not
   evaluated here; the locally observable half (manifest verified, numeric preflight clean,
   envelope built per §5.1 from the bundle's own operator inputs) is.
2. **§8.2 `verifier_digests` — "the three asserted digests".** Asserting the Python verifier's
   digest would require reading the other lane's tree, which §3 forbids crossing into. All three
   entries are emitted; only the two this lane uses are asserted.
3. **Predicate applicability keying.** §6.1 pins applicability per scenario ID. This evaluator
   keys it on bundle structure instead (one artifact ⇒ all `NOT_APPLICABLE`; one each of
   decision/control/execution/effect ⇒ all three evaluated; anything else ⇒ `ERROR`), which
   agrees with the pinned matrix on all twelve scenarios and follows §6.1's own stated rationale.
4. **§7.1 "artifacts the scenario expects to reach `AIREP-Authenticated`".** The evaluator holds
   no expected outcomes and must not. Any non-empty `authenticated_withheld` on any artifact is
   treated as measurement-invalid — a superset that cannot differ on the twelve, where no
   scenario expects a withheld Authenticated tier.
5. **Round-trip precision.** "no value requiring more than double precision to round-trip" is
   read as: the token must denote exactly the decimal that the shortest round-trip form of its
   double denotes. `0.1` passes; `1.00000000000000000001` does not. The integer bound is applied
   to the token's mathematical value, so `1e20` is rejected as an integer past 2^53−1 even though
   it is spelled as a float.
6. **R-A does not type-check its edge targets.** §6 names the edges Control→Decision etc., but
   the resolution rule it inherits (frozen §0) matches on `record_id`/`chain_id` only. A
   reference that resolves uniquely to an artifact of the wrong family is not a failure here.
7. **Exit 1 for an absent file after identity was established.** §8.5's exit-1 row lists "a
   required artifact absent", while the paragraph under the table says a result object is owed
   once identity is established. The table row is followed.
8. **`predicates` on a non-`MEASURED` result.** §8.2 requires the member always, and §6.1 closes
   its value set to three, but none of the three means "applicable and not measured". An errored
   four-artifact `IOP-R-*` bundle therefore reports `NOT_APPLICABLE`, which is
   indistinguishable in that member from a genuine single-artifact scenario. A fourth value, or
   permission to omit the member when `measurement_status != MEASURED`, would close it.
9. **`--help`.** The evaluator contract pins no behaviour for it, and the frozen class-verifier
   contract pins `--help` to exit `0` — which §8.5 here forbids, since exit `0` owes a result
   object. Treated as a usage error (exit `2`, usage on stderr). The two lanes have no shared
   basis to agree on this until it is pinned.
10. **Unlisted files in the bundle directory.** §5 says the manifest "lists every file the bundle
    ships", but does not say an evaluator must detect a file present on disk and absent from the
    manifest. Only the manifest→disk direction is verified here. Enforcing the other direction
    would require inventing an exemption for the manifest itself and for any incidental file
    (a README), which is why it is recorded rather than implemented.
