# Stage-4 normalized reason-code registry (closed)

> The `reasons` array of a normalized result may contain only codes from this table. Adding a
> code is a contract change (this file + fixture expectations updated together). The registry
> is deliberately coarse: **a verifier MUST NOT report a distinction it cannot actually make
> cryptographically.** When one observable failure has several possible causes, the code names
> the observable, not a guessed cause.

| Code | Verdict class | Meaning (observable) |
|---|---|---|
| `OK` | PASS | Every required check succeeded, no caveat. The only reason allowed with `PASS`. |
| `WIRE_ALG_IGNORED` | PASS_WITH_CAVEAT | An unauthenticated wire algorithm label disagreed with the binding-derived suite; verification proceeded from the binding and succeeded. |
| `UNSUPPORTED_VERSION` | REJECT | The declared `airep_version` is absent, malformed, or names a version this integrity verifier does not implement (includes a v0.1-style record presented as v0.2). No fallback attempted. |
| `UNREGISTERED_TAG` | REJECT | The declared (`airep_version`, `artifact_type`) pair maps to no tag in the closed registry (includes case variants — the registry is case-sensitive). No nearest-match attempted. |
| `HASH_MISMATCH` | REJECT | Recomputed `current` under the one derived hash tag differs from the artifact's `integrity.current`. Covers any cause that changes preimage bytes: tampered body, rewritten `artifact_type`/`airep_version`, wrong-tag production, malformed separator at production time. These causes are indistinguishable from the hash alone and MUST NOT be reported as distinct codes. |
| `SIGNATURE_INVALID` | REJECT | The record signature failed to verify over the preimage constructed with the derived sig tag and the binding-derived suite. Covers wrong key, tampered signature, cross-context signature replay, and a signed suite-id differing from the binding — cryptographically indistinguishable cases. |
| `WITNESS_SIGNATURE_INVALID` | REJECT | The witness signature failed to verify over the witness preimage constructed per INTEGRITY §4/§4.3 (head-derived version, trust-store-derived suite). Same indistinguishability rule as `SIGNATURE_INVALID`. |
| `WITNESS_HEAD_UNRESOLVED` | REJECT | The witness claim references a head artifact the verifier cannot resolve from the fixture inputs. |
| `WITNESS_HEAD_MISMATCH` | REJECT | The resolved head exists but the claim's `chain_id`, `sequence`, or `current` does not reconcile with the head's own members. |
| `WITNESS_TIME_INVALID` | REJECT | `witnessed_at` violates INTEGRITY §4.2 time semantics (format, leap-second `60`, invalid calendar date, non-`Z` offset, fractional seconds). |
| `WITNESS_STALE` | REJECT | The signed `witnessed_at` is outside the fixture-supplied freshness window relative to the fixture-supplied `now` (includes a signed timestamp in the future beyond the window). Unsigned freshness fields never enter this decision. |
| `KEY_BINDING_UNAVAILABLE` | REJECT | The fixture supplies no verifier-accepted binding for the key the check requires (producer or witness). Fail closed — the wire `alg`/label is never used as a substitute. |
| `SUITE_UNSUPPORTED` | REJECT | The verifier-accepted binding names a suite this integrity verifier does not implement. |

Notes:

- `REJECT` results may carry multiple codes only when the verifier genuinely established each
  named failure independently (e.g. a structurally invalid `witnessed_at` on a claim whose
  head also fails reconciliation). A verifier MUST NOT pad reasons with downstream
  consequences of one root failure.
- Ordering in the array is ASCII-ascending after deduplication (STAGE4_CONTRACT §1); the
  registry table order above carries no meaning.
