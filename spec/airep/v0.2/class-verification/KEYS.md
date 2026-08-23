# AIREP v0.2 class-verification — TEST-ONLY key material

> **These keys are TEST-ONLY.** Every private seed below is published in this repository, so
> every signature in `corpus/` is trivially forgeable by anyone. No fixture in this corpus is a
> cryptographically meaningful artifact, and none of these keys may be used anywhere outside
> conformance fixtures. The signatures are real Ed25519 signatures over the real frozen
> preimages ([`../INTEGRITY.md`](../INTEGRITY.md) §2–§4) so that a verifier's cryptographic path
> is genuinely exercised — that is their only purpose.

Suite: `ed25519` — the only entry in the closed v0.2 suite registry (INTEGRITY §3.1).

| Role | Private seed (hex, 32 bytes) | Raw Ed25519 public key (hex) | Provenance |
|---|---|---|---|
| producer | `00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff` | `3ccd241cffc9b3618044b97d036d8614593d8b017c340f1dee8773385517654b` | Stage-3 / Stage-4 published TEST-ONLY producer seed, reused unchanged |
| witness | `ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100` | `2e4e83fdb2d88f88c5f03e663c39ea3f9c7536312b62a2b09a95712dccf11a40` | Stage-3 / Stage-4 published TEST-ONLY witness seed, reused unchanged |
| executor | `6090c1bb1f1f50b5a61391b065567acc246af5d93a8906c9e03ba58ca63c5d14` | `0a3e66f14cea422caf45300e0c3bf42669e87839627750491f1f1e962d7a11cd` | derived: `sha256(ASCII "AIREP/0.2/class-verification/TEST-ONLY/executor")` |

The executor key is the third key the observer-path cases (`P3`, `OB1`–`OB5`) need: an
Execution artifact produced under a binding identity and key distinct from the Effect
artifact's producer. It is derived from a published ASCII string so that the seed is
reproducible from this file alone, with no stored secret and no randomness.

Where a case needs a signature that must *fail*, the builder signs the correct preimage with a
different one of these three keys rather than corrupting bytes — so the signature is
well-formed, schema-valid 128-hex, and definitively invalid under the binding the case supplies:

| Case | Signature under test | Signed by | Binding names | Intended result |
|---|---|---|---|---|
| `PS1` | primary record signature | witness key | producer key | invalid |
| `WM2` | head-witness signature | executor key | witness key | invalid |
| `OB4` | referenced Execution's record signature | witness key | executor key | invalid |
| `IND1` | head-witness signature | producer key | producer key (witness binding carries it) | valid — the defect is key non-distinctness, not the signature |

Verified by the builder's own self-checks (`corpus_manifest.json` → `builder_assertions`), which
assert each of these verifies / fails to verify against the key the case's binding store names.
