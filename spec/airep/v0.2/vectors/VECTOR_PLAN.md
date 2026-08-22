# WP-α01 Stage-3 — Fixed-vector plan (shared input specification)

> This file, [`INPUTS.json`](./INPUTS.json), and the normative
> [`../INTEGRITY.md`](../INTEGRITY.md) are the **only** inputs the two vector generators may
> read. The generators are written independently (Stage 3A: Python, Stage 3B: Node); neither
> may read the other's code, fixtures, or output. A third, separate comparator program performs
> the byte-for-byte comparison at the end. This preserves the independence discipline: both
> generators derive from the frozen normative text; agreement is measured, not inherited.

## Keys (published test seeds — TEST ONLY, never production)

The same fixed, published test seeds as the v0.1 example vectors:

| Role | Ed25519 seed (32 bytes, hex) |
|---|---|
| Producer | `00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff` |
| Witness | `ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100` |

Suite for every signature: `ed25519` (INTEGRITY §3.1). Ed25519 is deterministic (RFC 8032), so
identical preimages + identical keys ⇒ identical signature bytes across implementations.

Implementation note (not normative): Node's `crypto` imports a raw Ed25519 seed as PKCS#8 DER by
prefixing `302e020100300506032b657004220420` (hex) to the 32-byte seed.

## Vector set

From `INPUTS.json`:

- **V1–V4** — one construction-test body per artifact type (`decision`, `control`, `execution`,
  `effect`). These bodies exercise the integrity construction only; they are NOT
  schema-conformant artifacts (the four artifact schemas are still blocked). V2 carries JCS
  number edge values; V3 carries a Unicode/control-character string (forces `\n` escaping and
  UTF-8 handling); each body carries the §5 members (`airep_version`, `artifact_type`,
  `chain_id`, `record_id`, `sequence`) and `integrity.previous` (V1/V3 at genesis).
- **W1, W2** — head-witness claims. Each references a head vector by id (`head` field): the
  claim's `current` member is the **computed** `integrity.current` of that head vector;
  `chain_id` is the head's `chain_id` (W2's head has a non-ASCII `chain_id`); `sequence`,
  `length`, `witnessed_at` come from `INPUTS.json` verbatim.

For each of V1–V4 the generator MUST produce, per INTEGRITY §§1–3 and §5:

1. the hash tag and sig tag selected as a pure function of the body's
   (`airep_version`, `artifact_type`);
2. `jcs_body` — JCS of the body (the body as given already omits `integrity.current` /
   `integrity.signature`; the generator adds nothing);
3. `hash_preimage = hash_tag || 0x0A || jcs_body` and `current`;
4. `sig_preimage = sig_tag || 0x0A || "ed25519" || 0x0A || current` and the producer signature.

For each of W1–W2, per INTEGRITY §4:

5. the witness tag `AIREP/<head airep_version>/sig/head-witness`;
6. `jcs_claim` — JCS of the five-member claim, with `current` substituted from the head vector;
7. `witness_preimage = witness_tag || 0x0A || "ed25519" || 0x0A || jcs_claim` and the witness
   signature.

## Output contract

Each generator writes ONE JSON file:

- Stage 3A (Python): `out/python_vectors.json`
- Stage 3B (Node): `out/node_vectors.json`

Top level: `{"vectors": { "<id>": {…}, … }}` — **no timestamps, no environment data, no
generator metadata** (determinism: two runs of the same generator must be byte-identical).

Per artifact vector (V1–V4), all binary values as lowercase hex:

```
{ "hash_tag_hex":      …,   "sig_tag_hex":     …,
  "jcs_body_hex":      …,   "hash_preimage_hex": …,
  "current":           "sha256:…",
  "suite_id_hex":      …,   "sig_preimage_hex":  …,
  "signature_hex":     …,   "producer_pubkey_hex": … }
```

Per witness vector (W1–W2):

```
{ "head":              "V…",
  "witness_tag_hex":   …,   "suite_id_hex":      …,
  "jcs_claim_hex":     …,   "witness_preimage_hex": …,
  "witness_signature_hex": …, "witness_pubkey_hex":  … }
```

## Comparison gate (run by the separate comparator only)

All of the following MUST be byte-for-byte identical between the two outputs, per vector, per
field: tag bytes, JCS payload bytes, full preimages, SHA-256 `current` values, Ed25519
signatures, witness claim canonical bytes, and public keys. The comparator emits an agreement
manifest recording, for every vector, the input → canonical bytes → preimage → digest →
signature chain and the per-field agreement result — the evidence is *which byte sequences the
implementations agreed on*, not that "two programs passed".
