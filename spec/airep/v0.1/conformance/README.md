# AIREP conformance

This directory lets you check that a record really conforms to AIREP — with **two independent
verifiers** (Python and Node) that agree byte-for-byte.

- [`verify.py`](./verify.py) — verify **your own** record or chain (not just the bundled examples):
  `python3 verify.py <record.json | chain.jsonl> [--pubkey <hex|file>]`. For each record it runs
  schema validation (closed top level, required members, closed enums), the strip-`profiles`
  neutrality test, integrity (hash recompute), chain-replay (or the standalone genesis check),
  optional Ed25519 signature verification, and profile conformance — and exits non-zero if any
  record fails.
- [`verify.mjs`](./verify.mjs) — a **second, independent implementation** (Node, zero dependencies):
  `node verify.mjs <record.json | chain.jsonl> [--pubkey <hex|file>]`. It runs the **same checks** on
  a different language and crypto stack — structure (closed top level + closed enums), neutrality,
  hash, chain, signature — and re-derives every `integrity.current` to the **byte-identical** SHA-256
  the Python implementation computes. Two implementations agreeing on *both conformance and the
  hashes* is what makes AIREP an *interchange* format rather than a single-tool artifact. (Hand it a
  record with a stray vendor key and both report `FAIL(extra-top, neutrality, …)`; tamper a field and
  both report `FAIL(hash)`.)

- [`validate.py`](./validate.py) — the one-command conformance battery over
  [`../examples/`](../examples/). It runs: FULL schema validation; the **neutrality test** (delete
  `profiles`, still valid); **negative tests** (a stray vendor key and a missing `scope` must be
  rejected); **integrity** (recompute `integrity.current` over the canonical form, check the genesis
  `previous`, verify the Ed25519 signature); **chain replay** (walk the 5-record chain); **tamper
  detection** (an edited field, a rewritten `previous`, and a corrupted signature must each break
  exactly the right check); and **profile conformance** (every `profiles.<name>` validates against
  `profiles/<name>.schema.json`). Exit 0 when all pass.
- [`test_jcs.py`](./test_jcs.py) — the **cross-runtime canonicalization test**. It proves
  [`jcs.py`](./jcs.py) (Python, RFC 8785) and the Node canonicalizer produce byte-identical output
  across a value battery — including the cases naive sorted-key `json.dumps` gets wrong
  (`1.0`→`1`, `1e-07`→`1e-7`, `-0.0`→`0`). If Node is absent it falls back to hand-verified vectors.
- [`test_verifier_parity.py`](./test_verifier_parity.py) — the **verdict-parity test**. It runs both
  `verify.py` and `verify.mjs` over a battery of good and adversarial records (vendor-leak, bad verb,
  missing nested member, wrong type, empty `minItems`, non-`const`, tampered hash) and asserts the two
  verifiers reach the same verdict, matching the expected pass/fail. This is the runnable evidence
  behind the parity claim. (Node half skipped if `node` is absent.)

## Conformance vectors

The records in [`../examples/`](../examples/) are the test vectors — `neutral_record.json` (zero
vendor fields), `phionyx_profile_record.json` (vendor data under `profiles.phionyx`), plus
`eu_ai_act_record.json`, `key_trust_record.json`, `governance_record.json`,
`observability_record.json`, and the 5-record `chain.jsonl`. Their hashes and Ed25519 signatures are
**really computed**, not placeholders, and are reproducible via
[`../examples/regenerate.py`](../examples/regenerate.py) from a fixed, published test key.

## What this does not do

Canonicalization is **byte-exact RFC 8785** ([`jcs.py`](./jcs.py)); the *shipped reference RGE
packages*, however, still hash with sorted-key `json.dumps`, and aligning them to JCS is a separate
breaking change tracked in [`../STATUS.md`](../STATUS.md). `verify.py` validates with the full Draft-2020-12
engine (`jsonschema`) and is the authority for exhaustive schema validation; `verify.mjs` hand-codes
the same fixed core shape (closed top level, nested required members, value types, closed enums) and
is kept in lockstep with it. The two are tested to reach the same verdict on the example vectors and
on adversarial cases (vendor-leak, bad-verb, missing nested member, wrong type, tampered hash); they
agree on `integrity.current` byte-for-byte. `verify.mjs` exists to prove the format is checkable on a
second, dependency-free stack — not to be a general JSON Schema engine.

## Run

```bash
pip install jsonschema cryptography     # cryptography is optional: without it the hash recompute
cd ..                                   # still runs and the signature check is skipped
python3 conformance/validate.py             # full battery over the examples
python3 conformance/test_jcs.py             # Python vs Node canonicalization
python3 conformance/test_verifier_parity.py # verify.py and verify.mjs agree on every case
python3 conformance/verify.py  examples/chain.jsonl --pubkey examples/test_public_key.txt
node      conformance/verify.mjs examples/chain.jsonl --pubkey examples/test_public_key.txt
```
