# AIREP producer — TypeScript

An independent **producer** of AIREP v0.1 records, on a different stack from the reference Python
implementation. Zero runtime dependencies (uses only `node:crypto`).

AIREP ships two independent *verifiers* (Python `verify.py` + Node `verify.mjs`) that agree
byte-for-byte. Verifiers are *readers*. This is a *writer* on an independent stack: it emits a
signed, hash-chained chain that **both** reference verifiers accept byte-for-byte — which is what
makes AIREP an *interchange* format rather than one tool's serialization.

> **Honest scope.** This producer is author-written — a second language/stack, the same author. It is
> a bridge toward, not a substitute for, a genuinely *third-party* producer (the open item in
> [`../../spec/airep/v0.1/STATUS.md`](../../spec/airep/v0.1/STATUS.md)). It signs with the **published
> throwaway test key** (`examples/test_public_key.txt`) so the chain verifies out of the box; that key
> is for test vectors only and must never be used for real signing.

## Run it

```bash
npm install
npm run build              # tsc -> dist/airep_producer.js
node dist/airep_producer.js > /tmp/ts_chain.jsonl

# The same chain must pass BOTH reference verifiers:
PUB=../../spec/airep/v0.1/examples/test_public_key.txt
python3 ../../spec/airep/v0.1/conformance/verify.py  /tmp/ts_chain.jsonl --pubkey "$PUB" --class
node     ../../spec/airep/v0.1/conformance/verify.mjs /tmp/ts_chain.jsonl --pubkey "$PUB" --class
```

Both print `RESULT: all records OK` with `sig=ok`, and the per-record `integrity.current` hashes are
identical across the Python and Node verifiers. The CI workflow runs exactly this cross-stack interop
check on every push.

## How it stays byte-conformant

The canonicalizer is the RFC 8785 (JCS) form: recursive key sort + native ES6 `JSON.stringify` + no
whitespace — byte-identical to `verify.mjs`'s canonicalizer, which agrees with the Python `jcs.py`
over a value battery (`conformance/test_jcs.py`). The records carry only strings and integers (no
floats), so `JSON.stringify` equals JCS exactly. The hash is computed over the record with
`integrity.current` + `integrity.signature` removed and `integrity.previous` retained (SPEC §6), then
the result is signed with Ed25519 over `integrity.current`.
