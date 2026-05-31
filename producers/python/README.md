# AIREP Python producer

`airep_producer.py` is the copy-paste path for emitting a conformant AIREP v0.1 record from your
own runtime, signed with your **own** Ed25519 key (never the published test key).

## In this repo

```bash
# 1. draft a record: copy an example and edit the fields
cp ../../spec/airep/v0.1/examples/neutral_record.json my_record.json
#    ...edit subject / input / claim / output / evidence / directive / scope...

# 2. fill the integrity block and sign with a fresh key
python3 airep_producer.py my_record.json

# 3. verify (you should see `sig=ok`)
python3 ../../spec/airep/v0.1/conformance/verify.py my_record.json --pubkey my_record.pub.hex --class
```

The full walkthrough is **"Write your own record in 5 minutes"** in
[`../../spec/airep/v0.1/EXPLAINER.md`](../../spec/airep/v0.1/EXPLAINER.md).

## In your own project

Copy two stdlib-only files into your codebase and change the `import jcs` line to point at your copy:

- `airep_producer.py` (this file)
- `spec/airep/v0.1/conformance/jcs.py` — the RFC 8785 canonicalizer. **You must reproduce its bytes
  exactly**, or your hashes won't match other implementations.

Then call `build_record(record: dict, signing_key, previous) -> dict`. Requires `cryptography`
(`pip install cryptography`).

## The integrity rule it implements

Identical to what the verifiers re-derive:

```
body      = the record with integrity.current and integrity.signature removed (previous retained)
current   = "sha256:" + SHA-256( jcs.canonicalize(body) )
signature = Ed25519 over the `current` string, hex-encoded
```

## Keys

`--key` takes a hex file holding a 32-byte Ed25519 seed; omit it and a fresh key is generated and
saved to `<record>.key.hex` (chmod 600). **Keep the private key out of git and out of the record** —
a record carries only signatures, never key material. Publish only the raw public hex
(`<record>.pub.hex`) so others can verify.
