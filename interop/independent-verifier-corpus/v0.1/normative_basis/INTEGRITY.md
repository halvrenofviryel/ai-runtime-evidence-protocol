# AIREP v0.2 — Integrity (normative)

> **Normative.** The key words MUST, MUST NOT, SHOULD, MAY are per BCP 14 (RFC 2119, RFC 8174).
> Grammar fragments use ABNF (RFC 5234).
>
> This section is the Stage-2 integration of the WP-α01 Stage-1 frozen construction
> (freeze basis: PR #26, commit `9a30f972f28e4a0df6adb62d17f1b6e221216796`; design record:
> [`../v0.2-design/WP-A01_DOMAIN_TAG_CONSTRUCTION.md`](../v0.2-design/WP-A01_DOMAIN_TAG_CONSTRUCTION.md)).
> It introduces no design decision of its own; it restates the frozen semantics in the v0.2
> normative register. A byte-affecting change to anything below requires a WP-α01 Stage-1
> re-review.

## 1. Domain tags

### 1.1 Grammar

```abnf
tag           = "AIREP/" version "/" operation "/" context
version       = major "." minor          ; wire-format version, here "0.2"
major         = 1*3DIGIT
minor         = 1*3DIGIT
operation     = "hash" / "sig"
context       = 1*32( %x61-7A / %x30-39 / "-" )   ; lowercase letters, digits, hyphen
```

- A tag is **ASCII**; it contains no whitespace, no control characters, and — by the grammar —
  the `context` segment contains no `/`. The byte `0x0A` (LF) cannot occur anywhere in any tag.
- Tags are **case-sensitive** and always lowercase except the fixed `AIREP` prefix. A verifier
  MUST NOT case-fold.
- The `version` segment is the **wire-format** version. It changes exactly when the wire-format
  version changes; documentation-only or tooling-only releases MUST NOT change it.

### 1.2 Tag registry (closed)

The set of valid `(operation, context)` pairs is a **closed registry** owned by this
specification. For v0.2 it is exactly:

| Tag | Used for |
|---|---|
| `AIREP/0.2/hash/decision` | Hash preimage of a Decision Receipt |
| `AIREP/0.2/hash/control` | Hash preimage of a Control Evidence artifact |
| `AIREP/0.2/hash/execution` | Hash preimage of an Execution Evidence artifact |
| `AIREP/0.2/hash/effect` | Hash preimage of an Effect Evidence artifact |
| `AIREP/0.2/sig/decision` | Record-signature preimage of a Decision Receipt |
| `AIREP/0.2/sig/control` | Record-signature preimage of a Control Evidence artifact |
| `AIREP/0.2/sig/execution` | Record-signature preimage of an Execution Evidence artifact |
| `AIREP/0.2/sig/effect` | Record-signature preimage of an Effect Evidence artifact |
| `AIREP/0.2/sig/head-witness` | Head-witness signature preimage (§4) |

A producer MUST NOT use a tag not in the registry. A verifier encountering an unregistered tag
context MUST fail closed (reject; never guess a nearest match). Adding a registry entry is a
specification change: minimally a MINOR wire-format version bump, with the new entry recorded in
the registry table and covered by fixed vectors before use. Profiles MUST NOT define, alter, or
extend tags.

## 2. Hash preimage

For every v0.2 artifact:

```
hash_preimage = tag-bytes  LF  jcs-bytes

tag-bytes  = the ASCII bytes of the applicable "AIREP/<version>/hash/<context>" tag
LF         = the single byte 0x0A
jcs-bytes  = RFC 8785 (JCS) canonicalization of the artifact with
             integrity.current and integrity.signature removed and every
             other member retained
```

```
integrity.current = "sha256:" || lowercase-hex( SHA-256( hash_preimage ) )
```

The subtraction is defined mechanically; a conforming implementation performs exactly these
steps and no others:

```
body = logical copy of the artifact          # the artifact itself is never mutated
delete body.integrity.current
delete body.integrity.signature
jcs-bytes = JCS(body)
```

The `integrity` object itself remains (with `previous` and any other members intact), and every
other member of the artifact remains byte-relevant exactly as written. No other normalization of
any kind is performed — no member reordering beyond what RFC 8785 defines, no whitespace or
Unicode handling beyond RFC 8785, no removal or defaulting of any other member.

Rules:

1. The hash is computed **in place** — no wrapper object, no re-serialization variants. The
   retained members explicitly include `integrity.previous`, `chain_id`, `record_id`,
   `sequence`, `airep_version`, and `artifact_type` (§5), so chain position, chain identity,
   record identity, ordering, declared version, and declared type are all inside the digest.
2. `jcs-bytes` MUST be produced by RFC 8785 exactly.
3. There is exactly **one** LF in the preimage before the JCS bytes begin, and JCS output for an
   object begins with `{` (0x7B); a preimage is parsed by splitting at the **first** 0x0A.
4. The digest algorithm for v0.2 is SHA-256. The `"sha256:"` prefix on `integrity.current` is
   retained from v0.1; a future algorithm change is a wire-format version change (new tags), not
   a per-record option.

## 3. Record-signature preimage

```
sig_preimage = sig-tag-bytes  LF  suite-id-bytes  LF  current-bytes

sig-tag-bytes  = the ASCII bytes of the applicable "AIREP/<version>/sig/<context>" tag
LF             = the single byte 0x0A
suite-id-bytes = the ASCII bytes of the canonical suite identifier (§3.1)
current-bytes  = the ASCII bytes of the full integrity.current string
                 ("sha256:" || 64 lowercase hex characters)
```

`integrity.signature.value` is the signature over `sig_preimage` under the producer's key, using
the suite named by `suite-id`. No pre-hashing variant — the preimage is short and is signed
directly.

### 3.1 Suite registry

The **canonical suite identifier** comes from a closed registry owned by this specification. For
v0.2 it contains exactly one entry:

| suite-id | Meaning |
|---|---|
| `ed25519` | Ed25519 (RFC 8032), pure (no pre-hash), over the raw preimage bytes |

Adding a suite is a specification change (registered identifier + fixed vectors before use).
Suite identifiers are lowercase ASCII, LF-free, from the same character class as tag `context`
segments.

### 3.2 The wire algorithm label is informative only

**The wire field `integrity.signature.alg` MUST NOT drive any verification decision.** It sits
inside the signature object, which is excluded from the hash preimage (§2) — it is
unauthenticated bytes, and an unauthenticated field must never select cryptographic behaviour.
A verifier determines the suite from its **verifier-accepted key binding** (the trust store /
key material it was given), constructs the preimage with **that** suite's canonical identifier,
and verifies. The suite is thereby self-authenticating: a signature only verifies if the signer
bound the same suite identifier into the signed bytes. A mismatch between the wire `alg` and the
binding-derived suite SHOULD be reported as a caveat, but the verification decision comes from
the binding and the signed suite-id alone.

## 4. Head-witness signature preimage

```
witness_preimage = "AIREP/<version>/sig/head-witness"  LF  suite-id-bytes  LF  jcs-claim-bytes

jcs-claim-bytes = JCS of the head claim object (closed; exactly these five members):
                  { "chain_id":     <chain_id>,
                    "sequence":     <sequence of the head artifact>,
                    "current":      <integrity.current of the head artifact>,
                    "length":       <number of artifacts in the chain>,
                    "witnessed_at": <the witness's freshness timestamp> }
```

### 4.1 Freshness is signed by the witness

- `witnessed_at` is a member of the signed claim. The verifier's freshness recency check MUST
  read `witnessed_at` **from the signed claim only**; any freshness-related field outside the
  signed claim MUST NOT be consulted for the recency decision.
- The head-witness claim scope is exactly: **non-truncation + head anchoring + the witness's
  own signed statement of when it witnessed** — one assurance claim, no mixing.
  Challenge/nonce freshness protocols and transparency-log anchoring are separate mechanisms
  with their own authenticated timestamps; they are not folded into this claim.

### 4.2 Claim member types

The members are pinned; two independent implementations MUST NOT be able to serialize the same
semantic claim differently:

| Member | JSON type | Constraint |
|---|---|---|
| `chain_id` | string | the same JSON string value as the referenced head artifact; no Unicode normalization (see below) |
| `sequence` | number | non-negative integer, ≤ 2^53 − 1, no sign, no fraction, no exponent |
| `current` | string | exactly `sha256:` + 64 lowercase hex characters |
| `length` | number | positive integer, ≤ 2^53 − 1; **the total artifact count of the chain at witness time, the referenced head included** |
| `witnessed_at` | string | exactly `YYYY-MM-DDTHH:MM:SSZ` — RFC 3339 UTC, second precision, literal `Z`; time semantics further constrained below |

- **`witnessed_at` time semantics.** The value MUST be a valid Gregorian UTC datetime with hour
  `00`–`23`, minute `00`–`59`, and second `00`–`59`. The leap-second value `60` is **not
  permitted** in v0.2. An invalid calendar date (e.g. February 30) MUST be rejected. No
  fractional seconds; no offset other than the literal `Z`.
- **`chain_id` value semantics.** The claim carries the **same JSON string value** as the
  referenced head artifact; **no Unicode normalization is performed** at any point. RFC 8785
  alone determines the canonical bytes of that value — an implementation neither preserves the
  source document's escape spelling nor normalizes the string.
- Integers stay within the IEEE-754 safe range so RFC 8785's ES6 number serialization is exact
  and identical across languages.

### 4.3 Witness tag version, witness suite, and head reconciliation

- **Version.** The head-witness tag `<version>` MUST equal the `airep_version` of the
  **referenced head artifact**. There is no independent witness version.
- **Suite.** The witness `suite-id` MUST be derived solely from the **verifier-accepted binding
  for the witness key/identity** (trust store entry). Any wire-carried witness algorithm label
  is informative only and MUST NOT select verification behaviour.
- **No search.** The verifier MUST NOT try alternate versions, tags, suites, or v0.1-style
  constructions when witness verification fails.
- **Head reconciliation.** Witness verification is defined only relative to a resolvable head:
  if the referenced head artifact is unavailable, or the claim's `chain_id`, `sequence`, or
  `current` do not reconcile with that artifact's own members, witness verification MUST fail —
  a witness signature over an unresolvable or mismatching claim confers nothing.

## 5. In-record binding: `airep_version` and `artifact_type`

Every v0.2 artifact carries two required top-level members, both inside the hash preimage (§2):

- `airep_version` — exactly the `version` segment of its tags (`"0.2"`);
- `artifact_type` — exactly the `context` segment of its tags (`"decision"`, `"control"`,
  `"execution"`, `"effect"`), enforced per-artifact-type as a schema `const`.

**Tag selection is a function, never a search.** A verifier MUST derive the one hash tag and the
one sig tag from the pair **(`airep_version`, `artifact_type`) as declared by the artifact's own
bytes**, and MUST reject the artifact if hash recomputation or signature verification under
those tags fails. A verifier MUST NOT try any other tag — a different version, a different
context, or a v0.1-style untagged preimage — on failure, for **either** the hash **or** the
signature.

## 6. Unambiguity (informative)

The construction is injective — two distinct field tuples cannot yield the same preimage bytes:

1. **No field can contain the separator.** Tags and suite identifiers are LF-free by their
   grammars (§1.1, §3.1); `current-bytes` and `witnessed_at` are fixed-format ASCII with no
   control characters; and **JCS output contains no raw 0x0A byte** — RFC 8259 requires control
   characters in strings to be escaped, and RFC 8785 serializes U+000A as the two-character
   escape `\n`, so a raw LF never appears in canonical JSON. Every 0x0A in a preimage is
   therefore a separator, and splitting on 0x0A recovers the exact field list.
2. **Field count is fixed per preimage kind:** the hash preimage has exactly 2 fields (1 LF),
   the record-signature and head-witness preimages exactly 3 fields (2 LFs). Within a kind, the
   split is unambiguous; across kinds, the first field (a `hash/…` tag vs a `sig/…` tag)
   differs, so kinds can never collide with each other.
3. Distinct recovered tuples ⇒ distinct preimages, componentwise: distinct tags or suite-ids
   differ as ASCII; distinct canonical payloads differ because RFC 8785 guarantees one canonical
   byte sequence per JSON value; `current-bytes` is a fixed-format ASCII string.
4. A v0.2 preimage can never equal a v0.1 preimage: every v0.1 hash preimage begins with `{`
   (0x7B, JCS of an object) and every v0.1 signature preimage begins with `s` (0x73, of
   `"sha256:"`); every v0.2 preimage begins with `A` (0x41, of `"AIREP/"`).

## 7. Required adversarial conformance cases

Each case MUST be a committed fixture run against **both** reference verifiers. Every case MUST
produce the required outcome under both verifiers with identical verdict/reason semantics.
Every case whose required outcome is rejection MUST fail closed — never a downgrade, never a
fallback:

| # | Case | Required outcome |
|---|---|---|
| A1 | Identical body bytes hashed under two different `hash` tags | Two different `current` values; each verifies only under its own tag |
| A2 | A Decision Receipt presented to the verifier with `artifact_type` rewritten to `"execution"` | Reject (hash recomputation under the declared tag fails — `artifact_type` is inside the digest) |
| A3 | A valid signature from a `sig/decision` preimage presented on a Control Evidence artifact with the same `current` value | Reject (sig tag mismatch) |
| A4 | A head-witness signature replayed as a record signature (and vice versa) | Reject in both directions |
| A5 | A v0.1 record (untagged hash, bare-`current` signature) presented as a v0.2 artifact | Reject; and the v0.1 verifier continues to accept it under v0.1 rules (freeze intact) |
| A6 | An artifact hashed under a syntactically valid but unregistered tag context | Reject, fail closed, no nearest-match fallback |
| A7 | A tag differing only in case (`AIREP/0.2/HASH/decision`) | Reject (case-sensitive, no folding) |
| A8 | Preimage assembled with CRLF or trailing LF instead of a single LF separator | Hash mismatch ⇒ reject |
| A9 | Cross-version substitution: a body declaring `airep_version: "0.2"` hashed/signed under a `0.3` tag, and vice versa; also a body whose `airep_version` was rewritten after signing | Reject (tag derived only from the declared pair; version is inside the digest) |
| A10 | Freshness replay: an old, valid witness signature over a stale claim, re-presented with any unsigned freshness field set to now | Reject/stale — recency MUST be evaluated against the **signed** `witnessed_at` only; the unsigned field changes nothing |
| A11a | Wire-`alg` substitution: a valid `ed25519` signature re-presented with wire `alg` naming a different suite | Cryptographic verdict unchanged (wire `alg` is informative only); a caveat MAY be reported |
| A11b | Signed-suite mismatch: a signature whose preimage embeds a suite-id different from the verifier's key-binding suite | Reject |
| A12 | Witness cross-version substitution: a witness signature whose tag version differs from the referenced head artifact's `airep_version` | Reject (§4.3 — witness tag version equals the head's declared version; no search) |
| A13 | Witness-suite substitution: a wire-carried witness algorithm label naming a different suite, and a witness preimage embedding a suite-id different from the trust-store binding for the witness key | Wire label changes nothing (informative only); binding/suite-id mismatch ⇒ reject |
