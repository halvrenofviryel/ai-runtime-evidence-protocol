# AIREP Conformance Classes

> Normative. The key words MUST / SHOULD / MAY are per BCP 14 (RFC 2119, RFC 8174).
> A record or chain has a single **highest class** it satisfies. `verify.py` and `verify.mjs`
> report it with `--class`. The classes are a strict ladder: Trusted ⊃ Verified ⊃ Core.
>
> **By default the reference verifiers report only `Core`, `Verified`, and
> `TRUSTED_NOT_IMPLEMENTED`.** In that mode `Trusted` is **not reachable**, because four of its
> prerequisites are unenforced — see §TRUSTED_NOT_IMPLEMENTED. **`Trusted` becomes reportable in an
> opt-in STRICT mode** (WP-10): when the operator supplies `--trust-store` + `--freshness-window` +
> `--revocation-source`, the four gates run for real and a record earns `Trusted` iff every one
> passes — see §AIREP-Trusted (strict mode). Without those inputs the tier stays withheld: a
> prerequisite that did not run is never reported as satisfied.

A bare conformance result (valid / invalid) does not tell an auditor or regulator *how much* a
record can be relied on. The classes do: they turn the spec's SHOULD-vs-MUST distinctions into a
ladder a consumer can cite ("we require **AIREP-Verified**") without re-litigating the spec. They do
**not** change the wire format — every class is the same `core.schema.json` record; the higher
classes require additional *checks* and optional *profiles*, never new core members.

## AIREP-Core — well-formed

The floor. A record (or chain) is **AIREP-Core** when all of SPEC §8 holds:

1. it validates against `core.schema.json` (closed top level, required members, closed
   `directive.verb` / `evidence[].type` enums);
2. the **neutrality test** passes — it still validates with `profiles` removed;
3. `integrity.current` recomputes over the RFC 8785 canonical form (SPEC §6);
4. the chain links — each `previous` equals the prior `current`, the first record uses the genesis
   value, and `decision_index` increments;
5. `integrity.signature` is **present** (the `{alg, value}` object exists).

Core establishes *"this is a well-formed, untampered AIREP record."* The signature need only
**exist** at this tier; whether it *verifies* is the next tier's concern.

An input containing **zero records** is `INVALID` and MUST exit non-zero. It is not a vacuously
conformant chain: no check ran, so no class was earned. A verifier MUST NOT report any class for an
empty input, and MUST NOT let an initial or default class value stand in for a measured one — the
ceiling is earned by the records, never inherited.

## AIREP-Verified — cryptographically checkable

**AIREP-Verified** is Core **plus** the record's authorship is cryptographically established. A
verifier reports Verified only when, in addition to Core:

1. it re-verifies `integrity.signature` over `integrity.current` against a **supplied key** and the
   signature is valid (so Verified is only assertable by a verifier that *holds the key* — pass
   `--pubkey`);
2. `integrity.signature.alg` names a **real asymmetric or keyed signature** (e.g. `Ed25519`,
   `ECDSA`, `HMAC-SHA256` with a genuine key) — **not** a placeholder/demo signer and not
   `unsigned`;
3. every `evidence[]` entry with `resolvable: false` carries a `content_hash` (so withheld evidence
   is hash-anchored, never merely dropped);
4. a **`profiles.key_trust`** block binds the signing key (`key_id`, `algorithm`, `public_key`), so a
   verifier can say *which* key it checked against.

Verified establishes *"this record was provably written by the holder of a named key, and its
withheld evidence is anchored."* It is the right floor for any governance or audit use.

## AIREP-Trusted — auditable ledger (witness + freshness)

**AIREP-Trusted** is Verified **plus** the structural gaps the core leaves open — tail-truncation,
replay-as-latest, "is this the current head?" — are closed by an **independent witness**. A verifier
reports Trusted only when, in addition to Verified:

1. a **`profiles.chain_witness`** (a.k.a. `freshness_witness`) block provides a signed head witness —
   a `chain_id`, the head `{decision_index, current, length}`, and a witness signature **by a key
   distinct from the producer's** (a producer-signed "witness" provides **no** truncation defense and
   does not satisfy this tier) — **or** a transparency-log inclusion proof anchoring the head;
2. a **freshness anchor** is present (a witness timestamp, nonce, or challenge response) so a *valid*
   record can be mapped to a *current* one;
3. `profiles.key_trust` carries **rotation + revocation** state and the verifier honors revocation
   (a record signed after `revoked_at` by a revoked key is untrusted).

Trusted establishes *"this is the current, untruncated head of a chain whose signing key is
externally vouched-for."*

> **Status of Trusted: NOT REPORTABLE by the reference verifiers.** The `chain_witness` profile
> schema is published ([`../profiles/chain_witness.schema.json`](../profiles/chain_witness.schema.json))
> with a worked, independently-witnessed example
> ([`../examples/chain_witness.jsonl`](../examples/chain_witness.jsonl)), and the fixed-vector battery
> `validate.py` does re-verify that vector's witness signature under a key distinct from the
> producer's and does demonstrate that dropping the tail is detected. **That is a property of one
> committed vector under one battery — it is not the classifier.** The general-purpose classifiers
> `verify.py --class` and `verify.mjs --class` check witness *presence* only: they never re-verify
> `chain_witness.witness.value`, cannot prove the witness key is independent of the producer key (a
> `witness_id` string is not a key), never evaluate freshness *recency*, and consult no revocation
> source. Four of the tier's prerequisites are therefore unenforced **by default**, so `Trusted` is
> withheld and named — see §TRUSTED_NOT_IMPLEMENTED below. A prerequisite that is not enforced can
> never be reported as satisfied; granting the tier on witness *presence* would report an assurance
> no check produced. **These four gates ARE enforced in the opt-in strict mode below** — the honest
> ladder, not a marketing one: a tier is claimable once its checks actually run, and until the
> operator supplies the inputs that let them run, the gap is named rather than papered over.

## AIREP-Trusted (strict mode) — the four gates, run against operator inputs

`Trusted` is reachable **only** in strict mode, engaged when the operator passes all three of
`--trust-store`, `--freshness-window`, and `--revocation-source` (and a witness is present). Any
input missing → the gates cannot run → `TRUSTED_NOT_IMPLEMENTED` (never a silent `Trusted`). With
them, a record that already satisfies Verified and carries structurally-coherent witness material is
granted `Trusted` **iff all four gates pass**; any failure drops the ceiling to `Verified` with the
specific reason named:

| Gate | Check (v1) | Failure reason(s) |
|---|---|---|
| witness signature | re-verify `chain_witness.witness.value` over canonical `{chain_id, decision_index, current, length}` under the key **resolved from the trust store** by `witness_id` | `witness-signature-invalid` (or `witness-unknown` if `witness_id` is not in the store, `witness-untrusted` if its entry is not `trusted:true`) |
| witness-key independence | compare **resolved public keys**, not id strings: witness pubkey ≠ producer `key_trust.public_key` | `witness-not-independent` |
| freshness recency | `freshness.witness_timestamp_utc` within `--freshness-window` seconds of `--now` (deterministic; default `--now` = system clock, and the evaluated `now` is printed) | `freshness-stale`, `freshness-in-future`, `no-freshness-anchor` |
| revocation | consult `--revocation-source` for **both** the producer key_id and the witness key_id; a key signed at/after its `revoked_at` is revoked | `producer-key-revoked`, `witness-key-revoked` |

**Operator input files (v1, local JSON, network-free):**

```jsonc
// --trust-store
{ "<witness_id>": { "public_key_hex": "<64-hex>", "trusted": true } }
// --revocation-source
{ "<key_id>": { "revoked_at": "<iso8601>", "reason": "<str>" } }
```

**Determinism.** The freshness gate is the only time-dependent step; `--now` makes a `Trusted`
verdict reproducible and the verdict header records the `now` used. Identical inputs (including
`--now`) ⇒ identical verdict.

**v1 scope, stated so it is not misread.** Exactly **one** independent trusted witness — **no N-of-M
quorum**. Local JSON inputs only — **no transparency-log / `inclusion_proof` verification** and **no
online CRL/OCSP**. Timestamp freshness only — **no nonce/challenge** protocol. These remain named
future work; the strict verdict never claims more than it checked. The WP-09 **self-declared**
revocation caveat (`verified_withheld=producer-key-revoked`) is unchanged and independent of the
external `--revocation-source`.

## TRUSTED_NOT_IMPLEMENTED — the withheld top class

`TRUSTED_NOT_IMPLEMENTED` is the class the reference verifiers report **in default mode** for a
record that has cleared every check they *do* run and whose remaining distance to Trusted is
**unmeasured rather than failed**. It is normative output vocabulary, not an error string. (In strict
mode the four gates below ARE evaluated against the operator's inputs — see §AIREP-Trusted (strict
mode) — so a strict run returns `Trusted` or `Verified`+reason, not this class.)

**Validity.** A `TRUSTED_NOT_IMPLEMENTED` record is **valid**. It has passed every AIREP-Core check
and every AIREP-Verified check; nothing about it is malformed, tampered, or unsigned. The class says
something about the *verifier's coverage*, not about a defect in the record.

**Assurance class.** It ranks **exactly equal to AIREP-Verified**, never above it. A consumer whose
policy says "we require AIREP-Verified" MAY accept it. A consumer whose policy says "we require
AIREP-Trusted" **MUST NOT** accept it: the Trusted prerequisites were never evaluated, and an
unevaluated prerequisite is not a satisfied one. Formally it is AIREP-Verified plus a **named
statement of what was not checked**, carried in the `trusted_withheld=` list on the record line:

| reason | prerequisite left unevaluated |
|---|---|
| `witness-signature-not-verified` | req 1 — `chain_witness.witness.value` is never re-verified |
| `witness-key-distinctness-unproven` | req 1 — a `witness_id` string is not a key |
| `freshness-recency-not-evaluated` | req 2 — presence is checked; recency / nonce-challenge is not |
| `revocation-not-honored` | req 3 — no revocation source is consulted |

Distinguish it from a **structural failure**. When a Trusted prerequisite is checkable and
definitively fails — a witness naming the producer's own key, a missing freshness anchor, absent or
`revoked: true` revocation state — the record is reported as plain `Verified` with the specific
failure named (`witness-not-independent`, `no-freshness-anchor`, `no-revocation-state`,
`producer-key-revoked`). *Failed* and *not measured* are different states and are reported
differently; neither is ever `Trusted`.

**A revoked signing key is never a silent Verified — even off the Trusted path.** The naming above
is reached when a record *attempts* Trusted (a witness is present). A record that makes **no**
Trusted claim (no witness) but whose own `profiles.key_trust.revocation.revoked` is `true` is still
reported `Verified` — revocation is a Trusted gate, not a Verified requirement, so the class is
unchanged — but the caveat is surfaced on the record line as **`verified_withheld=producer-key-revoked`**.
This is a self-declared, definitively-checkable state that needs no external revocation source (that
source is the undefined Trusted-tier policy). It does not raise or lower the class; it stops a
Verified record signed by a self-declared-revoked key from reading as a clean pass. `verified_withheld=`
names caveats on a **Verified** record; `trusted_withheld=` names why **Trusted** was withheld — the
two channels are distinct and a consumer reads whichever its policy floor cares about.

**Exit-code meaning: none.** The exit code of `verify.py` / `verify.mjs` encodes **record validity
only**, never a class:

| exit | meaning |
|---|---|
| `0` | every record passed every check **that verifier actually ran** |
| `1` | at least one record failed a check, or the input could not be read/parsed |
| `2` | usage error (no input path supplied) |

`--help` exits `0` without verifying anything. A `TRUSTED_NOT_IMPLEMENTED` record exits `0`, because
it is a valid record. Exit 0 therefore MUST NOT be read as "Trusted", or as any class at all: the
class is a separate channel, printed as `CLASS:` on stdout. A consumer enforcing a class floor MUST
parse that line; it MUST NOT infer a class from the process exit status.

> **The two verifiers' exit codes are NOT equivalent.** `verify.mjs` runs no profile-schema
> validation, so a record whose `profiles` block violates its profile schema exits `1` under
> `verify.py` and `0` under `verify.mjs`. Read "every check that verifier actually ran" literally:
> exit 0 from `verify.mjs` is a weaker statement than exit 0 from `verify.py`.

> A verifier that implements a gate MUST remove its reason from the withheld list **and** add the
> real check in the same change. Removing a reason alone re-opens the hole silently, which is the
> exact failure this class exists to prevent.

## What the classes do NOT establish

No class — including Trusted — makes the *producer* honest or the AI output *correct*. A key-holding
producer can write a valid, signed, witnessed record with a false `claim`, `scope`, or `evidence`;
the classes raise the bar on *tamper-evidence, authorship, and freshness*, never on the *truth* of
what was recorded. That boundary is `scope.does_not_cover`, and it is deliberately outside every
class (see [`../THREAT_MODEL.md`](../THREAT_MODEL.md), malicious-producer = none by design).
