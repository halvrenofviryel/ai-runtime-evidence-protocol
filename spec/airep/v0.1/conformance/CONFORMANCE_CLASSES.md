# AIREP Conformance Classes

> Normative. The key words MUST / SHOULD / MAY are per BCP 14 (RFC 2119, RFC 8174).
> A record or chain has a single **highest class** it satisfies. `verify.py` and `verify.mjs`
> report it with `--class`. The classes are a strict ladder: Trusted ⊃ Verified ⊃ Core.

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

> **Status of Trusted:** the `chain_witness` / `freshness_witness` profile schema is **not yet
> published** (it is the headline of the v0.2 release, per [`../STATUS.md`](../STATUS.md)). Until it
> ships, **no record reaches AIREP-Trusted**, and `--class` will report Core or Verified. This is the
> honest ladder, not a marketing one: a tier is only claimable when its checks are runnable.

## What the classes do NOT establish

No class — including Trusted — makes the *producer* honest or the AI output *correct*. A key-holding
producer can write a valid, signed, witnessed record with a false `claim`, `scope`, or `evidence`;
the classes raise the bar on *tamper-evidence, authorship, and freshness*, never on the *truth* of
what was recorded. That boundary is `scope.does_not_cover`, and it is deliberately outside every
class (see [`../THREAT_MODEL.md`](../THREAT_MODEL.md), malicious-producer = none by design).
