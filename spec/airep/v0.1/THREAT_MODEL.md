# AIREP v0.1 — Threat Model

**Status: Experimental** (see [`STATUS.md`](./STATUS.md)). This document states, honestly, which
attacks AIREP's record format defends against, *how*, and — equally important — which it does **not**.
It is written in the same spirit as `scope.does_not_cover`: a defense you cannot name precisely is a
defense you should not claim.

## The one-sentence summary

AIREP gives a **tamper-evident, position-bound decision receipt**. It makes a specific class of
*after-the-fact tampering* **detectable** — and only under stated assumptions. It does **not** make the
producer honest, the content true, the record available, or "old" mean "invalid." On its own the
format **fully stops none** of the threats below; it raises the cost of some and is explicit about the
rest.

## Trust model and standing assumptions

Almost every defense below is **conditional**. These assumptions recur; read them as preconditions,
not guarantees the core provides:

1. **Signature verification happens, against *trusted* keys.** SPEC §8 makes signature re-verification
   a **SHOULD**. The conformance kit's two verifiers always re-verify signatures; the shipped reference
   chain verifier checks the hash chain by default but now offers **opt-in** signature verification
   ([`STATUS.md`](./STATUS.md) item 3). Where signature verification is off, anyone who can recompute
   SHA-256 (no key) can build a self-consistent forged chain. **Key trust/distribution is out of scope**
   (SPEC §9).
2. **The signing key is secret and producer-held.** Key possession = the ability to *silently rewrite*
   (recompute hash + re-sign). The format gives tamper-*evidence*, not tamper-*resistance*.
3. **Storage is immutable and append-only.** AIREP provides tamper-evidence, **not availability**: SPEC
   §9 concedes a party that controls storage "can withhold records, though it cannot alter them
   undetectably." Truncation and withholding are storage attacks, not hash attacks.
4. **The verifier walks the full chain from genesis and holds the legitimate head.** Binding is
   **relative** (each record names only its immediate predecessor); the core has no signed chain-id,
   length, or head witness.
5. **Canonicalization agrees byte-for-byte.** The conformance kit enforces RFC 8785
   (`conformance/jcs.py`) and its two independent verifiers agree byte-for-byte across a value battery
   that includes float and unicode edges (`conformance/test_jcs.py`). The remaining gap is the **shipped
   reference RGE packages** (STATUS items 1–2), which still hash with sorted-key `json.dumps`: a record
   produced by those packages and one canonicalized with JCS can disagree on `current` until they are
   aligned.

## What AIREP defends — and the residual gap

| Threat | Defense | What the format actually provides | Residual gap (still open) |
|---|---|---|---|
| **Splice** (move a signed record to another position/chain) | **partial (strongest)** | `previous` is *inside* the signed hash preimage and MUST equal the prior record's `current`; so a record is cryptographically welded to one predecessor. Repositioning either breaks the chain-link check or invalidates the signature. | Binding is *relative*, not absolute — no chain-id/head in the hash. A valid **prefix** can be presented as a whole chain; a lone record out of chain context defeats the `previous` check (nothing to compare against). |
| **Record tampering** (alter content after the fact) | **partial** | Any byte change to the canonical body changes `current`; if the verifier re-checks the signature over `current`, alteration is detected. | Tamper-*evidence*, never prevention/rollback. **Key possession → silent full rewrite.** A hash-only verifier (today's reference) misses signature substitution. |
| **Replay** (present an old valid record as current) | **partial in core; closeable by profile** | Anti-splice (above) defeats *replay-into-a-different-position*. | **Core has no freshness anchor** (clock/nonce/trusted "latest"): a stale-but-valid record passes every core check; `timestamp_utc` is producer-asserted. The now-shipped **`chain_witness` profile** adds a `freshness` anchor (witness timestamp / nonce / challenge response), mapping "valid" → "current" for records that adopt it (AIREP-Trusted). |
| **Chain truncation** | **partial in core (tail); closed by profile** | Head/reposition tampering breaks the links. | **In the core, tail truncation is undefended** — drop the last *N* records and the remaining prefix is self-consistent and reports VALID. The now-shipped **`chain_witness` profile** pins a signed `{chain_id, head, length}` by a key **independent of the producer**; `validate.py` demonstrates that dropping the tail then disagrees with the witnessed length/head and is detected. The core gap is real; the profile is the closure path. |
| **Signature stripping / downgrade** | **partial (weak)** | The schema requires the `integrity.signature` object (`alg`,`value`) to be present. | `value` can be replaced with garbage, or `alg` downgraded, and it is undetected **unless** the verifier opts into the SHOULD signature check. The field-level defense is structural, not cryptographic. |
| **Forged producer** (outsider mints records as a trusted producer) | **partial** | `integrity.signature` binds the record to whoever holds the key; a verifier with the genuine public key rejects a forgery. | `subject.producer` is **unauthenticated text** (always forgeable); the binding only bites if the verifier holds the right key **and** performs the optional signature check. |
| **Withholding** (hide real input/output/evidence, still emit a "valid" record) | **partial** | Content is referenced, never inlined; `output.redacted` / `evidence.resolvable=false` flag withheld content; `content_hash` can anchor it; `scope.does_not_cover` states what is not attested. | **Hash-anchoring is OPTIONAL** → withholding can be *unbound*. Availability is out of scope; a verifier cannot fetch what the producer withholds, and `resolvable`/`scope` honesty is producer-asserted. |
| **Evidence poisoning** (point evidence at fabricated/attacker content) | **partial** | After sealing, an `evidence[].ref`/`content_hash` cannot be altered without breaking `current`. | No **content authenticity** at authorship time: a producer can point at fabricated or attacker-controlled content; `content_hash` is optional and producer-computed. |
| **Canonicalization mismatch** (two impls hash the same record differently) | **partial** | RFC 8785 is enforced by the conformance kit (`jcs.py`); its two independent verifiers agree byte-for-byte across floats / unicode edges (`test_jcs.py`), and `canonical_json=true` declares the form. | The **shipped reference RGE packages** still use sorted-key `json.dumps`, so a record from those packages and a JCS verifier can disagree on `current` until they are aligned — a deferred, breaking, version-bumped change ([`STATUS.md`](./STATUS.md) items 1–2). |
| **Malicious producer** (legitimately-keyed author writes misleading-but-valid records) | **none** | — | **The format records the *path*, not the *truth*** (SPEC §9: "A record attests the path, not the truth… it does not prove the underlying AI output was correct"). A keyed producer can fabricate `claim`, `basis`, `policy_basis`, `scope`, and evidence at will. Out of reach of any integrity mechanism. |

## What AIREP explicitly does NOT defend

- **A dishonest authorized author.** This is the deepest boundary and it is by design: AIREP is *not a
  truth engine, not an alignment method, not a safety model*. It records what a system **claims** it
  decided and on what evidence — not whether that claim is honest or correct. Catching a malicious
  producer needs **independent corroboration** (a second producer, an out-of-band attestation, human
  audit), not the receipt format.
- **Availability.** A storage-controlling party can withhold or tail-truncate. AIREP detects
  *alteration*, never *absence*.
- **Freshness.** Nothing in the core maps "valid" to "current"; staleness is never a conformance error.

## Dependencies that close (or narrow) the gaps

None of these are in the v0.1 neutral core; they are deployment choices or v0.2 / profile work, named
here so the boundary is explicit:

- **Make signature verification a MUST** in the conformance kit, and add a **key-trust profile**
  (issuer, key id, rotation, and an optional **transparency log**). This is what turns several
  "partial" rows from optional to enforced, and gives `forged_producer` / `signature_stripping` real
  cryptographic weight.
- **A signed chain head / length witness** (or a transparency-log anchor) closes **tail truncation**
  and **replay-as-latest**: the verifier can detect a missing tail and identify the true head. This is
  **now shipped** as the [`chain_witness`](./profiles/chain_witness.schema.json) profile, with a worked
  independently-witnessed vector ([`examples/chain_witness.jsonl`](./examples/chain_witness.jsonl)) and a
  truncation-detection check in `validate.py`. It is what lifts a record to AIREP-Trusted.
- **A freshness mechanism** (trusted clock, nonce, or challenge-response, via a profile) maps "valid"
  to "current" — carried by the same `chain_witness` profile's `freshness` block.
- **Immutable, append-only storage** (deployment) is what makes withholding/truncation *attributable*
  rather than silent.
- **Full RFC 8785** canonicalization (a breaking, version-bumped reference change) closes
  **canonicalization mismatch** for arbitrary records.
- **Mandatory `content_hash` for non-resolvable evidence** bounds **unbound withholding**.
- **Malicious producer** is *not* closeable by the format — only by independent corroboration. The
  honest mitigation is to say so.

## Why this is still useful

AIREP does not stop a determined insider, and it says so. What it *does* give — a tamper-evident,
position-bound, scope-honest receipt per decision — turns "trust me, the gates passed" into a record
that an auditor can **recompute, walk, and challenge**, and that an honest producer cannot silently
revise after the fact without breaking the hash. That is a smaller claim than "trustworthy AI," and a
defensible one.
