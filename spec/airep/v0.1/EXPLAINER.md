# AIREP — Explainer: a tutorial introduction (v0.1)

> This document **teaches** the AIREP format in plain language. It does not define
> conformance. For the exact, binding rules an implementer builds against, see the
> normative specification, [`SPEC.md`](./SPEC.md). For the format's maturity and open
> items, see [`STATUS.md`](./STATUS.md).

## 1. What this is, and who it is for

When an AI system makes a decision — answer this, refuse that, hand the matter to a
person — someone may later need to ask a simple question: *what did it decide, why, and
on what basis?*

Today, every system answers that question differently, or not at all. There is no shared
way to write down a single AI decision so that an outsider — an auditor, a regulator, a
customer, a teammate on a different product — can read it and check it.

AIREP is a proposal for that shared way. It is a small, fixed format for **one record per
decision** — published openly so it can be examined, implemented, and improved, not handed
down as a finished standard.

> **What AIREP is, in one line.** AIREP is a runtime evidence layer for AI governance: it
> does not make AI truthful, but it makes AI decisions inspectable, bounded, and
> tamper-evident.

Think of the record as a **receipt**. When you buy something, the receipt says what you
bought, when, for how much, and it carries a stamp proving the shop issued it. You can
keep it, show it to someone else, and they can trust it without phoning the shop. An AIREP
record is a receipt for an AI decision.

You do not need any particular AI model, vendor, or programming language to write or read
these receipts. That is the whole point: **one receipt format that anyone can read.**

This document explains the format and the rules for using it. If you have never seen AIREP
before, read it top to bottom; each idea is explained before it is used.

## 2. One record, walked through

Let us follow a single decision.

An AI assistant named **Acme** is asked a question. Acme checks a safety rule, decides the
answer is acceptable, and releases it. Here is the receipt Acme writes:

```json
{
  "airep_version": "0.1",
  "subject":  { "runtime": "acme", "producer": "acme-governor/1.0",
                "decision_index": 0, "timestamp_utc": "2026-05-30T09:00:00Z" },
  "input":    { "input_ref": "sha256:9f2c…",
                "governance_state": { "policy_version": "p1" } },
  "claim":    { "assertion": "answer released after the safety rule passed",
                "basis": ["safety_rule"] },
  "output":   { "result_ref": "sha256:7a10…" },
  "evidence": [ { "type": "policy", "ref": "policy://safety/v1",
                  "content_hash": "sha256:1111…", "resolvable": true } ],
  "directive":{ "verb": "release", "policy_basis": ["safety_rule"] },
  "scope":    { "covers": ["the safety rule was checked and passed"],
                "does_not_cover": ["whether the answer is factually correct"] },
  "integrity":{ "previous": "sha256:0000…", "current": "sha256:abcd…",
                "canonical_json": true,
                "signature": { "alg": "Ed25519", "value": "…" } }
}
```

(The `sha256:…` values above are **abbreviated for readability**. Fully-computed, reproducible
records — real hashes and Ed25519 signatures — are in [`examples/`](./examples/).)

Read it top to bottom. Each part answers one question.

- **`subject` — who decided, and when.** "The runtime *acme* made decision number 0 at
  9am." `decision_index` counts decisions in order, starting at 0.
- **`input` — what was decided on.** We do **not** store the question itself inside the
  receipt. We store a *pointer* to it (`input_ref`) and, if useful, a fingerprint of it.
  We also note the state of the rules at that moment (`governance_state`).
- **`claim` — the thing Acme is asserting.** Here: "answer released after the safety rule
  passed." `basis` lists the rule the claim rests on.
- **`output` — the answer.** Again a pointer (`result_ref`), not the answer text.
- **`evidence` — the proof behind the claim.** A list of pointers. Here, one: the safety
  policy that was checked. Each item is marked `resolvable` — `true` if a checker can
  actually fetch and inspect it, `false` if it has been hidden (but its fingerprint is
  still recorded, so it can be matched later).
- **`directive` — the decision itself, as one word.** Acme chose **`release`**. The full
  set of words a decision can be is: `release`, `block`, `defer`, `redact`,
  `escalate_to_human`, `kill`. `policy_basis` lists which rules produced the decision.
- **`scope` — the honest part.** "This receipt *covers*: the safety rule was checked. It
  *does not cover*: whether the answer is factually correct." A receipt that hides its
  blind spots is worse than no receipt, so AIREP makes you state them.
- **`integrity` — the stamp.** This is what makes the receipt trustworthy. Section 3
  explains it.

A receipt written this way can be handed to anyone. They can read what was decided, see
the proof, and — using the stamp — confirm it has not been altered. They do not need
access to Acme or to whoever built it.

## 3. The stamp: making a record tamper-evident

The `integrity` block is three simple ideas.

**A fingerprint.** Take the whole record and run it through a standard one-way function
(SHA-256). Out comes a short string — the *fingerprint* (`current`). Change a single
character anywhere in the record and the fingerprint changes completely. So if you are
handed a record and its fingerprint, you can recompute the fingerprint yourself; if it
matches, the record is exactly as written.

**A seal.** The writer signs the fingerprint with a cryptographic key, producing
`signature`. Anyone with the matching public key can confirm the seal — proving *who*
wrote the record, not just that it is unchanged. AIREP does not force one key system; any
standard one works (Ed25519, HMAC, and others).

**A chain.** Each record records the fingerprint of the record before it (`previous`). So
the records form a chain, like links. Remove or alter any record in the middle and the
chain visibly breaks. The very first record points back to a fixed all-zero fingerprint,
which marks the start of the chain.

Together: you cannot quietly change a record (the fingerprint breaks), forge who wrote it
(the seal breaks), or delete one from history (the chain breaks).

## 4. Writing it the same way every time

A fingerprint is only useful if everyone computes the *same* fingerprint for the *same*
record. But JSON can be written many ways — keys in any order, extra spaces — and each
spelling would produce a different fingerprint.

So AIREP records are written in one **canonical** form: keys in a fixed order, no
insignificant spacing. (The agreed method is RFC 8785, the JSON Canonicalization Scheme.)
Write the record the canonical way, and the same record always produces the same
fingerprint — anywhere, in any language. This single rule is what turns an ordinary log
line into checkable evidence.

## 5. Replaying a decision later

Because the record carries the input pointer, the rule state, the evidence pointers, and
the chosen decision, a checker can **replay** it: recompute the fingerprint, follow the
chain, fetch the resolvable evidence, and read the recorded decision against the rules and
scope it was recorded under — all offline, without re-running the AI. Replay confirms the
record is intact and internally consistent; it does not judge whether the decision was the
*right* one.

One honest limit: replay proves *the path the decision took*, recorded faithfully. It does
**not** re-run the model and does not promise the AI would say the same thing twice. AIREP
records what happened; it does not make a probabilistic model deterministic.

## 6. Saying what you did not check

This is the rule that sets AIREP apart, so it is stated plainly:

> **Every record must fill in `scope.covers` and `scope.does_not_cover`.**

A claim is only as good as what it leaves out. If the safety rule was checked but factual
accuracy was not, the record must say so. A checker reading the receipt then knows exactly
what it may rely on — and what it may not. And if a piece of evidence is marked
`resolvable: false` (hidden), a checker must treat it as *unconfirmed*, never as verified.

## 7. Adding extra detail without breaking neutrality

The nine core members above (the eight parts walked through in Section 2, plus the
`airep_version` tag) are all any system needs, and they are deliberately generic. But a real
system often wants to record more — a bank wants the loan reason codes; a game wants the
age-rating check; one particular engine wants its own internal numbers.

All of that goes in one optional place: a `profiles` block.

```json
"profiles": {
  "phionyx": { "state_vector": { "coherence": 0.75, "amplitude": 5.4 } },
  "finance": { "adverse_action": { "reason_codes": ["DTI_TOO_HIGH"] } }
}
```

Anything vendor-, model-, or domain-specific lives under `profiles.<name>` and **nothing
extra lives in the core**. This keeps the receipt readable by everyone: a reader who does
not care about a particular profile simply ignores it.

There is a simple test for whether a record kept the core clean, the **neutrality test**:
*delete the whole `profiles` block; the record must still be a valid core record.* If it
is, no vendor-specific content leaked into the shared part. (This test checks the top
level. Hiding vendor data *inside* a core part — say, sneaking engine numbers into
`governance_state` — is against the rules but is caught by review, not by this test.)

Five profiles ship on disk today, described in the [`profiles/`](./profiles/) directory: key
trust, EU AI Act logging, NIST AI RMF, OWASP/threat-catalogue tagging, and observability
transport. The finance and game examples above are illustrations of the *shape* a profile
takes, not profiles that ship yet — more profiles (other regulations and domains) are
proposed, and anyone can define one by following the neutrality test. Profiles are optional:
a plain, single-system record uses no profile at all.

## 8. Checking a record

A record is a **valid core record** when:

1. it matches the core format ([`core.schema.json`](./core.schema.json)),
2. its fingerprint recomputes correctly and its chain links back,
3. it passes the neutrality test (delete `profiles`, still valid).

A runnable checker and a set of example receipts to test against are in the
[`conformance/`](./conformance/) directory.

## 9. What a record does and does not promise

- **It carries pointers, not content.** The question, the answer, and the evidence are
  referenced by pointer and fingerprint, not copied in. So a record can be kept and shared
  without exposing private data, and content can be redacted while the fingerprint still
  anchors it.
- **It proves the decision path, not the truth.** A valid record proves what the system
  recorded and that no one altered it. It does **not** prove the underlying answer was
  correct — that is exactly why `does_not_cover` exists.
- **Key trust is arranged separately.** AIREP fixes the receipt format. How you distribute
  and trust signing keys is a deployment choice (a profile may pin one).

---

*AIREP v0.1 is a proposed open format with one reference implementation; it is not a
ratified standard. Its current maturity, the reference implementation's status, and the
open engineering items are recorded in [`STATUS.md`](./STATUS.md) — kept separate from this
explanation on purpose.*
