# AIREP v0.2 — AuthZEN end-to-end contract (W3)

> **Status: DRAFT for maintainer review. No implementation, no evidence.** This contract fixes
> what the end-to-end case must demonstrate and what it must not claim, before any code exists.
>
> Basis: `v0.2.0-alpha.1` / `b5ae87f74b386b11b8882865e50c3ad38120ff97`. Branched from the release
> basis, **not** from W1 or W2, so its evidence lineage stays independent of both.

## 1. What AD-11 requires

[AD-11](../../v0.2-design/ARCHITECTURE_DECISIONS.md) is deliberately narrow, and the constraint
is the point:

> **Authorization is referenced, never defined.**

A Decision Receipt may carry a reference to, and digest of, an external authorization decision —
an AuthZEN Authorization API 1.0 decision, an OAuth token or delegation evidence artifact —
including the PDP identity and the decision's own identifier. AIREP records **that** an
authorization decision was obtained and **binds its bytes**. It never restates or reinterprets
authorization semantics. The v0.1 `subject.principal` block with `established_by` remains the
identity-provenance anchor.

The failure mode this guards against is AIREP quietly becoming a second, weaker authorization
system. The end-to-end case must therefore demonstrate binding **without** interpretation.

## 2. What the E2E case must demonstrate

| # | Step | Observable |
|---|---|---|
| A1 | Obtain a real authorization decision from an AuthZEN 1.0 PDP | the request and response bytes as exchanged |
| A2 | Digest the decision and record the PDP identity and decision identifier | the digest, computed from the exact response bytes |
| A3 | Emit an AIREP Decision Receipt referencing it | the artifact, with the reference resolvable to A1's bytes by digest |
| A4 | Carry it through to a Control artifact | the authorization reference surviving the decision→control step intact |
| A5 | Verify the binding independently | recomputing A2's digest from A1's stored bytes and matching the artifact's recorded value |

**A5 is the measurement.** Everything before it is plumbing. What is being shown is that a third
party holding the AIREP artifact and the stored authorization response can confirm they belong
together — not that the authorization was correct.

## 3. The non-interpretation requirement

The case must show, and its evidence must record, that AIREP **did not**:

- restate the authorization decision's semantics in AIREP vocabulary;
- derive an AIREP class, verdict or reason from the authorization outcome;
- treat a `permit` as evidence of anything beyond "this decision was obtained and bound";
- substitute the authorization decision for `subject.principal` / `established_by`.

A demonstration that binds an authorization decision **and also** lets it influence AIREP's own
evaluation would violate AD-11 while appearing to satisfy it. That is the specific thing to test
for, not assume.

## 4. Negative cases — required

- **N1** a substituted authorization response whose digest no longer matches the artifact's
  recorded value — the binding check must fail;
- **N2** a decision bound to the wrong AIREP artifact — must not verify;
- **N3** a `deny` decision bound and carried correctly — the AIREP artifact's own class and
  reasons must be **unchanged** relative to the `permit` case, since AD-11 forbids the
  authorization outcome from driving AIREP evaluation. If this case shows any difference, that
  difference is a finding.

N3 is the one that actually tests AD-11 rather than testing digest arithmetic.

## 5. Evidence

- the AuthZEN request/response bytes, and the PDP identity and version;
- the recorded digest and decision identifier;
- the emitted Decision Receipt and the downstream Control artifact;
- the independent binding verification result;
- the three negative-case results with the cause each triggered;
- an explicit statement of what was **not** derived from the authorization outcome.

## 6. Claim boundary

A clean run would establish that an external authorization decision can be referenced and
byte-bound from an AIREP Decision Receipt, carried to a Control artifact, and independently
verified — and that AIREP's own evaluation is unaffected by the authorization outcome.

It would **not** establish that the authorization decision was correct, that the PDP is
trustworthy, that AIREP validates authorization semantics, or that any policy was correctly
expressed. It satisfies AD-15 clause (3) only in part — SCITT (W2) is separate — and does not
address clause (1) at all.

## 7. Open for maintainer decision

1. Which AuthZEN 1.0 PDP — a reference implementation, a hosted service, or a local instance.
2. Whether the OAuth token/delegation variant AD-11 also permits is exercised in this round or
   deferred, given it is a second binding shape rather than a second decision source.
3. Whether the authorization reference profile is normatively fixed in this release or stays a
   demonstrated shape until a second implementation carries it.
