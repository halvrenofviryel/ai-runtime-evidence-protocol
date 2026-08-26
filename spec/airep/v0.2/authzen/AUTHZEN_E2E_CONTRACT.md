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
including the PDP identity and, in AD-11's own wording, "the decision's own identifier"
*(see ruling AUTHZEN-IR-1 below: AuthZEN 1.0 defines no such identifier, so this part of
AD-11's description has no counterpart in the standard and is not a qualifying element)*. AIREP records **that** an
authorization decision was obtained and **binds its bytes**. It never restates or reinterprets
authorization semantics. The v0.1 `subject.principal` block with `established_by` remains the
identity-provenance anchor.

The failure mode this guards against is AIREP quietly becoming a second, weaker authorization
system. The end-to-end case must therefore demonstrate binding **without** interpretation.

## 2. What the E2E case must demonstrate

### Ruling AUTHZEN-IR-1 — no synthetic decision identifier

The previous draft asked for "the decision's own identifier". **AuthZEN Authorization API 1.0
defines no such thing.** Verified against the specification source: it contains no decision
identifier of any kind, and an Access Evaluation response is a Decision entity — typically
`{"decision": true}` or `{"decision": false, "context": {...}}`. The correlation mechanism the
standard *does* define is `X-Request-ID`: the PEP MAY supply it, and *"if the PEP specified a
request identifier in the request, the PDP MUST include the same identifier in the response"*.

Qualifying binding for the AuthZEN 1.0 case is therefore:

- the **PDP identity**;
- the **exact request bytes**;
- the **exact response bytes**;
- the **response digest**;
- `X-Request-ID`, where present, as the **exchange correlation identifier**;
- the AIREP record's reference/digest binding to that evidence.

`X-Request-ID` is **never** to be called a "decision identifier". If a PDP emits a
vendor-specific decision id it may be recorded as optional vendor evidence, but it is not a
qualification requirement. **AIREP does not mint a synthetic PDP decision identifier.**

| # | Step | Observable |
|---|---|---|
| A1 | Obtain a real authorization decision from an AuthZEN 1.0 PDP | the request and response bytes as exchanged, with `X-Request-ID` if used |
| A2 | Digest the response and record the PDP identity | the digest, computed from the exact response bytes |
| A3 | Emit an AIREP Decision Receipt referencing it | the artifact, with the reference resolvable to A1's bytes by digest |
| A4 | Emit a Control artifact **referencing that Decision** | the Control's `decision_ref`, and the authorization evidence resolved **transitively** through the Decision — **not** copied into Control |
| A5 | Verify the binding independently | recomputing A2's digest from A1's stored bytes and matching the artifact's recorded value |

**A4 carries the authorization binding in exactly one place.** The Decision Receipt holds it;
the Control artifact reaches it through its own `decision_ref`. Copying the authorization
reference forward into Control would create two copies of the same external evidence that can
later diverge, and nothing needs the duplicate.

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

### Ruling AUTHZEN-IR-2 — body binding vs transcript correlation

`X-Request-ID` is an HTTP **header** correlation property; the authorization decision is the
response **body**. "Exact response bytes" must not be read as one blob covering both, or a header
change would silently alter the decision digest and N1 and N2 would stop being separable.

- the authorization decision digest is over the **exact response body bytes**;
- request and response **bodies are hashed and recorded separately**;
- `X-Request-ID` request and response header values are recorded as **transcript metadata**,
  separately from any body digest;
- **N2 tests the header-correlation predicate**; **N1 tests the body-binding predicate**;
- the AIREP authorization evidence digest **never** folds header values into the body digest;
- a full HTTP capture may be kept as a separate evidence artifact, but it is **not** a normative
  binding input.

This keeps a body mutation (N1) and a header-correlation mismatch (N2) independently detectable,
which is the same single-target discipline W1 applies to its fixtures.

## 4. Negative cases — required

- **N1** a substituted authorization response whose digest no longer matches the artifact's
  recorded value — the binding check must fail;
- **N2** a **request/response correlation mismatch**: the PEP sent `X-Request-ID: A` and the
  captured response carries a different identifier, or the profile records a different one — the
  transcript binding must fail. (The earlier draft used "a decision bound to the wrong AIREP
  artifact". That was a bad test: referencing one AuthZEN decision from more than one AIREP
  record is not prohibited, and deciding that a pairing is "wrong" would require AIREP to
  interpret subject/action/resource like an authorization engine — precisely what AD-11 forbids.
  Correlation mismatch tests a real, normative protocol property instead.)
- **N3** a `deny` decision bound and carried correctly — the AIREP artifact's own class and
  reasons must be **unchanged** relative to the `permit` case, since AD-11 forbids the
  authorization outcome from driving AIREP evaluation. If this case shows any difference, that
  difference is a finding.

N3 is the one that actually tests AD-11 rather than testing digest arithmetic. Note that under
AuthZEN a `deny` is a **successful** authorization response — HTTP 200 with `"decision": false`,
not a transport failure — so a `deny` lowering an AIREP class would be a genuine AD-11
violation, not a plausible edge case.

## 5. Evidence

- the AuthZEN request/response bytes, and the PDP identity and version;
- the recorded response-body digest, the PDP identity, and the `X-Request-ID` values from
  request and response where present;
- the emitted Decision Receipt and the downstream Control artifact;
- the independent binding verification result;
- the three negative-case results with the cause each triggered;
- an explicit statement of what was **not** derived from the authorization outcome.

### 5.1 The PoC wire shape (pinned — experimental, PoC-only)

The alpha common schema constrains `profiles` only as *namespaced key → object*
(`common.schema.json` `$defs/profiles`); it does not define any inner member set. Without pinning
it here the implementation would invent one, so the exact shape is fixed below.

**Profile key:** `airep.authzen-poc` — verified against the `namespaced_id` grammar.

**Closed member set.** Exactly these members; no others are permitted in the PoC.

| Member | Required | Type | Meaning |
|---|---|---|---|
| `profile_version` | yes | string, exactly `"poc-1"` | PoC shape version. Not an AIREP version. |
| `pdp_identity` | yes | string | The PDP identity recorded per AD-11. |
| `request_evidence_ref` | yes | string | The `ref` of the `evidence[]` entry carrying the AuthZEN request body. |
| `response_evidence_ref` | yes | string | The `ref` of the `evidence[]` entry carrying the AuthZEN response body. |
| `request_id` | no | string | The `X-Request-ID` sent by the PEP, when one was sent. |
| `response_request_id` | no | string | The `X-Request-ID` returned by the PDP, when one was returned. |

**Digests live in `evidence[]`, never here.** `request_evidence_ref` and `response_evidence_ref`
MUST each resolve to an entry in the same Decision Receipt's `evidence[]` array, matched on that
entry's `ref`. The bound body digest is that entry's `content_hash`, which the schema already
requires on every evidence item. The profile MUST NOT carry a second copy of either digest: one
digest, one place, so the two can never disagree.

### Ruling AUTHZEN-IR-3 — PoC evidence must be resolvable

Both entries carry:

- `type: "policy"` — the correct category in the existing closed vocabulary for an authorization
  request/response exchange;
- **`resolvable: true`**;
- `content_hash` — the digest of the exact body bytes.

`resolvable` is not a formatting preference. AIREP's inherited semantics are that `true` means a
verifier can fetch and check the referenced material, and `false` means the material is
unavailable or redacted. The A5 measurement re-reads the stored request and response body bytes
and recomputes their digests — so this evidence **is** available, inside the PoC package, and
declaring it `false` would misdescribe the very thing the measurement depends on.

Both refs MUST therefore resolve deterministically from within the PoC evidence bundle.

An earlier draft of this section specified `resolvable: false`. That was wrong for a qualifying
positive run. If a body is ever *deliberately* withheld, that is a different negative or privacy
scenario — it is not a qualifying positive E2E case.

**Correlation.** When both `request_id` and `response_request_id` are present they MUST be equal —
this is the positive case, and it is the property AuthZEN 1.0 makes normative when the PEP sends
`X-Request-ID`. **N2 measures exactly this inequality.** Both members are optional because the
Authorization API does not require the header; absence is not a failure, and a missing pair is
never reported as a correlation mismatch.

**Headers are never bound.** `response_evidence_ref`'s `content_hash` is a digest of the exact
response **body** bytes. No header value — `X-Request-ID` included — enters that digest, per
`AUTHZEN-IR-2`. `response_request_id` is transcript correlation and carries no integrity weight.

**No decision identifier.** Per `AUTHZEN-IR-1` and the AD-11 erratum, neither member above is a
decision identifier, and the PoC MUST NOT add one. AuthZEN Authorization API 1.0 defines no
decision identifier; `X-Request-ID` is an exchange correlation identifier.

**Status — PoC-only.** This shape is experimental and demonstrated, not normative. It is not
added to any schema, does not become a v0.2 profile, and binds nothing onto `v0.2.0-alpha.1`.
A conformance-relevant freeze waits for a second PDP or an external implementation carrying it,
per §7.

## 6. Claim boundary

A clean run would establish that an external authorization decision can be referenced and
byte-bound from an AIREP Decision Receipt, carried to a Control artifact, and independently
verified — and that AIREP's own evaluation is unaffected by the authorization outcome.

It would **not** establish that the authorization decision was correct, that the PDP is
trustworthy, that AIREP validates authorization semantics, or that any policy was correctly
expressed. It satisfies AD-15 clause (3) only in part — SCITT (W2) is separate — and does not
address clause (1) at all.

## 7. Decided (maintainer, 2026-08-26)

**PDP — Keycloak 26.7.2 in a local container, with the exact image digest pinned.** Keycloak
added AuthZEN Authorization API 1.0 PDP support from 26.7.0, implementing the Evaluation and
Evaluations endpoints. The feature is **experimental**, and that status must be recorded
explicitly in the evidence metadata rather than left for a reader to discover.

**The OAuth token / delegation variant is deferred.** AD-11 permits it, but it is a second
binding *shape* rather than a second decision source, and AD-15 clause (3) is satisfied by the
AuthZEN case. Adding it now widens scope for no gate benefit.

**The authorization reference profile stays a PoC/informative demonstrated shape**, exactly as
the SCITT projection mapping does in W2. No new normative profile semantics are bound onto
`v0.2.0-alpha.1`. A freeze decision waits for a second PDP or an external implementation
carrying it.
