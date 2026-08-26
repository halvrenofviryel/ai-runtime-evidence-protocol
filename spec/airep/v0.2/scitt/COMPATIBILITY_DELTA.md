# W2 SCITT compatibility delta analysis

Authorized by `SCITT_COMPATIBILITY_DELTA_ANALYSIS_AUTHORIZED` after
`W2_SCITT_STANDARDS_PREFLIGHT — INDETERMINATE`. Measured 2026-08-26.

**Document analysis only. Nothing was deployed, built or executed.** Every finding below is a
comparison of published specification text. No statement here describes observed behaviour of
`scitt-ccf-ledger` 0.19.0.

Sources compared, all retrieved 2026-08-26: `draft-ietf-scitt-architecture-11`, RFC 9943,
`draft-ietf-cose-merkle-tree-proofs-08`, RFC 9942, `draft-birkholz-cose-receipts-ccf-profile-03`,
`draft-ietf-scitt-receipts-ccf-profile-04`, `draft-ietf-scitt-scrapi-09`,
`draft-ietf-scitt-scrapi-11`.

---

## Finding 0 — the build's own alignment citations do not resolve

Before the three matrices, one result that changes how they should be read.

`docs/scitt.md` at tag `0.19.0` cites **Architecture Draft 11 §4.2** (Signed Statement inputs),
**§4.1.1** (registration policy) and **§4.4** (Transparent Statement output).

**None of those subsections exist in Draft 11.** Draft 11 §4 is "Definition of Transparency" and
has no subsections at all. The relevant material is at §5.1.1 (Registration Policies), §6 (Signed
Statements) and §7 (Transparent Statements) — and RFC 9943 carries the *same* numbering for all
three. Those `4.x` numbers belong to a pre-11 draft numbering.

**Consequence.** "This build targets Draft 11" is the build's self-description, and its citations
are stale relative to the very draft it names. It is evidence of intent, not of behaviour. Every
row below is therefore a *specification* delta; which side of it the code actually sits on is
`NOT_MEASURED` and can only be settled by observing the running service.

---

## Matrix 1 — Architecture Draft 11 → RFC 9943

| # | Change | Class | Touches S1–S6? |
|---|---|---|---|
| 1.1 | **Signed Statement wire structure is unchanged.** Both define the same CDDL protected-header set: `alg: 1 => int`, `kid: 4 => bstr`, `CWT_Claims: 15 => CWT_Claims` with `iss: 1 => tstr`, `sub: 2 => tstr` | **irrelevant — no change** | S2 — and this is the S2 answer |
| 1.2 | Section numbering for the relevant material is identical (§5.1.1, §6, §7) | irrelevant | none |
| 1.3 | New normative: "A TS **MUST** ensure that a Signed Statement is registered before releasing its Receipt" | **semantic-only** | S3→S4 ordering. A TS obligation, not an artifact format |
| 1.4 | New normative: issuer identity **MUST** be bound by an identifier in the protected header, verified per STD 96 | **semantic-only** | S2/S3. Constrains the TS's check, not our bytes |
| 1.5 | New normative: registration policies and trust anchors **MUST** be made transparent by registering them as Signed Statements | semantic-only | none — TS operations |
| 1.6 | Receipt now defined by **normative reference to RFC 9942** (was the draft); receipt profiles **MUST** support inclusion proofs | **semantic-only** | S4/S5 — reference target moves, structure does not (see Matrix 2) |
| 1.7 | Draft-11's numbered registration-step list restructured; TCB/remote-attestation paragraph dropped | irrelevant | none |
| 1.8 | New §6.2 "Signing Large or Sensitive Statements" (+184 words in §6) | semantic-only | S2 — an added *option*, not a changed requirement |

**Axis result: no wire-visible change on any surface S1–S6 touches.** The Signed Statement the PoC
would produce at S2 is byte-shaped identically under both documents. The additions are obligations
on the Transparency Service.

## Matrix 2 — COSE Receipt Draft 8 + CCF Profile Draft 3 → RFC 9942 + `draft-ietf-scitt-receipts-ccf-profile-04`

| # | Change | Class | Touches S1–S6? |
|---|---|---|---|
| 2.1 | **COSE header labels unchanged**: `vds` = **395**, proofs = **396**, inclusion proof = **-1**, consistency = **-2**, in both Draft 8 and RFC 9942 | **irrelevant — no change** | S4/S5 — and this is the receipt-bytes answer |
| 2.2 | Inclusion and consistency proof types present in both, same roles | irrelevant | S5 |
| 2.3 | **CCF profile document lineage changed**: the individual draft is **Replaced** / **Adopted by a WG**; the live line is `draft-ietf-scitt-receipts-ccf-profile-04` | **semantic-only** (provenance, not bytes) | S5 — cite the WG document, not the replaced one |
| 2.4 | Registry renamed "Verifiable Data Structure" → **"COSE Verifiable Data Structure Algorithms"**; inclusion-proof label restated as `(-1)` | **semantic-only** | S5 — same label, clearer prose |
| 2.5 | **`CCF_LEDGER_SHA256` carries value `TBD_1` in *both* the old and the new profile.** No IANA assignment exists on either side | **wire-visible — but identical on both sides** | S4/S5 — see below |
| 2.6 | WG draft adds `internal-transaction-hash` / `internal-evidence` discussion; verification algorithm restated with an explicit label assertion | semantic-only | S5 — editorial precision |

**Axis result: receipt bytes are stable across the version change, but carry a standing
pre-standard defect that neither version fixes.** 2.5 is the important row. The CCF verifiable-data-
structure algorithm identifier is **unassigned in both** the draft the build targets and the WG
document that replaced it. Whatever value a receipt carries at S4 is a placeholder under either
lineage. That is not drift — it is a property of anchoring in CCF at all today, and it must be
stated in the PoC's claim boundary regardless of which document is cited.

## Matrix 3 — SCRAPI Draft 09 → SCRAPI-11

| # | Change | Class | Touches S1–S6? |
|---|---|---|---|
| 3.1 | **Synchronous successful registration is `201 Created` in *both* 09 and 11**, with the Receipt returned directly in the body and a `Location` header **MUST** | **irrelevant — no change** | **S3/S4 — and this is the decisive row** |
| 3.2 | Asynchronous "registration is running": **`303 See Other` (09 §2.3.2) → `202 Accepted` (11 §2.3.2)** | **wire-visible** | S3 — async path only |
| 3.3 | Operation-check resource: **`302 Found` (09 §2.4.1) → `204 No Content` / `200` (11)** | **wire-visible** | S3 — async path only. This is upstream issue **#414** |
| 3.4 | SCRAPI-11 §2.3: clients **MUST** fall back to generic class semantics (1xx…5xx) for unrecognised codes, and **MUST** rely on the RFC 9290 problem-details object rather than the status code alone | **semantic-only** | S3 — client-side robustness rule |
| 3.5 | SCRAPI-11 remains an Internet-Draft; it is not an RFC | n/a | bounds the strength of any "per SCRAPI" claim |

**Axis result: the divergence is real, wire-visible, and confined to the asynchronous flow.** The
synchronous path is byte-identical between 09 and 11.

Row 3.4 does **not** rescue rows 3.2/3.3: `302`/`303` are **3xx** and `202` is **2xx**, so a client
falling back to class semantics reads redirection where the current draft means success-pending.
The fallback rule reduces brittleness within a class; it does not bridge a class change.

But rows 3.2/3.3 are avoidable. The maintainer relays that upstream states the implementation can
return the receipt directly — which is exactly the §2.3.1 synchronous shape, unchanged since 09.
**I have not verified that behaviour** and cannot without deploying, which is out of scope here.
It is the single thing the PoC must confirm at run time before any SCRAPI claim is made.

---

## Verdict

### `COMPATIBLE_WITH_EXPLICIT_DRAFT_LIMITATION`

Not `MATERIAL_INCOMPATIBILITY`: no surface that S1–S6 touches changed shape. The Signed Statement
CDDL is identical (1.1), the receipt header labels are identical (2.1), and the synchronous
registration exchange is identical (3.1). Nothing found would prevent the PoC from running or make
its measurement meaningless.

Not `COMPATIBLE_FOR_SCOPED_POC` either, because three limitations must be stated on the face of any
result, not discovered by a reader:

1. **The CCF algorithm identifier is unassigned (`TBD_1`) in every published version.** Receipts
   carry a pre-standard placeholder. No wording can make an S4/S5 result "per RFC 9942" in the
   sense a reader would assume.
2. **The asynchronous registration path is genuinely divergent** (3xx→2xx class change). The PoC
   qualifies only if it demonstrably takes the synchronous `201` path, and that must be *recorded
   as observed*, not assumed from upstream commentary.
3. **The build's self-description does not resolve** (Finding 0). Its own citations point at
   sections that exist in no version of the document it names, so the PoC must record observed
   behaviour and cite the specification text directly — never "as documented by the implementation".

### Conditions on proceeding

- Cite **RFC 9943** and **RFC 9942** for the architecture and receipt surfaces, since the relevant
  text is unchanged, and `draft-ietf-scitt-receipts-ccf-profile-04` for the CCF profile — **never**
  the replaced individual draft.
- Cite **SCRAPI-11 §2.3.1** for the registration exchange only after observing a `201`. If the
  observed exchange is `303`/`302`, the result is scoped to SCRAPI-09 and must say so.
- Record the CCF algorithm identifier **as observed on the wire**, next to the fact that it is
  unassigned in both profile versions.
- The §6 claim boundary must name all three limitations above.

**Implementation remains on HOLD pending the maintainer's decision on this verdict.**

## Verification record

| Check | Source | Result |
|---|---|---|
| Draft-11 §4.1.1/§4.2/§4.4 exist? | `draft-ietf-scitt-architecture-11` full text | **No** — §4 has no subsections in Draft 11 or RFC 9943 |
| Signed Statement CDDL | both documents | identical: `alg:1`, `kid:4`, `CWT_Claims:15` with `iss:1`, `sub:2` |
| Architecture normative deltas | paragraph-level comparison | 32 normative paragraphs → 24; additions are TS obligations |
| COSE receipt labels | Draft 8 vs RFC 9942 | `395`, `396`, `-1`, `-2` present in both |
| CCF algorithm identifier | profile 03 vs WG 04 | `CCF_LEDGER_SHA256` = `TBD_1` in **both** |
| CCF profile lineage | Datatracker states | individual = Replaced + Adopted by a WG; successor rev 04 (2026-08-24) |
| SCRAPI register codes | 09 vs 11 section titles + examples | 09: 201 / 303 / (op) 302 · 11: 201 / 202 / (op) 200, 204 |
| SCRAPI-11 sync semantics | §2.3.1 full text | "MAY return it directly", `201 Created`, `Location` header MUST |
