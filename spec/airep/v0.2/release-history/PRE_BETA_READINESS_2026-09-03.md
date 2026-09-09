# AIREP Core v0.2 — release readiness

**Mutable project status. Not evidence.** This file changes at every lifecycle step and is kept
outside every frozen/evidence-pinned object, for the same reason
[`class-verification/STATUS.md`](./class-verification/STATUS.md) is: normative text whose full-byte
digest is compared as a semantic-basis identity must not carry a status lifecycle. Nothing here is
citable as a measurement; each row points at the evidence object that is.

**Basis: [AD-16](../v0.2-design/ARCHITECTURE_DECISIONS.md#ad-16--core-release-boundary-and-companion-profile-policy)**
— *Core release boundary and companion-profile policy*. This matrix is **re-derived** from AD-16's
stable gate, not carried over from the pre-AD-16 matrix. Repository baseline `a3973ce3`.

## Status vocabulary

| Value | Meaning |
|---|---|
| `PASS` | The specified measurement ran and met its threshold; the evidence identity is recorded. |
| `FAIL` | It ran and did not meet its threshold. |
| `NOT_RUN` | The required measurement has not executed. |
| `EXTERNAL_REQUIRED` | Closure requires an independently controlled implementation or run. Not closable by maintainer-local work at any effort. |
| `BLOCKED` | Local work is prevented by an unresolved dependency or normative decision recorded below. |

`EXTERNAL_REQUIRED` is never upgraded by local work. Absence of observed failure is not capability
evidence. `NOT_RUN` / `NOT_MEASURED` / `NOT_EVALUATED` are never upgraded to success.

## Gate classes

| Class | Meaning | Blocks Core stable? |
|---|---|---|
| `CORE-ADOPTED` | Required by AD-16's Core v0.2.0 stable gate | **YES** |
| `LOCAL-MILESTONE` | Implementation route or supporting evidence this project chose | **NO** |
| `COMPANION` | Companion-profile work on its own versioned lifecycle (AD-10, AD-11, AD-12) | **NO** |
| `PROGRAMME` | Research / programme milestone | **NO** |

**Only `CORE-ADOPTED` rows can hold `v0.2.0` open.** A companion profile can never become a Core
stable blocker by being completed, delayed, or made normative in its own lifecycle — only an explicit
future Core architecture decision could change that (AD-16).

---

## Core gates — these block `v0.2.0` stable

| Gate | Requirement | Basis | Class | Blocks Core stable? | Status | Evidence identity | Blocker type |
|---|---|---|---|---|---|---|---|
| C-01 normative integrity construction | Domain tags, hash/signature/witness preimages, binding rules fixed and normative | AD-04, AD-05, AD-06 | `CORE-ADOPTED` | **YES** | `PASS` | `INTEGRITY.md` `sha256:2fca9a02ebd8b22807f51742278d7ddfc101e25ca6fd4fa844d6c6a537e98c11`; freeze basis PR #26 `9a30f972f28e4a0df6adb62d17f1b6e221216796` | — |
| C-02 artifact schemas | Five JSON Schema (2020-12) files expressing the accepted design contract, core closed | AD-03, AD-07 | `CORE-ADOPTED` | **YES** | `PASS` | 5 files; aggregate over sorted member digests `sha256:085f6126790dbc643893190b94ef31310760796a427d351f1248e25871752d46`; contract `schema-design/ARTIFACT_SCHEMA_DESIGN.md` ACCEPTED 2026-08-23 | — |
| C-03 normative conformance-class text | Normative Core / Authenticated / Witnessed text, not only a design contract | AD-09; AD-16 item 1 | `CORE-ADOPTED` | **YES** | `NOT_RUN` | Design contract only: `conformance-design/CONFORMANCE_CLASS_DESIGN.md` (ACCEPTED 2026-08-23, ODQ-1..7 decided). No normative text exists. | LOCAL — P2-A |
| C-04 two separately authored class verifiers | Two official verifiers written independently against the frozen contract | AD-14; AD-15 §2 | `CORE-ADOPTED` | **YES** | `PASS` | `verifier_py/class_verifier.py` `sha256:5d08c327…d01cc`; `verifier_node_r2/class_verifier.mjs` `sha256:e678ff57…bde4`; mandates `sha256:56e3c817…c62b` / `sha256:3fa9a488…9195`; frozen contract `sha256:7ecfce56ab576a495816df77e25442b25c1afdb22cc9828e47ba29a565138885` | — |
| C-05 verifier parity over the shipped Core surface | Same verdict, class, reason sets and exit code for every record, across **the normative validation surface that actually ships with Core** | AD-14 (preserved in full); AD-16 clarification | `CORE-ADOPTED` | **YES** | `NOT_RUN` | Prior evidence, current surface: official C1 parity run **PASS**, all hard gates, 0 findings, 60 cases + 15 probes, corpus aggregate `sha256:55f5189e38dfc81c6be68b5a51c789d5ed0f3ac8b0e57becfd7d796f1fddda4a`. Parity must be re-established over the **final** Core surface once C-03 and C-06 land. **AD-14 does not require any SCITT or AuthZEN schema.** | LOCAL — P5 |
| C-06 profile-extension parity capability | Both verifiers behave consistently for the Core-defined profile-validation mechanism | AD-07; AD-14; AD-16 item 7 | `CORE-ADOPTED` | **YES** | `NOT_RUN` | Profile **carriage** exists: `common.schema.json#/$defs/profiles` (`propertyNames` → `namespaced_id`, object values). The **validation** step exists in neither verifier. To be exercised with a repository-controlled, unmistakably **test-only** fixture — never named for SCITT, AuthZEN, or any real external system. **Open local normative decision N-01 (below) must be resolved first.** | LOCAL — P2-B, gated on N-01 |
| C-07 producer diversity | **≥2 producers** against the same applicable frozen v0.2 candidate, **≥1 genuinely non-maintainer**, and **each qualifying producer actually emits artifacts under that candidate** (existence is inventory, not interoperability) | AD-01 (≥2, preserved); AD-15 §1 (preserved); AD-16 item 2 | `CORE-ADOPTED` | **YES** | `EXTERNAL_REQUIRED` | 0 v0.2 producers exist. `producers/` targets **v0.1 only**. The Emek Can Doğru result is **v0.1.2** and contributes **zero** to the v0.2 count. Cannot be satisfied by maintainer-local work; remains `EXTERNAL_REQUIRED` until independently supplied v0.2 producer evidence against the applicable frozen candidate is received and reproduced at the strength that evidence permits. | EXTERNAL |
| C-08 independent consumer/verifier on the same candidate | ≥1 non-maintainer consumer/verifier exercised against the **same frozen v0.2 candidate**, at the exact evidentiary strength observed | AD-15 §2 (preserved); AD-16 item 3 | `CORE-ADOPTED` | **YES** | `EXTERNAL_REQUIRED` | A v0.2 consumer/verifier result exists against corpus revision `v0.1` (`sha256:b47f01c8…7923`), Certisyn implementation `sha256:2aef1212…eca8`, **17 AGREE / 1 DISAGREE**. That run targets an **earlier corpus revision, not the release candidate**, and was **not expected-blind**. It does not automatically satisfy this gate for a later, changed candidate. | EXTERNAL |
| C-09 cross-implementation corpus **constructed** | Three categories on the same frozen candidate: **(i)** project-maintained normative/adversarial cases incl. **≥1 deliberately broken case per artifact type** (AD-15 §2's term; the four types are Decision, Control, Execution, Effect); **(ii)** producer-output interoperability cases emitted by **each** qualifying producer; **(iii)** AD-03 reconciliation + multi-target / partial-observation cases | AD-03; AD-15 §2 (preserved); AD-16 items 4–5 | `CORE-ADOPTED` | **YES** | `NOT_RUN` | No reconciliation corpus exists. Corpus revision `v0.2` (`sha256:259b7f88…1569`) is a **starting asset, not the release-candidate corpus** — it lacks the AD-03 reconciliation surface, per-type broken cases, and any category (ii) producer output. | LOCAL — P4 (categories i, iii); category (ii) needs C-07 |
| C-11 cross-implementation corpus **passes, by role** | The required corpus **including category (ii) producer-output cases** passes under **(a)** official reference verifier A, **(b)** official reference verifier B, and **(c)** at least one qualifying **non-maintainer consumer/verifier** implementation — all against the **same frozen candidate** | AD-15 §2; **role ambiguity resolved by AD-16 item 5** | `CORE-ADOPTED` | **YES** | `EXTERNAL_REQUIRED` | Not established. Requires C-09's corpus plus all three role-distinct passes. **A producer does not satisfy (c) merely by existing** — it qualifies only if it independently implements the consumer/verifier evaluation surface. Producer diversity (C-07) and verifier diversity (C-08, C-11c) are **separate evidence dimensions** and are never traded against each other. A corpus that merely exists, passes only first-party, or passes only over category (i) does not satisfy this gate — **producer-specific disagreement or rejection must not be maskable by reference-only cases passing.** | EXTERNAL |
| C-10 reproducibility and frozen identity | Deterministic artifact identities, reproducible manifests, immutable evidence packages, no unresolved release-blocking disagreement | AD-16 item 8 | `CORE-ADOPTED` | **YES** | `NOT_RUN` | Precedent: corpus revision `v0.2` rebuilds to the same digest on repeat runs. Not yet established for the release candidate. | LOCAL — P11 |

## Local milestones — do not block `v0.2.0` stable

| Gate | Requirement | Basis | Class | Blocks Core stable? | Status | Evidence identity | Blocker type |
|---|---|---|---|---|---|---|---|
| L-01 fixed vectors | Cross-language byte agreement on the integrity construction | project (supports C-01) | `LOCAL-MILESTONE` | NO | `PASS` | Both generator outputs **byte-identical**: `vectors/out/python_vectors.json` and `node_vectors.json` both `sha256:3153ef094802fb657ba9a83169dede31662353088f68c5dd25a910f27b5bfb65`; inputs `sha256:a237c9e1…3c15`; manifest `sha256:c226a857…5980` | — |
| L-02 schema validation | Corpus discriminated as expected under two independent engines | project (supports C-02) | `LOCAL-MILESTONE` | NO | `PASS` | 117 fixtures; corpus aggregate `sha256:99e8c4a5…3d3a`; contract `sha256:1ae1a829…`; engines `sha256:0fd27ce5…`; result `SCHEMA_PARITY_MANIFEST.md` `sha256:1cabafb1…` — **ALL GATES PASSED** | — |
| L-03 first-party v0.2 producer | Reference producer for Decision / Control / Execution / Effect | project; planned route to C-07's count | `LOCAL-MILESTONE` | NO | `NOT_RUN` | No v0.2 producer exists. **AD-16 item 2: a first-party producer is not itself a normative requirement** — two genuinely independent producers would satisfy C-07 without it. It can never satisfy the non-maintainer half of C-07. | LOCAL — P3 |
| L-04 producer negative cases | Adversarial producer vectors (wrong previous, wrong chain id, domain-tag separation, malformed profile, cross-type replay, …) | project (supports L-03) | `LOCAL-MILESTONE` | NO | `NOT_RUN` | — | LOCAL — P3 |
| L-05 documentation claim audit | No claim exceeds observed evidence anywhere in published text | project claim discipline | `LOCAL-MILESTONE` | NO | `NOT_RUN` | — | LOCAL — P11 |

## Companion work — never blocks `v0.2.0` stable

Companion profiles have their own independently versionable lifecycle (AD-16). **They MAY themselves
become normative specifications within that lifecycle; that does not make them prerequisites of
AIREP Core stable unless a later explicit Core architecture decision says so.** Listed here for
visibility only.

| Gate | Requirement | Basis | Class | Blocks Core stable? | Status | Evidence identity | Blocker type |
|---|---|---|---|---|---|---|---|
| K-01 SCITT binding profile delivery | The SCITT binding profile as a companion specification | AD-10 (technical semantics preserved) | `COMPANION` | **NO** | `NOT_RUN` | 0 files with `scitt` in their path. Members not derivable from adopted text. | COMPANION — post-P5 |
| K-02 SCITT PoC | Registration + receipt verification against ≥1 SCITT implementation, end-to-end | AD-10; formerly AD-15 §3 (**superseded for Core gating by AD-16**) | `COMPANION` | **NO** | `NOT_RUN` | No PoC. External transparency service participation would be required for the non-simulated portion. | COMPANION — post-P5 |
| K-03 authorization-reference profile delivery | The AuthZEN/authorization-reference profile as a companion specification | AD-11 (technical semantics preserved, incl. the 2026-08-26 erratum) | `COMPANION` | **NO** | `NOT_RUN` | 0 files with `authzen` in their path. See defect **D-01**. | COMPANION — post-P5, see D-01 |
| K-04 AuthZEN reference case | An end-to-end authorization-reference case | AD-11; formerly AD-15 §3 (**superseded for Core gating by AD-16**) | `COMPANION` | **NO** | `NOT_RUN` | Not exercised. | COMPANION — post-P5 |
| K-05 MCP / A2A / OpenTelemetry profiles | Informative composition profiles | AD-12 (unchanged) | `COMPANION` | **NO** | `NOT_RUN` | Informative by original design; never a Core gate. | COMPANION |

## Programme work — never blocks `v0.2.0` stable

| Gate | Requirement | Basis | Class | Blocks Core stable? | Status | Evidence identity | Blocker type |
|---|---|---|---|---|---|---|---|
| R-01 external-standard mappings exercised | Generic "external-standard mappings exercised" | AD-01 clause **superseded for Core gating by AD-16** | `PROGRAMME` | **NO** | `NOT_RUN` | Retained for visibility. No longer a Core stable prerequisite. | PROGRAMME |
| R-02 foreign-system composition | Adapter experiment against a genuinely foreign system | release programme only — **in neither AD-01 nor AD-15** | `PROGRAMME` | **NO** | `EXTERNAL_REQUIRED` | None. **No third party is named as participating.** Absence of any foreign-system collaboration must never hold `v0.2.0` open. | PROGRAMME |

---

## Tallies

**23 independently status-bearing gates, each carrying exactly one status and an unambiguous YES or NO.**

| Class | Count | Blocks Core stable? |
|---|---|---|
| `CORE-ADOPTED` | 11 | **YES** |
| `LOCAL-MILESTONE` | 5 | NO |
| `COMPANION` | 5 | NO |
| `PROGRAMME` | 2 | NO |
| **Total** | **23** | **11 YES · 12 NO** |

| Status | Count | Gates |
|---|---|---|
| `PASS` | 5 | C-01, C-02, C-04, L-01, L-02 |
| `NOT_RUN` | 14 | C-03, C-05, C-06, C-09, C-10, L-03, L-04, L-05, K-01, K-02, K-03, K-04, K-05, R-01 |
| `EXTERNAL_REQUIRED` | 4 | C-07, C-08, C-11, R-02 |
| `BLOCKED` | 0 | — |
| **Total** | **23** | — |

5 + 14 + 4 + 0 = 23, reconciling against the 23 gate rows.

**No gate is `BLOCKED`.** Under the pre-AD-16 basis two gates were blocked; AD-16 dissolves both,
because neither the SCITT nor the AuthZEN normative gap can hold a Core gate open any longer.

## Open local normative decision N-01 — unknown-profile behaviour

The Core profile-extension mechanism (C-06) requires a decision that **adopted Core text does not
determine**: what a verifier does when an artifact carries a `profiles.<namespaced-id>` key for which
**no schema is registered**. AD-14 requires parity; it does not specify the behaviour. ODQ-12 states
the registered short-name registry **starts EMPTY**, so this is the ordinary case, not an edge case.

Candidate behaviours (accept-and-ignore, reject-unknown, or report-without-class-effect) each carry
different conformance consequences. **This must be resolved as a deliberate local normative decision
in P2-B. It must not be inferred from SCITT or AuthZEN requirements, from any external standard, or
from convenience.** Until resolved, C-06 cannot be implemented.

## Defect D-01 — AD-11 cites a contract file that does not exist

AD-11's 2026-08-26 erratum ends: *"See `AUTHZEN-IR-1` in
`spec/airep/v0.2/authzen/AUTHZEN_E2E_CONTRACT.md`."* Verified against the full tree: **no file has
`authzen` or `scitt` anywhere in its path**, and `AUTHZEN-IR-1` occurs exactly once repo-wide — in
that citation. The referenced contract does not exist.

Recorded as a repository defect, not repaired by deletion; AD-11's adopted text is not edited to make
the reference tidy. **Under AD-16 this is a companion-work defect (K-03) and no longer blocks Core
stable.** Missing AuthZEN semantics are never invented to close a gate.

## Non-claims this matrix does not disturb

- The Emek Can Doğru v0.1.2 producer result and the Certisyn v0.2 consumer/verifier result target
  **different frozen versions**, are separate evidence classes, and are **not additive**.
- Neither establishes producer↔consumer interoperability for any version. No AIREP version has both
  an independent producer and an independent consumer measured against it.
- Historical v0.1 producer evidence contributes **zero** to C-07's v0.2 producer count.
- Expected-aware validation is not expected-blind validation. Signature validity is not authority
  validity. Decision evidence is not execution evidence; execution evidence is not observed effect;
  receipt existence is not proof of delivery, enforcement, completeness, or real-world effect.
- AD-16 is a maintainer scope decision. It was **not** requested, prompted, endorsed or reviewed by
  IETF, the SCITT or AuthZEN working groups, or any external party. No external participation is
  claimed, and this is **not** a removal of SCITT or AuthZEN support.
