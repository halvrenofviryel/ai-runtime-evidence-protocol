# EMILIA × AIREP planning notes — historical first-party record

**HISTORICAL / PROVISIONAL / FIRST-PARTY. Phionyx-authored planning notes. Not frozen, not run,
not an interoperability result. Superseded; retained for provenance.** Status date: 12 September
2026 (revision 2 of this note).

## Phionyx provisional planning scope

The Phionyx-selected source snapshot for this planning scope is **0.2.0**. Its selection root is
`evidence/revision-0.2/`: Cases 1–3 retained byte-identical from 0.1.0, Cases 4–5 revised. Eight
proposed AIREP records in total (0 + 2 + 1 + 2 + 3). Selecting 0.2.0 is a Phionyx planning
decision; it is not a freeze, not a result, and it does not invalidate 0.1.0 material, which
remains preserved and citable. No external approval or endorsement is claimed.

| Item | Identity | Status |
| --- | --- | --- |
| Mapping contract | `v0.3` | Phionyx proposal; not approved by anyone else |
| Case sheet | `v0.2`, five cases | Phionyx planning input |
| AIREP measurement target | `8a6c01ecce457aa94330c0ed7219e4c56ebfe771` (`v0.2.0-beta.1`) | Pinned, verified against local beta objects |
| EMILIA baseline | `b1275b08f91939a2330aee26a03d0a6bfda375d6` | Public upstream commit, selected by Phionyx as a source pin |
| Adapter revision | declared in package metadata only | Not verified Git provenance |
| Reference verifier / reconciler | beta CLI, network-less rehearsal over the 8 records with **proposed** operator inputs | `PRE_FREEZE_REHEARSAL`; see the matrix. Not an accepted run. |
| Interoperability result | — | **NONE** |

## What changed from the previous status note

- Case 4 now has a native execution source: the pinned `Gate.run` execution receipt plus an
  action-bound operation trace. The old missing-source finding is closed **as a capture
  limitation that has been addressed**, not as a protocol change. No Effect; Effect absence
  is not non-effect evidence.
- Case 5 now carries a disclosed **same-executor** observation with observer identity,
  method (`local-record-store.get`) and window, after a disclosed synthetic overwrite. That is
  in scope: an independent observer was not a prerequisite of this five-case planning scope.
  Same-executor observation is not upgraded to independence, and the Effect reports
  divergence, not success.
- The previous note's statement that Case 5 lacked observer metadata applied to 0.1.0 and is
  withdrawn for 0.2.0.

## Coverage limit, stated

The kernel behaviour `COMMITTED` + `INDETERMINATE` described in the mapping contract is **not
exercised** by any of the five selected cases. This is an explicit coverage limit of this planning
scope, not a defect and not "covered".

## Claim boundaries

The upstream source material originates from a public upstream repository and was separately
written; this planning record is explicitly **not** clean-room, **not** expected-blind; prior
exposure to AIREP material is disclosed; AI-assisted. No certification, adoption, independence
qualification or stable-release qualification is claimed or established. Nothing here establishes
a general same-version producer-consumer interoperability result, and nothing here is approved,
accepted, confirmed, reproduced or endorsed by any external party. Lab keys are public test keys;
a valid signature under them is not evidence of human approval.

## Deliberately not published here

Upstream-authored candidate source, captures and evidence bytes are excluded pending explicit
redistribution terms for the captured evidence as data (the code is Apache-2.0; the captured
records are not covered by a stated licence). No private correspondence or external-review
material is included.
