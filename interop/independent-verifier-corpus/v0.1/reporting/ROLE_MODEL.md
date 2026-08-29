# Roles

Recorded separately, because in several findings this month different people held each position.
**Each person vouches only for work they personally performed or checked.** Nobody's name appears
against a measurement they did not make.

| Role | Meaning |
|---|---|
| **originator / corpus author** | produced the corpus and its expected results |
| **implementation / test author** | wrote the verifier or test that produced a result |
| **independent reproducer** | re-ran someone else's work and reports what they observed |
| **adjudicator** | resolved a disagreement between two results |

Only one attribution is pre-filled:

> originator / corpus author: **Ali Toygar Abak**

Every other role is **blank by design**. No one is pre-assigned to a role they have not accepted.

## Contribution kind

The conservative description, to be used unless the parties agree otherwise:

> independent verifier run against an author-produced, release-pinned AIREP corpus

Not "full interoperability achieved". A run of this corpus may populate the
**author-produced-corpus / independently implemented-consumer** category. It does not establish a
third-party AIREP producer or deployment interoperability.

## What the schema enforces, and what it does not

`REPORT_SCHEMA.json` makes the outcome dimensions **structurally impossible to collapse in a row
that states an agreement verdict**: a row whose `agreement` is `AGREE` or `DISAGREE` must carry
both result objects, must name the implementation and its digest and the input package digest, and
a result emitting an AIREP class must carry all five reason channels.

It deliberately does **not** enforce that on a blank template row — `agreement: null` with null
results is how the shipped template validates. So the guarantee is precise: *a submitted verdict
cannot be collapsed*, not *no document matching this schema can be empty*.

The schema also cannot check that a reported value is **true**. It checks shape. Truth is what the
run and the reviewers are for.
