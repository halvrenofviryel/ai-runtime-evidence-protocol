# Agent Control Delivery Evidence Reconciliation (ACDER)

This directory contains an experimental reference implementation and test
fixtures for **Agent Control Delivery Evidence Reconciliation (ACDER)**, a
candidate TEVV measurement methodology for evaluating evidence supporting
delivery claims for governance-relevant controls sent toward AI or agent
runtime enforcement points.

ACDER is intentionally format-neutral. It does not define a receipt format,
wire protocol, authorization system, telemetry schema, signature format, or
transparency service.

The measurement unit used here is an **instruction × required-target delivery
obligation**. This matters when one control instruction must reach more than one
enforcement target: evidence from one target must not be treated as evidence
that every required target received the control.

The reference runner preserves several claim boundaries:

- missing receiver evidence is `UNCONFIRMED`, not proof of non-delivery;
- a positive attributable failure is distinct from missing evidence;
- unresolved target or trust bindings remain `INDETERMINATE`;
- a closed target population is required for a complete-delivery claim;
- delivery evidence does not by itself establish enforcement; and
- an enforcement assertion does not by itself establish the resulting control
  effect.

Run the supplied fixtures with:

```bash
python3 acder_reference.py fixtures.json
```

The runner uses only the Python standard library. The fixture suite includes a
multi-target case in which one instruction requires two enforcement targets but
only one target has confirming receiver evidence; the resulting complete-delivery
claim remains false.

## Status and scope

This directory is **experimental research material**.

It is not part of the AIREP v0.1 or v0.2 conformance contract and does not modify
their schemas, runtime semantics, or release status.

It is not an implementation of a NIST standard, an IETF standard, or IETF
consensus. Its inclusion in this repository does not imply NIST acceptance,
endorsement, or publication of the associated measurement methodology.

The target-multiplicity behavior represented here was added as a candidate
measurement correction following independent review of an individual
Internet-Draft. It remains subject to further technical review.

For provenance-sensitive use, reference a specific commit rather than this
branch name.
