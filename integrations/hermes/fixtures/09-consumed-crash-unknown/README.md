# HERMES-AIREP-09 — consumed then crash; execution unknown

This directory is a deterministic synthetic mapping fixture, not a captured production Hermes run.

- Artifact families: control x2, decision x1
- Verification: pinned test-only inputs classify every record as `AIREP-Authenticated`.
- Global reconciliation status is not treated as a pass/fail oracle.
- Missing stages remain absent; no `Execution(unknown)` record is invented.
- `native_facts.json` separates scenario source facts, fixture-only constructed values, and mapping choices.

| Named reconciliation check | Expected state(s) |
|---|---|
| `artifact_admission` | `SATISFIED, SATISFIED, SATISFIED` |
| `record_authentication` | `SATISFIED, SATISFIED, SATISFIED` |
| `chain_link` | `SATISFIED, SATISFIED, SATISFIED` |
| `intended_target_coverage` | `NOT_EVALUATED` |
| `instruction_evidence` | `SATISFIED` |
| `issuer_dispatch` | `SATISFIED` |
| `receiver_receipt` | `SATISFIED` |
| `execution_evidence` | `MISSING` |
| `toctou` | `NOT_EVALUATED` |

`AIREP-Authenticated` here means only that the repository verifier accepted the fixture producer
binding, active revocation entry, signature, schema, and integrity inputs. It does not prove the
truth of the synthetic facts, Hermes policy correctness, authorization consumption, execution,
effect, or complete history.
