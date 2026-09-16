# HERMES-AIREP-03 — release without dispatch evidence

This directory is a deterministic synthetic mapping fixture, not a captured production Hermes run.

- Artifact families: decision x1
- Verification: pinned test-only inputs classify every record as `AIREP-Authenticated`.
- Global reconciliation status is not treated as a pass/fail oracle.
- Missing stages remain absent; no `Execution(unknown)` record is invented.
- `native_facts.json` separates scenario source facts, fixture-only constructed values, and mapping choices.

| Named reconciliation check | Expected state(s) |
|---|---|
| `artifact_admission` | `SATISFIED` |
| `record_authentication` | `SATISFIED` |
| `chain_link` | `SATISFIED` |
| `intended_target_coverage` | `NOT_EVALUATED` |
| `instruction_evidence` | `MISSING` |

`AIREP-Authenticated` here means only that the repository verifier accepted the fixture producer
binding, active revocation entry, signature, schema, and integrity inputs. It does not prove the
truth of the synthetic facts, Hermes policy correctness, authorization consumption, execution,
effect, or complete history.
