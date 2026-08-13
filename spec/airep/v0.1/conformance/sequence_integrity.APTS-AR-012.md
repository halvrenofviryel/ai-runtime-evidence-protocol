# Sequence integrity ↔ OWASP APTS-AR-012 — a mapping backed by a checkable property

**Anchor status: VERIFIED against the primary source.** The APTS-AR-012 text below was
read from `OWASP/APTS`, `standard/5_Auditability/README.md`, the `APTS-AR-012` section on
`main` (fetched via `gh api` this session). APTS-AR-012 — *Tamper-Evident Logging with
Hash Chains* — is classified **MUST | Tier 1**. Where this document quotes the standard it
transcribes; where it maps, it maps.

## The requirement (APTS-AR-012)

> - **Structure**: Each log entry includes a monotonically increasing entry sequence number
>   AND the hash of the previous entry.
> - **Sequence integrity**: Sequence numbers MUST be continuous; gaps in the sequence
>   indicate deletion and MUST be treated as tampering.

Verification (abridged): read entries in sequence order; recompute
`SHA256(content + previous_hash)` for each; verify sequence numbers are continuous (no
gaps); a mismatch or a gap means the log was tampered with; append-only enforcement must
hold; and an independent verification must agree with the platform's own tooling.

## The construct (AIREP)

Sequence integrity in AIREP is spread across the core, one profile, and two checkers:

- **core** (`core.schema.json`): each record carries `subject.decision_index` (the sequence
  number) and `integrity.previous` (the hash of the prior entry) — the per-record, RELATIVE
  binding.
- **`profiles/chain_witness.schema.json`**: a signed head witness carrying the chain
  `length`, the ABSOLUTE binding the core lacks — so a dropped tail (deletion of the last N
  entries) is detectable.
- **`conformance/sequence_integrity_check.py`** (new): makes continuity a first-class,
  standalone property — `check_sequence_integrity(chain)` over an arbitrary presented chain.
- **`conformance/verify.py`**: recomputes the content hash per record and verifies signatures.

## Requirement → construct

| APTS-AR-012 clause | Where it is expressed | How |
|---|---|---|
| "monotonically increasing entry sequence number" | core `subject.decision_index`; `sequence_integrity_check` | the check FAILs unless `decision_index` equals its 0-based position for every record — a gap, duplicate, or reorder is a positive FAIL |
| "hash of the previous entry" | core `integrity.previous`; `sequence_integrity_check` | the check FAILs unless each record's `previous` links to the prior record's `current`, and the first is the genesis value |
| "Sequence numbers MUST be continuous; gaps ... MUST be treated as tampering" | `sequence_integrity_check` | this is the check's central rule — an index gap is `FAIL`, exercised by the `index_gap`, `duplicate_index`, and `out_of_order` fixtures |
| "recompute SHA256(content + previous_hash)" | `verify.py` (`_recompute`) | **not** `sequence_integrity_check` — the sequence checker compares link strings only. verify.py realizes AR-012's recompute-and-compare with its OWN mechanism: it hashes the record's RFC 8785 canonical form (with `integrity.current` and `integrity.signature` removed, `integrity.previous` retained) and compares to `integrity.current`. That is AIREP's content-hash binding, not a literal `content + previous_hash` concatenation — the intent matches, the construction differs |
| tail deletion (a gap at the end the relative binding cannot see) | `profiles/chain_witness` head `length` + `sequence_integrity_check` | when the tail carries a witnessed `length`, the check FAILs if the presented length disagrees — exercised by the `truncated_vs_witness` fixture |
| "append-only enforcement" (verification item 5) | — | out of scope for a record/chain checker: append-only is a property of the log STORE, not of a presented chain. Named here rather than silently implied |

## What this mapping does and does not claim

- **Does:** show that AIREP can express and CHECK the sequence-integrity property APTS-AR-012
  requires — monotonic, continuous `decision_index`, previous-hash linkage, and (with
  `chain_witness`) tail-truncation detection — as a runnable check with pass/reject fixtures
  (11 chains) and tests (9).
- **Does not:** recompute content hashes or verify signatures in the sequence checker (that is
  `verify.py`), enforce append-only storage (a platform property), or claim any deployed system
  runs this check. First-party; not independently reproduced. The core is untouched.
- **Honest limit:** a matching previous-link STRING is not proof the content hash is
  cryptographically correct, and a witnessed `length` defends against truncation only if the
  witness is signed by a key independent of the producer (the `chain_witness` profile's own
  caveat). `truncation_checked=False` means no witness length was present to compare against.
- **Not a conformance claim about APTS itself.** APTS is a pentest-platform standard; this maps
  one AIREP property onto one of its Auditability requirements because tamper-evident sequencing
  is general. It is a contribution of a format property and a working check, not an assertion
  that any product is APTS-conformant.
