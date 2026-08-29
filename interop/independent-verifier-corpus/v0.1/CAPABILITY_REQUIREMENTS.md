# Capability requirements

## Required

| Capability | Why |
|---|---|
| **RFC 8785 (JCS)** canonicalisation | the hash preimage is JCS over the artifact with `integrity.current` and `integrity.signature` removed |
| **SHA-256** | `integrity.current` is `"sha256:" + lowercase-hex(SHA-256(hash_preimage))` |
| **RFC 8032 Ed25519, pure** | the only registered suite; no pre-hash; over raw preimage bytes |
| **JSON parsing that preserves lexical form** | one case turns on it — see below |
| A **third result** distinct from pass and fail | three cases cannot yield either |

## Not required

ES256, P-256, or any other signature suite. The v0.2 suite registry is closed with one entry.
Do not add a suite to accommodate this corpus; if a checker supports only Ed25519, it supports
everything this corpus signs with.

## The capability most likely to be missing

`CLS-LEX1` carries a witness claim whose `length` is written `1e0`. The **semantic JSON value is
correct** — it is the number 1 — and a parser that decodes to a numeric type and re-serialises
will not see anything wrong. The frozen expected result is a witness failure.

A checker that compares parsed values rather than preserving the lexical form of the received
bytes will disagree with this row. **That disagreement is a real finding about the checker's
reconstruction path, not a corpus defect**, and it is exactly the kind of result worth reporting.

If this capability is missing, say so rather than adjusting the case.

## Process-exit cases

Two cases (`PROC-UNP`, `PROC-NGR`) expect a **process exit and no verdict**. A checker with no
process-level surface cannot report these; that is a coverage gap to record, not a failure.
