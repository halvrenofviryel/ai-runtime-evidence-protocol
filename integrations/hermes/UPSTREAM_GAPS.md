# Current public Hermes gaps for a complete AIREP exporter

Measured against public Hermes `main@9796235822b89e08597a402dad045b5b4464e474` on
2026-09-16. See [`SOURCE_BASIS.json`](./SOURCE_BASIS.json) for the reviewed file identities.

Hermes already exposes a useful observer contract for sessions, turns, provider attempts, tool
calls, and approval prompts. The selected plugin approval transport also binds a response to its
host-created `request_id` and request digest and rejects stale/mismatched responses. These are
valuable correlation and fail-closed properties, but they are not the complete native evidence
contract needed for a generic approval → authorization instruction → execution export.

The following gaps remain on current public `main`:

1. **Stable approval-request identity on every public path.** The built-in gateway entry creates a
   request ID internally, while the ordinary approval-hook payload omits it. The selected plugin
   transport does expose request ID/digest; coverage is not uniform.
2. **Canonical governed-intent digest.** No documented, versioned public projection binds the exact
   intent that the native decision governs.
3. **Canonical authorization-action projection.** Redacted display text and the plugin transport
   request digest are not an action-digest contract shared with an executor.
4. **Finalized decision identity.** Public approval observer events do not provide a durable native
   decision ID suitable for binding later instruction and execution reports.
5. **Approver/principal establishment evidence.** Common observer metadata does not establish the
   authenticated principal and provenance needed to make a strong approver-identity claim.
6. **Authorization-instruction identity and digest.** There is no documented generic public event
   that names and hashes a post-decision authorization instruction.
7. **Authorized-action digest.** The authorization side does not expose a public canonical digest
   designed for comparison with what an executor actually ran.
8. **Durable reserve/claim/consume facts.** The approval path does not expose the cross-process,
   restart-safe single-use evidence requested by issue #89853. This enforcement belongs in Hermes,
   not AIREP.
9. **Explicit instruction dispatch and receiver receipt.** Approval hooks report prompt lifecycle;
   they do not provide generic authorization-instruction boundary events.
10. **Execution bound back to authorization.** Tool events expose session/turn/tool-call correlation,
    but no stable public link establishes which finalized approval/instruction authorized a call.
11. **Executed-action digest and exact authorization outcome semantics.** The tool lifecycle has
    observer-grade statuses (`ok`, `error`, `blocked`, `cancelled`), but no shared canonical
    executed-action digest or authorization-bound contract that cleanly exports AIREP
    `executed`/`failed`/`suppressed` in every path.
12. **Optional Effect observation contract.** No generic approval-bound state-observation event
    establishes a post-execution effect or observer relationship.

PR #104960 is open and unmerged at measurement time. Its proposed exact-request binding for native
interactive controls is not treated as part of Hermes `main`, and even if merged it would not by
itself supply the durable instruction, consume, execution-digest, and effect contracts above.

An upstream design should widen Hermes' native, versioned receipt/event surface. It should not make
Hermes depend on AIREP or use an AIREP artifact as an enforcement token.
