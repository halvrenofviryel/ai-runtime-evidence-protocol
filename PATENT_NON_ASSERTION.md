# AIREP Patent Non-Assertion Covenant

This Patent Non-Assertion Covenant applies to the AI Runtime Evidence Protocol (AIREP) neutral core
specification.

Ali Toygar Abak / Phionyx Research, on behalf of itself and its successors and assigns, irrevocably
covenants not to assert any Necessary Claim of its patents or patent applications against any party
for making, using, implementing, transmitting, canonicalizing, hash-chaining, signing, verifying,
validating, or otherwise processing a conformant AIREP core record, solely to the extent such acts
are necessary to implement the neutral AIREP interchange format.

For purposes of this covenant, a "conformant AIREP core record" means the neutral AIREP core object
as defined by the applicable published AIREP specification version, including its required core
members, the closed `directive.verb` and `evidence[].type` vocabularies, the `scope.covers` and
`scope.does_not_cover` fields, the canonical-JSON integrity rule, the SHA-256 hash-chain construction,
the signature field, the neutrality test, and the conformance checks.

For purposes of this covenant, a "Necessary Claim" means a patent claim that would necessarily be
infringed by implementing the neutral AIREP core specification, where no technically reasonable
non-infringing alternative exists for conforming to that specification.

This covenant is royalty-free, worldwide, and irrevocable for the acts described above.

This covenant does **not** grant any license or covenant with respect to underlying AI runtime
mechanisms, governance engines, policy engines, scoring models, state vectors, model-routing systems,
agent-orchestration methods, Phionyx-specific runtime internals, or any implementation-specific
technology beyond what is necessary to implement, transmit, or verify the neutral AIREP interchange
record itself.

This covenant does not apply to implementations that falsely claim conformance to AIREP, nor does it
waive any trademark, copyright, trade-secret, or contractual rights.

This covenant is provided to support open implementation and independent verification of AIREP. It is
not a certification, an endorsement, or a legal determination that any implementation conforms to
AIREP.

---

*This text is a good-faith covenant drafted to support open adoption; it has not been reviewed by
patent counsel. The "Necessary Claim" scope deliberately limits the covenant to what is technically
required to implement the neutral interchange record, and expressly does not reach the Phionyx runtime
mechanisms. Before any change that broadens it, obtain professional review.*
