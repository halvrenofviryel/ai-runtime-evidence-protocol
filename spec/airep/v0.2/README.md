# AIREP v0.2 — beta implementation target

**`v0.2.0-beta.1` is the current implementation target. Wire version: `0.2`.**
Experimental, not stable, and not yet a claim of independent same-version
producer→consumer interoperability. v0.1 remains frozen and supported.

Start with **[SPEC.md](SPEC.md)** → [producer quickstart](QUICKSTART.md) →
[verifier](VERIFICATION.md) → [runnable lifecycle](../../../examples/v02/README.md).

| Surface | Status |
|---|---|
| [First-party producer/library/CLI](../../../tools/airep_v02/) | Four families, real tagged hashes and Ed25519 signatures |
| [Lifecycle and negative corpus](../../../examples/v02/) | Decision, issuer dispatch, receiver receipt, Execution and Effect |
| [Reconciliation](RECONCILIATION.md) | Structured facts, failure, missing evidence, unevaluated prerequisites and indeterminacy |
| [Normative classes](CONFORMANCE_CLASSES.md) | Core / Authenticated / Witnessed; no truth assurance |
| [Input admission](JSON_INPUT_ADMISSIBILITY.md) and [r3 profiles](class-verification/contract-r3/CLASS_VERIFIER_CONTRACT_R3.md) | Both beta verifier adapters; historical engines preserved |
| [Integrity](INTEGRITY.md), [vectors](vectors/), [stage 4](stage4/), [schemas](schemas/) | Frozen accepted sources and reproduction evidence retained |
| [Schema corpus](schema-validation/) and [class corpus](class-verification/) | Historical 117-case schema / 60-case class measurement bases retained |
| [Imported W1 evaluators](interop/) | Prior Erratum-8 work consolidated with provenance; not an external beta interoperability result |

See [BETA_READINESS.md](BETA_READINESS.md) for measured release criteria and
[RELEASE_STAGES.md](RELEASE_STAGES.md) for remaining RC/stable work. The
[architecture record](../v0.2-design/) and every evidence-pinned subsidiary
contract remain available; their historical status prose is not the current
beta status. SCITT/AuthZEN E2E, third-party v0.2 production and migration tooling
are not claimed implemented.
