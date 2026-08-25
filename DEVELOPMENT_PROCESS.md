# Development process

AIREP uses AI-assisted software engineering for implementation, testing, adversarial
exploration, and documentation. Normative protocol decisions, scope decisions,
acceptance/rejection gates, publication claims, and final accountability remain with the human
maintainer. AI-generated outputs are treated as untrusted implementation proposals until
independently checked against frozen specifications and committed evidence.

## What that means in practice

The controls below are the reason the statement above is checkable rather than a claim about
intent. They are visible in the repository history and in the committed evidence directories.

- **Specification first.** Normative text is frozen before an implementation of it is written.
  Where an implementation and the specification disagree, the specification governs and the
  disagreement is recorded as a finding rather than resolved by changing the implementation to
  match.
- **Outcome-blind fixtures.** Conformance fixtures and their expected values are authored
  separately from the implementations they measure, and are derived from cited normative
  clauses rather than produced by executing an implementation. An expected value computed by
  running the code it is meant to test would make the test vacuous.
- **Independent implementations.** Where the specification calls for cross-implementation
  agreement, the implementations are authored separately, without access to each other's
  source or to the expected values, and the comparison is performed by a third component that
  imports code from neither.
- **Negative controls.** Checking harnesses are demonstrated to fail on deliberately broken
  input before their passing results are relied on. A check that cannot fail is not evidence.
- **Failures are kept.** Measurement runs that fail are committed as they were measured. The
  first official cross-implementation parity run of the v0.2 class verifiers failed; its
  evidence is committed on the v0.2 development branch alongside the later passing run, in a
  separate directory rather than overwritten. The two findings it raised were closed by
  amending the specification and correcting the implementation that diverged from it — not by
  relaxing the check that caught them.
- **Claims bounded by evidence.** Documentation uses the weakest accurate term for what was
  actually measured, and open gaps are recorded rather than omitted.

## Scope of this statement

This describes how the protocol and its reference material are developed. It is not a claim
about the maturity of the protocol itself — see
[`spec/airep/v0.1/STATUS.md`](./spec/airep/v0.1/STATUS.md) for that. AIREP is Experimental: a
proposed open format with one reference implementation, not a ratified standard.

For academic use, the appropriate methodological disclosure is that generative-AI coding agents
were used as implementation and adversarial-analysis tools during protocol development; that
all normative protocol decisions, acceptance criteria, specification rulings, interpretation of
findings, and publication claims were made and reviewed by the human author; and that generated
implementations were evaluated against independently authored fixtures, frozen expected
outcomes, negative controls, and cross-runtime parity checks.
