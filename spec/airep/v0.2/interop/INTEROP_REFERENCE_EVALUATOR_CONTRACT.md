# Reference interop evaluator contract (AD15-IR-2)

Status: **DRAFT — awaiting maintainer acceptance.** No evaluator code and no corpus bytes may be
produced until this contract is accepted.

## 1. Why this exists

`INTEROP_CORPUS_CONTRACT.md` §2 commits all three evaluation surfaces to a machine-observable
Level-1 result on **every one of the twelve** scenarios, the Python and Node reference lanes
included.

The frozen `CLASS_VERIFIER_CONTRACT.md` §8 says the opposite for part of that set:

> reconciliation (TOCTOU equality, reference resolution, lifecycle completeness — outside the
> ladder by design §7) … **out of scope**

Both cannot be true. Had the corpus been built first, three scenarios would have been scored
against a surface the reference lanes do not measure, and the run would have been reported as
"12/12 across three implementations" while three of the twelve were never actually evaluated by
two of the three. That is the failure this contract exists to prevent, and it is the reason the
frozen verifiers are **not** being changed to close it.

## 2. What is already covered, and what is not

Measured against the frozen contract, not assumed. §0 of that contract carries
`related_artifacts` and performs reference resolution for `head_ref`, an Effect's `execution_ref`,
and "any `decision_ref` a stage needs" — so the gap is narrower than "all reconciliation".

| Scenario | Frozen class verifier alone | Needs new bundle-level code |
|---|---|---|
| 4 positive family baselines | **yes** — schema, hash, signature, class | no |
| `IOP-B-DEC` / `IOP-B-CTL` / `IOP-B-EXE` / `IOP-B-EFF` | **yes** — stages 0, 1 and 4 | no |
| `IOP-R-INDEP` | **yes** — §0 resolves the Execution through `execution_ref`, verifies it to Authenticated in its own right, then compares identity and key, yielding `observer_assessment` | **no** — only the Level-1 mapping below |
| `IOP-R-CLEAN` | **no** — no stage asserts that a four-artifact graph resolves completely | **yes** |
| `IOP-R-TOCTOU` | **no** — no stage compares `authorized_action_digest` with `executed_action_digest` | **yes** |
| `IOP-R-XREF` | **no** — an Effect whose `decision_ref` resolves to nothing still classes normally, because no stage needs that reference | **yes** |

**Three scenarios require new code.** `IOP-R-INDEP` is delegable in full: the independence
condition is already a frozen stage-8 / observer-assessment property, and the evaluator only
translates its output into the Level-1 vocabulary.

## 3. Shape — composite, not a replacement

Two programs, one per lane:

- `interop_eval_py/` — Python reference interop evaluator
- `interop_eval_node/` — Node reference interop evaluator

Each:

1. invokes **its own** frozen class verifier **as a subprocess** for every artifact, and takes the
   per-artifact schema / hash / signature / class / reason result from that output verbatim;
2. implements bundle-level AD-03 reconciliation in **its own language, as independent code**;
3. emits one Level-1 verdict per scenario.

**The frozen verifiers are not modified, imported, vendored or re-implemented.** Their digests at
the time of this contract, which the evaluator MUST assert before use and record in its output:

| File | sha256 |
|---|---|
| `verifier_py/class_verifier.py` | `5d08c327648d4bdc83714879be8531c837b991dd474d7ca46397b0ff8c9d01cc` |
| `verifier_node_r2/class_verifier.mjs` | `e678ff5706547d4fb79ab8ad013bdf6f41e4429065a42309d6a4a6515632bde4` |
| `CLASS_VERIFIER_CONTRACT.md` | `7ecfce56ab576a495816df77e25442b25c1afdb22cc9828e47ba29a565138885` |

A digest mismatch is a hard `ERROR`. The run is not valid and no Level-1 verdict is emitted.

Crossing the lanes is forbidden: the Python evaluator invokes only `verifier_py`, the Node
evaluator only `verifier_node_r2`. An evaluator that shelled out to the other lane's verifier
would collapse the two surfaces into one and destroy the only property the dual lane provides.

## 4. Isolation — the same discipline as the class verifiers

The two evaluators are **separately authored against this contract**, in isolation. They share:

- no AIREP-specific reconciliation code, in any language;
- no shared helper module, transpiled artifact, or generated source;
- no line-by-line port of one into the other.

They may each use general-purpose libraries (JSON parsing, JCS, hashing, process invocation) and
they both read this contract. The reconciliation logic itself is written twice, independently.

Agreement between them is then evidence of the contract being unambiguous. If they are ported
from one another, agreement is evidence of nothing at all — which is exactly what the original
dual class-verifier exercise established, and the same reasoning applies here.

## 5. Bundle input

An evaluator consumes a **scenario bundle**: a directory containing the scenario's artifacts, the
operator inputs the frozen verifier requires (`--bindings`, `--independence-policy`,
`--revocation`, clock inputs), and a manifest naming the scenario id and the artifact files.

Reference resolution inside a bundle is by v0.2 reference semantics — `record_id`, additionally
`chain_id` when the reference carries one. **Zero matches is unresolved; more than one match is
ambiguous and fails closed.** An evaluator MUST NOT pick one. This mirrors the frozen §0 rule
deliberately: the same resolution semantics apply whether the resolution happens inside the class
verifier or in the bundle layer above it.

## 6. Reconciliation predicates (normative)

Exactly three, evaluated **only after** every artifact in the bundle has a frozen-verifier result.

**R-A — graph resolution.** Every cross-artifact reference in the bundle resolves uniquely:
Control→Decision, Execution→Decision, Effect→Decision, Effect→Execution. Unresolved or ambiguous
is a failure of this predicate.

**R-B — authorized-vs-executed equality.** The Control's `authorized_action_digest` and the
Execution's `executed_action_digest` are compared as **exact strings**. Both are `sha256_digest`
by schema, so no normalization, case folding or re-hashing is performed. Inequality is a failure
of this predicate.

**R-C — independence.** Taken from the frozen verifier's `observer_assessment` for the Effect. An
Effect whose wire `observer_relationship` is `independent` while the frozen output reports an
effective assessment of `unknown` fails this predicate. The evaluator MUST NOT re-derive
independence itself — that is a frozen stage-8 property and re-implementing it would create a
second, unpinned definition.

An evaluator computes all three and reports each. It does not stop at the first failure: a bundle
that fails two predicates must say so, because "which predicate fired" is the measurement.

## 7. Level-1 mapping (normative)

Level-1 is the vocabulary of `INTEROP_CORPUS_CONTRACT.md` §3, unchanged:
`ACCEPT` · `REJECT` · `RECONCILIATION_MISMATCH` · `INDEPENDENCE_NOT_ESTABLISHED`.

Mapping, in this order:

1. Any artifact in the bundle that the frozen verifier reports as **invalid** (no class at all), or
   for which it reports a **definitive Authenticated-tier failure** → **`REJECT`**.
   Per the §3 pin in the corpus contract, a completed verdict leaving the artifact at
   `AIREP-Core` with a populated `authenticated_failures` channel **is** a `REJECT`. A
   **withheld** channel is never a `REJECT`.
2. Otherwise, **R-C** fails → **`INDEPENDENCE_NOT_ESTABLISHED`**.
3. Otherwise, **R-A** or **R-B** fails → **`RECONCILIATION_MISMATCH`**.
4. Otherwise → **`ACCEPT`**.

Step 1 precedes the rest because a bundle containing a cryptographically broken artifact has no
meaningful reconciliation verdict — the reconciliation-negative fixtures are built to be
individually sound precisely so this branch is not taken. Step 2 precedes step 3 because
`IOP-R-INDEP` is built to satisfy R-A and R-B; if it ever reported
`RECONCILIATION_MISMATCH`, the fixture is wrong, not the ordering.

## 8. Output and determinism

One JSON object per scenario, on stdout, with: scenario id; the Level-1 verdict; the three
predicate results; the per-artifact frozen-verifier verdicts verbatim; the asserted verifier
digests; and the evaluator's own version.

Runs are deterministic: identical bundle plus identical operator inputs gives byte-identical
output, apart from nothing. Ordering of any collection in the output is by UTF-8 byte order of
the scenario or record identifier, matching the corpus contract's existing ordering rule.

Process exit: `0` when every scenario produced a Level-1 verdict; `1` when a bundle was rejected
as invalid input; `2` for usage error; **`3` when a verifier digest assertion failed or a frozen
verifier could not be invoked** — a run that could not measure exits distinctly from a run that
measured and disagreed. A non-zero exit is never itself a Level-1 result.

## 9. Provenance — extends the participation contract

The `PARTICIPATION_CONTRACT.md` D3 rule on the reference verifiers applies **identically** to
these two evaluators. A participant may:

- **read** the evaluator sources, and this contract;
- **run** them as an external process or diagnostic oracle against their own artifacts.

A participant may **not** import, vendor, port or adapt evaluator source into their own qualifying
evaluation path. The reason is unchanged from D3: an implementation that reuses ours measures our
reconciliation logic twice, not two implementations once.

## 10. What a clean run would and would not establish

**Would establish:** that two separately authored bundle-level reconciliation implementations,
each composed over its own frozen class verifier, agree on the Level-1 verdict for all twelve
scenarios — and, with the participant lane, that a third independent implementation agrees.

**Would not establish:** that the reconciliation semantics are correct; that the frozen class
verifiers are correct; that the corpus covers the reconciliation failure space; or that any
real-world AIREP bundle is truthful. As with the class-verifier phase, agreement between the two
reference evaluators is consistent with separate authoring but is not proof of it.

## 11. Out of scope

Producers; any change to the frozen class verifiers, their contract, or the accepted schemas;
SCITT anchoring; the AuthZEN case; lifecycle completeness beyond the four artifacts of a bundle;
and any new artifact family.

## 12. Sequencing

1. This contract is accepted.
2. Both evaluators are authored in isolation and their sources frozen with recorded digests.
3. Only then is corpus construction opened.

**Corpus bytes remain on HOLD until step 3.**
