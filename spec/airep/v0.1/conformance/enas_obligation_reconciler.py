"""ENAS obligation-protocol bundle reconciler — a bounded G3 reference implementation.

The single-record checker in ``enas_profiles.py`` establishes ``G2_SCHEMA_DEFINED``
for the WP-OP records: each record is *internally* well-formed. It explicitly does
NOT resolve cross-record references, chain conservation transitions into an
end-to-end lineage, or evaluate global closure — those are documented as
bundle-reconciliation concerns (see ``profiles/README.md``).

This module is the reference implementation of exactly that missing layer for the
obligation protocol. Given a *bundle*::

    {
      "bundle_id": "...",
      "origin_contract": <origin_contract record>,
      "transitions": [<conservation_accounting record>, ... (ordered)],
      "closure": <closure_accounting record>
    }

it reconciles the records into a single global verdict, grounded in
ENAS_SPECIFICATION.md §8.4 (conservation partition), A2 (causal continuity),
A3 (obligation conservation), and A7 (end-to-end closure):

1. Every embedded record passes its single-record semantic check (reuse of
   ``enas_profiles.validate_document``). A malformed record makes the bundle
   ``INCONCLUSIVE`` — an invalid record cannot be reconciled.
2. Cross-record references resolve: ``transition_ref`` / ``contract_ref`` bind,
   every ``transformed[].successor_ref`` is present in the SAME transition's
   ``created``/``after`` (already checked per record) and, across the chain,
   every id that leaves one transition is accounted for by the next.
3. Transition chaining (§8.4 across transitions, A2): the transitions form a
   contiguous lineage — ``after`` of transition N equals ``before`` of
   transition N+1, and ``before`` of the first transition equals the origin
   contract's declared obligation set.
4. End-to-end conservation (A3): every obligation introduced (origin obligations
   ∪ every ``created`` id) reaches exactly one terminal fate across the chain or
   remains outstanding at closure — none silently appears or disappears.
5. Global closure (A7): the closure record disposes exactly the obligations still
   outstanding after the last transition, and a global ``PASS`` / ``SUCCEEDED``
   is sound ONLY when no obligation is failed or unresolved anywhere in the
   chain, invariants are revalidated, and enforcement is confirmed.

The result is honest about its boundary: a ``PASS`` means "this bundle of records
is a conserved, closed lineage", not "the workflow really happened" — the records
are still producer-attested; binding them to a real runtime is a further step.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from enas_profiles import validate_document

FIXTURE = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "enas_profiles"
    / "enas_obligation_bundle_cases.json"
)


def _ids(values: list[str]) -> Counter[str]:
    return Counter(values)


def reconcile_obligation_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    """Reconcile a WP-OP bundle into a global verdict.

    Returns ``{"global_verdict", "record_errors", "reconciliation_errors"}`` where
    ``global_verdict`` is one of ``PASS`` | ``FAIL`` | ``INCONCLUSIVE`` (ENAS
    outcome algebra). The function is TOTAL over malformed input: a missing or
    non-object member yields a verdict, never an exception.
    """
    record_errors: dict[str, list[str]] = {}
    recon: list[str] = []

    origin = bundle.get("origin_contract")
    transitions = bundle.get("transitions")
    closure = bundle.get("closure")

    # --- structural presence (a bundle needs the three anchors) ---
    if not isinstance(origin, dict):
        recon.append("bundle is missing a well-formed origin_contract")
    if not isinstance(transitions, list) or not transitions:
        recon.append("bundle is missing an ordered, non-empty transitions list")
    if not isinstance(closure, dict):
        recon.append("bundle is missing a well-formed closure_accounting")
    if recon:
        return {"global_verdict": "INCONCLUSIVE", "record_errors": record_errors, "reconciliation_errors": recon}

    # --- 1. per-record single-record validity (reuse the G2 checker) ---
    def _check(label: str, profile: str, doc: Any) -> bool:
        errs = validate_document(profile, doc) if isinstance(doc, dict) else ["record is not an object"]
        if errs:
            record_errors[label] = errs
        return not errs

    ok = _check("origin_contract", "origin_contract", origin)
    for index, transition in enumerate(transitions):
        ok = _check(f"transition[{index}]", "conservation_accounting", transition) and ok
    ok = _check("closure_accounting", "closure_accounting", closure) and ok
    # Optional justification records (a transition's WHY): handoffs / transformations / fork-joins.
    handoffs = bundle.get("handoffs") or []
    transformations = bundle.get("transformations") or []
    fork_joins = bundle.get("fork_joins") or []
    for index, record in enumerate(handoffs):
        ok = _check(f"handoff[{index}]", "obligation_handoff", record) and ok
    for index, record in enumerate(transformations):
        ok = _check(f"transformation[{index}]", "transformation_record", record) and ok
    for index, record in enumerate(fork_joins):
        ok = _check(f"fork_join[{index}]", "fork_join_record", record) and ok
    if not ok:
        # An invalid record cannot be reconciled — this is INCONCLUSIVE, not FAIL.
        return {"global_verdict": "INCONCLUSIVE", "record_errors": record_errors, "reconciliation_errors": recon}

    # --- 2. reference binding: contract_ref / transition_ref resolve ---
    contract_id = origin["contract_id"]
    if closure["contract_ref"] != contract_id:
        recon.append("closure.contract_ref does not resolve to the origin contract")

    # --- 3. transition chaining (§8.4 across transitions, A2) ---
    origin_obligations = _ids([ob["obligation_id"] for ob in origin["obligations"]])
    first_before = _ids(transitions[0]["before"])
    if first_before != origin_obligations:
        recon.append("the first transition's `before` set does not equal the origin contract's obligation set")

    def _resulting(transition: dict[str, Any]) -> Counter[str]:
        # the outstanding set AFTER a transition is exactly its `after` set;
        # discharged / transformed / revoked / failed / unresolved have left it.
        return _ids(transition["after"])

    for index in range(len(transitions) - 1):
        after_n = _resulting(transitions[index])
        before_next = _ids(transitions[index + 1]["before"])
        if after_n != before_next:
            recon.append(
                f"conservation lineage breaks between transition[{index}].after and transition[{index + 1}].before"
            )

    # --- 4. end-to-end conservation (A3): assign each obligation exactly one chain fate ---
    # A transformed predecessor is SUPERSEDED (accounted via lineage to its successor),
    # not closed; every other in-chain fate is terminal. `chain_fate` maps id -> its
    # single in-chain fate; chaining (check 3) guarantees an id cannot receive two.
    fate_of = {
        "discharged": "DISCHARGED",
        "revoked": "VALIDLY_REVOKED",
        "failed": "FAILED",
        "unresolved": "UNRESOLVED",
    }
    chain_fate: dict[str, str] = {}
    introduced: Counter[str] = Counter(origin_obligations)
    seen: set[str] = set(origin_obligations)  # every id ever introduced
    for transition in transitions:
        for oid in transition["created"]:
            # §P5: obligation identity is single-use across the lineage — a created id must be
            # genuinely new, never a resurrection of an id already declared, created, or exited.
            if oid in seen:
                recon.append(f"obligation id {oid} is re-created after it was already introduced")
            seen.add(oid)
        introduced.update(transition["created"])
        for bucket, fate in fate_of.items():
            for oid in transition[bucket]:
                # §P5/A3: an obligation exits the lineage exactly once — a second fate (or a
                # supersession after exit) means a dead identity was reused.
                if oid in chain_fate:
                    recon.append(f"obligation id {oid} is given a second fate ({chain_fate[oid]} then {fate})")
                chain_fate[oid] = fate
        for item in transition["transformed"]:
            oid = item["obligation_id"]
            if oid in chain_fate:
                recon.append(f"obligation id {oid} is superseded after it already exited ({chain_fate[oid]})")
            chain_fate[oid] = "SUPERSEDED"
    outstanding_at_close = _resulting(transitions[-1])
    # accountable = every id with a terminal (non-superseded) fate, plus the ids still
    # outstanding at the last transition. Superseded predecessors are deliberately excluded.
    terminal_ids = {oid for oid, fate in chain_fate.items() if fate != "SUPERSEDED"}
    accountable = _ids(list(terminal_ids)) + outstanding_at_close
    superseded_ids = {oid for oid, fate in chain_fate.items() if fate == "SUPERSEDED"}
    accounted = accountable + _ids(list(superseded_ids))
    if introduced != accounted:
        missing = sorted((introduced - accounted).elements())
        if missing:
            recon.append(f"obligations introduced but never accounted for end-to-end: {missing}")
        extra = sorted((accounted - introduced).elements())
        if extra:
            recon.append(f"obligations accounted for that were never introduced: {extra}")

    # --- 5. global closure (A7): closure disposes EVERY accountable obligation, consistent
    # with its in-chain fate; a superseded predecessor MUST NOT appear at closure ---
    closure_map: dict[str, str] = {item["obligation_id"]: item["disposition"] for item in closure["obligation_dispositions"]}
    closure_ids = _ids(list(closure_map))
    if closure_ids != accountable:
        recon.append("closure does not dispose exactly the accountable obligations (missing, extra, or a superseded predecessor)")
    for oid, disposition in closure_map.items():
        fate = chain_fate.get(oid)
        if fate in fate_of.values() and disposition != fate:
            recon.append(f"closure disposition for {oid} ({disposition}) contradicts its in-chain fate ({fate})")
    chain_has_failure = any(transition["failed"] or transition["unresolved"] for transition in transitions)
    closure_has_failure = bool({"FAILED", "UNRESOLVED"} & set(closure_map.values()))
    claims_success = closure["terminal_outcome"] == "SUCCEEDED" or closure["global_verdict"] == "PASS"
    if claims_success and (chain_has_failure or closure_has_failure):
        recon.append("a global PASS/SUCCEEDED closure is unsound: an obligation failed or was left unresolved in the lineage")

    # --- 6. justification reconciliation (§4.8/§4.9/§8.7/§8.10): bind each transition's WHAT
    # (its conservation delta) to a WHY (a handoff / transformation / fork-join record). This
    # layer is OPT-IN per bundle: if no justification records are provided the transition_ref is
    # an opaque pointer (checks 1-5 stand alone); if any are provided, every transition_ref MUST
    # resolve to one and the justifying record must be consistent with the delta it explains. ---
    justif: dict[str, tuple[str, dict[str, Any]]] = {}
    justif_ids: list[str] = []
    for record in handoffs:
        justif[record["handoff_id"]] = ("handoff", record)
        justif_ids.append(record["handoff_id"])
    for record in transformations:
        justif[record["transformation_id"]] = ("transformation", record)
        justif_ids.append(record["transformation_id"])
    for record in fork_joins:
        justif[record["record_id"]] = ("fork_join", record)
        justif_ids.append(record["record_id"])
    # A transition_ref that maps to more than one justification record does not "resolve to one";
    # ambiguous justification identity is a reconciliation failure, not a silent last-writer-wins.
    ambiguous = {jid for jid in justif_ids if justif_ids.count(jid) > 1}
    if justif:
        for index, transition in enumerate(transitions):
            ref = transition["transition_ref"]
            if ref in ambiguous:
                recon.append(f"transition[{index}] transition_ref '{ref}' is ambiguous — it resolves to more than one justification record")
                continue
            if ref not in justif:
                recon.append(f"transition[{index}] transition_ref '{ref}' does not resolve to a provided justification record")
                continue
            kind, record = justif[ref]
            transformed_ids = {item["obligation_id"] for item in transition["transformed"]}
            carried = set(transition["created"]) | set(transition["after"])
            if kind == "transformation":
                # §8.10: the transformation's predecessor must be one the transition transforms,
                # and its successors must be created/carried by that same transition.
                if record["predecessor_obligation"] not in transformed_ids:
                    recon.append(f"transformation {ref} predecessor is not among transition[{index}]'s transformed obligations")
                if not set(record["successor_obligations"]).issubset(carried):
                    recon.append(f"transformation {ref} successors are not created or carried by transition[{index}]")
            elif kind == "handoff":
                # §4.8/§4.9: the handoff's terminal delta must be accounted by the transition —
                # a handoff cannot claim a disposition the conservation record does not record.
                delta = record["semantic_delta"]
                if not set(delta["discharged"]).issubset(set(transition["discharged"])):
                    recon.append(f"handoff {ref} discharges obligations transition[{index}] does not account as discharged")
                if not set(delta["revoked"]).issubset(set(transition["revoked"])):
                    recon.append(f"handoff {ref} revokes obligations transition[{index}] does not account as revoked")
                if not set(delta["transformed"]).issubset(transformed_ids):
                    recon.append(f"handoff {ref} transforms obligations transition[{index}] does not account as transformed")
                if not set(delta["created"]).issubset(set(transition["created"])):
                    recon.append(f"handoff {ref} creates obligations transition[{index}] does not account as created")
                if not set(delta["unresolved"]).issubset(set(transition["unresolved"])):
                    recon.append(f"handoff {ref} leaves obligations unresolved that transition[{index}] does not account")
                # preserved / delegated obligations remain outstanding — they must be in `after`.
                if not (set(delta["preserved"]) | set(delta["delegated"])).issubset(set(transition["after"])):
                    recon.append(f"handoff {ref} preserves or delegates obligations not outstanding after transition[{index}]")
            elif kind == "fork_join":
                # §8.7: a JOIN that closes the parent must see that parent actually accounted
                # (discharged / transformed / revoked) in the transition it justifies.
                if record["phase"] == "JOIN" and record.get("join", {}).get("parent_closed"):
                    accounted_here = set(transition["discharged"]) | transformed_ids | set(transition["revoked"])
                    if record["parent_obligation"] not in accounted_here:
                        recon.append(f"fork_join {ref} closes parent {record['parent_obligation']} but transition[{index}] does not account it")

    verdict = "FAIL" if recon else "PASS"
    return {"global_verdict": verdict, "record_errors": record_errors, "reconciliation_errors": recon}


def run_bundle_fixture(path: Path = FIXTURE) -> list[tuple[str, str, dict[str, Any]]]:
    fixture = json.loads(path.read_text(encoding="utf-8"))
    outcomes = []
    for case in fixture["cases"]:
        result = reconcile_obligation_bundle(case["bundle"])
        outcomes.append((case["name"], result["global_verdict"], result))
    return outcomes


def main() -> int:
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    expected = {case["name"]: case["expected"] for case in fixture["cases"]}
    outcomes = run_bundle_fixture()
    failures = []
    for name, verdict, result in outcomes:
        want = expected[name]
        print(f"{name}: {verdict} (expected {want})")
        if verdict != want:
            failures.append((name, result))
    if failures:
        for name, result in failures:
            print(f"  {name}: {result['reconciliation_errors'] or result['record_errors']}")
        return 1
    print(f"ENAS obligation reconciler: {len(outcomes)} bundles matched expected global verdicts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
