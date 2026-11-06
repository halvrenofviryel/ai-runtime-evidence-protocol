"""Core admission plus conservative handling of non-equivalent overlapping windows."""
from integrations.langgraph.temporal.core import evaluate as core_evaluate
from .source import DurablePolicy


def evaluate(deliveries, query, sources, ops):
    result = core_evaluate(deliveries, query, sources, ops, source_policy=DurablePolicy())
    qstart, qend = query['window']
    rows = [r['event'] for r in result['history'] if r['in_query_identity'] and not r['superseded']
            and r['event']['kind'] == 'effect' and r['event']['clock_id'] == query['clock_id']
            and r['event']['boundary'] == query['boundary'] and r['event']['predicate_id'] == query['predicate_id']
            and r['event']['observed_time'] <= query['cutoff'] and r['event']['event_time'] <= query['cutoff']]
    overlapping = [e for e in rows if max(e['window'][0], qstart) < min(e['window'][1], qend)]
    nonexact = [e for e in overlapping if e['window'] != query['window']]
    result['non_equivalent_overlapping_windows'] = sorted(e['event_id'] for e in nonexact)
    # Different statuses over partly overlapping windows are not necessarily a
    # logical contradiction. With endpoint samples we lack enough information
    # to reconcile them; neither arrival order nor the latest timestamp wins.
    result['overlap_requires_reconciliation'] = bool(nonexact and len({e['status'] for e in overlapping}) > 1)
    if result['overlap_requires_reconciliation']:
        result['stages']['effect']['status'] = 'INDETERMINATE'
    return result
