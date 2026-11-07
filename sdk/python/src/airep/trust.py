"""Operator-controlled trust is separate from the producer's evidence bundle."""
from ._native.basis import verifier
from ._native.producer import digest_bytes
from .io import bounded_loads, encoded


def from_bytes(raw):
    doc = bounded_loads(raw)
    if type(doc) is not dict or set(doc) - {'bindings', 'revocation', 'independence', 'now', 'freshness_window'}:
        raise ValueError('closed operator trust document required')
    ops = verifier.OperatorInputs()
    for field, target in [('bindings', 'bindings'), ('revocation', 'revocation'), ('independence', 'independence')]:
        if field in doc:
            setattr(ops, target + '_doc', doc[field])
            setattr(ops, target + '_digest', digest_bytes(encoded(doc[field])))
    if 'now' in doc:
        ops.now = verifier._parse_now(doc['now'])
    if 'freshness_window' in doc:
        ops.window = verifier._parse_window(str(doc['freshness_window']))
    return ops
