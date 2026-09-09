"""Small Ed25519 producer. No cryptographic option comes from wire metadata."""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .basis import SCHEMAS, verifier
from .json_input import normalize

GENESIS = 'sha256:' + '0' * 64
FAMILIES = ('decision', 'control', 'execution', 'effect')
CORE = {'airep_version', 'artifact_type', 'chain_id', 'record_id', 'sequence', 'subject', 'scope', 'integrity'}


def digest_bytes(value: bytes) -> str:
    if not isinstance(value, bytes):
        raise TypeError('digest_bytes requires explicit bytes')
    return 'sha256:' + hashlib.sha256(value).hexdigest()


def digest_json(value) -> str:
    """Explicit application choice: SHA-256 of admitted RFC 8785 JSON bytes."""
    return digest_bytes(verifier.jcs.canonicalize(normalize(value)))


def reference(artifact):
    return {'record_id': artifact['record_id'], 'chain_id': artifact['chain_id']}


def check_core(artifact):
    doc = normalize(artifact)
    verifier.schema_validate(doc, SCHEMAS)
    if verifier.compute_current(doc) != doc['integrity']['current']:
        raise ValueError('integrity.current mismatch')
    return doc


class Chain:
    """One writer's chain cursor; persist emitted artifacts for CLI continuation.

    Separate producers may use separate chains. A cursor is not a concurrent
    ledger, durable key store or authenticated checkpoint. Caller-supplied IDs
    and clocks make fixtures reproducible; defaults use UUID4 and UTC wall time.
    """
    def __init__(self, key: Ed25519PrivateKey, producer: str, *, chain_id=None, previous=None):
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError('an Ed25519 private key is required')
        if not isinstance(producer, str) or not producer:
            raise ValueError('producer must be a nonempty string')
        self.key, self.producer = key, producer
        self._previous = None if previous is None else check_core(previous)
        if previous is not None and chain_id is not None and chain_id != previous['chain_id']:
            raise ValueError('previous artifact belongs to a different chain')
        self.chain_id = previous['chain_id'] if previous is not None else (chain_id if chain_id is not None else str(uuid4()))
        self._ids = set() if previous is None else {previous['record_id']}

    def emit(self, family, payload, *, record_id=None, timestamp=None, scope=None):
        if family not in FAMILIES:
            raise ValueError('unregistered artifact family')
        if not isinstance(payload, dict) or CORE.intersection(payload):
            raise ValueError('payload must contain only family fields and optional profiles')
        rid = record_id if record_id is not None else str(uuid4())
        if not isinstance(rid, str) or not rid or rid in self._ids:
            raise ValueError('record_id must be nonempty and unused in this cursor')
        when = timestamp if timestamp is not None else datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        if verifier.parse_now_ns(when) is None:
            raise ValueError('timestamp must be a valid Gregorian UTC datetime')
        record = normalize(dict(deepcopy(payload), airep_version='0.2', artifact_type=family,
            chain_id=self.chain_id, record_id=rid,
            sequence=0 if self._previous is None else self._previous['sequence'] + 1,
            subject={'producer':self.producer, 'timestamp_utc':when},
            scope=scope if scope is not None else {
                'covers':['Authored report of the ' + family + ' stage'],
                'does_not_cover':['Truth of the report', 'Complete lifecycle history', 'Independent observation unless verified']},
            integrity={'previous':GENESIS if self._previous is None else self._previous['integrity']['current']}))
        record['integrity']['current'] = verifier.compute_current(record)
        preimage = verifier.record_sig_preimage('0.2', family, 'ed25519', record['integrity']['current'])
        record['integrity']['signature'] = {'alg':'ed25519', 'value':self.key.sign(preimage).hex()}
        check_core(record)
        # Transactional cursor update: rejected records never consume a position.
        self._previous = deepcopy(record)
        self._ids.add(rid)
        return record

    def emit_decision(self, payload, **kwargs):
        return self.emit('decision', payload, **kwargs)

    def emit_control(self, payload, **kwargs):
        return self.emit('control', payload, **kwargs)

    def emit_execution(self, payload, **kwargs):
        return self.emit('execution', payload, **kwargs)

    def emit_effect(self, payload, **kwargs):
        return self.emit('effect', payload, **kwargs)
