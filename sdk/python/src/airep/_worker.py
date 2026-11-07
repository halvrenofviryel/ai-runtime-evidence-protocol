"""Process boundary for bounded untrusted-input evaluation; never executes submitted code."""
import json
import sys

from ._native.basis import verifier
from ._native.verify import evaluate_request
from ._native.reconcile import reconcile
from .consumer import consume
from .io import bounded_loads, artifacts, encoded, MAX_BYTES, MAX_ARTIFACTS
from .trust import from_bytes


def main():
    try:
        request = sys.stdin.buffer.read(6 * MAX_BYTES + 1)
        if len(request) > 6 * MAX_BYTES:
            raise ValueError('worker request too large')
        envelope = json.loads(request)
        if type(envelope) is not dict or set(envelope) != {'command', 'raw', 'trust', 'query'}:
            raise ValueError('worker envelope invalid')
        data = bytes.fromhex(envelope['raw'])
        parsed = bounded_loads(data)
        ops = from_bytes(bytes.fromhex(envelope['trust']))
        if envelope['command'] == 'verify':
            if (isinstance(parsed, dict) and isinstance(parsed.get('related_artifacts'), list)
                    and len(parsed['related_artifacts']) >= MAX_ARTIFACTS):
                raise ValueError('verification artifact inventory exceeded')
            result = evaluate_request(data, ops=ops)
        elif envelope['command'] == 'reconcile':
            result = reconcile(artifacts(data), ops=ops)
        elif envelope['command'] == 'consume':
            query = bounded_loads(bytes.fromhex(envelope['query']))
            result = consume(data, ops=ops, expected_identity=query)
        else:
            raise ValueError('unsupported evaluation command')
        output = encoded(result)
        if len(output) > 8 * MAX_BYTES:
            raise ValueError('evaluation result too large')
        sys.stdout.buffer.write(output)
        return 0
    except (ValueError, TypeError, KeyError, OSError, RecursionError, verifier.RunInvalid, verifier.UsageError) as exc:
        # Input contents and local paths are not echoed as diagnostics.
        print('invalid evaluation input: ' + type(exc).__name__, file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
