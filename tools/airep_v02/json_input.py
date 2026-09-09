"""AD-17 admission BEFORE map collapse and before RFC 8785 serialization."""
import json
import math
import re


class InvalidInput(ValueError):
    pass


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InvalidInput('duplicate JSON member: ' + repr(key))
        result[key] = value
    return result


def _number(token):
    value = float(token)
    if not math.isfinite(value):
        raise InvalidInput('non-finite JSON number')
    # Safe exact integers can use Python int without changing the binary64 value.
    return int(value) if value.is_integer() and abs(value) <= 9007199254740991 else value


def normalize(value):
    """Admit a library JSON value; maps already have unique member identities.

    Integers follow binary64 semantics just like raw tokens. Exact large integers
    belong in strings. Never mutates the caller's object.
    """
    if value is None or type(value) is bool:
        return value
    if type(value) in (int, float):
        try:
            return _number(value)
        except OverflowError as exc:
            raise InvalidInput('non-finite JSON number') from exc
    if type(value) is str:
        for char in value:
            n = ord(char)
            if 0xd800 <= n <= 0xdfff or 0xfdd0 <= n <= 0xfdef or n & 0xffff in (0xfffe, 0xffff):
                raise InvalidInput('inadmissible Unicode scalar')
        return value
    if type(value) is list:
        return [normalize(item) for item in value]
    if type(value) is dict:
        if any(type(key) is not str for key in value):
            raise InvalidInput('JSON object keys must be strings')
        return {normalize(key): normalize(item) for key, item in value.items()}
    raise InvalidInput('not a JSON value: ' + type(value).__name__)


def loads(raw):
    try:
        if isinstance(raw, bytes):
            raw = raw.decode('utf-8', errors='strict')
        if raw.startswith('\ufeff'):
            raise InvalidInput('initial UTF-8 BOM is forbidden by AD-17')
        doc = json.loads(raw, object_pairs_hook=_pairs, parse_int=_number,
                         parse_float=_number, parse_constant=lambda _: _number('nan'))
        return normalize(doc)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise InvalidInput(str(exc)) from exc


def dumps(doc):
    return json.dumps(normalize(doc), ensure_ascii=False, indent=2, allow_nan=False) + '\n'


def check_core_number_bounds(raw, *, request=False):
    """AD-17 §6.4: rounding cannot move out-of-range sequence into the range.

    Re-read retained raw tokens ONLY for this bounded Core check;
    the actual JSON/JCS model remains binary64. Profiles are not exact integers.
    This is not applied to operator schemas/registries or witness claim tokens.
    """
    try:
        class NumericToken(str):
            pass
        exact = json.loads(raw, parse_int=NumericToken, parse_float=NumericToken, object_pairs_hook=_pairs)
        if request and isinstance(exact, dict):
            artifacts = [exact.get('artifact')] + (exact.get('related_artifacts') or [])
        else:
            artifacts = exact if isinstance(exact, list) else [exact]
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                continue
            number = artifact.get('sequence')
            if not isinstance(number, NumericToken):
                continue
            m = re.fullmatch(r'(-?)(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?', number)
            digits = (m[2] + (m[3] or '')).lstrip('0')
            if not digits:
                continue
            exponent = m[4] or '0'
            # Only its relation to a small bound matters. Avoid constructing
            # an enormous exponent integer on underflowing numeric tokens.
            significant_exponent = exponent.lstrip('+-0')
            exp = int(exponent) if len(significant_exponent) <= 20 else (-10**20 if exponent.startswith('-') else 10**20)
            magnitude = len(digits) + exp - len(m[3] or '')
            leading = digits.ljust(16, '0')[:16]
            if (m[1] == '-' or magnitude > 16 or magnitude == 16 and (
                    leading > '9007199254740991' or leading == '9007199254740991' and any(c!='0' for c in digits[16:]))):
                raise InvalidInput('raw sequence is outside the exact Core bounds')
    except (ValueError, TypeError) as exc:
        raise InvalidInput(str(exc)) from exc
