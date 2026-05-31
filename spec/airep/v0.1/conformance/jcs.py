#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""RFC 8785 (JSON Canonicalization Scheme) — the canonical form AIREP hashes over (SPEC §6).

The earlier tooling used `json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=False)`,
which is byte-identical to JCS only for float-free / simple-decimal, ASCII-key records. This is the
real thing: keys sorted by UTF-16 code unit, JCS string escaping, no whitespace, UTF-8, and — the
part that actually differed — **ES6 Number-to-String** number serialization, so an arbitrary record
canonicalizes to the same bytes here as it does in JavaScript (`JSON.stringify`, which is ES6-native).
Verified byte-for-byte against the Node implementation across a value battery (see jcs cross-check).

NaN / Infinity are not valid JSON numbers and are rejected. Numbers whose exact representation is
significant SHOULD be carried as strings (SPEC §6), but with this serializer plain JSON numbers also
canonicalize deterministically across implementations.

PUBLIC API (stable; this is the canonicalizer to copy into any producer — it is stdlib-only):
    canonicalize(obj: Any) -> bytes   the RFC 8785 canonical UTF-8 bytes AIREP hashes over.
    es6_number(n) -> str              the ES6 Number::toString(10) used for JSON numbers.
A producer in another language MUST reproduce these exact bytes. Reference copies: this file (Python)
and the inline canonical() in producers/typescript/airep_producer.ts (Node).
"""
from __future__ import annotations

import json
import math
from typing import Any


def es6_number(n) -> str:
    """Serialize a number exactly as ECMAScript Number::toString(10) (== RFC 8785)."""
    if isinstance(n, bool):
        raise TypeError("bool is not a JSON number")
    if isinstance(n, int):
        return str(n)
    if math.isnan(n) or math.isinf(n):
        raise ValueError("NaN and Infinity are not valid JCS numbers")
    if n == 0.0:
        return "0"  # ES6 String(-0) === "0"
    sign = "-" if n < 0 else ""
    r = repr(abs(n))  # Python's shortest round-tripping decimal
    if "e" in r:
        mant, e = r.split("e")
        e = int(e)
    else:
        mant, e = r, 0
    ip, fp = mant.split(".") if "." in mant else (mant, "")
    digits = ip + fp
    point_exp = e - len(fp)              # value = int(digits) * 10**point_exp
    digits = digits.lstrip("0")
    stripped = digits.rstrip("0")
    point_exp += len(digits) - len(stripped)
    digits = stripped or "0"
    k = len(digits)                      # significant digits
    big_n = point_exp + k                # value = digits * 10**(big_n - k)
    if k <= big_n <= 21:
        return sign + digits + "0" * (big_n - k)
    if 0 < big_n <= 21:
        return sign + digits[:big_n] + "." + digits[big_n:]
    if -6 < big_n <= 0:
        return sign + "0." + "0" * (-big_n) + digits
    mantissa = digits if k == 1 else digits[0] + "." + digits[1:]
    exp = big_n - 1
    return sign + mantissa + "e" + ("+" if exp >= 0 else "-") + str(abs(exp))


def _ser(v: Any) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)  # JCS string escaping == JSON.stringify
    if isinstance(v, (int, float)):
        return es6_number(v)
    if isinstance(v, list):
        return "[" + ",".join(_ser(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v.keys(), key=lambda k: k.encode("utf-16-be"))  # UTF-16 code-unit order
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + _ser(v[k]) for k in keys) + "}"
    raise TypeError(f"not JSON-serializable: {type(v).__name__}")


def canonicalize(obj: Any) -> bytes:
    """Return the RFC 8785 canonical UTF-8 bytes of obj."""
    return _ser(obj).encode("utf-8")


if __name__ == "__main__":
    import sys
    print(canonicalize(json.load(sys.stdin)).decode("utf-8"))
