#!/usr/bin/env python3
"""Prove that v0.2 pins the two things v0.1 left open in its signature bullet.

v0.1 SPEC.md section 6 requires a producer to sign `integrity.current` and record
`{alg, value}`. `integrity.current` is a string -- "sha256:" followed by 64 lowercase
hexadecimal characters -- and the frozen v0.1 text states neither

  (A) whether the signed bytes are that string or the 32 bytes it denotes, nor
  (B) how `signature.value` is encoded.

An independently authored v0.1 producer reached acceptance only by choosing one reading
of each, and re-signing the same records under the other readings was rejected by both
pinned v0.1 verifiers. See EXTERNAL_EVIDENCE.md.

v0.2 closes both. INTEGRITY.md section 3 fixes the preimage as

    sig_preimage = sig-tag-bytes  LF  suite-id-bytes  LF  current-bytes
    current-bytes = the ASCII bytes of the full integrity.current string

and `common.schema.json#/$defs/signature_value` fixes the encoding as ^[0-9a-f]{128}$.

This script asserts both against the frozen v0.2 vectors, and asserts that reading (A)
is not merely different but unverifiable: it produces different preimage bytes, over
which the frozen signature does not verify. It reads only frozen artifacts, mutates
nothing, and adds no fixture to any pinned corpus.

Run:
    python3 spec/airep/v0.2/prove_signature_input_pinning.py
"""
import base64
import json
import os
import re
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS = os.path.join(HERE, "vectors", "out", "python_vectors.json")
SCHEMA = os.path.join(HERE, "schemas", "common.schema.json")
LF = b"\x0a"
CURRENT_GRAMMAR = re.compile(r"^sha256:[0-9a-f]{64}$")

failures = []


def check(ok, label):
    print("  %-58s %s" % (label, "OK" if ok else "FAIL"))
    if not ok:
        failures.append(label)


def ed25519_verifies(pubkey_hex, signature_hex, preimage):
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex)).verify(
            bytes.fromhex(signature_hex), preimage)
        return True
    except (InvalidSignature, ValueError):
        return False


def main():
    vectors = json.load(open(VECTORS, encoding="utf-8"))["vectors"]
    schema = json.load(open(SCHEMA, encoding="utf-8"))
    value_pattern = schema["$defs"]["signature_value"]["pattern"]

    print("A. signed-input pinning -- INTEGRITY.md s3 current-bytes")
    for vid in ("V1", "V2", "V3", "V4"):
        v = vectors[vid]
        current = v["current"]
        sig_tag = bytes.fromhex(v["sig_tag_hex"])
        suite_id = bytes.fromhex(v["suite_id_hex"])
        frozen_preimage = bytes.fromhex(v["sig_preimage_hex"])

        if not CURRENT_GRAMMAR.match(current):
            check(False, "%s integrity.current grammar" % vid)
            continue

        # The pinned reading: the ASCII bytes of the full integrity.current string.
        pinned = sig_tag + LF + suite_id + LF + current.encode("ascii")
        # The v0.1-plausible alternative: the 32 bytes the string denotes.
        digest_bytes = sig_tag + LF + suite_id + LF + bytes.fromhex(current[len("sha256:"):])

        check(pinned == frozen_preimage,
              "%s pinned preimage reproduces the frozen bytes" % vid)
        check(digest_bytes != frozen_preimage,
              "%s digest-bytes reading is a different preimage" % vid)
        check(ed25519_verifies(v["producer_pubkey_hex"], v["signature_hex"], pinned),
              "%s frozen signature verifies over the pinned preimage" % vid)
        check(not ed25519_verifies(v["producer_pubkey_hex"], v["signature_hex"], digest_bytes),
              "%s frozen signature does NOT verify over digest bytes" % vid)

    print("\nB. head-witness preimage uses canonical claim bytes -- INTEGRITY.md s4")
    for vid in ("W1", "W2"):
        v = vectors[vid]
        claim_bytes = bytes.fromhex(v["jcs_claim_hex"])
        witness_tag = bytes.fromhex(v["witness_tag_hex"])
        suite_id = bytes.fromhex(v["suite_id_hex"])
        pinned = witness_tag + LF + suite_id + LF + claim_bytes
        check(pinned == bytes.fromhex(v["witness_preimage_hex"]),
              "%s pinned witness preimage reproduces the frozen bytes" % vid)
        check(ed25519_verifies(v["witness_pubkey_hex"], v["witness_signature_hex"], pinned),
              "%s frozen witness signature verifies over it" % vid)

    print("\nC. signature.value encoding pinning -- common.schema.json signature_value")
    print("  pattern: %s" % value_pattern)
    rx = re.compile(value_pattern)
    for vid in ("V1", "V2", "V3", "V4"):
        hex_value = vectors[vid]["signature_hex"]
        b64_value = base64.b64encode(bytes.fromhex(hex_value)).decode("ascii")
        check(bool(rx.match(hex_value)), "%s frozen hex value satisfies the pattern" % vid)
        check(not rx.match(b64_value), "%s base64 of the same signature does not" % vid)
    print("  the same gate already carries two generated schema-corpus negatives:")
    print("    decision-neg-sig-short      value 64 hex chars   -> INVALID /integrity/signature/value")
    print("    decision-neg-sig-uppercase  value 128 upper hex  -> INVALID /integrity/signature/value")

    print("\n%s" % ("RESULT: all signature-input and encoding pinning checks PASSED"
                    if not failures else
                    "RESULT: %d check(s) FAILED" % len(failures)))
    for f in failures:
        print("  FAILED: %s" % f)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
