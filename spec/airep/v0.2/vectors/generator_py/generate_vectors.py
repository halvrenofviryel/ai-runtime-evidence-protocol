#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""WP-a01 Stage-3A — Python fixed-vector generator.

Implements EXACTLY the frozen byte construction of spec/airep/v0.2/INTEGRITY.md
(sections 1-5) over the shared inputs in ../INPUTS.json, per ../VECTOR_PLAN.md.

Allowed inputs: INTEGRITY.md (normative text), VECTOR_PLAN.md, INPUTS.json, and
the pre-existing RFC 8785 implementation spec/airep/v0.1/conformance/jcs.py.
This generator reads no other generator's code, fixtures, or output.

Run:  python3 spec/airep/v0.2/vectors/generator_py/generate_vectors.py
Writes: spec/airep/v0.2/vectors/out/python_vectors.json (deterministic;
repeated runs are byte-identical — no timestamps, no metadata).
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HERE = Path(__file__).resolve().parent          # .../v0.2/vectors/generator_py
VECTORS_DIR = HERE.parent                       # .../v0.2/vectors
JCS_PATH = VECTORS_DIR.parent.parent / "v0.1" / "conformance" / "jcs.py"

# Load the pre-existing RFC 8785 canonicalizer (INTEGRITY.md section 2 rule 2:
# jcs-bytes MUST be produced by RFC 8785 exactly).
_spec = importlib.util.spec_from_file_location("airep_jcs", JCS_PATH)
_jcs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_jcs)
canonicalize = _jcs.canonicalize

LF = b"\x0a"                                    # the single separator byte
SUITE_ID = b"ed25519"                           # INTEGRITY.md section 3.1 (sole registry entry)

# Published TEST-ONLY seeds (VECTOR_PLAN.md "Keys").
PRODUCER_SEED = bytes.fromhex(
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
)
WITNESS_SEED = bytes.fromhex(
    "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"
)


def hash_tag(airep_version: str, artifact_type: str) -> bytes:
    """Hash tag as a pure function of the declared pair (INTEGRITY.md section 5)."""
    return f"AIREP/{airep_version}/hash/{artifact_type}".encode("ascii")


def sig_tag(airep_version: str, artifact_type: str) -> bytes:
    """Sig tag as a pure function of the declared pair (INTEGRITY.md section 5)."""
    return f"AIREP/{airep_version}/sig/{artifact_type}".encode("ascii")


def witness_tag(head_airep_version: str) -> bytes:
    """Head-witness tag; version equals the referenced head's airep_version (section 4.3)."""
    return f"AIREP/{head_airep_version}/sig/head-witness".encode("ascii")


def jcs_body_bytes(artifact: dict) -> bytes:
    """INTEGRITY.md section 2: logical copy, delete integrity.current and
    integrity.signature, retain everything else, then RFC 8785. The INPUTS.json
    bodies already omit both members, so the deletions are no-ops here; the
    mechanical steps are still performed exactly as specified."""
    body = copy.deepcopy(artifact)
    integrity = body.get("integrity")
    if isinstance(integrity, dict):
        integrity.pop("current", None)
        integrity.pop("signature", None)
    return canonicalize(body)


def main() -> None:
    with open(VECTORS_DIR / "INPUTS.json", "r", encoding="utf-8") as f:
        inputs = json.load(f)

    producer_key = Ed25519PrivateKey.from_private_bytes(PRODUCER_SEED)
    witness_key = Ed25519PrivateKey.from_private_bytes(WITNESS_SEED)
    producer_pub = producer_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    witness_pub = witness_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    vectors: dict[str, dict] = {}
    computed_current: dict[str, str] = {}   # vector id -> full integrity.current string

    # --- V1-V4: artifact construction vectors (INTEGRITY.md sections 1-3, 5) ---
    for vid, body in inputs["artifacts"].items():
        version = body["airep_version"]
        atype = body["artifact_type"]
        htag = hash_tag(version, atype)
        stag = sig_tag(version, atype)

        jcs_body = jcs_body_bytes(body)
        hash_preimage = htag + LF + jcs_body
        current = "sha256:" + hashlib.sha256(hash_preimage).hexdigest()
        computed_current[vid] = current

        sig_preimage = stag + LF + SUITE_ID + LF + current.encode("ascii")
        signature = producer_key.sign(sig_preimage)   # pure Ed25519, raw preimage

        vectors[vid] = {
            "hash_tag_hex": htag.hex(),
            "sig_tag_hex": stag.hex(),
            "jcs_body_hex": jcs_body.hex(),
            "hash_preimage_hex": hash_preimage.hex(),
            "current": current,
            "suite_id_hex": SUITE_ID.hex(),
            "sig_preimage_hex": sig_preimage.hex(),
            "signature_hex": signature.hex(),
            "producer_pubkey_hex": producer_pub.hex(),
        }

    # --- W1-W2: head-witness vectors (INTEGRITY.md section 4) ---
    for wid, wc in inputs["witness_claims"].items():
        head_id = wc["head"]
        head_body = inputs["artifacts"][head_id]
        wtag = witness_tag(head_body["airep_version"])

        # Closed five-member claim (section 4); current is the COMPUTED current of
        # the head vector; chain_id is the head body's chain_id; the rest verbatim.
        claim = {
            "chain_id": head_body["chain_id"],
            "sequence": wc["sequence"],
            "current": computed_current[head_id],
            "length": wc["length"],
            "witnessed_at": wc["witnessed_at"],
        }
        jcs_claim = canonicalize(claim)
        witness_preimage = wtag + LF + SUITE_ID + LF + jcs_claim
        witness_signature = witness_key.sign(witness_preimage)

        vectors[wid] = {
            "head": head_id,
            "witness_tag_hex": wtag.hex(),
            "suite_id_hex": SUITE_ID.hex(),
            "jcs_claim_hex": jcs_claim.hex(),
            "witness_preimage_hex": witness_preimage.hex(),
            "witness_signature_hex": witness_signature.hex(),
            "witness_pubkey_hex": witness_pub.hex(),
        }

    out_dir = VECTORS_DIR / "out"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "python_vectors.json"
    with open(out_path, "w", encoding="utf-8", newline="") as f:
        json.dump({"vectors": vectors}, f, sort_keys=True, indent=2)
        f.write("\n")


if __name__ == "__main__":
    main()
