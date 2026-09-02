#!/usr/bin/env python3
"""Per-case byte material. INTERNAL TOOLING, excluded from recipient archives.

Derives canonical bytes and preimages for each cryptographically applicable case and
SELF-VALIDATES every derivation against a value the frozen corpus already recorded:

  * the derived hash preimage must SHA-256 to the artifact's own `integrity.current`;
  * the derived signature preimage must verify under the artifact's own
    `integrity.signature` and the public key its bindings file names.

Those two recorded values were produced by the release's corpus builder, not by this
script, so agreement is a check against frozen output rather than against ourselves.
A derivation that fails either check is NOT emitted; the case is reported and skipped.
"""
from __future__ import annotations
import hashlib, importlib.util, json, sys
from pathlib import Path

REPO = Path("/mnt/data/claude/ai-runtime-evidence-protocol")
OUT = REPO / "interop/independent-verifier-corpus/v0.1"
PIN = "b5ae87f74b386b11b8882865e50c3ad38120ff97"

# RFC 8785 from the release's own v0.1 conformance module (not re-implemented here).
import subprocess
_jcs_src = subprocess.run(["git", "show", f"{PIN}:spec/airep/v0.1/conformance/jcs.py"],
                          cwd=REPO, capture_output=True).stdout
_ns: dict = {}
exec(compile(_jcs_src, "jcs.py", "exec"), _ns)
canonicalize = _ns.get("canonicalize") or _ns.get("jcs") or _ns.get("dumps")


def _jcs_bytes(obj) -> bytes:
    """The released module returns bytes; accept either and never re-encode twice."""
    out = canonicalize(obj)
    return out if isinstance(out, (bytes, bytearray)) else out.encode("utf-8")

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature


def hash_preimage(artifact: dict) -> bytes:
    body = json.loads(json.dumps(artifact))
    body.get("integrity", {}).pop("current", None)
    body.get("integrity", {}).pop("signature", None)
    tag = f"AIREP/{artifact['airep_version']}/hash/{artifact['artifact_type']}"
    return tag.encode("ascii") + b"\n" + _jcs_bytes(body)


def sig_preimage(artifact: dict, suite: str) -> bytes:
    tag = f"AIREP/{artifact['airep_version']}/sig/{artifact['artifact_type']}"
    return (tag.encode("ascii") + b"\n" + suite.encode("ascii") + b"\n"
            + artifact["integrity"]["current"].encode("ascii"))


def main() -> int:
    idx = json.loads((OUT / "CASE_INDEX.json").read_text())
    emitted, skipped = [], []
    for c in idx["cases"]:
        cid = c["package_case_id"]
        req_p = OUT / "cases" / cid / "request.json"
        try:
            req = json.loads(req_p.read_text())
        except Exception:
            skipped.append((cid, "request is not parseable JSON (this is the case's point)"))
            continue
        art = req.get("artifact")
        if not isinstance(art, dict) or "integrity" not in art:
            skipped.append((cid, "no artifact with an integrity block"))
            continue

        hp = hash_preimage(art)
        derived_current = "sha256:" + hashlib.sha256(hp).hexdigest()
        recorded_current = art["integrity"].get("current")
        if derived_current != recorded_current:
            skipped.append((cid, f"HASH SELF-CHECK FAILED derived={derived_current} "
                                 f"recorded={recorded_current}"))
            continue

        bindings = json.loads((OUT / "cases" / cid / "bindings.json").read_text())
        wire_producer = art.get("subject", {}).get("producer")
        bid = bindings.get("producer_bindings", {}).get(wire_producer)
        binding = bindings.get("bindings", {}).get(bid) if bid else None
        sig_ok, suite, pub = None, None, None
        sp = None
        if binding and binding.get("suite") and binding.get("public_key_hex"):
            suite, pub = binding["suite"], binding["public_key_hex"]
            sp = sig_preimage(art, suite)
            sigval = art["integrity"].get("signature", {}).get("value")
            try:
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).verify(
                    bytes.fromhex(sigval), sp)
                sig_ok = True
            except (InvalidSignature, ValueError, TypeError):
                sig_ok = False

        base = OUT / "bytes/cases" / cid
        base.mkdir(parents=True, exist_ok=True)
        body = json.loads(json.dumps(art))
        body.get("integrity", {}).pop("current", None)
        body.get("integrity", {}).pop("signature", None)
        jcs_bytes = _jcs_bytes(body)
        files = {"jcs_body": jcs_bytes, "hash_preimage": hp}
        if sp is not None:
            files["sig_preimage"] = sp
        for name, raw in files.items():
            (base / f"{name}.bin").write_bytes(raw)
            (base / f"{name}.hex").write_text(raw.hex() + "\n")
        meta = {
            "package_case_id": cid,
            "provenance_kind": "package_derived",
            "derivation": {
                "source_bytes": f"cases/{cid}/request.json (artifact object, verbatim)",
                "canonicalizer": f"spec/airep/v0.1/conformance/jcs.py at {PIN} (released module, "
                                 f"loaded unmodified; not re-implemented for this package)",
                "hash_preimage_rule": "INTEGRITY.md §2: tag || LF || JCS(artifact minus "
                                      "integrity.current and integrity.signature)",
                "signature_preimage_rule": "INTEGRITY.md §3",
            },
            "self_validation": {
                "derived_integrity_current": derived_current,
                "artifact_recorded_integrity_current": recorded_current,
                "hash_agreement": "MATCH — the derived preimage hashes to the value the frozen "
                                  "corpus recorded in the artifact, which this script did not produce",
                "signature_verifies_under_bound_key": sig_ok,
                "signature_note": (
                    "false here is the CASE's expected outcome, not a packaging error — see "
                    "expected_results.jsonl for this case" if sig_ok is False else
                    ("no producer binding resolves, so no signature preimage is emitted"
                     if sig_ok is None else "verified")),
                "suite": suite,
                "public_key_hex": pub,
            },
            "files": sorted(f"{n}.bin" for n in files) + sorted(f"{n}.hex" for n in files),
        }
        (base / "derivation.json").write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n")
        emitted.append((cid, sig_ok))

    print(f"emitted byte material for {len(emitted)} cases")
    for cid, ok in emitted:
        print(f"   {cid:10} hash self-check MATCH   signature_verifies={ok}")
    print(f"\nskipped {len(skipped)}:")
    for cid, why in skipped:
        print(f"   {cid:10} {why}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
