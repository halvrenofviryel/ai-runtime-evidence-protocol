#!/usr/bin/env python3
"""Package integrity checker for the AIREP v0.2 Independent-Verifier Corpus v0.1.

SCOPE, deliberately narrow. This checks that the package you received is the package that
was built: file presence, SHA-256 digests, declared-JSON parseability, unexpected files,
and package identity.

IT IS NOT AN AIREP VERIFIER. It does not canonicalize records, does not compute or compare
AIREP hash or signature preimages, does not verify signatures, and does not classify
assurance. If it passes, you have the right bytes — nothing more. Standard library only.
"""
from __future__ import annotations
import hashlib, json, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# Private-key denylist held as SHA-256 DIGESTS, never as the secrets themselves, so this
# file can be distributed without becoming the leak it is meant to prevent. (An earlier
# version embedded the seed literals and correctly flagged itself.)
FORBIDDEN_SEED_DIGESTS = {
    "2a8abfa8cb9906290437854193ca6bca41d4d4e26d1d454bd66a35158095e737",
    "8588cdfcd6d2b0d521bcf0bf5e7017c06a3f4a10a172d9af1436205e3af205ad",
    "72adbc9e31042ef17cbd5cd61a407ba3712f944eeca0280b42fc931080069596",
}
# Assembled from fragments for the same reason the seeds are digested: a scanner that
# contains the literal it searches for reports itself. Not obfuscation - the whole rule is
# stated here in plain sight.
_B = "BEG" + "IN "
FORBIDDEN_MARKERS = [_B + k + "PRIVATE KEY" for k in ("", "OPENSSH ", "EC ", "RSA ", "DSA ")]
HEX64 = re.compile(r"\b[0-9a-fA-F]{64}\b")

def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def main() -> int:
    errs: list[str] = []
    man = ROOT / "manifests/FILES.json"
    if not man.is_file():
        print("FAIL: manifests/FILES.json missing"); return 1
    files = json.loads(man.read_text())["files"]
    declared = {f["path"]: f for f in files}

    for rel, rec in sorted(declared.items()):
        p = ROOT / rel
        if not p.is_file():
            errs.append(f"missing file: {rel}"); continue
        got = sha256(p)
        if got != rec["sha256"]:
            errs.append(f"digest mismatch: {rel}\n    declared {rec['sha256']}\n    actual   {got}")
        if rec.get("json") and rel != "manifests/FILES.json":
            try:
                json.loads(p.read_text(encoding="utf-8"))
            except Exception as e:
                errs.append(f"declared JSON does not parse: {rel}: {e}")

    on_disk = {str(p.relative_to(ROOT)) for p in ROOT.rglob("*")
               if p.is_file() and "__pycache__" not in p.parts}
    for extra in sorted(on_disk - set(declared) - {"manifests/SHA256SUMS", "manifests/FILES.json"}):
        errs.append(f"unexpected file not in manifest: {extra}")

    for p in sorted(ROOT.rglob("*")):
        if not p.is_file() or "__pycache__" in p.parts:
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        rel = p.relative_to(ROOT)
        for marker in FORBIDDEN_MARKERS:
            if marker in text:
                errs.append(f"PROHIBITED private key block in {rel}")
        for cand in HEX64.findall(text):
            if hashlib.sha256(cand.lower().encode()).hexdigest() in FORBIDDEN_SEED_DIGESTS:
                errs.append(f"PROHIBITED private seed value in {rel}")

    basis = ROOT / "SOURCE_BASIS.json"
    if basis.is_file():
        b = json.loads(basis.read_text())
        if b.get("target_commit_sha") != "b5ae87f74b386b11b8882865e50c3ad38120ff97":
            errs.append("SOURCE_BASIS.json target_commit_sha is not the pinned release commit")
    else:
        errs.append("SOURCE_BASIS.json missing")

    if errs:
        print(f"FAIL: {len(errs)} problem(s)")
        for e in errs:
            print("  -", e)
        return 1
    print(f"OK: {len(declared)} files present, digests match, no unexpected files, "
          f"no prohibited key material, source basis correct")
    print("NOTE: this checked package integrity only. No AIREP record was canonicalized, "
          "hashed, signature-verified or classified.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
