#!/usr/bin/env python3
"""Manifests + deterministic archives. INTERNAL TOOLING, excluded from archives."""
import hashlib, json, subprocess, sys, zipfile
from pathlib import Path

REPO = Path("/mnt/data/claude/ai-runtime-evidence-protocol")
OUT = REPO / "interop/independent-verifier-corpus/v0.1"
DIST = REPO / "dist"
# Fixed timestamp derived from the source release commit, never wall clock.
REL_TS = subprocess.run(["git","show","-s","--format=%cI","b5ae87f74b386b11b8882865e50c3ad38120ff97"],
                        cwd=REPO, capture_output=True, text=True).stdout.strip()
ZIP_DATE = (2026, 8, 25, 0, 0, 0)   # UTC date of the release commit, fixed

def sha256(p):
    h = hashlib.sha256()
    with p.open("rb") as f:
        for c in iter(lambda: f.read(1<<20), b""): h.update(c)
    return h.hexdigest()

def rels():
    return sorted(str(p.relative_to(OUT)) for p in OUT.rglob("*")
                  if p.is_file() and "__pycache__" not in p.parts
                  and str(p.relative_to(OUT)) not in ("manifests/FILES.json","manifests/SHA256SUMS"))

def build_manifests():
    files = []
    for rel in rels():
        p = OUT/rel
        # PROC-UNP ships a deliberately unparseable request: the probe exists to make a
        # verifier report run-invalid. Declaring it parseable would make the package checker
        # demand that the corpus's own negative case be well-formed.
        UNPARSEABLE = {"cases/PROC-UNP/request.json"}
        is_json = rel.endswith(".json") and rel not in UNPARSEABLE
        files.append({"path": rel, "sha256": sha256(p), "size": p.stat().st_size, "json": is_json})
    agg = hashlib.sha256()
    for f in files:                      # documented aggregate rule
        agg.update(f["path"].encode("utf-8")); agg.update(b"\0")
        agg.update(f["sha256"].encode("ascii")); agg.update(b"\n")
    (OUT/"manifests").mkdir(exist_ok=True)
    (OUT/"manifests/FILES.json").write_text(json.dumps({
        "aggregate_rule": "sha256 over, for each file sorted by path: utf8(path) || 0x00 || "
                          "ascii(lowercase-hex sha256) || 0x0A",
        "aggregate": agg.hexdigest(),
        "file_count": len(files),
        "files": files}, indent=2, sort_keys=True)+"\n")
    (OUT/"manifests/SHA256SUMS").write_text(
        "".join(f"{f['sha256']}  {f['path']}\n" for f in files))
    return agg.hexdigest(), len(files)

def build_zip(name, include):
    DIST.mkdir(exist_ok=True)
    target = DIST/name
    if target.exists(): target.unlink()
    paths = sorted(p for p in rels()+["manifests/FILES.json","manifests/SHA256SUMS"] if include(p))
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for rel in paths:
            zi = zipfile.ZipInfo(f"airep-v0.2-independent-verifier-corpus-v0.1/{rel}", ZIP_DATE)
            zi.external_attr = (0o644 & 0xFFFF) << 16
            zi.create_system = 3
            z.writestr(zi, (OUT/rel).read_bytes())
    return sha256(target)

ORACLE = ("expected/", "CASE_INDEX.json")
def is_oracle(p): return p.startswith("expected/")

if __name__ == "__main__":
    agg, n = build_manifests()
    # One archive only. The inputs/oracle split was withdrawn: inputs.zip retained every
    # per-case expected.json (so it was not input-only) and shipped the checker with a
    # manifest declaring a file it did not contain (so the checker could only fail).
    full = build_zip("airep-v0.2-independent-verifier-corpus-v0.1-full.zip", lambda p: True)
    print(json.dumps({"release_commit_time": REL_TS, "file_count": n, "aggregate": agg,
                      "full": full}, indent=2))
