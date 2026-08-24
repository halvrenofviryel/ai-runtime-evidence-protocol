#!/usr/bin/env python3
"""Offline reproduction preflight for the AIREP v0.2 class-verification basis.

Establishes that both verifiers run from a clean checkout with no network and no
fallback to system-installed dependencies, and records each implementation's own
determinism digest.

This script deliberately does NOT compare the two implementations' outputs to each
other. Cross-runtime parity is the third-context comparator's measurement, not this
one's; mixing the two would let a preflight quietly become parity evidence.

WHAT IS ENFORCED, AND WHAT IS NOT -- stated at its real strength:
  * ENFORCED: pip runs with --no-index; the venv is built without
    --system-site-packages; every wheel and tarball hash is verified before use;
    every third-party module is asserted to resolve from inside the bundle; Node's
    ajv is asserted to resolve from the vendored node_modules, not from a system
    path; proxy variables are pointed at an unroutable address so an accidental
    outbound HTTP call fails immediately rather than silently succeeding.
  * NOT ENFORCED: kernel-level network isolation. `unshare -rn` is unavailable in
    this environment (uid_map write denied) and no sandbox tool is installed, so
    this preflight cannot PROVE a syscall-level absence of network. It proves that
    the configured tools were run in no-index/offline mode and that all inputs came
    from vendored, hash-verified files. A reviewer wanting a stronger claim should
    re-run this inside a network namespace or an air-gapped host.

Usage:  python3 preflight_offline_basis.py [--repo PATH]
Exit 0 only if every check passes.
"""
import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import sys

FAILURES = []


def check(label, ok, detail=""):
    print(("  [ ok ] " if ok else "  [FAIL] ") + label + ((" :: " + detail) if detail else ""))
    if not ok:
        FAILURES.append(label)
    return ok


def offline_env():
    """Point every proxy at an unroutable address and forbid pip indexes."""
    env = dict(os.environ)
    dead = "http://127.0.0.1:9"  # discard port, immediate connection refusal
    for k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "all_proxy"):
        env[k] = dead
    env["no_proxy"] = ""
    env["NO_PROXY"] = ""
    env["PIP_NO_INDEX"] = "1"
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["NODE_PATH"] = ""            # no ambient module search path
    env["npm_config_offline"] = "true"
    return env


def digest_runs(cmd, cwd, out_paths, env):
    """Run a verifier twice, return (exit codes, digests, verdict count)."""
    codes, digests = [], []
    for out in out_paths:
        r = subprocess.run(cmd + ["--out", str(out)], cwd=str(cwd), env=env,
                           capture_output=True, text=True)
        codes.append(r.returncode)
        if r.returncode != 0:
            print("      stderr:", (r.stderr or "").strip()[:300])
            digests.append(None)
            continue
        digests.append(hashlib.sha256(pathlib.Path(out).read_bytes()).hexdigest())
    count = None
    if digests and digests[0] is not None:
        count = len(json.loads(pathlib.Path(out_paths[0]).read_text())["verdicts"])
    return codes, digests, count


def compare_to_expected(out_path, corpus):
    """Each implementation against the FROZEN expected values -- not against each other."""
    verdicts = json.loads(pathlib.Path(out_path).read_text())["verdicts"]
    base = corpus / "cases"
    by_ref = {}
    for d in sorted(base.iterdir()):
        req = json.loads((d / "request.json").read_text())
        art = req.get("artifact") or req
        sub, ig = art.get("subject", {}), art.get("integrity", {})
        by_ref[(art.get("chain_id") or sub.get("chain_id") or ig.get("chain_id"),
                art.get("record_id") or sub.get("record_id") or ig.get("record_id"))] = d.name
    mismatches, seen = [], set()
    for v in verdicts:
        cid = by_ref.get((v["artifact_ref"]["chain_id"], v["artifact_ref"]["record_id"]))
        if cid is None:
            mismatches.append(("<unmapped>", v["artifact_ref"], None, None))
            continue
        seen.add(cid)
        exp = json.loads((base / cid / "expected.json").read_text())
        for k, want in exp.items():
            got = v.get(k, "<MISSING>")
            if got != want:
                mismatches.append((cid, k, want, got))
    missing = sorted({d.name for d in base.iterdir()} - seen)
    return len(verdicts), mismatches, missing


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=None, help="repo root (default: infer from this file)")
    ap.add_argument("--scratch", default="/tmp/airep_preflight_out")
    args = ap.parse_args()

    cv = (pathlib.Path(args.repo).resolve() / "spec/airep/v0.2/class-verification"
          if args.repo else pathlib.Path(__file__).resolve().parent)
    scratch = pathlib.Path(args.scratch)
    scratch.mkdir(parents=True, exist_ok=True)
    env = offline_env()
    corpus = cv / "corpus"

    print("AIREP v0.2 class-verification -- OFFLINE REPRODUCTION PREFLIGHT")
    print("tree:", cv)
    print("\n-- 0. environment --")
    print("  python:", sys.version.split()[0])
    node_v = subprocess.run(["node", "--version"], capture_output=True, text=True).stdout.strip()
    print("  node:  ", node_v)
    ns = subprocess.run(["unshare", "-rn", "true"], capture_output=True, text=True)
    print("  kernel network isolation available:", ns.returncode == 0,
          "" if ns.returncode == 0 else "(NOT enforced -- see module docstring)")

    print("\n-- 1. Node dependency materialization (vendored tarballs, offline) --")
    r = subprocess.run([sys.executable, str(cv / "offline-node-deps/materialize_node_modules.py")],
                       cwd=str(cv), env=env, capture_output=True, text=True)
    check("node_modules materialized from vendored tarballs", r.returncode == 0,
          (r.stderr or "").strip()[:200])
    for line in (r.stdout or "").strip().splitlines():
        print("      " + line)

    print("\n-- 2. Python venv materialization (hash-pinned wheelhouse, offline) --")
    r = subprocess.run([sys.executable, str(cv / "offline-python-deps/prepare_offline_venv.py")],
                       cwd=str(cv), env=env, capture_output=True, text=True)
    check("isolated venv built and isolation asserted", r.returncode == 0,
          (r.stderr or "").strip()[:300])
    for line in (r.stdout or "").strip().splitlines():
        print("      " + line)

    venv_py = cv / "offline-python-deps/.venv/bin/python"

    print("\n-- 3. no system-dependency fallback --")
    probe = ("import json,sys;import cryptography,jsonschema,referencing;"
             "print(json.dumps({'p':sys.prefix,'b':sys.base_prefix,'c':cryptography.__file__,"
             "'j':jsonschema.__file__,'r':referencing.__file__}))")
    r = subprocess.run([str(venv_py), "-c", probe], env=env, capture_output=True, text=True)
    if check("python third-party imports resolve", r.returncode == 0, (r.stderr or "")[:200]):
        info = json.loads(r.stdout)
        vroot = str((cv / "offline-python-deps/.venv").resolve())
        check("sys.prefix is the bundle venv", info["p"].startswith(vroot), info["p"])
        check("venv is isolated from the base interpreter", info["p"] != info["b"])
        for k, label in (("c", "cryptography"), ("j", "jsonschema"), ("r", "referencing")):
            check("%s loads from the bundle venv" % label, info[k].startswith(vroot), info[k])

    r = subprocess.run(["node", "--input-type=module", "-e",
                        "import{createRequire}from'module';"
                        "const rq=createRequire(process.cwd()+'/x.js');"
                        "console.log(rq.resolve('ajv'));"],
                       cwd=str(cv / "verifier_node_r2"), env=env, capture_output=True, text=True)
    if check("node resolves ajv", r.returncode == 0, (r.stderr or "")[:200]):
        p = r.stdout.strip()
        check("ajv loads from the vendored bundle, not a system path",
              p.startswith(str((cv / "verifier_node_r2/node_modules").resolve())), p)
        check("ajv is NOT the system copy", not p.startswith("/usr/"), p)

    print("\n-- 4. Python verifier, per-implementation determinism --")
    codes, digests, count = digest_runs(
        [str(venv_py), "class_verifier.py", "--corpus", str(corpus)],
        cv / "verifier_py", [scratch / "py1.json", scratch / "py2.json"], env)
    check("python verifier exit 0 on both runs", codes == [0, 0], str(codes))
    check("python verifier byte-deterministic across two runs",
          digests[0] is not None and digests[0] == digests[1])
    check("python verifier produced 45 verdicts", count == 45, str(count))
    if digests[0]:
        print("      python digest: " + digests[0])
        n, mism, missing = compare_to_expected(scratch / "py1.json", corpus)
        check("python matches every frozen expected.json", not mism and not missing,
              ("%d mismatches, %d missing" % (len(mism), len(missing))) if (mism or missing) else "")

    print("\n-- 5. Node verifier, per-implementation determinism --")
    codes, digests_n, count = digest_runs(
        ["node", "class_verifier.mjs", "--corpus", str(corpus)],
        cv / "verifier_node_r2", [scratch / "nd1.json", scratch / "nd2.json"], env)
    check("node verifier exit 0 on both runs", codes == [0, 0], str(codes))
    check("node verifier byte-deterministic across two runs",
          digests_n[0] is not None and digests_n[0] == digests_n[1])
    check("node verifier produced 45 verdicts", count == 45, str(count))
    if digests_n[0]:
        print("      node digest:   " + digests_n[0])
        n, mism, missing = compare_to_expected(scratch / "nd1.json", corpus)
        check("node matches every frozen expected.json", not mism and not missing,
              ("%d mismatches, %d missing" % (len(mism), len(missing))) if (mism or missing) else "")

    print("\n-- 6. frozen corpus integrity --")
    man = json.loads((cv / "corpus_manifest.json").read_text())
    real = {str(p.relative_to(corpus)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in corpus.rglob("*") if p.is_file()}
    check("all %d corpus file digests match the manifest" % len(man["files"]), real == man["files"])
    path_sorted = "".join("%s  %s\n" % (real[n], n) for n in sorted(real))
    line_sorted = "".join(sorted("%s  %s\n" % (real[n], n) for n in real))
    agg = hashlib.sha256(path_sorted.encode("utf-8")).hexdigest()
    check("documented path-sort rule reproduces the recorded aggregate",
          agg == man["aggregate_sha256"], agg)
    check("whole-line/hash-prefix sort is a DIFFERENT rule (negative discrimination)",
          hashlib.sha256(line_sorted.encode("utf-8")).hexdigest() != man["aggregate_sha256"])

    print("\n" + "=" * 72)
    if FAILURES:
        print("PREFLIGHT FAILED: %d check(s)" % len(FAILURES))
        for f in FAILURES:
            print("  - " + f)
        return 1
    print("PREFLIGHT CLEAN.")
    print("Per-implementation digests recorded above. NO cross-implementation comparison")
    print("was performed; that measurement belongs to the third-context comparator.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
