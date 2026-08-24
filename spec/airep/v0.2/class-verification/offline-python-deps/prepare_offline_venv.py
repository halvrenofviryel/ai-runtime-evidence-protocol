#!/usr/bin/env python3
"""Build the isolated offline venv that is the official Python reproduction basis.

Offline and fail-closed:
  * every wheel's sha256 is re-verified against MANIFEST.json BEFORE pip is invoked;
  * pip runs with --no-index (no network) and --require-hashes (no unpinned input);
  * the venv is created WITHOUT --system-site-packages, so nothing installed on the
    machine can satisfy an import;
  * after installation, every third-party module the verifier imports -- and every
    non-stdlib module loaded during a real import of them -- is asserted to resolve
    from inside this venv, and its version is asserted against the manifest.

The last check is the point of the whole bundle: it is what makes "the system had a
different cryptography/jsonschema installed" incapable of reaching the evidence basis.

Usage:  python3 prepare_offline_venv.py [--venv PATH]
Exit 0 only if every check passes.
"""
import argparse
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
MANIFEST = json.loads((HERE / "MANIFEST.json").read_text(encoding="utf-8"))
LOCK = HERE / "requirements.lock"
WHEELS = HERE / "wheels"


def fail(msg):
    print("FAIL: " + msg, file=sys.stderr)
    raise SystemExit(1)


def verify_wheels():
    names = sorted(p.name for p in WHEELS.glob("*.whl"))
    expected = sorted(r["wheel"] for r in MANIFEST["packages"].values())
    if names != expected:
        fail("wheelhouse contents %s != manifest %s" % (names, expected))
    for dist, rec in sorted(MANIFEST["packages"].items()):
        blob = (WHEELS / rec["wheel"]).read_bytes()
        got = hashlib.sha256(blob).hexdigest()
        if got != rec["sha256"]:
            fail("%s: sha256 mismatch\n  manifest %s\n  actual   %s" % (dist, rec["sha256"], got))
        print("  %-28s %-10s sha256-ok" % (dist, rec["version"]))
    agg_lines = "".join("%s  %s\n" % (MANIFEST["packages"][d]["sha256"],
                                      MANIFEST["packages"][d]["wheel"])
                        for d in sorted(MANIFEST["packages"]))
    agg = hashlib.sha256(agg_lines.encode("utf-8")).hexdigest()
    if agg != MANIFEST["aggregate_sha256"]:
        fail("bundle aggregate mismatch\n  manifest %s\n  actual   %s"
             % (MANIFEST["aggregate_sha256"], agg))
    print("  aggregate_sha256 ok: %s" % agg)


def build(venv: pathlib.Path):
    if venv.exists():
        shutil.rmtree(venv)
    # deliberately WITHOUT --system-site-packages
    subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
    py = venv / "bin" / "python"
    subprocess.run([str(py), "-m", "pip", "install", "--quiet", "--no-index",
                    "--find-links", str(WHEELS), "--require-hashes",
                    "-r", str(LOCK)], check=True)
    return py


def assert_isolated(py: pathlib.Path, venv: pathlib.Path):
    """Every third-party module must load from inside the venv, at the pinned version."""
    probe = r"""
import json, sys, sysconfig, importlib.metadata as md
venv = sys.prefix
before = set(sys.modules)
import cryptography
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa
import jsonschema, referencing  # noqa
stdlib = sysconfig.get_paths()["stdlib"]
leaked, versions = [], {}
for name, mod in sorted(sys.modules.items()):
    f = getattr(mod, "__file__", None)
    if not f or "." in name:
        continue
    if f.startswith(stdlib) or f.startswith(sys.base_prefix + "/lib/python"):
        continue
    if not f.startswith(venv):
        leaked.append((name, f))
for dist in ("cryptography", "jsonschema", "referencing", "attrs",
             "rpds-py", "jsonschema-specifications", "typing-extensions"):
    try:
        versions[dist] = md.version(dist)
    except Exception:
        versions[dist] = None
print(json.dumps({"prefix": sys.prefix, "base_prefix": sys.base_prefix,
                  "python": sys.version.split()[0], "leaked": leaked,
                  "versions": versions,
                  "crypto_file": cryptography.__file__}))
"""
    out = subprocess.run([str(py), "-c", probe], capture_output=True, text=True)
    if out.returncode != 0:
        fail("isolation probe failed:\n" + out.stderr)
    info = json.loads(out.stdout)
    if info["prefix"] == info["base_prefix"]:
        fail("not running inside a venv")
    if info["leaked"]:
        fail("third-party modules loaded from OUTSIDE the venv: %s" % info["leaked"])
    if not info["crypto_file"].startswith(str(venv)):
        fail("cryptography resolved outside the venv: %s" % info["crypto_file"])
    for dist, ver in sorted(info["versions"].items()):
        if dist not in MANIFEST["packages"]:
            continue
        want = MANIFEST["packages"][dist]["version"]
        if ver != want:
            fail("%s: venv has %s, manifest pins %s" % (dist, ver, want))
    print("  python in venv: %s" % info["python"])
    print("  cryptography loads from: %s" % info["crypto_file"])
    print("  modules leaking from outside the venv: none")
    for dist in sorted(info["versions"]):
        if info["versions"][dist] is not None:
            print("    %-28s %s" % (dist, info["versions"][dist]))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--venv", default=str(HERE / ".venv"))
    args = ap.parse_args()
    venv = pathlib.Path(args.venv).resolve()

    print("verifying wheelhouse against MANIFEST.json:")
    verify_wheels()
    print("\nbuilding isolated venv (no --system-site-packages, --no-index, --require-hashes):")
    py = build(venv)
    print("\nasserting isolation:")
    assert_isolated(py, venv)
    print("\noffline venv ready: %s" % venv)
    print("run the verifier with: %s/bin/python ../verifier_py/class_verifier.py ..." % venv)
    return 0


if __name__ == "__main__":
    sys.exit(main())
