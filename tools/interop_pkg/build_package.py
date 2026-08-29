#!/usr/bin/env python3
"""Build the AIREP v0.2 Independent-Verifier Corpus v0.1.

INTERNAL TOOLING. Excluded from every recipient archive: it reads the release
basis and emits the package, and knows nothing about AIREP semantics beyond
which files to copy. It does not canonicalize, verify or classify.

Every byte of normative source is read from the pinned commit via `git show`,
never from the working tree, so a moving `main` cannot leak in.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

PIN = "b5ae87f74b386b11b8882865e50c3ad38120ff97"
TAG = "v0.2.0-alpha.1"
TAG_OBJ = "2c20ff2d6cc990cfc4ceb14a5e22ef823821635f"
DOI = "10.5281/zenodo.22101986"
WIRE = "0.2"
REPO = Path("/mnt/data/claude/ai-runtime-evidence-protocol")
SRC = "spec/airep/v0.2"
OUT = REPO / "interop/independent-verifier-corpus/v0.1"

# Published TEST-ONLY private seeds. Never enter the distribution; they are the
# denylist the leak scanner enforces (KEYS.md at the pin publishes all three).
FORBIDDEN_SEEDS = [
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
    "6090c1bb1f1f50b5a61391b065567acc246af5d93a8906c9e03ba58ca63c5d14",
]
PUBLIC_KEYS = {
    "producer": "3ccd241cffc9b3618044b97d036d8614593d8b017c340f1dee8773385517654b",
    "witness": "2e4e83fdb2d88f88c5f03e663c39ea3f9c7536312b62a2b09a95712dccf11a40",
    "executor": "0a3e66f14cea422caf45300e0c3bf42669e87839627750491f1f1e962d7a11cd",
}


def git_show(path: str) -> bytes:
    r = subprocess.run(["git", "show", f"{PIN}:{path}"], cwd=REPO,
                       capture_output=True)
    if r.returncode != 0:
        raise SystemExit(f"pinned read failed: {path}\n{r.stderr.decode()[:300]}")
    return r.stdout


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def write(rel: str, data: bytes) -> None:
    p = OUT / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)


def write_json(rel: str, obj) -> None:
    write(rel, (json.dumps(obj, indent=2, sort_keys=True,
                           ensure_ascii=False) + "\n").encode("utf-8"))


# ── case selection ────────────────────────────────────────────────────────
# category: positive | failure | caveat | withheld | indeterminate
# Each row records why the case is here and what it does not establish.
CASES = [
    ("CLS-P1",   "P1",   "class", "positive",      "decision",  "clean Decision earns AIREP-Authenticated; witness absent is WITHHELD not FAIL"),
    ("CLS-P2",   "P2",   "class", "positive",      "decision",  "clean witnessed Decision earns AIREP-Witnessed with all five channels empty"),
    ("CLS-P3",   "P3",   "class", "positive",      "effect",    "clean Effect with referenced Execution; observer assessment independent"),
    ("CLS-CTL1", "CTL1", "class", "positive",      "control",   "clean issuer-side Control Evidence artifact"),
    ("CLS-NG1",  "NG1",  "class", "positive",      "decision",  "witness over a NON-GENESIS chain head"),
    ("CLS-FR3",  "FR3",  "class", "positive",      "decision",  "freshness exactly at the window boundary still earns Witnessed"),
    ("CLS-PS1",  "PS1",  "class", "failure",       "decision",  "record signature made with a key other than the bound one"),
    ("CLS-PS2",  "PS2",  "class", "caveat",        "decision",  "valid Ed25519 signature, misleading wire alg: the binding selects the suite, not the wire label"),
    ("CLS-XT1",  "XT1",  "class", "failure",       "decision",  "producer binding revoked in the snapshot: definitive FAILURE"),
    ("CLS-IND4", "IND4", "class", "failure",       "decision",  "producer/witness pair listed non-independent: definitive witness FAILURE"),
    ("CLS-FR1",  "FR1",  "class", "failure",       "decision",  "witness outside the freshness window"),
    ("CLS-WM3",  "WM3",  "class", "failure",       "decision",  "head_ref names a record_id present in neither artifact nor related_artifacts"),
    ("CLS-PB2",  "PB2",  "class", "withheld",      "decision",  "no producer binding entry: assurance WITHHELD, not failed"),
    ("CLS-WB2",  "WB2",  "class", "withheld",      "decision",  "no witness binding entry: witness assurance WITHHELD"),
    ("CLS-OB4",  "OB4",  "class", "withheld",      "effect",    "Effect declares independent; referenced Execution cannot earn the class, so observer is unknown"),
    ("CLS-LEX1", "LEX1", "class", "failure",       "decision",  "witness claim length written 1e0: the semantic JSON value alone is insufficient"),
    ("PROC-UNP", "PRB-REQUEST-UNPARSEABLE",   "probe", "indeterminate", "n/a", "request is not parseable: run-invalid, no verdict is emitted"),
    ("PROC-NGR", "PRB-CLI-NOW-NOT-GREGORIAN", "probe", "indeterminate", "n/a", "operator clock input is format-valid but not a Gregorian date: usage error"),
]
VECTORS = ["V1", "V2", "V3", "V4", "W1", "W2"]


def main() -> int:
    # Rebuild only the GENERATED subtrees. An earlier version wiped the whole package
    # directory, which silently deleted the hand-authored documents on every re-run.
    for gen in ["cases", "bytes", "normative_basis", "expected", "manifests"]:
        if (OUT / gen).exists():
            subprocess.run(["rm", "-rf", str(OUT / gen)], check=True)
    OUT.mkdir(parents=True, exist_ok=True)

    src_digests: dict[str, str] = {}

    def copy_pinned(src_rel: str, dst_rel: str) -> str:
        data = git_show(f"{SRC}/{src_rel}")
        d = sha256(data)
        src_digests[f"{SRC}/{src_rel}"] = d
        write(dst_rel, data)
        return d

    # normative basis (specification text + schemas only; never KEYS.md)
    copy_pinned("INTEGRITY.md", "normative_basis/INTEGRITY.md")
    copy_pinned("class-verification/CLASS_VERIFIER_CONTRACT.md",
                "normative_basis/CLASS_VERIFIER_CONTRACT.md")
    for s in ["common", "decision", "control", "execution", "effect"]:
        copy_pinned(f"schemas/{s}.schema.json",
                    f"normative_basis/schemas/{s}.schema.json")

    # vectors: frozen byte material, plus package-derived raw .bin forms
    # Digest-record every pinned source CONSULTED, not only those copied verbatim. An
    # earlier version recorded only copied files, so the vector sources and the probe index
    # were read but never pinned - the README's per-file-digest claim outran the manifest.
    for consulted in ["vectors/out/python_vectors.json", "vectors/out/node_vectors.json",
                      "class-verification/corpus/probes/probe_index.json"]:
        src_digests[f"{SRC}/{consulted}"] = sha256(git_show(f"{SRC}/{consulted}"))

    vecs = json.loads(git_show(f"{SRC}/vectors/out/python_vectors.json"))["vectors"]
    node_vecs = json.loads(git_show(f"{SRC}/vectors/out/node_vectors.json"))["vectors"]
    vector_rows = []
    for vid in VECTORS:
        v, nv = vecs[vid], node_vecs[vid]
        if v != nv:
            raise SystemExit(f"FINDING: released Python and Node vectors disagree for {vid}")
        base = f"bytes/vectors/{vid}"
        derived = []
        for field, name in [("jcs_body_hex", "jcs_body"),
                            ("hash_tag_hex", "hash_tag"),
                            ("hash_preimage_hex", "hash_preimage"),
                            ("sig_tag_hex", "sig_tag"),
                            ("suite_id_hex", "suite_id"),
                            ("sig_preimage_hex", "sig_preimage"),
                            ("signature_hex", "signature"),
                            ("producer_pubkey_hex", "producer_pubkey")]:
            if field in v:
                raw = bytes.fromhex(v[field])
                write(f"{base}/{name}.bin", raw)
                write(f"{base}/{name}.hex", (v[field] + "\n").encode())
                derived.append(name)
        write_json(f"{base}/vector.json", {
            "vector_id": vid,
            "provenance_kind": "frozen_release_vector",
            "source_path": f"{SRC}/vectors/out/python_vectors.json",
            "agreement": "python_vectors.json and node_vectors.json are byte-identical at the pin",
            "frozen_fields": v,
            "package_derived_files": {
                "kind": "package_derived",
                "derivation": "bytes.fromhex() of the frozen *_hex field; no recomputation",
                "files": sorted(derived),
            },
        })
        vector_rows.append(vid)

    # cases
    index = []
    for pkg_id, src_id, kind, category, family, why in CASES:
        if kind == "class":
            sdir = f"class-verification/corpus/cases/{src_id}"
        else:
            sdir = f"class-verification/corpus/probes/{src_id}"
        listing = subprocess.run(
            ["git", "ls-tree", "-r", "--name-only", PIN, "--", f"{SRC}/{sdir}/"],
            cwd=REPO, capture_output=True, text=True).stdout.split()
        files = []
        expected = None
        for f in listing:
            name = f.rsplit("/", 1)[1]
            d = copy_pinned(f.split(f"{SRC}/", 1)[1], f"cases/{pkg_id}/{name}")
            files.append({"name": name, "sha256": d})
            if name == "expected.json":
                expected = json.loads(git_show(f))
        index.append({
            "package_case_id": pkg_id,
            "source_case_id": src_id,
            "source_kind": kind,
            "source_path": f"{SRC}/{sdir}",
            "category": category,
            "artifact_family": family,
            "why_not_redundant": why,
            "files": sorted(files, key=lambda x: x["name"]),
            "expected_provenance_kind": (
                "frozen_release_expected_result" if expected else "none_frozen_release_declares_process_outcome_only"),
        })
    write_json("CASE_INDEX.json", {
        "package": "AIREP v0.2 Independent-Verifier Corpus v0.1",
        "cases": index,
        "vectors": vector_rows,
    })
    write_json("PUBLIC_KEYS.json", {
        "note": "TEST-ONLY keys. Public halves only. Private seeds are published in the source "
                "repository but are deliberately excluded here and denied by the leak scanner.",
        "suite": "ed25519",
        "keys": PUBLIC_KEYS,
    })
    write_json("SOURCE_BASIS.json", {
        "source_repository": "https://github.com/halvrenofviryel/ai-runtime-evidence-protocol",
        "source_tag": TAG,
        "annotated_tag_object_sha": TAG_OBJ,
        "target_commit_sha": PIN,
        "zenodo_version_doi": DOI,
        "wire_version": WIRE,
        "tag_signature": "none — the tag is unsigned",
        "identity_statement": (
            "The source content is pinned by the resolved commit SHA and per-file digests. "
            "The unsigned tag does not cryptographically authenticate the author or maintainer "
            "identity."),
        "main_may_have_advanced": (
            "main may have advanced after this source basis; no byte in this package was taken "
            "from main."),
        "source_file_digests": dict(sorted(src_digests.items())),
    })
    print(f"cases: {len(index)}  vectors: {len(vector_rows)}  "
          f"pinned source files copied: {len(src_digests)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
