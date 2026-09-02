#!/usr/bin/env python3
"""Build the handoff archive deterministically. INTERNAL TOOLING.

A zip built with the obvious recipe is not reproducible: entry order follows directory
iteration, and every entry carries the file's mtime and host permission bits. Two builds
of byte-identical content therefore produce two different archive digests, so an archive
digest cannot be used as an identity claim — which is exactly what a recipient is asked
to check against `corpus_digest`.

This builder removes every source of variation:

  * entries sorted by path, so order is content-determined;
  * a fixed timestamp for every entry, so build time does not leak in;
  * fixed permission bits, so the builder's umask does not leak in;
  * ZIP_DEFLATED at a fixed level, so compressor settings do not leak in;
  * no directory entries, so a directory's own mtime cannot vary the output.

Content is copied byte-for-byte from the package tree. This tool never edits a package
file, so it cannot change corpus bytes, expected results, prompts or digests.
"""
from __future__ import annotations

import argparse
from revision import TOP_LEVEL  # noqa: E402
import hashlib
import pathlib
import zipfile

# Any fixed value works; this one is the DOS epoch floor zip can represent.
FIXED_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
FIXED_MODE = 0o644 << 16
COMPRESS_LEVEL = 9


def build(package_dir: pathlib.Path, out: pathlib.Path, top_level: str) -> str:
    files = sorted(p for p in package_dir.rglob("*") if p.is_file())
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(out.suffix + ".tmp")
    with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED,
                         compresslevel=COMPRESS_LEVEL) as zf:
        for f in files:
            arcname = f"{top_level}/{f.relative_to(package_dir).as_posix()}"
            info = zipfile.ZipInfo(arcname, date_time=FIXED_TIMESTAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = FIXED_MODE
            info.create_system = 3  # unix, fixed
            zf.writestr(info, f.read_bytes())
    tmp.replace(out)
    return hashlib.sha256(out.read_bytes()).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--package", required=True, type=pathlib.Path)
    ap.add_argument("--out", required=True, type=pathlib.Path)
    ap.add_argument("--top-level", default=TOP_LEVEL)
    args = ap.parse_args()
    digest = build(args.package, args.out, args.top_level)
    print(f"{digest}  {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
