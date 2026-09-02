#!/usr/bin/env python3
"""Corpus revision identity for the interop package builders. INTERNAL TOOLING.

A published revision is never rewritten in place. The builders emit into the revision
named by AIREP_INTEROP_REVISION, so producing a corrected expectation means producing
the NEXT revision, leaving the published one and its digest byte-identical.

Two version numbers are in play and are deliberately distinct:

  * the AIREP protocol version the corpus is about -- v0.2, fixed in the names below;
  * the corpus revision -- v0.1 published and handed off, v0.2 the corrected revision.
"""
import os
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CORPUS = REPO / "interop/independent-verifier-corpus"
REVISION = os.environ.get("AIREP_INTEROP_REVISION", "v0.2")
OUT = CORPUS / REVISION

PACKAGE_NAME = "AIREP v0.2 Independent-Verifier Corpus %s" % REVISION
TOP_LEVEL = "airep-v0.2-independent-verifier-corpus-%s" % REVISION
ARCHIVE_NAME = "%s-full.zip" % TOP_LEVEL
