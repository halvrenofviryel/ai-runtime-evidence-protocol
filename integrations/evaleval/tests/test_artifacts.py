"""Integrity and semantic-boundary checks for committed study artifacts."""

from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[3]
STUDY = ROOT / "integrations" / "evaleval"
EXPERIMENT = STUDY / "experiment"


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


class StudyArtifactTests(unittest.TestCase):
    def test_crosswalk_rows_are_complete_and_summary_matches(self):
        crosswalk = read_json(STUDY / "CROSSWALK.json")
        required = {
            "eee", "airep", "mapping_class", "safe_directions", "value_source",
            "requires_new_assertion", "loss_eee_to_airep", "loss_airep_to_eee",
            "claim_risk", "sources",
        }
        counts = Counter()
        for row in crosswalk["rows"]:
            self.assertFalse(required - row.keys(), row["id"])
            self.assertIn(row["mapping_class"], crosswalk["classes"])
            counts[row["mapping_class"]] += 1
        self.assertGreaterEqual(len(crosswalk["rows"]), 30)
        self.assertEqual(dict(counts), {k: v for k, v in crosswalk["summary"].items() if k != "total"})
        self.assertEqual(sum(counts.values()), crosswalk["summary"]["total"])

    def test_native_manifest_matches_exact_bytes(self):
        native = EXPERIMENT / "native"
        manifest = read_json(native / "native-manifest.json")
        for item in manifest["files"]:
            path = native / item["path"]
            self.assertTrue(path.is_file(), item["path"])
            self.assertEqual(path.stat().st_size, item["bytes"], item["path"])
            self.assertEqual(sha256(path), item["sha256"], item["path"])

    def test_two_representations_share_source_observation_without_verdict_laundering(self):
        eee_paths = list((EXPERIMENT / "out" / "eee" / "data").rglob("*.json"))
        self.assertEqual(len(eee_paths), 1)
        eee = read_json(eee_paths[0])
        airep = read_json(EXPERIMENT / "out" / "airep" / "embedded-evaluation.profile.json")
        eee_result = eee["evaluation_results"][0]
        self.assertEqual(eee_result["score_details"]["score"], 0.0)
        self.assertEqual(airep["measurement"]["observed"]["metric_value"], 0.0)
        self.assertNotIn("PASS", json.dumps(eee_result))
        self.assertEqual(airep["measurement"]["observed"]["status"], "INCONCLUSIVE")
        self.assertNotIn("threshold", airep["measurement"]["criterion"])

    def test_relationship_never_becomes_independence(self):
        eee_paths = list((EXPERIMENT / "out" / "eee" / "data").rglob("*.json"))
        eee = read_json(eee_paths[0])
        airep = read_json(EXPERIMENT / "out" / "airep" / "embedded-evaluation.profile.json")
        self.assertEqual(eee["source_metadata"]["evaluator_relationship"], "third_party")
        self.assertEqual(airep["engagement"]["independence"]["status"], "unknown")
        self.assertFalse(airep["engagement"]["independence"]["conflicts_disclosed"])

    def test_validation_reports_have_bounded_meanings(self):
        eee_report = read_json(EXPERIMENT / "out" / "eee" / "validation-report.json")
        airep_report = read_json(EXPERIMENT / "out" / "airep" / "validation-report.json")
        manifest = read_json(EXPERIMENT / "out" / "airep" / "evidence-manifest.json")
        self.assertTrue(eee_report["passed"])
        self.assertIn("does not establish", eee_report["meaning"])
        self.assertTrue(airep_report["schema_valid"])
        self.assertIn("only", airep_report["meaning"])
        nonclaims = " ".join(manifest["claims"]["does_not_establish"]).lower()
        for phrase in ("independence", "truth", "completeness", "reproducibility", "safety"):
            self.assertIn(phrase, nonclaims)

    def test_airep_evidence_digests_are_recomputed_native_bytes(self):
        native_manifest = read_json(EXPERIMENT / "native" / "native-manifest.json")
        airep_manifest = read_json(EXPERIMENT / "out" / "airep" / "evidence-manifest.json")
        native = {item["role"]: "sha256:" + item["sha256"] for item in native_manifest["files"]}
        for item in airep_manifest["inputs"]:
            self.assertEqual(item["sha256"], native[item["role"]])
        profile = read_json(EXPERIMENT / "out" / "airep" / "embedded-evaluation.profile.json")
        self.assertTrue(all(not item["resolvable"] for item in profile["evidence"]))
        self.assertTrue(all(item["visibility"] == "restricted" for item in profile["evidence"]))


if __name__ == "__main__":
    unittest.main()
