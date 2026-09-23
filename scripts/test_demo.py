#!/usr/bin/env python3
"""Regression tests for the demo's result-derived presentation semantics."""

from copy import deepcopy
from pathlib import Path
import unittest

from demo import DemoError, render_demo


def report(status="INCOMPLETE"):
    states = {
        "issuer_dispatch": "SATISFIED",
        "receiver_receipt": "SATISFIED",
        "execution_evidence": "SATISFIED",
        "toctou": "SATISFIED",
        "effect_binding": "SATISFIED",
        "intended_target_coverage": "NOT_EVALUATED",
    }
    return {
        "summary": {"status": status},
        "records": [
            {
                "artifact_ref": {"record_id": "demo.decision"},
                "class_result": {"class": "AIREP-Authenticated"},
            }
        ],
        "checks": [{"check": name, "state": state} for name, state in states.items()],
    }


class DemoRenderingTests(unittest.TestCase):
    def test_values_are_read_from_reconciler_outputs(self):
        complete = report("FAILURE")
        negative = deepcopy(complete)
        for check in negative["checks"]:
            if check["check"] == "receiver_receipt":
                check["state"] = "MISSING"
            elif check["check"] == "execution_evidence":
                check["state"] = "INDETERMINATE"
            elif check["check"] == "toctou":
                check["state"] = "NOT_EVALUATED"
        text = render_demo(
            complete,
            negative,
            {"class": "AIREP-Core", "observer_assessment": "unknown"},
            Path("/tmp/result"),
        )
        self.assertIn("Overall                   FAILURE", text)
        self.assertIn("Receiver receipt    MISSING", text)
        self.assertIn("Execution evidence  INDETERMINATE", text)
        self.assertIn("TOCTOU comparison   NOT_EVALUATED", text)
        self.assertIn("Class                AIREP-Core", text)

    def test_missing_required_check_is_an_infrastructure_error(self):
        complete = report()
        complete["checks"] = [
            check for check in complete["checks"] if check["check"] != "effect_binding"
        ]
        with self.assertRaisesRegex(DemoError, "effect_binding"):
            render_demo(
                complete,
                report(),
                {"class": "AIREP-Core", "observer_assessment": "unknown"},
                Path("/tmp/result"),
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
