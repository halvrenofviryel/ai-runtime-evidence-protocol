"""Closed reason registry and legal value sets, transcribed from
CLASS_VERIFIER_CONTRACT.md sections 2 and 5.

Transcribed from the CONTRACT ONLY. No verifier source was consulted to build
this table; sharing a table with an implementation would make agreement an
artifact of shared code rather than a measurement.
"""

# (reason, tier, kind) -- contract section 5, 31 rows, in contract order.
REASON_REGISTRY = {
    "producer-binding-missing":            ("authenticated", "WITHHELD"),
    "producer-binding-not-trusted":        ("authenticated", "FAILURE"),
    "producer-binding-malformed":          ("authenticated", "WITHHELD"),
    "producer-suite-unsupported":          ("authenticated", "WITHHELD"),
    "producer-revocation-state-missing":   ("authenticated", "WITHHELD"),
    "producer-revocation-state-malformed": ("authenticated", "WITHHELD"),
    "producer-binding-revoked":            ("authenticated", "FAILURE"),
    "producer-signature-invalid":          ("authenticated", "FAILURE"),
    "producer-key-self-revoked":           ("authenticated", "CAVEAT"),
    "wire-alg-mismatch":                   ("authenticated", "CAVEAT"),
    "no-witness-supplied":                 ("witnessed", "WITHHELD"),
    "witness-binding-missing":             ("witnessed", "WITHHELD"),
    "witness-binding-not-trusted":         ("witnessed", "FAILURE"),
    "witness-binding-malformed":           ("witnessed", "WITHHELD"),
    "witness-suite-unsupported":           ("witnessed", "WITHHELD"),
    "witness-revocation-state-missing":    ("witnessed", "WITHHELD"),
    "witness-revocation-state-malformed":  ("witnessed", "WITHHELD"),
    "independence-policy-missing":         ("witnessed", "WITHHELD"),
    "independence-policy-malformed":       ("witnessed", "WITHHELD"),
    "independence-relation-absent":        ("witnessed", "WITHHELD"),
    "freshness-inputs-missing":            ("witnessed", "WITHHELD"),
    "witness-binding-revoked":             ("witnessed", "FAILURE"),
    "witness-head-unresolved":             ("witnessed", "FAILURE"),
    "witness-head-mismatch":               ("witnessed", "FAILURE"),
    "witness-claim-invalid":               ("witnessed", "FAILURE"),
    "witness-identity-not-distinct":       ("witnessed", "FAILURE"),
    "witness-key-not-distinct":            ("witnessed", "FAILURE"),
    "independence-explicitly-denied":      ("witnessed", "FAILURE"),
    "witness-signature-invalid":           ("witnessed", "FAILURE"),
    "witness-time-invalid":                ("witnessed", "FAILURE"),
    "witness-freshness-outside-window":    ("witnessed", "FAILURE"),
}

REGISTRY_SIZE = 31

# channel name -> (tier, kind) that channel may carry  (contract section 2 + 5)
CHANNELS = {
    "authenticated_failures": ("authenticated", "FAILURE"),
    "authenticated_withheld": ("authenticated", "WITHHELD"),
    "authenticated_caveats":  ("authenticated", "CAVEAT"),
    "witnessed_failures":     ("witnessed", "FAILURE"),
    "witnessed_withheld":     ("witnessed", "WITHHELD"),
}
CHANNEL_ORDER = [
    "authenticated_failures",
    "authenticated_withheld",
    "authenticated_caveats",
    "witnessed_failures",
    "witnessed_withheld",
]

LEGAL_CLASSES = ("AIREP-Core", "AIREP-Authenticated", "AIREP-Witnessed")
LEGAL_OBSERVER = ("same_executor", "independent", "unknown", "not_applicable")

VERDICT_MEMBERS = {
    "artifact_ref", "class",
    "authenticated_failures", "authenticated_withheld", "authenticated_caveats",
    "witnessed_failures", "witnessed_withheld",
    "observer_assessment", "evidence",
}
ARTIFACT_REF_MEMBERS = {"chain_id", "record_id"}
EVIDENCE_MEMBERS = {
    "now", "freshness_window_seconds",
    "bindings_digest", "independence_policy_digest", "revocation_digest",
}
