#!/usr/bin/env python3
"""Python engine runner (VALIDATION_CONTRACT s1/s3): jsonschema Draft202012Validator,
local registry, format NOT asserted. Emits normalized violation tuples
{instance_path, keyword} with JSON-Pointer paths; keyword source = error.validator.
Deterministic: sorted keys, trailing newline, no metadata. Exit 0 iff every corpus fixture
received a result; verdicts are data.
"""
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

HERE = Path(__file__).resolve().parent
SCHEMAS = HERE.parent / "schemas"
CORPUS = HERE / "corpus"
OUT = HERE / "results" / "results_python_schema.json"


def pointer(parts) -> str:
    return "".join("/" + str(p).replace("~", "~0").replace("/", "~1") for p in parts)


def main() -> int:
    docs = {n: json.loads((SCHEMAS / f"{n}.schema.json").read_text())
            for n in ("common", "decision", "control", "execution", "effect")}
    registry = Registry()
    for d in docs.values():
        registry = Resource.from_contents(d) @ registry
    validators = {f: Draft202012Validator(docs[f], registry=registry)
                  for f in ("decision", "control", "execution", "effect")}

    results = {}
    for p in sorted(CORPUS.glob("*.json")):
        fx = json.loads(p.read_text())
        v = validators[fx["target_schema"]]
        errors = list(v.iter_errors(fx["instance"]))
        violations = sorted({(pointer(e.absolute_path), e.validator) for e in errors})
        results[fx["fixture_id"]] = {
            "schema": fx["target_schema"],
            "expected": fx["expected"],
            "actual": "VALID" if not errors else "INVALID",
            "violations": [{"instance_path": a, "keyword": b} for a, b in violations],
        }

    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps({"results": results}, sort_keys=True, ensure_ascii=False, indent=1) + "\n",
                   encoding="utf-8")
    print(f"python engine: {len(results)} fixtures evaluated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
