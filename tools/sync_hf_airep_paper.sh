#!/usr/bin/env bash
set -euo pipefail

ARXIV_ID="2608.21363"
API_BASE="https://huggingface.co/api/papers"
OUTPUT_DIR="${OUTPUT_DIR:-$PWD}"
BEFORE="${OUTPUT_DIR}/hf-paper-before.json"
AFTER="${OUTPUT_DIR}/hf-paper-after.json"
REPORT="${OUTPUT_DIR}/hf-paper-sync-report.json"
LINK_PAYLOAD="${OUTPUT_DIR}/hf-paper-links-request.json"
APPLY_LINKS=0
AIREP_HF_TOKEN="${HF_TOKEN:-${HUGGINGFACE_HUB_TOKEN:-}}"

usage() {
  echo "Usage: $0 [--apply-links]" >&2
  echo >&2
  echo "Without --apply-links, the script snapshots metadata, optionally re-indexes when" >&2
  echo "HF_TOKEN or HUGGINGFACE_HUB_TOKEN is present, and prepares the link payload only." >&2
  echo "--apply-links is the explicit authorization gate for the paper-links write." >&2
}

while (($#)); do
  case "$1" in
    --apply-links) APPLY_LINKS=1 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
  shift
done

mkdir -p "$OUTPUT_DIR"

AUTH_ARGS=()
if [[ -n "$AIREP_HF_TOKEN" ]]; then
  AUTH_ARGS=(--header "Authorization: Bearer ${AIREP_HF_TOKEN}")
fi

echo "Fetching current Hugging Face paper metadata..."
curl -fsSL "${AUTH_ARGS[@]}" "${API_BASE}/${ARXIV_ID}" -o "$BEFORE"

if [[ -n "$AIREP_HF_TOKEN" ]]; then
  echo "A Hugging Face token is present; sending one author re-index request."
  curl -fsS "${API_BASE}/index" \
    --request POST \
    --header "Content-Type: application/json" \
    --header "Authorization: Bearer ${AIREP_HF_TOKEN}" \
    --data "{\"arxivId\":\"${ARXIV_ID}\"}"
  echo
else
  echo "Neither HF_TOKEN nor HUGGINGFACE_HUB_TOKEN is present; skipping the author re-index request."
fi

echo "Fetching post-check Hugging Face paper metadata..."
curl -fsSL "${AUTH_ARGS[@]}" "${API_BASE}/${ARXIV_ID}" -o "$AFTER"

python3 - "$BEFORE" "$AFTER" "$REPORT" "$ARXIV_ID" <<'PY'
import json
import sys
from pathlib import Path

before_path, after_path, report_path, arxiv_id = sys.argv[1:]
before = json.loads(Path(before_path).read_text(encoding="utf-8"))
after = json.loads(Path(after_path).read_text(encoding="utf-8"))

def first_text(record, keys):
    for key in keys:
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""

def author_identity(record):
    result = []
    for author in record.get("authors") or []:
        user = author.get("user") if isinstance(author, dict) else None
        user = user if isinstance(user, dict) else {}
        result.append({
            "name": author.get("name"),
            "status": author.get("status"),
            "user_id": user.get("_id"),
            "username": user.get("user") or user.get("name"),
        })
    return result

def resource_identity(record):
    resources = {}
    for key in ("linkedModels", "linkedDatasets", "linkedSpaces"):
        values = record.get(key) or []
        resources[key] = sorted(
            str(item.get("id") or item.get("_id") or item)
            for item in values
            if item is not None
        )
    resources["githubRepo"] = record.get("githubRepo")
    resources["projectPage"] = record.get("projectPage")
    resources["organization"] = record.get("organization") or record.get("organizationId")
    return resources

def object_id(record):
    candidates = [
        record.get("_id"),
        record.get("paperId"),
        record.get("objectId"),
        (record.get("paper") or {}).get("_id") if isinstance(record.get("paper"), dict) else None,
        (record.get("paper") or {}).get("id") if isinstance(record.get("paper"), dict) else None,
    ]
    plain_id = record.get("id")
    if isinstance(plain_id, str) and plain_id != arxiv_id:
        candidates.append(plain_id)
    return next((value for value in candidates if isinstance(value, str) and value), None)

before_summary = first_text(before, ("summary", "abstract"))
after_summary = first_text(after, ("summary", "abstract"))
summary_lower = after_summary.lower()
v2_markers = {
    name: name.lower() in summary_lower
    for name in ("Decision", "Control", "Execution", "Effect")
}

revision_keys = (
    "version", "revision", "revisedAt", "updatedAt", "lastUpdatedAt",
    "submittedAt", "publishedAt",
)
before_revision = {key: before.get(key) for key in revision_keys if key in before}
after_revision = {key: after.get(key) for key in revision_keys if key in after}
before_resources = resource_identity(before)
after_resources = resource_identity(after)

resources_preserved = all(
    set(before_resources[key]).issubset(set(after_resources[key]))
    for key in ("linkedModels", "linkedDatasets", "linkedSpaces")
) and all(
    before_resources[key] in (None, after_resources[key])
    for key in ("githubRepo", "projectPage", "organization")
)

report = {
    "arxivId": arxiv_id,
    "summaryChanged": before_summary != after_summary,
    "summaryHasV2LifecycleMarkers": all(v2_markers.values()),
    "summaryV2Markers": v2_markers,
    "revisionMetadataChanged": before_revision != after_revision,
    "revisionMetadataBefore": before_revision,
    "revisionMetadataAfter": after_revision,
    "authorshipAssociationRemainedIntact": author_identity(before) == author_identity(after),
    "authorsBefore": author_identity(before),
    "authorsAfter": author_identity(after),
    "existingHfResourcesRemainedAssociated": resources_preserved,
    "resourcesBefore": before_resources,
    "resourcesAfter": after_resources,
    "paperObjectId": object_id(after),
}

Path(report_path).write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print(json.dumps(report, indent=2, ensure_ascii=False))
PY

python3 - "$LINK_PAYLOAD" <<'PY'
import json
import sys
from pathlib import Path

payload = {
    "projectPage": "https://phionyx.ai/airep",
    "githubRepo": "https://github.com/halvrenofviryel/ai-runtime-evidence-protocol",
}
Path(sys.argv[1]).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
PY

PAPER_OBJECT_ID="$(python3 - "$REPORT" <<'PY'
import json
import sys
from pathlib import Path

value = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")).get("paperObjectId")
print(value or "")
PY
)"

if ((APPLY_LINKS)); then
  if [[ -z "$AIREP_HF_TOKEN" ]]; then
    echo "Cannot apply links: --apply-links requires HF_TOKEN or HUGGINGFACE_HUB_TOKEN." >&2
    exit 1
  fi
  if [[ -z "$PAPER_OBJECT_ID" ]]; then
    echo "Cannot apply links: the structured paper record did not expose a Hugging Face paper object id." >&2
    exit 1
  fi
  echo "Explicit --apply-links authorization received; updating paper links."
  curl -fsS "${API_BASE}/${PAPER_OBJECT_ID}/links" \
    --request POST \
    --header "Content-Type: application/json" \
    --header "Authorization: Bearer ${AIREP_HF_TOKEN}" \
    --data-binary "@${LINK_PAYLOAD}"
  echo
else
  echo "Prepared link payload at ${LINK_PAYLOAD}; no link update was sent."
  if [[ -n "$PAPER_OBJECT_ID" ]]; then
    echo "Prepared endpoint: ${API_BASE}/${PAPER_OBJECT_ID}/links"
  else
    echo "The structured record did not expose a distinct paper object id; resolve it before using --apply-links."
  fi
fi
