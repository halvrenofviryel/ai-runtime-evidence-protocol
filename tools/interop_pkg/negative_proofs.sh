#!/usr/bin/env bash
# Six negative proofs for verify_package.py. INTERNAL. Performs NO AIREP semantic verification.
set -u
SRC="$(cd "$(dirname "$0")/../../interop/independent-verifier-corpus/v0.1" && pwd)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
run() {  # name, mutation
  local name="$1"; shift
  rm -rf "$TMP/p"; cp -r "$SRC" "$TMP/p"
  ( cd "$TMP/p" && eval "$@" ) >/dev/null 2>&1
  local out; out="$(cd "$TMP/p" && python3 tools/verify_package.py 2>&1)"; local rc=$?
  printf '%-34s exit=%d  %s\n' "$name" "$rc" "$(echo "$out" | head -2 | tail -1 | sed 's/^  - //' | cut -c1-72)"
  [ "$rc" -ne 0 ] || echo "    *** NEGATIVE PROOF FAILED: expected non-zero exit ***"
}
echo "=== negative proofs (each MUST exit non-zero) ==="
run "1 case file modified"        "printf 'x' >> cases/CLS-P1/request.json"
run "2 required file removed"     "rm -f cases/CLS-P1/bindings.json"
run "3 unexpected file injected"  "printf 'stray' > cases/CLS-P1/EXTRA.txt"
run "4 manifest digest altered"   "python3 - <<'PY'
import json,pathlib
p=pathlib.Path('manifests/FILES.json'); d=json.loads(p.read_text())
d['files'][0]['sha256']='0'*64
p.write_text(json.dumps(d,indent=2,sort_keys=True))
PY"
# 5 and 6 also REBUILD the manifest digest for the file they touch, so the digest check
# cannot fire first. Otherwise a passing proof would only show that the digest check works -
# it would not show that the identity check or the seed scanner works at all.
run "5 source-basis identity changed" "python3 - <<'PY'
import json,hashlib,pathlib
p=pathlib.Path('SOURCE_BASIS.json'); d=json.loads(p.read_text())
d['target_commit_sha']='0'*40
new=json.dumps(d,indent=2,sort_keys=True)+chr(10); p.write_text(new)
m=pathlib.Path('manifests/FILES.json'); md=json.loads(m.read_text())
for f in md['files']:
    if f['path']=='SOURCE_BASIS.json':
        f['sha256']=hashlib.sha256(new.encode()).hexdigest(); f['size']=len(new.encode())
m.write_text(json.dumps(md,indent=2,sort_keys=True)+chr(10))
PY"
run "6 private seed introduced"   "python3 - <<'PY'
import json,hashlib,pathlib
seed='00112233'+'445566778899aabbccddeeff'+'00112233445566778899aabbccddeeff'
p=pathlib.Path('LICENSES/NOTICE.txt')
new=p.read_text()+'leaked: '+seed+chr(10); p.write_text(new)
m=pathlib.Path('manifests/FILES.json'); md=json.loads(m.read_text())
for f in md['files']:
    if f['path']=='LICENSES/NOTICE.txt':
        f['sha256']=hashlib.sha256(new.encode()).hexdigest(); f['size']=len(new.encode())
m.write_text(json.dumps(md,indent=2,sort_keys=True)+chr(10))
PY"
