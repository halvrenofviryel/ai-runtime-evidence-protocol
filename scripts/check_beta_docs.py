#!/usr/bin/env python3
"""Release audit: local reading-path links, versions and frozen-byte preservation."""
import hashlib
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
V02 = ROOT/'spec/airep/v0.2'


def main():
    failures=[]
    docs=[ROOT/'README.md', ROOT/'CHANGELOG.md', ROOT/'examples/v02/README.md',
          ROOT/'tools/airep_v02/README.md', *[V02/name for name in (
              'SPEC.md','QUICKSTART.md','VERIFICATION.md','RECONCILIATION.md',
              'RELEASE_STAGES.md','BETA_READINESS.md','RELEASE_NOTES_BETA_1.md','RELEASE_READINESS.md')]]
    for doc in docs:
        if not doc.is_file():
            failures.append('missing document: '+str(doc.relative_to(ROOT))); continue
        for target in re.findall(r'\]\(([^)]+)\)',doc.read_text()):
            if '://' in target or target.startswith('#') or target.startswith('../../labels/'):
                continue
            target=target.split('#')[0]
            if target and not (doc.parent/target).exists():
                failures.append(f'broken link: {doc.relative_to(ROOT)} -> {target}')
    manifest=ROOT/'reports/beta-2026-09-08/initial-files.sha256'
    preserved=0
    for line in manifest.read_text().splitlines():
        expected,name=line.split('  ',1)
        frozen=(name.startswith(('spec/airep/v0.1/','producers/','external-evidence/',
                  'interop/independent-verifier-corpus/','spec/airep/v0.2/schemas/',
                  'spec/airep/v0.2/vectors/','spec/airep/v0.2/stage4/',
                  'spec/airep/v0.2/schema-validation/','spec/airep/v0.2/class-verification/'))
                or name in ('EXTERNAL_EVIDENCE.md','spec/airep/v0.2/INTEGRITY.md',
                            'spec/airep/v0.2/CONFORMANCE_CLASSES.md'))
        if name in ('spec/airep/v0.2/class-verification/STATUS.md','spec/airep/v0.2/class-verification/REVISIONS.md'):
            frozen=False
        if frozen:
            p=ROOT/name
            if not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest()!=expected:
                failures.append('frozen-byte drift: '+name)
            preserved+=1
    if 'v0.2.0-beta.1' not in (ROOT/'README.md').read_text(): failures.append('README target missing')
    if 'version: "0.2.0-beta.1"' not in (ROOT/'CITATION.cff').read_text(): failures.append('citation version missing')
    for f in (ROOT/'examples/v02/fixtures').glob('*.json'):
        import json
        for a in json.loads(f.read_text()):
            if a.get('airep_version')!='0.2': failures.append('wire version drift: '+str(f))
    for failure in failures: print('FAIL:',failure)
    print(f'Checked {len(docs)} reading-path documents; {preserved} preserved historical files; {len(failures)} failures.')
    return bool(failures)


if __name__=='__main__':
    sys.exit(main())
