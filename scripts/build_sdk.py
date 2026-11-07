#!/usr/bin/env python3
"""Stage an explicit resource closure, then build a standalone wheel and sdist.

No generated native copy is maintained in the SDK source tree. Every copied
file is recorded with its repository path and SHA-256. No registry publication.
"""
import argparse
import hashlib
import json
import importlib.metadata
import platform
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def build(out, allow_dirty=False):
    status = subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True)
    if status and not allow_dirty:
        raise ValueError('commit the SDK source first, or explicitly use --allow-dirty for development')
    out.mkdir(parents=True, exist_ok=False)
    stage = out / 'source'
    shutil.copytree(ROOT / 'sdk/python', stage, ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '*.egg-info'))
    package = stage / 'src/airep'
    entries = []

    def copy(source, target, license_name):
        original = ROOT / source
        if original.is_symlink() or not original.resolve().is_relative_to(ROOT.resolve()):
            raise ValueError('unsafe package resource')
        raw = original.read_bytes()
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError('package resource exceeds 2 MiB')
        dest = package / target
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(raw)
        entries.append({'repository_path': source, 'package_path': target,
                        'sha256': hashlib.sha256(raw).hexdigest(), 'license': license_name})

    for path in sorted((ROOT / 'sdk/python/src/airep').rglob('*')):
        if path.is_file() and '__pycache__' not in path.parts:
            copy(str(path.relative_to(ROOT)), str(path.relative_to(ROOT / 'sdk/python/src/airep')), 'Apache-2.0')
    for name in ('producer', 'verify', 'reconcile', 'explain', 'profiles', 'json_input'):
        copy(f'tools/airep_v02/{name}.py', f'_native/{name}.py', 'Apache-2.0')
    resource_paths = ['spec/airep/v0.1/conformance/jcs.py',
        'spec/airep/v0.2/class-verification/verifier_py/class_verifier.py',
        'spec/airep/v0.2/SPEC.md', 'spec/airep/v0.2/INTEGRITY.md',
        'spec/airep/v0.2/RECONCILIATION.md', 'spec/airep/v0.2/JSON_INPUT_ADMISSIBILITY.md',
        'spec/airep/v0.2/CONFORMANCE_CLASSES.md',
        'spec/airep/v0.2/class-verification/contract-r3/CLASS_VERIFIER_CONTRACT_R3.md']
    resource_paths += [str(p.relative_to(ROOT)) for p in sorted((ROOT / 'spec/airep/v0.2/schemas').glob('*.json'))]
    resource_paths += ['spec/airep/v0.2/profiles/embedded-evaluation/registry.json',
                       'spec/airep/v0.2/profiles/embedded-evaluation/embedded-evaluation.schema.json']
    for name in resource_paths:
        copy(name, '_basis/' + name, 'CC-BY-4.0' if name.endswith(('.md', '.schema.json')) else 'Apache-2.0')
    for name in ('LICENSE', 'LICENSE-CC-BY-4.0.txt'):
        copy(name, name, 'License text')
        shutil.copy2(ROOT / name, stage / name)
    copy('integrations/langgraph/requirements.lock', 'requirements.lock', 'Apache-2.0')
    manifest = {'format': 'airep-sdk-source-v1',
        'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        'dirty_development_build': bool(status), 'native_version': '0.2.0-beta.1',
        'files': sorted(entries, key=lambda row: row['package_path'])}
    (package / 'SOURCE_MANIFEST.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    (stage / 'MANIFEST.in').write_text('recursive-include src/airep *\ninclude LICENSE LICENSE-CC-BY-4.0.txt\n')
    dist = out / 'dist'
    subprocess.run([sys.executable, '-m', 'build', '--no-isolation', '--outdir', str(dist), str(stage)], check=True)
    wheel = next(dist.glob('*.whl'))
    with zipfile.ZipFile(wheel) as z:
        if sum(i.file_size for i in z.infolist()) > 5 * 1024 * 1024:
            raise ValueError('wheel expanded content exceeds 5 MiB')
        for row in entries:
            assert hashlib.sha256(z.read('airep/' + row['package_path'])).hexdigest() == row['sha256']
        assert not any(n.startswith(('tools/', 'spec/', 'integrations/')) for n in z.namelist())
    result = {'source_commit': manifest['source_commit'], 'dirty': bool(status),
              'build_environment': {'python': platform.python_version(), **{name: importlib.metadata.version(name) for name in ('build', 'setuptools', 'wheel')}},
              'artifacts': {p.name: {'sha256': hashlib.sha256(p.read_bytes()).hexdigest(), 'bytes': p.stat().st_size}
                            for p in sorted(dist.iterdir()) if p.is_file()},
              'resource_count': len(entries)}
    (out / 'BUILD_RECORD.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--allow-dirty', action='store_true')
    args = parser.parse_args()
    build(args.out.resolve(), args.allow_dirty)
