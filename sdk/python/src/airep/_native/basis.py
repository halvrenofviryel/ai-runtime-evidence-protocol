"""Resource loader adapter; the copied reference verifier/JCS remain unchanged."""
import hashlib
import importlib.resources
import importlib.util
import json
from pathlib import Path
import sys

PACKAGE = Path(str(importlib.resources.files('airep')))
ROOT = PACKAGE / '_basis'
V02 = ROOT / 'spec/airep/v0.2'
SCHEMAS = str(V02 / 'schemas')
CV = V02 / 'class-verification'
MANIFEST = json.loads((PACKAGE / 'SOURCE_MANIFEST.json').read_bytes())
for item in MANIFEST['files']:
    path = PACKAGE / item['package_path']
    if path.is_symlink() or not path.resolve().is_relative_to(PACKAGE.resolve()):
        raise ImportError('SDK resource escapes installed package')
    if hashlib.sha256(path.read_bytes()).hexdigest() != item['sha256']:
        raise ImportError('SDK resource integrity mismatch: ' + item['package_path'])

_spec = importlib.util.spec_from_file_location('airep_packaged_class_verifier', CV / 'verifier_py/class_verifier.py')
verifier = importlib.util.module_from_spec(_spec)
old = sys.dont_write_bytecode
sys.dont_write_bytecode = True
try:
    _spec.loader.exec_module(verifier)
finally:
    sys.dont_write_bytecode = old
