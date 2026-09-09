"""Load the preserved reference implementation by repository-relative path."""
import importlib.util
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
V02 = ROOT / 'spec/airep/v0.2'
SCHEMAS = str(V02 / 'schemas')
CV = V02 / 'class-verification'
_spec = importlib.util.spec_from_file_location('airep_historical_class_verifier', CV / 'verifier_py/class_verifier.py')
verifier = importlib.util.module_from_spec(_spec)
old = sys.dont_write_bytecode
sys.dont_write_bytecode = True
try:
    _spec.loader.exec_module(verifier)
finally:
    sys.dont_write_bytecode = old
