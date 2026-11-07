"""Check saved source bytes and native/consumer views; no fresh runtime capture."""
import argparse,hashlib,importlib,json,sys
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('module',choices=['durable','boundaries','multitarget'])
a=p.parse_args()
root=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(root))
directory=root/'integrations/langgraph'/a.module/'evidence/2026-11-07'
manifest=json.loads((directory/'MANIFEST.json').read_text())
for entry in manifest['evidence']:
    assert hashlib.sha256((directory/entry['path']).read_bytes()).hexdigest()==entry['sha256'],entry['path']
for entry in manifest['implementation']:
    assert hashlib.sha256((root/entry['path']).read_bytes()).hexdigest()==entry['sha256'],entry['path']
module=importlib.import_module('integrations.langgraph.'+a.module+'.report')
actual=module.replay(json.loads((directory/'inputs.json').read_text()))
expected=json.loads((directory/'report.json').read_text())['views']
assert actual==expected,'parsed native/consumer views differ'
assert len(actual)==manifest['view_count']
print(json.dumps({'module':a.module,'views':len(actual),'exact_parsed_views':True,'fresh_runtime_captures':0,'measured_commit':manifest['measured_commit']}))
