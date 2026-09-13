#!/usr/bin/env python3
"""LightEval results → AIREP Embedded Evaluation Profile v0.1 exporter.

Non-normative integration. **Current parser: LightEval ``results_*.json``.** Inspect and
OpenEvals are related evaluation ecosystems discussed as future integration targets; native
Inspect ``.eval`` and arbitrary OpenEvals result formats are not parsed by this implementation.
It consumes the files LightEval wrote, hashes them, and produces:

* ``embedded-evaluation.profile.json`` — the ``profiles["airep.embedded-evaluation"]``
  payload (profile version 0.1, carrier AIREP 0.2), written only when it validates;
* ``evidence-manifest.json`` — every consumed input with its SHA-256 and evidence role;
* ``validation-report.json`` — the schema result against the digest-pinned basis.

What it never does:

* infer evaluator independence or access tier — both must be declared in the context file;
* reinterpret a Hugging Face ``verifyToken`` as anything but platform-specific verification
  evidence (``verification[].kind = "platform-verification"``, status ``NOT_EVALUATED``);
* manufacture an AIREP Decision/Control/Execution/Effect artifact — the native result files
  remain the source evidence, and the payload is context and evidence metadata around them;
* let a missing or contradictory measurement state become success;
* turn a timezone-naive LightEval filename date id into a UTC timestamp — the filename does not
  establish UTC, so ``started_at``/``ended_at`` must be declared with an explicit offset.

Usage:

    python3 export_embedded_evaluation.py --results results_2026-09-12T10-20-00.000000.json \
        --context context.json --out-dir out/ [--details details_*.parquet ...] \
        [--raw-output FILE ...] [--log FILE ...] [--profile-dir DIR]
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
DEFAULT_PROFILE_DIR = HERE.parents[1] / 'spec' / 'airep' / 'v0.2' / 'profiles' / 'embedded-evaluation'
PROFILE_ID = 'airep.embedded-evaluation'
PROFILE_VERSION = '0.1'
CARRIER_AIREP_VERSION = '0.2'
EXPORTER_NAME = 'airep-lighteval-exporter'
EXPORTER_VERSION = '0.1.1'

MEDIA_TYPES = {'.json': 'application/json', '.jsonl': 'application/x-ndjson',
               '.parquet': 'application/x-parquet', '.log': 'text/plain', '.txt': 'text/plain',
               '.yaml': 'application/yaml', '.yml': 'application/yaml'}
RESULTS_NAME = re.compile(r'results_(?P<date>\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}(?:\.\d{1,6})?)\.json$')
THRESHOLD = re.compile(r'^\s*(<=|>=|==|!=|<|>)\s*(-?\d+(?:\.\d+)?)\s*$')
EXECUTION_STATES = ('RAN', 'NOT_RUN', 'PARTIAL', 'INVALIDATED')
OBSERVED_STATES = ('PASS', 'FAIL', 'NOT_MEASURED', 'INCONCLUSIVE', 'ERROR', 'NOT_APPLICABLE')
CLAIMS = {
    'records_or_preserves': [
        'declared evaluator / engagement context',
        'declared target identity',
        'declared access context',
        'declared evaluation configuration (framework, tasks, environment, safeguards)',
        'declared measurement state and criterion',
    ],
    'establishes': [
        'SHA-256 digests of the exact evidence bytes supplied to this exporter',
        'whether the generated profile payload validates against the exact digest-pinned profile basis',
    ],
    'does_not_establish': [
        'evaluator independence or competence (declared in the context, never inferred)',
        'that the named model, revision or configuration was the one actually executed',
        'truth, representativeness, completeness or reproducibility of the observations',
        'model safety, alignment, security, regulatory conformity or deployment suitability',
        'any AIREP assurance class; the payload is a companion profile, not an artifact family',
        'validity of a platform verifyToken; it is preserved as evidence, not evaluated',
        'that any declared context is factually true; declarations are recorded, not verified',
        'wall-clock timing of the run beyond the explicitly declared, offset-bearing timestamps',
    ],
}


class ExportError(ValueError):
    """Fail closed: the inputs cannot be turned into an honest profile payload."""


# ------------------------------------------------------------------ small helpers
def sha256_of(raw: bytes) -> str:
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def media_type(name: str) -> str:
    return MEDIA_TYPES.get(Path(name).suffix.lower(), 'application/octet-stream')


def utc(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def require(mapping, path, what):
    node = mapping
    for key in path.split('.'):
        if not isinstance(node, dict) or key not in node:
            raise ExportError(f'context must declare {path} ({what}); it is never inferred')
        node = node[key]
    return node


# ------------------------------------------------------------------ profile basis
class Basis:
    """The exact schema bytes and registry the payload is validated against."""

    def __init__(self, schema_raw: bytes, registry_raw: bytes):
        registry = json.loads(registry_raw)
        entry = registry.get('profiles', {}).get(PROFILE_ID)
        if not entry:
            raise ExportError(f'registry does not declare {PROFILE_ID}')
        self.schema_digest = sha256_of(schema_raw)
        if entry.get('basis_digest') != self.schema_digest:
            raise ExportError('schema bytes do not match registry basis_digest: '
                              f'{self.schema_digest} != {entry.get("basis_digest")}')
        self.registry_digest = sha256_of(registry_raw)
        self.schema = json.loads(schema_raw)
        try:
            from jsonschema import Draft202012Validator
        except ImportError as exc:  # pragma: no cover - dependency documented in README
            raise ExportError('jsonschema is required to validate the profile payload') from exc
        Draft202012Validator.check_schema(self.schema)
        self._validator = Draft202012Validator(self.schema, format_checker=None)

    @classmethod
    def from_dir(cls, directory: Path) -> 'Basis':
        directory = Path(directory)
        return cls((directory / 'embedded-evaluation.schema.json').read_bytes(),
                   (directory / 'registry.json').read_bytes())

    def errors(self, payload) -> list[str]:
        return [f'{"/".join(str(p) for p in e.absolute_path) or "<root>"}: {e.message}'
                for e in sorted(self._validator.iter_errors(payload), key=lambda e: list(e.absolute_path))]


# ------------------------------------------------------------------ native inputs
class NativeFile:
    def __init__(self, name: str, role: str, raw: bytes):
        self.name, self.role, self.raw = Path(name).name, role, raw
        self.digest = sha256_of(raw)


def parse_results(raw: bytes) -> dict:
    try:
        doc = json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ExportError(f'results file is not valid JSON: {exc}') from exc
    if not isinstance(doc, dict) or not isinstance(doc.get('results'), dict):
        raise ExportError('Unsupported input shape: the current implementation expects LightEval '
                          'results_*.json output (a top-level object with a "results" mapping). '
                          'Native Inspect .eval and other result formats are not parsed.')
    return doc


def naive_date_id(name: str) -> str | None:
    """The LightEval filename date id as written: ``datetime.now().isoformat()`` with ':' → '-'.

    It is a timezone-naive local time on the machine that ran the evaluation. It is returned as a
    source observation only and is never converted to UTC by assumption.
    """
    match = RESULTS_NAME.search(Path(name).name)
    if not match:
        return None
    text = match.group('date')
    return text[:13] + ':' + text[14:16] + ':' + text[17:]


def parse_declared_timestamp(value, field: str) -> str:
    """ISO-8601 with an explicit 'Z' or ±HH:MM offset, normalised to the profile's UTC form."""
    if not isinstance(value, str) or not value.strip():
        raise ExportError(f'{field} must be an ISO-8601 string with an explicit timezone')
    text = value.strip()
    if text.endswith(('Z', 'z')):
        text = text[:-1] + '+00:00'
    try:
        ts = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ExportError(f'{field} is not ISO-8601: {value!r}') from exc
    if ts.tzinfo is None or ts.utcoffset() is None:
        raise ExportError(f'{field} is timezone-naive ({value!r}); declare it with an explicit "Z" or '
                          '±HH:MM offset. The host timezone is never assumed.')
    return utc(ts)


def compare(value, threshold):
    if isinstance(threshold, bool):
        return value == threshold
    if isinstance(threshold, (int, float)):
        raise ExportError('a bare numeric threshold is ambiguous; write it with an operator, e.g. "<= 0.05"')
    match = THRESHOLD.match(str(threshold))
    if not match:
        raise ExportError(f'unsupported threshold expression {threshold!r}; use <=, >=, <, >, ==, !=')
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ExportError(f'metric value {value!r} is not numeric; cannot apply threshold {threshold!r}')
    op, bound = match.group(1), float(match.group(2))
    return {'<=': value <= bound, '>=': value >= bound, '<': value < bound,
            '>': value > bound, '==': value == bound, '!=': value != bound}[op]


# ------------------------------------------------------------------ mapping
def map_target(context: dict, results: dict | None) -> dict:
    target = dict(require(context, 'target', 'provider, system_name and release_state'))
    general = (results or {}).get('config_general') or {}
    model_config = general.get('model_config') if isinstance(general.get('model_config'), dict) else {}
    if results is not None:
        target.setdefault('model_id', general.get('model_name') or model_config.get('model_name'))
        if model_config.get('revision'):
            target.setdefault('model_revision', str(model_config['revision']))
    return {k: v for k, v in target.items() if v is not None}


def map_framework(context: dict, results: dict | None) -> dict:
    declared = dict((context.get('evaluation') or {}).get('framework') or {})
    general = (results or {}).get('config_general') or {}
    framework = {'name': declared.get('name') or ('lighteval' if results is not None else None)}
    if framework['name'] is None:
        raise ExportError('context must declare evaluation.framework.name when no results file is supplied')
    for key in ('version', 'revision', 'source_ref', 'configuration_digest'):
        if declared.get(key):
            framework[key] = declared[key]
    if results is not None:
        sha = general.get('lighteval_sha')
        if sha and sha != '?' and 'revision' not in framework:
            framework['revision'] = str(sha)
        if 'configuration_digest' not in framework:
            framework['configuration_digest'] = sha256_of(canonical(general))
    return framework


def map_tasks(context: dict, results: dict | None) -> list[dict]:
    declared = (context.get('evaluation') or {}).get('tasks')
    if declared:
        return declared
    if results is None:
        raise ExportError('context must declare evaluation.tasks when no results file is supplied')
    configs = results.get('config_tasks') if isinstance(results.get('config_tasks'), dict) else {}
    names = [n for n in results['results'] if n != 'all'] or list(configs)
    if not names:
        raise ExportError('results carry no task entries; declare evaluation.tasks in the context')
    tasks = []
    for name in names:
        task = {'task_id': name}
        cfg = configs.get(name) if isinstance(configs.get(name), dict) else None
        if cfg:
            repo, subset = cfg.get('hf_repo'), cfg.get('hf_subset')
            if repo:
                task['dataset_ref'] = f'hf://datasets/{repo}' + (f'/{subset}' if subset and subset != 'default' else '')
            if cfg.get('hf_revision'):
                task['dataset_revision'] = str(cfg['hf_revision'])
            splits = cfg.get('evaluation_splits')
            if isinstance(splits, (list, tuple)) and splits:
                task['split'] = ','.join(str(s) for s in splits)
            task['configuration_digest'] = sha256_of(canonical(cfg))
        tasks.append(task)
    return tasks


def map_window(context: dict, results_name: str | None, results: dict | None, limitations: list) -> tuple[str, str]:
    evaluation = context.get('evaluation') or {}
    date_id = naive_date_id(results_name) if results_name else None
    declared = evaluation.get('started_at'), evaluation.get('ended_at')
    if not all(declared):
        hint = (f' The LightEval date id {date_id!r} in the results filename is timezone-naive and is '
                'not used as UTC.') if date_id else ''
        raise ExportError('LightEval date_id is timezone-naive. Declare evaluation.started_at and '
                          'evaluation.ended_at with an explicit timezone/offset in the context.' + hint)
    started = parse_declared_timestamp(declared[0], 'evaluation.started_at')
    ended = parse_declared_timestamp(declared[1], 'evaluation.ended_at')
    if ended < started:
        raise ExportError(f'evaluation.ended_at ({ended}) precedes started_at ({started}); a negative '
                          'duration is refused rather than reordered')
    if date_id:
        limitations.append(f'LightEval results filename date id {date_id} is a timezone-naive local '
                           'time recorded here as a source observation only; started_at/ended_at come '
                           'from the declared, offset-bearing context timestamps. LightEval '
                           'start_time/end_time are monotonic counters, not wall-clock timestamps.')
    return started, ended


def map_measurement(context: dict, results: dict | None, tasks: list[dict]) -> dict:
    declared = dict(require(context, 'measurement', 'criterion and limitations'))
    criterion = dict(require(context, 'measurement.criterion', 'the predeclared condition'))
    task_id = criterion.pop('task', None)
    metric = criterion.get('metric')
    threshold = criterion.get('threshold')
    execution = declared.get('execution_status')
    observed = dict(declared.get('observed') or {})
    limitations = list(declared.get('limitations') or [])
    if execution is not None and execution not in EXECUTION_STATES:
        raise ExportError(f'unknown execution_status {execution!r}')
    if observed.get('status') is not None and observed['status'] not in OBSERVED_STATES:
        raise ExportError(f'unknown observed.status {observed["status"]!r}')

    value = None
    found = False
    if results is not None and metric:
        if task_id is None:
            candidates = [t['task_id'] for t in tasks]
            if len(candidates) != 1:
                raise ExportError('measurement.criterion.task is required when the results carry more than one task')
            task_id = candidates[0]
        entry = results['results'].get(task_id)
        if isinstance(entry, dict) and metric in entry:
            value, found = entry[metric], True

    # --- contradictions: refuse rather than choose ---------------------------------
    if execution == 'NOT_RUN' and results is not None and results['results']:
        raise ExportError('context declares execution_status NOT_RUN but a results file with task '
                          'results was supplied; one of them is wrong')
    if execution in ('RAN', 'PARTIAL') and results is None:
        raise ExportError(f'context declares execution_status {execution} but no results file was supplied')
    if observed.get('status') in ('PASS', 'FAIL') and execution not in ('RAN', 'PARTIAL'):
        raise ExportError('observed PASS/FAIL requires execution_status RAN or PARTIAL')
    if results is None and execution is None:
        raise ExportError('no results file: context must declare measurement.execution_status '
                          '(NOT_RUN or INVALIDATED) and a matching observed status')

    # --- derive the observation ------------------------------------------------------
    if found and threshold is not None:
        derived = 'PASS' if compare(value, threshold) else 'FAIL'
        if observed.get('status') and observed['status'] != derived:
            raise ExportError(f'context observed.status {observed["status"]} contradicts the threshold '
                              f'result {derived} for {metric}={value!r} against {threshold!r}')
        observed.setdefault('status', derived)
        observed.setdefault('summary', f'{metric} = {value!r}; criterion {threshold!r} → {derived}')
        observed['metric_value'] = value
        execution = execution or 'RAN'
    elif found:
        if not observed.get('status'):
            raise ExportError('metric found but criterion.threshold is absent; declare a threshold or an '
                              'explicit measurement.observed.status')
        observed['metric_value'] = value
        execution = execution or 'RAN'
    else:
        if results is not None and metric and execution in (None, 'RAN'):
            raise ExportError(f'metric {metric!r} for task {task_id!r} is absent from the results; refusing '
                              'to report RAN — declare PARTIAL/INVALIDATED with a matching observed status')
        if not observed.get('status'):
            raise ExportError('no metric observation and no explicit measurement.observed.status')
        execution = execution or 'NOT_RUN'
        if execution == 'NOT_RUN' and observed['status'] not in ('NOT_MEASURED', 'NOT_APPLICABLE'):
            raise ExportError('NOT_RUN may only carry NOT_MEASURED or NOT_APPLICABLE')
    if execution == 'INVALIDATED' and observed['status'] in ('PASS', 'FAIL', 'NOT_APPLICABLE'):
        raise ExportError('INVALIDATED may only carry NOT_MEASURED, INCONCLUSIVE or ERROR')
    if not observed.get('summary'):
        raise ExportError('measurement.observed.summary is required')

    measurement = {'execution_status': execution, 'criterion': criterion, 'observed': observed,
                   'limitations': limitations}
    if 'sample_count' in declared:
        measurement['sample_count'] = declared['sample_count']
    elif results is not None and task_id:
        cfg = (results.get('config_tasks') or {}).get(task_id) if isinstance(results.get('config_tasks'), dict) else None
        count = (cfg or {}).get('effective_num_docs')
        if isinstance(count, int) and count >= 0:
            measurement['sample_count'] = count
    if 'attempts' in declared:
        measurement['attempts'] = declared['attempts']
    return measurement


def map_evidence(context: dict, files: list[NativeFile]) -> list[dict]:
    settings = context.get('evidence') or {}
    visibility = settings.get('visibility', 'public')
    prefix = settings.get('ref_prefix', 'file:')
    resolvable = bool(settings.get('resolvable', False))
    evidence = []
    for index, item in enumerate(files, 1):
        entry = {'evidence_id': f'ev-{index:02d}-{item.role}', 'role': item.role,
                 'ref': prefix + item.name, 'resolvable': resolvable, 'digest': item.digest,
                 'media_type': media_type(item.name), 'visibility': visibility}
        if visibility == 'withheld':
            reason = settings.get('withholding_reason')
            if not reason:
                raise ExportError('evidence.visibility withheld requires evidence.withholding_reason')
            entry['withholding_reason'] = reason
        evidence.append(entry)
    for extra in settings.get('additional') or []:
        evidence.append(dict(extra))
    if not evidence:
        raise ExportError('at least one evidence object is required; supply a results file or evidence.additional')
    return evidence


def map_verification(context: dict) -> list[dict]:
    verification = [dict(v) for v in (context.get('verification') or [])]
    platform = context.get('platform_verification')
    if platform:
        token = platform.get('verify_token')
        if not token:
            raise ExportError('platform_verification requires verify_token')
        verification.append({
            'verifier': platform.get('verifier', 'huggingface-hub'),
            'kind': 'platform-verification',
            'status': 'NOT_EVALUATED',
            'ref': platform.get('ref', 'hf-eval-results:verifyToken'),
            'digest': sha256_of(str(token).encode('utf-8')),
            'independence': 'unknown',
        })
    return verification


def build_profile(context: dict, results: NativeFile | None, extra: list[NativeFile] | None = None) -> dict:
    """Pure mapping from declared context + native bytes to the profile payload."""
    if not isinstance(context, dict):
        raise ExportError('context must be a JSON object')
    require(context, 'engagement.independence.status', 'declared independence status')
    require(context, 'engagement.independence.basis', 'independence basis')
    require(context, 'access.tier', 'evaluator access tier')
    require(context, 'access.capabilities', 'access capabilities')
    require(context, 'access.limitations', 'access limitations')
    doc = parse_results(results.raw) if results is not None else None
    evaluation_ctx = context.get('evaluation') or {}
    limitations_seed: list = []
    started, ended = map_window(context, results.name if results else None, doc, limitations_seed)
    tasks = map_tasks(context, doc)
    measurement = map_measurement(context, doc, tasks)
    measurement['limitations'] = list(dict.fromkeys(measurement['limitations'] + limitations_seed))
    files = ([results] if results is not None else []) + list(extra or [])
    evaluation = {
        'run_id': evaluation_ctx.get('run_id') or (results.name if results else None),
        'objective': require(context, 'evaluation.objective', 'the evaluation objective'),
        'risk_domains': require(context, 'evaluation.risk_domains', 'risk domains'),
        'framework': map_framework(context, doc),
        'tasks': tasks,
        'started_at': started,
        'ended_at': ended,
        'environment': require(context, 'evaluation.environment', 'runtime environment, never inferred'),
        'safeguards': require(context, 'evaluation.safeguards', 'safeguard state, never inferred'),
    }
    if evaluation['run_id'] is None:
        raise ExportError('context must declare evaluation.run_id when no results file is supplied')
    payload = {
        'profile_version': PROFILE_VERSION,
        'engagement': context['engagement'],
        'target': map_target(context, doc),
        'access': context['access'],
        'evaluation': evaluation,
        'measurement': measurement,
        'evidence': map_evidence(context, files),
        'disclosure': context.get('disclosure') or {'redactions_present': False, 'redactions': [],
                                                     'deviations': [], 'retries': [], 'incidents': []},
        'scope': require(context, 'scope', 'what the instance covers and does not cover'),
    }
    verification = map_verification(context)
    if verification:
        payload['verification'] = verification
    return payload


def manifest(basis: Basis, files: list[NativeFile], context_raw: bytes, payload: dict | None) -> dict:
    return {
        'generator': {'name': EXPORTER_NAME, 'version': EXPORTER_VERSION,
                      'source': 'integrations/lighteval/export_embedded_evaluation.py'},
        'profile': {'id': PROFILE_ID, 'version': PROFILE_VERSION, 'carrier_airep_version': CARRIER_AIREP_VERSION,
                    'schema_basis_digest': basis.schema_digest, 'registry_digest': basis.registry_digest},
        'inputs': [{'name': f.name, 'role': f.role, 'bytes': len(f.raw), 'sha256': f.digest,
                    'media_type': media_type(f.name)} for f in files],
        'context': {'sha256': sha256_of(context_raw), 'bytes': len(context_raw)},
        'outputs': {'profile_payload_sha256': sha256_of(canonical(payload)) if payload is not None else None},
        'claims': CLAIMS,
    }


def export(context_raw: bytes, results: NativeFile | None, extra: list[NativeFile], basis: Basis) -> tuple[dict | None, dict, dict]:
    """Returns (payload or None, manifest, validation report). Raises ExportError on contradictions."""
    try:
        context = json.loads(context_raw.decode('utf-8'))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ExportError(f'context is not valid JSON: {exc}') from exc
    payload = build_profile(context, results, extra)
    errors = basis.errors(payload)
    report = {
        'profile_id': PROFILE_ID, 'profile_version': PROFILE_VERSION, 'basis_digest': basis.schema_digest,
        'validator': 'jsonschema Draft202012Validator, format_checker=None',
        'schema_valid': not errors, 'errors': errors,
        'meaning': 'schema_valid true means only that the payload validates against the digest-pinned basis; '
                   'see claims.does_not_establish in evidence-manifest.json',
    }
    files = ([results] if results is not None else []) + list(extra)
    return (payload if not errors else None), manifest(basis, files, context_raw, payload if not errors else None), report


# ------------------------------------------------------------------ CLI
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--results', type=Path, help='LightEval results_*.json (aggregate-result); the only parsed input shape')
    ap.add_argument('--details', type=Path, nargs='*', default=[], help='native details_*.parquet (sample-details)')
    ap.add_argument('--raw-output', type=Path, nargs='*', default=[], help='raw model output files (raw-output)')
    ap.add_argument('--log', type=Path, nargs='*', default=[], help='harness/system logs (system-log)')
    ap.add_argument('--context', type=Path, required=True, help='explicit evaluator/target/access context JSON')
    ap.add_argument('--profile-dir', type=Path, default=DEFAULT_PROFILE_DIR, help='directory holding the schema and registry')
    ap.add_argument('--out-dir', type=Path, required=True)
    args = ap.parse_args(argv)
    try:
        basis = Basis.from_dir(args.profile_dir)
        results = NativeFile(args.results.name, 'aggregate-result', args.results.read_bytes()) if args.results else None
        extra = ([NativeFile(p.name, 'sample-details', p.read_bytes()) for p in args.details]
                 + [NativeFile(p.name, 'raw-output', p.read_bytes()) for p in args.raw_output]
                 + [NativeFile(p.name, 'system-log', p.read_bytes()) for p in args.log])
        payload, manifest_doc, report = export(args.context.read_bytes(), results, extra, basis)
    except (ExportError, OSError) as exc:
        print(f'export refused: {exc}', file=sys.stderr)
        return 2
    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / 'evidence-manifest.json').write_text(json.dumps(manifest_doc, indent=2) + '\n', encoding='utf-8')
    (args.out_dir / 'validation-report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    if payload is None:
        print('profile payload did not validate; no payload written (see validation-report.json)', file=sys.stderr)
        return 1
    (args.out_dir / 'embedded-evaluation.profile.json').write_text(json.dumps(payload, indent=2) + '\n', encoding='utf-8')
    print(f'wrote {args.out_dir}/embedded-evaluation.profile.json (basis {basis.schema_digest})')
    return 0


if __name__ == '__main__':
    sys.exit(main())
