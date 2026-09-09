#!/usr/bin/env node
// First-party beta adapter: AD-17 admission + r3 profiles + preserved r1 engine.
// Authorship of this adapter is not an independent implementation claim.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {createRequire} from 'node:module';
import {spawnSync} from 'node:child_process';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const cv = path.join(root, 'spec/airep/v0.2/class-verification');
const engine = path.join(cv, 'verifier_node_r2/class_verifier.mjs');
const require = createRequire(engine);
const Ajv = require('ajv/dist/2020.js');
const digest = raw => 'sha256:' + crypto.createHash('sha256').update(raw).digest('hex');

// Recursive descent keeps each object's member identities before map collapse.
// JSON.parse is used only for individual scalar tokens, never a complete object.
export function admit(raw, artifactRequest=false) {
  const text = new TextDecoder('utf-8', {fatal:true, ignoreBOM:true}).decode(raw);
  if (text.startsWith('\ufeff')) throw Error('initial UTF-8 BOM');
  let i = 0;
  const sequenceTokens = new WeakMap();
  const ws = () => { while (i < text.length && /[\x20\x09\x0a\x0d]/.test(text[i])) i++; };
  function string() {
    const start = i++;
    while (i < text.length) {
      if (text[i] === '\\') { i += 2; continue; }
      if (text[i++] === '"') {
        const s = JSON.parse(text.slice(start, i));
        for (const char of s) {
          const n = char.codePointAt(0);
          if ((n >= 0xd800 && n <= 0xdfff) || (n >= 0xfdd0 && n <= 0xfdef) ||
              (n & 0xffff) === 0xfffe || (n & 0xffff) === 0xffff) throw Error('inadmissible Unicode scalar');
        }
        return s;
      }
    }
    throw Error('unterminated string');
  }
  function value() {
    ws();
    if (text[i] === '"') return string();
    if (text[i] === '{') {
      i++; ws();
      const o = Object.create(null), keys = new Set();
      if (text[i] === '}') { i++; return o; }
      while (true) {
        ws(); if (text[i] !== '"') throw Error('expected object member');
        const k = string();
        if (keys.has(k)) throw Error('duplicate JSON member');
        keys.add(k); ws(); if (text[i++] !== ':') throw Error('expected colon');
        const start = i;
        o[k] = value();
        if (k === 'sequence' && typeof o[k] === 'number') sequenceTokens.set(o, text.slice(start, i).trim());
        ws();
        if (text[i] === '}') { i++; return o; }
        if (text[i++] !== ',') throw Error('expected comma');
      }
    }
    if (text[i] === '[') {
      i++; ws(); const a = [];
      if (text[i] === ']') { i++; return a; }
      while (true) {
        a.push(value()); ws();
        if (text[i] === ']') { i++; return a; }
        if (text[i++] !== ',') throw Error('expected comma');
      }
    }
    const token = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(i));
    if (!token) throw Error('invalid JSON token');
    i += token[0].length;
    const v = JSON.parse(token[0]);
    if (typeof v === 'number' && !Number.isFinite(v)) throw Error('non-finite JSON number');
    return v;
  }
  const result = value(); ws();
  if (i !== text.length) throw Error('trailing JSON content');
  if (artifactRequest && result && typeof result === 'object') {
    const artifacts = [result.artifact, ...(Array.isArray(result.related_artifacts) ? result.related_artifacts : [])];
    for (const artifact of artifacts) {
      const token = artifact && typeof artifact === 'object' ? sequenceTokens.get(artifact) : undefined;
      if (token !== undefined && !sequenceWithinBounds(token)) throw Error('raw sequence is outside the exact Core bounds');
    }
  }
  return result;
}

function sequenceWithinBounds(token) {
  const m = /^(-?)(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/.exec(token);
  if (!m) return false;
  const digits = (m[2] + (m[3] || '')).replace(/^0+/, '');
  if (!digits) return true; // negative zero is admitted
  if (m[1] === '-') return false;
  const magnitude = digits.length + Number(m[4] || 0) - (m[3] || '').length;
  if (magnitude !== 16) return magnitude < 16;
  const leading = digits.padEnd(16, '0').slice(0, 16), max = '9007199254740991';
  return leading < max || leading === max && !/[1-9]/.test(digits.slice(16));
}

const object = x => x !== null && typeof x === 'object' && !Array.isArray(x);
const sameKeys = (x, keys) => object(x) && Object.keys(x).sort().join(',') === [...keys].sort().join(',');
const dialect = 'https://json-schema.org/draft/2020-12/schema';
const vocabs = new Set(['core','applicator','unevaluated','validation','meta-data','format-annotation','content']
  .map(n => 'https://json-schema.org/draft/2020-12/vocab/' + n));

function* nodes(doc) {
  if (!object(doc)) return;
  yield doc;
  for (const key of ['$defs','definitions','properties','patternProperties','dependentSchemas'])
    if (object(doc[key])) for (const child of Object.values(doc[key])) yield* nodes(child);
  for (const key of ['allOf','anyOf','oneOf','prefixItems'])
    if (Array.isArray(doc[key])) for (const child of doc[key]) yield* nodes(child);
  for (const key of ['additionalProperties','unevaluatedProperties','propertyNames','items','unevaluatedItems','contains','not','if','then','else','contentSchema'])
    yield* nodes(doc[key]);
}

function loadBases(filename) {
  const result = {digest:null, validators:new Map()};
  if (filename === undefined) return result;
  const real = fs.realpathSync(filename), base = path.dirname(real);
  const raw = fs.readFileSync(real), registry = admit(raw);
  result.digest = digest(raw);
  if (!sameKeys(registry, ['profiles']) || !object(registry.profiles)) throw Error('malformed registry');
  for (const [id, entry] of Object.entries(registry.profiles)) {
    if (!/^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)+$/.test(id) ||
        !sameKeys(entry, ['schema_path','basis_digest']) || typeof entry.schema_path !== 'string' ||
        path.isAbsolute(entry.schema_path)) throw Error('malformed basis entry');
    const target = fs.realpathSync(path.resolve(base, entry.schema_path));
    const relative = path.relative(base, target);
    if (relative === '..' || relative.startsWith('..' + path.sep) || path.isAbsolute(relative)) throw Error('basis escapes resolved root');
    const basisRaw = fs.readFileSync(target), hash = digest(basisRaw);
    if (hash !== entry.basis_digest) throw Error('basis digest mismatch');
    const doc = admit(basisRaw);
    for (const node of nodes(doc)) {
      if ('$schema' in node && (typeof node.$schema !== 'string' || node.$schema.replace(/#$/, '') !== dialect)) throw Error('unsupported dialect');
      if ('$vocabulary' in node) {
        if (!object(node.$vocabulary)) throw Error('invalid vocabulary');
        for (const [name, required] of Object.entries(node.$vocabulary))
          if (required && !vocabs.has(name)) throw Error('unsupported required vocabulary');
      }
      for (const key of ['$ref','$dynamicRef'])
        if (key in node && (typeof node[key] !== 'string' || !node[key].startsWith('#'))) throw Error('external basis reference');
    }
    const ajv = new Ajv({strict:false, allErrors:true, validateFormats:false});
    const validate = ajv.compile(doc);
    // Ajv need not compile unused $defs. Resolve every reference explicitly as
    // well, so a dormant broken branch cannot masquerade as a usable basis.
    function walk(node, scope) {
      if (!object(node)) return;
      if (typeof node.$id === 'string') scope = new URL(node.$id, scope).href;
      for (const key of ['$ref','$dynamicRef']) {
        if (key in node) {
          const url = new URL(node[key], scope).href;
          // Register root with a deterministic local URI when $id is absent.
          if (!ajv.getSchema(url)) throw Error('unresolved basis fragment');
        }
      }
      for (const key of ['$defs','definitions','properties','patternProperties','dependentSchemas'])
        if (object(node[key])) for (const child of Object.values(node[key])) walk(child, scope);
      for (const key of ['allOf','anyOf','oneOf','prefixItems'])
        if (Array.isArray(node[key])) for (const child of node[key]) walk(child, scope);
      for (const key of ['additionalProperties','unevaluatedProperties','propertyNames','items','unevaluatedItems','contains','not','if','then','else','contentSchema']) walk(node[key], scope);
    }
    const uri = typeof doc?.$id === 'string' ? doc.$id : 'urn:airep:profile-basis';
    if (object(doc) && !('$id' in doc)) ajv.addSchema(doc, uri);
    walk(doc, uri);
    result.validators.set(id, {validate, digest:hash});
  }
  return result;
}

function main() {
  const args = process.argv.slice(2), allowed = new Set(['--request','--bindings','--independence-policy','--revocation','--now','--freshness-window','--profile-bases']);
  if (args.length === 1 && args[0] === '--help') {
    console.log('node tools/airep_v02/verify_node.mjs --request FILE [--bindings FILE --revocation FILE --independence-policy FILE --profile-bases FILE --now UTC --freshness-window SECONDS]'); return 0;
  }
  const flags = {}, forwarded = [];
  for (let i=0; i<args.length; i+=2) {
    if (!allowed.has(args[i]) || i+1 >= args.length || args[i] in flags) { console.error('usage: invalid option'); return 2; }
    flags[args[i]] = args[i+1];
    if (args[i] !== '--profile-bases') forwarded.push(args[i], args[i+1]);
  }
  if (!flags['--request']) { console.error('usage: --request required'); return 2; }
  try {
    const request = admit(fs.readFileSync(flags['--request']), true);
    const bases = loadBases(flags['--profile-bases']);
    const child = spawnSync(process.execPath, [engine, '--schema-dir', path.join(cv, '../schemas'), ...forwarded], {encoding:'utf8', maxBuffer:16*1024*1024});
    if (child.error || child.status !== 0) { process.stderr.write(child.stderr || String(child.error || 'engine failed')); return child.status === 2 ? 2 : 1; }
    const verdict = JSON.parse(child.stdout), artifact = request.artifact;
    if (artifact.artifact_type === 'effect' && artifact.observer_relationship === 'independent') {
      const ref = artifact.execution_ref;
      const matches = [artifact, ...(request.related_artifacts || [])].filter(a => a.record_id === ref.record_id);
      if (matches.length !== 1 || matches[0].artifact_type !== 'execution' ||
          ('chain_id' in ref && matches[0].chain_id !== ref.chain_id)) verdict.observer_assessment = 'unknown';
    }
    verdict.profile_evaluations = {};
    for (const id of Object.keys(artifact.profiles || {}).sort((a,b) => Buffer.compare(Buffer.from(a),Buffer.from(b)))) {
      const basis = bases.validators.get(id);
      verdict.profile_evaluations[id] = basis ? {result:basis.validate(artifact.profiles[id]) ? 'PASS':'FAIL', basis_digest:basis.digest} : {result:'NOT_EVALUATED',basis_digest:null};
    }
    verdict.evidence.profile_bases_digest = bases.digest;
    console.log(JSON.stringify(verdict));
    return 0;
  } catch (e) { console.error('invalid: ' + e.message); return 1; }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exitCode = main();
