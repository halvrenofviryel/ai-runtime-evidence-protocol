"""r3 exact, self-contained, network-free profile validation basis."""
from pathlib import Path
import re

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from .json_input import loads, InvalidInput
from .producer import digest_bytes

DIALECT = 'https://json-schema.org/draft/2020-12/schema'
VOCABS = {'https://json-schema.org/draft/2020-12/vocab/' + n for n in (
    'core', 'applicator', 'unevaluated', 'validation', 'meta-data', 'format-annotation', 'content')}
MAPS = ('$defs', 'definitions', 'properties', 'patternProperties', 'dependentSchemas')
LISTS = ('allOf', 'anyOf', 'oneOf', 'prefixItems')
SINGLE = ('additionalProperties', 'unevaluatedProperties', 'propertyNames', 'items',
          'unevaluatedItems', 'contains', 'not', 'if', 'then', 'else', 'contentSchema')


def schema_nodes(doc):
    if not isinstance(doc, dict):
        return
    yield doc
    for key in MAPS:
        if isinstance(doc.get(key), dict):
            for child in doc[key].values():
                yield from schema_nodes(child)
    for key in LISTS:
        if isinstance(doc.get(key), list):
            for child in doc[key]:
                yield from schema_nodes(child)
    for key in SINGLE:
        yield from schema_nodes(doc.get(key))


def validate_basis(doc):
    Draft202012Validator.check_schema(doc)
    for node in schema_nodes(doc):
        if '$schema' in node and node['$schema'].rstrip('#') != DIALECT:
            raise InvalidInput('profile basis dialect is not Draft 2020-12')
        vocab = node.get('$vocabulary', {})
        if any(required and name not in VOCABS for name, required in vocab.items()):
            raise InvalidInput('unsupported required vocabulary')
        for key in ('$ref', '$dynamicRef'):
            if key in node and not node[key].startswith('#'):
                raise InvalidInput('profile basis requires external bytes')
    # The resolver has no retrieval callback. Preflight every reference, including
    # unused branches, under the subschema's resource scope.
    resource = Resource.from_contents(doc, default_specification=__import__('referencing.jsonschema', fromlist=['DRAFT202012']).DRAFT202012)
    registry = Registry().with_resource('urn:airep:profile-basis', resource)

    def walk(res, resolver):
        node = res.contents
        if isinstance(node, dict):
            for key in ('$ref', '$dynamicRef'):
                if key in node:
                    resolver.lookup(node[key])
        for child in res.subresources():
            walk(child, resolver.in_subresource(child))

    walk(resource, registry.resolver('urn:airep:profile-basis'))
    return Draft202012Validator(doc, registry=registry, format_checker=None)


class ProfileBases:
    def __init__(self, path=None):
        self.digest = None
        self.validators = {}
        if path is None:
            return
        try:
            registry_path = Path(path).resolve(strict=True)
            root = registry_path.parent
            raw = registry_path.read_bytes()
            self.digest = digest_bytes(raw)
            doc = loads(raw)
            if not isinstance(doc, dict) or set(doc) != {'profiles'} or not isinstance(doc['profiles'], dict):
                raise InvalidInput('malformed profile basis registry')
            for name, entry in doc['profiles'].items():
                if not re.fullmatch(r'[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)+', name):
                    raise InvalidInput('invalid profile identifier')
                if not isinstance(entry, dict) or set(entry) != {'schema_path', 'basis_digest'}:
                    raise InvalidInput('malformed profile basis entry')
                locator = entry['schema_path']
                if not isinstance(locator, str) or Path(locator).is_absolute():
                    raise InvalidInput('basis locator must be relative')
                target = (root / locator).resolve(strict=True)
                if not target.is_relative_to(root):
                    raise InvalidInput('basis escapes resolved registry directory')
                basis_raw = target.read_bytes()
                digest = digest_bytes(basis_raw)
                if entry['basis_digest'] != digest:
                    raise InvalidInput('basis digest mismatch')
                self.validators[name] = (validate_basis(loads(basis_raw)), digest)
        except Exception as exc:
            # A supplied unusable basis invalidates the complete run, never a
            # profile FAIL/NOT_EVALUATED or a partially emitted batch.
            raise InvalidInput('unusable profile basis: ' + str(exc)) from exc

    def evaluate(self, artifact):
        result = {}
        for name in sorted(artifact.get('profiles', {}), key=lambda s: s.encode('utf-8')):
            if name not in self.validators:
                result[name] = {'result':'NOT_EVALUATED', 'basis_digest':None}
            else:
                validator, digest = self.validators[name]
                try:
                    valid = validator.is_valid(artifact['profiles'][name])
                except Exception as exc:
                    raise InvalidInput('profile evaluation unusable: ' + str(exc)) from exc
                result[name] = {'result':'PASS' if valid else 'FAIL', 'basis_digest':digest}
        return result
