"""Bounded local JSON/file boundary; references inside JSON are never fetched."""
import json
import os
from pathlib import Path
import stat

from ._native.json_input import loads, check_core_number_bounds

MAX_BYTES = 1024 * 1024
MAX_DEPTH = 32
MAX_NODES = 20000
MAX_ARTIFACTS = 128


def bounded_loads(raw):
    if type(raw) not in (bytes, str):
        raise ValueError('raw JSON bytes or text required')
    raw = raw.encode('utf-8') if isinstance(raw, str) else raw
    if len(raw) > MAX_BYTES:
        raise ValueError('JSON exceeds 1 MiB')
    # Bound nesting before the JSON parser builds a recursive object.
    depth, quoted, escaped = 0, False, False
    for char in raw:
        if quoted:
            if escaped:
                escaped = False
            elif char == 92:
                escaped = True
            elif char == 34:
                quoted = False
        elif char == 34:
            quoted = True
        elif char in (91, 123):
            depth += 1
            if depth > MAX_DEPTH:
                raise ValueError('JSON nesting exceeds 32')
        elif char in (93, 125):
            depth -= 1
    value = loads(raw)
    stack, count = [value], 0
    while stack:
        item = stack.pop()
        count += 1
        if count > MAX_NODES:
            raise ValueError('JSON node count exceeds 20000')
        if isinstance(item, dict):
            stack.extend(item.keys()); stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, str) and len(item.encode('utf-8')) > 131072:
            raise ValueError('JSON string exceeds 128 KiB')
    return value


def _parent_fd(path):
    """Walk directory descriptors without following symlinks, including parents."""
    if not all(hasattr(os, name) for name in ('O_DIRECTORY', 'O_NOFOLLOW', 'O_NONBLOCK')):
        raise ValueError('this file boundary requires POSIX descriptor support')
    path = Path(os.path.abspath(path))
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:-1]:
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = next_fd
        return fd, path.name
    except BaseException:
        os.close(fd)
        raise


def read_bytes(path, limit=MAX_BYTES, *, absent_ok=False):
    directory, name = _parent_fd(path)
    fd = None
    try:
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        except FileNotFoundError:
            if absent_ok:
                return None
            raise
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError('bounded regular input file required')
        with os.fdopen(fd, 'rb') as f:
            fd = None
            raw = f.read(limit + 1)
        if len(raw) > limit:
            raise ValueError('input grew beyond size limit')
        return raw
    finally:
        if fd is not None:
            os.close(fd)
        os.close(directory)


def write_bytes(path, raw):
    directory, name = _parent_fd(path)
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        with os.fdopen(fd, 'wb') as f:
            f.write(raw)
    finally:
        os.close(directory)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False) + '\n').encode()


def artifacts(raw):
    value = bounded_loads(raw)
    check_core_number_bounds(raw)
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_ARTIFACTS:
        raise ValueError('one to 128 artifacts required')
    return value


def check_bundle_sequences(raw):
    class Number(str):
        pass
    doc = json.loads(raw, parse_int=Number, parse_float=Number)
    if isinstance(doc, dict) and isinstance(doc.get('artifacts'), list):
        for item in doc['artifacts']:
            token = item.get('sequence') if isinstance(item, dict) else None
            if isinstance(token, Number):
                check_core_number_bounds('{"sequence":' + token + '}')
