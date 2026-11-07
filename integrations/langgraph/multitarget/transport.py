"""Bounded actual Unix socket transport; no external network or remote fetch."""
import socket
from integrations.langgraph.run import encoded
from tools.airep_v02.json_input import loads

MAX_WIRE = 262144


def read_line(connection):
    raw = bytearray()
    while len(raw) <= MAX_WIRE:
        chunk = connection.recv(1)
        if not chunk:
            raise EOFError('peer closed before complete response')
        raw += chunk
        if chunk == b'\n':
            return bytes(raw)
    raise ValueError('bounded wire message required')


def call(path, message):
    raw = encoded(message)
    if len(raw) > MAX_WIRE:
        raise ValueError('bounded request required')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(8)
        connection.connect(str(path))
        connection.sendall(raw)
        return read_line(connection)


def send_attempt(path, command, emit):
    raw = encoded(command)
    emit('send', {'command_hex': raw.hex()})
    try:
        reply = call(path, command)
        loads(reply)  # A malformed reply fails explicitly, never becomes success.
        result = {'delivery_attempt_id': command['delivery_attempt_id'], 'status': 'RESPONSE',
                  'response_hex': reply.hex(), 'error': None}
    except (OSError, EOFError) as exc:
        result = {'delivery_attempt_id': command['delivery_attempt_id'], 'status': 'TRANSPORT_UNKNOWN',
                  'response_hex': None, 'error': type(exc).__name__}
    emit('transport', result)
    return result
