"""An intentionally non-automatic SSH client for protocol state learning."""
import hashlib
import socket
import time

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from .packet import BadPacket, Direction, derive_keys
from .wire import Reader, mpint, string, uint32

INPUTS = (
    'KEXINIT', 'KEX30', 'NEWKEYS', 'SR_AUTH', 'SR_CONN', 'UA_PW_OK', 'UA_PW_NOK', 'UA_NONE',
    'CH_OPEN', 'CH_CLOSE', 'CH_EOF', 'CH_DATA', 'CH_REQUEST_EXEC',
    'IGNORE', 'DEBUG', 'UNIMPLEMENTED', 'DISCONNECT',
)
NAMES = dict(zip(
    (1, 2, 3, 4, 6, 7, 20, 21, 30, 31, 51, 52, 53, 80, 81, 82,
     91, 92, 93, 94, 95, 96, 97, 98, 99, 100),
    ('DISCONNECT', 'IGNORE', 'UNIMPLEMENTED', 'DEBUG', 'SERVICE_ACCEPT', 'EXT_INFO',
     'KEXINIT', 'NEWKEYS', 'KEX30', 'KEX31', 'UA_FAILURE', 'UA_SUCCESS', 'UA_BANNER',
     'GLOBAL_REQUEST', 'REQUEST_SUCCESS', 'REQUEST_FAILURE', 'CH_OPEN_SUCCESS',
     'CH_OPEN_FAILURE', 'CH_WINDOW_ADJUST', 'CH_DATA', 'CH_EXTENDED_DATA', 'CH_EOF',
     'CH_CLOSE', 'CH_REQUEST', 'CH_SUCCESS', 'CH_FAILURE')))
NAMES.update({5: 'SERVICE_REQUEST', 50: 'UA_REQUEST', 90: 'CH_OPEN'})
VERSION = b'SSH-2.0-smlearn_0.1'


class SSHMapper:
    def __init__(self, host, port, user='test', password='test', *, timeout=1.0,
                 quiet=0.15, strict_kex=True):
        self.host, self.port = host, port
        self.user, self.password = user, password
        self.timeout, self.quiet = timeout, quiet
        self.strict_kex = strict_kex
        self.sock = None
        self.trace = []
        self.strict_kex_active = False
        self.server_kex = None

    def close(self):
        if self.sock is not None:
            self.sock.close()
            self.sock = None

    def reset(self):
        self.close()
        self.trace = []
        self.incoming, self.outgoing = Direction(), Direction()
        self.buffer = bytearray()
        self.client_kex = self.server_kex = self.private_key = None
        self.pending = {}
        self.session_id = self.channel = None
        self.strict_kex_active = False
        self.sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock.sendall(VERSION + b'\r\n')
        deadline = time.monotonic() + self.timeout
        while True:
            while b'\n' not in self.buffer:
                self.sock.settimeout(max(0.001, deadline - time.monotonic()))
                data = self.sock.recv(65536)
                if not data:
                    self.close()
                    raise EOFError('closed during SSH identification')
                self.buffer.extend(data)
            line, _, rest = self.buffer.partition(b'\n')
            self.buffer = bytearray(rest)
            if line.startswith(b'SSH-'):
                self.server_version = bytes(line).rstrip(b'\r')
                break
        self._collect(self.quiet)

    def _install(self, direction, outgoing):
        keys = self.pending.pop(outgoing, None)
        if keys is not None:
            direction.install(*keys)
            if self.strict_kex_active:
                direction.sequence = 0

    def _received(self, payload):
        kind = payload[0]
        fields = Reader(payload[1:])
        if kind == 20:
            if self.server_kex is None:
                # Strict KEX is negotiated once, by the initial server KEXINIT.
                fields.take(16)
                offered = fields.string().split(b',')
                self.strict_kex_active = self.strict_kex and b'kex-strict-s-v00@openssh.com' in offered
            self.server_kex = payload
        elif kind == 31 and self.client_kex and self.server_kex and self.private_key:
            host_key, public = fields.string(), fields.string()
            fields.string()  # Host signature is deliberately not verified in this testbed.
            shared = self.private_key.exchange(X25519PublicKey.from_public_bytes(public))
            secret = int.from_bytes(shared, 'big')
            transcript = (VERSION, self.server_version, self.client_kex, self.server_kex,
                          host_key, self.private_key.public_key().public_bytes_raw(), public)
            exchange_hash = hashlib.sha256(b''.join(string(x) for x in transcript) + mpint(secret)).digest()
            if self.session_id is None:
                self.session_id = exchange_hash
            a, b, c, d, e, f = derive_keys(secret, exchange_hash, self.session_id)
            self.pending = {True: (a, c, e), False: (b, d, f)}
        elif kind == 21:
            self._install(self.incoming, False)
        elif kind == 91:
            fields.uint32()
            self.channel = fields.uint32()
        elif kind == 97:
            self.channel = None

    def _collect(self, first_timeout):
        outputs = []
        deadline = time.monotonic() + first_timeout
        while self.sock is not None:
            try:
                payload = self.incoming.decode(self.buffer)
                if payload is not None:
                    if not payload:
                        raise BadPacket('empty payload')
                    name = NAMES.get(payload[0], f'MSG{payload[0]}')
                    self.trace.append(('<', name, payload.hex()))
                    self._received(payload)
                    if not outputs or outputs[-1] != name:
                        outputs.append(name)
                    deadline = time.monotonic() + self.quiet
                    continue
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self.sock.settimeout(remaining)
                data = self.sock.recv(65536)
                if not data:
                    self.close()
                    outputs.append('CLOSED')
                    break
                self.buffer.extend(data)
            except socket.timeout:
                break
            except OSError:
                self.close()
                outputs.append('CLOSED')
            except ValueError:
                self.close()
                outputs.append('BAD_PACKET')
        return '+'.join(outputs) if outputs else 'NO_RESP'

    def _payload(self, symbol):
        if symbol == 'KEXINIT':
            kex = 'curve25519-sha256,curve25519-sha256@libssh.org'
            if self.strict_kex:
                kex += ',kex-strict-c-v00@openssh.com'
            lists = (kex, 'ssh-ed25519,rsa-sha2-256,ecdsa-sha2-nistp256',
                     'aes128-ctr', 'aes128-ctr', 'hmac-sha2-256', 'hmac-sha2-256',
                     'none', 'none', '', '')
            self.client_kex = b'\x14' + bytes(16) + b''.join(string(x) for x in lists) + b'\0' + uint32(0)
            return self.client_kex
        if symbol == 'KEX30':
            self.private_key = X25519PrivateKey.generate()
            return b'\x1e' + string(self.private_key.public_key().public_bytes_raw())
        if symbol == 'NEWKEYS':
            return b'\x15'
        if symbol in ('SR_AUTH', 'SR_CONN'):
            return b'\x05' + string('ssh-userauth' if symbol == 'SR_AUTH' else 'ssh-connection')
        if symbol.startswith('UA_'):
            payload = b'\x32' + string(self.user) + string('ssh-connection')
            if symbol == 'UA_NONE':
                return payload + string('none')
            password = self.password if symbol == 'UA_PW_OK' else self.password + '-wrong'
            return payload + string('password') + b'\0' + string(password)
        if symbol == 'CH_OPEN':
            return b'\x5a' + string('session') + uint32(0) + uint32(2**21) + uint32(32768)
        if symbol.startswith('CH_'):
            channel = uint32(self.channel)
            return {
                'CH_CLOSE': b'\x61' + channel,
                'CH_EOF': b'\x60' + channel,
                'CH_DATA': b'\x5e' + channel + string(b'x'),
                'CH_REQUEST_EXEC': b'\x62' + channel + string('exec') + b'\x01' + string('true'),
            }[symbol]
        return {'IGNORE': b'\x02' + string(b''),
                'DEBUG': b'\x04\0' + string(b'') + string(b''),
                'UNIMPLEMENTED': b'\x03' + uint32(0),
                'DISCONNECT': b'\x01' + uint32(11) + string(b'') + string(b'')}[symbol]

    def step(self, symbol):
        if symbol not in INPUTS:
            raise ValueError(f'unknown SSH input: {symbol}')
        if self.sock is None:
            return 'NO_CONN'
        if symbol in ('CH_CLOSE', 'CH_EOF', 'CH_DATA', 'CH_REQUEST_EXEC') and self.channel is None:
            return 'NO_CHANNEL'
        payload = self._payload(symbol)
        try:
            self.sock.sendall(self.outgoing.encode(payload))
        except OSError:
            self.close()
            return 'CLOSED'
        self.trace.append(('>', NAMES.get(payload[0], f'MSG{payload[0]}'), payload.hex()))
        if symbol == 'NEWKEYS':
            self._install(self.outgoing, True)
        elif symbol == 'CH_CLOSE':
            self.channel = None
        return self._collect(self.timeout)
