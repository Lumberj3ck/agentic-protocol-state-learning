"""RFC 4253 framing and key derivation; AES-CTR and SHA-256 MACs."""
import hashlib
import os

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature

from .wire import mpint, uint32


class BadPacket(ValueError):
    pass


def derive_keys(secret: int, exchange_hash: bytes, session_id: bytes):
    prefix = mpint(secret) + exchange_hash
    return tuple(hashlib.sha256(prefix + bytes([letter]) + session_id).digest()[:size]
                 for letter, size in zip(b'ABCDEF', (16, 16, 16, 16, 32, 32)))


class Direction:
    def __init__(self):
        self.sequence = 0
        self.cipher = None
        self.mac_key = None
        self.block_size = 8
        self.header = b''

    def install(self, iv: bytes, key: bytes, mac_key: bytes):
        self.cipher = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
        self.mac_key = mac_key
        self.block_size = 16

    def crypt(self, data: bytes) -> bytes:
        return self.cipher.update(data) if self.cipher else data

    def mac(self, packet: bytes):
        mac = hmac.HMAC(self.mac_key, hashes.SHA256())
        mac.update(uint32(self.sequence) + packet)
        return mac

    def advance(self):
        self.sequence = (self.sequence + 1) & 0xffffffff

    def encode(self, payload: bytes) -> bytes:
        padding = self.block_size - (len(payload) + 5) % self.block_size
        if padding < 4:
            padding += self.block_size
        packet = uint32(len(payload) + padding + 1) + bytes([padding]) + payload + os.urandom(padding)
        tag = self.mac(packet).finalize() if self.mac_key else b''
        result = self.crypt(packet) + tag
        self.advance()
        return result

    def decode(self, buffer: bytearray) -> bytes | None:
        # Retain the decrypted first block across partial TCP reads/timeouts.
        if not self.header:
            if len(buffer) < self.block_size:
                return None
            self.header = self.crypt(bytes(buffer[:self.block_size]))
            del buffer[:self.block_size]
        length = int.from_bytes(self.header[:4], 'big')
        if length < 6 or length > 1024 * 1024 or (length + 4) % self.block_size:
            raise BadPacket('invalid packet length')
        remaining = length + 4 - self.block_size
        mac_size = 32 if self.mac_key else 0
        if len(buffer) < remaining + mac_size:
            return None
        packet = self.header + self.crypt(bytes(buffer[:remaining]))
        if mac_size:
            try:
                self.mac(packet).verify(bytes(buffer[remaining:remaining + mac_size]))
            except InvalidSignature as exc:
                raise BadPacket('invalid MAC') from exc
        del buffer[:remaining + mac_size]
        self.header = b''
        padding = packet[4]
        if padding < 4 or padding >= length - 1:
            raise BadPacket('invalid padding')
        self.advance()
        return packet[5:-padding]
