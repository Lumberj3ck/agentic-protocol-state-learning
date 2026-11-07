"""SSH primitive encodings (RFC 4251 section 5)."""
import struct


def uint32(value: int) -> bytes:
    return struct.pack('>I', value & 0xffffffff)


def string(value: bytes | str) -> bytes:
    if isinstance(value, str):
        value = value.encode()
    return uint32(len(value)) + value


def mpint(value: int) -> bytes:
    if value == 0:
        return string(b'')
    size = (value.bit_length() + 8) // 8
    return string(value.to_bytes(size, 'big', signed=True))


class Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def take(self, size: int) -> bytes:
        end = self.offset + size
        if end > len(self.data):
            raise ValueError('truncated SSH field')
        result = self.data[self.offset:end]
        self.offset = end
        return result

    def uint32(self) -> int:
        return int.from_bytes(self.take(4), 'big')

    def string(self) -> bytes:
        return self.take(self.uint32())
