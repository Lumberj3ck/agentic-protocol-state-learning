"""Offline checks for SSH binary encodings and encrypted packet boundaries."""
import hashlib

import pytest

from smlearn.ssh.packet import BadPacket, Direction, derive_keys
from smlearn.ssh.mapper import SSHMapper
from smlearn.ssh.wire import Reader, mpint, string, uint32


@pytest.mark.parametrize(('value', 'encoded'), [
    (0, '00000000'), (127, '000000017f'), (128, '000000020080'),
    (-1, '00000001ff'), (-129, '00000002ff7f'),
])
def test_mpint(value, encoded):
    assert mpint(value).hex() == encoded


def test_fields():
    reader = Reader(uint32(42) + string('hello'))
    assert reader.uint32() == 42
    assert reader.string() == b'hello'
    with pytest.raises(ValueError):
        reader.string()


def test_key_derivation():
    # Independent preimage: positive 0x80 needs a sign byte in the mpint.
    keys = derive_keys(128, b'hash', b'first hash')
    for key, letter, size in zip(keys, b'ABCDEF', (16, 16, 16, 16, 32, 32)):
        assert key == hashlib.sha256(b'\0\0\0\2\0\x80hash' + bytes([letter]) + b'first hash').digest()[:size]
    assert derive_keys(128, b'hash', b'other session') != keys


@pytest.mark.parametrize('encrypted', [False, True])
def test_fragmented_packets(encrypted):
    sender, receiver = Direction(), Direction()
    if encrypted:
        for direction in (sender, receiver):
            direction.install(bytes(16), bytes(range(16)), bytes(range(32)))
    payloads = [b'\x02' + string(b''), b'\x5e' + string(b'x' * 100)]
    encoded = b''.join(sender.encode(p) for p in payloads)
    buffer, decoded = bytearray(), []
    for byte in encoded:
        buffer.append(byte)
        packet = receiver.decode(buffer)
        if packet is not None:
            decoded.append(packet)
    assert decoded == payloads
    assert sender.sequence == receiver.sequence == 2
    assert not buffer


def test_bad_mac():
    sender, receiver = Direction(), Direction()
    for direction in (sender, receiver):
        direction.install(bytes(16), bytes(16), bytes(32))
    packet = bytearray(sender.encode(b'\x15'))
    packet[-1] ^= 1
    with pytest.raises(BadPacket, match='MAC'):
        receiver.decode(packet)


@pytest.mark.parametrize('strict', [False, True])
def test_kexinit_offers_both_curve25519_names(strict):
    mapper = SSHMapper('unused', 0, strict_kex=strict)
    payload = mapper._payload('KEXINIT')
    reader = Reader(payload)
    assert reader.take(17) == b'\x14' + bytes(16)
    expected = [b'curve25519-sha256', b'curve25519-sha256@libssh.org']
    if strict:
        expected.append(b'kex-strict-c-v00@openssh.com')
    assert reader.string().split(b',') == expected
    assert mapper.client_kex == payload


@pytest.mark.parametrize('strict', [False, True])
@pytest.mark.parametrize('initial_marker', [False, True])
def test_strict_kex_uses_only_first_server_kexinit(strict, initial_marker):
    mapper = SSHMapper('unused', 0, strict_kex=strict)

    # Build server offers independently of whether the client enables strict KEX.
    offer = SSHMapper('unused', 0)._payload('KEXINIT')
    with_marker = offer.replace(b'kex-strict-c-v00@openssh.com',
                                b'kex-strict-s-v00@openssh.com')
    without_marker = SSHMapper('unused', 0, strict_kex=False)._payload('KEXINIT')
    for marker in (initial_marker, not initial_marker, initial_marker):
        payload = with_marker if marker else without_marker
        mapper._received(payload)
        assert mapper.server_kex == payload
        assert mapper.strict_kex_active == (strict and initial_marker)
        # Rekeys must continue to reset both sequence numbers in strict mode.
        mapper.pending = {True: (bytes(16), bytes(16), bytes(32)),
                          False: (bytes(16), bytes(16), bytes(32))}
        for outgoing in (True, False):
            direction = Direction()
            direction.sequence = 7
            mapper._install(direction, outgoing)
            assert direction.sequence == (0 if strict and initial_marker else 7)


@pytest.mark.parametrize('strict', [False, True])
@pytest.mark.parametrize('first', [False, True])
def test_pending_keys_consumed_per_direction(strict, first):
    mapper = SSHMapper('unused', 0)
    mapper.strict_kex_active = strict
    a, b, c, d, e, f = derive_keys(128, b'hash', b'session')
    pending = {True: (a, c, e), False: (b, d, f)}
    mapper.pending = pending.copy()
    directions = {True: Direction(), False: Direction()}

    for outgoing in (first, not first):
        direction = directions[outgoing]
        direction.sequence = 7
        mapper._install(direction, outgoing)
        assert outgoing not in mapper.pending
        assert direction.sequence == (0 if strict else 7)
        peer = Direction()
        peer.install(*pending[outgoing])
        peer.sequence = direction.sequence

        # Exercise both streams before and after an extra NEWKEYS installation.
        for _ in range(2):
            payload = b'\x15'
            if outgoing:
                assert peer.decode(bytearray(direction.encode(payload))) == payload
            else:
                assert direction.decode(bytearray(peer.encode(payload))) == payload
            cipher, sequence = direction.cipher, direction.sequence
            mapper._install(direction, outgoing)
            assert direction.cipher is cipher
            assert direction.sequence == sequence

        if outgoing == first:
            assert mapper.pending == {not first: pending[not first]}
    assert mapper.pending == {}
