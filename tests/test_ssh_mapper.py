"""Validation of the SSH mapper against real servers.

These tests are the oracle for the agent that writes the mapper:
a mapper that passes them completes real handshakes and is deterministic.
"""

import pytest

from smlearn.ssh.mapper import INPUTS, SSHMapper

HAPPY = ["KEXINIT", "KEX30", "NEWKEYS", "SR_AUTH", "UA_PW_OK", "CH_OPEN", "CH_CLOSE"]


@pytest.fixture
def mapper(ssh_instance):
    t = ssh_instance.target
    m = SSHMapper(ssh_instance.host, ssh_instance.port, user=t.user, password=t.password)
    yield m
    m.close()


def run(m, inputs):
    m.reset()
    return [m.step(i) for i in inputs]


def test_alphabet_is_complete():
    assert INPUTS == (
        "KEXINIT", "KEX30", "NEWKEYS", "SR_AUTH", "SR_CONN", "UA_PW_OK", "UA_PW_NOK", "UA_NONE",
        "CH_OPEN", "CH_CLOSE", "CH_EOF", "CH_DATA", "CH_REQUEST_EXEC",
        "IGNORE", "DEBUG", "UNIMPLEMENTED", "DISCONNECT",
    )


def test_happy_path_completes(mapper):
    out = run(mapper, HAPPY)
    assert out[0] == "NO_RESP"                 # server KEXINIT was absorbed by reset()
    assert out[1] == "KEX31+NEWKEYS"
    assert out[2] == "NO_RESP"
    assert "SERVICE_ACCEPT" in out[3].split("+")   # AsyncSSH sends IGNORE first
    assert "UA_SUCCESS" in out[4].split("+")
    assert "CH_OPEN_SUCCESS" in out[5].split("+")
    assert "CH_CLOSE" in out[6].split("+")


def test_strict_kex_is_negotiated(mapper):
    mapper.reset()
    assert mapper.strict_kex_active is True


def test_wrong_password_fails(mapper):
    out = run(mapper, ["KEXINIT", "KEX30", "NEWKEYS", "SR_AUTH", "UA_PW_NOK"])
    assert "UA_FAILURE" in out[4].split("+")


def test_session_works_after_auth(mapper):
    out = run(mapper, HAPPY[:-1] + ["CH_REQUEST_EXEC"])
    assert "CH_SUCCESS" in out[-1].split("+") or "CH_FAILURE" in out[-1].split("+")


def test_no_channel_sends_nothing(mapper):
    mapper.reset()
    assert mapper.step("CH_DATA") == "NO_CHANNEL"
    assert all(d == "<" for d, _, _ in mapper.trace)


def test_disconnect_then_no_conn(mapper):
    out = run(mapper, ["DISCONNECT", "KEXINIT", "IGNORE"])
    assert out[0].endswith("CLOSED")
    assert out[1:] == ["NO_CONN", "NO_CONN"]


def test_trace_records_packets(mapper):
    run(mapper, ["KEXINIT", "KEX30"])
    names = [(d, n) for d, n, _ in mapper.trace]
    assert (">", "KEXINIT") in names
    assert (">", "KEX30") in names
    assert ("<", "KEX31") in names


@pytest.mark.parametrize("seq", [
    HAPPY,
    ["KEX30", "KEXINIT", "NEWKEYS", "SR_AUTH"],
    ["KEXINIT", "IGNORE", "KEX30", "NEWKEYS", "SR_AUTH"],
    ["SR_AUTH", "UA_PW_OK", "CH_OPEN"],
    ["KEXINIT", "KEX30", "NEWKEYS", "SR_AUTH", "UA_PW_NOK", "UA_PW_NOK", "UA_PW_OK", "CH_OPEN", "CH_DATA", "CH_EOF"],
    ["KEXINIT", "KEX30", "NEWKEYS", "KEXINIT", "KEX30", "NEWKEYS", "SR_AUTH"],
    ["UNIMPLEMENTED", "DEBUG", "KEXINIT", "KEX30", "NEWKEYS", "SR_CONN"],
])
def test_queries_are_deterministic(mapper, seq):
    runs = [run(mapper, seq) for _ in range(3)]
    assert runs[0] == runs[1] == runs[2], runs


def test_newkeys_without_new_kex_keeps_keys(ssh_instance):
    """A NEWKEYS with no completed key exchange behind it must not re-install the old keys.

    OpenSSH refuses to rekey before authentication (UNIMPLEMENTED), so no new keys exist;
    the session must keep working under the current keys afterwards.
    Strict KEX is off here: with it on, OpenSSH 9.2p1 itself resets its receive sequence number
    on the rejected NEWKEYS (scripts/seqnr_experiment.py), which is server behaviour, not a mapper property.
    """
    if ssh_instance.target.name != "openssh":
        pytest.skip("relies on OpenSSH refusing a pre-auth rekey")
    t = ssh_instance.target
    mapper = SSHMapper(ssh_instance.host, ssh_instance.port, user=t.user, password=t.password, strict_kex=False)
    out = run(mapper, ["KEXINIT", "KEX30", "NEWKEYS", "SR_AUTH", "KEXINIT", "KEX30", "NEWKEYS", "UA_PW_OK"])
    mapper.close()
    assert out[4:7] == ["UNIMPLEMENTED"] * 3, out
    assert "UA_SUCCESS" in out[7].split("+"), out


def test_rekey_after_auth_installs_fresh_keys(mapper):
    out = run(mapper, ["KEXINIT", "KEX30", "NEWKEYS", "SR_AUTH", "UA_PW_OK",
                       "KEXINIT", "KEX30", "NEWKEYS", "CH_OPEN"])
    assert "KEXINIT" in out[5].split("+"), out
    assert "KEX31" in out[6].split("+") and "NEWKEYS" in out[6].split("+"), out
    assert "CH_OPEN_SUCCESS" in out[8].split("+"), out
