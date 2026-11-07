from psm.taint import first_tainted_index


def test_normal_handshake_and_rekey_are_clean():
    seq = ["KEXINIT", "KEX30", "NEWKEYS", "SR_AUTH", "UA_PK_OK", "KEXINIT", "KEX30", "NEWKEYS", "SR_AUTH"]
    out = ["KEXINIT", "KEX31+NEWKEYS+EXT_INFO", "NO_RESP", "SR_ACCEPT", "UA_SUCCESS", "KEXINIT", "KEX31+NEWKEYS",
           "NO_RESP", "SR_ACCEPT"]
    assert first_tainted_index(seq, out) is None


def test_newkeys_without_kex_reply_taints_everything_after_it():
    # NEWKEYS before any KEX31: the mapper corrupts its own outbound stream from the NEXT input on.
    seq = ["KEXINIT", "NEWKEYS", "SR_AUTH", "KEX30"]
    out = ["KEXINIT", "UNIMPL", "NO_RESP", "NO_CONN"]
    assert first_tainted_index(seq, out) == 2


def test_refused_rekey_then_newkeys_taints():
    # OpenSSH refuses pre-auth rekey (UNIMPL, no KEX31); the mapper's NEWKEYS then re-derives old keys.
    seq = ["KEXINIT", "KEX30", "NEWKEYS", "KEXINIT", "KEX30", "NEWKEYS", "SR_AUTH"]
    out = ["KEXINIT", "KEX31+NEWKEYS+EXT_INFO", "NO_RESP", "UNIMPL", "UNIMPL", "UNIMPL", "NO_RESP"]
    assert first_tainted_index(seq, out) == 6


def test_newkeys_as_last_input_is_not_tainted():
    assert first_tainted_index(["KEXINIT", "NEWKEYS"], ["KEXINIT", "UNIMPL"]) is None


def test_second_newkeys_after_one_kex_taints():
    seq = ["KEXINIT", "KEX30", "NEWKEYS", "NEWKEYS", "SR_AUTH"]
    out = ["KEXINIT", "KEX31+NEWKEYS", "NO_RESP", "NO_RESP", "NO_RESP"]
    assert first_tainted_index(seq, out) == 4


def _entry(seq, outs_by_server, det=True):
    return {"sequence": seq, "results": {n: {"deterministic": det, "distinct": [{"outputs": o, "count": 5}]}
                                          for n, o in outs_by_server.items()}}


def test_verify_classifies_reportable_tainted_agree_nondet():
    from psm.verify import classify
    rep = classify(_entry(["KEXINIT", "KEX30", "NEWKEYS", "UA_PK_OK"], {
        "a": ["KEXINIT", "KEX31", "NO_RESP", "UNIMPL"], "b": ["KEXINIT", "KEX31", "NO_RESP", "UA_SUCCESS"]}))
    assert rep["status"] == "reportable" and rep["divergence_index"] == 3
    assert rep["groups"] == {"UNIMPL": ["a"], "UA_SUCCESS": ["b"]}
    taint = classify(_entry(["KEXINIT", "NEWKEYS", "SR_AUTH"], {
        "a": ["KEXINIT", "UNIMPL", "NO_RESP"], "b": ["KEXINIT", "UNIMPL", "SR_ACCEPT"]}))
    assert taint["status"] == "discarded" and "tainted" in taint["reason"]
    agree = classify(_entry(["KEXINIT"], {"a": ["KEXINIT"], "b": ["KEXINIT"]}))
    assert agree["status"] == "agree"
    nd = classify(_entry(["KEXINIT"], {"a": ["KEXINIT"], "b": ["KEXINIT"]}, det=False))
    assert nd["status"] == "discarded" and "nondeterministic" in nd["reason"]


def test_verify_normalization_moves_divergence_past_extension_message():
    from psm.verify import classify
    e = _entry(["UA_PK_OK", "SR_AUTH"], {"o": ["UA_SUCCESS+GLOBAL_REQUEST", "UNIMPL"], "d": ["UA_SUCCESS", "SR_ACCEPT"]})
    r = classify(e, {"UA_SUCCESS+GLOBAL_REQUEST": "UA_SUCCESS"})
    assert r["divergence_index"] == 1 and r["raw_outputs"]["o"][0] == "UA_SUCCESS+GLOBAL_REQUEST"
