from psm.class_matrix import cells


def test_cells_take_output_at_divergence_index_and_flag_odd_prefix():
    replay = {"sequences": [
        {"sequence": ["KEXINIT", "KEX30", "KEX30"], "results": {
            "x": {"deterministic": True, "distinct": [{"outputs": ["KEXINIT", "KEX31+NEWKEYS", "UNIMPL"], "count": 3}]},
            "y": {"deterministic": True, "distinct": [{"outputs": ["KEXINIT", "NO_CONN", "NO_CONN"], "count": 3}]}}}]}
    div = {"KEXINIT KEX30 KEX30": 2, "_prefix": {"KEXINIT KEX30 KEX30": ["KEXINIT", "KEX31+NEWKEYS"]}}
    c = cells(replay, div, {})
    assert c["x"]["D7"] == "UNIMPL"
    assert c["y"]["D7"].startswith("NO_CONN (prefix differs")
