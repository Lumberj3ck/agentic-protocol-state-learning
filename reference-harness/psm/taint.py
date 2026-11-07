"""Mark where a trace stops being trustworthy because of a known mapper limitation.

The published mapper, on a NEWKEYS input with no completed key exchange since the last NEWKEYS (no KEX31 seen),
re-derives the old keys and resets its AES-CTR counter, so every later message it sends is garbage to the server
(results/review/remaining_classes.md). Outputs from the input AFTER such a NEWKEYS on are harness artifacts.
"""
from __future__ import annotations


def first_tainted_index(seq, outputs):
    """Index of the first input whose output is not trustworthy, or None."""
    fresh = False  # a KEX31 arrived since the last NEWKEYS we sent
    for i, (x, o) in enumerate(zip(seq, outputs)):
        if "KEX31" in o:
            fresh = True
        if x == "NEWKEYS":
            if not fresh and i + 1 < len(seq):
                return i + 1
            fresh = False
    return None


def tainted(seq, outputs) -> bool:
    return first_tainted_index(seq, outputs) is not None
