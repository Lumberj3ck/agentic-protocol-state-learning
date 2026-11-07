"""Equivalence oracle with a targeted, documented check plus random walks.

Random walks rarely reach deep paths such as "authenticate, then rekey, then probe" (9+ inputs), which is exactly
where the first Dropbear model was wrong (results/checks/dropbear2020_v1.json). So before random walks, for every
hypothesis state we test  access(state) + middle + suffix  for middle in {(), rekey} and every suffix of length <= depth.
RFC 4253 §9 implies a rekey should not change the session's authentication state, so this is where an under-learned
model is most likely to have merged states.
"""
from __future__ import annotations

from itertools import product

from aalpy.base import Oracle


class RekeyAwareOracle(Oracle):
    def __init__(self, alphabet, sul, fallback=None, rekey=("KEXINIT", "KEX30", "NEWKEYS"), depth: int = 2):
        super().__init__(alphabet, sul)
        self.fallback, self.rekey, self.depth = fallback, tuple(rekey), depth
        self.targeted_tests = 0

    def _words(self, hypothesis):
        suffixes = [()]
        for d in range(1, self.depth + 1):
            suffixes += list(product(self.alphabet, repeat=d))
        for state in sorted(hypothesis.states, key=lambda s: (len(s.prefix or ()), str(s.state_id))):
            if state.prefix is None:
                state.prefix = hypothesis.get_shortest_path(hypothesis.initial_state, state)
            for middle in ((), self.rekey):
                for suf in suffixes:
                    w = tuple(state.prefix) + middle + suf
                    if w:
                        yield w

    def find_cex(self, hypothesis):
        seen = set()
        for w in self._words(hypothesis):
            if w in seen:
                continue
            seen.add(w)
            self.targeted_tests += 1
            self.num_queries += 1
            self.num_steps += len(w)
            observed = self.sul.query(w)
            hypothesis.reset_to_initial()
            for i, x in enumerate(w):
                if hypothesis.step(x) != observed[i]:
                    return w[:i + 1]
        return self.fallback.find_cex(hypothesis) if self.fallback else None
