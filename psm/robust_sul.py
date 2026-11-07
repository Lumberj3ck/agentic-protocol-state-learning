"""AALpy SUL over the mapper, with a prefix cache, a NO_CONN sink shortcut, and repetition-based
nondeterminism detection. Nondeterminism is resolved by majority vote and always logged
(log_dir/nondet.jsonl), so it is visible instead of silently corrupting the learned model."""
from __future__ import annotations

import json
import random
import time
from collections import Counter
from pathlib import Path

from aalpy.base import SUL


class RobustSUL(SUL):
    def __init__(self, client, log_dir, repeats: int = 4, repeat_prob: float = 0.1,
                 sink: str = "NO_CONN", seed: int = 0):
        super().__init__()
        self.client, self.repeats, self.repeat_prob, self.sink = client, repeats, repeat_prob, sink
        self.rng = random.Random(seed)
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.cache: dict[tuple, tuple] = {}
        self.stats = Counter()
        self.word: list = []
        self.outs: list = []
        self.live = False

    # ---- cache -------------------------------------------------------------------
    def _store(self, word, outs):
        for i in range(1, len(word) + 1):
            self.cache[tuple(word[:i])] = tuple(outs[:i])

    def _conflicts(self, word, outs):
        for i in range(1, len(word) + 1):
            c = self.cache.get(tuple(word[:i]))
            if c is not None and c != tuple(outs[:i]):
                return c
        return None

    def lookup(self, word):
        word = tuple(word)
        if word in self.cache:
            self.stats["cache_hits"] += 1
            return list(self.cache[word])
        for i in range(len(word) - 1, 0, -1):
            c = self.cache.get(word[:i])
            if c is not None and c[-1] == self.sink:
                self.stats["sink_shortcuts"] += 1
                return list(c) + [self.sink] * (len(word) - i)
        return None

    # ---- execution -----------------------------------------------------------------
    def _harness_error(self, word, err):
        self.stats["harness_errors"] += 1
        with open(self.log_dir / "harness_errors.jsonl", "a") as f:
            f.write(json.dumps({"time": time.strftime("%H:%M:%S"), "word": list(word), "error": repr(err)}) + "\n")
        self.live = False
        self.client.reconnect()

    def _exec(self, word, attempts: int = 3):
        for i in range(attempts):
            self.stats["sut_queries"] += 1
            self.stats["sut_steps"] += len(word)
            try:
                return tuple(self.client.query(list(word)))
            except (ConnectionError, OSError) as e:  # mapper crashed: log, reconnect, retry
                self._harness_error(word, e)
                if i == attempts - 1:
                    raise

    def _resolve(self, word, observations, previously_cached=None):
        """Re-run `word` until we have `repeats` extra observations; majority wins; log everything."""
        obs = list(observations)
        for _ in range(self.repeats):
            obs.append(self._exec(word))
        counts = Counter(obs)
        chosen, n = counts.most_common(1)[0]
        self.stats["nondet_events"] += 1
        event = {"time": time.strftime("%H:%M:%S"), "word": list(word),
                 "observations": [{"outputs": list(o), "count": c} for o, c in counts.items()],
                 "chosen": list(chosen), "majority_fraction": n / len(obs),
                 "previously_cached": list(previously_cached) if previously_cached else None}
        with open(self.log_dir / "nondet.jsonl", "a") as f:
            f.write(json.dumps(event) + "\n")
        # Drop cached extensions that disagree with the chosen prefix, then store the majority.
        for k in [k for k in self.cache if k[:len(word)] == tuple(word) and self.cache[k][:len(word)] != chosen]:
            del self.cache[k]
        for i in range(1, len(word) + 1):
            self.cache.pop(tuple(word[:i]), None)
        self._store(word, chosen)
        self.live = False  # the mapper's connection may be on a minority path
        return list(chosen)

    def _run(self, word):
        outs = self._exec(word)
        old = self._conflicts(word, outs)
        if old is not None:
            return self._resolve(word, [outs], previously_cached=old)
        if self.repeat_prob and self.rng.random() < self.repeat_prob:
            self.stats["random_repeats"] += 1
            again = self._exec(word)
            if again != outs:
                return self._resolve(word, [outs, again])
        self._store(word, outs)
        self.live = True
        return list(outs)

    # ---- AALpy interface -----------------------------------------------------------
    def query(self, word):
        self.num_queries += 1
        self.num_steps += len(word)
        self.live = False
        ans = self.lookup(word)
        if ans is None:
            ans = self._run(tuple(word))
        self.live = False
        return ans

    def pre(self):
        self.word, self.outs, self.live = [], [], False

    def post(self):
        self.live = False

    def step(self, letter):
        self.num_steps += 1
        self.word.append(letter)
        w = tuple(self.word)
        if not self.live:
            ans = self.lookup(w)
            if ans is None:
                ans = self._run(w)
            self.outs = list(ans)
            return ans[-1]
        # Live session positioned after w[:-1].
        if self.outs and self.outs[-1] == self.sink:
            o = self.sink
        else:
            self.stats["sut_steps"] += 1
            try:
                o = self.client.step(letter)
            except (ConnectionError, OSError) as e:
                self._harness_error(w, e)
                ans = self._run(w)
                self.outs = list(ans)
                return ans[-1]
        cached = self.cache.get(w)
        if cached is not None and cached[-1] != o:
            ans = self._resolve(w, [tuple(self.outs) + (o,)], previously_cached=cached)
            self.outs = list(ans)
            return ans[-1]
        self.outs.append(o)
        self._store(w, self.outs)
        return o

    def save_cache(self, path):
        Path(path).write_text(json.dumps([[list(k), list(v)] for k, v in self.cache.items()]))
