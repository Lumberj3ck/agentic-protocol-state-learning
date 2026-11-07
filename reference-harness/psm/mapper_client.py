"""Client for the ssh-fuzzer mapper's line protocol (vendor/ssh-fuzzer/ssh-mapper/mapper/mapper.py).

One line per request: 'reset', a single input symbol, or 'reset S1 S2 ... Sn'.
One line per reply: space-separated outputs, 'resetok' for each reset.
"""
from __future__ import annotations

import socket
import time


class MapperClient:
    def __init__(self, host: str, port: int, timeout: float = 120.0):
        self.addr = (host, port)
        self.timeout = timeout
        self._connect()

    def _connect(self):
        self.sock = socket.create_connection(self.addr, timeout=self.timeout)
        self.rfile = self.sock.makefile("rb")

    def _request(self, line: str) -> list[str]:
        self.sock.sendall((line + "\n").encode())
        reply = self.rfile.readline()
        if not reply:
            raise ConnectionError(f"mapper closed the connection after {line!r}")
        return reply.decode().split()

    def reconnect(self, wait: float = 60.0):
        """The mapper container restarts itself after a crash; wait for it to listen again."""
        try:
            self.sock.close()
        except OSError:
            pass
        deadline = time.time() + wait
        while True:
            try:
                self._connect()
                return
            except OSError:
                if time.time() > deadline:
                    raise
                time.sleep(1)

    def reset(self) -> None:
        r = self._request("reset")
        if r != ["resetok"]:
            raise RuntimeError(f"unexpected reset reply {r!r}")

    def step(self, symbol: str) -> str:
        r = self._request(symbol)
        if len(r) != 1:
            raise RuntimeError(f"expected one output for {symbol!r}, got {r!r}")
        return r[0]

    def query(self, word) -> list[str]:
        r = self._request("reset " + " ".join(word))
        if not r or r[0] != "resetok" or len(r) != len(word) + 1:
            raise RuntimeError(f"bad reply {r!r} for {word!r}")
        return r[1:]

    def close(self):
        self.sock.close()
