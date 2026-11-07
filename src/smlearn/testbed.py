"""Start and stop target implementations as local Docker containers.

Every container publishes its port on 127.0.0.1 only, on a random host port,
so many instances of the same target can run side by side.
"""

import json
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

TARGETS_DIR = Path(__file__).resolve().parents[2] / "targets"


@dataclass
class Target:
    name: str
    implementation: str
    source: str
    port: int
    user: str = "test"
    password: str = "test"

    @property
    def image(self) -> str:
        return f"smlearn-{self.name}"


def load_target(name: str) -> Target:
    data = json.loads((TARGETS_DIR / name / "target.json").read_text())
    return Target(**{k: data[k] for k in Target.__dataclass_fields__ if k in data})


def list_targets() -> list[str]:
    return sorted(p.parent.name for p in TARGETS_DIR.glob("*/target.json"))


def build(target: Target) -> None:
    subprocess.run(["docker", "build", "-q", "-t", target.image, str(TARGETS_DIR / target.name)],
                   check=True, capture_output=True)


@dataclass
class Instance:
    target: Target
    container_id: str
    host: str
    port: int

    def stop(self) -> None:
        subprocess.run(["docker", "rm", "-f", self.container_id], capture_output=True)

    def logs(self) -> str:
        r = subprocess.run(["docker", "logs", self.container_id], capture_output=True, text=True)
        return r.stdout + r.stderr


def start(target: Target, ready_timeout: float = 30.0) -> Instance:
    """Run one container and wait until it sends an SSH identification line."""
    cid = subprocess.run(
        ["docker", "run", "-d", "--rm", "--label", "smlearn=1",
         "-p", f"127.0.0.1::{target.port}", target.image],
        check=True, capture_output=True, text=True).stdout.strip()
    out = subprocess.run(["docker", "port", cid, f"{target.port}/tcp"],
                         check=True, capture_output=True, text=True).stdout
    host_port = int(out.splitlines()[0].rsplit(":", 1)[1])
    inst = Instance(target, cid, "127.0.0.1", host_port)
    deadline = time.monotonic() + ready_timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((inst.host, inst.port), timeout=2) as s:
                if s.recv(256).startswith(b"SSH-"):
                    return inst
        except OSError:
            pass
        time.sleep(0.3)
    logs = inst.logs()
    inst.stop()
    raise RuntimeError(f"{target.name} did not become ready:\n{logs}")
