"""Minimal Paramiko server for stream B1. Adapted from the teammate's targets/paramiko/server.py
(vendor/agentic-protocol-state-learning, Apache-2.0): user tester, password + publickey, RSA host key, library defaults."""
import base64
import logging
import socketserver
import threading

import paramiko

HOST_KEY = paramiko.RSAKey.generate(3072)
USER, PASSWORD = "tester", "correct-horse-battery"


def authorized_blobs():
    out = []
    try:
        for line in open("/etc/psm/authorized_keys"):
            p = line.split()
            if len(p) >= 2:
                out.append(base64.b64decode(p[1]))
    except OSError:
        pass
    return out


class Server(paramiko.ServerInterface):
    def __init__(self):
        self.commands = set()
        self.lock = threading.Lock()

    def get_allowed_auths(self, username):
        return "publickey,password"

    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL if (username, password) == (USER, PASSWORD) else paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        if username == USER and key.asbytes() in authorized_blobs():
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel, command):
        with self.lock:
            self.commands.add(channel.get_id())
        return True


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        transport = paramiko.Transport(self.request)  # library defaults (strict kex is on by default in this paramiko)
        transport.add_server_key(HOST_KEY)
        server = Server()
        channels = []
        try:
            transport.start_server(server=server)
            while transport.is_active():
                channel = transport.accept(timeout=0.05)
                if channel is not None:
                    channels.append(channel)
                for channel in channels[:]:
                    with server.lock:
                        executed = channel.get_id() in server.commands
                        server.commands.discard(channel.get_id())
                    if executed and not channel.closed:
                        channel.send_exit_status(0)
                        channel.close()
                    if channel.closed:
                        channels.remove(channel)
        except (EOFError, OSError, paramiko.SSHException) as exc:
            logging.info("Connection ended: %s", exc)
        finally:
            transport.close()


class ThreadedServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    logging.getLogger("paramiko").setLevel(logging.DEBUG)
    with ThreadedServer(("0.0.0.0", 22), Handler) as server:
        server.serve_forever()
