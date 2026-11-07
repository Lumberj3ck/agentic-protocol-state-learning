"""Minimal Paramiko server using its native transport and algorithm defaults."""

import logging
import socketserver
import threading

import paramiko


HOST_KEY = paramiko.RSAKey.generate(2048)


class Server(paramiko.ServerInterface):
    def __init__(self):
        self.commands = set()
        self.lock = threading.Lock()

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        if username == "test" and password == "test":
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel, command):
        # Finish from the handler thread after Paramiko sends CHANNEL_SUCCESS.
        with self.lock:
            self.commands.add(channel.get_id())
        return True


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        transport = paramiko.Transport(self.request, strict_kex=True)
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
    with ThreadedServer(("0.0.0.0", 22), Handler) as server:
        server.serve_forever()
