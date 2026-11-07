"""Minimal AsyncSSH server for stream B1 (adapted from the teammate's targets/asyncssh/server.py, Apache-2.0)."""
import asyncio, logging, asyncssh

class Server(asyncssh.SSHServer):
    def begin_auth(self, username): return True
    def password_auth_supported(self): return True
    def validate_password(self, username, password): return username == "tester" and password == "correct-horse-battery"
    def public_key_auth_supported(self): return True

async def handle(process):
    process.stdout.write("ok\n")
    process.exit(0)

async def main():
    key = asyncssh.generate_private_key("ssh-rsa", key_size=3072)
    await asyncssh.create_server(Server, "", 22, server_host_keys=[key], process_factory=handle,
                                 authorized_client_keys="/etc/psm/authorized_keys")
    await asyncio.Event().wait()

logging.basicConfig(level=logging.DEBUG)
asyncssh.set_log_level("DEBUG")
asyncio.run(main())
