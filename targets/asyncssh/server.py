import asyncio, asyncssh

class Server(asyncssh.SSHServer):
    def begin_auth(self, username): return True
    def password_auth_supported(self): return True
    def validate_password(self, username, password): return username == "test" and password == "test"

async def handle(process):
    process.stdout.write("ok\n")
    process.exit(0)

async def main():
    key = asyncssh.generate_private_key("ssh-ed25519")
    await asyncssh.create_server(Server, "", 22, server_host_keys=[key], process_factory=handle)
    await asyncio.Event().wait()

asyncio.run(main())
