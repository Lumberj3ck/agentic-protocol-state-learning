"""Stock paramiko login check for a B1 SUT: password and publickey, then exec; prints server KEXINIT algorithms.
Usage: .venv/bin/python suts/b1/verify.py <port>"""
import sys, paramiko
port = int(sys.argv[1])
for mode in ("password", "publickey"):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        kw = dict(password="correct-horse-battery") if mode == "password" else dict(key_filename="keys/id_rsa")
        c.connect("127.0.0.1", port, username="tester", look_for_keys=False, allow_agent=False, timeout=15, banner_timeout=15, auth_timeout=15, **kw)
        t = c.get_transport()
        try:
            _i, o, e = c.exec_command("true", timeout=10); out = o.read(); rc = o.channel.recv_exit_status()
        except Exception as ex:
            out, rc = repr(ex), None
        print(mode, "AUTH_OK", "kex=", t.kex_engine.__class__.__name__ if hasattr(t,'kex_engine') and t.kex_engine else None,
              "hostkey=", t.get_remote_server_key().get_name(), "exec_out=", out, "rc=", rc)
    except Exception as ex:
        print(mode, "FAIL", repr(ex))
    finally:
        c.close()
