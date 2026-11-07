%% Erlang/OTP ssh daemon for stream B1. Adapted from vendor/agentic-protocol-state-learning/targets/erlang-otp (Apache-2.0).
-module(server).
-export([start/0]).

start() ->
    {ok, _} = application:ensure_all_started(ssh),
    SystemDir = "/tmp/ssh-host-keys",
    ok = file:make_dir(SystemDir),
    Key = public_key:generate_key({rsa, 3072, 65537}),
    Pem = public_key:pem_encode([public_key:pem_entry_encode('RSAPrivateKey', Key)]),
    KeyFile = filename:join(SystemDir, "ssh_host_rsa_key"),
    ok = file:write_file(KeyFile, Pem),
    ok = file:change_mode(KeyFile, 8#600),
    {ok, _} = ssh:daemon(22, [
        {system_dir, SystemDir},
        {user_dir, "/etc/psm"},
        {auth_methods, "publickey,password"},
        {user_passwords, [{"tester", "correct-horse-battery"}]},
        {shell, disabled},
        {exec, {direct, fun(_Command) -> {ok, "ok\n"} end}}
    ]),
    receive stop -> ok end.
