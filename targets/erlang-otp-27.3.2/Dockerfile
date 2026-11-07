FROM erlang:27.3.2.0-slim@sha256:eb71f4d1c00ef759d72b2160655c02bd74888713e9e47bed49532da2fe3edd8d

WORKDIR /app
COPY server.erl /app/server.erl
RUN test "$(cat /usr/local/lib/erlang/releases/27/OTP_VERSION)" = "27.3.2" \
    && erlc server.erl
EXPOSE 22
CMD ["erl", "-noshell", "-pa", "/app", "-s", "server", "start"]
