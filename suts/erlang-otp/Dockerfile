# Erlang/OTP ssh SUT (stream B1). Adapted from vendor/agentic-protocol-state-learning/targets/erlang-otp (Apache-2.0).
FROM erlang:29.1.2.0-slim@sha256:2110a9edc88a9788c07069e78fab3662fc91477b7902433a8b8bad9c852b0d1b
WORKDIR /app
RUN mkdir -p /etc/psm && touch /etc/psm/authorized_keys
COPY server.erl /app/server.erl
RUN erlc server.erl
EXPOSE 22
CMD ["erl", "-noshell", "-pa", "/app", "-s", "server", "start"]
