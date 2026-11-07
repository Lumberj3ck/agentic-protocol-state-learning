#!/usr/bin/env bash
# Build image psm-gossh:pinned and (re)start container psm-gossh on 127.0.0.1:2203 (box only).
# Idempotent. Run from repo root:  ./gx bash suts/gossh/run.sh
# (or, after code is synced: ssh gx10 'cd ~/research/proto-sm && bash suts/gossh/run.sh').
# Logs: ssh gx10 docker logs psm-gossh
set -euo pipefail
cd "$(dirname "$0")"
docker build -q -t psm-gossh:pinned .
docker rm -f psm-gossh >/dev/null 2>&1 || true
docker run -d --name psm-gossh --restart unless-stopped -p 127.0.0.1:2203:22 \
  --memory 128m --cpus 1 psm-gossh:pinned
sleep 1
sleep 1; bash ../authorize.sh psm-gossh
docker ps --filter name=^psm-gossh$ --format '{{.Names}} {{.Status}} {{.Ports}}'
