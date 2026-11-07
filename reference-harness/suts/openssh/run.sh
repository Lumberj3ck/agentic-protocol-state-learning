#!/usr/bin/env bash
# Build image psm-openssh:pinned and (re)start container psm-openssh on 127.0.0.1:2201 (box only).
# Idempotent. Run from repo root:  ssh gx10 'cd ~/research/proto-sm && bash suts/openssh/run.sh'
# (after ./gx true has synced the code), or:  ./gx bash suts/openssh/run.sh
set -euo pipefail
cd "$(dirname "$0")"
docker build -q -t psm-openssh:pinned .
docker rm -f psm-openssh >/dev/null 2>&1 || true
docker run -d --name psm-openssh --restart unless-stopped -p 127.0.0.1:2201:22 \
  --memory 128m --cpus 1 psm-openssh:pinned
sleep 1
sleep 1; bash ../authorize.sh psm-openssh
docker ps --filter name=^psm-openssh$ --format '{{.Names}} {{.Status}} {{.Ports}}'
