#!/usr/bin/env bash
# Build psm-dropbear:pinned and (re)start container psm-dropbear on 127.0.0.1:2202 (box only).
# Idempotent. Run from the repo root on the laptop:
#   ssh gx10 'bash -s' < suts/dropbear/run.sh        (needs the repo synced; uses ~/research/proto-sm)
#   ./gx bash suts/dropbear/run.sh                   (syncs code, runs on the box)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null || true
[ -f Dockerfile ] || cd "$HOME/research/proto-sm/suts/dropbear"
docker build -t psm-dropbear:pinned .
docker rm -f psm-dropbear >/dev/null 2>&1 || true
docker run -d --name psm-dropbear --restart unless-stopped \
  -p 127.0.0.1:2202:22 --memory 64m --cpus 0.5 psm-dropbear:pinned
sleep 1
sleep 1; bash ../authorize.sh psm-dropbear
docker ps --filter name=psm-dropbear --format '{{.Names}} {{.Status}} {{.Ports}}'
