#!/usr/bin/env bash
# Stream B1: build psm-b1-<impl>:pinned and (re)start container psm-b1-<impl> on 127.0.0.1:<port> (box only).
# Usage: bash suts/b1/run.sh <impl> <port> [memory]      (impl = directory under suts/, e.g. paramiko)
# Installs keys/id_rsa.pub as /etc/psm/authorized_keys (read on demand by every B1 server).
set -euo pipefail
IMPL=$1; PORT=$2; MEM=${3:-256m}
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
df -h / | tail -1
FREE=$(df -BG --output=avail / | tail -1 | tr -dc 0-9)
[ "$FREE" -ge 8 ] || { echo "STOP: free disk ${FREE}G < 8G"; exit 3; }
cd "$ROOT/suts/$IMPL"
docker build -t "psm-b1-$IMPL:pinned" .
docker rm -f "psm-b1-$IMPL" >/dev/null 2>&1 || true
docker run -d --name "psm-b1-$IMPL" --restart unless-stopped -p "127.0.0.1:$PORT:22" --memory "$MEM" --cpus 1 "psm-b1-$IMPL:pinned"
sleep 3
docker exec "psm-b1-$IMPL" mkdir -p /etc/psm 2>/dev/null || true
docker cp "$ROOT/keys/id_rsa.pub" "psm-b1-$IMPL:/etc/psm/authorized_keys"
docker ps --filter "name=^psm-b1-$IMPL\$" --format '{{.Names}} {{.Status}} {{.Ports}}'
docker image inspect "psm-b1-$IMPL:pinned" --format '{{.Id}}'
