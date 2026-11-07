#!/usr/bin/env bash
# Build psm-dropbear2020:pinned and (re)start psm-dropbear2020 on 127.0.0.1:2212 (box only).  ./gx bash suts/dropbear-2020.81/run.sh
set -euo pipefail
cd "$(dirname "$0")"
docker build -q -t psm-dropbear2020:pinned .
docker rm -f psm-dropbear2020 >/dev/null 2>&1 || true
docker run -d --name psm-dropbear2020 --restart unless-stopped -p 127.0.0.1:2212:22 --memory 64m --cpus 0.5 psm-dropbear2020:pinned >/dev/null
bash ../authorize.sh psm-dropbear2020
docker ps --filter name=psm-dropbear2020 --format '{{.Names}} {{.Status}} {{.Ports}}'
