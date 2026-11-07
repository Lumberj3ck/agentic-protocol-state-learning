#!/usr/bin/env bash
# Build psm-dropbear2022:pinned and (re)start psm-dropbear2022 on 127.0.0.1:2222 (box only).  ./gx bash suts/dropbear-2020.81/run.sh
set -euo pipefail
cd "$(dirname "$0")"
docker build -q -t psm-dropbear2022:pinned .
docker rm -f psm-dropbear2022 >/dev/null 2>&1 || true
docker run -d --name psm-dropbear2022 --restart unless-stopped -p 127.0.0.1:2222:22 --memory 64m --cpus 0.5 psm-dropbear2022:pinned >/dev/null
bash ../authorize.sh psm-dropbear2022
docker ps --filter name=psm-dropbear2022 --format '{{.Names}} {{.Status}} {{.Ports}}'
