#!/usr/bin/env bash
# Stream A copy of harness/start_mapper.sh with container name psm-a-mapper-<name> (prefix rule psm-a-).
# Usage: bash scripts_v2/a_start_mapper.sh <name> <listen_port 84xx> <sut_port> <timing_config> [PSM_ALGOS]
set -euo pipefail
cd "$(dirname "$0")/.."
NAME=$1; LPORT=$2; SPORT=$3; CFG=$4; ALGOS=${5:-legacy}
docker image inspect psm-mapper:pinned >/dev/null 2>&1 || { echo "psm-mapper:pinned missing" >&2; exit 1; }
docker rm -f "psm-a-mapper-$NAME" >/dev/null 2>&1 || true
docker run -d --name "psm-a-mapper-$NAME" --network host --restart unless-stopped --memory 256m --cpus 1 \
  -v "$PWD/vendor/ssh-fuzzer/ssh-mapper:/app:ro" -v "$PWD/keys:/home/mapper/.ssh:ro" \
  -e PSM_USER=tester -e PSM_PASS=correct-horse-battery -e PSM_BADPASS=wrong-password -e PSM_ALGOS="$ALGOS" \
  psm-mapper:pinned -l "127.0.0.1:$LPORT" -s "127.0.0.1:$SPORT" -c "$CFG" -f server >/dev/null
sleep 2; docker logs "psm-a-mapper-$NAME" 2>&1 | tail -2
