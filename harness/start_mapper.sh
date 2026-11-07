#!/usr/bin/env bash
# Start a mapper container for one SUT, on the box.
# Usage: bash harness/start_mapper.sh <name> <listen_port> <sut_port> <timing_config> [PSM_ALGOS]
# The mapper code is mounted read-only from vendor/ (so patches are visible and versioned), the
# throwaway test key from keys/ (never the box user's ~/.ssh). Network: host, bound to 127.0.0.1 only.
set -euo pipefail
cd "$(dirname "$0")/.."
NAME=$1; LPORT=$2; SPORT=$3; CFG=$4; ALGOS=${5:-legacy}
docker image inspect psm-mapper:pinned >/dev/null 2>&1 || docker build -q -t psm-mapper:pinned -f harness/mapper.Dockerfile harness >/dev/null
docker rm -f "psm-mapper-$NAME" >/dev/null 2>&1 || true
docker run -d --name "psm-mapper-$NAME" --network host --restart unless-stopped --memory 256m --cpus 1 \
  -v "$PWD/vendor/ssh-fuzzer/ssh-mapper:/app:ro" -v "$PWD/keys:/home/mapper/.ssh:ro" \
  -e PSM_USER=tester -e PSM_PASS=correct-horse-battery -e PSM_BADPASS=wrong-password -e PSM_ALGOS="$ALGOS" \
  psm-mapper:pinned -l "127.0.0.1:$LPORT" -s "127.0.0.1:$SPORT" -c "$CFG" -f server >/dev/null
sleep 2; docker logs "psm-mapper-$NAME" 2>&1 | tail -2
