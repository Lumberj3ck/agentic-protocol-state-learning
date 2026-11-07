#!/usr/bin/env bash
# Install the learner's throwaway test public key (keys/id_rsa.pub, box only, never committed) for user tester.
set -euo pipefail
C="$1"; KEY="$(cd "$(dirname "$0")/.." && pwd)/keys/id_rsa.pub"
docker exec "$C" sh -c 'mkdir -p /home/tester/.ssh && chmod 700 /home/tester/.ssh'
docker cp "$KEY" "$C:/home/tester/.ssh/authorized_keys"
docker exec "$C" sh -c 'chown -R tester:tester /home/tester/.ssh && chmod 600 /home/tester/.ssh/authorized_keys'
