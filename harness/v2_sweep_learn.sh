#!/usr/bin/env bash
# For every sweep target: wait for its replay to finish, then learn alphabet A through its own mapper (all in parallel).
cd "$(dirname "$0")/.."
grep -v '^#' harness/v2_sweep_list.txt | while read IMPL AV PV PORT MPORT PROF; do
  (
    while [ ! -s "results/v2/B2/$IMPL-$PV.json" ]; do grep -q "$IMPL $PV .*FAILED" results/v2/B2/sweep_run.log 2>/dev/null && exit 0; sleep 10; done
    PYTHONUNBUFFERED=1 .venv/bin/python -m psm.learn --name "b2_${IMPL}-${PV%%-r*}_A" --port "$MPORT" \
      --alphabet KEXINIT,KEX30,NEWKEYS,SR_AUTH,UA_PK_OK --oracle rekey --walks-per-state 25 --max-len 10 \
      > "results/learning/b2_${IMPL}-${PV%%-r*}_A.log" 2>&1
  ) &
done
wait
