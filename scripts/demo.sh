#!/usr/bin/env bash
# Live demo: the same message sequence on wolfSSH and OpenSSH.
# "Log in, start a rekey, open a channel, then finish the rekey."
# RFC 4253 §7.1: between its KEXINIT and its NEWKEYS a server MUST NOT send anything but key-exchange messages.
cd "$(dirname "$0")/.."
WORD="KEXINIT KEX30 NEWKEYS SR_AUTH UA_PW_OK KEXINIT CH_OPEN KEX30 NEWKEYS"
for t in wolfssh openssh; do
  uv run python scripts/replay.py "$t" "$WORD" --reps=3 2>/dev/null | grep -v -E "^\s+(KEX30|NEWKEYS|SR_AUTH|UA_PW_OK) +-> (KEX31\+NEWKEYS|NO_RESP|SERVICE_ACCEPT|UA_SUCCESS.*)$"
done
