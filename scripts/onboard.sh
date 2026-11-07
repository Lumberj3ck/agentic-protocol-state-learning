#!/usr/bin/env bash
# Spawn one Codex agent to onboard an SSH implementation: scripts/onboard.sh <name> "<implementation>" "<hints>"
set -euo pipefail
cd "$(dirname "$0")/.."
name=$1 impl=$2 hints=${3:-none}
prompt=$(sed -e "s|{NAME}|$name|g" -e "s|{IMPL}|$impl|g" -e "s|{HINTS}|$hints|g" agents/onboard-ssh-target.md)
log=logs/agents/onboard-$name
printf '%s\n' "$prompt" > "$log.prompt.md"
codex exec -m gpt-6.1-sol -s workspace-write -c sandbox_workspace_write.network_access=true \
  --add-dir "$HOME/.cache/uv" -C "$PWD" --json -o "$log.last.md" "$prompt" < /dev/null > "$log.jsonl" 2> "$log.stderr"
echo "EXIT $?" >> "$log.stderr"
