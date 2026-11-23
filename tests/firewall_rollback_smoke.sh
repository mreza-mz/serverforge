#!/usr/bin/env bash
# Induce a lockout on the alternate disposable VM, then verify rollback and resume.
set -euo pipefail

cli=$(realpath "${1:?pass the ServerForge binary}")
port=${2:?pass the loopback SSH port for the disposable VM}
[[ $port =~ ^[1-9][0-9]{0,4}$ ]] && (( port <= 65535 ))
remote=(ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=4 -p "$port" tester@127.0.0.1)
test "$("${remote[@]}" hostname)" = forge-test-b

work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
profile="$work/firewall.yaml"
receipt="$work/approval.json"
state="$work/state.json"
log="$work/apply.log"
cat >"$profile" <<YAML
version: 1
target:
  connection: ssh
  host: 127.0.0.1
  user: tester
  port: $port
security:
  ufw: true
YAML

id=$("$cli" plan --config "$profile" --json | python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])')
"$cli" approve --config "$profile" --output "$receipt" --non-interactive --plan-id "$id" --approve-security ufw
"${remote[@]}" 'set -- $SSH_CONNECTION; sudo -n ufw --force disable >/dev/null; sudo -n ufw deny from "$1" to any port "$4" proto tcp'

if "$cli" apply --config "$profile" --approval "$receipt" --state "$state" >"$log" 2>&1; then
  cat "$log"
  exit 1
fi
grep -q '^ufw failed ' "$log"
unreachable=false
for ((attempt = 0; attempt < 40; attempt++)); do
  if "${remote[@]}" true >/dev/null 2>&1; then
    test "$unreachable" = true
    "${remote[@]}" 'sudo -n ufw status | grep -Fx "Status: inactive"; sudo -n test ! -d /run/serverforge-firewall'
    break
  fi
  unreachable=true
  sleep 4
done
"${remote[@]}" 'set -- $SSH_CONNECTION; sudo -n ufw --force delete deny from "$1" to any port "$4" proto tcp'
"$cli" apply --config "$profile" --approval "$receipt" --state "$state" --resume
"${remote[@]}" 'sudo -n ufw status | grep -Fx "Status: active"; sudo -n test ! -d /run/serverforge-firewall'
printf '%s\n' 'SSH firewall rollback and successful resume passed'
