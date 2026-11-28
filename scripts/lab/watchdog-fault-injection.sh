#!/usr/bin/env bash
# #47 lab acceptance: run ONLY on a disposable lab VM with console access.
# Prereqs: agent installed with deploy/systemd/fleetguard-agent.service in
# enforce mode, a controller publishing a ban on $LAB_SOURCE, and the ipset
# name the agent owns in $FG_IPSET. Touches no non-Fleetguard objects.
set -euo pipefail
[[ -f /etc/fleetguard/DISPOSABLE_LAB_VM ]] || { echo "refusing: not a marked disposable lab VM" >&2; exit 2; }
: "${LAB_SOURCE:?set LAB_SOURCE (banned test IP)}" "${FG_IPSET:?set FG_IPSET (Fleetguard-owned ipset)}"
deadline=$((60 + 30 + 10))

has_entry() { firewall-cmd --ipset="$FG_IPSET" --get-entries | grep -Fqx "$LAB_SOURCE"; }
wait_for() { # $1=want(present) $2=seconds
  for _ in $(seq "$2"); do has_entry && return 0; sleep 1; done
  return 1
}
result() { printf '%-28s %s\n' "$1" "$2"; }

for fault in sigkill sigstop-agent sigstop-firewalld; do
  systemctl restart fleetguard-agent
  wait_for present 60 || { result "$fault" "SETUP FAIL (ban not installed)"; continue; }
  pid=$(systemctl show -p MainPID --value fleetguard-agent)
  case $fault in
    sigkill) kill -KILL "$pid" ;;
    sigstop-agent) kill -STOP "$pid" ;;
    sigstop-firewalld) kill -STOP "$(systemctl show -p MainPID --value firewalld)" ;;
  esac
  since=$(date '+%Y-%m-%d %H:%M:%S')
  if [[ $fault == sigstop-firewalld ]]; then
    # Nothing can remove entries through a stopped firewalld: the watchdog
    # must still kill the agent; resume firewalld so cleanup can complete.
    sleep "$deadline"; kill -CONT "$(systemctl show -p MainPID --value firewalld)"
  fi
  [[ $fault == sigstop-agent ]] && trap 'kill -CONT '"$pid"' 2>/dev/null || true' EXIT
  # The restarted agent legitimately re-applies still-valid signed bans, so
  # "entry absent" may last only ~1s. Pass = cleanup confirmed after the fault.
  ok=""
  for _ in $(seq "$deadline"); do
    if journalctl -u fleetguard-agent --since "$since" --no-pager | grep -q "owned runtime firewall entries removed"; then ok=1; break; fi
    sleep 1
  done
  [[ -n $ok ]] && result "$fault" "PASS (cleanup confirmed)" || result "$fault" "FAIL (no cleanup within ${deadline}s)"
done
journalctl -u fleetguard-agent --since "-15 min" --no-pager | grep -E "watchdog|cleanup|Watchdog" | tail -20 || true
