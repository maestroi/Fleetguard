#!/usr/bin/env bash
# Run from the repository root. Requires SSH root access and the existing issue #11 guests.
set -euo pipefail
host=${FG_PROXMOX_HOST:-root@192.168.50.171}
remote=(ssh -o BatchMode=yes "$host")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/grafana"
go build -o "$work/controller" ./cmd/fleetguard-controller
go build -o "$work/agent" ./cmd/fleetguard-agent
prom=$(docker create prom/prometheus:v3.5.0)
graf=$(docker create grafana/grafana:12.1.0)
trap 'docker rm "$prom" "$graf" >/dev/null; rm -rf "$work"' EXIT
docker cp "$prom:/bin/prometheus" "$work/prometheus"
docker cp "$graf:/usr/share/grafana/." "$work/grafana"
cp deploy/monitoring/{alerts.yml,grafana-dashboard.json} "$work/"
sed -e 's/100.64.0.10/172.29.50.10/' -e 's/100.64.0.21/172.29.50.11/' -e 's/100.64.0.22/172.29.50.12/' deploy/monitoring/prometheus.yml > "$work/prometheus.yml"
tar -C "$work" -czf "$work/controller.tar.gz" controller prometheus grafana alerts.yml grafana-dashboard.json prometheus.yml
gzip "$work/agent"
host_work=$("${remote[@]}" mktemp -d)
scp -q "$work/controller.tar.gz" "$work/agent.gz" "$host:$host_work/"
"${remote[@]}" bash -s -- "$host_work" <<'HOST'
set -euo pipefail
work=$1
ns=fg-issue11
for row in "102 fg-control" "111 fg-agent-a" "112 fg-agent-b"; do
  read -r id name <<<"$row"
  config=$(qm config "$id")
  grep -Fxq "name: $name" <<<"$config"
  grep -Eq '^net0: [^ ]*bridge=vmbr50(,|$)' <<<"$config"
  test "$(grep -c '^net[0-9]*:' <<<"$config")" -eq 1
done
if ! ip netns list | awk '{print $1}' | grep -Fxq "$ns"; then
  ip netns add "$ns"
  ip link add fg11-host type veth peer name fg11-access netns "$ns"
  ip link set fg11-host master vmbr50 up
  ip -n "$ns" link set lo up
  ip -n "$ns" link set fg11-access up
  ip -n "$ns" addr add 172.29.50.254/24 dev fg11-access
fi
ip netns exec "$ns" python3 -m http.server 18080 --bind 172.29.50.254 --directory "$work" >/dev/null 2>&1 &
server=$!
# The lab HTTP server is unauthenticated: guests verify digests passed over qm guest exec.
controller_sha=$(sha256sum "$work/controller.tar.gz" | cut -d' ' -f1)
agent_sha=$(sha256sum "$work/agent.gz" | cut -d' ' -f1)
trap 'kill "$server" 2>/dev/null || true; rm -rf "$work"' EXIT
guest() {
  local vm=$1 script=$2 result
  result=$(printf '%s\n' "$script" | qm guest exec "$vm" --timeout 300 --pass-stdin 1 -- /bin/bash -se)
  python3 -c 'import json,sys; r=json.load(sys.stdin); print(r.get("out-data",""),end=""); print(r.get("err-data",""),end="",file=sys.stderr); sys.exit(r.get("exitcode",1))' <<<"$result"
}
for row in '102 10' '111 11' '112 12'; do
  read -r vm octet <<<"$row"
  guest "$vm" "ip addr replace 172.29.50.$octet/24 dev enp6s18"
done
guest 102 "controller_sha=$controller_sha"'
cd /opt/fg-issue11
curl --fail --silent --show-error --retry 3 http://172.29.50.254:18080/controller.tar.gz -o monitoring.tar.gz
echo "$controller_sha  monitoring.tar.gz" | sha256sum -c --quiet
tar -xzf monitoring.tar.gz
rm monitoring.tar.gz
systemctl stop fg-issue11-controller || true
install -m 700 controller fleetguard-controller.new
mv fleetguard-controller.new fleetguard-controller
python3 -c "import json; p=\"server.json\"; d=json.load(open(p)); d[\"metrics_listen\"]=\"172.29.50.10:9465\"; json.dump(d,open(p,\"w\"))"
systemd-run --unit=fg-issue11-controller --collect "$PWD/fleetguard-controller" -serve -config "$PWD/server.json"
install -d provisioning/datasources provisioning/dashboards dashboards
cp grafana-dashboard.json dashboards/
printf "apiVersion: 1\ndatasources:\n  - name: Prometheus\n    uid: prometheus\n    type: prometheus\n    access: proxy\n    url: http://127.0.0.1:9090\n    isDefault: true\n" > provisioning/datasources/prometheus.yml
printf "apiVersion: 1\nproviders:\n  - name: Fleetguard\n    type: file\n    options:\n      path: /opt/fg-issue11/dashboards\n" > provisioning/dashboards/fleetguard.yml
systemctl stop fg-issue11-prometheus fg-issue11-grafana 2>/dev/null || true
systemd-run --unit=fg-issue11-prometheus --collect --working-directory="$PWD" "$PWD/prometheus" --config.file="$PWD/prometheus.yml" --storage.tsdb.path="$PWD/prometheus-data" --web.listen-address=127.0.0.1:9090
systemd-run --unit=fg-issue11-grafana --collect --working-directory="$PWD/grafana" --setenv=GF_SERVER_HTTP_ADDR=172.29.50.10 --setenv=GF_PATHS_PROVISIONING="$PWD/provisioning" --setenv=GF_SECURITY_DISABLE_INITIAL_ADMIN_CREATION=true --setenv=GF_AUTH_BASIC_ENABLED=false --setenv=GF_AUTH_DISABLE_LOGIN_FORM=true --setenv=GF_AUTH_ANONYMOUS_ENABLED=true --setenv=GF_AUTH_ANONYMOUS_ORG_ROLE=Viewer "$PWD/grafana/bin/grafana" server --homepath "$PWD/grafana"
'
for row in '111 11' '112 12'; do
  read -r vm octet <<<"$row"
  guest "$vm" "
cd /opt/fg-issue11
curl --fail --silent --show-error http://172.29.50.254:18080/agent.gz -o agent.gz
echo \"$agent_sha  agent.gz\" | sha256sum -c --quiet
gzip -df agent.gz
systemctl stop fg-issue11-agent || true
install -m 700 agent fleetguard-agent.new
mv fleetguard-agent.new fleetguard-agent
python3 -c 'import json; p=\"runtime.json\"; d=json.load(open(p)); d[\"metrics_listen\"]=\"172.29.50.$octet:9464\"; json.dump(d,open(p,\"w\"))'
systemd-run --unit=fg-issue11-agent --collect \"\$PWD/fleetguard-agent\" -run -runtime-config \"\$PWD/runtime.json\"
"
done
HOST
