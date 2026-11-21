#!/usr/bin/env python3
"""Fail CI if the public Compose example gains host privileges or broad access.

The input is normalized JSON from `docker compose config --format json`.
No PyYAML, Docker API, or third-party packages required.
"""

import json
import sys
from pathlib import Path


def require(condition, message):
    if not condition:
        raise SystemExit(f"insecure Compose configuration: {message}")


def main():
    require(len(sys.argv) == 2, "expected path to normalized Compose JSON")
    data = json.loads(Path(sys.argv[1]).read_text())
    require(set(data["services"]) == {"controller"}, "unexpected services")
    c = data["services"]["controller"]
    require(c["image"].startswith("ghcr.io/maestroi/fleetguard-controller:"), "wrong image")
    require(c.get("user") == "65532:65532", "container is not non-root")
    require(c.get("privileged", False) is False, "privileged must be explicitly false")
    require(c.get("cap_drop") == ["ALL"], "Linux capabilities not all dropped")
    require(c.get("read_only") is True, "root filesystem must be read-only")
    require("no-new-privileges:true" in c.get("security_opt", []), "privilege escalation allowed")
    for k in ("network_mode", "pid", "ipc", "cgroup", "devices", "device_cgroup_rules", "cap_add", "group_add"):
        require(not c.get(k), f"privileged option {k} present")
    require(c.get("pids_limit", 0) > 0 and c["pids_limit"] <= 64, "unbounded process count")
    require(c.get("mem_limit", 0) > 0 and c["mem_limit"] <= 256 * 1024 * 1024, "unbounded memory")
    ports = c.get("ports", [])
    require(len(ports) == 1, "unexpected published ports")
    p = ports[0]
    require(p.get("host_ip") == "127.0.0.1" and p.get("target") == 9443 and p.get("protocol", "tcp") == "tcp", "listener exposed beyond host loopback")
    volumes = c.get("volumes", [])
    require(len(volumes) == 2, "unexpected host mounts")
    by_target = {v.get("target"): v for v in volumes}
    require(set(by_target) == {"/etc/fleetguard", "/var/lib/fleetguard"}, "unexpected volume targets")
    require(all(v.get("type") == "bind" for v in volumes), "only explicit bind mounts allowed")
    require(by_target["/etc/fleetguard"].get("read_only") is True, "private config must be read-only")
    require(by_target["/var/lib/fleetguard"].get("read_only", False) is False, "SQLite directory must be writable")
    for target, directory in (("/etc/fleetguard", "private"), ("/var/lib/fleetguard", "state")):
        volume = by_target[target]
        source = Path(volume.get("source", ""))
        require(source.name == directory and source.parent.name == "controller", "unexpected bind mount source")
        require(volume.get("bind", {}).get("create_host_path", False) is False, "host mount must not be auto-created")
    require(any(str(tmp).startswith("/tmp:") for tmp in c.get("tmpfs", [])), "bounded /tmp tmpfs missing")
    require(not c.get("environment"), "do not inject credentials as environment")
    nets = c.get("networks", {})
    require(len(nets) == 1, "unexpected additional network")
    name, net = next(iter(nets.items()))
    require(net.get("ipv4_address") == "172.30.240.10", "test container IP changed without updating config")
    expected = json.loads((Path(__file__).parent.parent / "deploy/controller/server.example.json").read_text())
    require(expected["listen"] == "172.30.240.10:9443", "sample controller listen address disagrees with Compose")
    require(expected["mode"] == "observe", "must stay observe-only")
    require(expected["database_file"] == "/var/lib/fleetguard/evidence.sqlite", "unexpected SQLite location")
    print("Compose least-privilege contract passed")


if __name__ == "__main__":
    main()
