#!/usr/bin/env python3
"""Print the exact locally owned firewalld IP-set definition; never mutate host."""
import argparse
import hashlib
import re
from xml.sax.saxutils import escape

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("zone", "node", "group", "service"):
        parser.add_argument("--" + key, required=True)
    parser.add_argument("--protocol", choices=("tcp", "udp"), required=True)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    for key in ("zone", "node", "group", "service"):
        value = getattr(args, key)
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value):
            parser.error(key + " must be 1-64 alphanumeric/hyphen/underscore")
    if not 1 <= args.port <= 65535:
        parser.error("port must be 1-65535")
    identity = "\x00".join((
        args.zone, args.node, args.group, args.service,
        args.protocol, str(args.port),
    )).encode("utf-8")
    name = "fg1_" + hashlib.sha256(identity).hexdigest()[:16]
    description = "Fleetguard runtime entries v1 " + name
    print("name:", name)
    print("description:", description)
    print("path: /etc/firewalld/ipsets/" + name + ".xml")
    print("contents:")
    print('<ipset type="hash:ip">')
    print("  <short>Fleetguard runtime set</short>")
    print("  <description>" + escape(description) + "</description>")
    print('  <option name="family" value="inet"/>')
    print("</ipset>")
    print("Only install this manually on a disposable lab VM. Never auto-reload firewalld.")

if __name__ == "__main__":
    main()
