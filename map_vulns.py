#!/usr/bin/env python3
"""Nmap XML to searchsploit table. Run only on systems you own."""
import json, subprocess, sys
import xml.etree.ElementTree as ET

def services(xml_path):
    for host in ET.parse(xml_path).getroot().iter("host"):
        ip = host.find("address").get("addr")
        for p in host.iter("port"):
            svc = p.find("service")
            if svc is None or p.find("state").get("state") != "open":
                continue
            q = " ".join(filter(None, [svc.get("product"), svc.get("version")]))
            if q:
                yield ip, p.get("portid"), q

def searchsploit(q):
    r = subprocess.run(["searchsploit", "--json", q],
                       capture_output=True, text=True)
    return json.loads(r.stdout).get("RESULTS_EXPLOIT", [])

for ip, port, q in services(sys.argv[1]):
    print(f"{ip}:{port} | {q} | {len(searchsploit(q))} public exploit(s)")