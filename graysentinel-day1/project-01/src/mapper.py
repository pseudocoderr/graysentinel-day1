#!/usr/bin/env python3
"""
mapper.py
Authorized Web Attack-Surface Mapper -- GraySentinel Day 1, Project 01.

Pipeline:
  1. Subdomain discovery (passive CT-log lookup + DNS resolution)
  2. Port scan of each live host (common ports, TCP connect scan)
  3. HTTP(S) fingerprinting of any open web ports
  4. Light endpoint/path discovery against each web service
  5. JSON + Markdown report output

SAFETY:
This tool must only be run against a domain/host you own or are
explicitly authorized to test, or a GraySentinel-controlled lab
target. The --authorized flag is a mandatory, explicit acknowledgment
of this and the tool refuses to run without it.
"""

import argparse
import json
import sys
import os
from datetime import datetime, timezone

from subdomain_enum import discover_subdomains
from port_scanner import scan_host
from fingerprint import fetch_banner
from endpoint_discovery import check_paths


def run_mapper(domain: str, output_dir: str, single_host: bool = False,
                rate_limit: float = 0.05) -> dict:
    report = {
        "target": domain,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "hosts": {},
    }

    print(f"[*] Starting attack surface mapping for: {domain}")

    if single_host:
        # Skip CT-log lookup; treat the given domain/IP as the only host.
        import socket
        try:
            ip = socket.gethostbyname(domain)
            live_hosts = {domain: ip}
        except socket.gaierror:
            print(f"[!] Could not resolve {domain}. Aborting.")
            sys.exit(1)
    else:
        print("[*] Phase 1: Passive subdomain discovery (crt.sh) + DNS resolution")
        live_hosts = discover_subdomains(domain)
        print(f"[+] {len(live_hosts)} live host(s) confirmed")

    for hostname, ip in live_hosts.items():
        print(f"\n[*] Phase 2: Port scanning {hostname} ({ip})")
        open_ports = scan_host(ip, rate_limit=rate_limit)
        print(f"[+] Open ports on {hostname}: {open_ports if open_ports else 'none found'}")

        services = {}
        for port in open_ports:
            banner = fetch_banner(ip, port, hostname=hostname)
            if banner:
                print(f"[*] Phase 3: Fingerprinting {hostname}:{port} -> "
                      f"{banner.get('server_header') or 'unknown server'}")
                print(f"[*] Phase 4: Endpoint discovery on {hostname}:{port}")
                findings = check_paths(ip, port, hostname=hostname, rate_limit=rate_limit)
                banner["notable_paths"] = findings
                services[port] = banner
            else:
                services[port] = {"note": "open TCP port, not HTTP(S) or did not respond to GET"}

        report["hosts"][hostname] = {
            "ip": ip,
            "open_ports": open_ports,
            "services": services,
        }

    report["finished_at"] = datetime.now(timezone.utc).isoformat()

    os.makedirs(output_dir, exist_ok=True)
    json_path = os.path.join(output_dir, "scan_report.json")
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)

    md_path = os.path.join(output_dir, "scan_report.md")
    with open(md_path, "w") as f:
        f.write(render_markdown(report))

    print(f"\n[+] Reports written to {json_path} and {md_path}")
    return report


def render_markdown(report: dict) -> str:
    lines = [f"# Attack Surface Report: {report['target']}",
             f"\n_Scan window: {report['started_at']} -> {report['finished_at']}_\n"]
    if not report["hosts"]:
        lines.append("No live hosts were discovered.")
        return "\n".join(lines)

    for hostname, data in report["hosts"].items():
        lines.append(f"\n## {hostname} ({data['ip']})")
        lines.append(f"**Open ports:** {', '.join(map(str, data['open_ports'])) or 'none'}\n")
        for port, svc in data["services"].items():
            lines.append(f"### Port {port}")
            if "note" in svc:
                lines.append(f"- {svc['note']}")
                continue
            lines.append(f"- Scheme: `{svc.get('scheme')}`")
            lines.append(f"- Status: `{svc.get('status')}`")
            lines.append(f"- Server header: `{svc.get('server_header')}`")
            lines.append(f"- Page title: {svc.get('title')}")
            lines.append(f"- Detected tech: {', '.join(svc.get('technologies') or []) or 'none matched'}")
            paths = svc.get("notable_paths") or []
            if paths:
                lines.append("- Notable paths:")
                for p in paths:
                    lines.append(f"  - `{p['path']}` -> HTTP {p['status']}")
            else:
                lines.append("- Notable paths: none found")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="GraySentinel Authorized Web Attack-Surface Mapper")
    parser.add_argument("domain", help="Apex domain or single host to map")
    parser.add_argument("--authorized", action="store_true", required=True,
                         help="REQUIRED: confirms you own or are explicitly authorized "
                              "to test this target. The tool will not run without this flag.")
    parser.add_argument("--single-host", action="store_true",
                         help="Skip subdomain discovery; scan only the given host/IP.")
    parser.add_argument("--output-dir", default="./evidence",
                         help="Directory to write JSON/Markdown reports into.")
    parser.add_argument("--rate-limit", type=float, default=0.05,
                         help="Delay in seconds between individual requests (politeness).")
    args = parser.parse_args()

    print("=" * 70)
    print("GraySentinel Attack-Surface Mapper")
    print("Authorized use only. Do not run against systems you do not own")
    print("or do not have explicit written permission to test.")
    print("=" * 70)

    run_mapper(args.domain, args.output_dir, single_host=args.single_host,
               rate_limit=args.rate_limit)


if __name__ == "__main__":
    main()
