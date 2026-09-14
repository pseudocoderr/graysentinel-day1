"""
subdomain_enum.py
Passive subdomain discovery via Certificate Transparency logs (crt.sh),
followed by active DNS resolution to confirm which discovered names are
actually live.

Why crt.sh: querying a public CT-log aggregator is a passive technique --
it does not send any traffic to the target's own infrastructure, so it
is a safe first step before any active probing begins.
"""

import json
import socket
import urllib.request
import urllib.error
from config import REQUEST_TIMEOUT, USER_AGENT


def query_crtsh(domain: str) -> set:
    """
    Query crt.sh's JSON API for certificates issued for *.domain.
    Returns a set of unique hostnames found. Fails gracefully (returns
    an empty set) if the service is unreachable -- this keeps the tool
    usable in restricted / offline environments.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    names = set()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT * 3) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
        for entry in data:
            value = entry.get("name_value", "")
            for line in value.split("\n"):
                line = line.strip().lower()
                if line and "*" not in line and line.endswith(domain):
                    names.add(line)
    except (urllib.error.URLError, socket.timeout, json.JSONDecodeError, TimeoutError):
        # Passive source unavailable (offline sandbox, rate-limited, etc.)
        # -- not a fatal error for the overall run.
        pass
    return names


def resolve_hosts(hostnames: set) -> dict:
    """
    Attempt to resolve each candidate hostname to an IPv4 address.
    Returns {hostname: ip_address} for hosts that resolve successfully.
    Unresolvable / dead names are silently dropped -- they are not
    "live" attack surface.
    """
    live = {}
    for host in sorted(hostnames):
        try:
            ip = socket.gethostbyname(host)
            live[host] = ip
        except (socket.gaierror, socket.timeout):
            continue
    return live


def discover_subdomains(domain: str, include_base: bool = True) -> dict:
    """
    Full subdomain discovery pipeline for a single apex domain.
    Returns {hostname: ip_address} of confirmed-live hosts.
    """
    candidates = query_crtsh(domain)
    if include_base:
        candidates.add(domain)
    return resolve_hosts(candidates)
