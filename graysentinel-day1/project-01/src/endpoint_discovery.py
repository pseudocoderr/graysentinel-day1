"""
endpoint_discovery.py
Checks a short, curated list of common paths (robots.txt, admin panels,
leaked config files, etc.) against a discovered web service. This is
intentionally a small, conservative list -- the goal is surface-mapping
signal, not an aggressive brute-force fuzzing run.
"""

import http.client
import ssl
import socket
from config import REQUEST_TIMEOUT, USER_AGENT, COMMON_PATHS

HTTPS_PORTS = {443, 8443}


def check_paths(ip: str, port: int, hostname: str = None, paths=None, rate_limit: float = 0.05) -> list:
    """
    GET each path in `paths` (defaults to config.COMMON_PATHS) against
    ip:port. Returns a list of {path, status} for any path that did not
    404 (i.e. something exists there worth a human look).
    """
    import time
    paths = paths or COMMON_PATHS
    use_ssl = port in HTTPS_PORTS
    host_header = hostname or ip
    findings = []

    for path in paths:
        time.sleep(rate_limit)
        try:
            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(ip, port, timeout=REQUEST_TIMEOUT, context=ctx)
            else:
                conn = http.client.HTTPConnection(ip, port, timeout=REQUEST_TIMEOUT)

            conn.request("GET", path, headers={"Host": host_header, "User-Agent": USER_AGENT})
            resp = conn.getresponse()
            resp.read(256)  # drain, we only care about status
            conn.close()

            if resp.status != 404:
                findings.append({"path": path, "status": resp.status})
        except (socket.timeout, ConnectionRefusedError, OSError, http.client.HTTPException):
            continue

    return findings
