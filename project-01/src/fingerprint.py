"""
fingerprint.py
Lightweight HTTP(S) fingerprinting: fetches headers and a small slice
of the response body for a host:port, then matches known signatures
to guess server software / frameworks in use. This is a single normal
GET request per service -- not a scanner or exploit tool.
"""

import re
import ssl
import socket
import http.client
from config import REQUEST_TIMEOUT, USER_AGENT, TECH_SIGNATURES

HTTPS_PORTS = {443, 8443}


def fetch_banner(ip: str, port: int, hostname: str = None) -> dict:
    """
    Perform a single GET / against ip:port and return status, headers,
    a short body excerpt, and any matched technology signatures.
    Returns None if the port does not speak HTTP(S).
    """
    use_ssl = port in HTTPS_PORTS
    host_header = hostname or ip
    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(ip, port, timeout=REQUEST_TIMEOUT, context=ctx)
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=REQUEST_TIMEOUT)

        conn.request("GET", "/", headers={"Host": host_header, "User-Agent": USER_AGENT})
        resp = conn.getresponse()
        body = resp.read(4096).decode("utf-8", errors="ignore")
        headers = {k.lower(): v for k, v in resp.getheaders()}
        conn.close()

        haystack = (str(headers) + body).lower()
        matched = [tech for tech, sigs in TECH_SIGNATURES.items()
                   if any(sig in haystack for sig in sigs)]

        title_match = re.search(r"<title>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        title = title_match.group(1).strip() if title_match else None

        return {
            "scheme": "https" if use_ssl else "http",
            "status": resp.status,
            "server_header": headers.get("server"),
            "title": title,
            "technologies": matched,
        }
    except (socket.timeout, ConnectionRefusedError, OSError, http.client.HTTPException):
        return None
