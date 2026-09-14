"""
port_scanner.py
Simple TCP-connect port scanner. Deliberately uses a plain connect()
scan (no raw sockets / SYN scanning) so it requires no elevated
privileges and behaves like a normal client connection -- appropriate
for an authorized, low-noise recon exercise.
"""

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import COMMON_PORTS, PORT_SCAN_TIMEOUT, MAX_THREADS, DEFAULT_RATE_LIMIT


def _check_port(ip: str, port: int, timeout: float, rate_limit: float) -> tuple:
    time.sleep(rate_limit)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((ip, port))
        is_open = (result == 0)
    except (socket.timeout, OSError):
        is_open = False
    finally:
        sock.close()
    return port, is_open


def scan_host(ip: str, ports=None, timeout: float = PORT_SCAN_TIMEOUT,
              rate_limit: float = DEFAULT_RATE_LIMIT, threads: int = MAX_THREADS) -> list:
    """
    Scan a single host across the given list of ports (defaults to
    config.COMMON_PORTS). Returns a sorted list of open ports.
    """
    ports = ports or COMMON_PORTS
    open_ports = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(_check_port, ip, p, timeout, rate_limit) for p in ports]
        for fut in as_completed(futures):
            port, is_open = fut.result()
            if is_open:
                open_ports.append(port)
    return sorted(open_ports)
