"""
config.py
Shared constants and configuration for the Attack Surface Mapper.
"""

# Common TCP ports checked during the port-scan phase.
# Kept intentionally small/targeted (not a full 1-65535 sweep) to stay
# fast, low-noise, and appropriate for an authorized recon exercise.
COMMON_PORTS = [
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    53,    # DNS
    80,    # HTTP
    110,   # POP3
    143,   # IMAP
    443,   # HTTPS
    445,   # SMB
    3306,  # MySQL
    3389,  # RDP
    5432,  # PostgreSQL
    5900,  # VNC
    6379,  # Redis
    8000,  # HTTP-alt
    8080,  # HTTP-alt
    8443,  # HTTPS-alt
]

# Small, conservative wordlist for passive/light endpoint discovery.
# Deliberately not a large brute-force list -- this is a mapper, not
# an aggressive fuzzer.
COMMON_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/admin",
    "/login",
    "/.git/HEAD",
    "/.env",
    "/wp-login.php",
    "/api",
    "/api/health",
    "/server-status",
    "/.htaccess",
]

# HTTP response header / body signatures used for very lightweight
# technology fingerprinting. Not exhaustive -- meant as a starting point.
TECH_SIGNATURES = {
    "WordPress": ["wp-content", "wp-includes"],
    "Nginx": ["nginx"],
    "Apache": ["apache"],
    "PHP": ["x-powered-by: php", ".php"],
    "Express/Node.js": ["x-powered-by: express"],
    "Django": ["csrftoken", "django"],
    "Flask/Werkzeug": ["werkzeug"],
    "IIS": ["microsoft-iis"],
    "Cloudflare": ["cloudflare"],
}

REQUEST_TIMEOUT = 3          # seconds, per network call
PORT_SCAN_TIMEOUT = 1.0      # seconds, per port connect attempt
MAX_THREADS = 20
DEFAULT_RATE_LIMIT = 0.05    # seconds delay between requests, politeness
USER_AGENT = "GraySentinel-AttackSurfaceMapper/1.0 (authorized-recon)"
