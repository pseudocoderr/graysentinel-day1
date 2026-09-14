# Attack Surface Report: localhost

_Scan window: 2026-09-14T09:48:31.108172+00:00 -> 2026-09-14T09:48:31.392825+00:00_


## localhost (127.0.0.1)
**Open ports:** 8000

### Port 8000
- Scheme: `http`
- Status: `200`
- Server header: `SimpleHTTP/0.6 Python/3.12.3`
- Page title: GraySentinel Lab Target
- Detected tech: WordPress, Nginx
- Notable paths:
  - `/robots.txt` -> HTTP 200
  - `/.well-known/security.txt` -> HTTP 200
  - `/admin` -> HTTP 301