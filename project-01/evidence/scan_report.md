# Attack Surface Report: scanme.nmap.org

_Scan window: 2026-09-14T10:42:05.411513+00:00 -> 2026-09-14T10:42:18.786604+00:00_


## scanme.nmap.org (45.33.32.156)
**Open ports:** 22, 80

### Port 22
- open TCP port, not HTTP(S) or did not respond to GET
### Port 80
- Scheme: `http`
- Status: `200`
- Server header: `Apache/2.4.7 (Ubuntu)`
- Page title: Go ahead and ScanMe!
- Detected tech: Apache
- Notable paths:
  - `/.htaccess` -> HTTP 403