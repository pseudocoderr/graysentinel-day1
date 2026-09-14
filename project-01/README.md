# Project 01 — Authorized Web Attack-Surface Mapper

**Candidate:** Aman Maurya
**Domain:** DevSecOps / Red Team — Hyderabad
**Program:** GraySentinel Cyber Defence Lab, Day 1

## What this is

A Python CLI tool that maps the external attack surface of a web target you
are explicitly authorized to test. It chains four phases:

1. **Subdomain discovery** — passive Certificate Transparency lookup (crt.sh) + DNS resolution
2. **Port scan** — TCP-connect scan across a curated list of common ports
3. **HTTP(S) fingerprinting** — server headers, page title, lightweight tech-stack detection
4. **Endpoint discovery** — checks a small, conservative list of common paths (robots.txt, admin panels, `.git/HEAD`, etc.)

Output: a JSON report and a human-readable Markdown report.

## Folder structure

```
project-01/
├── README.md
├── report.md
├── src/
│   ├── config.py
│   ├── subdomain_enum.py
│   ├── port_scanner.py
│   ├── fingerprint.py
│   ├── endpoint_discovery.py
│   └── mapper.py
├── evidence/
│   ├── scan_report.json
│   ├── scan_report.md
│   └── console_output.txt
└── screenshots/
```

## Usage

```bash
# Full run against a domain you own (includes subdomain discovery)
python3 src/mapper.py example.com --authorized --output-dir evidence

# Single-host run (skip subdomain discovery, scan one host/IP directly)
python3 src/mapper.py example.com --authorized --single-host --output-dir evidence
```

`--authorized` is a **mandatory** flag. The tool will refuse to run without it —
this is a deliberate design choice, not an oversight (see Security Relevance in `report.md`).

## Requirements

- Python 3.8+
- No third-party packages — standard library only (`socket`, `http.client`,
  `urllib`, `ssl`, `concurrent.futures`)

## Authorization notice

Run this only against domains/hosts you own or are explicitly authorized to
test, or a GraySentinel-controlled lab target. Do not point this at
third-party systems.
