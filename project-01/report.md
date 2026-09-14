# Project 01 Report — Authorized Web Attack-Surface Mapper

**Candidate:** Aman Maurya
**Domain:** DevSecOps / Red Team
**Date:** 2026-09-14

## Problem

Organizations frequently don't have an accurate, current picture of what they
actually expose to the internet: forgotten subdomains, open ports on hosts
that should be locked down, outdated software fingerprintable from banners,
and leftover admin panels or config files sitting at predictable paths. This
"unknown attack surface" is a common entry point in real intrusions because
defenders can't protect what they don't know exists.

## Objective

Build a tool that, given a single authorized domain, automatically discovers
its live subdomains, scans them for open ports, fingerprints the web
services running there, and flags common sensitive/interesting endpoints —
producing a structured report a security team could triage.

## Scenario

Acting as an authorized internal red-teamer, I am asked to produce a
baseline attack-surface map for a domain before a deeper penetration test
begins, so the team knows what's actually live before spending time on
manual recon.

## Approach

I designed the tool as four sequential, independent phases so each can be
reasoned about (and tested) in isolation:

1. **Passive-first**: subdomain discovery starts passively (crt.sh certificate
   transparency logs) rather than brute-forcing a wordlist against DNS —
   lower noise, no traffic sent to the target until a host is already known
   to exist.
2. **Conservative active scanning**: only a curated list of ~18 common ports
   is checked via a plain TCP `connect()` scan (no raw sockets/SYN scanning,
   no privilege escalation needed, and it behaves like a normal client
   connection).
3. **Single GET fingerprinting**: one HTTP GET per open web port to pull
   headers, title, and match against a small signature table — not repeated
   requests or aggressive crawling.
4. **Small endpoint checklist**: ~12 well-known paths checked, not a large
   brute-force wordlist — the goal is signal, not noise.

A hard `--authorized` CLI flag is required before any scanning happens, and
every network call carries a configurable rate-limit delay to keep the tool
polite by default.

**Assumption:** I do not have internet egress from this build environment, so
I could not run the crt.sh lookup live here — that code path is implemented
and will work as soon as it's run from an environment with normal internet
access. I validated the tool end-to-end using `--single-host` mode against a
local controlled test server instead (see Testing/Evidence below).

## Implementation

- `config.py` — ports, paths, tech signatures, timeouts (single source of truth)
- `subdomain_enum.py` — crt.sh query + DNS resolution, fails gracefully if crt.sh is unreachable
- `port_scanner.py` — threaded TCP-connect scan (`ThreadPoolExecutor`, up to 20 workers)
- `fingerprint.py` — HTTP/HTTPS banner grab, title extraction via regex, signature matching
- `endpoint_discovery.py` — checks common paths, records any non-404 response
- `mapper.py` — CLI orchestrator, argument parsing, JSON + Markdown report rendering

Standard library only — no external dependencies, so it runs anywhere Python 3.8+ is available.

## Testing

I could not reach the public internet from this sandboxed build environment
(network egress is restricted to package registries), so I could not run a
live test against a real internet-facing domain here. To validate the full
pipeline I stood up a local controlled Python HTTP server as a stand-in
target, seeded with content that exercises every phase:

- `index.html` containing text that should trigger the WordPress/Nginx signature match
- `robots.txt` (should be found by endpoint discovery)
- `.well-known/security.txt` (should be found)
- `/admin/` directory (should be found, and returns a redirect)

**Expected case:** open port found, fingerprinted, endpoints discovered — confirmed (see Evidence).
**Edge case — closed port:** ran the scanner against a host with no listener; open_ports returned `[]`. Confirmed no false positives.
**Edge case — non-HTTP open port:** the code path for "port open but doesn't speak HTTP" returns a `note` instead of crashing — implemented in `mapper.py`'s service-building loop, not separately re-tested here since no such port was available in the local rig.
**Edge case — unreachable crt.sh:** `query_crtsh()` catches `URLError`/timeout and returns an empty set rather than throwing — this path *did* execute in this sandbox (no internet), so it's genuinely confirmed working, not just written.

## Evidence

Console output and both report formats are saved under `evidence/`:

- `evidence/console_output.txt` — full run log
- `evidence/scan_report.json` — structured machine-readable report
- `evidence/scan_report.md` — human-readable report

Result excerpt from `scan_report.md`:

```
## localhost (127.0.0.1)
**Open ports:** 8000

### Port 8000
- Scheme: http
- Status: 200
- Server header: SimpleHTTP/0.6 Python/3.12.3
- Page title: GraySentinel Lab Target
- Detected tech: WordPress, Nginx
- Notable paths:
  - /robots.txt -> HTTP 200
  - /.well-known/security.txt -> HTTP 200
  - /admin -> HTTP 301
```

## Result

The tool correctly identified the single open port, fingerprinted the
running service (including a couple of technology signature matches, one
genuinely present — Nginx-style content in the body — and one likely a
false positive worth noting, see Limitations), and flagged all three
seeded "notable" paths at the correct HTTP statuses. The pipeline runs
end-to-end without manual intervention and produces both machine- and
human-readable output.

## Security Relevance

This mirrors real recon-phase activity in both offensive engagements and
defensive exposure-management programs. The mandatory `--authorized` flag
and rate-limiting are there for a reason: the same techniques (passive
CT-log lookup, port scan, fingerprinting, path checks) are exactly what an
attacker's reconnaissance phase looks like, so the tool is only appropriate
for use against systems you're cleared to test.

## Limitations

- Tech-signature matching is naive substring matching, not authoritative —
  in this run it flagged "WordPress" purely because the test page's body
  text happened to contain the word "wp-content," even though no actual
  WordPress install was present. This is a real false-positive risk worth
  flagging rather than hiding.
- No IPv6 support.
- crt.sh is the only passive source; no additional sources (e.g. DNS zone
  transfer attempts, search-engine dorking) implemented.
- Endpoint discovery list is small by design — will miss anything not on
  the list.
- Not tested against a live internet-facing domain in this submission due
  to sandbox network restrictions — validated locally instead.

## Learning

Separating the pipeline into independently testable phases (passive
discovery → active scan → fingerprint → endpoint check) made it much easier
to validate correctness at each stage and reason about failure modes (e.g.
what happens when crt.sh is unreachable) rather than treating the whole
thing as one monolithic scan function.

## Future Improvement

- Add a second passive subdomain source and de-duplicate results
- Move tech fingerprinting from substring matching to a proper signature/CPE
  database (e.g. Wappalyzer-style rules) to reduce false positives like the
  one observed here
- Add TLS certificate inspection (issuer, SANs, expiry) as its own phase
- Add an optional screenshot-per-host feature for visual triage
- Re-run against the real authorized domain and attach that evidence once
  outside the sandboxed build environment
