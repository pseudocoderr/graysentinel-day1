# Project 02 — CI/CD Security Misconfiguration Auditor

**Candidate:** Aman Maurya
**Domain:** DevSecOps / Red Team — Hyderabad
**Program:** GraySentinel Cyber Defence Lab, Day 1

## What this is

A Python CLI tool that statically analyzes GitHub Actions workflow YAML
files for common security misconfigurations:

- **Hardcoded secrets** — AWS keys, GitHub PATs, generic credential-like strings, embedded private keys
- **Unpinned third-party actions** — actions referenced by a mutable tag/branch instead of a pinned commit SHA
- **Missing/overly broad `permissions:`** — no explicit permissions block, or `write-all`
- **Dangerous trigger patterns** — `pull_request_target` combined with checking out the PR's head ref (fork-PR secret exfiltration pattern)
- **Self-hosted runner exposure** — flags self-hosted runner usage for manual review

It never executes the pipeline itself — purely static analysis of the YAML.

## Folder structure

```
project-02/
├── README.md
├── report.md
├── src/
│   ├── rules.py
│   └── auditor.py
├── evidence/
│   ├── audit_report.json
│   ├── audit_report.md
│   ├── console_output.txt
│   └── test-fixtures/          # sample workflows used to validate the tool
└── screenshots/
```

## Usage

```bash
# Point it at a repo root (it looks under .github/workflows/ automatically)
python3 src/auditor.py /path/to/your/repo --output-dir evidence
```

## Requirements

- Python 3.8+
- `pyyaml` (`pip install pyyaml`)

## Scope note

This is a static analyzer — it reads YAML, it does not call the GitHub API.
Some checks (like actual branch-protection settings) require API access and
are intentionally out of scope here; see Limitations in `report.md`.
