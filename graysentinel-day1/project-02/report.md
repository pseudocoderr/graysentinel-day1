# Project 02 Report — CI/CD Security Misconfiguration Auditor

**Candidate:** Aman Maurya
**Domain:** DevSecOps / Red Team
**Date:** 2026-09-14

## Problem

CI/CD pipelines are a high-value target: they routinely hold secrets
(cloud credentials, deploy keys, API tokens) and often run with elevated
permissions. Common mistakes — a secret pasted directly into a workflow
file, a third-party action pinned to a mutable tag instead of a commit SHA,
`pull_request_target` combined with checking out untrusted fork code, or a
missing `permissions:` block — have caused real supply-chain incidents.
Most teams don't audit their workflow YAML for these patterns systematically.

## Objective

Build a static analyzer that scans a repository's GitHub Actions workflow
files and flags these known misconfiguration patterns with a severity
rating and enough detail for a developer to fix each finding, without
requiring the pipeline to actually run.

## Scenario

Acting as a DevSecOps engineer doing a pre-merge security review, I want to
run a quick automated check over a repo's `.github/workflows/` directory as
part of onboarding a new project or before a security audit, to catch the
most common, high-impact mistakes before a human reviewer spends time on it.

## Approach

- **Rule-per-function design**: each check (secrets, unpinned actions,
  permissions, dangerous triggers, self-hosted runners) is an independent
  function taking the parsed workflow dict + raw text, returning a list of
  `Finding` objects. This makes rules easy to test individually and easy to
  add to later.
- **Static-only, read-only**: the tool never executes any pipeline step —
  it only parses YAML and pattern-matches. No risk of accidentally running
  untrusted CI code.
- **Severity-ranked output**: findings are tagged CRITICAL/HIGH/MEDIUM/LOW
  and sorted so the most urgent issues surface first in both the JSON and
  Markdown reports.
- **Honest about what it can't do**: a placeholder rule
  (`rule_missing_branch_protection_hint`) documents that branch-protection
  settings require GitHub API access and aren't checkable from YAML alone,
  rather than silently pretending to cover it.

## Implementation

- `rules.py` — `Finding` dataclass + 5 active detection rules + regex
  patterns for secret-like strings (AWS keys, GitHub PATs, generic
  `key/token/secret/password: "..."` patterns, PEM private keys)
- `auditor.py` — CLI orchestrator: discovers workflow files under
  `.github/workflows/`, runs every rule against each file, aggregates and
  sorts findings, writes JSON + Markdown reports

Dependency: `pyyaml` for parsing (the only external dependency in either
project).

## Testing

I built two test fixture workflows under `evidence/test-fixtures/` to
validate the tool against both the expected case and a negative/edge case:

**`vulnerable_deploy.yml` (expected case — intentionally misconfigured):**
seeded with a hardcoded AWS access key + secret key, a generic
`api_key: "..."` string, three unpinned action references (`@main`,
`@v1`, `@master`), no `permissions:` block, a `pull_request_target`
trigger combined with checking out `github.event.pull_request.head.sha`,
and a `self-hosted` runner.

**`clean_ci.yml` (edge case — should produce zero findings):** uses a
pinned commit SHA for `actions/checkout`, an explicit
`permissions: {contents: read}` block, a normal `pull_request` trigger (not
`_target`), a proper `ubuntu-latest` runner, and references its API key via
`${{ secrets.API_KEY }}` instead of a literal string.

**Result:** the vulnerable file triggered all 9 expected findings across
5 rule categories; the clean file triggered **zero** findings — confirming
the rules don't false-positive on a well-configured workflow.

**Additional edge case — unparseable YAML:** verified separately that a
malformed workflow file produces a graceful `PARSE-001` LOW-severity
finding rather than crashing the whole scan (this was actually hit
mid-development when a fixture had a YAML syntax error — see Learning).

## Evidence

- `evidence/console_output.txt` — full run log
- `evidence/audit_report.json` — structured machine-readable findings
- `evidence/audit_report.md` — human-readable findings report
- `evidence/test-fixtures/` — the two workflow files used above

Result summary from the run:

```
[+] Summary: {'CRITICAL': 4, 'HIGH': 0, 'MEDIUM': 5, 'LOW': 0}
```

All 4 CRITICAL findings and all 5 MEDIUM findings came from
`vulnerable_deploy.yml`; `clean_ci.yml` contributed nothing.

## Result

The auditor correctly distinguished a deliberately misconfigured workflow
from a well-configured one, with zero false positives on the clean fixture
and full coverage of every misconfiguration seeded into the vulnerable
fixture. Output is actionable — each finding names the exact rule, file,
line (where applicable), and a plain-English explanation of the risk.

## Security Relevance

Every rule here maps to a real, documented CI/CD attack pattern:
hardcoded secrets are the most common source of pipeline-related breaches;
unpinned actions are a textbook software-supply-chain risk (a compromised
or re-tagged upstream action runs with your pipeline's permissions);
`pull_request_target` + untrusted checkout is GitHub's own documented
"critical" anti-pattern; missing `permissions:` blocks default to broader
`GITHUB_TOKEN` scope than most jobs need. Catching these before merge is
far cheaper than responding to the incident afterward.

## Limitations

- Only covers GitHub Actions YAML — no GitLab CI, Jenkins, or CircleCI support yet.
- Secret detection is regex/pattern-based, not entropy-based — it will miss
  secrets that don't match a known pattern, and could false-positive on
  long non-secret strings that happen to match (e.g., a hash or UUID in a
  `token:` field). In this test run it did not false-positive, but that's
  not a guarantee against all inputs.
- Cannot check branch-protection rules, required reviewers, or org-level
  policies — those live in GitHub's API/settings, not the workflow YAML,
  and are explicitly out of scope (documented as a stub rule rather than
  silently skipped).
- Does not follow `workflow_call`/reusable workflow references to audit
  the called workflow's own file.
- Not tested against a live, real-world open-source repo in this
  submission — validated against purpose-built fixtures instead.

## Learning

Writing the `clean_ci.yml` negative-control fixture alongside the
vulnerable one turned out to be as valuable as the vulnerable fixture
itself — it's what actually proved the rules aren't just always firing.
I also hit a real YAML parsing edge case during development (an inline
colon inside an unquoted scalar broke `yaml.safe_load`), which is exactly
the kind of malformed-input scenario `PARSE-001` exists to handle
gracefully rather than crash the whole audit run.

## Future Improvement

- Add entropy-based secret detection (e.g., a Shannon-entropy check) to
  catch secrets that don't match a known prefix pattern
- Add GitLab CI and Jenkins declarative-pipeline rule sets
- Add an optional `--github-api` mode that pulls branch protection /
  required-reviewer settings to close the gap noted in Limitations
- Add a SARIF output format so findings can be uploaded to GitHub's
  code-scanning UI directly
- Test against a real, permissioned open-source repository and attach
  that evidence
