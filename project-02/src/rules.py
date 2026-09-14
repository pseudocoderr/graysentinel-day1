"""
rules.py
Detection rules for the CI/CD Security Misconfiguration Auditor.
Focused on GitHub Actions workflow YAML files, since it's the most
common CI/CD system candidates will have hands-on access to for
authorized testing (their own repos).

Each rule is a function: (workflow_dict, raw_text, file_path) -> list[Finding]
"""

import re
from dataclasses import dataclass, field
from typing import List


@dataclass
class Finding:
    rule_id: str
    severity: str  # LOW / MEDIUM / HIGH / CRITICAL
    title: str
    detail: str
    file: str
    line: int = 0


# --- Secret-like pattern matching -------------------------------------------------
SECRET_PATTERNS = [
    (r'(?i)aws_secret_access_key\s*[:=]\s*["\']?[A-Za-z0-9/+=]{20,}', "AWS secret access key"),
    (r'(?i)aws_access_key_id\s*[:=]\s*["\']?AKIA[0-9A-Z]{16}', "AWS access key ID"),
    (r'(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*["\'][A-Za-z0-9_\-]{12,}["\']',
     "Hardcoded credential-like string"),
    (r'ghp_[A-Za-z0-9]{36}', "GitHub Personal Access Token"),
    (r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----', "Embedded private key"),
]


def rule_hardcoded_secrets(workflow, raw_text, path) -> List[Finding]:
    findings = []
    for pattern, label in SECRET_PATTERNS:
        for m in re.finditer(pattern, raw_text):
            line_no = raw_text[:m.start()].count("\n") + 1
            findings.append(Finding(
                rule_id="SECRET-001",
                severity="CRITICAL",
                title=f"Possible hardcoded secret: {label}",
                detail="A value matching a credential pattern was found directly in the "
                        "workflow file instead of referenced via ${{ secrets.NAME }}.",
                file=path,
                line=line_no,
            ))
    return findings


def rule_unpinned_actions(workflow, raw_text, path) -> List[Finding]:
    """
    Actions referenced by a mutable tag (e.g. @main, @master, @v1) instead of
    a pinned commit SHA can be silently changed upstream (supply-chain risk).
    """
    findings = []
    if not isinstance(workflow, dict):
        return findings
    jobs = workflow.get("jobs") or {}
    if not isinstance(jobs, dict):
        return findings
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        for step in job.get("steps", []) or []:
            if not isinstance(step, dict):
                continue
            uses = step.get("uses")
            if not uses or "@" not in uses:
                continue
            ref = uses.split("@", 1)[1]
            is_sha = re.fullmatch(r"[0-9a-fA-F]{40}", ref)
            if not is_sha:
                findings.append(Finding(
                    rule_id="SUPPLYCHAIN-001",
                    severity="MEDIUM",
                    title=f"Unpinned third-party action: {uses}",
                    detail=f"Job '{job_name}' uses '{uses}', referenced by a mutable "
                            f"tag/branch ('{ref}') rather than a pinned commit SHA. "
                            f"If the upstream tag is moved or the repo is compromised, "
                            f"malicious code could run in your pipeline unnoticed.",
                    file=path,
                ))
    return findings


def rule_permissive_permissions(workflow, raw_text, path) -> List[Finding]:
    """
    Flags workflows with no explicit `permissions:` block (defaults to broad
    read/write GITHUB_TOKEN permissions on many repos) or an explicit
    write-all grant.
    """
    findings = []
    if not isinstance(workflow, dict):
        return findings
    perms = workflow.get("permissions")
    if perms is None:
        findings.append(Finding(
            rule_id="PERM-001",
            severity="MEDIUM",
            title="No explicit `permissions:` block at workflow level",
            detail="Without an explicit permissions block, GITHUB_TOKEN may default to "
                    "broad read/write access. Best practice is to set 'permissions: "
                    "{contents: read}' at the top level and elevate per-job only where needed.",
            file=path,
        ))
    elif perms == "write-all" or perms == "write":
        findings.append(Finding(
            rule_id="PERM-002",
            severity="HIGH",
            title="Workflow grants write-all permissions",
            detail="The workflow explicitly requests broad write permissions for "
                    "GITHUB_TOKEN. Scope this down to only what each job needs.",
            file=path,
        ))
    return findings


def rule_dangerous_triggers(workflow, raw_text, path) -> List[Finding]:
    """
    Flags pull_request_target combined with a checkout of the PR head ref --
    a well-known pattern that lets fork PRs execute code with access to
    repo secrets.
    """
    findings = []
    if not isinstance(workflow, dict):
        return findings
    on = workflow.get("on") or workflow.get(True)  # YAML may parse bare `on:` oddly
    triggers = []
    if isinstance(on, str):
        triggers = [on]
    elif isinstance(on, list):
        triggers = on
    elif isinstance(on, dict):
        triggers = list(on.keys())

    if "pull_request_target" in triggers and "ref" in raw_text and "github.event.pull_request.head" in raw_text:
        findings.append(Finding(
            rule_id="TRIGGER-001",
            severity="CRITICAL",
            title="pull_request_target checking out untrusted PR head",
            detail="This workflow trigger runs with access to repo secrets even for "
                    "fork PRs, and appears to check out the PR's head ref. This is a "
                    "known pattern for secret exfiltration / arbitrary code execution "
                    "from a malicious fork.",
            file=path,
        ))
    return findings


def rule_self_hosted_runner_on_public_repo(workflow, raw_text, path) -> List[Finding]:
    findings = []
    if "self-hosted" in raw_text:
        findings.append(Finding(
            rule_id="RUNNER-001",
            severity="MEDIUM",
            title="Self-hosted runner referenced",
            detail="Self-hosted runners on public repos are a known risk: a malicious "
                    "fork PR (especially combined with pull_request_target) can execute "
                    "arbitrary code on infrastructure you control. Verify this runner is "
                    "not exposed to untrusted workflow triggers.",
            file=path,
        ))
    return findings


def rule_missing_branch_protection_hint(workflow, raw_text, path) -> List[Finding]:
    """
    Not detectable from workflow YAML alone -- this is a placeholder rule
    that reminds the auditor to check branch protection via the GitHub API,
    documented here so the limitation is explicit rather than silent.
    """
    return []  # Intentionally not implemented from YAML; see report.md Limitations.


ALL_RULES = [
    rule_hardcoded_secrets,
    rule_unpinned_actions,
    rule_permissive_permissions,
    rule_dangerous_triggers,
    rule_self_hosted_runner_on_public_repo,
]
