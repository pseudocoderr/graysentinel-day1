#!/usr/bin/env python3
"""
auditor.py
CI/CD Security Misconfiguration Auditor -- GraySentinel Day 1, Project 02.

Scans a directory (typically a cloned repo's .github/workflows/) for
GitHub Actions workflow YAML files and checks them against a rule set
covering: hardcoded secrets, unpinned third-party actions, missing or
overly broad permissions, dangerous trigger patterns, and self-hosted
runner exposure.

Usage:
    python3 auditor.py <path-to-repo-or-workflows-dir> --output-dir evidence
"""

import argparse
import glob
import json
import os
import sys
from datetime import datetime, timezone

import yaml
from rules import ALL_RULES, Finding

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def find_workflow_files(root: str) -> list:
    patterns = [
        os.path.join(root, ".github", "workflows", "*.yml"),
        os.path.join(root, ".github", "workflows", "*.yaml"),
        os.path.join(root, "*.yml"),
        os.path.join(root, "*.yaml"),
    ]
    files = set()
    for pattern in patterns:
        files.update(glob.glob(pattern))
    return sorted(files)


def audit_file(path: str) -> list:
    with open(path, "r", errors="ignore") as f:
        raw_text = f.read()
    try:
        workflow = yaml.safe_load(raw_text)
    except yaml.YAMLError as e:
        return [Finding(
            rule_id="PARSE-001",
            severity="LOW",
            title="Could not parse workflow YAML",
            detail=f"YAML parse error: {e}",
            file=path,
        )]

    findings = []
    for rule in ALL_RULES:
        findings.extend(rule(workflow, raw_text, path))
    return findings


def run_audit(target_dir: str, output_dir: str) -> dict:
    print(f"[*] Scanning for GitHub Actions workflows under: {target_dir}")
    files = find_workflow_files(target_dir)
    print(f"[+] Found {len(files)} workflow file(s)")

    report = {
        "target": target_dir,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "files_scanned": files,
        "findings": [],
    }

    for path in files:
        print(f"[*] Auditing {path}")
        findings = audit_file(path)
        for f in findings:
            print(f"    [{f.severity}] {f.rule_id}: {f.title}")
        report["findings"].extend([f.__dict__ for f in findings])

    report["findings"].sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    report["summary"] = {
        sev: sum(1 for f in report["findings"] if f["severity"] == sev)
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    }

    os.makedirs(output_dir, exist_ok=True)
    json_path = os.path.join(output_dir, "audit_report.json")
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)

    md_path = os.path.join(output_dir, "audit_report.md")
    with open(md_path, "w") as f:
        f.write(render_markdown(report))

    print(f"\n[+] Reports written to {json_path} and {md_path}")
    print(f"[+] Summary: {report['summary']}")
    return report


def render_markdown(report: dict) -> str:
    lines = [f"# CI/CD Security Audit: {report['target']}",
             f"\n_Scan window: {report['started_at']} -> {report['finished_at']}_\n",
             f"**Files scanned:** {len(report['files_scanned'])}\n",
             f"**Summary:** " + ", ".join(f"{k}: {v}" for k, v in report["summary"].items()) + "\n"]

    if not report["findings"]:
        lines.append("No findings.")
        return "\n".join(lines)

    for finding in report["findings"]:
        lines.append(f"\n## [{finding['severity']}] {finding['title']}")
        lines.append(f"- **Rule:** `{finding['rule_id']}`")
        lines.append(f"- **File:** `{finding['file']}`" +
                      (f" (line {finding['line']})" if finding.get("line") else ""))
        lines.append(f"- **Detail:** {finding['detail']}")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="GraySentinel CI/CD Security Misconfiguration Auditor")
    parser.add_argument("target", help="Path to a repo root (or .github/workflows dir)")
    parser.add_argument("--output-dir", default="./evidence",
                         help="Directory to write JSON/Markdown reports into.")
    args = parser.parse_args()

    if not os.path.isdir(args.target):
        print(f"[!] {args.target} is not a directory.")
        sys.exit(1)

    print("=" * 70)
    print("GraySentinel CI/CD Security Misconfiguration Auditor")
    print("Static analysis of workflow YAML -- read-only, no pipeline execution.")
    print("=" * 70)

    run_audit(args.target, args.output_dir)


if __name__ == "__main__":
    main()
