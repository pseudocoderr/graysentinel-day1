# CI/CD Security Audit: /home/claude/test_repo

_Scan window: 2026-09-14T09:50:20.754623+00:00 -> 2026-09-14T09:50:20.760886+00:00_

**Files scanned:** 2

**Summary:** CRITICAL: 4, HIGH: 0, MEDIUM: 5, LOW: 0


## [CRITICAL] Possible hardcoded secret: AWS secret access key
- **Rule:** `SECRET-001`
- **File:** `/home/claude/test_repo/.github/workflows/vulnerable_deploy.yml` (line 20)
- **Detail:** A value matching a credential pattern was found directly in the workflow file instead of referenced via ${{ secrets.NAME }}.

## [CRITICAL] Possible hardcoded secret: AWS access key ID
- **Rule:** `SECRET-001`
- **File:** `/home/claude/test_repo/.github/workflows/vulnerable_deploy.yml` (line 19)
- **Detail:** A value matching a credential pattern was found directly in the workflow file instead of referenced via ${{ secrets.NAME }}.

## [CRITICAL] Possible hardcoded secret: Hardcoded credential-like string
- **Rule:** `SECRET-001`
- **File:** `/home/claude/test_repo/.github/workflows/vulnerable_deploy.yml` (line 26)
- **Detail:** A value matching a credential pattern was found directly in the workflow file instead of referenced via ${{ secrets.NAME }}.

## [CRITICAL] pull_request_target checking out untrusted PR head
- **Rule:** `TRIGGER-001`
- **File:** `/home/claude/test_repo/.github/workflows/vulnerable_deploy.yml`
- **Detail:** This workflow trigger runs with access to repo secrets even for fork PRs, and appears to check out the PR's head ref. This is a known pattern for secret exfiltration / arbitrary code execution from a malicious fork.

## [MEDIUM] Unpinned third-party action: actions/checkout@main
- **Rule:** `SUPPLYCHAIN-001`
- **File:** `/home/claude/test_repo/.github/workflows/vulnerable_deploy.yml`
- **Detail:** Job 'deploy' uses 'actions/checkout@main', referenced by a mutable tag/branch ('main') rather than a pinned commit SHA. If the upstream tag is moved or the repo is compromised, malicious code could run in your pipeline unnoticed.

## [MEDIUM] Unpinned third-party action: some-org/some-action@v1
- **Rule:** `SUPPLYCHAIN-001`
- **File:** `/home/claude/test_repo/.github/workflows/vulnerable_deploy.yml`
- **Detail:** Job 'deploy' uses 'some-org/some-action@v1', referenced by a mutable tag/branch ('v1') rather than a pinned commit SHA. If the upstream tag is moved or the repo is compromised, malicious code could run in your pipeline unnoticed.

## [MEDIUM] Unpinned third-party action: another-org/deploy-action@master
- **Rule:** `SUPPLYCHAIN-001`
- **File:** `/home/claude/test_repo/.github/workflows/vulnerable_deploy.yml`
- **Detail:** Job 'deploy' uses 'another-org/deploy-action@master', referenced by a mutable tag/branch ('master') rather than a pinned commit SHA. If the upstream tag is moved or the repo is compromised, malicious code could run in your pipeline unnoticed.

## [MEDIUM] No explicit `permissions:` block at workflow level
- **Rule:** `PERM-001`
- **File:** `/home/claude/test_repo/.github/workflows/vulnerable_deploy.yml`
- **Detail:** Without an explicit permissions block, GITHUB_TOKEN may default to broad read/write access. Best practice is to set 'permissions: {contents: read}' at the top level and elevate per-job only where needed.

## [MEDIUM] Self-hosted runner referenced
- **Rule:** `RUNNER-001`
- **File:** `/home/claude/test_repo/.github/workflows/vulnerable_deploy.yml`
- **Detail:** Self-hosted runners on public repos are a known risk: a malicious fork PR (especially combined with pull_request_target) can execute arbitrary code on infrastructure you control. Verify this runner is not exposed to untrusted workflow triggers.