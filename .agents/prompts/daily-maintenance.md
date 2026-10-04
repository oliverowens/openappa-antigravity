# OpenAPPA Antigravity Daily Maintenance & Health Check

This prompt is designed for daily scheduled execution (via `/schedule` or the Antigravity recurring scheduler) to audit repository health, verify security invariants, clean ephemeral cache drift, check dependencies, and maintain manifest synchronization for **openappa-antigravity**.

---

## Scheduled Task Prompt

```text
Run daily maintenance and health check for the openappa-antigravity repository:
1. Policy & Invariant Verification: Run `python appa.py describe --check` to ensure the policy is VALID and all 29 rules are intact.
2. Deterministic Trace Replay: Run `python appa.py replay policy-tests/` to verify zero replay regressions against the active policy key.
3. Test Suite Execution: Run `python -m unittest tests/test_suite.py` to ensure all 27 unit tests pass.
4. SemVer Manifest Synchronization: Run `python scripts/release.py --verify` to verify lockstep version synchronization across pyproject.toml, appa-package.toml, runtime/__init__.py, adapter/__init__.py, and README.md.
5. Package Build Verification: Run `python -m build --sdist --wheel` to confirm clean package packaging, then clean up the temporary dist/ folder.
6. Workspace & Git Hygiene: Inspect `git status --short`, clean safe temporary cache files (__pycache__, stale .pytest_cache), and check for untracked debris or unpushed commits.
7. Dependency & Security Audit: Run `pip list --outdated` to identify packages needing updates and check GitHub Actions workflows.
8. Conventional Commit Audit: Inspect recent commits with `git log -n 5 --oneline` to ensure adherence to Conventional Commits standards.
9. Report: Output a structured Daily Maintenance Report summarizing the status of each check and any actionable items. Do not weaken any tests or modify policy rules to force a pass.
```

---

## Detailed Step-by-Step Execution Protocol

### Step 1: Policy & Invariant Verification
Execute:
```bash
python appa.py describe --check
```
- **Expected Outcome**: Exit code 0, Status: `VALID`, all 29 declared rules confirmed.
- **Invariant**: Trust lattice (`suspicious <= trusted`) and audience chain (`self <= internal <= public`) must remain intact.

### Step 2: Deterministic Trace Replay
Execute:
```bash
python appa.py replay policy-tests/
```
- **Expected Outcome**: Exit code 0, Replay Summary: `Total=8, Passed=8, Failed=0`.

### Step 3: Automated Test Suite Execution
Execute:
```bash
python -m unittest tests/test_suite.py
```
- **Expected Outcome**: Exit code 0, `Ran 27 tests in ...s, OK`.

### Step 4: Manifest & SemVer Synchronization Check
Execute:
```bash
python scripts/release.py --verify
# Or CLI alias:
python appa.py version --check
```
- **Expected Outcome**: Exit code 0, `SUCCESS: All manifests synchronized at vX.Y.Z`.
- **Constraint**: Never edit individual manifests manually.

### Step 5: Package Build Verification
Execute:
```bash
python -m build --sdist --wheel
```
- **Expected Outcome**: Clean build of sdist (`.tar.gz`) and wheel (`.whl`).
- Clean up generated `dist/` directory after check if no immediate publish is scheduled:
  ```powershell
  Remove-Item -Recurse -Force dist -ErrorAction SilentlyContinue
  ```

### Step 6: Workspace & Git Hygiene Check
Execute:
```bash
git status --short
git branch -vv
```
- Inspect for untracked files, uncommitted edits, or detached heads.
- Safely purge Python compilation artifacts:
  ```powershell
  Get-ChildItem -Path . -Include __pycache__ -Recurse -Directory | Remove-Item -Recurse -Force
  ```
- Check `.appa_audit/` for old session traces.

### Step 7: Dependency & Security Audit
Execute:
```bash
pip list --outdated
```
- Check for outdated dependencies or critical security advisories.

### Step 8: Conventional Commit & Release Readiness
Execute:
```bash
git log -n 5 --oneline
```
- Verify commit message prefix compliance: `feat:`, `fix:`, `chore:`, `docs:`, `perf:`, `test:`.
- Check if pending commits warrant an automatic SemVer bump via `python scripts/release.py --auto`.

---

## Daily Report Template

The agent must end the scheduled run by producing this structured report:

```markdown
## 🛠️ OpenAPPA Daily Maintenance Report - [YYYY-MM-DD]

### Overall Status: [🟢 HEALTHY | 🟡 ATTENTION REQUIRED | 🔴 CRITICAL]

| Area | Check Command | Status | Notes |
|---|---|---|---|
| **Policy & Invariants** | `python appa.py describe --check` | PASS / FAIL | 29 rules validated |
| **Deterministic Replay** | `python appa.py replay policy-tests/` | PASS / FAIL | 8/8 trajectory steps passed |
| **Unit Test Suite** | `python -m unittest tests/test_suite.py` | PASS / FAIL | 27/27 tests passed |
| **SemVer Synchronization**| `python scripts/release.py --verify` | PASS / FAIL | Lockstep at vX.Y.Z |
| **Package Build** | `python -m build` | PASS / FAIL | sdist + wheel verified |
| **Workspace Hygiene** | `git status --short` | CLEAN / DIRTY | Untracked / uncommitted items |
| **Dependencies** | `pip list --outdated` | OK / OUTDATED | Package update status |
| **Commit Standards** | `git log -n 5` | COMPLIANT / NON-COMPLIANT | Conventional commits check |

### Actionable Findings & Next Steps
- [None / List of pending items requiring developer attention]
```
