# AGENTS.md: AI Agent Operational & Versioning Protocol

This document defines mandatory guidelines for all autonomous coding agents (including Google Antigravity, GitHub Copilot, Claude Code, Cursor, and Codex) interacting with the **openappa-antigravity** repository.

---

## 1. Architectural & Security Directives

1. **Information-Flow Control (IFC) Invariants**:
   - The core lattice algebra must **never** be inverted:
     - **Trust Lattice**: `suspicious <= trusted` (meet is `min`). Ingesting unverified external inputs degrades trust floor.
     - **Audience Chain**: `self <= internal <= public`. Accessing credentials narrows audience to `self`. Data marked `self` or `internal` cannot flow to public network endpoints without approved remedies or secret sanitization.
   - All tool evaluations must be **fail-closed**: undeclared tools or unhandled exceptions must deny execution and withhold output.

2. **Tool Mapping Contracts**:
   - Any new tool or selector added must be declared in [`policy/appa.toml`](policy/appa.toml) and normalized in [`adapter/antigravity_adapter.py`](adapter/antigravity_adapter.py).

---

## 2. Mandatory Semantic Versioning (SemVer 2.0.0) Protocol

All AI agents proposing changes, creating pull requests, or preparing releases **MUST** adhere to Semantic Versioning (`MAJOR.MINOR.PATCH`):

### When to Bump What:
* **PATCH (`x.y.Z`)**:
  - Backward-compatible bug fixes.
  - Documentation additions or fixes.
  - Test suite enhancements or non-functional refactoring.
  - Minor internal optimizations that do not change public APIs, policy schemas, or CLI syntax.
* **MINOR (`x.Y.0`)**:
  - Backward-compatible new features.
  - New policy rules, tool selectors, or batteries.
  - New CLI commands, subcommands, or optional flags.
  - New built-in sanitizers, audit exporters, or hooks handlers.
* **MAJOR (`X.0.0`)**:
  - Incompatible API or wire protocol changes (e.g. changing Wire Protocol 1 structure).
  - Changes to lattice algebra properties or trust/audience ordering.
  - Breaking schema changes to `policy/appa.toml` or `appa-package.toml`.

---

## 3. Manifest Synchronization Rules

**NEVER** edit version strings manually in isolated files. Doing so causes manifest drift and breaks CI.

Version strings are synchronized across 5 manifests:
1. `pyproject.toml` (`version = "X.Y.Z"`)
2. `appa-package.toml` (`version = "X.Y.Z"`)
3. `runtime/__init__.py` (`__version__ = "X.Y.Z"`)
4. `adapter/__init__.py` (`__version__ = "X.Y.Z"`)
5. `README.md` (`badge: version-X.Y.Z-informational`)

### Agent Release & Version Commands:

* **Verify Lockstep Synchronization**:
  ```bash
  python scripts/release.py --verify
  # or via CLI:
  python appa.py version --check
  ```

* **Bump Version Automatically Based on Conventional Commits**:
  ```bash
  python scripts/release.py --auto
  ```

* **Bump Explicit Part**:
  ```bash
  python scripts/release.py --bump patch   # or minor, major
  ```

* **Perform Release with Git Tag and Push**:
  ```bash
  python scripts/release.py --auto --tag --push
  ```

---

## 4. Conventional Commit Standards for Automated Versioning

Agents must format commit titles following the Conventional Commits specification so that automated tooling can infer the required SemVer bump:

* `fix: ...` or `fix(scope): ...` $\rightarrow$ triggers **PATCH** bump.
* `docs: ...`, `chore: ...`, `style: ...`, `perf: ...` $\rightarrow$ triggers **PATCH** bump.
* `feat: ...` or `feat(scope): ...` $\rightarrow$ triggers **MINOR** bump.
* `feat!: ...`, `fix!: ...`, or commit body containing `BREAKING CHANGE:` $\rightarrow$ triggers **MAJOR** bump.

---

## 5. Pre-Commit / Pre-PR Verification Checklist

Before creating a commit or opening a pull request, agents must execute and pass:

```bash
# 1. Verify policy syntax & schema:
python appa.py describe --check

# 2. Run deterministic trace replays:
python appa.py replay policy-tests/

# 3. Verify manifest synchronization:
python scripts/release.py --verify

# 4. Run automated test suite (all 27 tests):
python -m unittest tests/test_suite.py
```
