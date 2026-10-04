# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.1] - 2026-10-05

### Changed & Maintained
- **Skill Manifest Synchronization**: Synchronized `skills/appa-guide/SKILL.md` with `.agents/skills/appa-guide/SKILL.md` to document the `audit` operational mode and argument options.
- **Dependency Automation**: Updated `dependabot/fetch-metadata` action from v2 to v3 in `.github/workflows/dependabot-automerge.yml`.
- **Runtime Daemon Synchronization**: Verified and aligned active local daemon on `http://127.0.0.1:8788` with `v0.5.1`.
- **Repository Hygiene**: Cleaned up ephemeral build artifacts and removed deprecated prompt files.

## [0.5.0] - 2026-10-04

### Added
- **AI Agent Operational & Versioning Protocol (`AGENTS.md`)**: Mandatory guidelines and semantic versioning contracts for autonomous coding agents (Antigravity, Copilot, Cursor, Claude Code, Codex).
- **Test-Driven Semantic Versioning Automation (`scripts/release.py`)**:
  - Automatic Conventional Commit bump inference (`fix:` -> patch, `feat:` -> minor, `BREAKING CHANGE:` -> major).
  - Lockstep manifest synchronization verification across `pyproject.toml`, `appa-package.toml`, `runtime/__init__.py`, `adapter/__init__.py`, and `README.md`.
  - Strict SemVer 2.0.0 syntax parsing and bump calculation.
- **CLI Version Command (`appa version`)**: Added `appa version` to inspect active version and `appa version --check` to verify manifest synchronization.
- **Runtime Version Reporting**: Server `/status` endpoint and `appa status` CLI command now report active runtime package version.
- **SemVer Test Suite**: Added 5 new automated unit tests (27 total tests in `tests/test_suite.py`) validating manifest synchronization, syntax parsing, bump arithmetic, commit inference, and CLI execution.
- **CI Version Integrity Gate**: Added `python scripts/release.py --verify` step to `.github/workflows/ci.yml`.

## [0.4.0] - 2026-10-04

### Added
- **Local Decision Audit Subsystem (`runtime/audit.py`)**: Real-time caching and persistence of OpenAPPA Information-Flow Control decisions, rule triggers, trajectory state transitions, and remedy offers.
- **Workspace-Confined Storage (`.appa_audit/`)**: Automatically records decisions inside `.appa_audit/` within the active agent workspace, resolving workspace paths from Antigravity hook payloads.
- **Dual Persistence Formats**:
  - Structured JSONL (`session_<id>.jsonl`): Deterministic replay event traces directly compatible with `appa replay`.
  - Markdown Review Cards (`session_<id>.md`): Human-readable session cards with visual status badges (🟢 ALLOWED, 🔴 BLOCKED, 🟡 REDACTED), matched policy rules, trajectory state before/after, and remedy offers.
- **Configurable Audit Toggle**: User-controllable toggle via `[policy.audit]` in `policy/appa.toml` or `OPENAPPA_AUDIT` environment variable.
- **Secret Redaction in Arguments**: Automatic credential masking for tokens, passwords, and private keys in logged argument traces.
- **Dual Hook Deduplication**: Idempotent event recording ensuring concurrent global and workspace hooks do not generate duplicate log entries.
- **Audit CLI Commands (`appa audit`)**: Added subcommands `appa audit status`, `appa audit list`, `appa audit view [session_id]`, and `appa audit enable|disable`.
- **Extended Test Suite**: Added 4 automated unit test cases (total 22 tests) validating audit generation, markdown cards, credential masking, disabled toggles, and CLI inspection.

## [0.3.0] - 2026-10-04

### Added
- **Proactive `PreInvocation` Auto-Warmup Hook**: Warms up and verifies runtime server health the moment a prompt is sent, before the LLM begins reasoning or proposing tools.
- **Fail-Safe Polling & Process Lock**: Multi-process lockfile (`openappa_supervisor.lock`) and active health polling (up to 3.5s) to eliminate duplicate spawns and cold-start failures.
- **Daemon Lifecycle Commands**: Added `appa status` (reports PID, policy key, rules, session count), `appa start`, `appa stop` (graceful `/shutdown`), and `appa restart` (`/reload` or restart).
- **Dynamic Policy Reloading**: Upgraded `POST /reload` in `runtime/server.py` to reload `policy/appa.toml` from disk dynamically with live policy key recomputation.

## [0.2.0] - 2026-10-04

### Added
- **Portable CLI Hook Invocation (`appa hook`)**: Added `appa hook` subcommand allowing hook execution without absolute file paths or OS-specific paths.
- **Hook Lifecycle Management (`appa install` / `appa uninstall`)**: Added dynamic installer to configure portable lifecycle hooks in global (`~/.gemini/config/hooks.json`) or workspace (`.agents/hooks.json`) scopes.
- **Console Script Entry Point**: Added `openappa-hook` console script in `pyproject.toml`.

### Changed
- Removed machine-static absolute paths from hook configurations, enabling seamless cross-platform deployment across Windows, macOS, and Linux.
- Added explicit working directory resolution (`cwd`) when auto-spawning runtime server subprocesses.

## [0.1.0] - 2026-10-03

### Added
- **Canonical OpenAPPA IFC Engine**: Checked monoid algebra for trust (`suspicious` $\le$ `trusted`) and audience (`self` $\le$ `internal` $\le$ `public`).
- **Wire Protocol 1 Support**: Full event handling (`session_start`, `prompt`, `turn_end`, `tool_call`, `tool_result`, `child_start`, `child_end`) on `127.0.0.1:8788`.
- **Dual-Layer Integration**: Native Antigravity `PreToolUse` lifecycle hook (`.agents/hooks.json`) and full agent loop proxy (`adapter/agent_loop.py`).
- **Antigravity Tool Coverage**: Declared security contracts for all 14 Antigravity host tools (`run_command`, `view_file`, `write_to_file`, `replace_file_content`, `read_url_content`, `search_web`, `invoke_subagent`, `send_message`, `manage_subagents`, `define_subagent`, `ask_question`, `manage_task`, `schedule`, `generate_image`, `execute_remedy_plan`).
- **Canonical CLI**: `appa describe --check`, `appa replay`, and `appa yell` (`openappa.yell.v1`).
- **Battery Manifest**: `appa-package.toml` specifying host composition and scripts.
- **Battery Composition**: Recursive `include = [...]` support in `runtime/policy_loader.py`.
- **RFC 8785 Canonicalization**: Deterministic JSON encoding for attestation and remedy keys.
- **Automated Verification**: Comprehensive 18-test suite.
