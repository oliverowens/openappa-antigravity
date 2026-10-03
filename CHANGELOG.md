# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Automated release workflows and branch protection.

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
