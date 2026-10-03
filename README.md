# OpenAPPA Integration for Google Antigravity

[![OpenAPPA](https://img.shields.io/badge/OpenAPPA-v1-blue.svg)](https://github.com/archestra-ai/OpenAPPA)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-brightgreen.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## About

**openappa-antigravity** provides an OpenAPPA Information-Flow Control (IFC) runtime and adapter for the **Google Antigravity** agent platform. It enables fine-grained policy enforcement, automated runtime secret redaction, subagent trajectory quarantine, and fail-closed safety gating.

## Overview

OpenAPPA protects agents from prompt injection, untrusted web execution, and data exfiltration using strict Information-Flow Control algebra:
* **Trust Lattice**: `suspicious` $\le$ `trusted` (meet is `min`). Ingesting untrusted external data (e.g. web pages or search queries) degrades the trajectory trust floor, preventing subsequent high-privilege executions (such as shell commands or filesystem writes).
* **Audience Chain**: `self` $\le$ `internal` $\le$ `public`. Reading sensitive credential paths narrows trajectory audience to `self`. Data marked `self` or `internal` cannot flow to `public` outbound network destinations without approved remedies or secret redaction.
* **Fail-Closed Guarantees**: Any undeclared tool call, unliftable policy gap, or runtime network error immediately stops tool execution and withholds output.

## Architecture

Antigravity operates with a **dual-layer integration**:
1. **Layer A: Native Lifecycle Hooks (`hooks.json`)**
   * Plugs into Antigravity's `PreToolUse` lifecycle hook via `adapter/hooks_handler.py`.
   * Enforces fail-closed blocking before tool execution.
2. **Layer B: Agent Loop Interceptor (`adapter/agent_loop.py`)**
   * Intercepts `ToolResult` outputs to perform automated secrets masking (`redact-secrets`) and output withholding for indeterminate runs.
   * Isolates child subagent contexts (`ChildStart`) and attests return payloads against JSON schemas (`ChildEnd` / `attest-schema`).
   * Handles remedy execution workflows (`execute_remedy_plan`) to authorize blocked calls.

## Directory Structure

```text
openappa-antigravity/
├── adapter/
│   ├── agent_loop.py          # Complete agent loop proxy with call, result & subagent checks
│   ├── antigravity_adapter.py # Canonical tool normalizer and selector extractor
│   ├── client.py              # OpenAPPA Wire Protocol 1 HTTP client (fail-closed)
│   └── hooks_handler.py       # CLI bridge for Antigravity .agents/hooks.json
├── policy/
│   └── appa.toml              # Root policy defining tool contracts, labels & sanitizers
├── runtime/
│   ├── algebra.py             # APPA Information-Flow Control monoid & lattice algebra
│   ├── engine.py              # Trajectory state store and decision engine
│   ├── policy_loader.py       # Built-in TOML policy loader
│   ├── sanitizers.py          # redact-secrets and attest-schema sanitizers
│   └── server.py              # OpenAPPA HTTP server (127.0.0.1:8788)
├── skills/
│   └── appa-guide/
│       └── SKILL.md           # Antigravity-specific setup and tuning guide
└── tests/
    └── test_suite.py          # Automated verification test suite (10 test cases)
```

## Tool Mapping

| Native Tool | Canonical OpenAPPA ID | Key Selector | Security Rules |
| :--- | :--- | :--- | :--- |
| `run_command` | `host/antigravity/run_command` | `command` | Requires `trusted`. Accessing credentials (`.env*`, `.ssh/*`, `.aws/*`, tokens) narrows audience to `self`. |
| `view_file` | `host/antigravity/view_file` | `path` | Credential paths narrow audience to `self`. Secret tokens masked by `redact-secrets`. |
| `write_to_file` | `host/antigravity/write_to_file` | `path` | Requires `trusted` trajectory. Blocks writes instructed by untrusted web pages. |
| `replace_file_content`| `host/antigravity/replace_file_content` | `path` | Requires `trusted` trajectory. |
| `read_url_content` | `host/antigravity/read_url_content` | `url` | Requires `public` audience. Downgrades trajectory trust to `suspicious`. |
| `search_web` | `host/antigravity/search_web` | `query` | Requires `public` audience. Downgrades trajectory trust to `suspicious`. |
| `invoke_subagent` | `host/antigravity/invoke_subagent` | N/A | Starts quarantined child context. Returns require schema attestation. |
| `execute_remedy_plan`| `mcp__appa__execute_remedy_plan` | `offer_id` | Authorizes retry of blocked calls upon approved remedy. |

## Running the Tests

To run the automated verification test suite:

```bash
python -m unittest tests/test_suite.py
```

The test suite verifies:
1. Denied calls never execute (undeclared tools, untrusted shell commands, credential exfiltration).
2. Blocked / sensitive results never reach the model (`redact-secrets` masks keys, indeterminate runs withheld).
3. Runtime errors stop the flow (fail-closed if server down).
4. Remedy flow works (`execute_remedy_plan` with `offer_id` unblocks retry).
5. Subagent context isolation and return schema attestation.
6. Native Hook handler contract (`PreToolUse`).

## License

MIT
