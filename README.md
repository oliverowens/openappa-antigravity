# OpenAPPA Integration for Google Antigravity

[![OpenAPPA](https://img.shields.io/badge/OpenAPPA-v1-blue.svg)](https://github.com/archestra-ai/OpenAPPA)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-brightgreen.svg)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-0.4.0-informational.svg)](CHANGELOG.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)


## About

**openappa-antigravity** provides an [OpenAPPA](https://github.com/archestra-ai/OpenAPPA) Information-Flow Control (IFC) runtime and adapter for the **Google Antigravity** agent platform. It provides mathematically sound, fail-closed policy enforcement, automated runtime secret redaction, subagent trajectory quarantine, and prompt injection defense.

## Overview

OpenAPPA protects agents from prompt injection, untrusted web execution, and data exfiltration using strict Information-Flow Control algebra:
* **Trust Lattice**: `suspicious` $\le$ `trusted` (meet is `min`). Ingesting untrusted external data (e.g. unverified web pages or search queries) degrades the trajectory trust floor, preventing subsequent high-privilege executions (such as shell commands or filesystem writes).
* **Audience Chain**: `self` $\le$ `internal` $\le$ `public`. Reading sensitive credential paths narrows trajectory audience to `self`. Data marked `self` or `internal` cannot flow to `public` outbound network destinations without approved remedies or secret redaction.
* **Fail-Closed Guarantees**: Any undeclared tool call, unliftable policy gap, or runtime network error immediately stops tool execution and withholds output.

---

## Installation

Install `openappa-antigravity` into your Python environment (Python 3.11+ required):

```bash
# Install from source in editable mode:
git clone https://github.com/oliverowens/openappa-antigravity.git
cd openappa-antigravity
pip install -e .

# Or install directly from PyPI (once published):
pip install openappa-antigravity
```

---

## Architecture & Integration Layers

Antigravity operates with a **dual-layer integration**:

1. **Layer A: Native Lifecycle Hooks (`hooks.json`)**
   * Plugs into Antigravity's `PreToolUse` lifecycle hook via `adapter/hooks_handler.py`.
   * Enforces fail-closed blocking before tool execution.
2. **Layer B: Agent Loop Interceptor (`adapter/agent_loop.py`)**
   * Intercepts `ToolResult` outputs to perform automated secrets masking (`redact-secrets`) and output withholding for indeterminate runs.
   * Isolates child subagent contexts (`ChildStart`) and attests return payloads against JSON schemas (`ChildEnd` / `attest-schema`).
   * Handles remedy execution workflows (`execute_remedy_plan`) to authorize blocked calls.

---

## Governance & External Services

Configured in [`policy/appa.toml`](policy/appa.toml):

### 1. Human-in-the-Loop (HITL) Approvals
* **Default Mode**: Interactive in-chat modal (`mode = "chat"`).
* **Configurable Options**:
  * `chat`: Native Antigravity approval dialogs and prompts.
  * `slack`: Dispatch remedy requests to a designated Slack security channel.
  * `pagerduty`: Trigger approval incident cards for high-risk operations.
  * `cli`: Terminal-based prompt.

### 2. Classification Service
* **Default Mode**: Local heuristic classifier (`mode = "local"`).
* Evaluates tool selectors, arguments, and command patterns instantly with zero external dependencies and no network latency.

### 3. Redaction Engine & Documented Limitations
* **Default Engine**: Built-in regex sanitizer (`engine = "builtin-regex"`).
* **Capabilities**: Masks RSA/EC private keys, AWS access keys, GitHub personal access tokens (`ghp_...`), bearer tokens, passwords, and JWTs in tool outputs before they reach the model.
* **Documented Limitations**:
  * The local sanitizer relies on known token patterns, structural keywords (`api_key =`, `password =`), and cryptographic headers.
  * It does not detect high-entropy random strings lacking semantic key indicators, custom internal proprietary token structures, or steganographic text.
  * Organizations requiring comprehensive data loss prevention (PII, HIPAA, credit cards) should route tool outputs through an external DLP / Microsoft Presidio service.

### 4. Directory Service (Roadmap Feature)
* **Status**: Planned (`provider = "none"`, `status = "planned"`).
* Future releases will synchronize audience groups with **GitHub Organization Collaborators**, **Okta**, or **SCIM** to automatically distinguish internal team members from external repository contributors.

---

## Boundaries, Domains & Subagent Isolation

### Filesystem Boundaries
* **Workspace Enforced**: By default, file modifications (`write_to_file`, `replace_file_content`) are confined to the active workspace/project root (`workspace_only = true`).
* Attempts to write to system directories (`C:/Windows`, `/etc`, `/usr`) are blocked fail-closed. Additional allowed paths can be defined in `allowed_external_paths`.

### Network & Trusted Domains
* Web fetching tools (`read_url_content`) check target URLs against `trusted_domains`.
* **Trusted Domains** (e.g. `docs.python.org`, `github.com`, `pypi.org`): Preserves `trusted` trajectory status, allowing subsequent code execution and commands.
* **Untrusted Domains**: Automatically degrades trajectory trust to `suspicious`, disallowing subsequent shell commands.

### Subagent Delegation Policy
* **Default Role**: Quarantined research (`default_role = "research"`).
* **Allowed Tools**: `view_file`, `search_web`, `read_url_content`.
* **Blocked by Default**: `run_command` (shell execution) and file writes are blocked in subagent contexts to prevent lateral delegation attacks.
* **Return Attestation**: Subagent outputs crossing back into the parent trajectory must pass strict JSON schema attestation (`attest-schema`).

---

## Directory Structure

```text
openappa-antigravity/
├── .agents/
│   ├── hooks.json             # Native Antigravity PreToolUse hook configuration
│   └── skills/
│       └── appa-guide/        # Antigravity setup, tuning, and inspection skill
├── adapter/
│   ├── agent_loop.py          # Complete agent loop proxy with call, result & subagent checks
│   ├── antigravity_adapter.py # Canonical tool normalizer and selector extractor
│   ├── cli.py                 # Canonical OpenAPPA CLI (describe, replay, yell, audit, install, version)
│   ├── client.py              # OpenAPPA Wire Protocol 1 HTTP client (fail-closed)
│   └── hooks_handler.py       # CLI bridge for Antigravity .agents/hooks.json
├── policy/
│   └── appa.toml              # Root policy defining tool contracts, labels, sanitizers & audit
├── policy-tests/
│   └── trajectories_replay.json # Scripted deterministic replay trace suite
├── runtime/
│   ├── algebra.py             # APPA Information-Flow Control monoid & lattice algebra
│   ├── audit.py               # Local decision audit logging, JSONL/Markdown generator & secret masking
│   ├── engine.py              # Trajectory state store and decision engine
│   ├── policy_loader.py       # Built-in TOML policy loader with include = [...] support
│   ├── sanitizers.py          # redact-secrets, attest-schema & RFC 8785 canonical JSON
│   └── server.py              # OpenAPPA HTTP server (127.0.0.1:8788)
├── appa-package.toml          # Canonical OpenAPPA battery package manifest
├── appa.py                    # Root CLI entry point
└── tests/
    └── test_suite.py          # Automated verification test suite (27 test cases)
```

---

## Canonical OpenAPPA CLI

The repository includes a complete implementation of the canonical OpenAPPA CLI (`python appa.py` or `python -m adapter.cli`):

```bash
# Validate policy configuration, verify syntax and display rules fingerprint
python appa.py describe --check

# Check runtime server status, active PID, policy key, and session counts
python appa.py status

# Start, stop, or hot-reload the OpenAPPA background daemon
python appa.py start
python appa.py restart --reload-only
python appa.py stop

# Install portable Antigravity lifecycle hooks (PreInvocation + PreToolUse)
python appa.py install              # Global (~/.gemini/config/hooks.json)
python appa.py install --workspace  # Current workspace (.agents/hooks.json)

# Inspect and review decision audit trails (.appa_audit/ in active workspace)
python appa.py audit status         # Show audit subsystem health, dir, and decision counts
python appa.py audit list           # List all recorded sessions with allowed/blocked tallies
python appa.py audit view [session] # Review decisions, triggered rules, and trajectory shifts
python appa.py audit enable|disable # Toggle audit logging in policy TOML configuration

# Deterministically replay recorded event traces without running live tools
python appa.py replay policy-tests/

# Inspect and verify semantic versioning
python appa.py version                # Display active package version
python appa.py version --check        # Verify all 5 package manifests are in lockstep

# Generate an openappa.yell.v1 diagnostic report
python appa.py yell
```

---

## Decision Audit Trails (`.appa_audit/`)

OpenAPPA caches and stores all security decisions directly in a `.appa_audit/` directory inside the active agent workspace:

- **Configurable Toggle**: Configured via `[policy.audit]` in `policy/appa.toml` or via the `OPENAPPA_AUDIT=1|0` environment variable.
- **Dual Persistence Formats**:
  * **Structured JSONL (`session_<id>.jsonl`)**: Deterministic event log compatible with `appa replay`.
  * **Markdown Review Card (`session_<id>.md`)**: Human-readable markdown document with color status badges (🟢 ALLOWED, 🔴 BLOCKED, 🟡 REDACTED), matched policy rules, trajectory state before/after, and remedy offers.
- **Argument Redaction**: Automatic credential masking for tokens, passwords, and private keys before logging.


## Tool Mapping

| Native Tool | Canonical OpenAPPA ID | Key Selector | Security Rules |
| :--- | :--- | :--- | :--- |
| `run_command` | `host/antigravity/run_command` | `command` | Requires `trusted`. Accessing credentials (`.env*`, `.ssh/*`, `.aws/*`, tokens) narrows audience to `self`. |
| `view_file` | `host/antigravity/view_file` | `path` | Credential paths narrow audience to `self`. Secret tokens masked by `redact-secrets`. |
| `write_to_file` | `host/antigravity/write_to_file` | `path` | Requires `trusted` trajectory and workspace confinement. |
| `replace_file_content`| `host/antigravity/replace_file_content` | `path` | Requires `trusted` trajectory and workspace confinement. |
| `read_url_content` | `host/antigravity/read_url_content` | `url` | Requires `public` audience. Preserves trust for allowlisted domains; degrades to `suspicious` for untrusted URLs. |
| `search_web` | `host/antigravity/search_web` | `query` | Requires `public` audience. Downgrades trajectory trust to `suspicious`. |
| `invoke_subagent` | `host/antigravity/invoke_subagent` | N/A | Starts quarantined child context. Returns require schema attestation. |
| `send_message` | `host/antigravity/send_message` | `recipient` | Requires `trusted` trajectory. Governs inter-agent messaging. |
| `manage_subagents` | `host/antigravity/manage_subagents` | `action` | Requires `trusted` trajectory. Governs listing and terminating subagents. |
| `define_subagent` | `host/antigravity/define_subagent` | N/A | Requires `trusted` trajectory. Prevents unverified subagent role creation. |
| `ask_question` | `host/antigravity/ask_question` | `questions` | Requires `trusted` trajectory. Prevents prompt injection from presenting spoofed dialogs. |
| `manage_task` | `host/antigravity/manage_task` | `action` | Requires `trusted` trajectory. Controls background tasks. |
| `schedule` | `host/antigravity/schedule` | `prompt` | Requires `trusted` trajectory. Controls timer/cron tasks. |
| `generate_image` | `host/antigravity/generate_image` | `prompt` | Requires `trusted` trajectory. |
| `execute_remedy_plan`| `mcp__appa__execute_remedy_plan` | `offer_id` | Authorizes retry of blocked calls upon approved remedy. |

---

## Running the Tests

To run the automated verification test suite:

```bash
python -m unittest tests/test_suite.py
```

The 27 automated tests verify:
1. Denied calls never execute (undeclared tools, untrusted shell commands, credential exfiltration).
2. Blocked / sensitive results never reach the model (`redact-secrets` masks keys, indeterminate runs withheld).
3. Runtime errors stop the flow (fail-closed if server down).
4. Remedy flow works (`execute_remedy_plan` with `offer_id` unblocks retry).
5. Subagent context isolation and return schema attestation (`attest-schema`).
6. Subagent default restrictions (shell commands in child context blocked).
7. Trusted domain allowlist (fetching from trusted domain preserves trust, allowing subsequent commands).
8. Workspace boundary enforcement (writing to system paths outside workspace blocked).
9. Native Hook handler contract (`PreToolUse`).
10. OpenAPPA CLI `describe --check` policy validation.
11. Deterministic trace replay (`appa replay`).
12. Schema-compliant diagnostic reporting (`openappa.yell.v1`).
13. Battery composition via `include = [...]` in `policy_loader.py`.
14. Complete Antigravity interactive tool governance (`ask_question`, `send_message`, etc.).
15. Decision audit logging into workspace `.appa_audit` (JSONL + Markdown).
16. Credential masking in recorded tool arguments.
17. Audit toggle enforcement via `[policy.audit]` and `OPENAPPA_AUDIT`.
18. CLI inspection tooling (`appa audit status`, `list`, `view`).
19. Lockstep SemVer manifest synchronization (`pyproject`, `appa-package`, inits, `README`).
20. Strict SemVer 2.0.0 syntax validation and parser robustness.
21. Semantic version bump arithmetic (patch, minor, major).
22. Conventional Commit bump inference (`fix:` -> patch, `feat:` -> minor, `BREAKING CHANGE:` -> major).
23. CLI version management (`appa version` and `appa version --check`).

---

## Contributing & Security

* **Contributing**: Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md).
* **AI Agent Directives**: Automated coding agents must adhere to the [AI Agent Operational & Versioning Protocol](AGENTS.md).
* **Security Policy**: For responsible vulnerability disclosure instructions, please consult our [Security Policy](SECURITY.md).

---

## License

This project is licensed under the [MIT License](LICENSE).


