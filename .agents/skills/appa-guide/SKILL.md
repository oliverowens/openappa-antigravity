---
name: appa-guide
description: Set up, inspect, and tune OpenAPPA security policies on the Google Antigravity host. Checks tool coverage, connects batteries, configures IFC boundaries, explains blocks, and configures remedies.
argument-hint: "[init | adjust | explain | what you want]"
---

# OpenAPPA Guide for Antigravity Host

This skill guides the setup, policy tuning, and operational inspection of OpenAPPA on the **Google Antigravity** agent platform.

## Architecture & Integration Layers

Antigravity operates with a dual-layer integration model to provide comprehensive Information-Flow Control (IFC):

1. **Layer A: Native Lifecycle Hooks (`hooks.json`)**
   - Hook: `PreToolUse`
   - Script: `python ./adapter/hooks_handler.py`
   - Capabilities: Synchronously blocks unauthorized tool proposals (`decision: "deny"`) before execution.
   - Limitation: Antigravity's native `PostToolUse` hook only receives execution status/error codes, not raw tool output strings.

2. **Layer B: Agent Loop Interceptor (`adapter/agent_loop.py`)**
   - Intercepts full tool invocation pipeline:
     - `ToolCall`: Pre-execution gating against policy.
     - `ToolResult`: Output inspection, automatic secret redaction (`redact-secrets`), and output withholding for indeterminate runs.
     - `Subagent`: Child context quarantine (`child_start`) and return payload schema attestation (`attest-schema` / `child_end`).
     - `Remedies`: Handling `execute_remedy_plan(offer_id="...")` to authorize remediated retries.

## Tool Canonicalization & Battery Mapping

Antigravity native tools map to OpenAPPA canonical identifiers:

| Native Tool | Canonical OpenAPPA ID | Selector Key | Default Policy Intent |
| :--- | :--- | :--- | :--- |
| `run_command` | `host/antigravity/run_command` | `command` | Requires `trusted`. Accessing credentials (`.env`, `.ssh`, `.aws`, tokens) narrows to `self`. |
| `view_file` | `host/antigravity/view_file` | `path` | Credential files narrow audience to `self`. Read outputs sanitized via `redact-secrets`. |
| `write_to_file` | `host/antigravity/write_to_file` | `path` | Requires `trusted` trajectory. Prevents writes directed by untrusted web inputs. |
| `replace_file_content` | `host/antigravity/replace_file_content` | `path` | Requires `trusted` trajectory. |
| `read_url_content` | `host/antigravity/read_url_content` | `url` | Requires `public` audience. Ingested content degrades trajectory to `suspicious`. |
| `search_web` | `host/antigravity/search_web` | `query` | Requires `public` audience. Search results degrade trajectory to `suspicious`. |
| `invoke_subagent` | `host/antigravity/invoke_subagent` | N/A | Starts quarantined child context. Returns require `attest-schema` validation. |
| `execute_remedy_plan` | `mcp__appa__execute_remedy_plan` | `offer_id` | Control tool: authorizes retry of blocked calls upon approved remedy. |

## Operational Modes

- **`init`**: Scan installed tools, inspect current `policy/appa.toml`, verify runtime server health (`GET http://127.0.0.1:8788/health`), and propose default policy.
- **`adjust`**: Adjust trust ceilings, reader lists, credential path selectors, or external service integrations (HITL approvals, secret redaction, directory sync).
- **`explain`**: Explain why a tool call was denied or why an output was redacted/withheld, citing the active policy rules and trajectory label.

## Strict Security Guarantees

- **Fail-Closed**: If the OpenAPPA runtime server is down, unreachable, or errors, all tool calls are immediately denied, and outputs are withheld.
- **Autonomous Within Boundaries**: As long as trusted data remains within its allowed audience, tools execute autonomously without human interruption.
- **Remedy Offer Chain**: Blocks that are curable emit an `offer_id`. Passing this `offer_id` to `execute_remedy_plan` unblocks authorized retries.
