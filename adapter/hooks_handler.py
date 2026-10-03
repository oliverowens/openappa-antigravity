"""
OpenAPPA Lifecycle Hook Handler for Antigravity.

Bridges Antigravity's lifecycle hooks (.agents/hooks.json) to the OpenAPPA runtime.
Implements the PreToolUse contract:
- Inspects proposed tool calls
- Evaluates policy against OpenAPPA runtime
- Returns fail-closed 'deny' or 'allow' decisions on stdout

Usage in hooks.json:
{
  "openappa-gate": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "command": "python path/to/openappa-antigravity/adapter/hooks_handler.py"
          }
        ]
      }
    ]
  }
}
"""

from __future__ import annotations
import json
import sys
from typing import Any, Dict

# Support relative and standalone execution
try:
    from .antigravity_adapter import identify_tool
    from .client import AppaClient, AppaClientError
except ImportError:
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from adapter.antigravity_adapter import identify_tool
    from adapter.client import AppaClient, AppaClientError


def _ensure_runtime_running(client: Optional[AppaClient] = None) -> None:
    """Attempts to auto-launch runtime server if default localhost endpoint is offline."""
    if client and "8788" not in client.runtime_url:
        return
    import subprocess
    import time
    from pathlib import Path
    server_script = Path(__file__).resolve().parent.parent / "runtime" / "server.py"
    if server_script.is_file():
        try:
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "DETACHED_PROCESS", 0)
            subprocess.Popen([sys.executable, str(server_script)], creationflags=creationflags)
            time.sleep(0.6)
        except Exception:
            pass


def handle_pre_tool_use(payload: Dict[str, Any], client: AppaClient) -> Dict[str, Any]:
    tool_call = payload.get("toolCall", {})
    raw_name = tool_call.get("name", "")
    args = tool_call.get("args", {})
    conversation_id = payload.get("conversationId", "default")
    step_idx = str(payload.get("stepIdx", "0"))

    canonical_tool, _ = identify_tool(raw_name)

    try:
        decision = client.tool_call(
            root_id=conversation_id,
            tool=canonical_tool.canonical_id,
            arguments=args,
            call_id=f"step_{step_idx}_{raw_name}",
        )
    except AppaClientError:
        # Attempt auto-launching server if offline and targeting default 8788, then retry once
        _ensure_runtime_running(client)
        try:
            decision = client.tool_call(
                root_id=conversation_id,
                tool=canonical_tool.canonical_id,
                arguments=args,
                call_id=f"step_{step_idx}_{raw_name}",
            )
        except AppaClientError as e:
            # Strict fail-closed: runtime errors halt execution
            return {
                "decision": "deny",
                "reason": f"[appa] Fail-closed block: OpenAPPA runtime unavailable ({e})",
            }
    except Exception as e:
        return {
            "decision": "deny",
            "reason": f"[appa] Fail-closed block: internal error ({e})",
        }

    status = decision.get("decision")
    if status in ("allow_call", "pass_control"):
        return {"decision": "allow"}
    elif status == "deny_call":
        feedback = decision.get("feedback", "[appa] Tool call denied by security policy.")
        return {
            "decision": "deny",
            "reason": feedback,
        }
    else:
        return {
            "decision": "deny",
            "reason": f"[appa] Unknown policy decision: {status}",
        }


def main() -> None:
    try:
        raw_input = sys.stdin.read().strip()
        if not raw_input:
            print(json.dumps({}))
            return
        payload = json.loads(raw_input)
    except Exception as e:
        # Fail closed on malformed input
        print(json.dumps({"decision": "deny", "reason": f"[appa] Malformed hook payload: {e}"}))
        return

    client = AppaClient(runtime_url="http://127.0.0.1:8788")

    # Determine event type
    if "toolCall" in payload:
        result = handle_pre_tool_use(payload, client)
        print(json.dumps(result))
    else:
        # PostToolUse, PreInvocation, or Stop
        print(json.dumps({}))


if __name__ == "__main__":
    main()
