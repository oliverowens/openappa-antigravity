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
from typing import Any, Dict, Optional

# Support relative and standalone execution
try:
    from .antigravity_adapter import identify_tool
    from .client import AppaClient, AppaClientError
except ImportError:
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from adapter.antigravity_adapter import identify_tool
    from adapter.client import AppaClient, AppaClientError


def is_server_healthy(url: str = "http://127.0.0.1:8788/health", timeout: float = 0.4) -> bool:
    import urllib.request
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.status == 200
    except Exception:
        return False


def _ensure_runtime_running(client: Optional[AppaClient] = None, max_wait: float = 3.5) -> bool:
    """Ensures runtime server is active, auto-spawning detached if offline with a lock to prevent duplicate instances."""
    runtime_url = client.runtime_url if client else "http://127.0.0.1:8788"
    if "8788" not in runtime_url:
        return is_server_healthy(f"{runtime_url}/health", timeout=1.0)

    health_url = f"{runtime_url}/health"
    if is_server_healthy(health_url, timeout=0.25):
        return True

    import os
    import subprocess
    import tempfile
    import time
    from pathlib import Path

    lock_file = Path(tempfile.gettempdir()) / "openappa_supervisor.lock"
    acquired = False
    lock_fd = None
    try:
        lock_fd = os.open(str(lock_file), os.O_CREAT | os.O_EXCL | os.O_RDWR)
        acquired = True
    except OSError:
        # Another process holds the lock; wait up to max_wait for it to become healthy
        start_wait = time.time()
        while time.time() - start_wait < max_wait:
            time.sleep(0.1)
            if is_server_healthy(health_url, timeout=0.2):
                return True
        # If still offline after waiting, assume stale lock and acquire
        try:
            lock_file.unlink(missing_ok=True)
            lock_fd = os.open(str(lock_file), os.O_CREAT | os.O_EXCL | os.O_RDWR)
            acquired = True
        except Exception:
            pass

    try:
        if is_server_healthy(health_url, timeout=0.2):
            return True

        server_script = Path(__file__).resolve().parent.parent / "runtime" / "server.py"
        cwd_dir = str(server_script.parent.parent) if server_script.is_file() else None

        creationflags = 0
        if sys.platform == "win32":
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "DETACHED_PROCESS", 0)

        cmd = [sys.executable, str(server_script)] if server_script.is_file() else [sys.executable, "-m", "runtime.server"]

        try:
            subprocess.Popen(
                cmd,
                cwd=cwd_dir,
                creationflags=creationflags,
                start_new_session=(sys.platform != "win32"),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            pass

        # Poll health until ready
        poll_start = time.time()
        while time.time() - poll_start < max_wait:
            time.sleep(0.1)
            if is_server_healthy(health_url, timeout=0.2):
                return True
        return False
    finally:
        if acquired and lock_fd is not None:
            try:
                os.close(lock_fd)
                lock_file.unlink(missing_ok=True)
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
        # Attempt auto-launching server with active polling if offline, then retry once
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

    # Record decision into .appa_audit directory in the active workspace
    try:
        from runtime.audit import AuditLogger
        from runtime.policy_loader import load_policy_and_config
        from pathlib import Path

        workspace_paths = payload.get("workspacePaths", [])
        workspace_root = workspace_paths[0] if workspace_paths else None

        policy_file = Path(__file__).resolve().parent.parent / "policy" / "appa.toml"
        audit_enabled = True
        if policy_file.is_file():
            try:
                _, config = load_policy_and_config(policy_file)
                audit_enabled = getattr(config, "audit_enabled", True)
            except Exception:
                pass

        logger = AuditLogger(workspace_dir=workspace_root, enabled=audit_enabled)
        logger.record_decision(
            session_id=conversation_id,
            event="tool_call",
            tool=canonical_tool.canonical_id,
            arguments=args,
            decision=status,
            reason=decision.get("feedback") or ("Allowed by security policy." if status in ("allow_call", "pass_control") else None),
            step_idx=step_idx,
            call_id=f"step_{step_idx}_{raw_name}",
            matched_rule=decision.get("matched_rule"),
            trajectory_state=decision.get("trajectory"),
            offers=decision.get("offers"),
            policy_key=decision.get("policy_key"),
        )
    except Exception:
        pass

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
    elif "invocationNum" in payload:
        # PreInvocation hook: Proactive auto-warmup before model starts reasoning
        _ensure_runtime_running(client)
        print(json.dumps({}))
    else:
        # PostToolUse, PostInvocation, or Stop
        print(json.dumps({}))


if __name__ == "__main__":
    main()
