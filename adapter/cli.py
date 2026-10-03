"""
OpenAPPA Command-Line Interface (CLI).

Implements canonical OpenAPPA CLI commands:
- appa describe --check : Validates policy TOML configuration and displays diagnostics.
- appa replay           : Verifies recorded/scripted tool calls against policy decisions.
- appa yell             : Emits diagnostic report adhering to openappa.yell.v1 schema.
"""

from __future__ import annotations
import argparse
import datetime
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure project root is importable
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from runtime.algebra import ToolRule, Trust
from runtime.engine import AppaEngine
from runtime.policy_loader import load_policy_and_config
from runtime.sanitizers import canonical_json


def cmd_describe(args: argparse.Namespace) -> int:
    config_path = Path(args.config).resolve() if args.config else ROOT_DIR / "policy" / "appa.toml"
    if not config_path.is_file():
        print(f"[OpenAPPA ERROR] Policy configuration not found: {config_path}", file=sys.stderr)
        return 1

    try:
        rules, config = load_policy_and_config(config_path)
    except Exception as e:
        print(f"[OpenAPPA ERROR] Failed to load policy: {e}", file=sys.stderr)
        return 1

    engine = AppaEngine(rules=rules, config=config)

    print("==================================================")
    print(" OpenAPPA Policy Verification: describe --check")
    print("==================================================")
    print(f"Policy File      : {config_path}")
    print(f"Policy Key       : {engine.policy_key}")
    print(f"Rules Declared   : {len(rules)}")
    print(f"HITL Mode        : {config.hitl_mode}")
    print(f"Classification   : {config.classification_mode}")
    print(f"Redaction Engine : {config.redaction_engine}")
    print(f"Workspace Only   : {config.workspace_only}")
    print(f"Trusted Domains  : {', '.join(config.trusted_domains) if config.trusted_domains else 'none'}")
    print(f"Subagent Exec    : {'allowed' if config.subagents_allow_execution else 'blocked (default)'}")
    print(f"Subagent Writes  : {'allowed' if config.subagents_allow_writes else 'blocked (default)'}")
    print("--------------------------------------------------")
    print("Rule Summary:")
    for idx, rule in enumerate(rules, 1):
        req_trust = rule.requires_trust.to_str() if rule.requires_trust else "any"
        delta = f"trust={rule.delta_trust or 'same'}, aud={rule.delta_audience or 'same'}"
        print(f"  {idx:2d}. {rule.canonical_name:<45} [requires: trust>={req_trust}] [delta: {delta}]")
    print("--------------------------------------------------")
    print("Status: VALID (Passed policy check)")
    print("==================================================")
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    config_path = Path(args.config).resolve() if args.config else ROOT_DIR / "policy" / "appa.toml"
    trace_path = Path(args.trace).resolve()

    if not config_path.is_file():
        print(f"[OpenAPPA ERROR] Policy configuration not found: {config_path}", file=sys.stderr)
        return 1
    if not trace_path.exists():
        print(f"[OpenAPPA ERROR] Replay trace not found: {trace_path}", file=sys.stderr)
        return 1

    rules, config = load_policy_and_config(config_path)
    engine = AppaEngine(rules=rules, config=config)

    # Collect trace files
    trace_files: List[Path] = []
    if trace_path.is_file():
        trace_files = [trace_path]
    else:
        trace_files = sorted(list(trace_path.glob("*.json")) + list(trace_path.glob("*.jsonl")))

    if not trace_files:
        print(f"[OpenAPPA ERROR] No JSON/JSONL trace files found in {trace_path}", file=sys.stderr)
        return 1

    total_events = 0
    passed_events = 0
    failed_events = 0

    print(f"[OpenAPPA Replay] Replaying against policy key: {engine.policy_key}")

    for tf in trace_files:
        print(f"\n--- Replaying: {tf.name} ---")
        try:
            content = tf.read_text(encoding="utf-8")
            if tf.suffix == ".jsonl":
                events = [json.loads(line) for line in content.splitlines() if line.strip()]
            else:
                data = json.loads(content)
                events = data if isinstance(data, list) else data.get("events", [])
        except Exception as e:
            print(f"  [ERROR] Failed to parse trace file {tf.name}: {e}")
            failed_events += 1
            continue

        for ev_idx, ev in enumerate(events, 1):
            total_events += 1
            event_type = ev.get("event")
            root_id = ev.get("root_id", "replay_session")
            child_id = ev.get("child_id")
            expected_decision = ev.get("expect_decision")

            if event_type == "session_start":
                res = engine.handle_session_start(root_id)
            elif event_type == "prompt":
                res = engine.handle_prompt(root_id, child_id, ev.get("text", ""))
            elif event_type == "turn_end":
                res = engine.handle_turn_end(root_id, child_id)
            elif event_type == "tool_call":
                res = engine.handle_tool_call(
                    root_id=root_id,
                    child_id=child_id,
                    tool=ev.get("tool", ""),
                    arguments=ev.get("arguments", {}),
                    call_id=ev.get("call_id"),
                )
            elif event_type == "tool_result":
                res = engine.handle_tool_result(
                    root_id=root_id,
                    child_id=child_id,
                    tool=ev.get("tool", ""),
                    arguments=ev.get("arguments", {}),
                    outcome=ev.get("outcome", {}),
                    call_id=ev.get("call_id"),
                )
            elif event_type == "child_start":
                res = engine.handle_child_start(root_id, child_id or "", ev.get("return_schema"))
            elif event_type == "child_end":
                res = engine.handle_child_end(root_id, child_id or "", ev.get("value"))
            else:
                print(f"  [FAIL] Step {ev_idx}: Unknown event type '{event_type}'")
                failed_events += 1
                continue

            actual_decision = res.get("decision")
            if expected_decision:
                if actual_decision == expected_decision:
                    passed_events += 1
                    print(f"  [OK]   Step {ev_idx:2d}: {event_type} -> {actual_decision}")
                else:
                    failed_events += 1
                    print(
                        f"  [FAIL] Step {ev_idx:2d}: {event_type} expected '{expected_decision}', got '{actual_decision}' (detail: {res})"
                    )
            else:
                passed_events += 1
                print(f"  [INFO] Step {ev_idx:2d}: {event_type} -> {actual_decision}")

    print("\n==================================================")
    print(f"Replay Summary: Total={total_events}, Passed={passed_events}, Failed={failed_events}")
    print("==================================================")
    return 0 if failed_events == 0 else 1


def cmd_yell(args: argparse.Namespace) -> int:
    config_path = Path(args.config).resolve() if args.config else ROOT_DIR / "policy" / "appa.toml"
    try:
        rules, config = load_policy_and_config(config_path)
    except Exception as e:
        print(f"[OpenAPPA ERROR] Failed to load policy: {e}", file=sys.stderr)
        return 1

    engine = AppaEngine(rules=rules, config=config)

    report = {
        "$schema": "openappa.yell.v1",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "adapter": "antigravity",
        "policy_key": engine.policy_key,
        "policy_version": 2,
        "diagnostics": {
            "rules_count": len(rules),
            "sanitizers": ["redact-secrets", "attest-schema"],
            "boundaries": {
                "workspace_only": config.workspace_only,
                "allowed_external_paths": config.allowed_external_paths,
            },
            "network": {
                "trusted_domains": config.trusted_domains,
            },
            "subagents": {
                "allow_execution": config.subagents_allow_execution,
                "allow_writes": config.subagents_allow_writes,
            },
        },
        "session": {
            "active_trajectories": len(engine.trajectories),
        },
    }

    report_json = json.dumps(report, indent=2)
    if args.output:
        out_path = Path(args.output).resolve()
        out_path.write_text(report_json, encoding="utf-8")
        print(f"[OpenAPPA] Diagnostic report exported to: {out_path}")
    else:
        print(report_json)
    return 0


def cmd_hook(args: argparse.Namespace) -> int:
    """Invokes the lifecycle hook handler over stdin/stdout."""
    try:
        from adapter.hooks_handler import main as hooks_main
    except ImportError:
        from .hooks_handler import main as hooks_main
    hooks_main()
    return 0


def cmd_install(args: argparse.Namespace) -> int:
    """Installs portable hook configuration into global or workspace hooks.json."""
    import shutil

    if args.workspace:
        hooks_dir = Path.cwd() / ".agents"
        hooks_file = hooks_dir / "hooks.json"
        scope = "workspace"
        default_cmd = "python ../adapter/hooks_handler.py"
    else:
        hooks_dir = Path.home() / ".gemini" / "config"
        hooks_file = hooks_dir / "hooks.json"
        scope = "global"
        # Determine portable command
        if shutil.which("appa"):
            default_cmd = "appa hook"
        elif shutil.which("openappa-hook"):
            default_cmd = "openappa-hook"
        else:
            default_cmd = "python -m adapter.hooks_handler"

    command_str = args.custom_command if args.custom_command else default_cmd

    hooks_dir.mkdir(parents=True, exist_ok=True)
    data: Dict[str, Any] = {}
    if hooks_file.is_file():
        try:
            data = json.loads(hooks_file.read_text(encoding="utf-8"))
        except Exception:
            data = {}

    hook_entry_tool = {
        "matcher": "*",
        "hooks": [
            {
                "type": "command",
                "command": command_str,
                "timeout": 15,
            }
        ],
    }

    hook_entry_invoc = [
        {
            "type": "command",
            "command": command_str,
            "timeout": 15,
        }
    ]

    if "openappa-gate" not in data or not isinstance(data["openappa-gate"], dict):
        data["openappa-gate"] = {}

    data["openappa-gate"]["PreInvocation"] = hook_entry_invoc
    data["openappa-gate"]["PreToolUse"] = [hook_entry_tool]

    hooks_file.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print("==================================================")
    print(" OpenAPPA Hook Installation")
    print("==================================================")
    print(f"Scope       : {scope}")
    print(f"Config File : {hooks_file}")
    print(f"Command     : {command_str}")
    print("Hooks Added : PreInvocation (auto-warmup), PreToolUse (policy gate)")
    print("Status      : INSTALLED")
    print("==================================================")
    return 0


def cmd_uninstall(args: argparse.Namespace) -> int:
    """Removes openappa-gate from global or workspace hooks.json."""
    if args.workspace:
        hooks_file = Path.cwd() / ".agents" / "hooks.json"
        scope = "workspace"
    else:
        hooks_file = Path.home() / ".gemini" / "config" / "hooks.json"
        scope = "global"

    if not hooks_file.is_file():
        print(f"[OpenAPPA] No hook configuration found at: {hooks_file}")
        return 0

    try:
        data = json.loads(hooks_file.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[OpenAPPA ERROR] Failed to parse {hooks_file}: {e}", file=sys.stderr)
        return 1

    if "openappa-gate" in data:
        del data["openappa-gate"]
        hooks_file.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        print(f"[OpenAPPA] Successfully uninstalled {scope} hook from: {hooks_file}")
    else:
        print(f"[OpenAPPA] No 'openappa-gate' found in: {hooks_file}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    import urllib.request
    port = getattr(args, "port", None) or 8788
    host = getattr(args, "host", None) or "127.0.0.1"
    url = f"http://{host}:{port}"

    print("==================================================")
    print(" OpenAPPA Runtime Status")
    print("==================================================")
    print(f"Endpoint   : {url}")
    try:
        req = urllib.request.Request(f"{url}/status")
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            print("Status     : ONLINE")
            print(f"PID        : {data.get('pid', 'unknown')}")
            print(f"Policy Key : {data.get('policy_key', 'unknown')}")
            print(f"Rules      : {data.get('rules', 'unknown')}")
            print(f"Sessions   : {data.get('trajectories', 0)}")
            print("==================================================")
            return 0
    except Exception:
        try:
            with urllib.request.urlopen(f"{url}/health", timeout=1.0) as resp:
                if resp.status == 200:
                    print("Status     : ONLINE (healthy)")
                    print("==================================================")
                    return 0
        except Exception:
            pass
        print("Status     : OFFLINE")
        print("==================================================")
        return 1


def cmd_start(args: argparse.Namespace) -> int:
    from adapter.hooks_handler import _ensure_runtime_running, is_server_healthy
    port = getattr(args, "port", None) or 8788
    host = getattr(args, "host", None) or "127.0.0.1"
    url = f"http://{host}:{port}"

    if is_server_healthy(f"{url}/health", timeout=0.5):
        print(f"[OpenAPPA] Runtime server is already running on {url}")
        return 0

    print(f"[OpenAPPA] Starting OpenAPPA runtime server on {url}...")
    success = _ensure_runtime_running(max_wait=5.0)
    if success:
        print(f"[OpenAPPA] Server started successfully and listening on {url}")
        return 0
    else:
        print(f"[OpenAPPA ERROR] Failed to start runtime server within timeout.", file=sys.stderr)
        return 1


def cmd_stop(args: argparse.Namespace) -> int:
    import urllib.request
    import time
    port = getattr(args, "port", None) or 8788
    host = getattr(args, "host", None) or "127.0.0.1"
    url = f"http://{host}:{port}"

    try:
        req = urllib.request.Request(f"{url}/shutdown", method="POST", data=b"{}")
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            pass
        print(f"[OpenAPPA] Sent shutdown signal to {url}")
        time.sleep(0.5)
        print(f"[OpenAPPA] Server stopped.")
        return 0
    except Exception:
        print(f"[OpenAPPA] No active server detected on {url}")
        return 0


def cmd_restart(args: argparse.Namespace) -> int:
    import urllib.request
    port = getattr(args, "port", None) or 8788
    host = getattr(args, "host", None) or "127.0.0.1"
    url = f"http://{host}:{port}"

    if getattr(args, "reload_only", False):
        try:
            req = urllib.request.Request(f"{url}/reload", method="POST", data=b"{}")
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                print(f"[OpenAPPA] Policy reloaded successfully! New policy key: {data.get('policy_key')}")
                return 0
        except Exception as e:
            print(f"[OpenAPPA ERROR] Failed to reload policy: {e}", file=sys.stderr)
            return 1

    cmd_stop(args)
    import time
    time.sleep(0.6)
    return cmd_start(args)


def main() -> None:
    parser = argparse.ArgumentParser(prog="appa", description="OpenAPPA CLI for Antigravity")
    subparsers = parser.add_subparsers(dest="command")

    # describe
    p_describe = subparsers.add_parser("describe", help="Verify policy configuration")
    p_describe.add_argument("--check", action="store_true", help="Validate policy and exit with status")
    p_describe.add_argument("--config", type=str, help="Path to policy TOML file")

    # replay
    p_replay = subparsers.add_parser("replay", help="Replay scripted events against policy")
    p_replay.add_argument("trace", type=str, help="Path to trace JSON/JSONL file or directory")
    p_replay.add_argument("--config", type=str, help="Path to policy TOML file")

    # yell
    p_yell = subparsers.add_parser("yell", help="Generate openappa.yell.v1 diagnostic report")
    p_yell.add_argument("--config", type=str, help="Path to policy TOML file")
    p_yell.add_argument("--output", "-o", type=str, help="Optional output file path")

    # hook
    subparsers.add_parser("hook", help="Run the lifecycle hook handler (stdin/stdout)")

    # install
    p_install = subparsers.add_parser("install", help="Install portable Antigravity lifecycle hooks")
    p_install.add_argument("--workspace", action="store_true", help="Install to workspace (.agents/hooks.json) instead of global (~/.gemini/config/hooks.json)")
    p_install.add_argument("--cmd", "--command", dest="custom_command", type=str, help="Custom hook command string to register")

    # uninstall
    p_uninstall = subparsers.add_parser("uninstall", help="Remove Antigravity lifecycle hooks")
    p_uninstall.add_argument("--workspace", action="store_true", help="Uninstall from workspace (.agents/hooks.json) instead of global")

    # status
    p_status = subparsers.add_parser("status", help="Check OpenAPPA runtime server status")
    p_status.add_argument("--host", type=str, default="127.0.0.1", help="Server host (default: 127.0.0.1)")
    p_status.add_argument("--port", type=int, default=8788, help="Server port (default: 8788)")

    # start
    p_start = subparsers.add_parser("start", help="Start OpenAPPA runtime server daemon")
    p_start.add_argument("--host", type=str, default="127.0.0.1", help="Server host (default: 127.0.0.1)")
    p_start.add_argument("--port", type=int, default=8788, help="Server port (default: 8788)")

    # stop
    p_stop = subparsers.add_parser("stop", help="Stop OpenAPPA runtime server daemon")
    p_stop.add_argument("--host", type=str, default="127.0.0.1", help="Server host (default: 127.0.0.1)")
    p_stop.add_argument("--port", type=int, default=8788, help="Server port (default: 8788)")

    # restart
    p_restart = subparsers.add_parser("restart", help="Restart runtime daemon or reload active policy")
    p_restart.add_argument("--reload-only", action="store_true", help="Reload policy TOML without process restart")
    p_restart.add_argument("--host", type=str, default="127.0.0.1", help="Server host (default: 127.0.0.1)")
    p_restart.add_argument("--port", type=int, default=8788, help="Server port (default: 8788)")

    args = parser.parse_args()

    if args.command == "describe":
        sys.exit(cmd_describe(args))
    elif args.command == "replay":
        sys.exit(cmd_replay(args))
    elif args.command == "yell":
        sys.exit(cmd_yell(args))
    elif args.command == "hook":
        sys.exit(cmd_hook(args))
    elif args.command == "install":
        sys.exit(cmd_install(args))
    elif args.command == "uninstall":
        sys.exit(cmd_uninstall(args))
    elif args.command == "status":
        sys.exit(cmd_status(args))
    elif args.command == "start":
        sys.exit(cmd_start(args))
    elif args.command == "stop":
        sys.exit(cmd_stop(args))
    elif args.command == "restart":
        sys.exit(cmd_restart(args))
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
