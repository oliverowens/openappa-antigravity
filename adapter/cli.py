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

    args = parser.parse_args()

    if args.command == "describe":
        sys.exit(cmd_describe(args))
    elif args.command == "replay":
        sys.exit(cmd_replay(args))
    elif args.command == "yell":
        sys.exit(cmd_yell(args))
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
