"""
OpenAPPA Audit & Decision Logging Subsystem.

Caches and stores Information-Flow Control (IFC) decisions, rule triggers,
trajectory state shifts, and remedy offers into a local `.appa_audit` directory
located inside the active workspace.

Features:
- Configurable toggle via policy TOML (`[policy.audit]`) or `OPENAPPA_AUDIT` env var
- Dual-format persistence:
  * Structured JSONL (fully compatible with `appa replay`)
  * Human-readable Markdown summary (`session_<id>.md`)
- Safe credential redaction for argument logging
- CLI inspection commands (`appa audit status`, `appa audit list`, `appa audit view`)
"""

from __future__ import annotations
import datetime
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def mask_sensitive_arguments(args: Dict[str, Any]) -> Dict[str, Any]:
    """Masks secret tokens, passwords, and sensitive keys in logged tool arguments."""
    sanitized: Dict[str, Any] = {}
    secret_keys = ("token", "secret", "password", "key", "auth", "credential", "private")

    for k, v in args.items():
        k_lower = k.lower()
        if any(sec in k_lower for sec in secret_keys) and isinstance(v, str):
            if len(v) > 8:
                sanitized[k] = f"{v[:3]}...[REDACTED]"
            else:
                sanitized[k] = "[REDACTED]"
        elif isinstance(v, dict):
            sanitized[k] = mask_sensitive_arguments(v)
        elif isinstance(v, list):
            sanitized[k] = [
                mask_sensitive_arguments(item) if isinstance(item, dict) else item
                for item in v
            ]
        else:
            sanitized[k] = v
    return sanitized


class AuditLogger:
    """
    Manages decision audit trails within the active workspace.
    """

    def __init__(
        self,
        workspace_dir: Optional[str | Path] = None,
        audit_dirname: str = ".appa_audit",
        enabled: bool = True,
        generate_markdown: bool = True,
        mask_secrets: bool = True,
    ):
        self.workspace_dir = Path(workspace_dir).resolve() if workspace_dir else Path.cwd()
        self.audit_dirname = audit_dirname
        # Environment variable override takes precedence if set
        env_toggle = os.environ.get("OPENAPPA_AUDIT")
        if env_toggle is not None:
            self.enabled = env_toggle.lower() in ("1", "true", "yes", "on")
        else:
            self.enabled = enabled
        self.generate_markdown = generate_markdown
        self.mask_secrets = mask_secrets

    @property
    def audit_dir(self) -> Path:
        return self.workspace_dir / self.audit_dirname

    def _sanitize_session_id(self, session_id: str) -> str:
        safe = re.sub(r"[^\w\-.]", "_", session_id.strip())
        return safe if safe and safe != "default" else datetime.datetime.now(datetime.timezone.utc).strftime("session_%Y%m%d")

    def get_session_file(self, session_id: str, ext: str = "jsonl") -> Path:
        clean_id = self._sanitize_session_id(session_id)
        if not clean_id.startswith("session_"):
            filename = f"session_{clean_id}.{ext}"
        else:
            filename = f"{clean_id}.{ext}"
        return self.audit_dir / filename

    def record_decision(
        self,
        session_id: str,
        event: str,
        tool: str,
        arguments: Dict[str, Any],
        decision: str,
        reason: Optional[str] = None,
        call_id: Optional[str] = None,
        step_idx: Optional[str] = None,
        child_id: Optional[str] = None,
        matched_rule: Optional[Dict[str, Any]] = None,
        trajectory_state: Optional[Dict[str, Any]] = None,
        offers: Optional[List[Dict[str, Any]]] = None,
        policy_key: Optional[str] = None,
        outcome: Optional[Dict[str, Any]] = None,
    ) -> Optional[Path]:
        """
        Records a single policy decision event into `.appa_audit/session_<id>.jsonl`
        and appends a formatted block to `.appa_audit/session_<id>.md`.
        """
        if not self.enabled:
            return None

        try:
            self.audit_dir.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
            logged_args = mask_sensitive_arguments(arguments) if self.mask_secrets else dict(arguments)

            entry: Dict[str, Any] = {
                "timestamp": timestamp,
                "session_id": session_id,
                "child_id": child_id,
                "step_idx": step_idx,
                "call_id": call_id,
                "event": event,
                "tool": tool,
                "arguments": logged_args,
                "decision": decision,
                "reason": reason,
                "matched_rule": matched_rule,
                "trajectory_state": trajectory_state,
                "offers": offers or [],
                "policy_key": policy_key,
                "expect_decision": decision,  # for direct appa replay compatibility
            }
            if outcome:
                entry["outcome"] = outcome

            # 1. Append JSONL
            jsonl_path = self.get_session_file(session_id, "jsonl")

            # Deduplicate if another hook (e.g. dual global and workspace hooks)
            # has already logged this exact call within the session
            if call_id and jsonl_path.exists():
                try:
                    file_size = jsonl_path.stat().st_size
                    with open(jsonl_path, "rb") as f:
                        f.seek(max(0, file_size - 4096))
                        lines = f.read().decode("utf-8", errors="replace").splitlines()
                        for prev_line in reversed(lines):
                            if not prev_line.strip():
                                continue
                            try:
                                prev_rec = json.loads(prev_line)
                                if (
                                    prev_rec.get("call_id") == call_id
                                    and prev_rec.get("event") == event
                                    and prev_rec.get("tool") == tool
                                ):
                                    return jsonl_path
                            except Exception:
                                pass
                            break
                except Exception:
                    pass

            with open(jsonl_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")

            # Update latest pointer
            try:
                latest_ref = self.audit_dir / "latest.session"
                latest_ref.write_text(jsonl_path.name, encoding="utf-8")
                old_jsonl_ref = self.audit_dir / "latest.jsonl"
                if old_jsonl_ref.exists():
                    old_jsonl_ref.unlink(missing_ok=True)
            except Exception:
                pass

            # 2. Append Markdown summary if enabled
            if self.generate_markdown:
                self._append_markdown(session_id, entry)

            return jsonl_path
        except Exception:
            # Audit logging is observational: fail-open on logging I/O to avoid blocking main execution
            return None

    def _append_markdown(self, session_id: str, entry: Dict[str, Any]) -> None:
        md_path = self.get_session_file(session_id, "md")
        is_new = not md_path.exists()

        try:
            with open(md_path, "a", encoding="utf-8") as f:
                if is_new:
                    f.write(f"# OpenAPPA Decision Audit Log\n\n")
                    f.write(f"- **Session ID**: `{session_id}`\n")
                    f.write(f"- **Workspace**: `{self.workspace_dir}`\n")
                    f.write(f"- **Policy Fingerprint**: `{entry.get('policy_key', 'unknown')}`\n")
                    f.write(f"- **Created At**: {entry['timestamp']}\n\n")
                    f.write("---\n\n")

                step = entry.get("step_idx")
                step_str = f"Step {step}" if step else entry.get("event", "event")
                decision = entry.get("decision", "unknown")
                tool_name = entry.get("tool") or entry.get("event", "action")

                if decision in ("allow_call", "pass_control", "ack"):
                    badge = "🟢 ALLOWED"
                elif decision == "replace_output":
                    badge = "🟡 REDACTED / WITHHELD"
                else:
                    badge = "🔴 BLOCKED"

                f.write(f"### {step_str}: `{tool_name}` — {badge}\n\n")
                f.write(f"* **Timestamp**: `{entry['timestamp']}`\n")
                f.write(f"* **Event**: `{entry.get('event')}`\n")
                f.write(f"* **Decision**: `{decision}`\n")

                if entry.get("reason"):
                    f.write(f"* **Reason**: {entry['reason']}\n")

                rule = entry.get("matched_rule")
                if rule and isinstance(rule, dict):
                    pat = rule.get("pattern", "default")
                    req_t = rule.get("requires_trust") or "any"
                    f.write(f"* **Matched Policy Rule**: `{pat}` (requires `trust >= {req_t}`)\n")

                traj = entry.get("trajectory_state")
                if traj and isinstance(traj, dict):
                    f.write(f"* **Trajectory State**: `trust: {traj.get('trust')}`, `audience: {traj.get('audience')}`\n")

                offers = entry.get("offers")
                if offers:
                    f.write(f"* **Remedy Offers**: `{offers}`\n")

                args = entry.get("arguments")
                if args:
                    args_json = json.dumps(args, indent=2)
                    f.write(f"* **Arguments**:\n```json\n{args_json}\n```\n")

                f.write("\n---\n\n")
        except Exception:
            pass

    def list_sessions(self) -> List[Dict[str, Any]]:
        """Returns metadata for all recorded audit sessions in the current workspace."""
        if not self.audit_dir.is_dir():
            return []

        sessions: List[Dict[str, Any]] = []
        for file in sorted(self.audit_dir.glob("session_*.jsonl"), reverse=True):
            session_id = file.stem.replace("session_", "")
            event_count = 0
            allowed = 0
            blocked = 0
            redacted = 0
            first_time = None
            last_time = None

            try:
                with open(file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            record = json.loads(line)
                            event_count += 1
                            dec = record.get("decision", "")
                            if dec in ("allow_call", "pass_control", "ack"):
                                allowed += 1
                            elif dec in ("deny_call", "refuse"):
                                blocked += 1
                            elif dec == "replace_output":
                                redacted += 1

                            ts = record.get("timestamp")
                            if ts and not first_time:
                                first_time = ts
                            if ts:
                                last_time = ts
                        except Exception:
                            continue
            except Exception:
                continue

            sessions.append({
                "session_id": session_id,
                "jsonl_file": file,
                "md_file": file.with_suffix(".md"),
                "event_count": event_count,
                "allowed": allowed,
                "blocked": blocked,
                "redacted": redacted,
                "first_time": first_time,
                "last_time": last_time,
            })
        return sessions

    def read_session_events(self, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Reads all JSONL event records for a given session ID (or latest if omitted)."""
        if not self.audit_dir.is_dir():
            return []

        target_file: Optional[Path] = None
        if session_id:
            target_file = self.get_session_file(session_id, "jsonl")
            if not target_file.is_file():
                # Try finding by partial prefix
                for f in self.audit_dir.glob("session_*.jsonl"):
                    if session_id in f.name:
                        target_file = f
                        break
        else:
            latest_ref = self.audit_dir / "latest.session"
            if not latest_ref.is_file():
                latest_ref = self.audit_dir / "latest.jsonl"
            if latest_ref.is_file():
                try:
                    ref_name = latest_ref.read_text(encoding="utf-8").strip()
                    target_file = self.audit_dir / ref_name
                except Exception:
                    pass
            if not target_file or not target_file.is_file():
                all_sessions = sorted(self.audit_dir.glob("session_*.jsonl"), reverse=True)
                if all_sessions:
                    target_file = all_sessions[0]

        if not target_file or not target_file.is_file():
            return []

        events: List[Dict[str, Any]] = []
        with open(target_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except Exception:
                        pass
        return events
