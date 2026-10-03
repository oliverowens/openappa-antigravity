"""
OpenAPPA Decision Engine and Trajectory State.

Evaluates ToolCall, ToolResult, Prompt, TurnEnd, ChildStart, and ChildEnd
against the loaded policy rules, maintaining strict information-flow tracking.
"""

from __future__ import annotations
import hashlib
import json
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .algebra import Label, Trust, ToolRule
from .sanitizers import redact_secrets, attest_schema


@dataclass
class RemedyOffer:
    offer_id: str
    tool_name: str
    arguments: Dict[str, Any]
    remedy_type: str  # "narrowing", "sanitizer", "hitl", "schema"
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TrajectoryState:
    root_id: str
    child_id: Optional[str] = None
    label: Label = field(default_factory=Label)
    pending_calls: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    active_offers: Dict[str, RemedyOffer] = field(default_factory=dict)
    authorized_calls: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    child_schemas: Dict[str, Dict[str, Any]] = field(default_factory=dict)


class AppaEngine:
    CONTROL_TOOLS = {
        "mcp__appa__execute_remedy_plan",
        "appa/execute_remedy_plan",
        "mcp/appa/execute_remedy_plan",
        "execute_remedy_plan",
        "host/antigravity/execute_remedy_plan",
    }

    def __init__(self, rules: List[ToolRule], confined_tools: Optional[Set[str]] = None):
        self.rules = rules
        self.confined_tools = confined_tools or set()
        self.trajectories: Dict[str, TrajectoryState] = {}
        self.policy_key = hashlib.sha256(str([(r.canonical_name, r.raw_pattern) for r in rules]).encode()).hexdigest()[:16]

    def _get_trajectory(self, root_id: str, child_id: Optional[str] = None) -> TrajectoryState:
        key = f"{root_id}:{child_id}" if child_id else root_id
        if key not in self.trajectories:
            self.trajectories[key] = TrajectoryState(root_id=root_id, child_id=child_id)
        return self.trajectories[key]

    def handle_session_start(self, root_id: str) -> Dict[str, Any]:
        self._get_trajectory(root_id)
        return {
            "protocol": 1,
            "decision": "context",
            "text": "OpenAPPA is active. Actions are checked against information-flow security policies.",
        }

    def handle_prompt(self, root_id: str, child_id: Optional[str], text: str) -> Dict[str, Any]:
        # User turn marks boundary
        traj = self._get_trajectory(root_id, child_id)
        return {"protocol": 1, "decision": "ack"}

    def handle_turn_end(self, root_id: str, child_id: Optional[str]) -> Dict[str, Any]:
        traj = self._get_trajectory(root_id, child_id)
        traj.pending_calls.clear()
        return {"protocol": 1, "decision": "ack"}

    def handle_tool_call(
        self,
        root_id: str,
        child_id: Optional[str],
        tool: str,
        arguments: Dict[str, Any],
        call_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        traj = self._get_trajectory(root_id, child_id)
        cid = call_id or str(uuid.uuid4())

        # Check if this is the control tool for remedies
        if tool in self.CONTROL_TOOLS:
            offer_id = arguments.get("offer_id", "")
            if offer_id in traj.active_offers:
                offer = traj.active_offers.pop(offer_id)
                # Authorize the call for retry
                call_key = f"{offer.tool_name}:{json.dumps(offer.arguments, sort_keys=True)}"
                traj.authorized_calls[call_key] = offer.arguments
                return {
                    "protocol": 1,
                    "decision": "pass_control",
                    "reply": f"Authorized. Propose the '{offer.tool_name}' tool again to execute.",
                }
            return {
                "protocol": 1,
                "decision": "deny_call",
                "feedback": f"[appa] Invalid or expired remedy offer '{offer_id}'.",
                "offers": [],
            }

        # Check if previously authorized via remedy
        call_key = f"{tool}:{json.dumps(arguments, sort_keys=True)}"
        if call_key in traj.authorized_calls:
            traj.authorized_calls.pop(call_key)
            traj.pending_calls[cid] = {"tool": tool, "arguments": arguments, "rule": None, "authorized": True}
            return {"protocol": 1, "decision": "allow_call", "spawn": None}

        # Find matching policy rule
        matched_rule: Optional[ToolRule] = None
        for rule in self.rules:
            if rule.matches(tool, arguments):
                matched_rule = rule
                break

        if not matched_rule:
            return {
                "protocol": 1,
                "decision": "deny_call",
                "feedback": f"[appa] Blocked: tool '{tool}' is not declared in policy (fail-closed).",
                "offers": [],
            }

        # 1. Check trust requirement
        if matched_rule.requires_trust is not None:
            if traj.label.trust < matched_rule.requires_trust:
                return {
                    "protocol": 1,
                    "decision": "deny_call",
                    "feedback": f"[appa] Blocked: trust is '{traj.label.trust.to_str()}', below required floor '{matched_rule.requires_trust.to_str()}'.",
                    "offers": [],
                }

        # 2. Check audience requirement
        if matched_rule.requires_audience:
            for required_aud in matched_rule.requires_audience:
                if not traj.label.can_flow_to(required_aud):
                    # Destination is wider than source audience: exfiltration risk!
                    offer_id = uuid.uuid4().hex[:16]
                    traj.active_offers[offer_id] = RemedyOffer(
                        offer_id=offer_id,
                        tool_name=tool,
                        arguments=arguments,
                        remedy_type="narrowing",
                    )
                    return {
                        "protocol": 1,
                        "decision": "deny_call",
                        "feedback": (
                            f"[appa] Blocked: data with private audience '{traj.label.audience}' "
                            f"cannot flow to public destination '{tool}'. "
                            f'Take remedy with offer_id: "{offer_id}".'
                        ),
                        "offers": [{"offer_id": offer_id, "remedy_type": "narrowing"}],
                    }

        # Call is allowed
        traj.pending_calls[cid] = {"tool": tool, "arguments": arguments, "rule": matched_rule}
        return {"protocol": 1, "decision": "allow_call", "spawn": None}

    def handle_tool_result(
        self,
        root_id: str,
        child_id: Optional[str],
        tool: str,
        arguments: Dict[str, Any],
        outcome: Dict[str, Any],
        call_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        traj = self._get_trajectory(root_id, child_id)
        cid = call_id or ""
        pending = traj.pending_calls.pop(cid, None)

        status = outcome.get("status")
        if status == "failure":
            return {"protocol": 1, "decision": "ack"}
        if status == "indeterminate":
            return {
                "protocol": 1,
                "decision": "replace_output",
                "output": "[appa] Tool execution indeterminate; output withheld for safety.",
            }

        body = outcome.get("body", "")

        # Find rule that governed this tool
        matched_rule = pending.get("rule") if pending else None
        if not matched_rule:
            for rule in self.rules:
                if rule.matches(tool, arguments):
                    matched_rule = rule
                    break

        # Check for secrets sanitization if body is text
        if isinstance(body, str):
            sanitized_body, was_redacted = redact_secrets(body)
            if was_redacted:
                # Update label without 'self' narrowing because secrets were redacted!
                if matched_rule:
                    traj.label = traj.label.combine(delta_trust=matched_rule.delta_trust, delta_audience=None)
                return {
                    "protocol": 1,
                    "decision": "replace_output",
                    "output": sanitized_body,
                }

        # Apply normal delta to trajectory label
        if matched_rule:
            traj.label = traj.label.combine(
                delta_trust=matched_rule.delta_trust,
                delta_audience=matched_rule.delta_audience,
            )

        return {"protocol": 1, "decision": "ack"}

    def handle_child_start(self, root_id: str, child_id: str, schema: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        parent_traj = self._get_trajectory(root_id)
        child_traj = self._get_trajectory(root_id, child_id)
        # Child starts at parent's trust floor
        child_traj.label = Label(trust=parent_traj.label.trust, audience="public")
        if schema:
            parent_traj.child_schemas[child_id] = schema
        return {"protocol": 1, "decision": "ack"}

    def handle_child_end(self, root_id: str, child_id: str, value: Optional[str]) -> Dict[str, Any]:
        parent_traj = self._get_trajectory(root_id)
        child_traj = self._get_trajectory(root_id, child_id)

        # Check if parent registered an attested return schema
        schema = parent_traj.child_schemas.get(child_id)
        if schema and value is not None:
            valid, canonical, err = attest_schema(value, schema)
            if not valid:
                return {
                    "protocol": 1,
                    "decision": "block",
                    "reason": f"[appa] Subagent return failed schema validation: {err}",
                }
            # Return crosses attested into parent: leaves parent trusted
            return {
                "protocol": 1,
                "decision": "deliver_value",
                "value": canonical,
            }

        # Otherwise crossing as spoken
        return {"protocol": 1, "decision": "ack"}
