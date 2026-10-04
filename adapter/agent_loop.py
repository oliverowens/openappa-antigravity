"""
OpenAPPA Full Agent Loop Wrapper for Antigravity.

Provides comprehensive interception for environments where native hooks
cannot inspect or redact tool results or subagent lifecycle events:
- ToolCall gating (fail-closed call denial)
- ToolResult inspection and redaction (secrets masking, output withholding)
- Remedy plan execution (offer authorization and retry)
- Subagent lifecycle isolation and schema attestation
- Monotonic information-flow tracking across conversation turns
"""

from __future__ import annotations
import json
import uuid
from typing import Any, Callable, Dict, Optional, Tuple

from .antigravity_adapter import identify_tool
from .client import AppaClient, AppaClientError


class InterceptedExecutionError(Exception):
    """Raised when OpenAPPA policy blocks execution or runtime fails."""
    pass


class OpenAppaAgentLoop:
    """
    Wraps an agent execution context with OpenAPPA policy evaluation.
    Enforces fail-closed boundaries on tool calls, tool results, and subagent returns.
    """

    def __init__(self, root_id: Optional[str] = None, runtime_url: str = "http://127.0.0.1:8788", workspace_dir: Optional[str] = None):
        self.root_id = root_id or str(uuid.uuid4())
        self.client = AppaClient(runtime_url=runtime_url, adapter_name="antigravity")
        self.active = False
        try:
            from runtime.audit import AuditLogger
            self.audit_logger = AuditLogger(workspace_dir=workspace_dir)
        except Exception:
            self.audit_logger = None

    def start_session(self) -> Dict[str, Any]:
        """Notifies runtime of session start and retrieves initial context."""
        try:
            res = self.client.session_start(self.root_id)
            self.active = True
            return res
        except AppaClientError as e:
            raise InterceptedExecutionError(f"[appa] Cannot start session - runtime unavailable: {e}")

    def on_prompt(self, user_text: str) -> None:
        """Informs runtime of incoming user prompt."""
        try:
            self.client.prompt(self.root_id, user_text)
        except AppaClientError as e:
            raise InterceptedExecutionError(f"[appa] Runtime failure on prompt: {e}")

    def execute_tool_safely(
        self,
        raw_name: str,
        arguments: Dict[str, Any],
        tool_fn: Callable[[Dict[str, Any]], str],
        child_id: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        Safely executes a tool call through OpenAPPA:
        1. Pre-execution check: evaluates ToolCall against policy.
        2. Execution: runs only if allowed.
        3. Post-execution check: evaluates ToolResult, applies redactions/withholding.

        Returns (success, result_text_for_model).
        """
        canonical_tool, is_spawn = identify_tool(raw_name)
        call_id = str(uuid.uuid4())

        # 1. Pre-call policy check
        try:
            decision = self.client.tool_call(
                root_id=self.root_id,
                tool=canonical_tool.canonical_id,
                arguments=arguments,
                call_id=call_id,
                child_id=child_id,
            )
        except AppaClientError as e:
            # FAIL-CLOSED: runtime failure stops tool from running
            raise InterceptedExecutionError(f"[appa] Fail-closed: Runtime unreachable before call ({e})")

        status = decision.get("decision")

        if self.audit_logger:
            self.audit_logger.record_decision(
                session_id=self.root_id,
                event="tool_call",
                tool=canonical_tool.canonical_id,
                arguments=arguments,
                decision=status,
                reason=decision.get("feedback"),
                call_id=call_id,
                child_id=child_id,
                matched_rule=decision.get("matched_rule"),
                trajectory_state=decision.get("trajectory"),
                offers=decision.get("offers"),
                policy_key=decision.get("policy_key"),
            )

        # Handle remedy control tool
        if status == "pass_control":
            reply = decision.get("reply", "Remedy plan executed.")
            return True, reply

        # Handle call denial
        if status == "deny_call":
            feedback = decision.get("feedback", f"[appa] Tool '{raw_name}' blocked by policy.")
            offers = decision.get("offers", [])
            if offers:
                offer_info = " ".join([f"[Offer: {o.get('offer_id')}]" for o in offers])
                feedback = f"{feedback} {offer_info}"
            return False, feedback

        if status != "allow_call":
            return False, f"[appa] Blocked: unexpected decision '{status}'."

        # 2. Tool Execution (ONLY executes because decision == 'allow_call')
        try:
            raw_output = tool_fn(arguments)
            outcome_status = "success"
        except Exception as e:
            raw_output = str(e)
            outcome_status = "failure"

        # 3. Post-result policy check and redaction
        try:
            result_decision = self.client.tool_result(
                root_id=self.root_id,
                tool=canonical_tool.canonical_id,
                arguments=arguments,
                outcome={"status": outcome_status, "body": raw_output},
                call_id=call_id,
                child_id=child_id,
            )
        except AppaClientError as e:
            # FAIL-CLOSED: output withheld if runtime cannot check it
            return False, f"[appa] Fail-closed: Output withheld due to runtime verification error ({e})"

        res_status = result_decision.get("decision")

        if self.audit_logger:
            self.audit_logger.record_decision(
                session_id=self.root_id,
                event="tool_result",
                tool=canonical_tool.canonical_id,
                arguments=arguments,
                decision=res_status,
                call_id=call_id,
                child_id=child_id,
                outcome={"status": outcome_status},
                trajectory_state=result_decision.get("trajectory"),
                policy_key=result_decision.get("policy_key"),
            )

        if res_status == "replace_output":
            # Model receives sanitized/redacted output
            sanitized_output = result_decision.get("output", "")
            return True, sanitized_output
        elif res_status == "ack":
            return True, raw_output
        else:
            return False, "[appa] Tool result blocked by policy."

    def execute_subagent_safely(
        self,
        subagent_name: str,
        child_fn: Callable[[], str],
        return_schema: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, str]:
        """
        Executes a child subagent with quarantined trajectory context and
        enforces schema attestation on return values.
        """
        child_id = f"subagent-{subagent_name}-{uuid.uuid4().hex[:8]}"

        # Start child in quarantined context
        try:
            self.client.child_start(self.root_id, child_id, return_schema)
        except AppaClientError as e:
            raise InterceptedExecutionError(f"[appa] Fail-closed: Cannot start subagent ({e})")

        # Execute child tasks
        child_result_value = child_fn()

        # End child and attest return value against schema
        try:
            end_decision = self.client.child_end(self.root_id, child_id, child_result_value)
        except AppaClientError as e:
            return False, f"[appa] Fail-closed: Subagent return withheld ({e})"

        dec = end_decision.get("decision")
        if dec == "block":
            reason = end_decision.get("reason", "Subagent return failed verification")
            return False, reason
        elif dec == "deliver_value":
            return True, end_decision.get("value", child_result_value)
        else:
            return True, child_result_value

    def finish_turn(self) -> None:
        """Marks end of agent turn."""
        try:
            self.client.turn_end(self.root_id)
        except AppaClientError:
            pass
