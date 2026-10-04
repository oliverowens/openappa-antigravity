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
import tempfile
import unittest
from pathlib import Path

# Setup paths
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from runtime.engine import AppaEngine
from runtime.server import AppaServer
from runtime.policy_loader import load_policy, load_policy_and_config
import argparse
from adapter.client import AppaClient, AppaClientError
from adapter.agent_loop import OpenAppaAgentLoop, InterceptedExecutionError
from adapter.hooks_handler import handle_pre_tool_use
from adapter.cli import cmd_describe, cmd_replay, cmd_yell, cmd_audit, cmd_version
from runtime.audit import AuditLogger, mask_sensitive_arguments
from scripts.release import (
    verify_versions,
    get_current_version,
    parse_semver,
    bump_version,
    infer_bump_from_commits,
    SEMVER_REGEX,
)



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

    # ==========================================================================
    # Requirement 6: CLI & Verification Tooling (describe, replay, yell)
    # ==========================================================================

    def test_cli_describe_check(self):
        """OpenAPPA CLI describe --check must validate the policy and return code 0."""
        args = argparse.Namespace(config=str(ROOT_DIR / "policy" / "appa.toml"), check=True)
        ret = cmd_describe(args)
        self.assertEqual(ret, 0)

    def test_cli_replay(self):
        """OpenAPPA CLI replay must verify recorded traces against policy deterministically."""
        trace_file = ROOT_DIR / "policy-tests" / "trajectories_replay.json"
        args = argparse.Namespace(config=str(ROOT_DIR / "policy" / "appa.toml"), trace=str(trace_file))
        ret = cmd_replay(args)
        self.assertEqual(ret, 0)

    def test_cli_yell(self):
        """OpenAPPA CLI yell must generate a report conforming to openappa.yell.v1."""
        captured = io.StringIO()
        old_stdout = sys.stdout
        try:
            sys.stdout = captured
            args = argparse.Namespace(config=str(ROOT_DIR / "policy" / "appa.toml"), output=None)
            ret = cmd_yell(args)
        finally:
            sys.stdout = old_stdout

        self.assertEqual(ret, 0)
        report = json.loads(captured.getvalue())
        self.assertEqual(report.get("$schema"), "openappa.yell.v1")
        self.assertEqual(report.get("adapter"), "antigravity")
        self.assertIn("policy_key", report)
        self.assertIn("diagnostics", report)

    def test_policy_loader_include_support(self):
        """Policy loader must correctly resolve include = [...] directives for battery composition."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            battery_path = Path(tmpdir) / "sub_battery.toml"
            battery_path.write_text(
                """
                [policy]
                version = 2
                [[policy.tool]]
                name = "mcp/github/create_issue"
                requires = { trust = "trusted" }
                delta = {}
                """,
                encoding="utf-8",
            )

            main_path = Path(tmpdir) / "main.toml"
            main_path.write_text(
                f"""
                [policy]
                version = 2
                include = ["sub_battery.toml"]
                [[policy.tool]]
                name = "host/antigravity/run_command"
                delta = {{}}
                """,
                encoding="utf-8",
            )

            rules, _ = load_policy_and_config(main_path)
            rule_names = [r.canonical_name for r in rules]
            self.assertIn("host/antigravity/run_command", rule_names)
            self.assertIn("mcp/github/create_issue", rule_names)

    def test_antigravity_interactive_tools_coverage(self):
        """Antigravity interactive tools (ask_question, send_message, manage_task) are governed by policy."""
        # 1. ask_question succeeds on trusted trajectory
        asked = False

        def ask_fn(args):
            nonlocal asked
            asked = True
            return "User confirmed"

        ok_ask, res_ask = self.agent.execute_tool_safely(
            raw_name="ask_question",
            arguments={"questions": [{"question": "Proceed?", "options": ["Yes", "No"]}]},
            tool_fn=ask_fn,
        )
        self.assertTrue(ok_ask)
        self.assertTrue(asked)

        # 2. Ingest untrusted data to degrade trust
        self.agent.execute_tool_safely(
            raw_name="read_url_content",
            arguments={"Url": "https://untrusted-site.com/payload"},
            tool_fn=lambda args: "attacker injection",
        )

        # 3. ask_question is blocked on suspicious trajectory to stop spoofing
        asked_again = False
        ok_blocked, res_blocked = self.agent.execute_tool_safely(
            raw_name="ask_question",
            arguments={"questions": [{"question": "Grant admin?", "options": ["Yes", "No"]}]},
            tool_fn=lambda args: "spoofed",
        )
        self.assertFalse(ok_blocked)
        self.assertIn("below required floor", res_blocked)

    # ==========================================================================
    # Requirement 7: Audit & Decision Logging Subsystem
    # ==========================================================================

    def test_audit_logger_creates_jsonl_and_markdown(self):
        """AuditLogger correctly records decisions into dual JSONL and Markdown review cards."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = AuditLogger(workspace_dir=tmpdir, enabled=True)
            session_id = "test_audit_session"

            # 1. Record an allowed decision
            path1 = logger.record_decision(
                session_id=session_id,
                event="tool_call",
                tool="host/antigravity/run_command",
                arguments={"CommandLine": "echo 'safe'"},
                decision="allow_call",
                reason="Allowed by security policy.",
                step_idx="1",
                call_id="call_001",
                matched_rule={"pattern": "host/antigravity/run_command", "requires_trust": "trusted"},
                trajectory_state={"trust": "trusted", "audience": ["public"]},
            )
            self.assertIsNotNone(path1)

            # 2. Record a denied decision
            path2 = logger.record_decision(
                session_id=session_id,
                event="tool_call",
                tool="host/antigravity/delete_all",
                arguments={"target": "*"},
                decision="deny_call",
                reason="[appa] Blocked: tool 'delete_all' is undeclared.",
                step_idx="2",
                call_id="call_002",
            )
            self.assertIsNotNone(path2)

            audit_dir = Path(tmpdir) / ".appa_audit"
            self.assertTrue(audit_dir.is_dir())

            jsonl_file = audit_dir / f"session_{session_id}.jsonl"
            md_file = audit_dir / f"session_{session_id}.md"
            latest_file = audit_dir / "latest.session"

            self.assertTrue(jsonl_file.is_file())
            self.assertTrue(md_file.is_file())
            self.assertTrue(latest_file.is_file())
            self.assertEqual(latest_file.read_text(encoding="utf-8").strip(), jsonl_file.name)

            # Verify JSONL content
            lines = [json.loads(line) for line in jsonl_file.read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertEqual(len(lines), 2)
            self.assertEqual(lines[0]["decision"], "allow_call")
            self.assertEqual(lines[0]["tool"], "host/antigravity/run_command")
            self.assertEqual(lines[1]["decision"], "deny_call")

            # Verify Markdown content
            md_content = md_file.read_text(encoding="utf-8")
            self.assertIn("OpenAPPA Decision Audit Log", md_content)
            self.assertIn("🟢 ALLOWED", md_content)
            self.assertIn("🔴 BLOCKED", md_content)

            # Verify session listing
            sessions = logger.list_sessions()
            self.assertEqual(len(sessions), 1)
            self.assertEqual(sessions[0]["session_id"], session_id)
            self.assertEqual(sessions[0]["event_count"], 2)
            self.assertEqual(sessions[0]["allowed"], 1)
            self.assertEqual(sessions[0]["blocked"], 1)

            # Verify reading session events
            events = logger.read_session_events(session_id)
            self.assertEqual(len(events), 2)

    def test_audit_logger_masks_sensitive_secrets(self):
        """Audit logger masks secret keys, tokens, and passwords in logged arguments."""
        args = {
            "api_key": "sk-1234567890abcdef",
            "token": "ghp_secrettokenvalue",
            "db_password": "supersecretpassword",
            "short_secret": "abc",
            "public_param": "hello_world",
            "nested": {
                "auth_bearer": "bearer_jwt_token_12345",
                "normal": 42,
            },
        }

        sanitized = mask_sensitive_arguments(args)
        self.assertTrue(sanitized["api_key"].startswith("sk-"))
        self.assertTrue(sanitized["api_key"].endswith("...[REDACTED]"))
        self.assertTrue(sanitized["token"].endswith("...[REDACTED]"))
        self.assertEqual(sanitized["short_secret"], "[REDACTED]")
        self.assertEqual(sanitized["public_param"], "hello_world")
        self.assertTrue(sanitized["nested"]["auth_bearer"].endswith("...[REDACTED]"))
        self.assertEqual(sanitized["nested"]["normal"], 42)

    def test_audit_logger_disabled_toggle(self):
        """When audit is disabled, no files or directories are created."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # 1. Explicitly disabled via constructor
            logger = AuditLogger(workspace_dir=tmpdir, enabled=False)
            res = logger.record_decision(
                session_id="disabled_session",
                event="tool_call",
                tool="run_command",
                arguments={},
                decision="allow_call",
            )
            self.assertIsNone(res)
            self.assertFalse((Path(tmpdir) / ".appa_audit").exists())

            # 2. Environment variable override
            old_env = os.environ.get("OPENAPPA_AUDIT")
            try:
                os.environ["OPENAPPA_AUDIT"] = "0"
                logger_env = AuditLogger(workspace_dir=tmpdir, enabled=True)
                self.assertFalse(logger_env.enabled)
            finally:
                if old_env is not None:
                    os.environ["OPENAPPA_AUDIT"] = old_env
                else:
                    os.environ.pop("OPENAPPA_AUDIT", None)

    def test_audit_cli_commands(self):
        """CLI `appa audit status`, `appa audit list`, and `appa audit view` run cleanly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = AuditLogger(workspace_dir=tmpdir, enabled=True)
            logger.record_decision(
                session_id="cli_test_session",
                event="tool_call",
                tool="host/antigravity/run_command",
                arguments={"CommandLine": "echo 'testing CLI'"},
                decision="allow_call",
                step_idx="1",
                call_id="call_cli_1",
            )

            # Test status
            args_status = argparse.Namespace(
                audit_action="status",
                workspace=tmpdir,
                config=str(ROOT_DIR / "policy" / "appa.toml"),
            )
            buf = io.StringIO()
            old_stdout = sys.stdout
            try:
                sys.stdout = buf
                code = cmd_audit(args_status)
                self.assertEqual(code, 0)
                output = buf.getvalue()
                self.assertIn("OpenAPPA Audit Subsystem Status", output)
                self.assertIn("Total Sessions   : 1", output)
            finally:
                sys.stdout = old_stdout

            # Test list
            args_list = argparse.Namespace(
                audit_action="list",
                workspace=tmpdir,
                config=str(ROOT_DIR / "policy" / "appa.toml"),
            )
            buf = io.StringIO()
            try:
                sys.stdout = buf
                code = cmd_audit(args_list)
                self.assertEqual(code, 0)
                output = buf.getvalue()
                self.assertIn("cli_test_session", output)
            finally:
                sys.stdout = old_stdout

            # Test view
            args_view = argparse.Namespace(
                audit_action="view",
                session_id="cli_test_session",
                workspace=tmpdir,
                config=str(ROOT_DIR / "policy" / "appa.toml"),
            )
            buf = io.StringIO()
            try:
                sys.stdout = buf
                code = cmd_audit(args_view)
                self.assertEqual(code, 0)
                output = buf.getvalue()
                self.assertIn("OpenAPPA Audit Review: Session cli_test_session", output)
                self.assertIn("[ALLOWED]", output)
            finally:
                sys.stdout = old_stdout

    # ==========================================================================
    # Requirement 7: Test-Driven Semantic Versioning & Manifest Integrity
    # ==========================================================================

    def test_semver_manifests_are_synchronized(self):
        """All package manifests (pyproject, appa-package, inits, README badge) are in lockstep."""
        in_sync, primary, discrepancies = verify_versions()
        self.assertTrue(
            in_sync,
            f"Version drift detected across repository manifests! Primary: {primary}, Discrepancies: {discrepancies}"
        )
        self.assertRegex(primary, SEMVER_REGEX)

    def test_semver_syntax_and_parser(self):
        """parse_semver correctly parses semantic versions and rejects malformed versions."""
        # Valid standard SemVer
        maj, min_, patch = parse_semver("0.4.0")
        self.assertEqual((maj, min_, patch), (0, 4, 0))

        maj, min_, patch = parse_semver("v1.2.3")
        self.assertEqual((maj, min_, patch), (1, 2, 3))

        maj, min_, patch = parse_semver("2.10.5-rc.1")
        self.assertEqual((maj, min_, patch), (2, 10, 5))

        # Invalid versions
        with self.assertRaises(ValueError):
            parse_semver("1.2")
        with self.assertRaises(ValueError):
            parse_semver("invalid-semver")
        with self.assertRaises(ValueError):
            parse_semver("1.2.3.4")

    def test_semver_bump_calculation_rules(self):
        """bump_version strictly follows SemVer arithmetic (patch, minor, major)."""
        base = "0.4.0"
        self.assertEqual(bump_version(base, "patch"), "0.4.1")
        self.assertEqual(bump_version(base, "minor"), "0.5.0")
        self.assertEqual(bump_version(base, "major"), "1.0.0")

        v2 = "1.9.9"
        self.assertEqual(bump_version(v2, "patch"), "1.9.10")
        self.assertEqual(bump_version(v2, "minor"), "1.10.0")
        self.assertEqual(bump_version(v2, "major"), "2.0.0")

        with self.assertRaises(ValueError):
            bump_version(base, "unknown_part")

    def test_semver_conventional_commit_inference(self):
        """infer_bump_from_commits correctly infers bump level from Conventional Commits."""
        # 1. Bug fixes, docs, chore -> patch
        patch_commits = [
            "fix: correct edge case in path confinement",
            "docs: update readme with quickstart",
            "chore: bump dependencies in lockfile",
        ]
        bump, _ = infer_bump_from_commits(patch_commits)
        self.assertEqual(bump, "patch")

        # 2. Features -> minor
        feat_commits = [
            "fix: typo in error message",
            "feat(cli): add appa version command",
        ]
        bump, _ = infer_bump_from_commits(feat_commits)
        self.assertEqual(bump, "minor")

        # 3. Breaking changes via bang -> major
        breaking_bang = [
            "feat!: redesign Information-Flow Control algebra",
            "fix: minor bug",
        ]
        bump, _ = infer_bump_from_commits(breaking_bang)
        self.assertEqual(bump, "major")

        # 4. Breaking changes via footer -> major
        breaking_footer = [
            "feat: update wire protocol\n\nBREAKING CHANGE: changes decision response envelope",
        ]
        bump, _ = infer_bump_from_commits(breaking_footer)
        self.assertEqual(bump, "major")

    def test_semver_cli_version_command(self):
        """CLI `appa version` and `appa version --check` execute successfully."""
        # 1. Standard version display
        args_plain = argparse.Namespace(check=False)
        buf = io.StringIO()
        old_stdout = sys.stdout
        try:
            sys.stdout = buf
            code = cmd_version(args_plain)
            self.assertEqual(code, 0)
            self.assertIn("openappa-antigravity v", buf.getvalue())
        finally:
            sys.stdout = old_stdout

        # 2. Lockstep verification check
        args_check = argparse.Namespace(check=True)
        buf2 = io.StringIO()
        try:
            sys.stdout = buf2
            code = cmd_version(args_check)
            self.assertEqual(code, 0)
            self.assertIn("[OpenAPPA SemVer] SUCCESS", buf2.getvalue())
        finally:
            sys.stdout = old_stdout


if __name__ == "__main__":
    unittest.main()

