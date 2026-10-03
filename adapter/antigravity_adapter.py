"""
Antigravity Tool Adapter for OpenAPPA.

Identifies and canonicalizes Antigravity tool calls:
- run_command -> host/antigravity/run_command (with CommandLine selector)
- view_file -> host/antigravity/view_file (with AbsolutePath selector)
- replace_file_content -> host/antigravity/replace_file_content (with TargetFile selector)
- write_to_file -> host/antigravity/write_to_file (with TargetFile selector)
- read_url_content -> host/antigravity/read_url_content (with Url selector)
- search_web -> host/antigravity/search_web
- invoke_subagent -> host/antigravity/invoke_subagent (identified as spawn tool)
- execute_remedy_plan -> mcp__appa__execute_remedy_plan (control tool)
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple


CONTROL_TOOL = "mcp__appa__execute_remedy_plan"


@dataclass
class CanonicalTool:
    namespace: str
    server: str
    name: str

    @property
    def canonical_id(self) -> str:
        return f"{self.namespace}/{self.server}/{self.name}"

    def is_control(self) -> bool:
        return self.canonical_id in ("appa/execute_remedy_plan", "mcp/appa/execute_remedy_plan")


def identify_tool(raw_name: str) -> Tuple[CanonicalTool, bool]:
    """
    Identifies a tool name and determines if it is a subagent spawn call.
    Returns (canonical_tool, is_spawn).
    """
    if raw_name in ("execute_remedy_plan", "mcp__appa__execute_remedy_plan", "appa/execute_remedy_plan"):
        return CanonicalTool("mcp", "appa", "execute_remedy_plan"), False

    if raw_name == "invoke_subagent":
        return CanonicalTool("host", "antigravity", "invoke_subagent"), True

    if raw_name.startswith("mcp__"):
        parts = raw_name[5:].split("__", 1)
        if len(parts) == 2:
            return CanonicalTool("mcp", parts[0], parts[1]), False
        return CanonicalTool("mcp", "unknown", raw_name[5:]), False

    return CanonicalTool("host", "antigravity", raw_name), False


def extract_selector_value(raw_tool: str, args: Dict[str, Any]) -> Tuple[str, str]:
    """
    Extracts the key argument used for fine-grained policy selection.
    """
    if raw_tool == "run_command":
        return "command", str(args.get("CommandLine", ""))
    elif raw_tool in ("view_file", "view_image_file"):
        return "path", str(args.get("AbsolutePath", ""))
    elif raw_tool in ("replace_file_content", "write_to_file"):
        return "path", str(args.get("TargetFile", ""))
    elif raw_tool == "read_url_content":
        return "url", str(args.get("Url", ""))
    elif raw_tool == "search_web":
        return "query", str(args.get("query", ""))
    elif raw_tool == "ask_question":
        return "questions", str(args.get("questions", ""))
    elif raw_tool == "send_message":
        return "recipient", str(args.get("Recipient", ""))
    elif raw_tool in ("manage_subagents", "manage_task"):
        return "action", str(args.get("Action", ""))
    elif raw_tool in ("schedule", "generate_image"):
        return "prompt", str(args.get("Prompt", ""))
    elif raw_tool == "execute_remedy_plan":
        return "offer_id", str(args.get("offer_id", ""))
    return "", ""

