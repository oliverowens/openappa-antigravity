"""
OpenAPPA Policy Loader.

Parses OpenAPPA TOML policy files (appa.toml) into canonical ToolRules
and engine configurations using Python's built-in tomllib.
"""

from __future__ import annotations
import tomllib
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .algebra import ToolRule, Trust


def parse_tool_rule(data: Dict[str, Any]) -> ToolRule:
    raw_name = data.get("name", "")
    description = data.get("description", "")
    delta = data.get("delta", {})
    requires = data.get("requires", {})
    tags = data.get("tags", [])
    annotator = data.get("annotator")

    # Parse delta
    delta_trust = delta.get("trust")
    delta_audience = delta.get("audience")
    if isinstance(delta_audience, str):
        delta_audience = [delta_audience]

    # Parse requires
    req_trust: Optional[Trust] = None
    if "trust" in requires:
        req_trust = Trust.from_str(requires["trust"])

    req_audience: Optional[List[str]] = None
    if "audience" in requires:
        aud_val = requires["audience"]
        if isinstance(aud_val, dict) and "contains" in aud_val:
            req_audience = aud_val["contains"]
        elif isinstance(aud_val, list):
            req_audience = aud_val
        elif isinstance(aud_val, str):
            req_audience = [aud_val]

    return ToolRule(
        canonical_name=raw_name,
        raw_pattern=raw_name,
        description=description,
        delta_trust=delta_trust,
        delta_audience=delta_audience,
        requires_trust=req_trust,
        requires_audience=req_audience,
        tags=tags,
        annotator=annotator,
    )


def load_policy(toml_path: str | Path) -> List[ToolRule]:
    """Loads a TOML policy file and returns a list of ToolRules."""
    path = Path(toml_path)
    if not path.is_file():
        raise FileNotFoundError(f"Policy file not found: {path}")

    with open(path, "rb") as f:
        data = tomllib.load(f)

    rules: List[ToolRule] = []
    policy_sec = data.get("policy", {})
    tools = policy_sec.get("tool", [])

    for tool_data in tools:
        rule = parse_tool_rule(tool_data)
        rules.append(rule)

    return rules
