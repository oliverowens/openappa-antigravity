"""
OpenAPPA Policy Loader.

Parses OpenAPPA TOML policy files (appa.toml) into canonical ToolRules
and engine configurations using Python's built-in tomllib.
"""

from __future__ import annotations
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .algebra import ToolRule, Trust


@dataclass
class PolicyConfig:
    hitl_mode: str = "chat"
    classification_mode: str = "local"
    redaction_engine: str = "builtin-regex"
    directory_provider: str = "none"
    workspace_only: bool = True
    allowed_external_paths: List[str] = field(default_factory=list)
    trusted_domains: List[str] = field(default_factory=list)
    subagents_allow_execution: bool = False
    subagents_allow_writes: bool = False
    audit_enabled: bool = True
    audit_dir: str = ".appa_audit"
    audit_format: str = "jsonl"
    audit_generate_markdown: bool = True
    audit_mask_secrets: bool = True


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


def load_policy_and_config(
    toml_path: str | Path,
    visited_paths: Optional[Set[Path]] = None,
) -> Tuple[List[ToolRule], PolicyConfig]:
    """Loads a TOML policy file and returns both ToolRules and PolicyConfig.
    Supports OpenAPPA 'include = [...]' directive for composing batteries.
    """
    path = Path(toml_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Policy file not found: {path}")

    if visited_paths is None:
        visited_paths = set()
    if path in visited_paths:
        raise ValueError(f"Circular include detected: {path}")
    visited_paths.add(path)

    with open(path, "rb") as f:
        data = tomllib.load(f)

    rules: List[ToolRule] = []
    policy_sec = data.get("policy", {})
    tools = policy_sec.get("tool", [])

    # Local rules first (OpenAPPA first-match evaluation)
    for tool_data in tools:
        rule = parse_tool_rule(tool_data)
        rules.append(rule)

    # Process included policies/batteries
    includes = data.get("include", []) or policy_sec.get("include", [])
    if isinstance(includes, str):
        includes = [includes]

    for inc in includes:
        inc_path = (path.parent / inc).resolve()
        inc_rules, _ = load_policy_and_config(inc_path, visited_paths)
        rules.extend(inc_rules)

    hitl_sec = policy_sec.get("hitl", {})
    class_sec = policy_sec.get("classification", {})
    redact_sec = policy_sec.get("sanitizers", {}).get("redact-secrets", {})
    dir_sec = policy_sec.get("directory", {})
    bound_sec = policy_sec.get("boundaries", {})
    net_sec = policy_sec.get("network", {})
    sub_sec = policy_sec.get("subagents", {})
    audit_sec = policy_sec.get("audit", {})

    config = PolicyConfig(
        hitl_mode=hitl_sec.get("mode", "chat"),
        classification_mode=class_sec.get("mode", "local"),
        redaction_engine=redact_sec.get("engine", "builtin-regex"),
        directory_provider=dir_sec.get("provider", "none"),
        workspace_only=bound_sec.get("workspace_only", True),
        allowed_external_paths=bound_sec.get("allowed_external_paths", []),
        trusted_domains=net_sec.get("trusted_domains", []),
        subagents_allow_execution=sub_sec.get("allow_execution", False),
        subagents_allow_writes=sub_sec.get("allow_writes", False),
        audit_enabled=audit_sec.get("enabled", True),
        audit_dir=audit_sec.get("dir", ".appa_audit"),
        audit_format=audit_sec.get("format", "jsonl"),
        audit_generate_markdown=audit_sec.get("generate_markdown", True),
        audit_mask_secrets=audit_sec.get("mask_secrets", True),
    )

    return rules, config


def load_policy(toml_path: str | Path) -> List[ToolRule]:
    """Loads a TOML policy file and returns a list of ToolRules."""
    rules, _ = load_policy_and_config(toml_path)
    return rules
