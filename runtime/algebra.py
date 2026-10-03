"""
APPA Information-Flow Policy Algebra.

Implements the formal algebraic rules from OpenAPPA (appa-engine):
- Monoid of labels: checked monoid of (trust x audience)
- Trust lattice: suspicious <= trusted (ordered lattice; meet is min)
- Audience chain: self <= internal <= public (ordered subset inclusion)
- Sound information-flow checking and monotonic label propagation.
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, List, Optional, Set, Tuple


class Trust(IntEnum):
    SUSPICIOUS = 0
    TRUSTED = 1

    @classmethod
    def from_str(cls, s: str) -> Trust:
        val = s.strip().lower()
        if val == "trusted":
            return cls.TRUSTED
        elif val == "suspicious":
            return cls.SUSPICIOUS
        raise ValueError(f"Unknown trust level: {s}")

    def to_str(self) -> str:
        return "trusted" if self == Trust.TRUSTED else "suspicious"

    def meet(self, other: Trust) -> Trust:
        """Meet operator for trust lattice: min(self, other)."""
        return Trust(min(self.value, other.value))


class AudienceOrder(IntEnum):
    SELF = 0
    INTERNAL = 1
    PUBLIC = 2

    @classmethod
    def from_str(cls, s: str) -> AudienceOrder:
        val = s.strip().lower()
        if val == "self":
            return cls.SELF
        elif val == "internal":
            return cls.INTERNAL
        elif val == "public":
            return cls.PUBLIC
        return cls.SELF


@dataclass(frozen=True)
class Label:
    trust: Trust = Trust.TRUSTED
    # Audience is represented as the narrowest allowed visibility boundary.
    # self <= internal <= public
    audience: str = "public"

    def combine(self, delta_trust: Optional[str] = None, delta_audience: Optional[List[str]] = None) -> Label:
        """Monoid fold: propagation narrows audience and takes minimum trust."""
        new_trust = self.trust
        if delta_trust:
            t = Trust.from_str(delta_trust)
            new_trust = new_trust.meet(t)

        new_audience = self.audience
        if delta_audience:
            # Narrowest audience wins (intersection of audiences)
            current_ord = AudienceOrder.from_str(self.audience)
            for aud in delta_audience:
                aud_ord = AudienceOrder.from_str(aud)
                if aud_ord < current_ord:
                    current_ord = aud_ord
                    new_audience = aud
        return Label(trust=new_trust, audience=new_audience)

    def can_flow_to(self, target_audience: str) -> bool:
        """
        Information flow check: can data at this label flow to target_audience?
        Data labeled 'self' can only flow to 'self'.
        Data labeled 'internal' can flow to 'internal' or 'self'.
        Data labeled 'public' can flow anywhere.
        """
        source_ord = AudienceOrder.from_str(self.audience)
        target_ord = AudienceOrder.from_str(target_audience)
        # Source must be as public or more public than target sink's requirement
        return source_ord >= target_ord


@dataclass
class ToolRequirement:
    trust: Optional[Trust] = None
    audience_contains: Optional[List[str]] = None


@dataclass
class ToolRule:
    canonical_name: str
    raw_pattern: str
    description: str = ""
    delta_trust: Optional[str] = None
    delta_audience: Optional[List[str]] = None
    requires_trust: Optional[Trust] = None
    requires_audience: Optional[List[str]] = None
    tags: List[str] = field(default_factory=list)
    annotator: Optional[str] = None

    def matches(self, tool_name: str, args: Dict[str, Any]) -> bool:
        """Check if rule matches raw tool name and arguments selector."""
        # Check tool name prefix
        if "(" in self.raw_pattern and self.raw_pattern.endswith(")"):
            base_pattern, selector = self.raw_pattern[:-1].split("(", 1)
            if not self._pattern_match(base_pattern, tool_name):
                return False
            # Selector format: key:glob_pattern
            if ":" in selector:
                key, pattern = selector.split(":", 1)
                val = args.get(key)
                if val is None:
                    # Check common argument aliases
                    aliases = {
                        "path": ["AbsolutePath", "TargetFile", "file_path", "path", "file"],
                        "command": ["CommandLine", "cmd", "command"],
                        "url": ["Url", "url", "uri"],
                        "query": ["query", "q"],
                    }
                    for alias in aliases.get(key, []):
                        if alias in args:
                            val = args[alias]
                            break
                val = str(val or "")
                # Normalize Windows backslashes for path matching
                if key in ("path", "AbsolutePath", "TargetFile", "file_path"):
                    val = val.replace("\\", "/")
                return self._glob_match(pattern, val)
            return True
        else:
            return self._pattern_match(self.raw_pattern, tool_name)

    @staticmethod
    def _pattern_match(pattern: str, text: str) -> bool:
        if pattern == "*" or pattern == text:
            return True
        regex = "^" + re.escape(pattern).replace(r"\*", ".*") + "$"
        return bool(re.match(regex, text))

    @staticmethod
    def _glob_match(glob: str, text: str) -> bool:
        regex = "^" + re.escape(glob).replace(r"\*", ".*") + "$"
        return bool(re.match(regex, text, re.IGNORECASE))
