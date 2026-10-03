"""
OpenAPPA Built-in Sanitizers.

Implements standard OpenAPPA sanitizers:
1. redact-secrets: Masks private keys, credentials, tokens, and secret assignments.
   Permits audience transition from ['self'] to ['public'].
2. attest-schema: Attests child return payload against a strict JSON schema.
   Permits trust transition from 'suspicious' to 'trusted'.
"""

from __future__ import annotations
import json
import re
from typing import Any, Dict, Optional, Tuple


# Regex patterns matching secrets and credentials
SECRET_PATTERNS = [
    # RSA / EC private keys
    r"-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----",
    # AWS Access Key ID & Secret Key
    r"\bAKIA[0-9A-Z]{16}\b",
    r"\b[A-Za-z0-9/+=]{40}\b(?=.*[A-Za-z0-9])",
    # GitHub Tokens
    r"\bgh[pousr]_[A-Za-z0-9_]{36,255}\b",
    # Generic bearer tokens & API keys
    r'(?i)(api[_-]?key|secret|password|token|bearer)\s*[:=]\s*["\']?([A-Za-z0-9_\-\.]{8,})["\']?',
    # Common JWTs
    r"\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b",
]


def redact_secrets(text: str) -> Tuple[str, bool]:
    """
    Sanitizes secrets in text, replacing them with [REDACTED_SECRET].
    Returns (sanitized_text, whether_redacted).
    """
    redacted = False
    result = text

    # First handle multi-line private keys
    key_match = re.search(r"-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----", result)
    if key_match:
        result = result[:key_match.start()] + "[REDACTED_PRIVATE_KEY]" + result[key_match.end():]
        redacted = True

    # Handle key-value secret assignments
    for pattern in SECRET_PATTERNS:
        matches = list(re.finditer(pattern, result))
        if matches:
            redacted = True
            for m in reversed(matches):
                if m.lastindex and m.lastindex >= 2:
                    # Key-value assignment match: preserve key, mask value
                    start, end = m.span(2)
                    result = result[:start] + "[REDACTED]" + result[end:]
                else:
                    start, end = m.span()
                    result = result[:start] + "[REDACTED_SECRET]" + result[end:]

    return result, redacted


def canonical_json(data: Any) -> str:
    """RFC 8785 Canonical JSON output: sorted keys, compact separators, UTF-8."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def attest_schema(payload: str, schema: Dict[str, Any]) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Validates payload against schema and returns canonical JSON representation.
    Returns (valid, canonical_json_or_error, error_message).
    """
    try:
        data = json.loads(payload)
    except Exception as e:
        return False, None, f"Payload is not valid JSON: {e}"

    if not isinstance(data, dict):
        return False, None, "Payload must be a JSON object"

    # Validate type and required properties
    req = schema.get("required", [])
    for field_name in req:
        if field_name not in data:
            return False, None, f"Missing required property: {field_name}"

    props = schema.get("properties", {})
    for k, v in data.items():
        if k in props:
            expected_type = props[k].get("type")
            if expected_type == "string" and not isinstance(v, str):
                return False, None, f"Property '{k}' must be string"
            elif expected_type == "integer" and not isinstance(v, int):
                return False, None, f"Property '{k}' must be integer"
            elif expected_type == "boolean" and not isinstance(v, bool):
                return False, None, f"Property '{k}' must be boolean"

            # Check enum if present
            if "enum" in props[k] and v not in props[k]["enum"]:
                return False, None, f"Property '{k}' must be one of {props[k]['enum']}"

    # Canonical sorted JSON output
    canonical = canonical_json(data)
    return True, canonical, None


