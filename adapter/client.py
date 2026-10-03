"""
OpenAPPA Runtime HTTP Client.

Speaks the canonical OpenAPPA wire protocol (protocol 1) to the runtime.
Provides fail-closed guarantees: network or server failures block tool calls
and withhold tool outputs.
"""

from __future__ import annotations
import json
import urllib.error
import urllib.request
from typing import Any, Dict, Optional


class AppaClientError(Exception):
    pass


class AppaClient:
    def __init__(self, runtime_url: str = "http://127.0.0.1:8788", adapter_name: str = "antigravity", timeout: float = 10.0):
        self.runtime_url = runtime_url.rstrip("/")
        self.adapter_name = adapter_name
        self.timeout = timeout

    def post(self, event: str, root_id: str, fields: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Send a WireEvent to OpenAPPA runtime and parse WireDecision."""
        payload = {
            "protocol": 1,
            "adapter": self.adapter_name,
            "event": event,
            "root_id": root_id,
            **(fields or {}),
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.runtime_url}/hook",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                body = response.read().decode("utf-8")
                res = json.loads(body)
                if not isinstance(res, dict) or res.get("protocol") != 1:
                    raise AppaClientError(f"Invalid runtime reply: {body}")
                return res
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError, OSError) as e:
            # Strict fail-closed: return simulated block decision
            raise AppaClientError(f"Runtime communication failed: {e}") from e

    def session_start(self, root_id: str) -> Dict[str, Any]:
        return self.post("session_start", root_id)

    def prompt(self, root_id: str, text: str, child_id: Optional[str] = None) -> Dict[str, Any]:
        fields: Dict[str, Any] = {"text": text}
        if child_id:
            fields["child_id"] = child_id
        return self.post("prompt", root_id, fields)

    def tool_call(
        self,
        root_id: str,
        tool: str,
        arguments: Dict[str, Any],
        call_id: Optional[str] = None,
        child_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        fields: Dict[str, Any] = {
            "tool": tool,
            "arguments": arguments,
        }
        if call_id:
            fields["call_id"] = call_id
        if child_id:
            fields["child_id"] = child_id
        return self.post("tool_call", root_id, fields)

    def tool_result(
        self,
        root_id: str,
        tool: str,
        arguments: Dict[str, Any],
        outcome: Dict[str, Any],
        call_id: Optional[str] = None,
        child_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        fields: Dict[str, Any] = {
            "tool": tool,
            "arguments": arguments,
            "outcome": outcome,
        }
        if call_id:
            fields["call_id"] = call_id
        if child_id:
            fields["child_id"] = child_id
        return self.post("tool_result", root_id, fields)

    def child_start(self, root_id: str, child_id: str, return_schema: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        fields: Dict[str, Any] = {"child_id": child_id}
        if return_schema:
            fields["return_schema"] = return_schema
        return self.post("child_start", root_id, fields)

    def child_end(self, root_id: str, child_id: str, value: Optional[str] = None) -> Dict[str, Any]:
        fields: Dict[str, Any] = {"child_id": child_id}
        if value is not None:
            fields["value"] = value
        return self.post("child_end", root_id, fields)

    def turn_end(self, root_id: str, child_id: Optional[str] = None) -> Dict[str, Any]:
        fields: Dict[str, Any] = {}
        if child_id:
            fields["child_id"] = child_id
        return self.post("turn_end", root_id, fields)
