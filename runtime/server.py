"""
OpenAPPA Runtime HTTP Server.

Serves the canonical OpenAPPA endpoints on 127.0.0.1:8788:
- POST /hook: Wire protocol hook evaluation
- GET /health: Health probe (returns 'ok')
- POST /reload: Reload policy configuration
- GET /policy-key: Returns active policy key
"""

from __future__ import annotations
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional

from .engine import AppaEngine
from .algebra import ToolRule, Trust


class AppaHTTPHandler(BaseHTTPRequestHandler):
    engine: AppaEngine

    def log_message(self, format: str, *args) -> None:
        # Suppress routine logging for quiet operation
        pass

    def _send_json(self, status: int, data: dict) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
        elif self.path == "/policy-key":
            key_bytes = self.engine.policy_key.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(key_bytes)))
            self.end_headers()
            self.wfile.write(key_bytes)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self) -> None:
        if self.path == "/reload":
            self._send_json(200, {"changed": True, "policy_key": self.engine.policy_key})
            return

        if self.path != "/hook":
            self.send_response(404)
            self.end_headers()
            return

        content_length = int(self.headers.get("Content-Length", 0))
        req_bytes = self.rfile.read(content_length)
        try:
            payload = json.loads(req_bytes.decode("utf-8"))
        except Exception as e:
            self._send_json(400, {"protocol": 1, "decision": "refuse", "detail": f"Malformed JSON: {e}"})
            return

        protocol = payload.get("protocol")
        if protocol != 1:
            self._send_json(400, {"protocol": 1, "decision": "refuse", "detail": "Unsupported protocol version"})
            return

        event = payload.get("event")
        root_id = payload.get("root_id", "default")
        child_id = payload.get("child_id")

        if event == "ping":
            self._send_json(200, {"protocol": 1, "decision": "ack"})
        elif event == "session_start":
            res = self.engine.handle_session_start(root_id)
            self._send_json(200, res)
        elif event == "prompt":
            res = self.engine.handle_prompt(root_id, child_id, payload.get("text", ""))
            self._send_json(200, res)
        elif event == "turn_end":
            res = self.engine.handle_turn_end(root_id, child_id)
            self._send_json(200, res)
        elif event == "tool_call":
            res = self.engine.handle_tool_call(
                root_id=root_id,
                child_id=child_id,
                tool=payload.get("tool", ""),
                arguments=payload.get("arguments", {}),
                call_id=payload.get("call_id"),
            )
            self._send_json(200, res)
        elif event == "tool_result":
            res = self.engine.handle_tool_result(
                root_id=root_id,
                child_id=child_id,
                tool=payload.get("tool", ""),
                arguments=payload.get("arguments", {}),
                outcome=payload.get("outcome", {}),
                call_id=payload.get("call_id"),
            )
            self._send_json(200, res)
        elif event == "child_start":
            res = self.engine.handle_child_start(
                root_id=root_id,
                child_id=payload.get("child_id", ""),
                schema=payload.get("return_schema"),
            )
            self._send_json(200, res)
        elif event == "child_end":
            res = self.engine.handle_child_end(
                root_id=root_id,
                child_id=payload.get("child_id", ""),
                value=payload.get("value"),
            )
            self._send_json(200, res)
        else:
            self._send_json(400, {"protocol": 1, "decision": "refuse", "detail": f"Unknown event: {event}"})


class AppaServer:
    def __init__(self, engine: AppaEngine, host: str = "127.0.0.1", port: int = 8788):
        self.engine = engine
        self.host = host
        self.port = port
        self.server: Optional[HTTPServer] = None
        self.thread: Optional[threading.Thread] = None

    def start(self) -> None:
        handler = type("ConfiguredHandler", (AppaHTTPHandler,), {"engine": self.engine})
        self.server = HTTPServer((self.host, self.port), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
