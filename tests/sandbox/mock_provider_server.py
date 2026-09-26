"""Mock server simulating upstream LLM provider validation and intelligence endpoints."""

from __future__ import annotations

import http.server
import json
import socketserver
import threading
from urllib.parse import parse_qs, urlparse

from tests.sandbox.fixtures import TEST_KEYS


class MockProviderHandler(http.server.BaseHTTPRequestHandler):
    """Handler routing requests to mock LLM provider endpoints."""

    def _get_key_from_request(self) -> tuple[str, dict[str, str]]:
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        headers = {k.lower(): v for k, v in self.headers.items()}
        
        key = ""
        # 1. Query parameter (?key=...)
        if "key" in query and query["key"]:
            key = query["key"][0]
        # 2. X-Goog-Api-Key
        elif "x-goog-api-key" in headers:
            key = headers["x-goog-api-key"]
        # 3. X-Api-Key (Anthropic)
        elif "x-api-key" in headers:
            key = headers["x-api-key"]
        # 4. Bearer token (OpenAI / NVIDIA)
        elif "authorization" in headers and headers["authorization"].startswith("Bearer "):
            key = headers["authorization"][7:].strip()

        return key, headers

    def _send_json_response(self, status_code: int, data: dict | list) -> None:
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        key, headers = self._get_key_from_request()

        # -------------------------------------------------------------
        # 1. Google Gemini Endpoints (/v1beta/models, /v1beta/tunedModels, etc.)
        # -------------------------------------------------------------
        if path.startswith("/v1beta/") or path.startswith("/v1alpha/") or ("key=" in self.path and "AIzaSy" in self.path) or "x-goog-api-key" in headers or key.startswith("AIzaSy"):
            if path.startswith("/v1beta/tunedModels") or path.startswith("/v1alpha/tunedModels"):
                self._send_json_response(200, {"tunedModels": []})
                return

            if key == TEST_KEYS["google_valid"]:
                self._send_json_response(200, {
                    "models": [
                        {"name": "models/gemini-1.5-pro", "version": "001", "displayName": "Gemini 1.5 Pro"},
                        {"name": "models/gemini-2.0-flash", "version": "001", "displayName": "Gemini 2.0 Flash"},
                    ]
                })
                return

            if key == TEST_KEYS["google_bypass"]:
                referer = headers.get("referer", "")
                origin = headers.get("origin", "")
                # Simulate successful HTTP Referrer bypass
                if referer or origin:
                    self._send_json_response(200, {
                        "models": [
                            {"name": "models/gemini-1.5-flash", "version": "001", "displayName": "Gemini 1.5 Flash"}
                        ]
                    })
                else:
                    self._send_json_response(403, {
                        "error": {
                            "code": 403,
                            "message": "API key not valid. Please pass a valid API key.",
                            "status": "PERMISSION_DENIED",
                            "details": [
                                {
                                    "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                                    "reason": "API_KEY_HTTP_REFERRER_BLOCKED",
                                    "domain": "googleapis.com",
                                }
                            ],
                        }
                    })
                return

            if key == TEST_KEYS["google_rate_limited"]:
                self._send_json_response(429, {
                    "error": {
                        "code": 429,
                        "message": "Resource has been exhausted (e.g. check quota).",
                        "status": "RESOURCE_EXHAUSTED",
                    }
                })
                return

            # Default Google invalid key
            self._send_json_response(403, {
                "error": {
                    "code": 403,
                    "message": "API key not valid",
                    "status": "PERMISSION_DENIED",
                    "details": [{"reason": "API_KEY_INVALID"}],
                }
            })
            return

        # -------------------------------------------------------------
        # 2. OpenAI / NVIDIA Endpoints (/v1/models)
        # -------------------------------------------------------------
        if path == "/v1/models":
            # OpenAI keys
            if key.startswith("sk-proj-") or key.startswith("sk-") or key.startswith("org-"):
                if key in (TEST_KEYS["openai_standard"], TEST_KEYS["openai_project"], TEST_KEYS["openai_org"]):
                    self._send_json_response(200, {
                        "object": "list",
                        "data": [
                            {"id": "gpt-4o", "object": "model", "owned_by": "openai"},
                            {"id": "gpt-4o-mini", "object": "model", "owned_by": "openai"},
                        ]
                    })
                    return
                self._send_json_response(401, {
                    "error": {
                        "message": "Incorrect API key provided.",
                        "type": "invalid_request_error",
                        "code": "invalid_api_key",
                    }
                })
                return

            # NVIDIA keys
            if key.startswith("nvapi-"):
                if key == TEST_KEYS["nvidia_valid"]:
                    self._send_json_response(200, {
                        "object": "list",
                        "data": [
                            {"id": "meta/llama-3.1-405b-instruct", "object": "model", "owned_by": "nvidia"},
                            {"id": "nvidia/nemotron-4-340b-instruct", "object": "model", "owned_by": "nvidia"},
                        ]
                    })
                    return
                self._send_json_response(401, {
                    "detail": "Invalid or missing token"
                })
                return

            self._send_json_response(401, {
                "error": {
                    "message": "Unauthorized.",
                }
            })
            return

        self._send_json_response(404, {"error": "Not found"})

    def do_POST(self) -> None:
        content_length = int(self.headers.get("content-length", 0))
        if content_length > 0:
            self.rfile.read(content_length)
            
        path = urlparse(self.path).path
        key, _ = self._get_key_from_request()

        # -------------------------------------------------------------
        # 3. Anthropic Messages (/v1/messages)
        # -------------------------------------------------------------
        if path == "/v1/messages":
            if key == TEST_KEYS["anthropic_valid"]:
                self._send_json_response(200, {
                    "id": "msg_01DummyAnthropicMsg123",
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "text", "text": "Hi"}],
                    "model": "claude-sonnet-4-20250514",
                    "stop_reason": "max_tokens",
                })
                return

            self._send_json_response(401, {
                "type": "error",
                "error": {
                    "type": "authentication_error",
                    "message": "invalid x-api-key",
                }
            })
            return

        self._send_json_response(404, {"error": "Not found"})

    def log_message(self, format: str, *args: object) -> None:
        pass


class MockProviderServer:
    """Manages lifecycle of the mock LLM provider API server."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.host = host
        self.server = socketserver.TCPServer((host, port), MockProviderHandler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self) -> str:
        """Start the server in background thread and return base URL."""
        self.thread.start()
        return f"http://{self.host}:{self.port}"

    def stop(self) -> None:
        """Shutdown and close socket."""
        self.server.shutdown()
        self.server.server_close()


if __name__ == "__main__":
    server = MockProviderServer(port=8082)
    url = server.start()
    print(f"Mock provider server running at {url}")
    try:
        server.thread.join()
    except KeyboardInterrupt:
        server.stop()
