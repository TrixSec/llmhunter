"""Mock target web server for serving vulnerable HTML, JS bundles, source maps, and webpack chunks."""

from __future__ import annotations

import http.server
import socketserver
import threading
from typing import ClassVar

from tests.sandbox.fixtures import (
    MOCK_APP_JS,
    MOCK_CHUNK_0_JS,
    MOCK_CHUNK_1_JS,
    MOCK_INDEX_HTML,
    MOCK_MANIFEST_JS,
    MOCK_VENDOR_JS,
    MOCK_VENDOR_SOURCE_MAP,
)


class MockTargetHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler for mock vulnerable web assets."""

    ROUTES: ClassVar[dict[str, tuple[str, str]]] = {
        "/": (MOCK_INDEX_HTML, "text/html"),
        "/index.html": (MOCK_INDEX_HTML, "text/html"),
        "/static/app.js": (MOCK_APP_JS, "application/javascript"),
        "/static/vendor.js": (MOCK_VENDOR_JS, "application/javascript"),
        "/static/vendor.js.map": (MOCK_VENDOR_SOURCE_MAP, "application/json"),
        "/static/chunks/manifest.js": (MOCK_MANIFEST_JS, "application/javascript"),
        "/static/chunks/chunk.0.js": (MOCK_CHUNK_0_JS, "application/javascript"),
        "/static/chunks/chunk.1.js": (MOCK_CHUNK_1_JS, "application/javascript"),
    }

    def do_GET(self) -> None:
        path = self.path.split("?")[0]
        if path in self.ROUTES:
            content, content_type = self.ROUTES[path]
            data = content.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", f"{content_type}; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"404 Not Found")

    def log_message(self, format: str, *args: object) -> None:
        # Suppress standard logging during tests
        pass


class MockTargetServer:
    """Manages lifecycle of the mock vulnerable web target server."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.host = host
        self.server = socketserver.TCPServer((host, port), MockTargetHandler)
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
    server = MockTargetServer(port=8081)
    url = server.start()
    print(f"Mock target server running at {url}")
    try:
        server.thread.join()
    except KeyboardInterrupt:
        server.stop()
