#!/usr/bin/env python3
"""
CRLF Injection Vulnerable Test Server
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
A deliberately vulnerable HTTP server for testing the CRLF scanner.
Provides multiple endpoints with varying levels of CRLF vulnerability.

Usage:
    python test_server.py [--port 8000]

Endpoints:
    /                       → Safe homepage (not vulnerable)
    /redirect?url=...       → CRLF-vulnerable redirect (Location header)
    /setcookie?name=...     → CRLF-vulnerable Set-Cookie (reflects input)
    /echo?header=...        → CRLF-vulnerable custom header reflection
    /safe/redirect?url=...  → Safe redirect (sanitized)
    /safe/cookie?name=...   → Safe cookie (sanitized)

⚠️  DO NOT expose this server to the internet!
"""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote


class VulnerableHandler(BaseHTTPRequestHandler):
    """HTTP handler with intentionally vulnerable CRLF endpoints."""

    def log_message(self, format, *args):
        """Custom log format."""
        print(f"  [REQUEST] {self.address_string()} -> {args[0]}")

    def do_GET(self):
        decoded_path = unquote(self.path)
        parsed = urlparse(decoded_path)
        path = parsed.path
        params = parse_qs(parsed.query, keep_blank_values=True)

        # ── Route: Homepage (safe) ──
        if path == "/" or path == "":
            self._serve_homepage()

        # ── Route: Vulnerable redirect ──
        elif path == "/redirect":
            self._handle_vuln_redirect(params, decoded_path)

        # ── Route: Vulnerable Set-Cookie ──
        elif path == "/setcookie":
            self._handle_vuln_cookie(params, decoded_path)

        # ── Route: Vulnerable header echo ──
        elif path == "/echo":
            self._handle_vuln_echo(params, decoded_path)

        # ── Route: Safe redirect (sanitized) ──
        elif path == "/safe/redirect":
            self._handle_safe_redirect(params)

        # ── Route: Safe cookie (sanitized) ──
        elif path == "/safe/cookie":
            self._handle_safe_cookie(params)

        # ── Route: Path-based CRLF (vulnerable) ──
        elif path.startswith("/vuln/"):
            self._handle_vuln_path(decoded_path)

        # ── Route: Catch-all for path injection testing ──
        else:
            self._handle_catchall(decoded_path)

    def _serve_homepage(self):
        """Safe homepage — no CRLF vulnerability."""
        body = """<!DOCTYPE html>
<html>
<head><title>CRLF Test Server</title></head>
<body style="font-family: monospace; background: #1a1a2e; color: #e0e0e0; padding: 40px;">
<h1 style="color: #00d4ff;">🔬 CRLF Injection Test Server</h1>
<p>This server has intentionally vulnerable endpoints for testing.</p>
<h2>Vulnerable Endpoints:</h2>
<ul>
    <li><code>/redirect?url=&lt;value&gt;</code> — Reflects value in Location header</li>
    <li><code>/setcookie?name=&lt;value&gt;</code> — Reflects value in Set-Cookie</li>
    <li><code>/echo?header=&lt;value&gt;</code> — Reflects value as custom header</li>
    <li><code>/vuln/&lt;path&gt;</code> — Path-based CRLF injection</li>
</ul>
<h2>Safe Endpoints (sanitized):</h2>
<ul>
    <li><code>/safe/redirect?url=&lt;value&gt;</code></li>
    <li><code>/safe/cookie?name=&lt;value&gt;</code></li>
</ul>
<p style="color: #ff6b6b;">⚠️ DO NOT expose this server to the internet!</p>
</body>
</html>"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body.encode())))
        self.send_header("X-Server", "CRLF-TestServer/1.0")
        self.end_headers()
        self.wfile.write(body.encode())

    def _handle_vuln_redirect(self, params, decoded_path):
        """
        VULNERABLE: Reflects user input directly in Location header.
        The value from ?url= is inserted raw into the Location header,
        allowing CRLF injection to add arbitrary headers.
        """
        redirect_url = params.get("url", ["http://example.com"])[0]
        body = f"Redirecting to {redirect_url}".encode()

        # Write raw response to allow CRLF injection in the Location header
        raw_response = (
            f"HTTP/1.1 302 Found\r\n"
            f"Content-Type: text/plain\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"X-Server: CRLF-TestServer/1.0\r\n"
            f"Connection: close\r\n"
            f"Location: {redirect_url}\r\n"
            f"\r\n"
        )
        self.wfile.write(raw_response.encode("utf-8", errors="replace"))
        self.wfile.write(body)

    def _handle_vuln_cookie(self, params, decoded_path):
        """
        VULNERABLE: Reflects user input directly in Set-Cookie header.
        """
        cookie_name = params.get("name", ["session"])[0]
        cookie_value = params.get("value", ["abc123"])[0]
        body = f"Cookie set: {cookie_name}={cookie_value}".encode()

        raw_response = (
            f"HTTP/1.1 200 OK\r\n"
            f"Content-Type: text/plain\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"X-Server: CRLF-TestServer/1.0\r\n"
            f"Connection: close\r\n"
            f"Set-Cookie: {cookie_name}={cookie_value}\r\n"
            f"\r\n"
        )
        self.wfile.write(raw_response.encode("utf-8", errors="replace"))
        self.wfile.write(body)

    def _handle_vuln_echo(self, params, decoded_path):
        """
        VULNERABLE: Reflects user input as a custom response header.
        """
        header_value = params.get("header", ["safe_value"])[0]
        body = f"Header echoed: {header_value}".encode()

        raw_response = (
            f"HTTP/1.1 200 OK\r\n"
            f"Content-Type: text/plain\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"X-Server: CRLF-TestServer/1.0\r\n"
            f"Connection: close\r\n"
            f"X-Custom-Header: {header_value}\r\n"
            f"\r\n"
        )
        self.wfile.write(raw_response.encode("utf-8", errors="replace"))
        self.wfile.write(body)

    def _handle_vuln_path(self, decoded_path):
        """
        VULNERABLE: Path-based CRLF injection.
        Reflects the URL path in a response header, allowing injection.
        """
        # Extract everything after /vuln/
        injected = decoded_path.split("/vuln/", 1)[1] if "/vuln/" in decoded_path else ""
        body = f"Path received: {injected}".encode()

        raw_response = (
            f"HTTP/1.1 200 OK\r\n"
            f"Content-Type: text/plain\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"X-Server: CRLF-TestServer/1.0\r\n"
            f"Connection: close\r\n"
            f"X-Debug-Path: {injected}\r\n"
            f"\r\n"
        )
        self.wfile.write(raw_response.encode("utf-8", errors="replace"))
        self.wfile.write(body)

    def _handle_catchall(self, decoded_path):
        """
        SAFE catch-all for unrecognized paths.

        It reflects the requested path back into a response header, but strips
        CR/LF first, so unknown paths are NOT injectable. The deliberately
        vulnerable path case is covered exclusively by ``/vuln/<path>``; keeping
        the catch-all safe means the documented "safe" endpoints stay clean even
        when a path-injection payload reroutes them here.
        """
        safe_path = decoded_path.replace("\r", "").replace("\n", "")
        body = f"Path: {safe_path}".encode()

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Server", "CRLF-TestServer/1.0")
        self.send_header("X-Reflected-Path", safe_path)
        self.end_headers()
        self.wfile.write(body)

    def _handle_safe_redirect(self, params):
        """SAFE: Sanitized redirect — strips CR/LF from input."""
        redirect_url = params.get("url", ["http://example.com"])[0]
        # Sanitize: remove any CR or LF characters
        safe_url = redirect_url.replace("\r", "").replace("\n", "")
        body = f"Redirecting safely to {safe_url}".encode()

        self.send_response(302)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Location", safe_url)
        self.end_headers()
        self.wfile.write(body)

    def _handle_safe_cookie(self, params):
        """SAFE: Sanitized cookie — strips CR/LF from input."""
        cookie_name = params.get("name", ["session"])[0]
        cookie_value = params.get("value", ["abc123"])[0]
        # Sanitize
        safe_name = cookie_name.replace("\r", "").replace("\n", "")
        safe_value = cookie_value.replace("\r", "").replace("\n", "")
        body = f"Safe cookie set: {safe_name}={safe_value}".encode()

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Set-Cookie", f"{safe_name}={safe_value}")
        self.end_headers()
        self.wfile.write(body)


def main():
    parser = argparse.ArgumentParser(description="CRLF Injection Test Server")
    parser.add_argument("--port", "-p", type=int, default=8000, help="Port to listen on (default: 8000)")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to (default: 127.0.0.1)")
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), VulnerableHandler)
    print(f"""
  +-------------------------------------------------------+
  |  CRLF Injection Test Server                            |
  |  -------------------------------------------------    |
  |  Listening on: http://{args.host}:{args.port:<5}                  |
  |                                                        |
  |  Vulnerable endpoints:                                 |
  |    /redirect?url=...    /setcookie?name=...            |
  |    /echo?header=...     /vuln/<path>                   |
  |                                                        |
  |  Safe endpoints:                                       |
  |    /safe/redirect?url=...   /safe/cookie?name=...      |
  |                                                        |
  |  WARNING: DO NOT expose to the internet!               |
  +-------------------------------------------------------+
    """)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  [*] Server shutting down...")
        server.server_close()


if __name__ == "__main__":
    main()
