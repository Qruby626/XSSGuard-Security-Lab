"""Minimal Raw WSGI demonstration for XSSGuard.

Demonstrates:
1. Creating a pure WSGI application (framework-agnostic, zero Flask dependency).
2. Wrapping the WSGI application with XSSGuardMiddleware.
3. Using MemoryStore for detection storage.
4. Automatic XSS detection on request body and request body replay.
5. Explicit Trusted-Script Nonce integration via environ["xssguard.nonce"].
6. CSP header generation with matching request-scoped nonce (without automatic HTML injection).
"""

import html
import io
import re
import sys
from pathlib import Path
from typing import Callable, Iterable, List, Tuple
from urllib.parse import parse_qs

# Ensure repo root is in sys.path when run directly
repo_root = str(Path(__file__).resolve().parent.parent)
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from xssguard.middleware import XSSGuardMiddleware
from xssguard.storage import MemoryStore


def simple_app(environ: dict, start_response: Callable) -> Iterable[bytes]:
    """A simple raw WSGI application that reads input and returns HTML."""
    # Read request body if present
    content_length = int(environ.get("CONTENT_LENGTH", "0") or "0")
    body_data = b""
    if content_length > 0 and "wsgi.input" in environ:
        body_data = environ["wsgi.input"].read(content_length)

    parsed = parse_qs(body_data.decode("utf-8", errors="replace"))
    raw_message = parsed.get("message", ["Hello from Raw WSGI"])[0]
    safe_message = html.escape(raw_message)

    # Explicitly consume request-scoped nonce provided by XSSGuardMiddleware
    nonce = environ.get("xssguard.nonce", "")

    html_content = f"""<!DOCTYPE html>
<html>
<head><title>Raw WSGI Demo</title></head>
<body>
    <h1>Raw WSGI Application</h1>
    <p>Received message: {safe_message}</p>
    <script nonce="{nonce}">console.log("Application script executed");</script>
</body>
</html>"""

    response_body = html_content.encode("utf-8")
    headers = [
        ("Content-Type", "text/html; charset=utf-8"),
        ("Content-Length", str(len(response_body))),
    ]
    start_response("200 OK", headers)
    return [response_body]


def run_demo() -> None:
    """Execute a demonstration of XSSGuardMiddleware with raw WSGI."""
    print("=== XSSGuard Raw WSGI Demo ===")

    # 1. Initialize MemoryStore
    store = MemoryStore()

    # 2. Wrap WSGI application with XSSGuardMiddleware
    app = XSSGuardMiddleware(simple_app, store=store)

    # Helper to invoke WSGI application directly without external server
    def invoke_wsgi(
        method: str, path: str, body: bytes = b"", content_type: str = ""
    ) -> Tuple[str, List[Tuple[str, str]], bytes]:
        response_status = ""
        response_headers: List[Tuple[str, str]] = []

        def start_response(status, headers, exc_info=None):
            nonlocal response_status, response_headers
            response_status = status
            response_headers = headers
            return lambda x: None

        environ = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "SERVER_NAME": "localhost",
            "SERVER_PORT": "8000",
            "wsgi.version": (1, 0),
            "wsgi.url_scheme": "http",
            "wsgi.input": io.BytesIO(body),
            "CONTENT_LENGTH": str(len(body)),
            "CONTENT_TYPE": content_type,
            "REMOTE_ADDR": "127.0.0.1",
        }

        chunks = app(environ, start_response)
        content = b"".join(chunks)
        return response_status, response_headers, content

    # Step 1: Normal GET request
    print("\n1. Invoking WSGI application with normal GET request...")
    status1, headers1, content1 = invoke_wsgi("GET", "/")
    header_map1 = {k.lower(): v for k, v in headers1}
    csp1 = header_map1.get("content-security-policy", "")
    print(f"   Status: {status1}")
    print(f"   CSP Header: {csp1}")
    content_str1 = content1.decode("utf-8", errors="replace")

    csp_nonce_match1 = re.search(r"'nonce-([^']+)'", csp1)
    csp_nonce1 = csp_nonce_match1.group(1) if csp_nonce_match1 else ""
    script_nonce_match1 = re.search(r'<script nonce="([^"]+)">', content_str1)
    script_nonce1 = script_nonce_match1.group(1) if script_nonce_match1 else ""

    for line in content_str1.splitlines():
        if "<script" in line:
            print(f"   Script tag with explicit nonce: {line.strip()}")
    print(f"   Nonce matches CSP header: {bool(csp_nonce1 and csp_nonce1 == script_nonce1)}")

    # Step 2: POST request with XSS payload
    print("\n2. Invoking WSGI application with POST containing XSS payload...")
    xss_payload = b"message=<script>alert('RawWSGI-XSS')</script>"
    status2, headers2, content2 = invoke_wsgi(
        "POST",
        "/submit",
        body=xss_payload,
        content_type="application/x-www-form-urlencoded",
    )
    print(f"   Status: {status2}")
    header_map2 = {k.lower(): v for k, v in headers2}
    csp2 = header_map2.get("content-security-policy", "")
    csp_nonce_match2 = re.search(r"'nonce-([^']+)'", csp2)
    csp_nonce2 = csp_nonce_match2.group(1) if csp_nonce_match2 else ""

    detections = store.recent_detections()
    print(f"   Logged Detections Count: {len(detections)}")
    if detections:
        rec = detections[0]
        print(
            f"   Latest Detection Record: payload='{rec.payload}', "
            f"source='{rec.source}', rule='{rec.matched_rule}'"
        )

    content_str2 = content2.decode("utf-8", errors="replace")
    user_payload_has_nonce = f'<script nonce="{csp_nonce2}">alert' in content_str2
    print(f"   User XSS payload given nonce: {user_payload_has_nonce} (Expected False)")
    print(f"   Request isolation (Nonce 1 != Nonce 2): {bool(csp_nonce1 and csp_nonce2 and csp_nonce1 != csp_nonce2)}")

    print("\n=== Raw WSGI Demo completed successfully ===")


if __name__ == "__main__":
    run_demo()
