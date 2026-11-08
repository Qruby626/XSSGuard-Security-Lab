"""Minimal Flask demonstration for XSSGuard.

Demonstrates:
1. Creating a Flask application.
2. Initializing MemoryStore.
3. Attaching XSSGuard and registering the CSP report endpoint.
4. Processing inputs with automatic XSS detection.
5. Trusted-Script Nonce integration with explicit nonce="{{ xssguard_nonce }}" in Jinja template.
6. Receiving and logging browser CSP violation reports.
"""

import sys
from pathlib import Path

# Ensure repo root is in sys.path when run directly
repo_root = str(Path(__file__).resolve().parent.parent)
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from flask import Flask, Response, render_template_string, request
from xssguard.flask_ext import XSSGuard, register_csp_report_route
from xssguard.storage import MemoryStore
from xssguard.dashboard import create_dashboard_blueprint


def create_app() -> tuple[Flask, MemoryStore]:
    """Create and configure the Flask application with XSSGuard."""
    app = Flask(__name__)

    # 1. Create storage backend
    store = MemoryStore()

    # 2. Attach XSSGuard Flask extension
    # This wraps app.wsgi_app with XSSGuardMiddleware and automatically
    # registers the default CSP report endpoint at /csp-report
    guard = XSSGuard(app=app, store=store)

    # 3. Register XSSGuard Security Dashboard blueprint (read-only presentation layer)
    dashboard_bp = create_dashboard_blueprint(store)
    app.register_blueprint(dashboard_bp, url_prefix="/xssguard")

    # 4. Simple application endpoint receiving input and returning HTML with script
    @app.route("/", methods=["GET", "POST"])
    def index():
        user_input = request.form.get("comment", "Welcome to XSSGuard Demo")
        # HTML template containing a trusted script tag with explicit xssguard_nonce
        template = """<!DOCTYPE html>
<html>
<head><title>XSSGuard Flask Demo</title></head>
<body>
    <h1>XSSGuard Flask Demo</h1>
    <p>Input received: {{ user_input }}</p>
    <script nonce="{{ xssguard_nonce }}">console.log("Legitimate application script");</script>
</body>
</html>"""
        return render_template_string(template, user_input=user_input)

    return app, store


def run_demo() -> None:
    """Execute a non-blocking demonstration using Flask test client."""
    app, store = create_app()
    client = app.test_client()

    print("=== XSSGuard Flask Demo ===")

    # Step 1: Send normal GET request
    print("\n1. Sending safe GET request...")
    resp = client.get("/")
    csp_header = resp.headers.get("Content-Security-Policy", "")
    print(f"   Status: {resp.status_code}")
    print(f"   CSP Header: {csp_header}")
    body = resp.get_data(as_text=True)
    for line in body.splitlines():
        if "<script" in line:
            print(f"   Script tag: {line.strip()}")

    # Step 2: Send POST request with XSS payload
    print("\n2. Sending POST request with XSS payload...")
    xss_payload = "<script>alert('XSS')</script>"
    resp = client.post("/", data={"comment": xss_payload})
    print(f"   Status: {resp.status_code}")
    detections = store.recent_detections()
    print(f"   Logged Detections Count: {len(detections)}")
    if detections:
        print(f"   Latest Detection: {detections[0].payload} (rule: {detections[0].matched_rule})")

    # Step 3: Send CSP violation report
    print("\n3. Sending CSP violation report to /csp-report...")
    report_payload = (
        b'{"csp-report":{"document-uri":"http://localhost/",'
        b'"violated-directive":"script-src","blocked-uri":"http://evil.com/xss.js"}}'
    )
    resp = client.post(
        "/csp-report",
        data=report_payload,
        content_type="application/csp-report",
    )
    print(f"   Status: {resp.status_code} (Expected 204 No Content)")
    reports = store.recent_csp_reports()
    print(f"   Logged CSP Reports Count: {len(reports)}")
    if reports:
        print(
            f"   Latest CSP Report: blocked={reports[0].blocked_uri}, "
            f"directive={reports[0].violated_directive}"
        )

    print("\n=== Demo completed successfully ===")


if __name__ == "__main__":
    import sys

    if "--server" in sys.argv:
        app, _ = create_app()
        print("Running Flask development server on http://127.0.0.1:5000 ...")
        app.run(host="127.0.0.1", port=5000, debug=True)
    else:
        run_demo()
