"""Phase D4 — Browser E2E Stored XSS Blocking Test Fixture.

This fixture serves as an external test host environment specifically designed
to prove that Stored XSS payloads rendered back into HTML as inline <script> tags
without a nonce are blocked by XSSGuard's Content Security Policy (CSP) in real browsers.

Architecture & Trust Boundary:
- XSSGuard generates dynamic CSP nonces per request and sets the CSP header.
- The host application (this fixture) simulates a vulnerable application storing and
  re-rendering user input into HTML without sanitization/escaping.
- The host application does NOT attach a nonce to the attacker's stored payload.
- XSSGuard does NOT perform automatic nonce injection or HTML rewriting.
- Consequently, the re-rendered attacker script remains nonceless and is blocked by CSP.

Endpoints:
- POST /store: Accepts 'payload' form field, stores in memory, and redirects to /stored.
- GET /store: Displays a minimal form to submit payloads for manual browser testing.
- GET /stored: Re-renders stored payload(s) as raw HTML/script without nonce.

Running independently:
    python tests/e2e/d4_stored_xss_fixture.py
Server will listen on http://127.0.0.1:5002
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

# Ensure repository root is in sys.path when executed directly
repo_root = str(Path(__file__).resolve().parent.parent.parent)
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from flask import Flask, Response, redirect, request
from xssguard.flask_ext import XSSGuard
from xssguard.storage import BaseStore, MemoryStore


class StoredPayloadStore:
    """Minimal in-memory store for holding stored XSS payloads in the fixture."""

    def __init__(self) -> None:
        self._payloads: list[str] = []

    def add(self, payload: str) -> None:
        self._payloads.append(payload)

    def get_all(self) -> list[str]:
        return list(self._payloads)

    def clear(self) -> None:
        self._payloads.clear()


STORE_FORM_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>D4 Stored XSS Fixture - Submit</title>
</head>
<body>
    <h1>D4 Stored XSS: Submit Payload</h1>
    <form method="POST" action="/store">
        <label for="payload">Payload:</label><br>
        <textarea id="payload" name="payload" rows="6" cols="60">&lt;script&gt;
    console.log("D4_STORED_XSS_EXECUTED");
&lt;/script&gt;</textarea><br><br>
        <button type="submit">Store Payload</button>
    </form>
</body>
</html>"""


STORED_PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>D4 Stored XSS Fixture - Stored View</title>
</head>
<body>
    <h1>D4 Stored XSS Fixture: Stored View</h1>
    <p>Testing CSP enforcement against stored attacker script rendered without nonce.</p>
    <div id="stored-content">
{content}
    </div>
</body>
</html>"""


def create_test_app(
    store: Optional[BaseStore] = None,
    payload_store: Optional[StoredPayloadStore] = None,
) -> Flask:
    """Create and configure the minimal Flask application wrapped with XSSGuard."""
    app = Flask(__name__)

    # Storage backend for XSSGuard (defaults to MemoryStore)
    fixture_guard_store = store if store is not None else MemoryStore()

    # In-memory store for the host application's stored payloads
    app_payload_store = payload_store if payload_store is not None else StoredPayloadStore()

    # Attach XSSGuard extension
    guard = XSSGuard(app=app, store=fixture_guard_store)
    app.extensions["xssguard"] = guard
    app.store = fixture_guard_store
    app.payload_store = app_payload_store

    @app.route("/store", methods=["GET", "POST"])
    def store_payload() -> Response:
        """Endpoint to receive and store user payload, or display submit form."""
        if request.method == "POST":
            payload = request.form.get("payload", "")
            if not payload.strip():
                return Response("Payload is empty", status=400, mimetype="text/plain")
            app_payload_store.add(payload)
            return redirect("/stored", code=302)
        return Response(STORE_FORM_HTML, mimetype="text/html")

    @app.route("/stored", methods=["GET"])
    def view_stored() -> Response:
        """Endpoint rendering stored payload(s) as raw HTML without nonce."""
        payloads = app_payload_store.get_all()
        rendered_content = "\n".join(payloads) if payloads else "<p>No payload stored</p>"
        html = STORED_PAGE_TEMPLATE.format(content=rendered_content)
        return Response(html, mimetype="text/html")

    return app


if __name__ == "__main__":
    app = create_test_app()
    print("Starting D4 Stored XSS Fixture server on http://127.0.0.1:5002 ...")
    app.run(host="127.0.0.1", port=5002, debug=False)
