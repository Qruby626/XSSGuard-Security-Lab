"""Automated regression tests for xssguard.flask_ext module.

Validates:
1. XSSGuard initialization:
   - XSSGuard(app) with defaults
   - guard = XSSGuard(); guard.init_app(app) with custom patterns and store
   - Idempotent init_app (double-wrap prevention)
   - app.extensions registration
   - Custom path and root path for register_csp_report_route
2. Flask request + XSS detection:
   - XSS detection in query string, form POST, and JSON body
   - Detection record formatting: status="DETECTED", payload, matched_rule, source, client_ip
   - Safe input produces zero detections
   - Absence of IP blocking: repeated attacks succeed with normal HTTP status
3. CSP header and Trusted-Script Nonce via Flask:
   - Content-Security-Policy header generated with script-src and nonce
   - Dynamic nonce matches template context variable xssguard_nonce
   - Pre-existing nonce preservation and absence of automatic HTML nonce injection
   - Multiple script tags in a single response
   - Non-HTML responses maintain body unmodified
   - Nonce uniqueness across sequential requests
   - User-controlled content receives no nonce
4. CSP report endpoint:
   - Valid direct CSP report -> HTTP 204 and stored in BaseStore
   - Valid underscore keys and empty report handling
5. Invalid CSP report:
   - Malformed JSON -> HTTP 204 and NOT stored (never returns 400)
   - Empty body -> HTTP 204 and NOT stored
   - Non-dict JSON -> HTTP 204 and NOT stored
6. Wrapped CSP report:
   - {"csp-report": {...}} format -> HTTP 204 and stored correctly
7. Record type separation:
   - CSP reports strictly create CspReportRecord (zero DetectionRecord)
   - XSS detections strictly create DetectionRecord (zero CspReportRecord)
   - Strict type isolation in store
8. Architectural isolation and public API:
   - __all__ and public symbols strictly ["XSSGuard", "register_csp_report_route"]
   - No forbidden framework or internal cross-imports
"""

import ast
import inspect
import json
import re
from typing import Any

import pytest
from flask import Flask, Response, render_template_string, request

import xssguard.flask_ext as flask_ext_module
from xssguard.flask_ext import XSSGuard, register_csp_report_route
from xssguard.middleware import XSSGuardMiddleware
from xssguard.patterns import DEFAULT_XSS_PATTERNS
from xssguard.storage import BaseStore, CspReportRecord, DetectionRecord, MemoryStore


# ---------------------------------------------------------------------------
# Helpers & App Factories
# ---------------------------------------------------------------------------

def create_test_app(
    *,
    guard_first: bool = False,
    custom_patterns: Any = None,
    custom_store: Any = None,
) -> tuple[Flask, XSSGuard, BaseStore]:
    """Create a configured Flask application for testing."""
    app = Flask(__name__)
    store = custom_store if custom_store is not None else MemoryStore()

    if guard_first:
        guard = XSSGuard(app, patterns=custom_patterns, store=store)
    else:
        guard = XSSGuard(patterns=custom_patterns, store=store)
        guard.init_app(app)

    @app.route("/search", methods=["GET"])
    def search() -> Response:
        q = request.args.get("q", "")
        return Response(f"Search results for: {q}", mimetype="text/plain")

    @app.route("/submit", methods=["POST"])
    def submit() -> Response:
        comment = request.form.get("comment", "")
        return Response(f"Received comment: {comment}", mimetype="text/plain")

    @app.route("/api/feedback", methods=["POST"])
    def feedback() -> Response:
        data = request.get_json(silent=True) or {}
        bio = data.get("bio", "")
        return Response(json.dumps({"bio": bio}), mimetype="application/json")

    @app.route("/page", methods=["GET"])
    def page() -> Response:
        html = (
            "<!DOCTYPE html><html><head><title>Test</title></head>"
            "<body><h1>Hello World</h1></body></html>"
        )
        return Response(html, mimetype="text/html")

    @app.route("/script-page", methods=["GET"])
    def script_page() -> Response:
        html = (
            "<!DOCTYPE html><html><head>"
            '<script src="/app.js"></script>'
            "<script>console.log('inline');</script>"
            "</head><body></body></html>"
        )
        return Response(html, mimetype="text/html")

    @app.route("/existing-nonce-page", methods=["GET"])
    def existing_nonce_page() -> Response:
        html = (
            '<!DOCTYPE html><html><head>'
            '<script nonce="custom-static-nonce">console.log("untouched");</script>'
            '<script>console.log("needs-nonce");</script>'
            '</head><body></body></html>'
        )
        return Response(html, mimetype="text/html")

    @app.route("/template-nonce-page", methods=["GET"])
    def template_nonce_page() -> Response:
        html = (
            "<!DOCTYPE html><html><head>"
            '<script nonce="{{ xssguard_nonce }}">console.log("trusted");</script>'
            "</head><body></body></html>"
        )
        return Response(render_template_string(html), mimetype="text/html")

    return app, guard, store


# ---------------------------------------------------------------------------
# Test Suite 1: XSSGuard Initialization
# ---------------------------------------------------------------------------

class TestXSSGuardInitialization:
    """Validate XSSGuard instantiation, init_app, and route registration."""

    def test_init_with_app_default(self) -> None:
        """XSSGuard(app) with defaults attaches middleware, store, and report route."""
        app = Flask(__name__)
        guard = XSSGuard(app)

        assert isinstance(guard.store, MemoryStore)
        assert guard.patterns is None
        assert getattr(app, "_xssguard_initialized", False) is True
        assert app.extensions.get("xssguard") is guard

        # Middleware wraps wsgi_app
        assert isinstance(app.wsgi_app, XSSGuardMiddleware)
        assert app.wsgi_app.store is guard.store
        assert app.wsgi_app.patterns == DEFAULT_XSS_PATTERNS

        # Route /csp-report is registered
        routes = [r.rule for r in app.url_map.iter_rules()]
        assert "/csp-report" in routes

    def test_init_app_deferred(self) -> None:
        """guard = XSSGuard(); guard.init_app(app) binds custom store and patterns."""
        app = Flask(__name__)
        custom_store = MemoryStore()
        custom_patterns = [r"(?i)<\s*script\b"]

        guard = XSSGuard(patterns=custom_patterns, store=custom_store)
        assert guard.store is custom_store
        assert guard.patterns == custom_patterns

        guard.init_app(app)

        assert getattr(app, "_xssguard_initialized", False) is True
        assert app.extensions.get("xssguard") is guard
        assert isinstance(app.wsgi_app, XSSGuardMiddleware)
        assert app.wsgi_app.store is custom_store
        assert app.wsgi_app.patterns == custom_patterns

    def test_init_app_idempotent(self) -> None:
        """Calling init_app multiple times does not re-wrap wsgi_app."""
        app = Flask(__name__)
        guard = XSSGuard(app)
        original_wsgi_app = app.wsgi_app

        # Second call on same app
        guard.init_app(app)
        assert app.wsgi_app is original_wsgi_app

        # Another guard instance on already initialized app
        guard2 = XSSGuard(app)
        assert app.wsgi_app is original_wsgi_app

    def test_init_app_without_extensions_dict(self) -> None:
        """init_app safely handles an app object lacking extensions dict."""
        app = Flask(__name__)
        # Temporarily delete extensions attribute if present
        if hasattr(app, "extensions"):
            delattr(app, "extensions")

        guard = XSSGuard(app)
        assert isinstance(app.wsgi_app, XSSGuardMiddleware)
        assert getattr(app, "_xssguard_initialized", False) is True

    def test_register_csp_report_route_custom_path(self) -> None:
        """register_csp_report_route can register an endpoint at a custom path."""
        app = Flask(__name__)
        store = MemoryStore()
        register_csp_report_route(app, store, path="/custom/reports")

        rules = {r.rule: r.endpoint for r in app.url_map.iter_rules()}
        assert "/custom/reports" in rules
        assert rules["/custom/reports"] == "csp_report_custom_reports"

    def test_register_csp_report_route_root_path(self) -> None:
        """register_csp_report_route handles root path '/' cleanly."""
        app = Flask(__name__)
        store = MemoryStore()
        register_csp_report_route(app, store, path="/")

        rules = {r.rule: r.endpoint for r in app.url_map.iter_rules()}
        assert "/" in rules
        assert rules["/"] == "csp_report_root"

    # ------------------------------------------------------------------
    # CSP Report Path Single Source of Truth — Regression Tests
    # ------------------------------------------------------------------

    def test_csp_report_path_default_value(self) -> None:
        """XSSGuard defaults csp_report_path to '/csp-report' (single source)."""
        guard = XSSGuard()
        assert guard.csp_report_path == "/csp-report"

    def test_csp_report_path_init_custom_value_stored(self) -> None:
        """Custom csp_report_path parameter is stored as self.csp_report_path."""
        guard = XSSGuard(csp_report_path="/security/csp-report")
        assert guard.csp_report_path == "/security/csp-report"

    def test_csp_report_path_deferred_init_app_uses_same_value(self) -> None:
        """Deferred init_app() registers CSP route at the configured custom path."""
        app = Flask(__name__)
        guard = XSSGuard(csp_report_path="/internal/csp-events")
        guard.init_app(app)

        rules = {r.rule: r.endpoint for r in app.url_map.iter_rules()}
        assert "/internal/csp-events" in rules
        assert "/csp-report" not in rules

    def test_csp_report_path_inline_init_uses_same_value(self) -> None:
        """XSSGuard(app, csp_report_path=...) registers route at the custom path."""
        app = Flask(__name__)
        XSSGuard(app, csp_report_path="/app/csp-report")

        rules = {r.rule: r.endpoint for r in app.url_map.iter_rules()}
        assert "/app/csp-report" in rules

    def test_csp_report_path_synced_with_blocking_exclude(self) -> None:
        """Custom CSP report path is EXPLICITLY added to middleware blocking_exclude_paths
        (single source of truth, no desync between route path and exclusion path)."""
        custom = "/reports/csp-violations"
        app = Flask(__name__)
        guard = XSSGuard(app, blocking_enabled=True, csp_report_path=custom)

        mw = app.wsgi_app
        assert isinstance(mw, XSSGuardMiddleware)
        assert custom in mw.blocking_exclude_paths, (
            f"Custom CSP report path {custom!r} must be in middleware "
            "blocking_exclude_paths; otherwise CSP reports may get HTTP 403."
        )
        assert "/csp-report" not in mw.blocking_exclude_paths, (
            "Default '/csp-report' must NOT appear in exclusion set when "
            "csp_report_path is customised; single source = self.csp_report_path."
        )

    def test_default_csp_report_path_still_excluded(self) -> None:
        """Regression: DEFAULT '/csp-report' path still appears in exclusion
        when no custom csp_report_path is supplied (backward compat)."""
        app = Flask(__name__)
        XSSGuard(app, blocking_enabled=True)

        mw = app.wsgi_app
        assert isinstance(mw, XSSGuardMiddleware)
        assert "/csp-report" in mw.blocking_exclude_paths


# ---------------------------------------------------------------------------
# Test Suite 2: Flask Request + XSS Detection
# ---------------------------------------------------------------------------

class TestFlaskXSSDetection:
    """Validate XSS detection on Flask requests via query, form, and JSON."""

    def test_detect_xss_query_param(self) -> None:
        """XSS payload in GET query string is detected and logged."""
        app, _, store = create_test_app()
        client = app.test_client()

        resp = client.get("/search?q=%3Cscript%3Ealert('xss')%3C/script%3E")
        assert resp.status_code == 200
        assert b"Search results" in resp.data

        detections = store.recent_detections()
        assert len(detections) == 1

        rec = detections[0]
        assert isinstance(rec, DetectionRecord)
        assert rec.status == "DETECTED"
        assert rec.payload == "q=<script>alert('xss')</script>"
        assert rec.matched_rule == r"(?i)<\s*/?\s*script\b"
        assert rec.source == "/search"
        assert rec.client_ip is not None

    def test_detect_xss_form_post(self) -> None:
        """XSS payload in POST form body is detected and logged."""
        app, _, store = create_test_app()
        client = app.test_client()

        payload = "<img src=x onerror=alert(1)>"
        resp = client.post("/submit", data={"comment": payload})
        assert resp.status_code == 200

        detections = store.recent_detections()
        assert len(detections) == 1

        rec = detections[0]
        assert rec.status == "DETECTED"
        assert rec.payload == f"comment={payload}"
        assert rec.matched_rule == r"(?i)\bon[a-z][a-z0-9_-]*\s*="
        assert rec.source == "/submit"

    def test_detect_xss_json_body(self) -> None:
        """XSS payload in JSON request body is detected and logged."""
        app, _, store = create_test_app()
        client = app.test_client()

        payload = "javascript:alert(1)"
        resp = client.post(
            "/api/feedback",
            data=json.dumps({"bio": payload}),
            content_type="application/json",
        )
        assert resp.status_code == 200

        detections = store.recent_detections()
        assert len(detections) == 1

        rec = detections[0]
        assert rec.status == "DETECTED"
        assert rec.payload == f"bio={payload}"
        assert rec.matched_rule == r"(?i)\b(?:java|vb)script\s*:"
        assert rec.source == "/api/feedback"

    def test_safe_request_produces_zero_detections(self) -> None:
        """Safe requests in GET, form POST, and JSON produce zero detections."""
        app, _, store = create_test_app()
        client = app.test_client()

        resp1 = client.get("/search?q=normal+search+term")
        assert resp1.status_code == 200

        resp2 = client.post("/submit", data={"comment": "Hello, clean world!"})
        assert resp2.status_code == 200

        resp3 = client.post(
            "/api/feedback",
            data=json.dumps({"bio": "Software developer at tech firm"}),
            content_type="application/json",
        )
        assert resp3.status_code == 200

        assert len(store.recent_detections()) == 0

    def test_no_ip_blocking_on_multiple_attacks(self) -> None:
        """Repeated attacks from the same IP are logged but never blocked."""
        app, _, store = create_test_app()
        client = app.test_client()

        attack_count = 8
        for i in range(attack_count):
            resp = client.get(
                f"/search?q=%3Cscript%3Ealert({i})%3C/script%3E",
                environ_overrides={"REMOTE_ADDR": "198.51.100.42"},
            )
            assert resp.status_code == 200
            assert b"Search results" in resp.data

        detections = store.recent_detections()
        assert len(detections) == attack_count
        for rec in detections:
            assert rec.status == "DETECTED"
            assert rec.client_ip == "198.51.100.42"

    def test_custom_patterns_respected_by_flask(self) -> None:
        """Custom regex patterns override default patterns in Flask application."""
        custom_rule = r"(?i)\bcustom_evil_token\b"
        app, _, store = create_test_app(custom_patterns=[custom_rule])
        client = app.test_client()

        # Standard pattern should not match when overridden
        resp1 = client.get("/search?q=%3Cscript%3Ealert(1)%3C/script%3E")
        assert resp1.status_code == 200
        assert len(store.recent_detections()) == 0

        # Custom pattern matches
        resp2 = client.get("/search?q=custom_evil_token")
        assert resp2.status_code == 200
        detections = store.recent_detections()
        assert len(detections) == 1
        assert detections[0].matched_rule == custom_rule


# ---------------------------------------------------------------------------
# Test Suite 3: CSP Header via Flask
# ---------------------------------------------------------------------------

class TestFlaskCSPHeaderAndNonce:
    """Validate dynamic CSP header and Trusted-Script Nonce integration on Flask responses."""

    def test_csp_header_present_in_html_response(self) -> None:
        """HTML responses receive Content-Security-Policy header with nonce."""
        app, _, _ = create_test_app()
        client = app.test_client()

        resp = client.get("/page")
        assert resp.status_code == 200

        csp = resp.headers.get("Content-Security-Policy")
        assert csp is not None
        assert "default-src 'self'" in csp
        assert "script-src 'self' 'nonce-" in csp
        assert "object-src 'none'" in csp

    def test_nonce_in_csp_header_matches_script_tag(self) -> None:
        """Nonce in CSP header exactly matches the nonce exposed to Jinja template."""
        app, _, _ = create_test_app()
        client = app.test_client()

        resp = client.get("/template-nonce-page")
        assert resp.status_code == 200

        csp = resp.headers.get("Content-Security-Policy", "")
        m_header = re.search(r"'nonce-([A-Za-z0-9+/=_-]+)'", csp)
        assert m_header is not None, f"Nonce missing in CSP header: {csp}"
        header_nonce = m_header.group(1)

        body = resp.get_data(as_text=True)
        script_nonces = re.findall(r'<script\s+nonce="([^"]+)"', body)
        assert len(script_nonces) == 1, f"Expected 1 script nonce, got: {script_nonces}"
        assert script_nonces[0] == header_nonce

    def test_existing_nonce_is_preserved(self) -> None:
        """Pre-existing nonce attribute is preserved and un-nonced tag receives no automatic injection."""
        app, _, _ = create_test_app()
        client = app.test_client()

        resp = client.get("/existing-nonce-page")
        assert resp.status_code == 200

        csp = resp.headers.get("Content-Security-Policy", "")
        m_header = re.search(r"'nonce-([A-Za-z0-9+/=_-]+)'", csp)
        assert m_header is not None

        body = resp.get_data(as_text=True)
        assert 'nonce="custom-static-nonce"' in body
        assert '<script>console.log("needs-nonce");</script>' in body
        assert body.count("nonce=") == 1

    def test_raw_html_scripts_receive_no_automatic_injection(self) -> None:
        """Un-nonced scripts in raw HTML responses are not automatically modified by middleware."""
        app, _, _ = create_test_app()
        client = app.test_client()

        resp = client.get("/script-page")
        assert resp.status_code == 200
        body = resp.get_data(as_text=True)

        assert '<script src="/app.js"></script>' in body
        assert "<script>console.log('inline');</script>" in body
        assert "nonce=" not in body

    def test_xssguard_nonce_sourced_from_wsgi_environ(self) -> None:
        """Template variable xssguard_nonce is sourced from request.environ['xssguard.nonce']."""
        app, _, _ = create_test_app()
        client = app.test_client()

        captured = []

        @app.route("/environ-test", methods=["GET"])
        def environ_test() -> Response:
            captured.append(request.environ.get("xssguard.nonce"))
            return Response(render_template_string("{{ xssguard_nonce }}"), mimetype="text/plain")

        resp = client.get("/environ-test")
        assert resp.status_code == 200
        rendered_nonce = resp.get_data(as_text=True)

        assert len(captured) == 1
        assert captured[0] is not None and len(captured[0]) >= 16
        assert rendered_nonce == captured[0]

    def test_user_controlled_content_receives_no_nonce(self) -> None:
        """User input rendered in template does not receive nonce."""
        app, _, _ = create_test_app()
        client = app.test_client()

        @app.route("/user-content", methods=["GET"])
        def user_content() -> Response:
            user_input = request.args.get("q", "")
            return Response(
                render_template_string(
                    "<p>{{ user_input }}</p><script nonce='{{ xssguard_nonce }}'>init();</script>",
                    user_input=user_input,
                ),
                mimetype="text/html",
            )

        xss_payload = "<script>alert('pwn')</script>"
        resp = client.get(f"/user-content?q={xss_payload}")
        assert resp.status_code == 200
        body = resp.get_data(as_text=True)

        csp = resp.headers.get("Content-Security-Policy", "")
        header_nonce = re.search(r"'nonce-([A-Za-z0-9+/=_-]+)'", csp).group(1)

        # Trusted script receives nonce
        assert f"<script nonce='{header_nonce}'>init();</script>" in body
        # User payload does not receive nonce
        assert f"nonce='{header_nonce}'>alert" not in body
        assert f'nonce="{header_nonce}">alert' not in body

    def test_non_html_response_body_unmodified(self) -> None:
        """Non-HTML responses (e.g., JSON) keep their body intact."""
        app, _, _ = create_test_app()
        client = app.test_client()

        resp = client.post(
            "/api/feedback",
            data=json.dumps({"bio": "safe text"}),
            content_type="application/json",
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data == {"bio": "safe text"}
        assert "Content-Security-Policy" in resp.headers

    def test_nonce_uniqueness_across_requests(self) -> None:
        """Each sequential request receives a unique CSPRNG nonce."""
        app, _, _ = create_test_app()
        client = app.test_client()

        nonces = set()
        for _ in range(10):
            resp = client.get("/page")
            csp = resp.headers.get("Content-Security-Policy", "")
            m = re.search(r"'nonce-([A-Za-z0-9+/=_-]+)'", csp)
            assert m is not None
            nonces.add(m.group(1))

        assert len(nonces) == 10


# ---------------------------------------------------------------------------
# Test Suite 4: CSP Report Endpoint
# ---------------------------------------------------------------------------

class TestFlaskCspReportEndpoint:
    """Validate valid CSP reports received at /csp-report."""

    def test_valid_csp_report_direct_format(self) -> None:
        """Valid direct CSP report returns 204 and stores CspReportRecord."""
        app, _, store = create_test_app()
        client = app.test_client()

        report_payload = {
            "document-uri": "https://example.com/account",
            "violated-directive": "script-src 'nonce-abc'",
            "blocked-uri": "https://evil.com/leak.js",
            "original-policy": "default-src 'self'; script-src 'nonce-abc'",
        }
        resp = client.post(
            "/csp-report",
            data=json.dumps(report_payload),
            content_type="application/csp-report",
            environ_overrides={"REMOTE_ADDR": "192.0.2.1"},
        )

        assert resp.status_code == 204
        assert resp.get_data() == b""

        reports = store.recent_csp_reports()
        assert len(reports) == 1

        rec = reports[0]
        assert isinstance(rec, CspReportRecord)
        assert rec.document_uri == "https://example.com/account"
        assert rec.violated_directive == "script-src 'nonce-abc'"
        assert rec.blocked_uri == "https://evil.com/leak.js"
        assert rec.client_ip == "192.0.2.1"
        assert rec.created_at is not None

    def test_valid_csp_report_underscore_keys(self) -> None:
        """Valid CSP report using underscore keys returns 204 and stores record."""
        app, _, store = create_test_app()
        client = app.test_client()

        report_payload = {
            "document_uri": "https://example.com/dashboard",
            "violated_directive": "img-src 'self'",
            "blocked_uri": "https://tracker.com/pixel.png",
        }
        resp = client.post(
            "/csp-report",
            data=json.dumps(report_payload),
            content_type="application/json",
        )

        assert resp.status_code == 204
        reports = store.recent_csp_reports()
        assert len(reports) == 1
        assert reports[0].document_uri == "https://example.com/dashboard"
        assert reports[0].violated_directive == "img-src 'self'"
        assert reports[0].blocked_uri == "https://tracker.com/pixel.png"

    def test_valid_csp_report_empty_dict(self) -> None:
        """Valid JSON object with empty dictionary returns 204 and logs record with None fields."""
        app, _, store = create_test_app()
        client = app.test_client()

        resp = client.post("/csp-report", data=b"{}", content_type="application/json")
        assert resp.status_code == 204

        reports = store.recent_csp_reports()
        assert len(reports) == 1
        assert reports[0].document_uri is None
        assert reports[0].violated_directive is None
        assert reports[0].blocked_uri is None


# ---------------------------------------------------------------------------
# Test Suite 5: Invalid CSP Report
# ---------------------------------------------------------------------------

class TestFlaskInvalidCspReport:
    """Validate invalid or malformed CSP reports return 204 and are not stored."""

    def test_malformed_json_returns_204_and_not_stored(self) -> None:
        """Malformed JSON must return HTTP 204 (never 400) and log zero records."""
        app, _, store = create_test_app()
        client = app.test_client()

        resp = client.post(
            "/csp-report",
            data=b"INVALID_JSON_BODY{{{",
            content_type="application/csp-report",
        )
        assert resp.status_code == 204
        assert len(store.recent_csp_reports()) == 0

    def test_empty_body_returns_204_and_not_stored(self) -> None:
        """Empty request body returns HTTP 204 and logs zero records."""
        app, _, store = create_test_app()
        client = app.test_client()

        resp = client.post("/csp-report", data=b"", content_type="application/json")
        assert resp.status_code == 204
        assert len(store.recent_csp_reports()) == 0

    @pytest.mark.parametrize(
        "non_object_payload",
        [
            b"[]",
            b'["item1", "item2"]',
            b'"just a string"',
            b"12345",
            b"99.9",
            b"true",
            b"null",
        ],
    )
    def test_non_object_json_returns_204_and_not_stored(
        self, non_object_payload: bytes
    ) -> None:
        """Non-object JSON (array, primitive, string) returns 204 and logs zero records."""
        app, _, store = create_test_app()
        client = app.test_client()

        resp = client.post(
            "/csp-report",
            data=non_object_payload,
            content_type="application/json",
        )
        assert resp.status_code == 204
        assert len(store.recent_csp_reports()) == 0


# ---------------------------------------------------------------------------
# Test Suite 6: Wrapped CSP Report
# ---------------------------------------------------------------------------

class TestFlaskWrappedCspReport:
    """Validate browser-wrapped {"csp-report": {...}} payload handling."""

    def test_wrapped_csp_report_success(self) -> None:
        """Browser wrapped format is extracted, returns 204, and is stored."""
        app, _, store = create_test_app()
        client = app.test_client()

        wrapped_payload = {
            "csp-report": {
                "document-uri": "https://example.test/",
                "violated-directive": "script-src",
                "blocked-uri": "https://evil.test/x.js",
            }
        }
        resp = client.post(
            "/csp-report",
            data=json.dumps(wrapped_payload),
            content_type="application/csp-report",
            environ_overrides={"REMOTE_ADDR": "198.51.100.7"},
        )

        assert resp.status_code == 204
        reports = store.recent_csp_reports()
        assert len(reports) == 1

        rec = reports[0]
        assert isinstance(rec, CspReportRecord)
        assert rec.document_uri == "https://example.test/"
        assert rec.violated_directive == "script-src"
        assert rec.blocked_uri == "https://evil.test/x.js"
        assert rec.client_ip == "198.51.100.7"

    def test_wrapped_csp_report_underscore_keys(self) -> None:
        """Wrapped format with underscore keys is extracted cleanly."""
        app, _, store = create_test_app()
        client = app.test_client()

        wrapped_payload = {
            "csp-report": {
                "document_uri": "https://example.test/admin",
                "violated_directive": "script-src-elem",
                "blocked_uri": "inline",
            }
        }
        resp = client.post(
            "/csp-report",
            data=json.dumps(wrapped_payload),
            content_type="application/json",
        )

        assert resp.status_code == 204
        reports = store.recent_csp_reports()
        assert len(reports) == 1
        assert reports[0].document_uri == "https://example.test/admin"
        assert reports[0].violated_directive == "script-src-elem"
        assert reports[0].blocked_uri == "inline"


# ---------------------------------------------------------------------------
# Test Suite 7: Report and Detection Record Separation
# ---------------------------------------------------------------------------

class TestFlaskRecordSeparation:
    """Validate strict separation between DetectionRecord and CspReportRecord."""

    def test_csp_report_does_not_create_detection_record(self) -> None:
        """Receiving a CSP report only creates CspReportRecord, zero DetectionRecord."""
        app, _, store = create_test_app()
        client = app.test_client()

        payload = {
            "csp-report": {
                "document-uri": "https://example.test/page",
                "violated-directive": "script-src",
                "blocked-uri": "https://evil.test/script.js",
            }
        }
        resp = client.post(
            "/csp-report",
            data=json.dumps(payload),
            content_type="application/csp-report",
        )
        assert resp.status_code == 204

        csp_reports = store.recent_csp_reports()
        detections = store.recent_detections()

        assert len(csp_reports) == 1
        assert len(detections) == 0
        assert isinstance(csp_reports[0], CspReportRecord)

    def test_xss_detection_does_not_create_csp_report_record(self) -> None:
        """Detecting XSS attack only creates DetectionRecord, zero CspReportRecord."""
        app, _, store = create_test_app()
        client = app.test_client()

        resp = client.get("/search?q=%3Cscript%3Ealert(1)%3C/script%3E")
        assert resp.status_code == 200

        csp_reports = store.recent_csp_reports()
        detections = store.recent_detections()

        assert len(detections) == 1
        assert len(csp_reports) == 0
        assert isinstance(detections[0], DetectionRecord)

    def test_mixed_traffic_record_type_isolation(self) -> None:
        """In a mixed stream of reports and attacks, records strictly retain their types."""
        app, _, store = create_test_app()
        client = app.test_client()

        # Send 2 CSP reports
        for i in range(2):
            client.post(
                "/csp-report",
                data=json.dumps(
                    {
                        "csp-report": {
                            "document-uri": f"https://example.test/item/{i}",
                            "violated-directive": "script-src",
                            "blocked-uri": f"https://evil.test/attack_{i}.js",
                        }
                    }
                ),
                content_type="application/csp-report",
            )

        # Send 3 XSS attacks
        for i in range(3):
            client.get(f"/search?q=%3Cscript%3Ealert({i})%3C/script%3E")

        csp_reports = store.recent_csp_reports()
        detections = store.recent_detections()

        assert len(csp_reports) == 2
        assert len(detections) == 3

        for r in csp_reports:
            assert isinstance(r, CspReportRecord)
            assert not isinstance(r, DetectionRecord)

        for d in detections:
            assert isinstance(d, DetectionRecord)
            assert not isinstance(d, CspReportRecord)


# ---------------------------------------------------------------------------
# Test Suite 8: Architectural Isolation & Public API
# ---------------------------------------------------------------------------

class TestFlaskExtArchitecturalIsolation:
    """Validate public API surface and architectural boundaries of flask_ext."""

    def test_public_api_surface(self) -> None:
        """Module exposes exactly XSSGuard and register_csp_report_route."""
        tree = ast.parse(inspect.getsource(flask_ext_module))
        defined_classes = {
            n.name
            for n in tree.body
            if isinstance(n, ast.ClassDef) and not n.name.startswith("_")
        }
        defined_funcs = {
            n.name
            for n in tree.body
            if isinstance(n, ast.FunctionDef) and not n.name.startswith("_")
        }

        assert defined_classes == {"XSSGuard"}
        assert defined_funcs == {"register_csp_report_route"}
        assert flask_ext_module.__all__ == ["XSSGuard", "register_csp_report_route"]

    def test_no_forbidden_framework_imports(self) -> None:
        """Module must not import unauthorized frameworks or internal core layers directly."""
        tree = ast.parse(inspect.getsource(flask_ext_module))
        imports = []
        for n in tree.body:
            if isinstance(n, ast.Import):
                for a in n.names:
                    imports.append(a.name)
            elif isinstance(n, ast.ImportFrom) and n.module:
                imports.append(n.module)

        forbidden_prefixes = (
            "sqlalchemy",
            "django",
            "bottle",
            "requests",
            "xssguard.detector",
            "xssguard.nonce",
            "xssguard.dashboard",
        )
        for imp in imports:
            assert not imp.startswith(forbidden_prefixes), f"Forbidden import: {imp}"
