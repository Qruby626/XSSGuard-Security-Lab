"""Automated regression tests for xssguard.dashboard module.

Validates:
1. Blueprint creation:
   - create_dashboard_blueprint(store) returns Flask Blueprint
   - Custom blueprint name support
   - Registration to Flask application (root or prefixed)
2. Dashboard endpoint:
   - GET / returns HTTP 200 with HTML content
   - Standard page title, headers, and structure
3. DetectionRecord display:
   - Payload, status, matched_rule, source, client_ip, created_at rendered
   - Fallback '-' for optional None fields
   - Multiple detection records displayed
4. CspReportRecord display:
   - Document_uri, violated_directive, blocked_uri, client_ip, created_at rendered
   - Fallback '-' for optional None fields
   - Multiple CSP report records displayed
5. Empty state:
   - Clean render without error when store has zero records
   - "No detection records." and "No CSP violation reports." displayed
6. FakeStore / BaseStore abstraction:
   - FakeStore satisfies BaseStore protocol without inheriting MemoryStore
   - Dashboard functions identically with FakeStore
   - Zero reliance on private MemoryStore implementation details
7. Dashboard architectural isolation:
   - No imports of detector, patterns, nonce, report, middleware, flask_ext
   - Minimal public API surface: only create_dashboard_blueprint
   - Zero dependence on core detection/mitigation runtime
8. HTML Escaping / XSS Safety:
   - Malicious HTML/script strings in records are strictly escaped by template
   - Zero raw executable <script>, <img>, or <svg> injected into rendered DOM
9. Default LIMIT = 50:
   - Store receives limit=50 for recent_detections and recent_csp_reports
   - Verified via FakeStore call recorder
10. Detection and CSP report record separation:
   - Detection records remain strictly in Detection Logs section
   - CSP violation reports remain strictly in CSP Violation Reports section
   - No data cross-contamination between tables
"""

import ast
import inspect
from datetime import datetime, timezone
from typing import Optional

import pytest
from flask import Flask, Response

import xssguard.dashboard as dashboard_module
from xssguard.dashboard import create_dashboard_blueprint
from xssguard.storage import BaseStore, CspReportRecord, DetectionRecord, MemoryStore


# ---------------------------------------------------------------------------
# Test Helpers & FakeStore (BaseStore Abstraction)
# ---------------------------------------------------------------------------

class FakeStore:
    """Minimal storage implementing BaseStore Protocol without inheriting MemoryStore.

    Used to prove that dashboard depends strictly on the BaseStore interface.
    Also tracks the limit argument passed to query methods.
    """

    def __init__(self) -> None:
        self._detections: list[DetectionRecord] = []
        self._csp_reports: list[CspReportRecord] = []
        self.last_detections_limit: Optional[int] = None
        self.last_csp_reports_limit: Optional[int] = None

    def log_detection(self, record: DetectionRecord) -> None:
        self._detections.append(record)

    def log_csp_report(self, record: CspReportRecord) -> None:
        self._csp_reports.append(record)

    def recent_detections(self, limit: int = 50) -> list[DetectionRecord]:
        self.last_detections_limit = limit
        if limit <= 0:
            return []
        return self._detections[:limit]

    def recent_csp_reports(self, limit: int = 50) -> list[CspReportRecord]:
        self.last_csp_reports_limit = limit
        if limit <= 0:
            return []
        return self._csp_reports[:limit]


def create_dashboard_app(
    store: BaseStore,
    *,
    url_prefix: str = "",
    blueprint_name: str = "xssguard_dashboard",
) -> Flask:
    """Create a test Flask application registering the dashboard blueprint."""
    app = Flask(__name__)
    app.config["TESTING"] = True
    bp = create_dashboard_blueprint(store, name=blueprint_name)
    app.register_blueprint(bp, url_prefix=url_prefix)
    return app


# ---------------------------------------------------------------------------
# 1. Blueprint Creation
# ---------------------------------------------------------------------------

class TestDashboardBlueprintCreation:
    """Validate factory function create_dashboard_blueprint."""

    def test_blueprint_created_with_default_name(self) -> None:
        """create_dashboard_blueprint returns Blueprint with default name."""
        store = MemoryStore()
        bp = create_dashboard_blueprint(store)
        assert bp.name == "xssguard_dashboard"

    def test_blueprint_created_with_custom_name(self) -> None:
        """create_dashboard_blueprint supports custom blueprint name."""
        store = MemoryStore()
        bp = create_dashboard_blueprint(store, name="custom_sec_dash")
        assert bp.name == "custom_sec_dash"

    def test_blueprint_can_be_registered_on_flask_app(self) -> None:
        """Blueprint successfully registers onto Flask with routes in url_map."""
        store = MemoryStore()
        app = Flask(__name__)
        bp = create_dashboard_blueprint(store)
        app.register_blueprint(bp, url_prefix="/dashboard")

        rules = [r.rule for r in app.url_map.iter_rules()]
        assert "/dashboard/" in rules


# ---------------------------------------------------------------------------
# 2. Dashboard Endpoint
# ---------------------------------------------------------------------------

class TestDashboardEndpoint:
    """Validate dashboard endpoint rendering and basic response structure."""

    def test_dashboard_endpoint_get_success(self) -> None:
        """GET / returns HTTP 200 with HTML content and core headings."""
        store = MemoryStore()
        app = create_dashboard_app(store)
        client = app.test_client()

        resp = client.get("/")
        assert resp.status_code == 200
        assert "text/html" in resp.headers.get("Content-Type", "")

        html = resp.get_data(as_text=True)
        assert "<title>XSSGuard Security Dashboard</title>" in html
        assert "<h1>XSSGuard Security Dashboard</h1>" in html
        assert "<h2>Detection Logs</h2>" in html
        assert "<h2>CSP Violation Reports</h2>" in html

    def test_dashboard_endpoint_with_url_prefix(self) -> None:
        """GET /security/dashboard/ renders correctly when prefixed."""
        store = MemoryStore()
        app = create_dashboard_app(store, url_prefix="/security/dashboard")
        client = app.test_client()

        resp = client.get("/security/dashboard/")
        assert resp.status_code == 200
        assert "XSSGuard Security Dashboard" in resp.get_data(as_text=True)

    def test_dashboard_method_not_allowed_for_post(self) -> None:
        """POST / returns 405 Method Not Allowed as dashboard is read-only GET."""
        store = MemoryStore()
        app = create_dashboard_app(store)
        client = app.test_client()

        resp = client.post("/")
        assert resp.status_code == 405


# ---------------------------------------------------------------------------
# 3. DetectionRecord Display
# ---------------------------------------------------------------------------

class TestDashboardDetectionRecordDisplay:
    """Validate rendering of DetectionRecord items in dashboard."""

    def test_detection_record_all_fields_displayed(self) -> None:
        """DetectionRecord attributes appear correctly in the Detection Logs table."""
        store = MemoryStore()
        record = DetectionRecord(
            payload="q=<script>alert('xss')</script>",
            status="DETECTED",
            matched_rule=r"(?i)<\s*/?\s*script\b",
            source="/search",
            client_ip="198.51.100.15",
            created_at=datetime(2026, 9, 12, 10, 30, 0, tzinfo=timezone.utc),
        )
        store.log_detection(record)

        app = create_dashboard_app(store)
        client = app.test_client()

        resp = client.get("/")
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)

        assert "2026-09-12 10:30:00+00:00" in html
        assert '<span class="badge">DETECTED</span>' in html
        assert "<code>/search</code>" in html
        assert "198.51.100.15" in html
        assert r"(?i)&lt;\s*/?\s*script\b" in html or r"(?i)<\s*/?\s*script\b" in html
        assert "q=&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;" in html or "q=<script>alert('xss')</script>" in html

    def test_detection_record_none_optional_fields(self) -> None:
        """DetectionRecord with None matched_rule and client_ip displays '-' placeholder."""
        store = MemoryStore()
        record = DetectionRecord(
            payload="text=test",
            status="DETECTED",
            matched_rule=None,
            source="/api",
            client_ip=None,
        )
        store.log_detection(record)

        app = create_dashboard_app(store)
        client = app.test_client()

        resp = client.get("/")
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)

        assert "<code>/api</code>" in html
        assert "<td>-</td>" in html

    def test_multiple_detection_records_rendered(self) -> None:
        """Multiple DetectionRecords are rendered as separate table rows."""
        store = MemoryStore()
        for i in range(3):
            store.log_detection(
                DetectionRecord(
                    payload=f"input_{i}=val_{i}",
                    status="DETECTED",
                    matched_rule="test_rule",
                    source=f"/route_{i}",
                    client_ip=f"192.0.2.{i}",
                )
            )

        app = create_dashboard_app(store)
        client = app.test_client()

        resp = client.get("/")
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)

        for i in range(3):
            assert f"<code>/route_{i}</code>" in html
            assert f"<code>input_{i}=val_{i}</code>" in html
            assert f"192.0.2.{i}" in html


# ---------------------------------------------------------------------------
# 4. CspReportRecord Display
# ---------------------------------------------------------------------------

class TestDashboardCspReportRecordDisplay:
    """Validate rendering of CspReportRecord items in dashboard."""

    def test_csp_report_record_all_fields_displayed(self) -> None:
        """CspReportRecord attributes appear correctly in CSP Violation Reports table."""
        store = MemoryStore()
        report = CspReportRecord(
            document_uri="https://example.com/dashboard",
            violated_directive="script-src 'self'",
            blocked_uri="https://evil.com/leak.js",
            client_ip="203.0.113.88",
            created_at=datetime(2026, 9, 12, 11, 15, 0, tzinfo=timezone.utc),
        )
        store.log_csp_report(report)

        app = create_dashboard_app(store)
        client = app.test_client()

        resp = client.get("/")
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)

        assert "2026-09-12 11:15:00+00:00" in html
        assert "<code>https://example.com/dashboard</code>" in html
        assert "<code>script-src &#39;self&#39;</code>" in html or "<code>script-src 'self'</code>" in html
        assert "<code>https://evil.com/leak.js</code>" in html
        assert "203.0.113.88" in html

    def test_csp_report_record_none_optional_fields(self) -> None:
        """CspReportRecord with None optional fields displays '<code>-</code>' or '-' placeholder."""
        store = MemoryStore()
        report = CspReportRecord(
            document_uri=None,
            violated_directive=None,
            blocked_uri=None,
            client_ip=None,
        )
        store.log_csp_report(report)

        app = create_dashboard_app(store)
        client = app.test_client()

        resp = client.get("/")
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)

        assert "<code>-</code>" in html
        assert "<td>-</td>" in html

    def test_multiple_csp_report_records_rendered(self) -> None:
        """Multiple CspReportRecords are rendered as separate table rows."""
        store = MemoryStore()
        for i in range(3):
            store.log_csp_report(
                CspReportRecord(
                    document_uri=f"https://example.com/page/{i}",
                    violated_directive="script-src",
                    blocked_uri=f"https://attacker.test/bad_{i}.js",
                    client_ip=f"198.51.100.{i}",
                )
            )

        app = create_dashboard_app(store)
        client = app.test_client()

        resp = client.get("/")
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)

        for i in range(3):
            assert f"<code>https://example.com/page/{i}</code>" in html
            assert f"<code>https://attacker.test/bad_{i}.js</code>" in html
            assert f"198.51.100.{i}" in html


# ---------------------------------------------------------------------------
# 5. Empty State
# ---------------------------------------------------------------------------

class TestDashboardEmptyState:
    """Validate dashboard behavior when storage contains zero records."""

    def test_empty_store_renders_cleanly(self) -> None:
        """Dashboard renders HTTP 200 without error when store is empty."""
        store = MemoryStore()
        app = create_dashboard_app(store)
        client = app.test_client()

        resp = client.get("/")
        assert resp.status_code == 200

    def test_empty_state_notices_displayed(self) -> None:
        """Explicit empty state notices are shown for both sections."""
        store = MemoryStore()
        app = create_dashboard_app(store)
        client = app.test_client()

        resp = client.get("/")
        html = resp.get_data(as_text=True)

        assert '<p class="empty">No detection records.</p>' in html
        assert '<p class="empty">No CSP violation reports.</p>' in html
        assert "<table>" not in html


# ---------------------------------------------------------------------------
# 6. WAJIB — FakeStore / BaseStore Abstraction
# ---------------------------------------------------------------------------

class TestDashboardBaseStoreAbstraction:
    """Prove that dashboard works strictly with BaseStore abstraction, not MemoryStore."""

    def test_fake_store_satisfies_base_store_protocol(self) -> None:
        """FakeStore conforms to runtime_checkable BaseStore Protocol."""
        fake = FakeStore()
        assert isinstance(fake, BaseStore)
        assert not isinstance(fake, MemoryStore)

    def test_dashboard_renders_with_fake_store(self) -> None:
        """Dashboard successfully queries and renders records using FakeStore."""
        fake = FakeStore()
        fake.log_detection(
            DetectionRecord(
                payload="param=attack",
                status="DETECTED",
                matched_rule="test_rule",
                source="/fake_test",
                client_ip="10.0.0.1",
            )
        )
        fake.log_csp_report(
            CspReportRecord(
                document_uri="https://fake.test/doc",
                violated_directive="img-src",
                blocked_uri="https://bad.fake/img.png",
                client_ip="10.0.0.2",
            )
        )

        app = create_dashboard_app(fake)
        client = app.test_client()

        resp = client.get("/")
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)

        assert "<code>param=attack</code>" in html
        assert "<code>https://fake.test/doc</code>" in html
        assert "10.0.0.1" in html
        assert "10.0.0.2" in html

    def test_dashboard_does_not_access_private_memory_store_attributes(self) -> None:
        """Dashboard does not rely on MemoryStore internal fields (_lock, _detections)."""
        fake = FakeStore()
        assert not hasattr(fake, "_lock")

        app = create_dashboard_app(fake)
        client = app.test_client()
        resp = client.get("/")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 7. Dashboard Architectural Isolation
# ---------------------------------------------------------------------------

class TestDashboardArchitecturalIsolation:
    """Verify that dashboard.py is completely isolated from core and middleware."""

    def test_public_api_surface(self) -> None:
        """Only create_dashboard_blueprint is exposed in dashboard public API."""
        tree = ast.parse(inspect.getsource(dashboard_module))
        defined_funcs = {
            n.name
            for n in tree.body
            if isinstance(n, ast.FunctionDef) and not n.name.startswith("_")
        }
        defined_classes = {
            n.name
            for n in tree.body
            if isinstance(n, ast.ClassDef) and not n.name.startswith("_")
        }

        assert defined_funcs == {"create_dashboard_blueprint"}
        assert defined_classes == set()
        assert dashboard_module.__all__ == ["create_dashboard_blueprint"]

    def test_no_forbidden_module_imports(self) -> None:
        """Dashboard must not import detector, patterns, nonce, report, middleware, flask_ext."""
        tree = ast.parse(inspect.getsource(dashboard_module))
        imports = []
        for n in tree.body:
            if isinstance(n, ast.Import):
                for a in n.names:
                    imports.append(a.name)
            elif isinstance(n, ast.ImportFrom) and n.module:
                imports.append(n.module)

        forbidden_prefixes = (
            "xssguard.detector",
            "xssguard.patterns",
            "xssguard.nonce",
            "xssguard.report",
            "xssguard.middleware",
            "xssguard.flask_ext",
            "sqlalchemy",
            "django",
            "bottle",
            "requests",
        )
        for imp in imports:
            assert not imp.startswith(forbidden_prefixes), f"Forbidden import found: {imp}"


# ---------------------------------------------------------------------------
# 8. HTML Escaping / XSS Safety
# ---------------------------------------------------------------------------

class TestDashboardHtmlEscaping:
    """Verify that untrusted data in records is strictly HTML-escaped by Jinja."""

    def test_xss_in_detection_payload_is_escaped(self) -> None:
        """Detection payload containing script tags is strictly escaped."""
        store = MemoryStore()
        dangerous_payload = "<script>alert('payload-xss')</script>"
        store.log_detection(
            DetectionRecord(
                payload=dangerous_payload,
                status="DETECTED",
                matched_rule="rule",
                source="/test",
                client_ip="127.0.0.1",
            )
        )

        app = create_dashboard_app(store)
        client = app.test_client()

        resp = client.get("/")
        html = resp.get_data(as_text=True)

        # Raw executable <script> must never exist in the HTML response
        assert "<script>" not in html
        assert "<script" not in html
        assert "</script>" not in html

        # Properly escaped entity representation must be present
        assert "&lt;script&gt;alert(" in html

    def test_xss_in_detection_metadata_fields_is_escaped(self) -> None:
        """Source, client_ip, and matched_rule fields with HTML tags are escaped."""
        store = MemoryStore()
        store.log_detection(
            DetectionRecord(
                payload="normal=1",
                status="DETECTED",
                matched_rule="<img src=x onerror=alert('rule')>",
                source="/<svg/onload=alert('source')>",
                client_ip="<script>alert('ip')</script>",
            )
        )

        app = create_dashboard_app(store)
        client = app.test_client()

        resp = client.get("/")
        html = resp.get_data(as_text=True)

        assert "<script" not in html
        assert "<img" not in html
        assert "<svg" not in html

        assert "&lt;img" in html
        assert "&lt;svg" in html
        assert "&lt;script&gt;" in html

    def test_xss_in_csp_report_fields_is_escaped(self) -> None:
        """CSP report URIs and directives containing injection attempts are escaped."""
        store = MemoryStore()
        store.log_csp_report(
            CspReportRecord(
                document_uri="https://evil.com/<script>alert('uri')</script>",
                violated_directive="script-src <b onmouseover=alert(1)>",
                blocked_uri="javascript:alert('blocked')<script>evil()</script>",
                client_ip="<iframe src='about:blank'>",
            )
        )

        app = create_dashboard_app(store)
        client = app.test_client()

        resp = client.get("/")
        html = resp.get_data(as_text=True)

        assert "<script" not in html
        assert "<b onmouseover" not in html
        assert "<iframe" not in html

        assert "&lt;script&gt;" in html
        assert "&lt;b onmouseover" in html
        assert "&lt;iframe" in html


# ---------------------------------------------------------------------------
# 9. Default LIMIT = 50
# ---------------------------------------------------------------------------

class TestDashboardDefaultLimit:
    """Validate that dashboard queries store with default limit=50."""

    def test_dashboard_requests_limit_50_for_both_queries(self) -> None:
        """Dashboard explicitly passes limit=50 to recent_detections and recent_csp_reports."""
        fake = FakeStore()
        app = create_dashboard_app(fake)
        client = app.test_client()

        assert fake.last_detections_limit is None
        assert fake.last_csp_reports_limit is None

        resp = client.get("/")
        assert resp.status_code == 200

        assert fake.last_detections_limit == 50
        assert fake.last_csp_reports_limit == 50

    def test_store_with_excess_records_renders_at_most_50(self) -> None:
        """When store contains 60 records, dashboard queries and renders at most 50."""
        store = MemoryStore()
        for i in range(65):
            store.log_detection(
                DetectionRecord(
                    payload=f"entry={i}",
                    status="DETECTED",
                    matched_rule="rule",
                    source="/bulk",
                    client_ip="127.0.0.1",
                )
            )

        app = create_dashboard_app(store)
        client = app.test_client()

        resp = client.get("/")
        html = resp.get_data(as_text=True)

        badge_count = html.count('<span class="badge">DETECTED</span>')
        assert badge_count == 50


# ---------------------------------------------------------------------------
# 10. Detection and CSP Report Separation
# ---------------------------------------------------------------------------

class TestDashboardRecordSeparation:
    """Validate strict separation between DetectionRecord and CspReportRecord display."""

    def test_detection_only_leaves_csp_section_empty(self) -> None:
        """When only DetectionRecords exist, CSP section renders empty notice."""
        store = MemoryStore()
        store.log_detection(
            DetectionRecord(
                payload="x=1",
                status="DETECTED",
                matched_rule="rule",
                source="/detection-only",
                client_ip="10.0.0.1",
            )
        )

        app = create_dashboard_app(store)
        client = app.test_client()

        resp = client.get("/")
        html = resp.get_data(as_text=True)

        assert "<code>/detection-only</code>" in html
        assert '<p class="empty">No CSP violation reports.</p>' in html
        assert '<p class="empty">No detection records.</p>' not in html

    def test_csp_only_leaves_detection_section_empty(self) -> None:
        """When only CspReportRecords exist, Detection section renders empty notice."""
        store = MemoryStore()
        store.log_csp_report(
            CspReportRecord(
                document_uri="https://example.com/csp-only",
                violated_directive="script-src",
                blocked_uri="https://evil.test/x.js",
                client_ip="10.0.0.2",
            )
        )

        app = create_dashboard_app(store)
        client = app.test_client()

        resp = client.get("/")
        html = resp.get_data(as_text=True)

        assert "<code>https://example.com/csp-only</code>" in html
        assert '<p class="empty">No detection records.</p>' in html
        assert '<p class="empty">No CSP violation reports.</p>' not in html

    def test_mixed_records_stay_in_respective_tables(self) -> None:
        """Detection and CSP reports appear strictly in their respective sections."""
        store = MemoryStore()
        unique_detection_marker = "UNIQUE_DETECTION_SOURCE_MARKER"
        unique_csp_marker = "https://unique.csp.report.marker/test"

        store.log_detection(
            DetectionRecord(
                payload="marker=1",
                status="DETECTED",
                matched_rule="rule",
                source=unique_detection_marker,
                client_ip="10.0.0.1",
            )
        )
        store.log_csp_report(
            CspReportRecord(
                document_uri=unique_csp_marker,
                violated_directive="script-src",
                blocked_uri="inline",
                client_ip="10.0.0.2",
            )
        )

        app = create_dashboard_app(store)
        client = app.test_client()

        resp = client.get("/")
        html = resp.get_data(as_text=True)

        # Split HTML by the two section headers
        detection_heading = "<h2>Detection Logs</h2>"
        csp_heading = "<h2>CSP Violation Reports</h2>"

        assert detection_heading in html
        assert csp_heading in html

        parts = html.split(csp_heading)
        detection_section = parts[0]
        csp_section = parts[1]

        # Detection marker must only be in detection section
        assert unique_detection_marker in detection_section
        assert unique_detection_marker not in csp_section

        # CSP marker must only be in CSP section
        assert unique_csp_marker in csp_section
        assert unique_csp_marker not in detection_section
