"""Regression & Acceptance Test Suite for Request/Payload Blocking feature.

Validates the 10 mandatory test cases from DESIGN_DECISION_REQUEST_PAYLOAD_BLOCKING.md
and IMPLEMENTATION_CONTRACT.

Scope: XSSGuardMiddleware enforcement layer only.
NOT included: detector.py logic (covered by test_detector.py),
              nonce.py policy (covered by test_middleware.py).
"""

import io
from typing import Any, Iterable, List, Tuple
from wsgiref.types import StartResponse

import pytest

from xssguard.middleware import XSSGuardMiddleware
from xssguard.storage import DetectionRecord, MemoryStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_start_response() -> Tuple[StartResponse, List[str], List[Tuple[str, str]]]:
    status_captured: List[str] = []
    headers_captured: List[Tuple[str, str]] = []

    def start_response(
        status: str,
        response_headers: List[Tuple[str, str]],
        exc_info: Any = None,
    ) -> None:
        status_captured.append(status)
        headers_captured.extend(response_headers)

    return start_response, status_captured, headers_captured


def extract_header(headers: List[Tuple[str, str]], name: str) -> str:
    for k, v in headers:
        if k.lower() == name.lower():
            return v
    return ""


def _attack_environ(path: str = "/submit", query_attack: bool = True) -> dict:
    """Return a WSGI environ containing an XSS payload in query string."""
    qs = "q=%3Cscript%3Ealert(1)%3C/script%3E" if query_attack else ""
    return {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": path,
        "QUERY_STRING": qs,
        "REMOTE_ADDR": "203.0.113.7",
        "wsgi.input": io.BytesIO(b""),
    }


def _safe_environ(path: str = "/home") -> dict:
    return {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": path,
        "QUERY_STRING": "page=1",
        "REMOTE_ADDR": "192.0.2.1",
        "wsgi.input": io.BytesIO(b""),
    }


# ---------------------------------------------------------------------------
# TEST-01  Safe request + blocking OFF
# ---------------------------------------------------------------------------

class TestBlockingT01SafeRequestBlockingOff:
    def test_application_executed_and_response_200(self) -> None:
        app_called: List[bool] = [False]

        def host_app(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
            app_called[0] = True
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"OK"]

        store = MemoryStore()
        mw = XSSGuardMiddleware(host_app, store=store, blocking_enabled=False)
        start_resp, status, _ = make_start_response()
        body = b"".join(mw(_safe_environ(), start_resp))

        assert app_called[0] is True, "Application MUST execute for safe request"
        assert "200" in status[0]
        assert body == b"OK"

    def test_no_detection_record_created(self) -> None:
        def host_app(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"OK"]

        store = MemoryStore()
        mw = XSSGuardMiddleware(host_app, store=store, blocking_enabled=False)
        start_resp, _, _ = make_start_response()
        list(mw(_safe_environ(), start_resp))

        assert store.recent_detections() == [], "SAFE request MUST NOT create DetectionRecord"


# ---------------------------------------------------------------------------
# TEST-02  Detected request + blocking OFF
# ---------------------------------------------------------------------------

class TestBlockingT02DetectedBlockingOff:
    def test_application_executed_response_200(self) -> None:
        app_called: List[bool] = [False]

        def host_app(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
            app_called[0] = True
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"PROCESSED"]

        store = MemoryStore()
        mw = XSSGuardMiddleware(host_app, store=store, blocking_enabled=False)
        start_resp, status, _ = make_start_response()
        body = b"".join(mw(_attack_environ(), start_resp))

        assert app_called[0] is True, "With blocking OFF, detected request MUST reach host app"
        assert "200" in status[0]
        assert body == b"PROCESSED"

    def test_detection_record_action_is_ALLOWED(self) -> None:
        def host_app(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"OK"]

        store = MemoryStore()
        mw = XSSGuardMiddleware(host_app, store=store, blocking_enabled=False)
        start_resp, _, _ = make_start_response()
        list(mw(_attack_environ(), start_resp))

        records = store.recent_detections()
        assert len(records) >= 1
        for rec in records:
            assert rec.action == "ALLOWED", (
                f"With blocking OFF, DetectionRecord.action MUST be 'ALLOWED', got: {rec.action!r}"
            )


# ---------------------------------------------------------------------------
# TEST-03  Detected request + blocking ON
# ---------------------------------------------------------------------------

class TestBlockingT03DetectedBlockingOn:
    def test_application_NOT_executed_response_403(self) -> None:
        app_called: List[bool] = [False]

        def host_app(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
            app_called[0] = True
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"THIS MUST NOT APPEAR"]

        store = MemoryStore()
        mw = XSSGuardMiddleware(host_app, store=store, blocking_enabled=True)
        start_resp, status, _ = make_start_response()
        body = b"".join(mw(_attack_environ(path="/unprotected"), start_resp))

        assert app_called[0] is False, "With blocking ON, detected request MUST NOT reach host app"
        assert "403" in status[0], f"Expected HTTP 403, got: {status[0]}"
        assert b"THIS MUST NOT APPEAR" not in body
        assert b"403 Forbidden" in body or b"blocked" in body.lower()

    def test_content_type_is_text_html(self) -> None:
        def host_app(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
            start_response("200 OK", [])
            return [b""]

        store = MemoryStore()
        mw = XSSGuardMiddleware(host_app, store=store, blocking_enabled=True)
        start_resp, _, headers = make_start_response()
        list(mw(_attack_environ(path="/hit"), start_resp))

        ct = extract_header(headers, "Content-Type")
        assert ct.startswith("text/html"), f"403 Content-Type must be text/html, got: {ct!r}"

    def test_csp_header_still_present_on_403(self) -> None:
        def host_app(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
            start_response("200 OK", [])
            return [b""]

        store = MemoryStore()
        mw = XSSGuardMiddleware(host_app, store=store, blocking_enabled=True)
        start_resp, _, headers = make_start_response()
        list(mw(_attack_environ(path="/hit2"), start_resp))

        csp = extract_header(headers, "Content-Security-Policy")
        assert csp != "", "CSP header MUST be present on 403 response"
        assert "script-src" in csp

    def test_detection_record_action_is_BLOCKED(self) -> None:
        def host_app(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
            start_response("200 OK", [])
            return [b""]

        store = MemoryStore()
        mw = XSSGuardMiddleware(host_app, store=store, blocking_enabled=True)
        start_resp, _, _ = make_start_response()
        list(mw(_attack_environ(path="/blocked"), start_resp))

        records = store.recent_detections()
        assert len(records) >= 1
        for rec in records:
            assert rec.action == "BLOCKED", (
                f"With blocking ON, DetectionRecord.action MUST be 'BLOCKED', got: {rec.action!r}"
            )


# ---------------------------------------------------------------------------
# TEST-04  Detected request + blocking ON + excluded path
# ---------------------------------------------------------------------------

class TestBlockingT04DetectedBlockingOnExcluded:
    def test_application_executed_and_response_200(self) -> None:
        app_called: List[bool] = [False]

        def host_app(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
            app_called[0] = True
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"ALLOWED-THROUGH"]

        store = MemoryStore()
        mw = XSSGuardMiddleware(
            host_app,
            store=store,
            blocking_enabled=True,
            blocking_exclude_paths=["/csp-report", "/lab/store"],
        )
        start_resp, status, _ = make_start_response()
        body = b"".join(mw(_attack_environ(path="/lab/store"), start_resp))

        assert app_called[0] is True, "Excluded path MUST reach host app"
        assert "200" in status[0]
        assert body == b"ALLOWED-THROUGH"

    def test_action_is_ALLOWED_for_excluded_path(self) -> None:
        def host_app(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
            start_response("200 OK", [])
            return [b""]

        store = MemoryStore()
        mw = XSSGuardMiddleware(
            host_app,
            store=store,
            blocking_enabled=True,
            blocking_exclude_paths=["/csp-report"],
        )
        start_resp, _, _ = make_start_response()
        list(mw(_attack_environ(path="/csp-report"), start_resp))

        records = store.recent_detections()
        assert len(records) >= 1
        for rec in records:
            assert rec.action == "ALLOWED", (
                f"Excluded path must yield action='ALLOWED', got: {rec.action!r}"
            )


# ---------------------------------------------------------------------------
# TEST-05  Detected request + blocking ON + non-excluded path
# ---------------------------------------------------------------------------

class TestBlockingT05DetectedBlockingOnNonExcluded:
    def test_403_and_app_not_called(self) -> None:
        app_called: List[bool] = [False]

        def host_app(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
            app_called[0] = True
            start_response("200 OK", [])
            return [b"NOPE"]

        store = MemoryStore()
        mw = XSSGuardMiddleware(
            host_app,
            store=store,
            blocking_enabled=True,
            blocking_exclude_paths=["/csp-report"],
        )
        start_resp, status, _ = make_start_response()
        body = b"".join(mw(_attack_environ(path="/comments/create"), start_resp))

        assert app_called[0] is False
        assert "403" in status[0]
        assert b"NOPE" not in body

    def test_action_is_BLOCKED(self) -> None:
        def host_app(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
            start_response("200 OK", [])
            return [b""]

        store = MemoryStore()
        mw = XSSGuardMiddleware(
            host_app,
            store=store,
            blocking_enabled=True,
            blocking_exclude_paths=["/csp-report"],
        )
        start_resp, _, _ = make_start_response()
        list(mw(_attack_environ(path="/api/v1/comment"), start_resp))

        records = store.recent_detections()
        assert len(records) >= 1
        for rec in records:
            assert rec.action == "BLOCKED"


# ---------------------------------------------------------------------------
# TEST-06  PATH_INFO matching exact, case-sensitive, no query, trailing-slash explicit
# ---------------------------------------------------------------------------

class TestBlockingT06PathMatching:
    def _run(self, path: str, excluded: list) -> Tuple[bool, str]:
        """Return (app_was_called, status)."""
        called: List[bool] = [False]

        def host_app(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
            called[0] = True
            start_response("200 OK", [])
            return [b""]

        store = MemoryStore()
        mw = XSSGuardMiddleware(
            host_app,
            store=store,
            blocking_enabled=True,
            blocking_exclude_paths=excluded,
        )
        start_resp, status, _ = make_start_response()
        list(mw(_attack_environ(path=path), start_resp))
        return called[0], status[0]

    def test_exact_match_excludes(self) -> None:
        excluded = ["/csp-report"]
        called, status = self._run("/csp-report", excluded)
        assert called is True, "/csp-report exact match must be excluded → 200"
        assert "200" in status

    def test_trailing_slash_does_NOT_match_no_slash(self) -> None:
        excluded = ["/csp-report"]
        called, status = self._run("/csp-report/", excluded)
        assert called is False, "/csp-report/ must NOT match '/csp-report' → 403"
        assert "403" in status

    def test_case_sensitive(self) -> None:
        excluded = ["/csp-report"]
        called, status = self._run("/CSP-REPORT", excluded)
        assert called is False, "/CSP-REPORT must NOT match '/csp-report' (case-sensitive)"
        assert "403" in status

    def test_query_string_is_ignored_in_exclusion(self) -> None:
        """Exclusion is based on PATH_INFO only. Query string does not make it match."""
        env = _attack_environ(path="/csp-report", query_attack=True)
        env["PATH_INFO"] = "/csp-report"
        env["QUERY_STRING"] = "foo=%3Cscript%3Ealert(1)%3C/script%3E"

        called: List[bool] = [False]

        def host_app(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
            called[0] = True
            start_response("200 OK", [])
            return [b""]

        store = MemoryStore()
        mw = XSSGuardMiddleware(
            host_app,
            store=store,
            blocking_enabled=True,
            blocking_exclude_paths=["/csp-report"],
        )
        start_resp, status, _ = make_start_response()
        list(mw(env, start_resp))

        assert called[0] is True, (
            "Path exclusion uses PATH_INFO only; query string must be ignored"
        )
        assert status and "200" in status[0]


# ---------------------------------------------------------------------------
# TEST-07  Nonce generated exactly once per request (all branches)
# ---------------------------------------------------------------------------

class TestBlockingT07NonceGeneratedOnce:
    def test_safe_request_exactly_one_nonce(self, monkeypatch: pytest.MonkeyPatch) -> None:
        call_count: List[int] = [0]
        import xssguard.middleware as mw_mod

        original_gen = mw_mod.generate_nonce

        def counting_nonce(*a: Any, **kw: Any) -> str:
            call_count[0] += 1
            return original_gen(*a, **kw)

        monkeypatch.setattr(mw_mod, "generate_nonce", counting_nonce)

        def host_app(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
            start_response("200 OK", [])
            return [b""]

        mw = mw_mod.XSSGuardMiddleware(host_app)
        start_resp, _, _ = make_start_response()
        list(mw(_safe_environ(), start_resp))

        assert call_count[0] == 1, f"SAFE: generate_nonce called {call_count[0]}x, expected 1"

    def test_detected_ALLOWED_exactly_one_nonce(self, monkeypatch: pytest.MonkeyPatch) -> None:
        call_count: List[int] = [0]
        import xssguard.middleware as mw_mod

        original_gen = mw_mod.generate_nonce

        def counting_nonce(*a: Any, **kw: Any) -> str:
            call_count[0] += 1
            return original_gen(*a, **kw)

        monkeypatch.setattr(mw_mod, "generate_nonce", counting_nonce)

        def host_app(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
            start_response("200 OK", [])
            return [b""]

        mw = mw_mod.XSSGuardMiddleware(host_app, blocking_enabled=False)
        start_resp, _, _ = make_start_response()
        list(mw(_attack_environ(), start_resp))

        assert call_count[0] == 1, f"ALLOWED: generate_nonce called {call_count[0]}x, expected 1"

    def test_detected_BLOCKED_exactly_one_nonce(self, monkeypatch: pytest.MonkeyPatch) -> None:
        call_count: List[int] = [0]
        import xssguard.middleware as mw_mod

        original_gen = mw_mod.generate_nonce

        def counting_nonce(*a: Any, **kw: Any) -> str:
            call_count[0] += 1
            return original_gen(*a, **kw)

        monkeypatch.setattr(mw_mod, "generate_nonce", counting_nonce)

        def host_app(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
            start_response("200 OK", [])
            return [b""]

        mw = mw_mod.XSSGuardMiddleware(host_app, blocking_enabled=True)
        start_resp, _, _ = make_start_response()
        list(mw(_attack_environ(path="/x"), start_resp))

        assert call_count[0] == 1, f"BLOCKED: generate_nonce called {call_count[0]}x, expected 1"

    def test_nonce_in_environ_matches_csp_on_blocked_403(self) -> None:
        import re

        def host_app(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
            start_response("200 OK", [])
            return [b""]

        mw = XSSGuardMiddleware(host_app, blocking_enabled=True)
        start_resp, _, headers = make_start_response()
        list(mw(_attack_environ(path="/y"), start_resp))

        csp = extract_header(headers, "Content-Security-Policy")
        match = re.search(r"'nonce-([A-Za-z0-9_-]+)'", csp)
        assert match is not None, "CSP header must contain nonce"
        nonce_from_csp = match.group(1)
        assert len(nonce_from_csp) >= 16


# ---------------------------------------------------------------------------
# TEST-08  Blocked route NOT executed (route marker/counter)
# ---------------------------------------------------------------------------

class TestBlockingT08BlockedRouteNotExecuted:
    def test_counter_unchanged_when_blocked(self) -> None:
        counter: List[int] = [0]

        def host_app(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
            path = environ.get("PATH_INFO", "")
            if path == "/submit":
                counter[0] += 1
            start_response("200 OK", [])
            return [f"count={counter[0]}".encode()]

        mw = XSSGuardMiddleware(host_app, blocking_enabled=True)

        for _ in range(5):
            start_resp, _, _ = make_start_response()
            list(mw(_attack_environ(path="/submit"), start_resp))

        assert counter[0] == 0, (
            f"Blocked request must NOT run route handler. Expected counter=0, got {counter[0]}"
        )


# ---------------------------------------------------------------------------
# TEST-09  Allowed route IS executed (counter increment)
# ---------------------------------------------------------------------------

class TestBlockingT09AllowedRouteExecuted:
    def test_counter_increments_when_allowed_blocking_off(self) -> None:
        counter: List[int] = [0]

        def host_app(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
            counter[0] += 1
            start_response("200 OK", [])
            return [b""]

        mw = XSSGuardMiddleware(host_app, blocking_enabled=False)
        for _ in range(5):
            start_resp, _, _ = make_start_response()
            list(mw(_attack_environ(path="/submit"), start_resp))

        assert counter[0] == 5, f"ALLOWED requests must run route handler 5x, got {counter[0]}"

    def test_counter_increments_when_excluded_path(self) -> None:
        counter: List[int] = [0]

        def host_app(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
            counter[0] += 1
            start_response("200 OK", [])
            return [b""]

        mw = XSSGuardMiddleware(
            host_app,
            blocking_enabled=True,
            blocking_exclude_paths=["/lab/store"],
        )
        for _ in range(3):
            start_resp, _, _ = make_start_response()
            list(mw(_attack_environ(path="/lab/store"), start_resp))

        assert counter[0] == 3, f"Excluded path requests must run route handler 3x, got {counter[0]}"


# ---------------------------------------------------------------------------
# TEST-10  Legacy DetectionRecord action == None compatibility
# ---------------------------------------------------------------------------

class TestBlockingT10LegacyActionCompatibility:
    def test_getattr_safe_returns_none_for_missing_action(self) -> None:
        """Legacy record instances created before 'action' field was added must
        not cause AttributeError when action is accessed via getattr fallback."""

        class LegacyRecord:
            """Simulate a record pickled / created before action field existed."""
            def __init__(self) -> None:
                self.payload = "old=x"
                self.status = "DETECTED"
                self.matched_rule = None
                self.source = "/"
                self.client_ip = "1.2.3.4"

        legacy = LegacyRecord()
        action_value = getattr(legacy, "action", None)
        assert action_value is None, (
            "Legacy record without 'action' attribute must yield None via getattr fallback"
        )

    def test_current_dataclass_default_action_is_none(self) -> None:
        """Current DetectionRecord dataclass must default action to None for compat."""
        rec = DetectionRecord(
            payload="f=v",
            status="DETECTED",
            matched_rule=None,
            source="/",
            client_ip="1.2.3.4",
        )
        assert rec.action is None, (
            "DetectionRecord default action must be None for backward compat"
        )

    def test_memory_store_preserves_distinct_action_values(self) -> None:
        """Store must correctly persist ALLOWED, BLOCKED, and None records together."""
        store = MemoryStore()
        store.log_detection(DetectionRecord(
            payload="a=1", status="DETECTED", matched_rule="r1", source="/", client_ip="1.1.1.1",
            action=None,  # legacy
        ))
        store.log_detection(DetectionRecord(
            payload="b=2", status="DETECTED", matched_rule="r2", source="/", client_ip="2.2.2.2",
            action="ALLOWED",
        ))
        store.log_detection(DetectionRecord(
            payload="c=3", status="DETECTED", matched_rule="r3", source="/", client_ip="3.3.3.3",
            action="BLOCKED",
        ))

        records = store.recent_detections()
        actions = [getattr(r, "action", None) for r in records]
        assert None in actions
        assert "ALLOWED" in actions
        assert "BLOCKED" in actions
        assert len(records) == 3


# ---------------------------------------------------------------------------
# Additional Safety: XSS payload never reflected raw in 403 body
# ---------------------------------------------------------------------------

class TestBlocking403NoPayloadReflection:
    def test_403_body_does_not_contain_raw_user_payload(self) -> None:
        raw_payload = "<script>alert('XSS-REFLECTION-TEST')</script>"
        import urllib.parse
        qs = f"input={urllib.parse.quote(raw_payload)}"
        env = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/victim",
            "QUERY_STRING": qs,
            "REMOTE_ADDR": "198.51.100.9",
            "wsgi.input": io.BytesIO(b""),
        }

        def host_app(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
            start_response("200 OK", [])
            return [b""]

        mw = XSSGuardMiddleware(host_app, blocking_enabled=True)
        start_resp, _, _ = make_start_response()
        body = b"".join(mw(env, start_resp))

        body_str = body.decode("utf-8", errors="replace")
        assert raw_payload not in body_str, (
            "Raw XSS payload MUST NOT be reflected verbatim into 403 response"
        )
        assert "XSS-REFLECTION-TEST" not in body_str, (
            "User-controlled marker must not appear in 403 page"
        )


# ---------------------------------------------------------------------------
# TEST-11  Custom CSP Report Path Sync — Flask + Blocking ON (E2E)
# ---------------------------------------------------------------------------

class TestCustomCspReportPathSyncE2E:
    """Runtime E2E regression tests for Single-Source-of-Truth CSP report path.

    These tests exercise the FULL stack: Flask app → XSSGuard init_app →
    XSSGuardMiddleware → HTTP Request → Enforcement Decision → Store.

    Critical invariant: When user supplies a custom csp_report_path=...,
    (1) route is registered at custom path, and
    (2) middleware excludes the SAME custom path, and
    (3) POST to that custom path (even if body coincidentally triggers
        detection) still returns HTTP 204 (CSP report endpoint semantics)
        and still writes CspReportRecord into the store.
    """

    def test_flask_custom_csp_path_does_not_return_403_for_detected_body(self) -> None:
        """E2E: custom /security/csp-report endpoint stays HTTP 204 even when
        request body (coincidentally) contains XSS-like patterns, because
        csp_report_path is added to blocking_exclude_paths."""
        import json as _json
        from flask import Flask
        from xssguard.flask_ext import XSSGuard
        from xssguard.storage import MemoryStore

        store = MemoryStore()
        app = Flask(__name__)
        custom_path = "/security/csp-report"
        XSSGuard(
            app,
            store=store,
            blocking_enabled=True,
            csp_report_path=custom_path,
        )

        payload_with_script_token = _json.dumps({
            "csp-report": {
                "document-uri": "https://example.com/",
                "violated-directive": "script-src 'self'",
                "blocked-uri": "inline",
                # Coincidence: CSP report contains "<script>" as part of a
                # blocked source field value.  Middleware must NOT block
                # CSP report endpoints because of detection result on body.
                "script-sample": "<script>alert(1)</script>",
            }
        }).encode("utf-8")

        client = app.test_client()
        resp = client.post(
            custom_path,
            data=payload_with_script_token,
            content_type="application/csp-report",
        )

        assert resp.status_code == 204, (
            f"Custom CSP report path must return HTTP 204, got {resp.status_code}. "
            "Block exclusion desync if 403 appears here."
        )

    def test_default_csp_path_still_stores_report(self) -> None:
        """Regression: default /csp-report path still stores CSP report AND
        returns HTTP 204 while blocking is ON (backward compat check)."""
        import json as _json
        from flask import Flask
        from xssguard.flask_ext import XSSGuard

        store = MemoryStore()
        app = Flask(__name__)
        XSSGuard(app, store=store, blocking_enabled=True)

        valid_report = _json.dumps({
            "csp-report": {
                "document-uri": "https://app.example.com/dashboard",
                "violated-directive": "default-src 'self'",
                "blocked-uri": "https://evil.example.com/bad.js",
            }
        }).encode("utf-8")

        client = app.test_client()
        resp = client.post(
            "/csp-report",
            data=valid_report,
            content_type="application/csp-report",
        )

        assert resp.status_code == 204
        records = store.recent_csp_reports()
        assert len(records) >= 1, "CSP report must be stored; path excluded from blocking"

    def test_custom_csp_path_included_in_middleware_exclusion_set(self) -> None:
        """Static contract check: Flask Extension forwards the SAME custom
        csp_report_path string into XSSGuardMiddleware.blocking_exclude_paths.

        This is the concrete safety invariant: if path is in exclude_set →
        action = ALLOWED → self.app() is called → CSP route view runs.
        If it is NOT in exclude_set → request to custom path could become 403
        if body happens to match a pattern."""
        from flask import Flask
        from xssguard.flask_ext import XSSGuard
        from xssguard.middleware import XSSGuardMiddleware

        custom = "/analytics/csp/_report"
        app = Flask(__name__)
        XSSGuard(app, blocking_enabled=True, csp_report_path=custom)

        mw = app.wsgi_app
        assert isinstance(mw, XSSGuardMiddleware)
        assert custom in mw.blocking_exclude_paths, (
            f"Expected {custom!r} in mw.blocking_exclude_paths={sorted(mw.blocking_exclude_paths)!r}"
        )
