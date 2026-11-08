"""Phase D5.4 — End-to-End Verification of CSP Violation Report Storage.

Validates the full pipeline:
1. Browser/fixture triggers CSP violation on /no-nonce or /wrong-nonce.
2. CSP header contains dynamic nonce and 'report-uri /csp-report;'.
3. Browser-generated CSP violation report is received via POST /csp-report.
4. parse_csp_report() successfully parses the raw request body into CspReportData.
5. BaseStore.log_csp_report() logs the CspReportRecord into storage backend (MemoryStore).
6. BaseStore.recent_csp_reports() retrieves the stored record.
7. Minimal required fields verified:
   - document_uri
   - violated_directive
   - blocked_uri
   - original_policy (contains 'report-uri /csp-report')
8. Endpoint consistently returns HTTP 204 No Content with empty body.
9. Strict isolation: CSP violation reports never pollute DetectionRecord store.
10. Trusted-Script Nonce mechanism and non-rewriting invariants remain strictly intact.
"""

from __future__ import annotations

import json
from typing import Any
import pytest

from tests.e2e.d3_csp_fixture import create_test_app
from xssguard.report import CspReportData, parse_csp_report
from xssguard.storage import BaseStore, CspReportRecord, DetectionRecord, MemoryStore


class TestPhaseD5CspViolationReportStorage:
    """End-to-end verification of browser CSP violation reporting and storage."""

    def test_d5_no_nonce_csp_violation_flow_and_storage(self) -> None:
        """Requirement A through H: /no-nonce violation flow, parsing, and storage."""
        # 1. Setup isolated test app with clean MemoryStore
        store = MemoryStore()
        app = create_test_app(store=store)
        client = app.test_client()

        # [A] Trigger CSP violation condition on /no-nonce
        resp = client.get("/no-nonce")
        assert resp.status_code == 200
        csp_header = resp.headers.get("Content-Security-Policy", "")
        body = resp.get_data(as_text=True)

        # Confirm un-nonced script is rendered as raw HTML
        assert "<script>" in body
        assert 'console.log("D3_NO_NONCE_EXECUTED");' in body
        assert 'nonce="' not in body

        # Confirm CSP header contains report-uri directive and script-src nonce
        assert "default-src 'self'" in csp_header
        assert "script-src 'self' 'nonce-" in csp_header
        assert "report-uri /csp-report" in csp_header

        # [A] Exact Chrome browser CSP violation report payload (as recorded in D5.3)
        chrome_report_payload = {
            "csp-report": {
                "document-uri": "http://127.0.0.1:5001/no-nonce",
                "referrer": "",
                "violated-directive": "script-src-elem",
                "effective-directive": "script-src-elem",
                "original-policy": csp_header,
                "disposition": "enforce",
                "blocked-uri": "inline",
                "line-number": 42,
                "column-number": 9,
                "source-file": "http://127.0.0.1:5001/no-nonce",
                "status-code": 200,
                "script-sample": "",
            }
        }
        raw_report_bytes = json.dumps(chrome_report_payload).encode("utf-8")

        # [C] Direct verification: parse_csp_report() produces valid CspReportData
        parsed = parse_csp_report(raw_report_bytes)
        assert parsed is not None
        assert isinstance(parsed, CspReportData)
        assert parsed.document_uri == "http://127.0.0.1:5001/no-nonce"
        assert parsed.violated_directive == "script-src-elem"
        assert parsed.blocked_uri == "inline"
        assert parsed.original_policy == csp_header
        # [G] original_policy must contain 'report-uri /csp-report'
        assert "report-uri /csp-report" in parsed.original_policy
        assert isinstance(parsed.raw, dict)

        # [B & H] Dispatch POST /csp-report to endpoint
        post_resp = client.post(
            "/csp-report",
            data=raw_report_bytes,
            content_type="application/csp-report",
            environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
        )
        assert post_resp.status_code == 204
        assert post_resp.get_data() == b""

        # [D & E] Retrieve logged record from store via recent_csp_reports()
        reports = store.recent_csp_reports()
        assert len(reports) == 1
        rec = reports[0]
        assert isinstance(rec, CspReportRecord)

        # [F] Verify minimal fields on stored record
        assert rec.document_uri == "http://127.0.0.1:5001/no-nonce"
        assert rec.violated_directive == "script-src-elem"
        assert rec.blocked_uri == "inline"
        assert rec.client_ip == "127.0.0.1"
        assert rec.created_at is not None

    def test_d5_wrong_nonce_csp_violation_flow_and_storage(self) -> None:
        """Requirement A through H: /wrong-nonce violation flow, parsing, and storage."""
        store = MemoryStore()
        app = create_test_app(store=store)
        client = app.test_client()

        # [A] Trigger CSP violation condition on /wrong-nonce
        resp = client.get("/wrong-nonce")
        assert resp.status_code == 200
        csp_header = resp.headers.get("Content-Security-Policy", "")
        body = resp.get_data(as_text=True)

        assert '<script nonce="invalid-test-nonce">' in body
        assert 'console.log("D3_WRONG_NONCE_EXECUTED");' in body
        assert "report-uri /csp-report" in csp_header

        # Browser reports violation for invalid nonce attribute
        wrong_nonce_report = {
            "csp-report": {
                "document-uri": "http://127.0.0.1:5001/wrong-nonce",
                "violated-directive": "script-src-elem",
                "blocked-uri": "inline",
                "original-policy": csp_header,
                "disposition": "enforce",
            }
        }
        raw_bytes = json.dumps(wrong_nonce_report).encode("utf-8")

        # [C] parse_csp_report verification
        parsed = parse_csp_report(raw_bytes)
        assert parsed is not None
        assert parsed.document_uri == "http://127.0.0.1:5001/wrong-nonce"
        assert parsed.violated_directive == "script-src-elem"
        assert parsed.blocked_uri == "inline"
        assert parsed.original_policy == csp_header
        assert "report-uri /csp-report" in parsed.original_policy

        # [B & H] POST /csp-report
        post_resp = client.post(
            "/csp-report",
            data=raw_bytes,
            content_type="application/csp-report",
            environ_overrides={"REMOTE_ADDR": "192.168.1.100"},
        )
        assert post_resp.status_code == 204
        assert post_resp.get_data() == b""

        # [D, E, F] Check store
        reports = store.recent_csp_reports()
        assert len(reports) == 1
        rec = reports[0]
        assert rec.document_uri == "http://127.0.0.1:5001/wrong-nonce"
        assert rec.violated_directive == "script-src-elem"
        assert rec.blocked_uri == "inline"
        assert rec.client_ip == "192.168.1.100"
        assert rec.created_at is not None

    def test_d5_multiple_reports_ordered_newest_first(self) -> None:
        """Validate multiple sequential CSP reports are stored and retrieved newest-first."""
        store = MemoryStore()
        app = create_test_app(store=store)
        client = app.test_client()

        # Send report 1
        payload1 = {
            "csp-report": {
                "document-uri": "http://127.0.0.1:5001/no-nonce",
                "violated-directive": "script-src",
                "blocked-uri": "inline",
            }
        }
        client.post("/csp-report", data=json.dumps(payload1), content_type="application/csp-report")

        # Send report 2
        payload2 = {
            "csp-report": {
                "document-uri": "http://127.0.0.1:5001/wrong-nonce",
                "violated-directive": "script-src-elem",
                "blocked-uri": "inline",
            }
        }
        client.post("/csp-report", data=json.dumps(payload2), content_type="application/csp-report")

        reports = store.recent_csp_reports()
        assert len(reports) == 2
        # Newest first
        assert reports[0].document_uri == "http://127.0.0.1:5001/wrong-nonce"
        assert reports[1].document_uri == "http://127.0.0.1:5001/no-nonce"

    def test_d5_strict_storage_isolation_no_detection_pollution(self) -> None:
        """Validate CSP reports never log to DetectionRecord store (rule.md S9)."""
        store = MemoryStore()
        app = create_test_app(store=store)
        client = app.test_client()

        payload = {
            "csp-report": {
                "document-uri": "http://127.0.0.1:5001/no-nonce",
                "violated-directive": "script-src",
                "blocked-uri": "inline",
            }
        }
        client.post("/csp-report", data=json.dumps(payload), content_type="application/csp-report")

        # Zero detection records logged
        assert len(store.recent_detections()) == 0
        assert len(store.recent_csp_reports()) == 1

    def test_d5_invalid_report_always_returns_204_and_not_logged(self) -> None:
        """Validate invalid/malformed reports return HTTP 204 and log zero records."""
        store = MemoryStore()
        app = create_test_app(store=store)
        client = app.test_client()

        # Malformed JSON
        r1 = client.post("/csp-report", data=b"MALFORMED_JSON_NOT_DICT", content_type="application/csp-report")
        assert r1.status_code == 204
        assert len(store.recent_csp_reports()) == 0

        # Empty body
        r2 = client.post("/csp-report", data=b"", content_type="application/csp-report")
        assert r2.status_code == 204
        assert len(store.recent_csp_reports()) == 0

        # JSON array instead of object
        r3 = client.post("/csp-report", data=b"[]", content_type="application/csp-report")
        assert r3.status_code == 204
        assert len(store.recent_csp_reports()) == 0

    def test_d5_trusted_script_nonce_and_headers_unaffected(self) -> None:
        """Verify Trusted-Script Nonce invariants and absence of forbidden reporting features."""
        store = MemoryStore()
        app = create_test_app(store=store)
        client = app.test_client()

        resp = client.get("/no-nonce")
        csp = resp.headers.get("Content-Security-Policy", "")

        # Trusted-Script Nonce present
        assert "script-src 'self' 'nonce-" in csp
        # report-uri present
        assert "report-uri /csp-report" in csp
        # Forbidden features strictly absent
        assert "report-to" not in csp
        assert "Reporting-Endpoints" not in resp.headers


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
