"""Unit tests for xssguard.report module.

Validates:
- CspReportData frozen dataclass
- parse_csp_report() with direct JSON report
- parse_csp_report() with wrapped {"csp-report": {...}} format
- parse_csp_report() with missing fields (evaluates to None per contract)
- parse_csp_report() with invalid JSON (returns None)
- parse_csp_report() with non-object JSON (returns None)
- Preservation of the raw report payload
- Architectural isolation and public API surface
"""

import ast
import dataclasses
import inspect
from typing import Any

import pytest

import xssguard.report as rep
from xssguard.report import CspReportData, parse_csp_report


class TestCspReportDataDataclass:
    """Test CspReportData dataclass instantiation and immutability."""

    def test_instantiation_full(self) -> None:
        data = CspReportData(
            document_uri="https://example.com/page",
            violated_directive="script-src 'self'",
            blocked_uri="inline",
            original_policy="default-src 'none'; script-src 'self'",
            raw={"document-uri": "https://example.com/page"},
        )
        assert data.document_uri == "https://example.com/page"
        assert data.violated_directive == "script-src 'self'"
        assert data.blocked_uri == "inline"
        assert data.original_policy == "default-src 'none'; script-src 'self'"
        assert data.raw == {"document-uri": "https://example.com/page"}

    def test_is_frozen_dataclass(self) -> None:
        assert dataclasses.is_dataclass(CspReportData)
        data = CspReportData(
            document_uri="https://example.com",
            violated_directive="script-src",
            blocked_uri="eval",
            original_policy="default-src 'none'",
            raw={},
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            data.document_uri = "https://other.com"  # type: ignore[misc]

        with pytest.raises(dataclasses.FrozenInstanceError):
            data.blocked_uri = "modified"  # type: ignore[misc]


class TestParseCspReportDirect:
    """Test parse_csp_report with direct JSON object (dash and underscore keys)."""

    def test_direct_report_dash_keys(self) -> None:
        raw = b"""{
            "document-uri": "https://example.com/profile",
            "violated-directive": "script-src 'nonce-abc'",
            "blocked-uri": "https://attacker.com/evil.js",
            "original-policy": "default-src 'self'; script-src 'nonce-abc'"
        }"""
        res = parse_csp_report(raw)
        assert res is not None
        assert res.document_uri == "https://example.com/profile"
        assert res.violated_directive == "script-src 'nonce-abc'"
        assert res.blocked_uri == "https://attacker.com/evil.js"
        assert res.original_policy == "default-src 'self'; script-src 'nonce-abc'"
        assert isinstance(res.raw, dict)
        assert res.raw["document-uri"] == "https://example.com/profile"

    def test_direct_report_underscore_keys(self) -> None:
        raw = b"""{
            "document_uri": "https://example.com/dashboard",
            "violated_directive": "img-src 'self'",
            "blocked_uri": "https://evil.com/tracker.png",
            "original_policy": "default-src 'self'"
        }"""
        res = parse_csp_report(raw)
        assert res is not None
        assert res.document_uri == "https://example.com/dashboard"
        assert res.violated_directive == "img-src 'self'"
        assert res.blocked_uri == "https://evil.com/tracker.png"
        assert res.original_policy == "default-src 'self'"


class TestParseCspReportWrapped:
    """Test parse_csp_report with standard browser-wrapped {"csp-report": {...}} format."""

    def test_wrapped_report_standard(self) -> None:
        raw = b"""{
            "csp-report": {
                "document-uri": "https://example.com/cart",
                "violated-directive": "script-src",
                "blocked-uri": "inline",
                "original-policy": "default-src 'self'; script-src 'nonce-xyz'"
            }
        }"""
        res = parse_csp_report(raw)
        assert res is not None
        assert res.document_uri == "https://example.com/cart"
        assert res.violated_directive == "script-src"
        assert res.blocked_uri == "inline"
        assert res.original_policy == "default-src 'self'; script-src 'nonce-xyz'"
        # raw points to the inner object
        assert res.raw["document-uri"] == "https://example.com/cart"
        assert "csp-report" not in res.raw

    def test_wrapped_report_with_extra_fields(self) -> None:
        raw = b"""{
            "csp-report": {
                "document-uri": "https://example.com/blog",
                "violated-directive": "style-src",
                "blocked-uri": "https://fonts.googleapis.com",
                "line-number": 42,
                "column-number": 10,
                "source-file": "https://example.com/app.js"
            }
        }"""
        res = parse_csp_report(raw)
        assert res is not None
        assert res.document_uri == "https://example.com/blog"
        assert res.violated_directive == "style-src"
        assert res.blocked_uri == "https://fonts.googleapis.com"
        assert res.original_policy is None
        assert res.raw["line-number"] == 42


class TestParseCspReportMissingFields:
    """Test parse_csp_report when fields are missing or empty."""

    def test_partial_fields_returns_none_for_missing(self) -> None:
        raw = b"""{
            "document-uri": "https://example.com/checkout",
            "blocked-uri": "https://malicious.com/pay.js"
        }"""
        res = parse_csp_report(raw)
        assert res is not None
        assert res.document_uri == "https://example.com/checkout"
        assert res.violated_directive is None
        assert res.blocked_uri == "https://malicious.com/pay.js"
        assert res.original_policy is None

    def test_empty_json_object(self) -> None:
        res = parse_csp_report(b"{}")
        assert res is not None
        assert res.document_uri is None
        assert res.violated_directive is None
        assert res.blocked_uri is None
        assert res.original_policy is None
        assert res.raw == {}

    def test_wrapped_empty_csp_report_object(self) -> None:
        res = parse_csp_report(b'{"csp-report": {}}')
        assert res is not None
        assert res.document_uri is None
        assert res.violated_directive is None
        assert res.blocked_uri is None
        assert res.original_policy is None
        assert res.raw == {}


class TestParseCspReportInvalidInput:
    """Test parse_csp_report with malformed JSON or non-object types."""

    @pytest.mark.parametrize(
        "invalid_json",
        [
            b"not a json string",
            b"{bad json: 123",
            b"",
            b"   \n\t  ",
            b"{\"key\": undefined}",
            b"\x80\x81\x82 invalid utf-8",
        ],
    )
    def test_malformed_json_returns_none(self, invalid_json: bytes) -> None:
        assert parse_csp_report(invalid_json) is None

    @pytest.mark.parametrize(
        "non_object_json",
        [
            b"[]",
            b'["a", "b", "c"]',
            b'"just a string"',
            b"123",
            b"45.67",
            b"true",
            b"false",
            b"null",
        ],
    )
    def test_non_object_json_returns_none(self, non_object_json: bytes) -> None:
        assert parse_csp_report(non_object_json) is None


class TestReportArchitecturalIsolation:
    """Ensure report module strictly exposes only CspReportData and parse_csp_report."""

    def test_public_api_surface(self) -> None:
        tree = ast.parse(inspect.getsource(rep))
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
        assert (defined_classes | defined_funcs) == {"CspReportData", "parse_csp_report"}
        assert rep.__all__ == ["CspReportData", "parse_csp_report"]

    def test_no_forbidden_framework_imports(self) -> None:
        tree = ast.parse(inspect.getsource(rep))
        imports = []
        for n in tree.body:
            if isinstance(n, ast.Import):
                for a in n.names:
                    imports.append(a.name)
            elif isinstance(n, ast.ImportFrom) and n.module:
                imports.append(n.module)

        forbidden_prefixes = (
            "flask",
            "sqlalchemy",
            "requests",
            "django",
            "bottle",
            "xssguard.detector",
            "xssguard.nonce",
            "xssguard.storage",
            "xssguard.middleware",
            "xssguard.flask_ext",
            "xssguard.dashboard",
        )
        for imp in imports:
            assert not imp.startswith(forbidden_prefixes), f"Forbidden import: {imp}"
