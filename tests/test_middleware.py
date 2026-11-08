"""Unit tests for xssguard.middleware module.

Validates:
- Request body reading and replay back to environ["wsgi.input"]
- Detection logging to BaseStore / MemoryStore (query string, form, JSON)
- Formatting of DetectionRecord (payload="field=value", source, client_ip)
- Safe requests produce zero detection records
- Dynamic CSP header insertion and CSPRNG nonce uniqueness
- Nonce consistency: CSP header nonce matches environ["xssguard.nonce"]
- Trusted-Script Nonce: nonce exposed via WSGI environ without automatic HTML rewriting
- Response body preservation: HTML and non-HTML bodies passed through unmodified
- Existing nonce preservation and un-nonced script tags left intact
- Multiple script tags in a single document remain untouched
- Content-Length preservation: Content-Length preserved since body is unmodified
- WSGI iterable close() lifecycle preservation
- Strict absence of IP blocking or rate limiting mechanisms
- Module architectural isolation and clean public API
"""

import ast
import inspect
import io
import re
from typing import Any, Iterable, List, Tuple
from wsgiref.types import StartResponse, WSGIApplication

import pytest

import xssguard.middleware as mw_module
from xssguard.middleware import XSSGuardMiddleware
from xssguard.nonce import build_csp_header
from xssguard.storage import BaseStore, DetectionRecord, MemoryStore


# ---------------------------------------------------------------------------
# Helpers & Dummy WSGI Apps
# ---------------------------------------------------------------------------

def make_start_response() -> Tuple[StartResponse, List[str], List[Tuple[str, str]]]:
    """Create a mock start_response capturing status and headers."""
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
    """Retrieve header value by case-insensitive name."""
    for k, v in headers:
        if k.lower() == name.lower():
            return v
    return ""


# ---------------------------------------------------------------------------
# Test Suites
# ---------------------------------------------------------------------------

class TestRequestBodyReplay:
    """Verify middleware replays wsgi.input so the host application receives full body."""

    def test_form_body_replayed_to_application(self) -> None:
        body_received: List[bytes] = []

        def host_app(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
            wsgi_input = environ.get("wsgi.input")
            if wsgi_input:
                body_received.append(wsgi_input.read())
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"OK"]

        store = MemoryStore()
        mw = XSSGuardMiddleware(host_app, store=store)

        body = b"username=alice&message=hello+world"
        environ = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": "/submit",
            "REMOTE_ADDR": "192.168.1.10",
            "CONTENT_LENGTH": str(len(body)),
            "CONTENT_TYPE": "application/x-www-form-urlencoded",
            "wsgi.input": io.BytesIO(body),
        }

        start_resp, status, headers = make_start_response()
        response_iter = mw(environ, start_resp)
        response_body = b"".join(response_iter)

        assert response_body == b"OK"
        assert body_received == [body]
        assert len(store.recent_detections()) == 0

    def test_json_body_replayed_to_application(self) -> None:
        body_received: List[bytes] = []

        def host_app(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
            wsgi_input = environ.get("wsgi.input")
            if wsgi_input:
                body_received.append(wsgi_input.read())
            start_response("200 OK", [("Content-Type", "application/json")])
            return [b'{"status": "ok"}']

        store = MemoryStore()
        mw = XSSGuardMiddleware(host_app, store=store)

        json_bytes = b'{"name": "Bob", "active": true}'
        environ = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": "/api/users",
            "REMOTE_ADDR": "10.0.0.5",
            "CONTENT_LENGTH": str(len(json_bytes)),
            "CONTENT_TYPE": "application/json",
            "wsgi.input": io.BytesIO(json_bytes),
        }

        start_resp, _, _ = make_start_response()
        list(mw(environ, start_resp))

        assert body_received == [json_bytes]


class TestDetectionLogging:
    """Verify detector results are logged to BaseStore with contract record schema."""

    def test_query_string_xss_detection(self) -> None:
        def echo_app(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"OK"]

        store = MemoryStore()
        mw = XSSGuardMiddleware(echo_app, store=store)

        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/search",
            "QUERY_STRING": "q=%3Cscript%3Ealert(1)%3C/script%3E",
            "REMOTE_ADDR": "1.2.3.4",
            "wsgi.input": io.BytesIO(b""),
        }

        start_resp, _, _ = make_start_response()
        list(mw(environ, start_resp))

        records = store.recent_detections()
        assert len(records) == 1
        rec = records[0]
        assert rec.status == "DETECTED"
        assert rec.source == "/search"
        assert rec.client_ip == "1.2.3.4"
        assert rec.payload == "q=<script>alert(1)</script>"
        assert rec.matched_rule is not None

    def test_form_body_xss_detection(self) -> None:
        def echo_app(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"OK"]

        store = MemoryStore()
        mw = XSSGuardMiddleware(echo_app, store=store)

        body = b"comment=%3Cscript%3Edocument.cookie%3C/script%3E"
        environ = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": "/comments/create",
            "REMOTE_ADDR": "5.6.7.8",
            "CONTENT_LENGTH": str(len(body)),
            "CONTENT_TYPE": "application/x-www-form-urlencoded",
            "wsgi.input": io.BytesIO(body),
        }

        start_resp, _, _ = make_start_response()
        list(mw(environ, start_resp))

        records = store.recent_detections()
        assert len(records) == 1
        rec = records[0]
        assert rec.status == "DETECTED"
        assert rec.source == "/comments/create"
        assert rec.client_ip == "5.6.7.8"
        assert rec.payload == "comment=<script>document.cookie</script>"

    def test_json_body_xss_detection(self) -> None:
        def echo_app(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
            start_response("200 OK", [("Content-Type", "application/json")])
            return [b'{"status": "ok"}']

        store = MemoryStore()
        mw = XSSGuardMiddleware(echo_app, store=store)

        body = b'{"profile": {"bio": "<img src=x onerror=alert(1)>"}}'
        environ = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": "/api/profile",
            "REMOTE_ADDR": "9.10.11.12",
            "CONTENT_LENGTH": str(len(body)),
            "CONTENT_TYPE": "application/json",
            "wsgi.input": io.BytesIO(body),
        }

        start_resp, _, _ = make_start_response()
        list(mw(environ, start_resp))

        records = store.recent_detections()
        assert len(records) == 1
        rec = records[0]
        assert rec.status == "DETECTED"
        assert rec.source == "/api/profile"
        assert rec.client_ip == "9.10.11.12"
        assert rec.payload == "profile.bio=<img src=x onerror=alert(1)>"

    def test_safe_request_generates_zero_detection_records(self) -> None:
        def echo_app(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"OK"]

        store = MemoryStore()
        mw = XSSGuardMiddleware(echo_app, store=store)

        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/home",
            "QUERY_STRING": "page=1&sort=asc&q=valid+term",
            "REMOTE_ADDR": "192.168.1.1",
            "wsgi.input": io.BytesIO(b""),
        }

        start_resp, _, _ = make_start_response()
        list(mw(environ, start_resp))

        assert store.recent_detections() == []


class TestCspHeaderAndNonce:
    """Verify dynamic CSP header generation and nonce properties."""

    def test_csp_header_present_with_dynamic_nonce(self) -> None:
        def dummy_app(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
            start_response("200 OK", [("Content-Type", "text/html")])
            return [b"<h1>Hello</h1>"]

        mw = XSSGuardMiddleware(dummy_app)
        start_resp, _, headers = make_start_response()
        list(mw({"wsgi.input": io.BytesIO(b"")}, start_resp))

        csp = extract_header(headers, "Content-Security-Policy")
        assert csp != ""
        assert "script-src" in csp
        assert "report-uri /csp-report" in csp
        match = re.search(r"'nonce-([A-Za-z0-9_-]+)'", csp)
        assert match is not None
        nonce = match.group(1)
        assert len(nonce) >= 16

    def test_default_csp_header_contains_report_uri(self) -> None:
        """Verify default CSP header from build_csp_header contains report-uri directive."""
        csp = build_csp_header("testnonce")
        assert "report-uri /csp-report" in csp

    def test_dynamic_nonce_unique_per_request(self) -> None:
        def dummy_app(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
            start_response("200 OK", [("Content-Type", "text/html")])
            return [b"<h1>Hello</h1>"]

        mw = XSSGuardMiddleware(dummy_app)

        start_resp1, _, headers1 = make_start_response()
        list(mw({"wsgi.input": io.BytesIO(b"")}, start_resp1))
        csp1 = extract_header(headers1, "Content-Security-Policy")
        nonce1 = re.search(r"'nonce-([^']+)'", csp1).group(1)  # type: ignore[union-attr]

        start_resp2, _, headers2 = make_start_response()
        list(mw({"wsgi.input": io.BytesIO(b"")}, start_resp2))
        csp2 = extract_header(headers2, "Content-Security-Policy")
        nonce2 = re.search(r"'nonce-([^']+)'", csp2).group(1)  # type: ignore[union-attr]

        assert nonce1 != nonce2, f"Nonce must be unique per request: {nonce1} vs {nonce2}"


class TestBuildCspHeaderP1NonceInvariant:
    """Validate build_csp_header() ensures 'nonce-{nonce}' resides in script-src for all template variants."""

    @staticmethod
    def _parse_directives(csp: str) -> dict[str, list[str]]:
        """Parse CSP header into directive_name -> list of tokens."""
        directives: dict[str, list[str]] = {}
        for part in csp.split(";"):
            part = part.strip()
            if not part:
                continue
            tokens = part.split()
            directives.setdefault(tokens[0].lower(), []).extend(tokens[1:])
        return directives

    @staticmethod
    def _count_directive(csp: str, d_name: str) -> int:
        """Count occurrences of a directive name."""
        count = 0
        for part in csp.split(";"):
            tokens = part.strip().split()
            if tokens and tokens[0].lower() == d_name.lower():
                count += 1
        return count

    def test_case_1_default_template(self) -> None:
        csp = build_csp_header("abc")
        directives = self._parse_directives(csp)
        assert "script-src" in directives
        assert "'nonce-abc'" in directives["script-src"]
        assert "'self'" in directives["script-src"]
        assert self._count_directive(csp, "script-src") == 1

    def test_case_2_custom_template_with_placeholder(self) -> None:
        tmpl = "default-src 'self'; script-src {script_src_tokens}; object-src 'none';"
        csp = build_csp_header("abc", policy_template=tmpl)
        directives = self._parse_directives(csp)
        assert "script-src" in directives
        assert "'nonce-abc'" in directives["script-src"]
        assert self._count_directive(csp, "script-src") == 1

    def test_case_3_custom_template_without_script_src(self) -> None:
        tmpl = "default-src 'self'; object-src 'none';"
        csp = build_csp_header("abc", policy_template=tmpl)
        directives = self._parse_directives(csp)
        assert "script-src" in directives
        assert "'nonce-abc'" in directives["script-src"]
        assert self._count_directive(csp, "script-src") == 1

    def test_case_4_custom_template_with_script_src_no_placeholder(self) -> None:
        tmpl = "default-src 'self'; script-src 'self'; object-src 'none';"
        csp = build_csp_header("abc", policy_template=tmpl)
        directives = self._parse_directives(csp)
        assert "script-src" in directives
        assert "'nonce-abc'" in directives["script-src"]
        assert "'self'" in directives["script-src"]
        assert self._count_directive(csp, "script-src") == 1

    def test_case_5_extra_script_src(self) -> None:
        csp = build_csp_header("abc", extra_script_src="https://cdn.example.com")
        directives = self._parse_directives(csp)
        assert "script-src" in directives
        assert "'nonce-abc'" in directives["script-src"]
        assert "https://cdn.example.com" in directives["script-src"]
        assert self._count_directive(csp, "script-src") == 1

    def test_case_6_custom_template_and_extra_script_src(self) -> None:
        tmpl = "default-src 'self'; script-src 'unsafe-inline'; object-src 'none';"
        csp = build_csp_header("abc", extra_script_src="https://cdn.example.com", policy_template=tmpl)
        directives = self._parse_directives(csp)
        assert "script-src" in directives
        assert "'nonce-abc'" in directives["script-src"]
        assert "https://cdn.example.com" in directives["script-src"]
        assert "'unsafe-inline'" in directives["script-src"]
        assert self._count_directive(csp, "script-src") == 1

    def test_duplicate_identical_nonce_not_added(self) -> None:
        tmpl = "default-src 'self'; script-src 'self' 'nonce-abc'; object-src 'none';"
        csp = build_csp_header("abc", policy_template=tmpl)
        directives = self._parse_directives(csp)
        assert directives["script-src"].count("'nonce-abc'") == 1
        assert self._count_directive(csp, "script-src") == 1

    def test_old_different_nonce_preserved(self) -> None:
        tmpl = "default-src 'self'; script-src 'self' 'nonce-old'; object-src 'none';"
        csp = build_csp_header("abc", policy_template=tmpl)
        directives = self._parse_directives(csp)
        assert "'nonce-old'" in directives["script-src"]
        assert "'nonce-abc'" in directives["script-src"]
        assert self._count_directive(csp, "script-src") == 1

    def test_boundary_script_src_elem_and_attr_not_treated_as_script_src(self) -> None:
        tmpl = "default-src 'self'; script-src-elem 'self'; script-src-attr 'none';"
        csp = build_csp_header("abc", policy_template=tmpl)
        directives = self._parse_directives(csp)
        assert "'nonce-abc'" not in directives.get("script-src-elem", [])
        assert "'nonce-abc'" not in directives.get("script-src-attr", [])
        assert "script-src" in directives
        assert "'nonce-abc'" in directives["script-src"]
        assert self._count_directive(csp, "script-src") == 1


class TestTrustedScriptNonceAndBodyPreservation:
    """Verify Trusted-Script Nonce WSGI exposure, CSP matching, and body preservation."""

    def test_nonce_exposed_to_wsgi_environ_before_host_runs(self) -> None:
        """Verify middleware generates nonce and sets environ['xssguard.nonce'] before calling host."""
        captured_environ_nonce = []

        def app(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
            captured_environ_nonce.append(environ.get("xssguard.nonce"))
            start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
            return [b"<h1>Hello</h1>"]

        mw = XSSGuardMiddleware(app)
        start_resp, _, headers = make_start_response()
        list(mw({"wsgi.input": io.BytesIO(b"")}, start_resp))

        assert len(captured_environ_nonce) == 1
        nonce = captured_environ_nonce[0]
        assert nonce is not None and len(nonce) >= 16

        csp = extract_header(headers, "Content-Security-Policy")
        assert f"'nonce-{nonce}'" in csp

    def test_nonce_matches_csp_header_and_host_explicit_usage(self) -> None:
        """Nonce in CSP header exactly matches nonce used explicitly by host application."""
        def app(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
            nonce = environ.get("xssguard.nonce", "")
            body = f'<script nonce="{nonce}">alert(1)</script>'.encode("utf-8")
            start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
            return [body]

        mw = XSSGuardMiddleware(app)
        start_resp, _, headers = make_start_response()
        output_html = b"".join(mw({"wsgi.input": io.BytesIO(b"")}, start_resp))

        csp = extract_header(headers, "Content-Security-Policy")
        nonce = re.search(r"'nonce-([^']+)'", csp).group(1)  # type: ignore[union-attr]

        expected_tag = f'<script nonce="{nonce}">alert(1)</script>'.encode("utf-8")
        assert output_html == expected_tag

    def test_response_body_is_not_rewritten_by_middleware(self) -> None:
        """Un-nonced script tags in host response are NOT automatically injected with nonce."""
        html_input = b"<html><head><script>alert(1)</script></head><body>hi</body></html>"

        def app(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
            start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
            return [html_input]

        mw = XSSGuardMiddleware(app)
        start_resp, _, headers = make_start_response()
        output_html = b"".join(mw({"wsgi.input": io.BytesIO(b"")}, start_resp))

        # Body must remain strictly unmodified
        assert output_html == html_input
        assert b"nonce=" not in output_html

        # But CSP header still has a dynamic nonce
        csp = extract_header(headers, "Content-Security-Policy")
        assert "'nonce-" in csp

    def test_existing_nonce_double_quotes_preserved(self) -> None:
        """Existing double-quoted nonce in HTML response is preserved without modification."""
        html_input = b'<html><head><script nonce="pre-existing">console.log("ok")</script></head></html>'

        def app(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
            start_response("200 OK", [("Content-Type", "text/html")])
            return [html_input]

        mw = XSSGuardMiddleware(app)
        start_resp, _, headers = make_start_response()
        output_html = b"".join(mw({"wsgi.input": io.BytesIO(b"")}, start_resp))

        assert output_html == html_input
        assert output_html.count(b"nonce=") == 1

    def test_existing_nonce_single_quotes_preserved(self) -> None:
        """Existing single-quoted nonce in HTML response is preserved without modification."""
        html_input = b"<html><head><script nonce='existing-single'>init()</script></head></html>"

        def app(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
            start_response("200 OK", [("Content-Type", "text/html")])
            return [html_input]

        mw = XSSGuardMiddleware(app)
        start_resp, _, _ = make_start_response()
        output_html = b"".join(mw({"wsgi.input": io.BytesIO(b"")}, start_resp))

        assert output_html == html_input
        assert output_html.count(b"nonce") == 1

    def test_attribute_differentiation_data_nonce_unmodified(self) -> None:
        """Tags with data-nonce are not modified or given automatic nonce."""
        html_input = b'<script data-nonce="sample">alert(1)</script>'

        def app(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
            start_response("200 OK", [("Content-Type", "text/html")])
            return [html_input]

        mw = XSSGuardMiddleware(app)
        start_resp, _, headers = make_start_response()
        output_html = b"".join(mw({"wsgi.input": io.BytesIO(b"")}, start_resp))

        assert output_html == html_input
        assert b' nonce=' not in output_html

    def test_attribute_differentiation_nonce_test_and_mynonce_unmodified(self) -> None:
        """Tags with nonce-like attribute names are not modified by middleware."""
        html_input = b'<script nonce-test="123" mynonce="456">alert(1)</script>'

        def app(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
            start_response("200 OK", [("Content-Type", "text/html")])
            return [html_input]

        mw = XSSGuardMiddleware(app)
        start_resp, _, headers = make_start_response()
        output_html = b"".join(mw({"wsgi.input": io.BytesIO(b"")}, start_resp))

        assert output_html == html_input
        assert b' nonce=' not in output_html

    def test_multiple_script_tags_unmodified(self) -> None:
        """Multiple script tags are preserved verbatim without automatic nonce injection."""
        html_input = (
            b'<html><head>\n'
            b'<script src="/app.js"></script>\n'
            b'<script nonce="already-set">init()</script>\n'
            b'<script data-nonce="val">track()</script>\n'
            b'</head></html>'
        )

        def app(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
            start_response("200 OK", [("Content-Type", "text/html")])
            return [html_input]

        mw = XSSGuardMiddleware(app)
        start_resp, _, headers = make_start_response()
        output_html = b"".join(mw({"wsgi.input": io.BytesIO(b"")}, start_resp))

        assert output_html == html_input

    def test_nonce_is_request_scoped_and_unique_across_requests(self) -> None:
        """Verify sequential requests produce unique nonces in environ and CSP."""
        captured_nonces = []

        def app(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
            captured_nonces.append(environ.get("xssguard.nonce"))
            start_response("200 OK", [("Content-Type", "text/html")])
            return [b"OK"]

        mw = XSSGuardMiddleware(app)
        for _ in range(5):
            start_resp, _, headers = make_start_response()
            list(mw({"wsgi.input": io.BytesIO(b"")}, start_resp))
            csp = extract_header(headers, "Content-Security-Policy")
            match = re.search(r"'nonce-([^']+)'", csp)
            assert match is not None
            assert match.group(1) == captured_nonces[-1]

        assert len(captured_nonces) == 5
        assert len(set(captured_nonces)) == 5


class TestNonHtmlAndContentLength:
    """Verify non-HTML bodies are untouched and Content-Length is handled safely."""

    def test_non_html_response_body_strictly_unmodified(self) -> None:
        json_body = b'{"status": "ok", "mock_tag": "<script>alert(1)</script>"}'

        def app(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
            start_response(
                "200 OK",
                [
                    ("Content-Type", "application/json"),
                    ("Content-Length", str(len(json_body))),
                ],
            )
            return [json_body]

        mw = XSSGuardMiddleware(app)
        start_resp, _, headers = make_start_response()
        output_body = b"".join(mw({"wsgi.input": io.BytesIO(b"")}, start_resp))

        assert output_body == json_body
        assert extract_header(headers, "Content-Type") == "application/json"
        assert extract_header(headers, "Content-Length") == str(len(json_body))
        # CSP header is still present on non-HTML responses
        assert extract_header(headers, "Content-Security-Policy") != ""

    def test_content_length_preserved_on_html_response(self) -> None:
        """Content-Length is preserved on HTML responses because body is not rewritten."""
        raw_html = b"<html><head><script>alert(1)</script></head></html>"

        def app(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
            start_response(
                "200 OK",
                [
                    ("Content-Type", "text/html"),
                    ("Content-Length", str(len(raw_html))),
                ],
            )
            return [raw_html]

        mw = XSSGuardMiddleware(app)
        start_resp, _, headers = make_start_response()
        output_html = b"".join(mw({"wsgi.input": io.BytesIO(b"")}, start_resp))

        cl = extract_header(headers, "Content-Length")
        assert cl == str(len(raw_html)), "Content-Length must be preserved because body is not modified"
        assert output_html == raw_html


class TestWsgiLifecycle:
    """Verify WSGI iterable close() is called properly."""

    def test_close_called_on_host_iterable_for_html(self) -> None:
        closed = {"val": False}

        class CloseableIterable:
            def __iter__(self) -> Iterable[bytes]:
                yield b"<html><head><script>foo()</script></head></html>"

            def close(self) -> None:
                closed["val"] = True

        def app(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
            start_response("200 OK", [("Content-Type", "text/html")])
            return CloseableIterable()

        mw = XSSGuardMiddleware(app)
        start_resp, _, _ = make_start_response()
        res_iter = mw({"wsgi.input": io.BytesIO(b"")}, start_resp)
        list(res_iter)
        assert hasattr(res_iter, "close")
        res_iter.close()

        assert closed["val"] is True, "Host application iterable close() must be callable on returned iterable"

    def test_close_callable_on_non_html_iterable(self) -> None:
        closed = {"val": False}

        class CloseableIterable:
            def __iter__(self) -> Iterable[bytes]:
                yield b"Plain text"

            def close(self) -> None:
                closed["val"] = True

        def app(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
            start_response("200 OK", [("Content-Type", "text/plain")])
            return CloseableIterable()

        mw = XSSGuardMiddleware(app)
        start_resp, _, _ = make_start_response()
        res_iter = mw({"wsgi.input": io.BytesIO(b"")}, start_resp)
        assert hasattr(res_iter, "close")
        res_iter.close()
        assert closed["val"] is True


class TestAbsenceOfIpBlocking:
    """Verify strict adherence to zero IP blocking / rate limiting rules."""

    def test_no_ip_blocking_attributes_or_methods(self) -> None:
        mw = XSSGuardMiddleware(lambda e, s: [b""])
        forbidden_attributes = [
            "_blocked_ips",
            "blocked_ips",
            "block_ip",
            "is_blocked",
            "_detection_counts",
            "block_after_n_detections",
            "blacklist",
            "whitelist",
        ]
        for attr in forbidden_attributes:
            assert not hasattr(mw, attr), f"Forbidden attribute found on middleware: {attr}"

    def test_repeated_attacks_from_same_ip_not_blocked(self) -> None:
        """Sequential attacks from the same IP must NOT result in HTTP 403 or blocking."""
        attack_count = 10
        responses_received = []

        def host_app(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"Application processed request"]

        store = MemoryStore()
        mw = XSSGuardMiddleware(host_app, store=store)

        for i in range(attack_count):
            environ = {
                "REQUEST_METHOD": "GET",
                "PATH_INFO": "/vuln",
                "QUERY_STRING": f"q=%3Cscript%3Ealert({i})%3C/script%3E",
                "REMOTE_ADDR": "198.51.100.25",
                "wsgi.input": io.BytesIO(b""),
            }
            start_resp, status, _ = make_start_response()
            body = b"".join(mw(environ, start_resp))
            responses_received.append((status[0], body))

        assert len(responses_received) == attack_count
        for status_code, body in responses_received:
            assert "200" in status_code
            assert body == b"Application processed request"

        # Detections are logged for audit, but host application always served the requests
        assert len(store.recent_detections()) == attack_count


class TestMiddlewareArchitecturalIsolation:
    """Verify middleware public API and dependency boundaries."""

    def test_public_api_surface(self) -> None:
        tree = ast.parse(inspect.getsource(mw_module))
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
        assert defined_classes == {"XSSGuardMiddleware"}
        assert defined_funcs == set()
        assert mw_module.__all__ == ["XSSGuardMiddleware"]

    def test_no_forbidden_framework_imports(self) -> None:
        tree = ast.parse(inspect.getsource(mw_module))
        imports = []
        for n in tree.body:
            if isinstance(n, ast.Import):
                for a in n.names:
                    imports.append(a.name)
            elif isinstance(n, ast.ImportFrom) and n.module:
                imports.append(n.module)

        forbidden = (
            "flask",
            "sqlalchemy",
            "requests",
            "django",
            "bottle",
            "xssguard.flask_ext",
            "xssguard.dashboard",
            "xssguard.report",
        )
        for imp in imports:
            assert not imp.startswith(forbidden), f"Forbidden import: {imp}"
