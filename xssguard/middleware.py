"""WSGI Middleware for rule-based XSS detection and Trusted-Script Nonce CSP integration.

Implements the extension layer middleware for WSGI applications (Flask, Django,
Bottle, or raw WSGI).

Public API (locked by UML Class Diagram and IMPLEMENTATION_CONTRACT.md):
- XSSGuardMiddleware
"""

import io
import json
import urllib.parse
from typing import Any, Callable, Iterable, Optional, Sequence

from xssguard.detector import scan_mapping
from xssguard.nonce import build_csp_header, generate_nonce
from xssguard.patterns import DEFAULT_XSS_PATTERNS
from xssguard.storage import BaseStore, DetectionRecord, MemoryStore

__all__ = ["XSSGuardMiddleware"]

# Type aliases for WSGI callables (compatible with Python >=3.9)
StartResponse = Callable[..., Any]
WSGIApplication = Callable[..., Iterable[bytes]]


def _extract_request_data(environ: dict, body_bytes: bytes) -> dict[str, Any]:
    """Extract query and body parameters into a mapping for detector scan."""
    data: dict[str, Any] = {}

    # 1. Query parameters
    qs = environ.get("QUERY_STRING", "")
    if qs:
        parsed_qs = urllib.parse.parse_qs(qs, keep_blank_values=True)
        for k, v in parsed_qs.items():
            data[k] = v[0] if len(v) == 1 else v

    # 2. Body parameters
    if body_bytes:
        content_type = environ.get("CONTENT_TYPE", "")
        parsed_body = False

        # Check JSON
        if "application/json" in content_type or body_bytes.strip().startswith((b"{", b"[")):
            try:
                json_obj = json.loads(body_bytes.decode("utf-8", errors="replace"))
                if isinstance(json_obj, dict):
                    for k, v in json_obj.items():
                        if k in data:
                            existing = data[k] if isinstance(data[k], list) else [data[k]]
                            data[k] = existing + (v if isinstance(v, list) else [v])
                        else:
                            data[k] = v
                    parsed_body = True
                elif isinstance(json_obj, list):
                    data["_body"] = json_obj
                    parsed_body = True
            except Exception:
                pass

        # Check form urlencoded / raw body
        if not parsed_body:
            try:
                body_str = body_bytes.decode("utf-8", errors="replace")
                if "=" in body_str:
                    parsed_form = urllib.parse.parse_qs(body_str, keep_blank_values=True)
                    for k, v in parsed_form.items():
                        val = v[0] if len(v) == 1 else v
                        if k in data:
                            existing = data[k] if isinstance(data[k], list) else [data[k]]
                            data[k] = existing + (val if isinstance(val, list) else [val])
                        else:
                            data[k] = val
                elif body_str.strip():
                    data["_raw_body"] = body_str
            except Exception:
                pass

    return data


_FORBIDDEN_BODY = (
    b"<!DOCTYPE html>\n"
    b"<html lang=\"en\">\n"
    b"<head><meta charset=\"utf-8\"><title>403 Forbidden &mdash; XSSGuard</title></head>\n"
    b"<body>\n"
    b"  <h1>403 Forbidden</h1>\n"
    b"  <p>Your request has been blocked by XSSGuard.</p>\n"
    b"  <p>Reason: Potential XSS payload detected in request input.</p>\n"
    b"  <hr>\n"
    b"  <small>XSSGuard Security Enforcement</small>\n"
    b"</body>\n"
    b"</html>\n"
)


class XSSGuardMiddleware:
    """WSGI Middleware for rule-based XSS detection and dynamic CSP nonce integration."""

    def __init__(
        self,
        app: WSGIApplication,
        *,
        patterns: Optional[Sequence[str]] = None,
        store: Optional[BaseStore] = None,
        blocking_enabled: bool = False,
        blocking_exclude_paths: Optional[Sequence[str]] = None,
    ) -> None:
        self.app = app
        self.patterns = patterns if patterns is not None else DEFAULT_XSS_PATTERNS
        self.store = store if store is not None else MemoryStore()
        self.blocking_enabled = bool(blocking_enabled)
        self.blocking_exclude_paths: frozenset[str] = frozenset(blocking_exclude_paths) if blocking_exclude_paths else frozenset()

    def __call__(
        self,
        environ: dict,
        start_response: StartResponse,
    ) -> Iterable[bytes]:
        # 1. Read request body if CONTENT_LENGTH > 0 and replay back to environ["wsgi.input"]
        body_bytes = b""
        content_length_str = environ.get("CONTENT_LENGTH")
        if content_length_str:
            try:
                content_length = int(content_length_str)
                if content_length > 0:
                    wsgi_input = environ.get("wsgi.input")
                    if wsgi_input is not None:
                        body_bytes = wsgi_input.read(content_length)
                        environ["wsgi.input"] = io.BytesIO(body_bytes)
            except (ValueError, TypeError):
                pass
        elif "wsgi.input" in environ:
            wsgi_input = environ.get("wsgi.input")
            if wsgi_input is not None:
                try:
                    if hasattr(wsgi_input, "getvalue"):
                        body_bytes = wsgi_input.getvalue()
                        wsgi_input.seek(0)
                except Exception:
                    pass

        # 2. Extract request parameters and call detector.scan_mapping(data, self.patterns)
        data = _extract_request_data(environ, body_bytes)
        results = scan_mapping(data, self.patterns)

        # 3. Generate dynamic CSP nonce exactly once per request — BEFORE action decision
        nonce = generate_nonce()

        # 4. Expose nonce through WSGI environment before calling host application
        environ["xssguard.nonce"] = nonce

        # 5. Determine enforcement action iff detection results exist (DETECTED status)
        action: Optional[str] = None
        if results:
            path_info = environ.get("PATH_INFO", "")
            if not self.blocking_enabled:
                action = "ALLOWED"
            elif path_info in self.blocking_exclude_paths:
                action = "ALLOWED"
            else:
                action = "BLOCKED"

        # 6. For each DetectionResult, create DetectionRecord(action) and log to store
        if results:
            path_info = environ.get("PATH_INFO", "")
            client_ip = environ.get("REMOTE_ADDR")
            for result in results:
                self.store.log_detection(
                    DetectionRecord(
                        payload=f"{result.field}={result.payload}",
                        status=result.status,
                        matched_rule=result.matched_rule,
                        source=path_info,
                        client_ip=client_ip,
                        action=action,
                    )
                )

        # 7. Enforcement branch — BLOCKED case: early return HTTP 403, never call self.app()
        if action == "BLOCKED":
            def _blocked_start_response(
                status: str,
                response_headers: list[tuple[str, str]],
                exc_info: Any = None,
            ) -> Any:
                headers = list(response_headers)
                headers.append(("Content-Security-Policy", build_csp_header(nonce)))
                return start_response(status, headers, exc_info)

            headers: list[tuple[str, str]] = [
                ("Content-Type", "text/html; charset=utf-8"),
            ]
            _blocked_start_response("403 Forbidden", headers)
            return [_FORBIDDEN_BODY]

        # 8. ALLOWED / SAFE case: continue to host application via custom_start_response
        def custom_start_response(
            status: str,
            response_headers: list[tuple[str, str]],
            exc_info: Any = None,
        ) -> Any:
            headers = list(response_headers)
            headers.append(("Content-Security-Policy", build_csp_header(nonce)))
            return start_response(status, headers, exc_info)

        return self.app(environ, custom_start_response)
