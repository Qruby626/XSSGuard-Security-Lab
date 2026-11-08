"""Flask integration extension for XSSGuard.

Provides the XSSGuard class to wrap Flask's WSGI application with
XSSGuardMiddleware, and register_csp_report_route() to receive and log CSP
violation reports.

Public API (locked by UML Class Diagram and IMPLEMENTATION_CONTRACT.md):
- XSSGuard
- register_csp_report_route
"""

from typing import Optional, Sequence
from flask import Flask, Response, has_request_context, request

from xssguard.middleware import XSSGuardMiddleware
from xssguard.report import parse_csp_report
from xssguard.storage import BaseStore, CspReportRecord, MemoryStore

__all__ = ["XSSGuard", "register_csp_report_route"]


def register_csp_report_route(
    app: Flask,
    store: BaseStore,
    path: str = "/csp-report",
) -> None:
    """Register a route on the Flask app to receive and log CSP violation reports.

    The endpoint reads raw request body bytes, parses via report.parse_csp_report(),
    logs valid reports to store via store.log_csp_report(), and always returns
    HTTP 204 No Content.
    """
    endpoint = f"csp_report_{path.strip('/').replace('/', '_') or 'root'}"

    def csp_report() -> Response:
        raw_body = request.get_data()
        report_data = parse_csp_report(raw_body)
        if report_data is not None:
            store.log_csp_report(
                CspReportRecord(
                    document_uri=report_data.document_uri,
                    violated_directive=report_data.violated_directive,
                    blocked_uri=report_data.blocked_uri,
                    client_ip=request.remote_addr,
                )
            )
        return Response(status=204)

    csp_report.__name__ = endpoint
    app.add_url_rule(path, endpoint=endpoint, view_func=csp_report, methods=["POST"])


_DEFAULT_CSP_REPORT_PATH = "/csp-report"


class XSSGuard:
    """Flask extension wrapper for XSSGuard WSGI middleware and CSP reporting."""

    def __init__(
        self,
        app: Optional[Flask] = None,
        *,
        patterns: Optional[Sequence[str]] = None,
        store: Optional[BaseStore] = None,
        blocking_enabled: bool = False,
        blocking_exclude_paths: Optional[Sequence[str]] = None,
        csp_report_path: str = _DEFAULT_CSP_REPORT_PATH,
    ) -> None:
        self.patterns = patterns
        self.store = store if store is not None else MemoryStore()
        self.blocking_enabled = bool(blocking_enabled)
        self._blocking_exclude_paths = list(blocking_exclude_paths) if blocking_exclude_paths else []
        self.csp_report_path = str(csp_report_path)
        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        """Initialize the extension on the given Flask application."""
        if getattr(app, "_xssguard_initialized", False):
            return
        app._xssguard_initialized = True

        if hasattr(app, "extensions"):
            app.extensions["xssguard"] = self

        register_csp_report_route(app, self.store, path=self.csp_report_path)

        exclude_set = set(self._blocking_exclude_paths)
        exclude_set.add(self.csp_report_path)

        app.wsgi_app = XSSGuardMiddleware(
            app.wsgi_app,
            patterns=self.patterns,
            store=self.store,
            blocking_enabled=self.blocking_enabled,
            blocking_exclude_paths=list(exclude_set),
        )

        @app.context_processor
        def _inject_xssguard_nonce() -> dict[str, Optional[str]]:
            nonce = request.environ.get("xssguard.nonce") if has_request_context() else None
            return {"xssguard_nonce": nonce}

