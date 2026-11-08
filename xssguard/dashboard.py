"""Dashboard module -- provides monitoring dashboard view (Presentation layer).

Implements the dashboard factory create_dashboard_blueprint(store).
This module is read-only and must strictly depend ONLY on BaseStore and Flask Blueprint.
It must NOT import detector, patterns, nonce, report, middleware, flask_ext,
SQLAlchemy, database drivers, or any other external modules.

Public API (locked by UML Class Diagram and IMPLEMENTATION_CONTRACT.md):
- create_dashboard_blueprint
"""

from flask import Blueprint, render_template_string, url_for
from xssguard.storage import BaseStore

__all__ = ["create_dashboard_blueprint"]

_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XSSGuard Security Dashboard</title>
    <link rel="stylesheet" href="{{ dashboard_css_url }}">
</head>
<body>
    <h1>XSSGuard Security Dashboard</h1>

    <h2>Detection Logs</h2>
    {% if detections %}
    <table>
        <thead>
            <tr>
                <th>Created At (UTC)</th>
                <th>Status</th>
                <th>Source</th>
                <th>Client IP</th>
                <th>Matched Rule</th>
                <th>Payload</th>
            </tr>
        </thead>
        <tbody>
            {% for d in detections %}
            <tr>
                <td>{{ d.created_at }}</td>
                <td><span class="badge">{{ d.status }}</span></td>
                <td><code>{{ d.source }}</code></td>
                <td>{{ d.client_ip or '-' }}</td>
                <td>{{ d.matched_rule or '-' }}</td>
                <td><code>{{ d.payload }}</code></td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    {% else %}
    <p class="empty">No detection records.</p>
    {% endif %}

    <h2>CSP Violation Reports</h2>
    {% if csp_reports %}
    <table>
        <thead>
            <tr>
                <th>Created At (UTC)</th>
                <th>Document URI</th>
                <th>Violated Directive</th>
                <th>Blocked URI</th>
                <th>Client IP</th>
            </tr>
        </thead>
        <tbody>
            {% for c in csp_reports %}
            <tr>
                <td>{{ c.created_at }}</td>
                <td><code>{{ c.document_uri or '-' }}</code></td>
                <td><code>{{ c.violated_directive or '-' }}</code></td>
                <td><code>{{ c.blocked_uri or '-' }}</code></td>
                <td>{{ c.client_ip or '-' }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    {% else %}
    <p class="empty">No CSP violation reports.</p>
    {% endif %}
</body>
</html>
"""


def create_dashboard_blueprint(
    store: BaseStore,
    name: str = "xssguard_dashboard",
) -> Blueprint:
    """Create and return a Flask Blueprint for the XSSGuard monitoring dashboard."""
    bp = Blueprint(name, __name__, static_folder="static")

    @bp.route("/", methods=["GET"])
    def index() -> str:
        detections = store.recent_detections(limit=50)
        csp_reports = store.recent_csp_reports(limit=50)
        dashboard_css_url = url_for(f"{name}.static", filename="dashboard.css")
        return render_template_string(
            _DASHBOARD_HTML,
            detections=detections,
            csp_reports=csp_reports,
            dashboard_css_url=dashboard_css_url,
        )

    return bp
