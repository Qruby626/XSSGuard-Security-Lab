"""CSP Violation Report parser -- implements IReport interface (Core layer).

This module is framework-agnostic and must not import Flask, SQLAlchemy,
storage, middleware, or any database/request/response framework objects.

Public API (locked by UML Class Diagram and IMPLEMENTATION_CONTRACT.md):
- CspReportData
- parse_csp_report
"""

import json
from dataclasses import dataclass
from typing import Optional

__all__ = ["CspReportData", "parse_csp_report"]


@dataclass(frozen=True)
class CspReportData:
    """Parsed representation of a Content Security Policy (CSP) violation report."""

    document_uri: Optional[str]
    violated_directive: Optional[str]
    blocked_uri: Optional[str]
    original_policy: Optional[str]
    raw: dict


def _get_str(data: dict, key_dash: str, key_underscore: str) -> Optional[str]:
    """Extract a string value from a dictionary using dash or underscore keys."""
    val = data.get(key_dash)
    if val is None:
        val = data.get(key_underscore)
    if val is None:
        return None
    if isinstance(val, str):
        return val
    if isinstance(val, (int, float)) and not isinstance(val, bool):
        return str(val)
    return None


def parse_csp_report(raw_body: bytes) -> Optional[CspReportData]:
    """Parse raw HTTP request body containing a CSP violation report JSON.

    Supports both direct JSON objects and reports wrapped in a "csp-report" key.
    Returns None if the body cannot be parsed as valid JSON or is not a JSON object.
    Missing fields in a valid report object evaluate to None in CspReportData.
    """
    try:
        data = json.loads(raw_body)
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError, ValueError):
        return None

    if not isinstance(data, dict):
        return None

    # Handle browser-wrapped format: {"csp-report": {...}}
    inner = data.get("csp-report")
    if isinstance(inner, dict):
        target = inner
    else:
        target = data

    return CspReportData(
        document_uri=_get_str(target, "document-uri", "document_uri"),
        violated_directive=_get_str(target, "violated-directive", "violated_directive"),
        blocked_uri=_get_str(target, "blocked-uri", "blocked_uri"),
        original_policy=_get_str(target, "original-policy", "original_policy"),
        raw=target,
    )
