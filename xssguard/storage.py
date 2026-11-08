"""Storage module -- defines BaseStore (Protocol), MemoryStore, and records.

Implements the IStorage interface (Storage layer).
This module is framework-agnostic and must not import Flask, SQLAlchemy,
database drivers, middleware, detector, nonce, report, flask_ext, or dashboard.

Public API (locked by UML Class Diagram, ERD, and IMPLEMENTATION_CONTRACT.md):
- DetectionRecord
- CspReportRecord
- BaseStore
- MemoryStore
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import Lock
from typing import Optional, Protocol, runtime_checkable

__all__ = ["DetectionRecord", "CspReportRecord", "BaseStore", "MemoryStore"]


def _now() -> datetime:
    """Return current timestamp in UTC (timezone-aware)."""
    return datetime.now(timezone.utc)


@dataclass
class DetectionRecord:
    """Record representing an XSS detection event."""

    payload: str
    status: str
    matched_rule: Optional[str]
    source: str
    client_ip: Optional[str]
    created_at: datetime = field(default_factory=_now)
    action: Optional[str] = None


@dataclass
class CspReportRecord:
    """Record representing a received Content Security Policy violation report."""

    document_uri: Optional[str]
    violated_directive: Optional[str]
    blocked_uri: Optional[str]
    client_ip: Optional[str]
    created_at: datetime = field(default_factory=_now)


@runtime_checkable
class BaseStore(Protocol):
    """Protocol defining the storage interface (IStorage)."""

    def log_detection(self, record: DetectionRecord) -> None: ...

    def log_csp_report(self, record: CspReportRecord) -> None: ...

    def recent_detections(self, limit: int = 50) -> list[DetectionRecord]: ...

    def recent_csp_reports(self, limit: int = 50) -> list[CspReportRecord]: ...


class MemoryStore:
    """In-memory thread-safe implementation of BaseStore."""

    def __init__(self) -> None:
        self._lock: Lock = Lock()
        self._detections: list[DetectionRecord] = []
        self._csp_reports: list[CspReportRecord] = []

    def log_detection(self, record: DetectionRecord) -> None:
        """Log an XSS detection event."""
        with self._lock:
            self._detections.append(record)

    def log_csp_report(self, record: CspReportRecord) -> None:
        """Log a CSP violation report."""
        with self._lock:
            self._csp_reports.append(record)

    def recent_detections(self, limit: int = 50) -> list[DetectionRecord]:
        """Return recent detection records in descending order of created_at (newest first)."""
        with self._lock:
            if limit <= 0:
                return []
            records = self._detections[::-1]
            return sorted(records, key=lambda r: r.created_at, reverse=True)[:limit]

    def recent_csp_reports(self, limit: int = 50) -> list[CspReportRecord]:
        """Return recent CSP report records in descending order of created_at (newest first)."""
        with self._lock:
            if limit <= 0:
                return []
            records = self._csp_reports[::-1]
            return sorted(records, key=lambda r: r.created_at, reverse=True)[:limit]
