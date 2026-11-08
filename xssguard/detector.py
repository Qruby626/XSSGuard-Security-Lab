"""Rule-Based XSS Detector -- implements IDetector interface (Core layer).

This module is framework-agnostic and must not import Flask, SQLAlchemy, or
any request/response framework object. All public API receives and returns
plain Python types only.

Public API (locked by UML Class Diagram and IMPLEMENTATION_CONTRACT.md S1.2):
    - DetectionResult   (frozen dataclass)
    - scan()
    - scan_mapping()
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Sequence

from .patterns import DEFAULT_XSS_PATTERNS


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DetectionResult:
    """Immutable result of a single payload scan.

    Attributes:
        status:       "DETECTED" if a pattern matched, "SAFE" otherwise.
        matched_rule: The first regex pattern string that matched; None when SAFE.
        payload:      The raw value that was scanned (unchanged).
        field:        Dot-notation path to the field inside a mapping
                      (e.g. "comment.0.text"); None when produced by scan().
    """

    status: str
    matched_rule: Optional[str]
    payload: str
    field: Optional[str] = None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _compile_patterns(patterns: Sequence[str]) -> list[re.Pattern[str]]:
    """Return compiled regex objects for *patterns* in order."""
    return [re.compile(p) for p in patterns]


def _normalize(text: str) -> str:
    """One-pass HTML entity decoding for detection normalization.

    This is conservative detection hardening: encoded representations that
    would become dangerous after HTML parsing in an unsafe rendering context
    are normalized so that rule-based patterns can match them.  This does NOT
    imply that every entity-encoded string is itself an exploitable XSS.
    """
    return html.unescape(text)


def _scan_str(
    text: str,
    compiled: list[re.Pattern[str]],
    raw_patterns: Sequence[str],
) -> tuple[str, Optional[str]]:
    """Return (status, matched_rule) for *text* against *compiled* patterns."""
    for pattern_obj, pattern_str in zip(compiled, raw_patterns):
        if pattern_obj.search(text):
            return "DETECTED", pattern_str
    return "SAFE", None


def _walk_iterative(
    data: Mapping[str, Any],
    compiled: list[re.Pattern[str]],
    raw_patterns: Sequence[str],
    results: list[DetectionResult],
) -> None:
    """Iteratively walk *data*, scanning every string scalar leaf.

    Uses an explicit stack (DFS) instead of Python recursion to avoid
    call-stack exhaustion on deeply nested attacker-controlled structures.

    Children are pushed in reverse order so that the effective processing
    order matches the previous recursive implementation.

    Appends a DetectionResult to *results* for each leaf that matches at
    least one pattern.  SAFE results are never appended -- only DETECTED.

    Field path format: dotted notation, e.g. "comment.0.text".
    """
    # Each stack frame: (container, prefix)
    # container is a Mapping or a list/tuple.
    stack: list[tuple[Any, str]] = [(data, "")]

    while stack:
        container, prefix = stack.pop()

        if isinstance(container, Mapping):
            entries: list[tuple[Any, Any]] = list(container.items())
        else:
            # list or tuple — enumerate for index-based keys
            entries = list(enumerate(container))

        # Collect child containers to push onto the stack after processing
        # all immediate string leaves in forward order.
        deferred: list[tuple[Any, str]] = []

        for key, value in entries:
            field_path = f"{prefix}.{key}" if prefix else str(key)

            if isinstance(value, str):
                normalized = _normalize(value)
                status, matched_rule = _scan_str(
                    normalized, compiled, raw_patterns,
                )
                if status == "DETECTED":
                    results.append(
                        DetectionResult(
                            status="DETECTED",
                            matched_rule=matched_rule,
                            payload=value,
                            field=field_path,
                        )
                    )

            elif isinstance(value, Mapping):
                deferred.append((value, field_path))

            elif isinstance(value, (list, tuple)):
                deferred.append((value, field_path))

            # Non-string scalars (int, float, bool, None, bytes) are not
            # converted to strings -- they cannot carry XSS payloads as-is
            # and coercing them would risk false positives (e.g. True -> "True").

        # Push deferred containers in reverse order so the first one is
        # popped (processed) next, preserving forward DFS traversal order.
        for item in reversed(deferred):
            stack.append(item)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan(
    payload: str,
    patterns: Sequence[str] = DEFAULT_XSS_PATTERNS,
) -> DetectionResult:
    """Scan a single string *payload* against *patterns*.

    Rules (IMPLEMENTATION_CONTRACT.md S1.2):
    - Patterns are evaluated in order; the first match wins.
    - Returns DetectionResult with status="DETECTED" and matched_rule set to
      the first matching pattern string if any pattern matches.
    - Returns DetectionResult with status="SAFE" and matched_rule=None if no
      pattern matches.
    - Never raises an exception for an empty or None-safe payload.
    - payload in the result is always the original, unmodified input value.
    - field is always None (use scan_mapping() for field-path tracking).

    Args:
        payload:  The raw string to inspect.
        patterns: Ordered sequence of regex pattern strings to test against.
                  Defaults to DEFAULT_XSS_PATTERNS from patterns.py.

    Returns:
        A frozen DetectionResult instance.
    """
    # Guard: treat non-string / falsy payload as safe per the None-safe invariant.
    if not isinstance(payload, str) or not payload:
        return DetectionResult(
            status="SAFE",
            matched_rule=None,
            payload=payload if isinstance(payload, str) else "",
        )

    compiled = _compile_patterns(patterns)
    normalized = _normalize(payload)
    status, matched_rule = _scan_str(normalized, compiled, patterns)
    return DetectionResult(
        status=status,
        matched_rule=matched_rule,
        payload=payload,
    )


def scan_mapping(
    data: Mapping[str, Any],
    patterns: Sequence[str] = DEFAULT_XSS_PATTERNS,
) -> list[DetectionResult]:
    """Scan all string values in *data* (recursively) against *patterns*.

    Recursively traverses nested Mappings and sequences (list / tuple),
    building a dotted field-path for each leaf scalar.

    Invariants (IMPLEMENTATION_CONTRACT.md S1.2 and S6 rule 5):
    - ONLY returns DetectionResult entries with status == "DETECTED".
    - SAFE results are filtered out before returning.
    - Returns [] if no payload matches any pattern.
    - field is set to the dotted path of the matched leaf
      (e.g. "comment.0.text").
    - Non-string scalars (int, float, bool, None) are not scanned.

    Args:
        data:     A Mapping (e.g. dict parsed from form data or JSON body).
        patterns: Ordered sequence of regex pattern strings.
                  Defaults to DEFAULT_XSS_PATTERNS from patterns.py.

    Returns:
        A list of DetectionResult, each with status == "DETECTED".
        Empty list when nothing is detected.
    """
    compiled = _compile_patterns(patterns)
    results: list[DetectionResult] = []
    _walk_iterative(data, compiled, patterns, results)
    return results
