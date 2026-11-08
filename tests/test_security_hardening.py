"""Security hardening regression tests for xssguard.detector.

These tests validate three targeted fixes that do NOT belong to the official
30-payload research dataset:

A. HTML entity encoding bypass — entity-encoded XSS evading literal-token
   regex detection is now caught via one-pass html.unescape() normalization.
B. Cookie bracket notation bypass — document['cookie'] / document["cookie"]
   is now detected alongside the existing dot-notation pattern.
C. Recursion DoS in scan_mapping() — iterative stack-based DFS replaces
   recursive traversal to eliminate Python call-stack exhaustion on deeply
   nested attacker-controlled structures.
"""

import sys

import pytest

from xssguard.detector import DetectionResult, scan, scan_mapping


# -----------------------------------------------------------------------
# A. HTML Entity Encoding Bypass
# -----------------------------------------------------------------------

class TestHtmlEntityBypass:
    """Verify that entity-encoded XSS payloads are detected while normal
    benign HTML entities remain SAFE.

    Entity normalization is conservative detection hardening: it does NOT
    claim that every HTML-entity encoded string is inherently exploitable.
    The purpose is to reduce detector evasion under potentially unsafe HTML
    rendering contexts.
    """

    def test_encoded_script_tag_detected(self) -> None:
        result = scan("&lt;script&gt;alert(1)&lt;/script&gt;")
        assert result.status == "DETECTED"

    def test_encoded_event_handler_detected(self) -> None:
        result = scan("&lt;img src=x onerror=alert(1)&gt;")
        assert result.status == "DETECTED"

    def test_encoded_payload_preserves_original(self) -> None:
        original = "&lt;script&gt;alert(1)&lt;/script&gt;"
        result = scan(original)
        assert result.status == "DETECTED"
        assert result.payload == original, (
            "DetectionResult.payload must retain the original entity-encoded "
            "input, not the normalized representation."
        )

    def test_non_xss_entities_not_flagged(self) -> None:
        """Normal benign HTML entities must not trigger false positives."""
        benign_inputs = [
            "&amp;",
            "&copy; 2026 XSSGuard",
            "5 &gt; 3 &amp;&amp; 2 &lt; 4",
            "Use &amp;amp; for ampersands",
            "Price: &dollar;9.99",
        ]
        for text in benign_inputs:
            result = scan(text)
            assert result.status == "SAFE", (
                f"Benign entity input falsely detected as XSS: {text!r}"
            )

    def test_mixed_entity_and_plain_xss(self) -> None:
        """A payload mixing entities with plain XSS patterns is detected."""
        result = scan("&lt;script&gt;document.cookie&lt;/script&gt;")
        assert result.status == "DETECTED"

    def test_numeric_entity_script_tag(self) -> None:
        """Numeric HTML entities for '<script>' should also be detected."""
        # &#60; = '<', &#115;&#99;&#114;&#105;&#112;&#116; = 'script', &#62; = '>'
        result = scan("&#60;script&#62;alert(1)&#60;/script&#62;")
        assert result.status == "DETECTED"


# -----------------------------------------------------------------------
# B. Cookie Bracket Notation Bypass
# -----------------------------------------------------------------------

class TestCookieBracketNotation:
    """Verify that document['cookie'] and document["cookie"] are detected,
    including whitespace variants, without breaking existing dot-notation
    detection.
    """

    def test_single_quote_bracket(self) -> None:
        assert scan("document['cookie']").status == "DETECTED"

    def test_double_quote_bracket(self) -> None:
        assert scan('document["cookie"]').status == "DETECTED"

    def test_whitespace_single_quote(self) -> None:
        assert scan("document [ 'cookie' ]").status == "DETECTED"

    def test_whitespace_double_quote(self) -> None:
        assert scan('document [ "cookie" ]').status == "DETECTED"

    def test_case_insensitive_bracket(self) -> None:
        assert scan("DOCUMENT['cookie']").status == "DETECTED"
        assert scan("Document[\"COOKIE\"]").status == "DETECTED"

    def test_dot_notation_still_works(self) -> None:
        """Existing dot-notation detection must remain functional."""
        assert scan("document.cookie").status == "DETECTED"
        assert scan("DOCUMENT.COOKIE").status == "DETECTED"
        assert scan("document . cookie").status == "DETECTED"

    def test_bracket_notation_preserves_original_payload(self) -> None:
        original = "document['cookie']"
        result = scan(original)
        assert result.status == "DETECTED"
        assert result.payload == original


# -----------------------------------------------------------------------
# C. Recursion DoS in scan_mapping()
# -----------------------------------------------------------------------

class TestDeepNestingDoS:
    """Verify that scan_mapping() handles deeply nested structures without
    raising RecursionError and still detects malicious payloads at the
    deepest reachable level.

    Uses a deterministic depth of 3000 levels, substantially above the
    default Python recursion limit (~1000).
    """

    DEPTH = 3000

    def test_deep_nested_mapping_no_recursion_error(self) -> None:
        """Deeply nested Mapping must not cause RecursionError."""
        data: dict = {}
        current = data
        for _ in range(self.DEPTH):
            child: dict = {}
            current["nested"] = child
            current = child
        current["payload"] = "<script>alert('deep')</script>"

        # Must not raise RecursionError
        results = scan_mapping(data)
        assert any(r.status == "DETECTED" for r in results), (
            "Malicious payload at depth 3000 must be detected, not silently "
            "classified as SAFE."
        )

    def test_deep_nested_mapping_detects_payload_and_field_path(self) -> None:
        """Verify the payload is detected and field path is correct."""
        data: dict = {}
        current = data
        for _ in range(self.DEPTH):
            child: dict = {}
            current["nested"] = child
            current = child
        current["payload"] = "<script>alert('deep')</script>"

        results = scan_mapping(data)
        assert len(results) >= 1

        detected = results[0]
        assert detected.status == "DETECTED"
        assert detected.payload == "<script>alert('deep')</script>"
        # Field path should be "nested.nested.nested...nested.payload"
        expected_prefix = ".".join(["nested"] * self.DEPTH)
        assert detected.field == f"{expected_prefix}.payload"

    def test_deep_nested_list(self) -> None:
        """Deeply nested list structure must not cause RecursionError."""
        # Build: {"items": [[[...[<script>...]...]]]}
        inner: list = ["<img src=x onerror=alert(1)>"]
        for _ in range(self.DEPTH):
            inner = [inner]
        data = {"items": inner}

        results = scan_mapping(data)
        assert any(r.status == "DETECTED" for r in results), (
            "Malicious payload inside deeply nested list must be detected."
        )

    def test_deep_nested_tuple(self) -> None:
        """Deeply nested tuple structure must not cause RecursionError."""
        inner: tuple = ("document.cookie",)
        for _ in range(self.DEPTH):
            inner = (inner,)
        data = {"values": inner}

        results = scan_mapping(data)
        assert any(r.status == "DETECTED" for r in results), (
            "Malicious payload inside deeply nested tuple must be detected."
        )

    def test_mixed_deep_nesting(self) -> None:
        """Mix of dict, list, and tuple nesting at depth 3000."""
        data: dict = {}
        current = data
        for i in range(self.DEPTH):
            if i % 3 == 0:
                child: dict = {}
                current["level"] = child
                current = child
            elif i % 3 == 1:
                child_dict: dict = {}
                current["items"] = [child_dict]
                current = child_dict
            else:
                child_dict2: dict = {}
                current["entry"] = (child_dict2,)
                current = child_dict2
        current["attack"] = "eval('malicious()')"

        results = scan_mapping(data)
        assert any(r.status == "DETECTED" for r in results)
