"""CSP Nonce generator -- implements INonce interface (Core layer).

This module is framework-agnostic and must not import Flask, SQLAlchemy,
or any request/response framework object.

Public API (locked by UML Class Diagram and IMPLEMENTATION_CONTRACT.md S1.3):
    - generate_nonce()
    - build_csp_header()

Invariants (IMPLEMENTATION_CONTRACT.md S1.3):
    - generate_nonce() uses secrets (CSPRNG), never random.
    - Nonce is base64url-safe encoded so it is valid as an HTML attribute
      value and as a CSP token (no '+', '/', or '=' characters that would
      break the CSP directive syntax).
    - build_csp_header() always inserts 'nonce-{nonce}' into script-src.
"""

from __future__ import annotations

import base64
import re
import secrets
from typing import Optional


# ---------------------------------------------------------------------------
# Default CSP policy template.
#
# The placeholder {script_src_tokens} is replaced at runtime with the
# generated nonce token (and any extra_script_src tokens the caller
# supplies).  All other directives are fixed and do not change
# between responses.
# ---------------------------------------------------------------------------
_DEFAULT_POLICY_TEMPLATE = (
    "default-src 'self'; "
    "script-src 'self' {script_src_tokens}; "
    "object-src 'none'; "
    "report-uri /csp-report;"
)


def generate_nonce(n_bytes: int = 16) -> str:
    """Generate a cryptographically secure random nonce.

    Uses secrets.token_bytes() (CSPRNG) and encodes the result with
    URL-safe Base64 (no padding) so that the nonce string is safe to
    embed directly in a CSP header value and in an HTML nonce attribute
    without any further escaping.

    Args:
        n_bytes: Number of random bytes to use before encoding.
                 Defaults to 16 (128 bits of entropy), which provides
                 sufficient unpredictability for a per-request nonce.

    Returns:
        A URL-safe Base64-encoded string (no '=', '+', or '/').
    """
    raw = secrets.token_bytes(n_bytes)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def build_csp_header(
    nonce: str,
    *,
    extra_script_src: str = "",
    policy_template: Optional[str] = None,
) -> str:
    """Build a Content-Security-Policy header value for the given *nonce*.

    Always inserts ``'nonce-{nonce}'`` into the script-src directive.

    Args:
        nonce:            The nonce string produced by generate_nonce().
        extra_script_src: Additional script-src tokens to append after
                          the nonce token (e.g. "'strict-dynamic'").
                          Defaults to "" (empty, no extras).
        policy_template:  A custom CSP policy string containing the
                          placeholder ``{script_src_tokens}``.  If None,
                          the built-in default template is used.

    Returns:
        A complete Content-Security-Policy header value string, e.g.:
            "default-src 'self'; script-src 'self' 'nonce-abc123'; object-src 'none';"

    Invariant:
        The nonce token ``'nonce-{nonce}'`` is ALWAYS present in the
        returned string, regardless of the policy_template provided.
    """
    nonce_token = f"'nonce-{nonce}'"
    tokens_to_add: list[str] = [nonce_token]
    if extra_script_src and extra_script_src.strip():
        tokens_to_add.append(extra_script_src.strip())

    if policy_template is None:
        return _DEFAULT_POLICY_TEMPLATE.format(
            script_src_tokens=" ".join(tokens_to_add)
        )

    # 1. Custom template containing placeholder {script_src_tokens}
    if "{script_src_tokens}" in policy_template:
        return policy_template.replace(
            "{script_src_tokens}", " ".join(tokens_to_add)
        )

    # 2. Custom template without placeholder: check if script-src directive exists.
    # Strict regex matching only 'script-src' (not 'script-src-elem' or 'script-src-attr').
    pattern = r"(?i)(\A|;)(\s*script-src(?=[ \t;]|\Z))([^;]*)"
    match = re.search(pattern, policy_template)

    if match:
        def repl(m: re.Match[str]) -> str:
            prefix = m.group(1)
            directive = m.group(2)
            existing_tokens_part = m.group(3)
            existing_tokens = existing_tokens_part.split()

            to_append = [t for t in tokens_to_add if t not in existing_tokens]
            if to_append:
                spacer = " " if existing_tokens_part and not existing_tokens_part.endswith(" ") else (" " if not existing_tokens_part else "")
                return f"{prefix}{directive}{existing_tokens_part}{spacer}{' '.join(to_append)}"
            return m.group(0)

        return re.sub(pattern, repl, policy_template, count=1)

    # 3. Custom template without script-src directive: append script-src directive
    clean_tmpl = policy_template.strip()
    if clean_tmpl and not clean_tmpl.endswith(";"):
        clean_tmpl += ";"

    script_src_directive = f"script-src {' '.join(tokens_to_add)};"
    if clean_tmpl:
        return f"{clean_tmpl} {script_src_directive}"
    return script_src_directive
