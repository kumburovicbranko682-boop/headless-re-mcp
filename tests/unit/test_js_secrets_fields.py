"""Unit tests for js.secrets (node-free credential scan of a JS/text file).

Pure Python, so it runs against real temp files: per-provider pattern matches,
dedupe/sort, the no-hit and clean-file paths, pagination, the distinct-finding
collect cap, and the size/existence guards.

The sample tokens are assembled by concatenation (prefix ``+`` body) so the
committed source never contains a contiguous secret-shaped literal -- that would
trip GitHub push protection. The temp file written at runtime holds the full
token, which is what the scanner reads; it is never committed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.jsre.client import JsReError, scan_secrets

_AWS = "AKIA" + "IOSFODNN7EXAMPLE"
_GOOGLE = "AIza" + "SyA1234567890abcdefghijklmnopqrstuv"
_GITHUB = "ghp_" + "0123456789abcdefghijklmnopqrstuvwxyzAB"
_STRIPE = "sk_" + "live_" + "0123456789abcdefABCDEF12"
_JWT = "eyJhbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0" + "." + "abcDEF123456"


def _write(tmp_path: Path, text: str, name: str = "bundle.js") -> Path:
    target = tmp_path / name
    target.write_text(text, encoding="utf-8")
    return target


def _aws_variant(suffix: str) -> str:
    """An AWS-shaped key (AKIA + 16 upper-alnum) built without a literal secret.

    The suffix leads so each variant stays distinct after the 16-char clamp.
    """
    body = (suffix + "IOSFODNN7EXAMPLE")[:16]
    return "AKIA" + body


def test_secrets_detects_known_providers(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        f"""
        const aws = "{_AWS}";
        const g = "{_GOOGLE}";
        const gh = "{_GITHUB}";
        const stripe = "{_STRIPE}";
        const tok = "{_JWT}";
        """,
    )

    payload = scan_secrets(src)

    kinds = {row["type"] for row in payload["findings"]}
    assert kinds == {
        "aws_access_key_id",
        "google_api_key",
        "github_token",
        "stripe_key",
        "jwt",
    }
    aws = next(r for r in payload["findings"] if r["type"] == "aws_access_key_id")
    assert aws["value"] == _AWS
    assert payload["total"] == 5
    assert payload["scan_capped"] is False


def test_secrets_detects_private_key_header(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        "const k = `-----BEGIN RSA PRIVATE KEY-----\\nMIIB...`;",
    )

    payload = scan_secrets(src)

    assert payload["findings"] == [
        {"type": "private_key", "value": "-----BEGIN RSA PRIVATE KEY-----"}
    ]


def test_secrets_dedupes_and_sorts(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        f"""
        a = "{_AWS}";
        b = "{_AWS}";
        c = "{_GOOGLE}";
        """,
    )

    payload = scan_secrets(src)

    assert payload["findings"] == [
        {"type": "aws_access_key_id", "value": _AWS},
        {"type": "google_api_key", "value": _GOOGLE},
    ]
    assert payload["total"] == 2


def test_secrets_none_on_clean_file(tmp_path: Path) -> None:
    src = _write(tmp_path, "function add(a, b) { return a + b; }\nconst n = 42;")

    payload = scan_secrets(src)

    assert payload["findings"] == []
    assert payload["total"] == 0
    assert payload["has_more"] is False
    assert payload["scan_capped"] is False


def test_secrets_ignores_lookalikes(tmp_path: Path) -> None:
    # AKIA prefix but wrong length; AIza prefix but too short; not real hits.
    src = _write(tmp_path, 'x="AKIA" + "SHORT"; y="AIza" + "TooShort"; z="not a key";')

    payload = scan_secrets(src)

    assert payload["findings"] == []


def test_secrets_paginates(tmp_path: Path) -> None:
    keys = "\n".join(f'k{i}="{_aws_variant(chr(65 + i))}";' for i in range(5))
    src = _write(tmp_path, keys)

    payload = scan_secrets(src, offset=2, limit=2)

    assert payload["offset"] == 2
    assert payload["count"] == 2
    assert payload["total"] == 5
    assert payload["has_more"] is True


def test_secrets_collect_cap_sets_scan_capped(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.backends.jsre.client._MAX_SECRETS_COLLECT", 3
    )
    keys = "\n".join(f'k="{_aws_variant(f"{i:02d}")}";' for i in range(10))
    src = _write(tmp_path, keys)

    payload = scan_secrets(src)

    assert payload["total"] == 3
    assert payload["scan_capped"] is True


def test_secrets_clamps_oversized_limit(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr("headless_re_mcp.backends.jsre.client._MAX_SECRETS_PAGE", 2)
    keys = "\n".join(f'k{i}="{_aws_variant(chr(65 + i))}";' for i in range(5))
    src = _write(tmp_path, keys)

    payload = scan_secrets(src, limit=10**9)

    assert payload["count"] == 2
    assert payload["has_more"] is True


def test_secrets_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as excinfo:
        scan_secrets(tmp_path / "nope.js")
    assert excinfo.value.code == "not_found"


def test_secrets_refuses_oversized_input(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr("headless_re_mcp.backends.jsre.client._MAX_INPUT_BYTES", 32)
    src = _write(tmp_path, f'const k = "{_AWS}"; ' + "x" * 200)

    with pytest.raises(JsReError) as excinfo:
        scan_secrets(src)
    assert excinfo.value.code == "too_large"


def test_secrets_docstring_names_shape() -> None:
    doc = scan_secrets.__doc__ or ""
    assert "Node-free" in doc
    assert "scan_capped" in doc
