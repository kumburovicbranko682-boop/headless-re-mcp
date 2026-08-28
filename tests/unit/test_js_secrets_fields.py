"""js.secrets: classify string literals against known credential patterns.

The two load-bearing properties are precision (a distinctive prefix, matched
against decoded string values, so a name in a comment or ordinary prose is not
flagged) and safety (the matched secret is redacted, never echoed whole).
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

import headless_re_mcp.backends.jsre.client as client_mod
from headless_re_mcp.backends.jsre.client import JsClient, JsReError
from headless_re_mcp.backends.jsre.js_static import extract_js_secrets
from headless_re_mcp.tools.js_wasm import build_js_wasm_tools

# Synthetic, well-formed but fake credentials at the lengths the patterns want.
_AWS = "AKIAIOSFODNN7EXAMPLE"
_GOOGLE = "AIzaSyA1234567890abcdefghijklmnopqrstuv"
_GITHUB = "ghp_" + "a" * 36
_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3In0.SflKxwRJSMeKKF2QT4"
_STRIPE_LIVE = "sk_live_0123456789abcdefABCDEF"
_PEM = "-----BEGIN RSA PRIVATE KEY-----"


def _tool_docstring(name: str) -> str:
    source = Path(build_js_wasm_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            for keyword in decorator.keywords:
                if (
                    keyword.arg == "name"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value == name
                ):
                    return ast.get_docstring(node) or ""
    return ""


def _by_kind(payload: dict[str, object]) -> dict[str, dict[str, object]]:
    return {str(f["kind"]): f for f in payload["findings"]}  # type: ignore[index,union-attr]


def test_detects_the_major_providers() -> None:
    src = (
        f"const a='{_AWS}';\n"
        f"const g='{_GOOGLE}';\n"
        f"const h='{_GITHUB}';\n"
        f"const j='{_JWT}';\n"
        f"const s='{_STRIPE_LIVE}';\n"
    )
    kinds = _by_kind(extract_js_secrets(src))
    assert set(kinds) >= {
        "aws_access_key_id",
        "google_api_key",
        "github_token",
        "jwt",
        "stripe_secret_key",
    }


def test_ignores_a_secret_in_a_comment_or_bare_code() -> None:
    # The AWS key appears only in a comment and as a bare (unquoted) token, never
    # as a string literal, so it must not be flagged.
    src = f"// key {_AWS}\nconst x = {_AWS};\n"
    payload = extract_js_secrets(src)
    assert payload["findings"] == []
    assert payload["total"] == 0


def test_redacts_the_matched_value() -> None:
    src = f"const a = '{_AWS}';"
    finding = _by_kind(extract_js_secrets(src))["aws_access_key_id"]
    assert _AWS not in str(finding["preview"])
    assert str(finding["preview"]).startswith("AKIA")
    assert finding["length"] == len(_AWS)


def test_dedupes_repeated_secret_and_samples_lines() -> None:
    src = f"const a='{_AWS}';\nconst b='{_AWS}';\nconst c='{_AWS}';\n"
    finding = _by_kind(extract_js_secrets(src))["aws_access_key_id"]
    assert finding["count"] == 3
    assert finding["lines"] == [1, 2, 3]
    # One distinct finding, three occurrences.
    assert extract_js_secrets(src)["total"] == 1
    assert extract_js_secrets(src)["total_findings"] == 3


def test_severity_orders_high_before_medium() -> None:
    # A live Stripe key (high) and a test key (medium); high sorts first.
    src = f"const a='{_STRIPE_LIVE}';const b='sk_test_0123456789abcdefABCDEF';"
    findings = extract_js_secrets(src)["findings"]
    severities = [f["severity"] for f in findings]
    assert severities == sorted(severities, key=lambda s: {"high": 0, "medium": 1}[s])
    assert severities[0] == "high"


def test_detects_private_key_header() -> None:
    src = f'const k = "{_PEM}\\nMIIabc\\n-----END RSA PRIVATE KEY-----";'
    assert "private_key" in _by_kind(extract_js_secrets(src))


def test_clean_file_returns_no_findings() -> None:
    payload = extract_js_secrets("const greeting = 'hello there, this is fine';")
    assert payload["findings"] == []
    assert payload["kinds"] == {}
    assert payload["total_findings"] == 0


def test_pages_the_findings() -> None:
    src = "".join(f"const k{i}='sk_live_{i:022d}ABCDEF';" for i in range(5))
    payload = extract_js_secrets(src, offset=0, limit=2)
    assert payload["count"] == 2
    assert payload["total"] == 5
    assert payload["has_more"] is True


def test_scan_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    import headless_re_mcp.backends.jsre.js_static as js_static

    monkeypatch.setattr(js_static, "_MAX_SECRETS_COLLECT", 2)
    src = "".join(f"const k{i}='sk_live_{i:022d}ABCDEF';" for i in range(5))
    payload = extract_js_secrets(src)
    assert payload["total"] == 2
    assert payload["scan_capped"] is True


# --- client + service integration -------------------------------------------


def test_client_secrets_needs_no_webcrack(tmp_path: Path) -> None:
    js = tmp_path / "a.js"
    js.write_text(f"const k = '{_AWS}';", encoding="utf-8")
    payload = JsClient(None).secrets(js)
    assert "aws_access_key_id" in _by_kind(payload)


def test_client_secrets_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as caught:
        JsClient(None).secrets(tmp_path / "nope.js")
    assert caught.value.code == "not_found"


def test_client_secrets_oversized_is_too_large(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(client_mod, "_MAX_INPUT_BYTES", 16)
    js = tmp_path / "big.js"
    js.write_text(f"const k = '{_AWS}';" * 5, encoding="utf-8")
    with pytest.raises(JsReError) as caught:
        JsClient(None).secrets(js)
    assert caught.value.code == "too_large"


def test_service_js_secrets_dispatch(tmp_path: Path) -> None:
    from dataclasses import replace

    from headless_re_mcp.config import Settings
    from headless_re_mcp.core.service import AnalysisService

    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    js = tmp_path / "s.js"
    js.write_text(f"const k = '{_AWS}';", encoding="utf-8")
    result = service.js_secrets(str(js))
    assert result.ok, result.error
    assert result.data is not None
    assert "aws_access_key_id" in _by_kind(result.data)


def test_new_js_secrets_tool_is_registered() -> None:
    from headless_re_mcp.config import Settings
    from headless_re_mcp.core.service import AnalysisService

    service = AnalysisService(Settings.load())
    names = {tool.name for tool in build_js_wasm_tools(service)}
    assert "js.secrets" in names


def test_js_secrets_docstring_names_its_shape() -> None:
    doc = _tool_docstring("js.secrets")
    assert "findings" in doc
    assert "severity" in doc
    assert "preview" in doc
    assert "redact" in doc.lower()
    assert "too_large" in doc
