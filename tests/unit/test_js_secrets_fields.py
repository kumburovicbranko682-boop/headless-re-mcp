"""js.secrets detects embedded credentials in a JS file's string literals.

js.strings returns every literal and js.endpoints the network surface; js.secrets
is the credential cut on the same lexer -- the API keys, tokens and private keys
a bundle hardcoded. These cover the individual detectors, escape-decoding,
dedup/aggregation, comment/regex safety (reused lexer), the include_generic
gate, value clipping, the filter, sorting, the collect cap, client paging, the
webcrack-free path, errors, service routing, and the read-only classification.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.jsre import client as jsre_client
from headless_re_mcp.backends.jsre import js_strings as js_strings_mod
from headless_re_mcp.backends.jsre.client import JsClient, JsReError
from headless_re_mcp.backends.jsre.js_strings import extract_secrets
from headless_re_mcp.tools.js_wasm import build_js_wasm_tools

# Canonical fake credentials (pattern-valid, not real): the AWS docs example
# key, a canonical example JWT, and synthetic keys of the required shape.
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
GH_TOKEN = "ghp_" + "0123456789abcdefghijklmnopqrstuvwxyz"
GOOGLE_KEY = "AIza" + "B" * 35
# Assembled from fragments so the full (fake) secret never appears verbatim in
# this file's committed bytes -- GitHub push protection flags a contiguous Slack
# webhook/token even when it is a test value. The detector still sees the whole
# reconstructed string at runtime.
SLACK_WEBHOOK = "https://hooks.slack.com/" + "services/" + "T00000000/B00000000/" + "a" * 24
SLACK_TOKEN = "xoxb-" + "1234567890-abcdefghijklmn"
STRIPE_KEY = "sk_live_" + "0123456789abcdef0123abcd"
JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ"
    ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)


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


def _by_value(source: str, **kwargs: Any) -> dict[str, dict[str, Any]]:
    secrets, _detectors, _capped = extract_secrets(source, **kwargs)
    return {s["value"]: s for s in secrets}


def _detectors_of(source: str, **kwargs: Any) -> set[str]:
    secrets, _detectors, _capped = extract_secrets(source, **kwargs)
    return {s["detector"] for s in secrets}


def test_detects_aws_access_key_id() -> None:
    secrets, detectors, capped = extract_secrets(f'var k = "{AWS_KEY}";')
    assert capped is False
    assert len(secrets) == 1
    assert secrets[0]["detector"] == "aws_access_key_id"
    assert secrets[0]["value"] == AWS_KEY
    assert secrets[0]["count"] == 1
    assert detectors == ["aws_access_key_id"]


def test_detects_google_api_key() -> None:
    assert _detectors_of(f'const k="{GOOGLE_KEY}";') == {"google_api_key"}


def test_detects_github_token() -> None:
    row = _by_value(f'token = "{GH_TOKEN}"')[GH_TOKEN]
    assert row["detector"] == "github_token"


def test_detects_slack_webhook() -> None:
    assert _detectors_of(f'post("{SLACK_WEBHOOK}")') == {"slack_webhook"}


def test_detects_slack_token() -> None:
    assert _detectors_of(f'h={{a:"{SLACK_TOKEN}"}}') == {"slack_token"}


def test_detects_stripe_secret_key() -> None:
    assert _detectors_of(f'k="{STRIPE_KEY}"') == {"stripe_secret_key"}


def test_detects_jwt() -> None:
    row = _by_value(f'var t = "{JWT}";')[JWT]
    assert row["detector"] == "jwt"


def test_detects_private_key_header() -> None:
    src = "var pem = '-----BEGIN RSA PRIVATE KEY-----\\nMIIabc...';"
    detectors = _detectors_of(src)
    assert "private_key" in detectors


def test_detects_basic_auth_url() -> None:
    row = _by_value('fetch("https://admin:s3cr3t@internal.test/api")')
    assert "https://admin:s3cr3t@internal.test" in row
    assert row["https://admin:s3cr3t@internal.test"]["detector"] == "basic_auth_url"


def test_decodes_hex_escaped_secret() -> None:
    escaped = "".join(f"\\x{ord(c):02x}" for c in AWS_KEY)
    row = _by_value(f'var k = "{escaped}";')
    assert AWS_KEY in row
    assert row[AWS_KEY]["detector"] == "aws_access_key_id"


def test_deduplicates_and_counts_occurrences() -> None:
    src = f'a="{AWS_KEY}"; b="{AWS_KEY}";'
    secrets, _detectors, _capped = extract_secrets(src)
    assert len(secrets) == 1
    assert secrets[0]["count"] == 2
    assert secrets[0]["first_offset"] == src.index('"')


def test_secret_in_comment_is_not_detected() -> None:
    src = f"// leftover key {AWS_KEY}\nvar ok = '{GH_TOKEN}';"
    detectors = _detectors_of(src)
    assert detectors == {"github_token"}


def test_secret_in_regex_literal_is_not_detected() -> None:
    src = f"var re = /{AWS_KEY}/; var s = \"{GH_TOKEN}\";"
    values = set(_by_value(src))
    assert GH_TOKEN in values
    assert AWS_KEY not in values


def test_generic_high_entropy_is_gated_off_by_default() -> None:
    token = "aB3xZ9kQ2wE7rT1yU5iO0pL4mN6vC8bX0zA2sD4fG6h"
    assert _detectors_of(f'k="{token}"') == set()
    assert _detectors_of(f'k="{token}"', include_generic=True) == {"generic_high_entropy"}


def test_generic_skips_low_entropy_token() -> None:
    token = "a" * 40
    assert _detectors_of(f'k="{token}"', include_generic=True) == set()


def test_generic_skips_literal_a_specific_detector_claimed() -> None:
    # The github token literal is also long/base64-ish, but a specific detector
    # already claimed it, so the generic catch-all must not double-flag it.
    detectors = _detectors_of(f'k="{GH_TOKEN}"', include_generic=True)
    assert detectors == {"github_token"}


def test_value_truncated_on_oversized_match() -> None:
    long_jwt = "eyJ" + "a" * 250 + ".eyJ" + "b" * 250 + "." + "c" * 250
    row = _by_value(f'var t = "{long_jwt}";')
    assert len(row) == 1
    (secret,) = row.values()
    assert secret["detector"] == "jwt"
    assert secret["value_truncated"] is True
    assert len(secret["value"]) == js_strings_mod._MAX_SECRET_VALUE


def test_name_filter_matches_detector_or_value() -> None:
    src = f'a="{AWS_KEY}"; b="{GH_TOKEN}";'
    secrets, _detectors, _capped = extract_secrets(src, name_filter="aws")
    assert [s["value"] for s in secrets] == [AWS_KEY]
    secrets2, _d2, _c2 = extract_secrets(src, name_filter=GH_TOKEN[:10])
    assert [s["value"] for s in secrets2] == [GH_TOKEN]


def test_sorted_by_detector_then_count() -> None:
    other_aws = "ASIAZZZZZZZZZZZZZZZZ"
    src = f'a="{AWS_KEY}"; b="{AWS_KEY}"; c="{other_aws}"; d="{GH_TOKEN}";'
    secrets, _detectors, _capped = extract_secrets(src)
    assert [s["detector"] for s in secrets] == [
        "aws_access_key_id",
        "aws_access_key_id",
        "github_token",
    ]
    # Within aws, the count-2 key sorts before the count-1 key.
    assert secrets[0]["value"] == AWS_KEY
    assert secrets[0]["count"] == 2
    assert secrets[1]["value"] == other_aws


def test_collect_cap_sets_scan_capped(monkeypatch: Any) -> None:
    monkeypatch.setattr(js_strings_mod, "_MAX_SECRETS_COLLECT", 2)
    keys = [f"AKIA{i:016d}" for i in range(5)]
    src = ";".join(f'x="{k}"' for k in keys)
    secrets, _detectors, capped = extract_secrets(src)
    assert capped is True
    assert len(secrets) == 2


def _write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "bundle.js"
    p.write_text(text, encoding="utf-8")
    return p


def test_client_secrets_pages_and_summarises(tmp_path: Path) -> None:
    keys = [f"AKIA{i:016d}" for i in range(10)]
    src = ";".join(f'x="{k}"' for k in keys) + f'; g="{GH_TOKEN}";'
    out = JsClient().secrets(_write(tmp_path, src), limit=3)
    assert out["count"] == 3
    assert out["total"] == 11
    assert out["has_more"] is True
    assert out["detectors"] == ["aws_access_key_id", "github_token"]
    assert out["scan_capped"] is False


def test_client_secrets_works_without_webcrack(tmp_path: Path) -> None:
    client = JsClient(executable=None)
    assert client.available is False
    out = client.secrets(_write(tmp_path, f'var k = "{AWS_KEY}";'))
    assert [s["value"] for s in out["secrets"]] == [AWS_KEY]


def test_client_secrets_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as info:
        JsClient().secrets(tmp_path / "nope.js")
    assert info.value.code == "not_found"


def test_client_secrets_page_limit_is_capped(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(jsre_client, "_MAX_JS_SECRETS_PAGE", 2)
    keys = [f"AKIA{i:016d}" for i in range(6)]
    src = ";".join(f'x="{k}"' for k in keys)
    out = JsClient().secrets(_write(tmp_path, src), limit=1000)
    assert out["count"] == 2
    assert out["total"] == 6
    assert out["has_more"] is True


def test_service_js_secrets_routes_to_client(tmp_path: Path) -> None:
    from headless_re_mcp.core.service import AnalysisService

    service = AnalysisService()
    try:
        src = f'a="{AWS_KEY}"; b="{GH_TOKEN}";'
        p = _write(tmp_path, src)
        result = service.js_secrets(str(p), name_filter="github")
        assert result.ok and result.data is not None
        assert [s["value"] for s in result.data["secrets"]] == [GH_TOKEN]
        assert result.data["total"] == 1
        assert result.data["detectors"] == ["github_token"]
    finally:
        service.close_all()


def test_js_secrets_tool_docstring_and_read_only() -> None:
    doc = " ".join(_tool_docstring("js.secrets").split())
    assert "secrets" in doc
    assert "detectors" in doc
    assert "include_generic" in doc
    from headless_re_mcp.tools.catalog import _READ_ONLY_NAMES

    assert "js.secrets" in _READ_ONLY_NAMES
