"""js.secrets: a node-free credential scanner over JS string literals.

The JS twin of apk.secrets. It reuses js.strings' literal scan, then matches a
fixed catalog of vendor-prefixed secret shapes, so a key hidden behind \\x / \\u
escapes is caught once decoded and one in a comment is skipped. These tests pin
the contract on hand-written JS: every catalog kind firing on a sample, comment
skipping, escape decoding, non-secret rejection, dedup, the match cap, paging,
both caps, truncation, the not_found guard and the tool docstring.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre.client import (
    _JS_SECRET_CATALOG,
    JsReError,
    scan_js_secrets,
)
from headless_re_mcp.tools.js_wasm import build_js_wasm_tools

SAMPLES = {
    "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
    "google_api_key": "AIza" + "B" * 35,
    "google_oauth_token": "ya29." + "A" * 30,
    "github_token": "ghp_" + "c" * 36,
    "slack_token": "xoxb-1234567890abcdef",
    "slack_webhook": "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX",
    "stripe_secret_key": "sk_live_" + "d" * 24,
    "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV",
    "private_key": "-----BEGIN RSA PRIVATE KEY-----",
    "twilio_api_key": "SK" + "0" * 32,
    "twilio_account_sid": "AC" + "f" * 32,
    "firebase_db": "https://myapp-12345.firebaseio.com",
}


def _write(tmp_path: Path, text: str) -> Path:
    target = tmp_path / "app.js"
    target.write_text(text, encoding="utf-8")
    return target


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


def test_every_catalog_kind_fires_on_its_sample(tmp_path: Path) -> None:
    catalog_kinds = {kind for kind, _ in _JS_SECRET_CATALOG}
    assert catalog_kinds == set(SAMPLES), catalog_kinds ^ set(SAMPLES)
    src = ";".join(f"var s{i} = {sample!r}" for i, sample in enumerate(SAMPLES.values()))
    payload = scan_js_secrets(_write(tmp_path, src))
    found = {(row["kind"], row["match"]) for row in payload["secrets"]}
    for kind, sample in SAMPLES.items():
        assert (kind, sample) in found, kind
    assert payload["kinds"] == sorted(SAMPLES)


def test_secrets_in_comments_are_skipped(tmp_path: Path) -> None:
    src = (
        f"// key {SAMPLES['aws_access_key_id']}\n"
        f"/* {SAMPLES['github_token']} */\n"
        f"var real = {SAMPLES['stripe_secret_key']!r};\n"
    )
    payload = scan_js_secrets(_write(tmp_path, src))
    assert [row["kind"] for row in payload["secrets"]] == ["stripe_secret_key"]


def test_obfuscated_secret_is_decoded_then_matched(tmp_path: Path) -> None:
    # "AKIAIOSFODNN7EXAMPLE" with the AKIA prefix hex-escaped.
    src = r"""var k = "\x41\x4b\x49\x41IOSFODNN7EXAMPLE";"""
    payload = scan_js_secrets(_write(tmp_path, src))
    assert payload["secrets"] == [{"kind": "aws_access_key_id", "match": "AKIAIOSFODNN7EXAMPLE"}]


def test_non_secret_strings_are_ignored(tmp_path: Path) -> None:
    src = "var a = 'hello world'; var b = 'AKIAshort'; var c = 'version 1.2.3';"
    payload = scan_js_secrets(_write(tmp_path, src))
    assert payload["secrets"] == []
    assert payload["kinds"] == []
    assert payload["total"] == 0


def test_dedup_by_kind_and_match(tmp_path: Path) -> None:
    key = SAMPLES["aws_access_key_id"]
    src = f"a({key!r}); b({key!r}); c('x {key} y');"
    payload = scan_js_secrets(_write(tmp_path, src))
    aws = [r for r in payload["secrets"] if r["kind"] == "aws_access_key_id"]
    assert len(aws) == 1


def test_match_is_capped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("headless_re_mcp.backends.jsre.client._MAX_JS_SECRET_MATCH_LEN", 8)
    src = f"var g = {SAMPLES['google_api_key']!r};"
    payload = scan_js_secrets(_write(tmp_path, src))
    row = next(r for r in payload["secrets"] if r["kind"] == "google_api_key")
    assert row["match"] == "AIzaBBBB"


def test_collect_cap_sets_scan_capped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("headless_re_mcp.backends.jsre.client._MAX_JS_SECRETS_COLLECT", 2)
    src = ";".join(f"f('https://app{i:05d}.firebaseio.com')" for i in range(6))
    payload = scan_js_secrets(_write(tmp_path, src))
    assert payload["total"] == 2
    assert payload["scan_capped"] is True


def test_literal_scan_cap_also_sets_scan_capped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("headless_re_mcp.backends.jsre.client._MAX_JS_STRINGS_COLLECT", 1)
    src = f"a('nope'); b({SAMPLES['firebase_db']!r});"
    payload = scan_js_secrets(_write(tmp_path, src))
    assert payload["scan_capped"] is True


def test_page_window_and_has_more(tmp_path: Path) -> None:
    src = ";".join(f"f('https://app{i:05d}.firebaseio.com')" for i in range(15))
    first = scan_js_secrets(_write(tmp_path, src), offset=0, limit=10)
    assert first["count"] == 10
    assert first["total"] == 15
    assert first["has_more"] is True
    tail = scan_js_secrets(_write(tmp_path, src), offset=10, limit=10)
    assert tail["count"] == 5
    assert tail["has_more"] is False


def test_unterminated_literal_sets_truncated(tmp_path: Path) -> None:
    src = f"var ok = {SAMPLES['firebase_db']!r}; var bad = 'https://cut.firebaseio.com"
    payload = scan_js_secrets(_write(tmp_path, src))
    assert payload["truncated"] is True


def test_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as info:
        scan_js_secrets(tmp_path / "nope.js")
    assert info.value.code == "not_found"


def test_docstring_names_returned_fields() -> None:
    doc = _tool_docstring("js.secrets")
    assert "Answers with" in doc
    assert "secrets" in doc and "kinds" in doc
    assert "scan_capped" in doc
