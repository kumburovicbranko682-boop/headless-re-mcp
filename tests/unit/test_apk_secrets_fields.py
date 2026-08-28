"""apk.secrets classifies DEX string constants against the credential table.

The classifier itself is the shared backends.common.secrets.classify_secrets
(also driving js.secrets); this file drives the ApkClient._parsed seam plus the
No-line-number path of the shared classifier.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.apk.client import ApkClient
from headless_re_mcp.backends.common.secrets import classify_secrets, redact_secret
from headless_re_mcp.tools.apk import build_apk_tools

_AWS = "AKIAIOSFODNN7EXAMPLE"
_GOOGLE = "AIzaSyA1234567890abcdefghijklmnopqrstuv"
_FIREBASE = "https://my-app-12345.firebaseio.com"


def _tool_docstring(name: str) -> str:
    source = Path(build_apk_tools.__code__.co_filename).read_text(encoding="utf-8")
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


def _fake_client(strings: list[str]) -> ApkClient:
    fake_items = [SimpleNamespace(get_value=lambda v=s: v) for s in strings]
    fake_parsed = SimpleNamespace(
        analysis=SimpleNamespace(get_strings=lambda: fake_items)
    )
    client = ApkClient()
    client._parsed = lambda _path: fake_parsed  # type: ignore[method-assign]
    return client


def _by_kind(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(f["kind"]): f for f in payload["findings"]}


# --- shared classifier, no-location path -----------------------------------


def test_classify_secrets_without_locations_keeps_lines_empty() -> None:
    payload = classify_secrets([(f"key {_AWS}", None), (f"dup {_AWS}", None)])
    finding = _by_kind(payload)["aws_access_key_id"]
    # Same secret across two constants: one finding, counted twice, no lines.
    assert finding["count"] == 2
    assert finding["lines"] == []
    assert payload["total"] == 1
    assert payload["total_findings"] == 2


def test_classify_secrets_redacts_and_orders_by_severity() -> None:
    payload = classify_secrets(
        [(_GOOGLE, None), ("sk_test_0123456789abcdefABCDEF", None)]
    )
    severities = [f["severity"] for f in payload["findings"]]
    assert severities[0] == "high"  # google_api_key before the test key
    for finding in payload["findings"]:
        assert "*" in str(finding["preview"])


def test_redact_secret_hides_the_body() -> None:
    out = redact_secret(_AWS)
    assert _AWS not in out
    assert out.startswith("AKIA")
    assert "(len 20)" in out


# --- apk.secrets through the client seam ------------------------------------


def test_apk_secrets_finds_keys_in_dex_strings() -> None:
    client = _fake_client(
        [
            f"config {_AWS}",
            _GOOGLE,
            _FIREBASE,
            "just a normal resource string",
        ]
    )
    payload = client.secrets(Path("d.apk"))
    kinds = _by_kind(payload)
    assert set(kinds) >= {"aws_access_key_id", "google_api_key", "firebase_database_url"}
    assert payload["total_findings"] >= 3


def test_apk_secrets_clean_app_has_no_findings() -> None:
    client = _fake_client(["Landroid/app/Activity;", "onCreate", "hello world"])
    payload = client.secrets(Path("d.apk"))
    assert payload["findings"] == []
    assert payload["kinds"] == {}


def test_apk_secrets_pages() -> None:
    strings = [f"sk_live_{i:022d}ABCDEF" for i in range(5)]
    payload = _fake_client(strings).secrets(Path("d.apk"), offset=0, limit=2)
    assert payload["count"] == 2
    assert payload["total"] == 5
    assert payload["has_more"] is True


def test_apk_secrets_scan_capped(monkeypatch: Any) -> None:
    import headless_re_mcp.backends.apk.client as apk_client

    monkeypatch.setattr(apk_client, "_MAX_STRINGS_COLLECT", 2)
    strings = [f"sk_live_{i:022d}ABCDEF" for i in range(5)]
    payload = _fake_client(strings).secrets(Path("d.apk"))
    # Only the first two constants were scanned before the input cap tripped.
    assert payload["scan_capped"] is True
    assert payload["total"] == 2


# --- service + tool registration --------------------------------------------


def test_service_apk_secrets_dispatch(monkeypatch: Any, tmp_path: Path) -> None:
    from headless_re_mcp.config import Settings
    from headless_re_mcp.core.service import AnalysisService

    service = AnalysisService(Settings.load())
    monkeypatch.setattr(
        service, "_apk_binary", lambda _sid: tmp_path / "d.apk"
    )
    monkeypatch.setattr(
        ApkClient,
        "secrets",
        lambda self, binary, offset=0, limit=200: {"findings": [], "total": 0},
    )
    result = service.apk_secrets("sess-1")
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["total"] == 0


def test_apk_secrets_tool_is_registered() -> None:
    from headless_re_mcp.config import Settings
    from headless_re_mcp.core.service import AnalysisService

    service = AnalysisService(Settings.load())
    names = {tool.name for tool in build_apk_tools(service)}
    assert "apk.secrets" in names


def test_apk_secrets_docstring_names_the_shape() -> None:
    doc = " ".join(_tool_docstring("apk.secrets").split())
    assert "findings" in doc
    assert "severity" in doc
    assert "redact" in doc.lower()
    assert "scan_capped" in doc
    assert "lines list is always empty" in doc
