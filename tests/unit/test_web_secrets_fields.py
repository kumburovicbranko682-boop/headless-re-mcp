"""web.secrets scans the live page's parsed scripts for embedded credentials.

js.secrets scans a file at rest; web.secrets fetches the source of every script
the running page parsed -- including the runtime eval/new-Function scripts a
packer unpacks in memory and never writes to disk -- and runs the same detector
table (shared JS lexer + secret_scan.py) over each. These fake the parsed-script
list and the CDP getScriptSource fetch and cover cross-script dedup, the detector
summary, the dynamic_only/url filters, the WASM skip, name_filter, include_generic,
value truncation, the fetch-failure skip, the script/byte/finding caps, paging,
service routing and the read-only classification.

Secret-looking test values are assembled from fragments at runtime so the
contiguous string never appears in the committed bytes (GitHub push protection).
"""

from __future__ import annotations

import ast
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.web import client as web_client
from headless_re_mcp.backends.web.client import WebBackend
from headless_re_mcp.tools.web import build_web_tools

# Assembled so the whole secret never appears contiguously in this file.
_AWS = "AKIA" + "IOSFODNN7" + "EXAMPLE"
_STRIPE = "sk_" + "live_" + "0123456789abcdef0123"
_JWT = (
    "ey" + "JhbGciOiJIUzI1NiJ9"
    + "." + "ey" + "JzdWIiOiIxMjM0NTY3ODkwIn0"
    + "." + "dozjgNryP4J3jVmNHl0w5N" + "_XgL0n3I9PlFUP0THsR8U"
)
_JWT_LONG = (
    "ey" + "JhbGciOiJIUzI1NiJ9"
    + "." + "ey" + "JzdWIiOiJ4In0"
    + "." + ("a" * 560)
)
_HIGH_ENTROPY = "aB3xK9pQ7wZ2mN5vR8tY1cF4gH6jL0dS"


def _tool_docstring(name: str) -> str:
    source = Path(build_web_tools.__code__.co_filename).read_text(encoding="utf-8")
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


class _Immediate:
    def call(self, work: Any, timeout: float | None = None) -> Any:
        return work()


class _Cdp:
    def __init__(self, sources: dict[str, str], fail: set[str] | None = None) -> None:
        self._sources = sources
        self._fail = fail or set()
        self.calls: list[str] = []

    def send(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        del method
        sid = str(params["scriptId"])
        self.calls.append(sid)
        if sid in self._fail:
            raise RuntimeError("no such script")
        return {"scriptSource": self._sources.get(sid, "")}


def _handle(scripts: list[dict[str, Any]], cdp: _Cdp, *, dropped: int = 0) -> Any:
    from collections import OrderedDict

    table: OrderedDict[str, dict[str, Any]] = OrderedDict()
    for entry in scripts:
        table[str(entry["scriptId"])] = entry
    return SimpleNamespace(scripts=table, cdp=cdp, scripts_dropped=dropped, lock=threading.Lock())


def _backend(handle: Any, monkeypatch: Any) -> WebBackend:
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    return backend


def _js(entry_id: str, url: str, **extra: Any) -> dict[str, Any]:
    row = {"scriptId": entry_id, "url": url, "language": "JavaScript"}
    row.update(extra)
    return row


def _sample() -> tuple[list[dict[str, Any]], _Cdp]:
    scripts = [
        _js("1", "https://app.example.com/a.js"),
        _js("2", "https://app.example.com/b.js"),
        _js("3", "", dynamic=True),
    ]
    sources = {
        "1": f'var a = "{_AWS}"; var b = "{_STRIPE}";',
        "2": f'const j = "{_JWT}";',
        "3": f'window.k = "{_AWS}";',
    }
    return scripts, _Cdp(sources)


def _by_detector(out: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {row["detector"]: row for row in out["secrets"]}


def test_web_secrets_scans_all_scripts_and_dedupes(monkeypatch: Any) -> None:
    scripts, cdp = _sample()
    out = _backend(_handle(scripts, cdp, dropped=3), monkeypatch).secrets("s")
    assert out["scan_capped"] is False
    assert out["scanned_scripts"] == 3
    assert out["scripts_dropped"] == 3
    by_kind = _by_detector(out)
    assert by_kind["aws_access_key_id"]["value"] == _AWS
    # AWS is in scripts 1 and 3 -> deduped, count 2, first_script pins script 1.
    assert by_kind["aws_access_key_id"]["count"] == 2
    assert by_kind["aws_access_key_id"]["first_script"] == {
        "script_id": "1",
        "url": "https://app.example.com/a.js",
    }
    assert out["detectors"] == ["aws_access_key_id", "jwt", "stripe_secret_key"]


def test_web_secrets_dynamic_only_isolates_runtime_scripts(monkeypatch: Any) -> None:
    scripts, cdp = _sample()
    out = _backend(_handle(scripts, cdp), monkeypatch).secrets("s", dynamic_only=True)
    assert out["detectors"] == ["aws_access_key_id"]
    assert out["scanned_scripts"] == 1
    assert cdp.calls == ["3"]


def test_web_secrets_url_filter_narrows_scope(monkeypatch: Any) -> None:
    scripts, cdp = _sample()
    out = _backend(_handle(scripts, cdp), monkeypatch).secrets("s", url_filter="b.js")
    assert out["detectors"] == ["jwt"]
    assert cdp.calls == ["2"]


def test_web_secrets_skips_wasm_scripts(monkeypatch: Any) -> None:
    scripts = [
        _js("1", "https://app.example.com/a.js"),
        {"scriptId": "w", "url": "wasm://x", "language": "WebAssembly"},
    ]
    cdp = _Cdp({"1": f'var a = "{_AWS}";', "w": f'garbage "{_STRIPE}"'})
    out = _backend(_handle(scripts, cdp), monkeypatch).secrets("s")
    assert out["detectors"] == ["aws_access_key_id"]
    assert "w" not in cdp.calls


def test_web_secrets_name_filter_matches_detector_or_value(monkeypatch: Any) -> None:
    scripts, cdp = _sample()
    backend = _backend(_handle(scripts, cdp), monkeypatch)
    by_kind = backend.secrets("s", name_filter="STRIPE")
    assert [r["detector"] for r in by_kind["secrets"]] == ["stripe_secret_key"]
    by_value = backend.secrets("s", name_filter=_JWT.lower())
    assert [r["detector"] for r in by_value["secrets"]] == ["jwt"]


def test_web_secrets_include_generic_is_opt_in(monkeypatch: Any) -> None:
    scripts = [_js("1", "https://app.example.com/a.js")]
    cdp = _Cdp({"1": f'var token = "{_HIGH_ENTROPY}";'})
    backend = _backend(_handle(scripts, cdp), monkeypatch)
    assert backend.secrets("s")["total"] == 0
    out = backend.secrets("s", include_generic=True)
    assert [r["detector"] for r in out["secrets"]] == ["generic_high_entropy"]


def test_web_secrets_marks_value_truncated(monkeypatch: Any) -> None:
    scripts = [_js("1", "https://app.example.com/a.js")]
    cdp = _Cdp({"1": f'var t = "{_JWT_LONG}";'})
    row = _backend(_handle(scripts, cdp), monkeypatch).secrets("s")["secrets"][0]
    assert row["detector"] == "jwt"
    assert row["value_truncated"] is True


def test_web_secrets_skips_a_failed_fetch(monkeypatch: Any) -> None:
    scripts, _cdp = _sample()
    cdp = _Cdp(_cdp._sources, fail={"2"})
    out = _backend(_handle(scripts, cdp), monkeypatch).secrets("s")
    # Script 2 (the JWT) failed to fetch and was skipped, not fatal.
    assert "jwt" not in out["detectors"]
    assert "aws_access_key_id" in out["detectors"]
    assert out["scanned_scripts"] == 2


def test_web_secrets_pages_and_reports_has_more(monkeypatch: Any) -> None:
    scripts, cdp = _sample()
    out = _backend(_handle(scripts, cdp), monkeypatch).secrets("s", offset=0, limit=2)
    assert out["count"] == 2
    assert out["total"] == 3
    assert out["has_more"] is True


def test_web_secrets_script_count_cap(monkeypatch: Any) -> None:
    monkeypatch.setattr(web_client, "_MAX_WEB_SECRET_SCRIPTS", 1)
    scripts, cdp = _sample()
    out = _backend(_handle(scripts, cdp), monkeypatch).secrets("s")
    assert out["scan_capped"] is True
    assert out["scanned_scripts"] == 1


def test_web_secrets_scan_byte_budget(monkeypatch: Any) -> None:
    monkeypatch.setattr(web_client, "_MAX_WEB_SECRET_SCAN_BYTES", 5)
    scripts, cdp = _sample()
    out = _backend(_handle(scripts, cdp), monkeypatch).secrets("s")
    assert out["scan_capped"] is True
    assert out["scanned_scripts"] == 1


def test_web_secrets_findings_cap(monkeypatch: Any) -> None:
    monkeypatch.setattr(web_client, "_MAX_WEB_SECRET_FINDINGS", 1)
    scripts, cdp = _sample()
    out = _backend(_handle(scripts, cdp), monkeypatch).secrets("s")
    assert out["scan_capped"] is True
    assert out["total"] == 1


def test_service_web_secrets_routes_to_backend(monkeypatch: Any) -> None:
    from headless_re_mcp.core.service import AnalysisService

    service = AnalysisService()
    try:
        captured: dict[str, Any] = {}

        def fake_secrets(session_id: str, **kwargs: Any) -> dict[str, Any]:
            captured["session_id"] = session_id
            captured.update(kwargs)
            return {"secrets": [], "total": 0}

        monkeypatch.setattr(service._web_backend, "secrets", fake_secrets)
        result = service.web_secrets(
            "sess", limit=5, name_filter="jwt", include_generic=True,
            url_filter="app", dynamic_only=True,
        )
        assert result.ok and result.data is not None
        assert captured["session_id"] == "sess"
        assert captured["limit"] == 5
        assert captured["name_filter"] == "jwt"
        assert captured["include_generic"] is True
        assert captured["url_filter"] == "app"
        assert captured["dynamic_only"] is True
    finally:
        service.close_all()


def test_web_secrets_tool_docstring_and_read_only() -> None:
    doc = " ".join(_tool_docstring("web.secrets").split())
    assert "detector" in doc
    assert "first_script" in doc
    assert "scan_capped" in doc
    from headless_re_mcp.tools.catalog import _READ_ONLY_NAMES

    assert "web.secrets" in _READ_ONLY_NAMES
