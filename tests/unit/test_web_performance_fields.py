"""web.performance reads Navigation/Resource Timing, bounded and normalised.

Driven through the _get/_runner seam with a fake page whose evaluate() returns
the shape the in-page script produces. No real browser is needed.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.web.client import WebBackend
from headless_re_mcp.tools.web import build_web_tools


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


class _Page:
    def __init__(self, result: Any, url: str) -> None:
        self._result = result
        self.url = url

    def evaluate(self, script: str, cfg: dict[str, Any]) -> Any:
        del script, cfg
        return self._result


def _backend_with(monkeypatch: Any, result: Any, url: str) -> WebBackend:
    backend = WebBackend()
    page = _Page(result, url)
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(page=page))
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    return backend


def _timing() -> dict[str, Any]:
    return {
        "navigation": {
            "type": "navigate",
            "redirect_count": 1,
            "dns_ms": 12,
            "connect_ms": 30,
            "tls_ms": 18,
            "ttfb_ms": 210,
            "response_ms": 40,
            "dom_interactive_ms": 500,
            "dom_content_loaded_ms": 620,
            "load_ms": 900,
            "transfer_size": 4096,
            "encoded_body_size": 3800,
            "decoded_body_size": 12000,
        },
        "resources": [
            {
                "url": "https://cdn.example/app.js",
                "initiator_type": "script",
                "duration_ms": 350,
                "transfer_size": 90000,
            },
            {
                "url": "https://cdn.example/style.css",
                "initiator_type": "link",
                "duration_ms": 40,
                "transfer_size": 5000,
            },
        ],
        "resource_total": 2,
    }


def test_performance_reports_navigation_phases(monkeypatch: Any) -> None:
    payload = _backend_with(
        monkeypatch, _timing(), "https://example.com/"
    ).performance("s")
    nav = payload["navigation"]
    assert nav["type"] == "navigate"
    assert nav["redirect_count"] == 1
    assert nav["ttfb_ms"] == 210
    assert nav["load_ms"] == 900
    assert nav["decoded_body_size"] == 12000
    assert payload["url"] == "https://example.com/"


def test_performance_lists_resources(monkeypatch: Any) -> None:
    payload = _backend_with(
        monkeypatch, _timing(), "https://example.com/"
    ).performance("s")
    assert payload["resource_count"] == 2
    assert payload["resource_total"] == 2
    assert payload["truncated"] is False
    first = payload["resources"][0]
    assert first["url"] == "https://cdn.example/app.js"
    assert first["initiator_type"] == "script"
    assert first["duration_ms"] == 350


def test_performance_handles_missing_navigation_entry(monkeypatch: Any) -> None:
    raw = {"navigation": None, "resources": [], "resource_total": 0}
    payload = _backend_with(monkeypatch, raw, "about:blank").performance("s")
    assert payload["navigation"] is None
    assert payload["resources"] == []
    assert payload["resource_count"] == 0


def test_performance_reports_truncation(monkeypatch: Any) -> None:
    raw = _timing()
    raw["resource_total"] = 500
    payload = _backend_with(
        monkeypatch, raw, "https://example.com/"
    ).performance("s")
    assert payload["truncated"] is True
    assert payload["resource_total"] == 500


def test_performance_rejects_non_dict(monkeypatch: Any) -> None:
    from headless_re_mcp.backends.web.client import WebError

    backend = _backend_with(monkeypatch, ["not", "a", "dict"], "https://x/")
    try:
        backend.performance("s")
    except WebError as exc:
        assert exc.code == "backend_error"
    else:  # pragma: no cover - the call must raise
        raise AssertionError("expected WebError backend_error")


def test_web_performance_docstring_names_the_shape() -> None:
    doc = _tool_docstring("web.performance")
    assert "navigation" in doc
    assert "ttfb_ms" in doc
    assert "resources" in doc
    assert "resource_total" in doc
