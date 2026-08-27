"""web.storage must return localStorage/sessionStorage, bounded and JSON-safe.

The DOM storage is the client-side token store a cookie read misses, so these
drive WebBackend.storage with a fake CDP that stands in for the DOMStorage
domain, plus direct checks of the origin and bounding helpers.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from threading import Lock
from typing import Any

from headless_re_mcp.backends.web.client import (
    _MAX_STORAGE_VALUE_BYTES,
    WebBackend,
    _bounded_storage,
    _security_origin,
)
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


class _StorageCdp:
    """Fake CDP DOMStorage: distinct entries for local vs session storage."""

    def __init__(self, local: list[list[str]], session: list[list[str]]) -> None:
        self._local = local
        self._session = session
        self.enabled = False

    def send(self, method: str, params: dict[str, Any] | None = None) -> Any:
        if method == "DOMStorage.enable":
            self.enabled = True
            return {}
        assert method == "DOMStorage.getDOMStorageItems", method
        assert params is not None
        is_local = params["storageId"]["isLocalStorage"]
        return {"entries": self._local if is_local else self._session}


class _Page:
    def __init__(self, url: str) -> None:
        self.url = url


class _Handle:
    def __init__(self, url: str, cdp: _StorageCdp) -> None:
        self.lock = Lock()
        self.page = _Page(url)
        self.cdp = cdp


def _storage(handle: _Handle, monkeypatch: Any) -> dict[str, Any]:
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    monkeypatch.setattr(backend, "_runner", lambda h: _Immediate())
    return backend.storage("s")


def test_returns_local_and_session_storage(monkeypatch: Any) -> None:
    cdp = _StorageCdp(
        local=[["gate_token", "jwtABC"], ["theme", "dark"]],
        session=[["csrf", "xyz"]],
    )
    handle = _Handle("http://127.0.0.1:8080/app", cdp)
    payload = _storage(handle, monkeypatch)
    assert payload["origin"] == "http://127.0.0.1:8080"
    assert payload["local_storage"] == {"gate_token": "jwtABC", "theme": "dark"}
    assert payload["session_storage"] == {"csrf": "xyz"}
    assert payload["local_storage_truncated"] is False
    assert payload["session_storage_truncated"] is False
    assert cdp.enabled is True


def test_opaque_origin_yields_empty_without_touching_cdp(monkeypatch: Any) -> None:
    cdp = _StorageCdp(local=[["k", "v"]], session=[])
    handle = _Handle("data:text/html,<h1>x</h1>", cdp)
    payload = _storage(handle, monkeypatch)
    # A data: URL has an opaque origin: report empty and never ask CDP for a
    # storageId it would reject.
    assert payload["origin"] == ""
    assert payload["local_storage"] == {}
    assert payload["session_storage"] == {}
    assert cdp.enabled is False


def test_large_value_is_capped_and_flagged(monkeypatch: Any) -> None:
    huge = "v" * (_MAX_STORAGE_VALUE_BYTES * 4)
    cdp = _StorageCdp(local=[["blob", huge]], session=[])
    handle = _Handle("https://example.com/", cdp)
    payload = _storage(handle, monkeypatch)
    assert len(payload["local_storage"]["blob"].encode()) <= _MAX_STORAGE_VALUE_BYTES
    assert payload["local_storage_truncated"] is True


def test_a_flood_of_entries_stays_within_budget(monkeypatch: Any) -> None:
    value = "x" * (_MAX_STORAGE_VALUE_BYTES - 64)
    local = [[f"k{i}", value] for i in range(200)]
    cdp = _StorageCdp(local=local, session=[])
    handle = _Handle("https://example.com/", cdp)
    payload = _storage(handle, monkeypatch)
    # The map is trimmed to fit its per-map budget; the trim is flagged.
    assert payload["local_storage_truncated"] is True
    assert len(payload["local_storage"]) < 200
    assert len(json.dumps(payload).encode()) <= 262144


def test_security_origin_extracts_scheme_host_port() -> None:
    assert _security_origin("http://127.0.0.1:8080/x?y=1") == "http://127.0.0.1:8080"
    assert _security_origin("https://example.com/a") == "https://example.com"
    # Opaque / non-web origins have no storage key.
    assert _security_origin("data:text/html,hi") is None
    assert _security_origin("about:blank") is None
    assert _security_origin(None) is None


def test_bounded_storage_coerces_and_skips_malformed() -> None:
    items, truncated = _bounded_storage([["a", "1"], ["bad"], "nope", [b"k", 2]])
    assert items == {"a": "1", "k": "2"}
    assert truncated is False


def test_docstring_names_both_stores() -> None:
    doc = _tool_docstring("web.storage")
    assert "local_storage" in doc
    assert "session_storage" in doc
    assert "origin" in doc
