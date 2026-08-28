"""web.indexed_db reads IndexedDB, stays bounded, and names its fields.

The third Web-storage surface after web.cookies and web.storage: SPAs keep auth
tokens, cached API responses and user records in IndexedDB, which no Set-Cookie
capture, document.cookie read or Web Storage read reaches. These fake the fixed
in-page reader (honoring its databases/stores/records/value caps) and cover the
structure summary, the flat record list, value truncation, the database/store/key
filters, paging, the truncation flags, the opaque-origin case, the error paths,
service routing, and the read-only classification.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.web import client as web_client
from headless_re_mcp.backends.web.client import (
    _MAX_IDB_VALUE,
    WebBackend,
    WebError,
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


class _Page:
    """A page whose evaluate() imitates the fixed IndexedDB snippet in JS.

    Given a nested {db -> stores -> [(key, value)]} description, it honors the
    same databases/stores/records/value caps the real reader applies, so the
    backend's own shaping and filtering are what gets exercised.
    """

    def __init__(
        self,
        dbs: list[dict[str, Any]] | None = None,
        *,
        origin: str = "https://app.example.com",
        unavailable: bool = False,
        returns: Any = None,
        raises: bool = False,
    ) -> None:
        self._dbs = dbs or []
        self._origin = origin
        self._unavailable = unavailable
        self._returns = returns
        self._raises = raises

    def evaluate(self, expression: str, arg: dict[str, Any]) -> Any:
        del expression
        if self._raises:
            raise RuntimeError("evaluate blew up")
        if self._returns is not None:
            return self._returns
        if self._unavailable:
            return {"unavailable": True, "origin": ""}
        max_databases = int(arg["maxDatabases"])
        max_stores = int(arg["maxStores"])
        max_records = int(arg["maxRecords"])
        max_per_store = int(arg["maxRecordsPerStore"])
        max_value = int(arg["maxValue"])
        databases: list[dict[str, Any]] = []
        records: list[dict[str, Any]] = []
        over = False
        stores_scanned = 0
        for meta in self._dbs:
            if len(databases) >= max_databases:
                over = True
                break
            name = meta["name"]
            version = meta.get("version")
            stores = meta.get("stores", {})
            shown: list[str] = []
            stores_over = False
            for store_name, recs in stores.items():
                if stores_scanned >= max_stores:
                    over = True
                    stores_over = True
                    break
                shown.append(store_name)
                stores_scanned += 1
                if len(records) >= max_records:
                    over = True
                    continue
                count = len(recs)
                if count > max_per_store:
                    count = max_per_store
                    over = True
                for index in range(count):
                    if len(records) >= max_records:
                        over = True
                        break
                    key, value = recs[index]
                    clipped = len(value) > max_value
                    records.append(
                        {
                            "database": name,
                            "store": store_name,
                            "key": key,
                            "value": value[:max_value] if clipped else value,
                            "value_truncated": clipped,
                        }
                    )
            row: dict[str, Any] = {"name": name, "version": version, "stores": shown}
            if stores_over:
                row["stores_over"] = True
            databases.append(row)
        return {
            "origin": self._origin,
            "databases": databases,
            "records": records,
            "over": over,
            "unavailable": False,
        }


def _backend(page: _Page, monkeypatch: Any) -> WebBackend:
    backend = WebBackend()
    handle = SimpleNamespace(page=page)
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    return backend


def _sample() -> list[dict[str, Any]]:
    return [
        {
            "name": "app-db",
            "version": 3,
            "stores": {
                "tokens": [("access", '{"jwt":"h.p.s"}'), ("refresh", '"r-token"')],
                "cache": [("/api/me", '{"id":1}')],
            },
        },
        {
            "name": "analytics",
            "version": 1,
            "stores": {"events": [("evt-1", '{"name":"click"}')]},
        },
    ]


def test_web_indexed_db_returns_structure_and_records(monkeypatch: Any) -> None:
    out = _backend(_Page(_sample()), monkeypatch).indexed_db("s")
    assert out["origin"] == "https://app.example.com"
    assert out["collection_truncated"] is False
    # databases is the structure overview: name, version, store names.
    by_db = {d["name"]: d for d in out["databases"]}
    assert by_db["app-db"]["version"] == 3
    assert set(by_db["app-db"]["stores"]) == {"tokens", "cache"}
    assert by_db["analytics"]["stores"] == ["events"]
    # records is the flat data across databases/stores.
    assert out["total"] == 4
    assert out["count"] == 4
    record = next(r for r in out["records"] if r["key"] == "access")
    assert record["database"] == "app-db"
    assert record["store"] == "tokens"
    assert record["value"] == '{"jwt":"h.p.s"}'
    assert "value_truncated" not in record


def test_web_indexed_db_serialized_placeholder_passes_through(monkeypatch: Any) -> None:
    dbs = [{"name": "files", "version": 1, "stores": {"blobs": [("avatar", "[Blob 1234]")]}}]
    out = _backend(_Page(dbs), monkeypatch).indexed_db("s")
    assert out["records"][0]["value"] == "[Blob 1234]"


def test_web_indexed_db_clips_a_huge_value_and_marks_it(monkeypatch: Any) -> None:
    dbs = [{"name": "d", "version": 1, "stores": {"s": [("big", "A" * (_MAX_IDB_VALUE + 50))]}}]
    row = _backend(_Page(dbs), monkeypatch).indexed_db("s")["records"][0]
    assert len(row["value"].encode()) <= _MAX_IDB_VALUE
    assert row["value_truncated"] is True


def test_web_indexed_db_null_version_becomes_none(monkeypatch: Any) -> None:
    dbs = [{"name": "d", "version": None, "stores": {"s": [("k", "v")]}}]
    out = _backend(_Page(dbs), monkeypatch).indexed_db("s")
    assert out["databases"][0]["version"] is None


def test_web_indexed_db_database_filter_before_paging(monkeypatch: Any) -> None:
    out = _backend(_Page(_sample()), monkeypatch).indexed_db("s", database_filter="ANALYTICS")
    assert {r["database"] for r in out["records"]} == {"analytics"}
    assert out["total"] == 1
    # The structure map still lists every database regardless of the record filter.
    assert {d["name"] for d in out["databases"]} == {"app-db", "analytics"}


def test_web_indexed_db_store_filter_before_paging(monkeypatch: Any) -> None:
    out = _backend(_Page(_sample()), monkeypatch).indexed_db("s", store_filter="tokens")
    assert {r["store"] for r in out["records"]} == {"tokens"}
    assert out["total"] == 2


def test_web_indexed_db_key_filter_is_case_insensitive(monkeypatch: Any) -> None:
    out = _backend(_Page(_sample()), monkeypatch).indexed_db("s", key_filter="REFRESH")
    assert [r["key"] for r in out["records"]] == ["refresh"]
    assert out["total"] == 1


def test_web_indexed_db_pages_and_reports_has_more(monkeypatch: Any) -> None:
    out = _backend(_Page(_sample()), monkeypatch).indexed_db("s", offset=0, limit=2)
    assert out["count"] == 2
    assert out["total"] == 4
    assert out["has_more"] is True
    assert out["offset"] == 0


def test_web_indexed_db_page_limit_is_capped(monkeypatch: Any) -> None:
    monkeypatch.setattr(web_client, "_MAX_IDB_PAGE", 2)
    out = _backend(_Page(_sample()), monkeypatch).indexed_db("s", limit=1000)
    assert out["count"] == 2
    assert out["total"] == 4
    assert out["has_more"] is True


def test_web_indexed_db_caps_databases_and_flags_truncation(monkeypatch: Any) -> None:
    monkeypatch.setattr(web_client, "_MAX_IDB_DATABASES", 1)
    out = _backend(_Page(_sample()), monkeypatch).indexed_db("s")
    assert len(out["databases"]) == 1
    assert out["collection_truncated"] is True


def test_web_indexed_db_flags_stores_truncated(monkeypatch: Any) -> None:
    monkeypatch.setattr(web_client, "_MAX_IDB_STORES", 1)
    out = _backend(_Page(_sample()), monkeypatch).indexed_db("s")
    first = out["databases"][0]
    assert first["stores_truncated"] is True
    assert out["collection_truncated"] is True


def test_web_indexed_db_opaque_origin_is_invalid_state(monkeypatch: Any) -> None:
    with pytest.raises(WebError) as info:
        _backend(_Page(unavailable=True), monkeypatch).indexed_db("s")
    assert info.value.code == "invalid_state"


def test_web_indexed_db_non_dict_result_is_backend_error(monkeypatch: Any) -> None:
    with pytest.raises(WebError) as info:
        _backend(_Page(returns=["not", "a", "dict"]), monkeypatch).indexed_db("s")
    assert info.value.code == "backend_error"


def test_web_indexed_db_evaluate_failure_is_backend_error(monkeypatch: Any) -> None:
    with pytest.raises(WebError) as info:
        _backend(_Page(raises=True), monkeypatch).indexed_db("s")
    assert info.value.code == "backend_error"


def test_service_web_indexed_db_routes_to_backend(monkeypatch: Any) -> None:
    from headless_re_mcp.core.service import AnalysisService

    service = AnalysisService()
    try:
        captured: dict[str, Any] = {}

        def fake_indexed_db(session_id: str, **kwargs: Any) -> dict[str, Any]:
            captured["session_id"] = session_id
            captured.update(kwargs)
            return {"records": [], "databases": [], "total": 0}

        monkeypatch.setattr(service._web_backend, "indexed_db", fake_indexed_db)
        result = service.web_indexed_db(
            "sess", limit=5, database_filter="app", store_filter="tok", key_filter="jwt"
        )
        assert result.ok and result.data is not None
        assert captured["session_id"] == "sess"
        assert captured["limit"] == 5
        assert captured["database_filter"] == "app"
        assert captured["store_filter"] == "tok"
        assert captured["key_filter"] == "jwt"
    finally:
        service.close_all()


def test_web_indexed_db_tool_docstring_and_read_only() -> None:
    doc = " ".join(_tool_docstring("web.indexed_db").split())
    assert "IndexedDB" in doc
    assert "databases" in doc
    assert "records" in doc
    assert "collection_truncated" in doc
    from headless_re_mcp.tools.catalog import _READ_ONLY_NAMES

    assert "web.indexed_db" in _READ_ONLY_NAMES
