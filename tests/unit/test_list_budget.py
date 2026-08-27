"""Paged list results must fit the transport budget by their encoded size.

apk.classes/methods/strings/xrefs and proxy.flows return windowed lists whose
per-row size varies -- an apk string is capped at 2000 chars, a flow url at
16 KiB -- so a page that fills the row-count limit can still encode past the
262144-byte result budget. When that happens ``bounded_tool_result`` throws the
*whole* reply away (rows, counts, and pagination cursors) for a ~16 KiB summary,
and the count cap alone cannot prevent it. Each method trims its window with
``fit_json_list`` before ``has_more`` is computed. These tests drive real
oversized data through the real budget and check three things: the page was
trimmed below the requested limit, the encoded reply fits the budget, and
``has_more`` still says there is more to fetch so a caller pages past it.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.apk.client import ApkClient
from headless_re_mcp.backends.common.json_budget import RESULT_BUDGET_BYTES
from headless_re_mcp.backends.proxy.client import ProxyBackend, _FlowRecorder


def _encoded_size(payload: dict[str, Any]) -> int:
    return len(json.dumps(payload, ensure_ascii=False).encode("utf-8"))


class _FakeMethod:
    def __init__(self, name: str, descriptor: str = "", access: str = "") -> None:
        self.name = name
        self.descriptor = descriptor
        self.access = access
        self._xrefs: list[Any] = []

    def is_external(self) -> bool:
        return False

    def get_methods(self) -> list[_FakeMethod]:
        return []

    def get_xref_from(self) -> list[tuple[Any, Any, Any]]:
        return self._xrefs


class _FakeClass:
    def __init__(self, name: str, methods: list[_FakeMethod] | None = None) -> None:
        self.name = name
        self._methods = methods or []

    def is_external(self) -> bool:
        return False

    def get_methods(self) -> list[_FakeMethod]:
        return self._methods


class _FakeString:
    def __init__(self, value: str) -> None:
        self._value = value

    def get_value(self) -> str:
        return self._value


class _FakeAnalysis:
    def __init__(
        self,
        *,
        classes: list[_FakeClass] | None = None,
        strings: list[_FakeString] | None = None,
        methods: list[_FakeMethod] | None = None,
    ) -> None:
        self._classes = classes or []
        self._strings = strings or []
        self._methods = methods or []

    def get_classes(self) -> list[_FakeClass]:
        return self._classes

    def get_strings(self) -> list[_FakeString]:
        return self._strings

    def get_methods(self) -> list[_FakeMethod]:
        return self._methods


def _apk_with(analysis: _FakeAnalysis) -> ApkClient:
    client = ApkClient()
    client._parsed = lambda _path: SimpleNamespace(analysis=analysis)  # type: ignore[method-assign]
    return client


def test_classes_page_is_trimmed_to_the_encoded_budget() -> None:
    # 1500 classes, each name ~300 chars: a 1000-row page encodes to ~300 KB,
    # past the budget, so the count limit never bites -- the size does.
    names = [f"L{index:05d}" + "n" * 295 + ";" for index in range(1500)]
    client = _apk_with(_FakeAnalysis(classes=[_FakeClass(name) for name in names]))

    payload = client.classes(Path("app.apk"), offset=0, limit=1000)

    assert 0 < payload["count"] < 1000
    assert len(payload["classes"]) == payload["count"]
    assert payload["total"] == 1500
    assert payload["has_more"] is True
    assert _encoded_size(payload) <= RESULT_BUDGET_BYTES


def test_methods_page_is_trimmed_to_the_encoded_budget() -> None:
    methods = [
        _FakeMethod(f"m{index:04d}", descriptor="(" + "J" * 300 + ")V", access="public")
        for index in range(1200)
    ]
    analysis = _FakeAnalysis(classes=[_FakeClass("Lcom/x;", methods)])
    client = _apk_with(analysis)

    payload = client.methods(Path("app.apk"), "Lcom/x;", offset=0, limit=1000)

    assert 0 < payload["count"] < 1000
    assert len(payload["methods"]) == payload["count"]
    assert payload["total"] == 1200
    assert payload["has_more"] is True
    assert _encoded_size(payload) <= RESULT_BUDGET_BYTES


def test_strings_default_page_already_overflows_and_is_trimmed() -> None:
    # The headline case: the default limit is 200 and each string is capped at
    # 2000 chars, so 200 rows is ~400 KB with no help from the caller -- the
    # default page overflows on its own.
    strings = [_FakeString(f"{index:04d}" + "x" * 1996) for index in range(300)]
    client = _apk_with(_FakeAnalysis(strings=strings))

    payload = client.strings(Path("app.apk"))  # default offset=0, limit=200

    assert 0 < payload["count"] < 200
    assert len(payload["strings"]) == payload["count"]
    assert payload["total"] == 300
    assert payload["has_more"] is True
    assert _encoded_size(payload) <= RESULT_BUDGET_BYTES


def test_strings_small_page_is_returned_whole() -> None:
    # A page that fits is not trimmed and does not lie about having more.
    strings = [_FakeString(f"s{index}") for index in range(20)]
    client = _apk_with(_FakeAnalysis(strings=strings))

    payload = client.strings(Path("app.apk"), offset=0, limit=100)

    assert payload["count"] == 20
    assert payload["has_more"] is False
    assert _encoded_size(payload) <= RESULT_BUDGET_BYTES


def test_xrefs_budget_cut_drives_has_more_without_an_offset() -> None:
    # 800 callers with long class names, limit 2000: the row cap is never hit
    # (so the count-cap has_more stays False), but the encoded list overflows,
    # so has_more must come from the budget cut alone -- xrefs has no offset to
    # page with, so a trimmed list would otherwise read as the whole set.
    target = _FakeMethod("secret")
    target._xrefs = [
        (None, SimpleNamespace(class_name="L" + "c" * 400 + str(index) + ";", name="caller"), None)
        for index in range(800)
    ]
    analysis = _FakeAnalysis(methods=[target])
    client = _apk_with(analysis)

    payload = client.xrefs(Path("app.apk"), "secret", limit=2000)

    assert 0 < payload["count"] < 800
    assert len(payload["callers"]) == payload["count"]
    assert payload["has_more"] is True
    assert _encoded_size(payload) <= RESULT_BUDGET_BYTES


def test_proxy_flows_page_is_trimmed_to_the_encoded_budget(monkeypatch: Any) -> None:
    # Each summary carries a url up to 16 KiB, so a 100-row page of long urls
    # can run to megabytes; the row-count limit never bites, the size does.
    recorder = _FlowRecorder(capacity=500)
    long_url = "http://x/" + "u" * 8000
    for index in range(300):
        request = SimpleNamespace(
            method="GET", pretty_url=f"{long_url}/{index}", host="x"
        )
        response = SimpleNamespace(
            status_code=200, headers={"content-type": "text/plain"}
        )
        recorder.response(
            SimpleNamespace(id=str(index), request=request, response=response)
        )

    backend = ProxyBackend()
    monkeypatch.setattr(
        backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder)
    )

    payload = backend.flows("s", offset=0, limit=100)

    assert 0 < payload["count"] < 100
    assert len(payload["flows"]) == payload["count"]
    assert payload["total"] == 300
    assert payload["has_more"] is True
    assert _encoded_size(payload) <= RESULT_BUDGET_BYTES
