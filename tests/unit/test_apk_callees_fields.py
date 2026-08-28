"""apk.callees must return the forward call edges its description promises.

apk.callees is the mirror of apk.xrefs: xrefs walks get_xref_from (who calls
this method), callees walks get_xref_to (what this method calls). This pins the
payload shape -- callees rows of class/method, method_name echo, count and a
has_more that only trips when the page actually left something out -- against a
faked androguard analysis, so no real DEX or JRE is needed, and checks the
docstring names the fields the backend really returns.
"""

from __future__ import annotations

import ast
from pathlib import Path

from headless_re_mcp.backends.apk.client import ApkClient
from headless_re_mcp.tools.apk import build_apk_tools


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


class _FakeCallee:
    def __init__(self, class_name: str, name: str) -> None:
        self.class_name = class_name
        self.name = name


class _FakeMethod:
    def __init__(
        self, name: str, *, external: bool, callees: list[_FakeCallee]
    ) -> None:
        self._name = name
        self._external = external
        self._callees = callees

    @property
    def name(self) -> str:
        return self._name

    def is_external(self) -> bool:
        return self._external

    def get_xref_to(self) -> list[tuple[object, _FakeCallee, int]]:
        # androguard yields (class, callee-method, offset); the backend reads
        # the middle element, so the flanks can be anything.
        return [(None, callee, index) for index, callee in enumerate(self._callees)]


class _FakeParsed:
    def __init__(self, methods: list[_FakeMethod]) -> None:
        self.analysis = self
        self._methods = methods

    def get_methods(self) -> list[_FakeMethod]:
        return self._methods


def _client(methods: list[_FakeMethod]) -> ApkClient:
    client = ApkClient()
    client._parsed = lambda _path: _FakeParsed(methods)  # type: ignore[method-assign]
    return client


def test_callees_lists_forward_edges_of_named_methods() -> None:
    methods = [
        _FakeMethod(
            "onCreate",
            external=False,
            callees=[
                _FakeCallee("Landroid/util/Log;", "d"),
                _FakeCallee("Lcom/app/Db;", "open"),
            ],
        ),
        # A same-named method in another class contributes its edges too.
        _FakeMethod(
            "onCreate",
            external=False,
            callees=[_FakeCallee("Lcom/app/Net;", "connect")],
        ),
        # External and differently-named methods are skipped.
        _FakeMethod("onCreate", external=True, callees=[_FakeCallee("X", "y")]),
        _FakeMethod("onDestroy", external=False, callees=[_FakeCallee("X", "y")]),
    ]
    payload = _client(methods).callees(Path("dummy.apk"), "onCreate", limit=100)

    assert payload["method_name"] == "onCreate"
    assert "callers" not in payload
    assert payload["callees"] == [
        {"class": "Landroid/util/Log;", "method": "d"},
        {"class": "Lcom/app/Db;", "method": "open"},
        {"class": "Lcom/app/Net;", "method": "connect"},
    ]
    assert payload["count"] == 3
    assert payload["has_more"] is False


def test_callees_has_more_trips_only_when_a_row_is_dropped() -> None:
    callees = [_FakeCallee(f"L{i};", f"m{i}") for i in range(5)]
    methods = [_FakeMethod("run", external=False, callees=callees)]

    full = _client(methods).callees(Path("dummy.apk"), "run", limit=5)
    assert full["count"] == 5
    assert full["has_more"] is False

    clipped = _client(methods).callees(Path("dummy.apk"), "run", limit=3)
    assert clipped["count"] == 3
    assert clipped["has_more"] is True


def test_callees_rejects_blank_method_name() -> None:
    from headless_re_mcp.backends.apk.client import ApkError

    client = _client([])
    try:
        client.callees(Path("dummy.apk"), "   ", limit=10)
    except ApkError as exc:
        assert exc.code == "invalid_params"
    else:  # pragma: no cover - the call must raise
        raise AssertionError("blank method_name was accepted")


def test_callees_docstring_names_returned_fields() -> None:
    doc = _tool_docstring("apk.callees")
    assert "Answers with callees" in doc
    assert "method_name" in doc
    assert "has_more" in doc
