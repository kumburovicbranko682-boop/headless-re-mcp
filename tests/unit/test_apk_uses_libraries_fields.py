"""apk.uses_libraries must parse <uses-library>/<uses-native-library> honestly.

The manifest declares shared framework and platform native libraries the app
loads from the device at runtime; that is a different fact from apk.native_libs
(the .so files packaged inside the APK). The parser has to read the Android
namespaced attributes the way androguard's own accessors do, default an omitted
android:required to true, and cap a large list while disclosing has_more.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.apk.client import ApkClient
from headless_re_mcp.tools.apk import build_apk_tools

_NS = "http://schemas.android.com/apk/res/android"


def _android(name: str) -> str:
    return f"{{{_NS}}}{name}"


class _El:
    """Minimal stand-in for the lxml element androguard returns.

    Reproduces only the two calls the parser makes: bare element tags with
    namespaced attributes, self-inclusive depth-first `iter(tag)`, and `get`.
    """

    def __init__(
        self,
        tag: str,
        attrs: dict[str, str] | None = None,
        children: list[_El] | None = None,
    ) -> None:
        self.tag = tag
        self._attrs = attrs or {}
        self._children = children or []

    def get(self, key: str, default: Any = None) -> Any:
        return self._attrs.get(key, default)

    def iter(self, tag: str | None = None) -> Iterator[_El]:
        if tag is None or self.tag == tag:
            yield self
        for child in self._children:
            yield from child.iter(tag)


class _FakeApk:
    def __init__(self, root: _El | None) -> None:
        self._root = root

    def get_android_manifest_xml(self) -> _El | None:
        return self._root


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


def _client_returning(root: _El | None) -> ApkClient:
    client = ApkClient()
    client._apk = lambda _path: _FakeApk(root)  # type: ignore[method-assign]
    return client


def test_uses_libraries_reads_required_type_and_namespace_fallback() -> None:
    """required defaults to true when omitted; bare-attr fallback still resolves.

    Measured intent: an entry with android:required="false" is optional, an
    entry with no required attribute is required (Android's default), a
    uses-native-library is type native, an attribute written without the
    android namespace still resolves via the bare-name fallback, and an entry
    with no name at all is dropped rather than surfaced as an empty dependency.
    """
    app = _El(
        "application",
        children=[
            _El(
                "uses-library",
                {_android("name"): "org.apache.http.legacy", _android("required"): "false"},
            ),
            _El("uses-library", {_android("name"): "android.test.runner"}),
            _El(
                "uses-native-library",
                {_android("name"): "libvulkan.so", _android("required"): "true"},
            ),
            _El("uses-library", {"name": "legacy.bare"}),
            _El("uses-library", {}),  # no name -> skipped
        ],
    )
    root = _El("manifest", children=[app])
    payload = _client_returning(root).uses_libraries(Path("dummy.apk"))

    assert "native_libs" not in payload
    assert "uses_libraries" not in payload
    assert payload["count"] == 4
    assert payload["has_more"] is False
    assert payload["libraries"] == [
        {"name": "android.test.runner", "type": "java", "required": True},
        {"name": "legacy.bare", "type": "java", "required": True},
        {"name": "org.apache.http.legacy", "type": "java", "required": False},
        {"name": "libvulkan.so", "type": "native", "required": True},
    ]

    doc = _tool_docstring("apk.uses_libraries")
    assert "libraries" in doc
    assert "required" in doc
    assert "has_more" in doc
    assert "apk.native_libs" in doc


def test_uses_libraries_caps_and_discloses_has_more() -> None:
    """A list that fills the 256 cap must report has_more, not read as complete."""
    children = [
        _El("uses-library", {_android("name"): f"lib.pkg.n{index:04d}"})
        for index in range(300)
    ]
    root = _El("manifest", children=[_El("application", children=children)])
    payload = _client_returning(root).uses_libraries(Path("dummy.apk"))

    assert payload["count"] == 256
    assert len(payload["libraries"]) == 256
    assert payload["has_more"] is True


def test_uses_libraries_missing_manifest_is_honest_error() -> None:
    """No manifest xml is a backend_error, not a silent empty dependency list."""
    from headless_re_mcp.backends.apk.client import ApkError

    client = _client_returning(None)
    try:
        client.uses_libraries(Path("dummy.apk"))
    except ApkError as exc:
        assert exc.code == "backend_error"
    else:  # pragma: no cover - the call must raise
        raise AssertionError("expected ApkError when manifest xml is unavailable")
