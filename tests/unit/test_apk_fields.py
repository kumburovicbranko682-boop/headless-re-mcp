"""apk tool descriptions must name the fields the backends return."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apk.client import _MAX_MANIFEST_CHARS, ApkClient, ApkError
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


class _FakeCall:
    def __init__(self, index: int) -> None:
        self.class_name = f"Lcom/example/Caller{index};"
        self.name = "invoke"


class _FakeMethod:
    def __init__(self, name: str, callers: int) -> None:
        self.name = name
        self._callers = callers

    def is_external(self) -> bool:
        return False

    def get_xref_from(self) -> list[tuple[object, _FakeCall, int]]:
        return [(None, _FakeCall(index), index) for index in range(self._callers)]


class _FakeParsed:
    def __init__(self, methods: list[_FakeMethod]) -> None:
        self.analysis = self
        self._methods = methods

    def get_methods(self) -> list[_FakeMethod]:
        return self._methods


def test_apk_xrefs_puts_the_list_in_callers_and_says_when_it_stopped(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The catalog said xrefs-from and never named the payload.

    Measured: 25 callers, limit 10 -> count 10, has_more True, field is
    callers not xrefs. Looking for xrefs after a successful call reads as
    no callers, and a full page with no has_more reads as the whole list.
    """
    client = ApkClient()
    monkeypatch.setattr(
        ApkClient,
        "_parsed",
        lambda self, path: _FakeParsed([_FakeMethod("decrypt", 25)]),
    )
    payload = client.xrefs(tmp_path / "app.apk", "decrypt", limit=10)
    assert "xrefs" not in payload
    assert payload["count"] == 10
    assert payload["total"] == 25
    assert payload["offset"] == 0
    assert len(payload["callers"]) == 10
    assert payload["has_more"] is True
    doc = _tool_docstring("apk.xrefs")
    assert "Answers with callers" in doc
    assert "has_more" in doc
    assert "offset" in doc


def test_apk_xrefs_names_method_name_on_the_payload(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The catalog named callers and never named the method the page is for.

    Measured: xrefs(..., 'decrypt', limit=10) -> method_name decrypt, 10
    callers. Looking for method after a successful page reads as a list
    with no target, so a later page cannot be aimed at the same name.
    """
    client = ApkClient()
    monkeypatch.setattr(
        ApkClient,
        "_parsed",
        lambda self, path: _FakeParsed([_FakeMethod("decrypt", 25)]),
    )
    payload = client.xrefs(tmp_path / "app.apk", "decrypt", limit=10)
    assert payload["method_name"] == "decrypt"
    assert "method" not in payload
    doc = " ".join(_tool_docstring("apk.xrefs").split())
    assert "callers (class and method, sorted), method_name" in doc


class _ReverseXrefCall:
    def __init__(self, index: int) -> None:
        self.class_name = f"Lcom/example/Caller{index:02d};"
        self.name = "invoke"


class _ReverseXrefMethod:
    def __init__(self, name: str, count: int) -> None:
        self.name = name
        self._count = count

    def is_external(self) -> bool:
        return False

    def get_xref_from(self) -> list[tuple[object, _ReverseXrefCall, int]]:
        # Emit in reverse (a stand-in for androguard's undefined iteration order)
        # so a fix that sorts before windowing is visible: the walk-order prefix
        # would be the high indices, the sorted head the low ones.
        return [(None, _ReverseXrefCall(i), i) for i in range(self._count - 1, -1, -1)]


class _ReverseXrefParsed:
    def __init__(self, methods: list[_ReverseXrefMethod]) -> None:
        self.analysis = self
        self._methods = methods

    def get_methods(self) -> list[_ReverseXrefMethod]:
        return self._methods


def test_apk_xrefs_returns_the_sorted_head_and_pages_by_offset(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """xrefs sorts callers and pages by offset, not a walk-order prefix.

    The old xrefs stopped at the page size in androguard iteration order with no
    offset: a method with more call sites than one page returned an arbitrary,
    iteration-order subset (two analyses of the same APK could disagree on which
    callers) and every caller past the first page was unreachable -- the same
    broken contract apk.classes/methods/strings had before they gained offset.
    With 25 callers emitted in reverse, offset 0 limit 10 must return the
    alphabetical head Caller00..Caller09, and offset 20 limit 10 the final five
    (offset 20, count 5, total 25, has_more False). A negative offset (the
    agent/OpenAI transports bypass the schema's offset >= 0 bound) clamps to the
    head.
    """
    monkeypatch.setattr(
        ApkClient,
        "_parsed",
        lambda self, path: _ReverseXrefParsed([_ReverseXrefMethod("decrypt", 25)]),
    )
    client = ApkClient()

    head = client.xrefs(tmp_path / "app.apk", "decrypt", offset=0, limit=10)
    assert [caller["class"] for caller in head["callers"]] == [
        f"Lcom/example/Caller{index:02d};" for index in range(10)
    ]
    assert head["total"] == 25
    assert head["has_more"] is True
    assert head["scan_capped"] is False

    tail = client.xrefs(tmp_path / "app.apk", "decrypt", offset=20, limit=10)
    assert tail["offset"] == 20
    assert tail["count"] == 5
    assert tail["total"] == 25
    assert tail["has_more"] is False
    assert [caller["class"] for caller in tail["callers"]] == [
        f"Lcom/example/Caller{index:02d};" for index in range(20, 25)
    ]

    negative = client.xrefs(tmp_path / "app.apk", "decrypt", offset=-5, limit=10)
    assert negative["offset"] == 0
    assert [caller["class"] for caller in negative["callers"]] == [
        f"Lcom/example/Caller{index:02d};" for index in range(10)
    ]
    assert negative["has_more"] is True


def test_apk_xrefs_flags_scan_capped_at_the_collect_ceiling(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """scan_capped marks total as a floor when a method exceeds the caller ceiling.

    xrefs collects callers up to _MAX_XREFS_COLLECT to bound memory; a hotter
    method trips the ceiling, so total is a floor and callers past it were never
    scanned -- has_more alone would understate the set, exactly the scan_capped
    contract apk.classes/methods/strings keep. With the ceiling monkeypatched to
    3 against 10 call sites, total is the floor 3 and scan_capped is true.
    """
    from headless_re_mcp.backends.apk import client as mod

    monkeypatch.setattr(mod, "_MAX_XREFS_COLLECT", 3)
    monkeypatch.setattr(
        ApkClient,
        "_parsed",
        lambda self, path: _ReverseXrefParsed([_ReverseXrefMethod("decrypt", 10)]),
    )
    payload = ApkClient().xrefs(tmp_path / "app.apk", "decrypt", offset=0, limit=100)
    assert payload["scan_capped"] is True
    assert payload["total"] == 3
    assert payload["count"] == 3
    assert payload["has_more"] is False


class _ManifestBody:
    def get_xml(self) -> bytes:
        return b"<manifest/>" * ((_MAX_MANIFEST_CHARS // 10) + 20)


class _FakeApk:
    def get_android_manifest_axml(self) -> _ManifestBody:
        return _ManifestBody()

    def get_package(self) -> str:
        return "com.example.app"


def test_apk_manifest_names_manifest_xml_and_says_when_it_was_cut(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The catalog said AndroidManifest.xml and never named the payload.

    Measured: truncated True, manifest_xml 200000 chars (the cap), bytes 220220
    (the full manifest size), no manifest or xml field. Looking for those after
    a successful call reads as a missing manifest, and a 200000-char string with
    no truncated flag reads as the whole file, and a clipped manifest with no
    bytes gives no scale for the security-relevant tail that was cut.
    """
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _FakeApk())
    payload = client.manifest(tmp_path / "app.apk")
    assert "manifest" not in payload
    assert "xml" not in payload
    assert payload["truncated"] is True
    assert payload["package"] == "com.example.app"
    assert len(payload["manifest_xml"]) == _MAX_MANIFEST_CHARS
    assert payload["bytes"] == len(b"<manifest/>" * ((_MAX_MANIFEST_CHARS // 10) + 20))
    doc = _tool_docstring("apk.manifest")
    assert "manifest_xml" in doc
    assert "truncated" in doc
    assert "bytes" in doc


class _SmallManifestBody:
    def get_xml(self) -> bytes:
        return b"<manifest package='com.x'/>"


class _SmallManifestApk:
    def get_android_manifest_axml(self) -> _SmallManifestBody:
        return _SmallManifestBody()

    def get_package(self) -> str:
        return "com.x"


def test_apk_manifest_reports_the_full_size_and_is_not_truncated_when_it_fits(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A manifest under the cap carries bytes equal to its size, not truncated."""
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _SmallManifestApk())
    payload = client.manifest(tmp_path / "app.apk")
    assert payload["truncated"] is False
    assert payload["manifest_xml"] == "<manifest package='com.x'/>"
    assert payload["bytes"] == len(b"<manifest package='com.x'/>")

class _FakeClass:
    def __init__(self, name: str, *, external: bool = False) -> None:
        self.name = name
        self._external = external

    def is_external(self) -> bool:
        return self._external


class _FakeClassParsed:
    def __init__(self, classes: list[_FakeClass]) -> None:
        self.analysis = self
        self._classes = classes

    def get_classes(self) -> list[_FakeClass]:
        return self._classes


def test_apk_classes_puts_the_list_in_classes_and_says_when_it_stopped(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The catalog said pagination and never named the payload.

    Measured: 25 classes, limit 10 -> count 10, total 25, has_more True,
    field is classes not class_list or items. Looking for those after a
    successful call reads as no classes, and a full page with no has_more
    reads as the whole DEX.
    """
    client = ApkClient()
    monkeypatch.setattr(
        ApkClient,
        "_parsed",
        lambda self, path: _FakeClassParsed(
            [_FakeClass(f"L{index};") for index in range(25)]
        ),
    )
    payload = client.classes(tmp_path / "app.apk", offset=0, limit=10)
    assert "class_list" not in payload
    assert "items" not in payload
    assert payload["count"] == 10
    assert payload["total"] == 25
    assert len(payload["classes"]) == 10
    assert payload["has_more"] is True
    doc = _tool_docstring("apk.classes")
    assert "Answers with classes" in doc
    assert "has_more" in doc

class _FakeApkMethod:
    def __init__(self, index: int) -> None:
        self.name = f"m{index}"
        self.descriptor = "()V"
        self.access = "public"


class _FakeMethodClass:
    def __init__(self, count: int) -> None:
        self.name = "Lcom/example/Foo;"
        self._methods = [_FakeApkMethod(index) for index in range(count)]

    def get_methods(self) -> list[_FakeApkMethod]:
        return self._methods


class _FakeMethodParsed:
    def __init__(self, count: int) -> None:
        self.analysis = self
        self._classes = [_FakeMethodClass(count)]

    def get_classes(self) -> list[_FakeMethodClass]:
        return self._classes


def test_apk_methods_puts_the_list_in_methods_and_says_when_it_stopped(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The catalog said paginated and never named the payload.

    Measured: 25 methods, limit 10 -> count 10, total 25, has_more True,
    field is methods not method_list or items. Looking for those after a
    successful call reads as no methods, and a full page with no has_more
    reads as the whole class.
    """
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: _FakeMethodParsed(25))
    payload = client.methods(tmp_path / "app.apk", "com.example.Foo", offset=0, limit=10)
    assert "method_list" not in payload
    assert "items" not in payload
    assert payload["count"] == 10
    assert payload["total"] == 25
    assert len(payload["methods"]) == 10
    assert payload["has_more"] is True
    doc = _tool_docstring("apk.methods")
    assert "Answers with methods" in doc
    assert "has_more" in doc

def test_apk_decompile_names_source_and_says_when_it_was_cut(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The catalog said Java and never named the payload.

    Measured: truncated True, source 400000 chars (the cap), bytes 400080 (the
    full on-disk size), no java, code or text field. Looking for those after a
    successful call reads as a missing class, and a 400000-char string with no
    truncated flag reads as the whole file, and a truncated source with no bytes
    gives no scale at all.
    """
    from headless_re_mcp.backends.jadx.client import _MAX_SOURCE_BYTES, JadxClient

    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK")
    out = tmp_path / "out"
    src_dir = out / "sources" / "com" / "example"
    src_dir.mkdir(parents=True)
    (src_dir / "Foo.java").write_text("x" * (_MAX_SOURCE_BYTES + 80), encoding="utf-8")
    client = JadxClient(tmp_path / "jadx.bat")
    monkeypatch.setattr(client, "export_sources", lambda *args, **kwargs: {"ok": True})
    payload = client.decompile(apk, out, "com.example.Foo")
    assert "java" not in payload
    assert "code" not in payload
    assert "text" not in payload
    assert payload["truncated"] is True
    assert payload["class_name"] == "com.example.Foo"
    assert len(payload["source"]) == _MAX_SOURCE_BYTES
    assert payload["bytes"] == _MAX_SOURCE_BYTES + 80
    doc = _tool_docstring("apk.decompile")
    assert "source" in doc
    assert "truncated" in doc
    assert "bytes" in doc

def test_apk_export_sources_says_when_the_java_list_was_cut(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The catalog said a Java source tree and never named the payload.

    Measured: 5 java files, list capped at 3, has_more True, field is
    java_files not files or sources. Looking for those after a successful
    call reads as a missing tree, and a full page with no has_more reads
    as every class.
    """
    from headless_re_mcp.backends.jadx import client as mod

    out = tmp_path / "out"
    sources = out / "sources"
    sources.mkdir(parents=True)
    for index in range(5):
        (sources / f"C{index}.java").write_text("class C {}", encoding="utf-8")
    monkeypatch.setattr(mod, "_MAX_LISTED_FILES", 3)
    client = mod.JadxClient(tmp_path / "jadx.bat")
    monkeypatch.setattr(client, "_run", lambda *args, **kwargs: ("", "", 0))
    payload = client.export_sources(tmp_path / "app.apk", out)
    assert "files" not in payload
    assert "sources" not in payload
    assert payload["java_file_count"] == 5
    assert len(payload["java_files"]) == 3
    assert payload["has_more"] is True
    doc = _tool_docstring("apk.export_sources")
    assert "java_files" in doc
    assert "has_more" in doc


class _PackagelessApk:
    def get_package(self) -> None:
        return None


def test_apk_open_rejects_a_zip_with_no_package_name(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The catalog said opened; a zip that is not an APK answered opened True.

    Measured: get_package() returning None still answered
    {opened: True, package: None}, so an unattended agent treated a plain
    zip as an opened package. An empty package is now a backend error.
    """
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _PackagelessApk())
    with pytest.raises(ApkError) as caught:
        client.open(tmp_path / "not-an.apk")
    assert caught.value.code == "backend_error"
    assert caught.value.message == "failed to read package name"
    assert caught.value.details["opened"] is False
    doc = _tool_docstring("apk.open")
    assert "backend error" in doc
