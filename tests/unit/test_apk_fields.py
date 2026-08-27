"""apk tool descriptions must name the fields the backends return."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.apk.client import _MAX_MANIFEST_CHARS, ApkClient
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
    def __init__(self, name: str, callers: int, class_name: str = "") -> None:
        self.name = name
        self.class_name = class_name
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
    assert len(payload["callers"]) == 10
    assert payload["has_more"] is True
    doc = _tool_docstring("apk.xrefs")
    assert "Answers with callers" in doc
    assert "has_more" in doc


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
    assert "callers (class and method), method_name" in doc
    assert "class_name" in doc


def test_apk_xrefs_class_name_scopes_to_one_declaring_class(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """Two classes declare decrypt; name-only matching conflates their callers.

    Measured: Crypto.decrypt has 2 callers, Util.decrypt has 3 -> unscoped total
    5 (conflated, class_name null), scoped to com.target.Crypto total 2, and the
    dotted and Lsmali/ forms both resolve.
    """
    methods = [
        _FakeMethod("decrypt", 2, class_name="Lcom/target/Crypto;"),
        _FakeMethod("decrypt", 3, class_name="Lcom/other/Util;"),
    ]
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: _FakeParsed(methods))
    client = ApkClient()
    unscoped = client.xrefs(tmp_path / "app.apk", "decrypt", limit=100)
    assert unscoped["total"] == 5
    assert unscoped["class_name"] is None
    scoped = client.xrefs(
        tmp_path / "app.apk", "decrypt", limit=100, class_name="com.target.Crypto"
    )
    assert scoped["total"] == 2
    assert scoped["class_name"] == "com.target.Crypto"
    scoped_smali = client.xrefs(
        tmp_path / "app.apk", "decrypt", limit=100, class_name="Lcom/target/Crypto;"
    )
    assert scoped_smali["total"] == 2


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

    Measured: truncated True, manifest_xml 200000 chars (the cap), no
    manifest or xml field. Looking for those after a successful call reads
    as a missing manifest, and a 200000-char string with no truncated flag
    reads as the whole file.
    """
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _FakeApk())
    payload = client.manifest(tmp_path / "app.apk")
    assert "manifest" not in payload
    assert "xml" not in payload
    assert payload["truncated"] is True
    assert payload["package"] == "com.example.app"
    assert len(payload["manifest_xml"]) == _MAX_MANIFEST_CHARS
    doc = _tool_docstring("apk.manifest")
    assert "manifest_xml" in doc
    assert "truncated" in doc
    assert "manifest_path" in doc


class _SmallManifestBody:
    def get_xml(self) -> bytes:
        return b"<manifest package='com.example.app'/>"


class _SmallFakeApk:
    def get_android_manifest_axml(self) -> _SmallManifestBody:
        return _SmallManifestBody()

    def get_package(self) -> str:
        return "com.example.app"


def test_apk_manifest_spills_the_whole_xml_when_it_is_cut(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A manifest cut at the char cap is not well-formed; the tail was lost.

    With a spill_dir the whole document is written to manifest_path so the
    caller can parse the real thing, while manifest_xml keeps the bounded
    preview.
    """
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _FakeApk())
    spill = tmp_path / "apk"
    payload = client.manifest(tmp_path / "app.apk", spill_dir=spill)

    assert payload["truncated"] is True
    assert len(payload["manifest_xml"]) == _MAX_MANIFEST_CHARS
    assert "manifest_path" in payload
    written = Path(payload["manifest_path"])
    assert written.parent == spill
    full = written.read_text(encoding="utf-8")
    assert len(full) > _MAX_MANIFEST_CHARS
    assert full.startswith("<manifest/>")


def test_apk_manifest_does_not_spill_when_it_fits(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A manifest within the buffer stays inline: no file, no manifest_path."""
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _SmallFakeApk())
    spill = tmp_path / "apk"
    payload = client.manifest(tmp_path / "app.apk", spill_dir=spill)

    assert payload["truncated"] is False
    assert "manifest_path" not in payload
    assert not spill.exists() or not any(spill.iterdir())


def test_apk_manifest_without_spill_dir_keeps_old_shape(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The backend called with no spill_dir behaves exactly as before."""
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _FakeApk())
    payload = client.manifest(tmp_path / "app.apk")

    assert payload["truncated"] is True
    assert "manifest_path" not in payload


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
    assert "name_filter" in doc


def test_apk_classes_name_filter_reaches_a_class_past_the_collect_cap(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A specific class in a >10000-class app must be findable regardless of
    scan order; without filtering during the scan it is stranded past the cap.

    Measured: cap lowered to 3, target class after 3 noise classes -> unfiltered
    it is not collected (scan_capped True), filtered on 'Crypto' it is the only
    row and scan_capped is False.
    """
    from headless_re_mcp.backends.apk import client as mod

    monkeypatch.setattr(mod, "_MAX_CLASSES_COLLECT", 3)
    classes = [_FakeClass(f"Lnoise/N{index};") for index in range(3)]
    classes.append(_FakeClass("Lcom/target/Crypto;"))
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: _FakeClassParsed(classes))
    client = ApkClient()
    unfiltered = client.classes(tmp_path / "app.apk", offset=0, limit=100)
    assert "Lcom/target/Crypto;" not in unfiltered["classes"]
    assert unfiltered["scan_capped"] is True
    filtered = client.classes(tmp_path / "app.apk", offset=0, limit=100, name_filter="Crypto")
    assert filtered["classes"] == ["Lcom/target/Crypto;"]
    assert filtered["total"] == 1
    assert filtered["scan_capped"] is False

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
    assert "name_filter" in doc


def test_apk_methods_name_filter_reaches_a_method_past_the_collect_cap(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A target method on a class that declares more than the cap must be
    reachable by name; without filtering during the scan it is stranded.

    Measured: cap lowered to 3, 25 declared methods m0..m24 -> unfiltered stops
    at 3 (scan_capped True) and m24 is absent, filtered on 'm24' it is the only
    row and scan_capped is False.
    """
    from headless_re_mcp.backends.apk import client as mod

    monkeypatch.setattr(mod, "_MAX_METHODS_COLLECT", 3)
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: _FakeMethodParsed(25))
    client = ApkClient()
    unfiltered = client.methods(tmp_path / "app.apk", "com.example.Foo", offset=0, limit=100)
    assert unfiltered["scan_capped"] is True
    assert all(row["name"] != "m24" for row in unfiltered["methods"])
    filtered = client.methods(
        tmp_path / "app.apk", "com.example.Foo", offset=0, limit=100, name_filter="m24"
    )
    assert [row["name"] for row in filtered["methods"]] == ["m24"]
    assert filtered["total"] == 1
    assert filtered["scan_capped"] is False

def test_apk_decompile_names_source_and_says_when_it_was_cut(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The catalog said Java and never named the payload.

    Measured: truncated True, source 400000 chars (the cap), no java, code
    or text field. Looking for those after a successful call reads as a
    missing class, and a 400000-char string with no truncated flag reads
    as the whole file.
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
    doc = _tool_docstring("apk.decompile")
    assert "source" in doc
    assert "truncated" in doc

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
