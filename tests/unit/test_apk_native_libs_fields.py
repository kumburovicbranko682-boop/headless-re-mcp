"""apk.native_libs descriptions must name the fields the parser actually returns."""

from __future__ import annotations

import ast
import hashlib
import zipfile
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient, ApkError, _apk_entry_category
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


class _FakeApk:
    def get_files(self) -> list[str]:
        return [f"lib/arm64-v8a/l{index}.so" for index in range(300)] + ["classes.dex"]


def test_apk_native_libs_names_native_libs_not_libraries() -> None:
    """The catalog said libraries and ABIs; the parser has no such fields.

    Measured: 300 lib paths, cap 256 -> count 256, has_more True, field is
    native_libs not libs or libraries, and the ABI list is abis. Looking
    for libraries after a successful call reads as no native code, and a
    full 256 list with no has_more reads as every .so.
    """
    client = ApkClient()
    client._apk = lambda _path: _FakeApk()  # type: ignore[method-assign]
    payload = client.native_libs(Path("dummy.apk"))
    assert "libs" not in payload
    assert "libraries" not in payload
    assert "native_libraries" not in payload
    assert payload["count"] == 256
    assert len(payload["native_libs"]) == 256
    assert payload["has_more"] is True
    assert payload["abis"] == ["arm64-v8a"]
    doc = _tool_docstring("apk.native_libs")
    assert "Answers with native_libs" in doc
    assert "abis" in doc
    assert "has_more" in doc


_SO_BYTES = b"\x7fELF" + b"native-payload" * 8


class _ExtractApk:
    def get_files(self) -> list[str]:
        return ["lib/arm64-v8a/libnative.so", "lib/armeabi-v7a/libnative.so", "classes.dex"]

    def get_file(self, name: str) -> bytes:
        if name == "lib/arm64-v8a/libnative.so":
            return _SO_BYTES
        raise KeyError(name)


def test_apk_extract_native_lib_writes_the_real_bytes(tmp_path: Path) -> None:
    """native_libs names the .so; without this you still cannot get its bytes.

    Pull lib/arm64-v8a/libnative.so and assert the file on disk is byte-for-byte
    the zip member (not base64, not a decode), the reported size/sha256 match,
    and abi/name are split out so the binary line can open path directly.
    """
    client = ApkClient()
    client._apk = lambda _path: _ExtractApk()  # type: ignore[method-assign]
    out = client.extract_native_lib(
        Path("dummy.apk"), "lib/arm64-v8a/libnative.so", tmp_path
    )
    written = Path(out["path"])
    assert written.read_bytes() == _SO_BYTES
    assert out["size"] == len(_SO_BYTES)
    assert out["sha256"] == hashlib.sha256(_SO_BYTES).hexdigest()
    assert out["abi"] == "arm64-v8a"
    assert out["name"] == "libnative.so"
    assert out["entry"] == "lib/arm64-v8a/libnative.so"
    # No inline byte blob leaks into the JSON result.
    assert "bytes" not in out and "data" not in out


def test_apk_extract_native_lib_rejects_non_library_and_missing_entries(
    tmp_path: Path,
) -> None:
    """Only a real loadable lib, only by its exact archive path.

    A DEX entry, a path that climbs out of lib/, and an entry androguard does
    not list must each be refused with a structured code rather than writing a
    file or reading an arbitrary zip member.
    """
    client = ApkClient()
    client._apk = lambda _path: _ExtractApk()  # type: ignore[method-assign]

    # classes.dex is present in the archive but is not a lib/<abi>/<name>.so.
    with pytest.raises(ApkError) as dex:
        client.extract_native_lib(Path("dummy.apk"), "classes.dex", tmp_path)
    assert dex.value.code == "invalid_params"

    with pytest.raises(ApkError) as missing:
        client.extract_native_lib(Path("dummy.apk"), "lib/x86/nope.so", tmp_path)
    assert missing.value.code == "not_found"

    # An entry that is listed but is not a lib/<abi>/<name>.so triple.
    client._apk = lambda _path: _NestedApk()  # type: ignore[method-assign]
    with pytest.raises(ApkError) as nested:
        client.extract_native_lib(
            Path("dummy.apk"), "lib/arm64-v8a/sub/deep.so", tmp_path
        )
    assert nested.value.code == "invalid_params"
    assert not list(tmp_path.iterdir())


class _NestedApk:
    def get_files(self) -> list[str]:
        return ["lib/arm64-v8a/sub/deep.so"]

    def get_file(self, name: str) -> bytes:
        return b"unused"


def test_apk_extract_native_lib_docstring_names_its_fields() -> None:
    doc = _tool_docstring("apk.extract_native_lib")
    assert "entry" in doc
    assert "sha256" in doc
    assert "path" in doc


def _write_sample_apk(dest: Path) -> None:
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", b"AXML-manifest")
        zf.writestr("classes.dex", b"dex\n" + b"\x00" * 40)
        zf.writestr("classes2.dex", b"dex2")
        zf.writestr("resources.arsc", b"\x00" * 16)
        zf.writestr("res/layout/main.xml", b"<x/>")
        zf.writestr("lib/arm64-v8a/libfoo.so", b"\x7fELF" + b"\x00" * 60)
        zf.writestr("assets/config.json", b'{"k":1}')
        zf.writestr("META-INF/CERT.RSA", b"signature-bytes")


def test_apk_files_lists_entries_with_category_and_size(tmp_path: Path) -> None:
    """native_libs only saw .so; apk.files must show the whole archive.

    Build an APK-shaped zip and assert each entry is listed with its size and
    the right triage category, that the category tally spans the whole archive
    (two dex), and that assets/config.json's size matches its bytes.
    """
    apk = tmp_path / "app.apk"
    _write_sample_apk(apk)
    client = ApkClient()
    # Stub the androguard parse (the availability/validity gate) so the test
    # exercises the zip listing without needing androguard, like native_libs.
    client._apk = lambda _path: object()  # type: ignore[method-assign]

    payload = client.files(apk)
    by_name = {row["name"]: row for row in payload["files"]}
    assert by_name["AndroidManifest.xml"]["category"] == "manifest"
    assert by_name["classes.dex"]["category"] == "dex"
    assert by_name["classes2.dex"]["category"] == "dex"
    assert by_name["resources.arsc"]["category"] == "resource"
    assert by_name["res/layout/main.xml"]["category"] == "resource"
    assert by_name["lib/arm64-v8a/libfoo.so"]["category"] == "native_lib"
    assert by_name["assets/config.json"]["category"] == "asset"
    assert by_name["META-INF/CERT.RSA"]["category"] == "signature"
    assert by_name["assets/config.json"]["size"] == len(b'{"k":1}')
    assert "compressed" in by_name["assets/config.json"]

    assert payload["total"] == 8
    assert payload["count"] == 8
    assert payload["categories"]["dex"] == 2
    assert payload["categories"]["native_lib"] == 1
    assert payload["total_bytes"] == sum(row["size"] for row in payload["files"])
    assert payload["has_more"] is False

    doc = _tool_docstring("apk.files")
    assert "category" in doc
    assert "categories" in doc
    assert "compressed" in doc


def test_apk_files_paginates_and_flags_more(tmp_path: Path) -> None:
    """A page that filled the limit must not read as the whole archive."""
    apk = tmp_path / "many.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        for index in range(10):
            zf.writestr(f"assets/file{index}.bin", b"x" * index)
    client = ApkClient()
    client._apk = lambda _path: object()  # type: ignore[method-assign]

    first = client.files(apk, offset=0, limit=4)
    assert first["count"] == 4
    assert first["total"] == 10
    assert first["has_more"] is True
    assert first["categories"]["asset"] == 10  # tally spans the whole archive

    last = client.files(apk, offset=8, limit=4)
    assert last["count"] == 2
    assert last["has_more"] is False


_ASSET_BYTES = b'{"endpoint":"https://api.example.com","flag":true}'


class _FilesApk:
    def get_files(self) -> list[str]:
        return ["assets/config/app.json", "classes.dex", "META-INF/CERT.RSA"]

    def get_file(self, name: str) -> bytes:
        if name == "assets/config/app.json":
            return _ASSET_BYTES
        if name == "classes.dex":
            return b"dexbytes"
        raise KeyError(name)


def test_apk_extract_file_writes_any_entry_flattened(tmp_path: Path) -> None:
    """extract_native_lib only handled .so; extract_file pulls any listed entry.

    Pull a nested asset and assert the bytes on disk are the real member, the
    output name is flattened (no subdirectory created, so a nested entry cannot
    escape the artifact dir), and size/sha256/category/name are reported.
    """
    client = ApkClient()
    client._apk = lambda _path: _FilesApk()  # type: ignore[method-assign]
    out = client.extract_file(Path("dummy.apk"), "assets/config/app.json", tmp_path)
    written = Path(out["path"])
    assert written.parent == tmp_path  # flattened into out_dir, no nested dirs
    assert written.name == "assets_config_app.json"
    assert written.read_bytes() == _ASSET_BYTES
    assert out["size"] == len(_ASSET_BYTES)
    assert out["sha256"] == hashlib.sha256(_ASSET_BYTES).hexdigest()
    assert out["category"] == "asset"
    assert out["name"] == "app.json"
    assert out["entry"] == "assets/config/app.json"
    assert "bytes" not in out and "data" not in out


def test_apk_extract_file_rejects_unlisted_and_empty(tmp_path: Path) -> None:
    """Only a listed entry, and not an empty one -- and nothing lands on reject."""
    client = ApkClient()
    client._apk = lambda _path: _FilesApk()  # type: ignore[method-assign]
    with pytest.raises(ApkError) as missing:
        client.extract_file(Path("dummy.apk"), "assets/nope.bin", tmp_path)
    assert missing.value.code == "not_found"
    with pytest.raises(ApkError) as empty:
        client.extract_file(Path("dummy.apk"), "   ", tmp_path)
    assert empty.value.code == "invalid_params"
    assert not list(tmp_path.iterdir())


def test_apk_extract_file_docstring_names_fields() -> None:
    doc = _tool_docstring("apk.extract_file")
    assert "category" in doc
    assert "sha256" in doc
    assert "artifact_id" in doc


def test_apk_entry_category_buckets_paths() -> None:
    assert _apk_entry_category("AndroidManifest.xml") == "manifest"
    assert _apk_entry_category("META-INF/MANIFEST.MF") == "signature"
    assert _apk_entry_category("classes.dex") == "dex"
    assert _apk_entry_category("lib/x86_64/libc++.so") == "native_lib"
    assert _apk_entry_category("resources.arsc") == "resource"
    assert _apk_entry_category("res/values/strings.xml") == "resource"
    assert _apk_entry_category("assets/www/index.html") == "asset"
    assert _apk_entry_category("kotlin/kotlin.kotlin_builtins") == "other"
