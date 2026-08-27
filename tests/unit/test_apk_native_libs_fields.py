"""apk.native_libs descriptions must name the fields the parser actually returns."""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient, ApkError
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
