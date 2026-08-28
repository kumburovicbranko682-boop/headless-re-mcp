"""apk.extract_native_lib must pull exact bytes and refuse non-library entries."""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path
from typing import Any

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


_SO_BYTES = b"\x7fELF" + bytes(range(64)) + b"\x00native-payload-9449"
_ENTRY = "lib/arm64-v8a/libnative.so"


class _FakeApk:
    def get_files(self) -> list[str]:
        return ["AndroidManifest.xml", "classes.dex", _ENTRY, "lib/x86_64/libother.so"]

    def get_file(self, name: str) -> bytes:
        payloads = {
            _ENTRY: _SO_BYTES,
            "lib/x86_64/libother.so": b"\x7fELFother",
        }
        if name not in payloads:
            raise KeyError(name)
        return payloads[name]


def _client(monkeypatch: Any) -> ApkClient:
    client = ApkClient()
    # Bypass androguard's real APK parse/file checks: this test pins the extract
    # bookkeeping (validation, byte fidelity, naming), not androguard itself.
    monkeypatch.setattr(client, "_require", lambda p: Path(p))
    monkeypatch.setattr(client, "_apk", lambda p: _FakeApk())
    return client


def test_extract_native_lib_writes_the_exact_bytes(tmp_path: Path, monkeypatch: Any) -> None:
    """A valid lib/<abi>/<name>.so must land on disk byte-for-byte.

    The whole point is feeding the native tools, so the extracted file has to be
    the real bytes (magic and all), the reported sha256 must match them, and the
    abi/path/name fields must describe where it went -- not a lossy summary.
    """
    client = _client(monkeypatch)
    out = client.extract_native_lib(Path("app.apk"), _ENTRY, tmp_path)
    assert out["name"] == _ENTRY
    assert out["abi"] == "arm64-v8a"
    assert out["size"] == len(_SO_BYTES)
    assert out["sha256"] == hashlib.sha256(_SO_BYTES).hexdigest()
    written = Path(out["path"])
    assert written.parent == tmp_path
    assert written.read_bytes() == _SO_BYTES
    # The ABI is prefixed so two same-named libs from different ABIs cannot clash.
    assert written.name == "arm64-v8a-libnative.so"
    doc = _tool_docstring("apk.extract_native_lib")
    assert "path" in doc and "sha256" in doc and "artifact_id" in doc


def test_extract_native_lib_rejects_a_non_library_entry(tmp_path: Path, monkeypatch: Any) -> None:
    """A real entry that is not a lib/*.so must be refused, not extracted.

    classes.dex is present in the archive, so this is not a "missing" case; it is
    "present but not a native library". Refusing it invalid_params keeps this
    from becoming an arbitrary zip extractor.
    """
    client = _client(monkeypatch)
    with pytest.raises(ApkError) as info:
        client.extract_native_lib(Path("app.apk"), "classes.dex", tmp_path)
    assert info.value.code == "invalid_params", info.value.code
    assert not list(tmp_path.iterdir()), "nothing should have been written"


def test_extract_native_lib_missing_entry_is_not_found(tmp_path: Path, monkeypatch: Any) -> None:
    """A .so name absent from the archive must be a clean not_found."""
    client = _client(monkeypatch)
    with pytest.raises(ApkError) as info:
        client.extract_native_lib(Path("app.apk"), "lib/armeabi-v7a/ghost.so", tmp_path)
    assert info.value.code == "not_found", info.value.code


def test_extract_native_lib_blank_name_is_invalid_params(tmp_path: Path, monkeypatch: Any) -> None:
    """An empty name is a caller error, refused before any archive read."""
    client = _client(monkeypatch)
    with pytest.raises(ApkError) as info:
        client.extract_native_lib(Path("app.apk"), "   ", tmp_path)
    assert info.value.code == "invalid_params", info.value.code
