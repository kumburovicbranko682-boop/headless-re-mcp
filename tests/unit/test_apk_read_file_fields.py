"""apk.read_file reads one APK entry, bounded, without unpacking the tree.

Nothing in the surface could read a named archive entry's bytes; peeking at an
embedded asset/config/dex meant apk.decode unpacking everything. These pin the
new reader: text decoded into content, binary base64-encoded, the 200000-byte
cap surfaced as truncated with the declared size still reported, a streamed
bounded read that never materializes more than the cap, and not_found for a
name absent from the archive. The docstring must name the returned fields.
"""

from __future__ import annotations

import ast
import base64
import zipfile
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apk import client as apk_client
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


def _make_zip(tmp_path: Path, entries: dict[str, bytes]) -> Path:
    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return apk


def test_text_entry_comes_back_decoded(tmp_path: Path) -> None:
    apk = _make_zip(tmp_path, {"assets/config.json": b'{"url": "https://api.example.com"}'})
    payload = ApkClient().read_file(apk, "assets/config.json")
    assert payload["base64_encoded"] is False
    assert payload["content"] == '{"url": "https://api.example.com"}'
    assert payload["size"] == len(b'{"url": "https://api.example.com"}')
    assert payload["returned_bytes"] == payload["size"]
    assert payload["truncated"] is False
    assert "body" not in payload
    assert "data" not in payload


def test_binary_entry_is_base64_encoded(tmp_path: Path) -> None:
    blob = bytes(range(256))  # contains NUL and non-utf8 bytes
    apk = _make_zip(tmp_path, {"res/raw/blob.bin": blob})
    payload = ApkClient().read_file(apk, "res/raw/blob.bin")
    assert payload["base64_encoded"] is True
    assert base64.b64decode(payload["content"]) == blob
    assert payload["size"] == 256
    assert payload["truncated"] is False


def test_a_large_entry_is_truncated_at_the_cap(tmp_path: Path, monkeypatch: Any) -> None:
    """A small cap proves the read stops at the cap and reports the full size."""
    monkeypatch.setattr(apk_client, "_MAX_FILE_INLINE", 16)
    data = b"A" * 10_000
    apk = _make_zip(tmp_path, {"assets/big.txt": data})
    payload = ApkClient().read_file(apk, "assets/big.txt")
    assert payload["returned_bytes"] == 16
    assert payload["content"] == "A" * 16
    assert payload["size"] == 10_000
    assert payload["truncated"] is True


def test_streamed_read_does_not_materialize_a_compression_bomb(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A tiny cap over a very compressible entry returns only cap bytes.

    The stored entry decompresses to 5 MB but the reader only ever pulls
    cap + 1 bytes off the stream, so returned_bytes stays at the cap: the
    whole entry is never allocated.
    """
    monkeypatch.setattr(apk_client, "_MAX_FILE_INLINE", 32)
    data = b"\x00" * 5_000_000  # NUL-filled: highly compressible, and binary
    apk = _make_zip(tmp_path, {"assets/bomb.bin": data})
    payload = ApkClient().read_file(apk, "assets/bomb.bin")
    assert payload["returned_bytes"] == 32
    assert payload["truncated"] is True
    assert payload["size"] == 5_000_000
    assert payload["base64_encoded"] is True


def test_missing_entry_is_not_found(tmp_path: Path) -> None:
    apk = _make_zip(tmp_path, {"classes.dex": b"dex"})
    with pytest.raises(ApkError) as excinfo:
        ApkClient().read_file(apk, "assets/does_not_exist")
    assert excinfo.value.code == "not_found"


def test_read_file_docstring_names_the_returned_fields() -> None:
    doc = _tool_docstring("apk.read_file")
    assert "Answers with name" in doc
    assert "base64_encoded" in doc
    assert "truncated" in doc
