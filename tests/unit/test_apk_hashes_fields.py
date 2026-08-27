"""apk.hashes must fingerprint the file (streamed) and each DEX, bounded.

The whole-file sha256/sha1/md5 and size are the keys sample databases index
on; each DEX gets its own sha256 so repackaged builds can be matched. The file
is streamed (so a large APK never loads whole), the DEX list is capped with
has_more, and the digests live under file rather than a top-level hash field.
"""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path

from headless_re_mcp.backends.apk.client import ApkClient
from headless_re_mcp.tools.apk import build_apk_tools


class _FakeApk:
    def __init__(self, dex_map: dict[str, bytes]) -> None:
        self._dex_map = dex_map

    def get_dex_names(self) -> list[str]:
        return list(self._dex_map)

    def get_file(self, name: str) -> bytes:
        return self._dex_map[name]


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


def _client(dex_map: dict[str, bytes]) -> ApkClient:
    client = ApkClient()
    client._available = True
    client._apk = lambda _path: _FakeApk(dex_map)  # type: ignore[method-assign]
    return client


def test_hashes_streams_file_and_hashes_each_dex(tmp_path: Path) -> None:
    """File digests match the raw bytes across a multi-chunk read; dexes sort.

    Measured intent: a >2 MiB file (crossing the 1 MiB streaming chunk) hashes
    to the same sha256/sha1/md5 as hashing the bytes in one shot, size is the
    byte length, each DEX carries its own sha256/size, dexes sort by name, and
    the whole-file digests live under file with no top-level hash/digest field.
    """
    content = b"PK\x03\x04 fake apk payload " * 120_000  # ~2.6 MiB
    apk_path = tmp_path / "sample.apk"
    apk_path.write_bytes(content)
    dex1 = b"dex\n035\x00classes-one"
    dex2 = b"dex\n035\x00classes-two-longer"

    payload = _client({"classes2.dex": dex2, "classes.dex": dex1}).hashes(apk_path)

    assert payload["file"]["sha256"] == hashlib.sha256(content).hexdigest()
    assert payload["file"]["sha1"] == hashlib.sha1(content, usedforsecurity=False).hexdigest()
    assert payload["file"]["md5"] == hashlib.md5(content, usedforsecurity=False).hexdigest()
    assert payload["file"]["size"] == len(content)

    assert "hash" not in payload
    assert "digest" not in payload
    assert payload["dex_count"] == 2
    assert payload["has_more"] is False
    assert [d["name"] for d in payload["dexes"]] == ["classes.dex", "classes2.dex"]
    assert payload["dexes"][0]["sha256"] == hashlib.sha256(dex1).hexdigest()
    assert payload["dexes"][0]["size"] == len(dex1)

    doc = _tool_docstring("apk.hashes")
    assert "file" in doc
    assert "dexes" in doc
    assert "has_more" in doc


def test_hashes_caps_dex_list_and_discloses_has_more(tmp_path: Path) -> None:
    """A heavily multidexed app caps the dex list and sets has_more."""
    apk_path = tmp_path / "multidex.apk"
    apk_path.write_bytes(b"content")
    dex_map = {f"classes{index}.dex": f"dex-{index}".encode() for index in range(70)}

    payload = _client(dex_map).hashes(apk_path)
    assert payload["dex_count"] == 64
    assert len(payload["dexes"]) == 64
    assert payload["has_more"] is True


def test_hashes_survive_missing_dex_names(tmp_path: Path) -> None:
    """No readable DEX names still yields the file digests, dexes empty."""
    apk_path = tmp_path / "nodex.apk"
    apk_path.write_bytes(b"abc")

    payload = _client({}).hashes(apk_path)
    assert payload["dexes"] == []
    assert payload["dex_count"] == 0
    assert payload["file"]["size"] == 3
