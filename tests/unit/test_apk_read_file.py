"""apk.read_file returns bounded entry bytes with honest size/sha256/truncation."""

from __future__ import annotations

import base64
import hashlib
import types
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apk.client import _MAX_FILE_TOTAL, ApkClient, ApkError


class _FakeZip:
    """androguard 4.x infolist(): a dict of central-directory entries by name."""

    def __init__(self, sizes: dict[str, int | None]) -> None:
        self._sizes = sizes

    def infolist(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for name, size in self._sizes.items():
            if size is None:
                out[name] = types.SimpleNamespace(filename=name)
            else:
                out[name] = types.SimpleNamespace(filename=name, uncompressed_size=size)
        return out


class _FakeApk:
    def __init__(self, files: dict[str, bytes], sizes: dict[str, int | None]) -> None:
        self._files = files
        self.zip = _FakeZip(sizes)
        self.get_file_calls: list[str] = []

    def get_file(self, name: str) -> bytes:
        from androguard.core.apk import FileNotPresent

        self.get_file_calls.append(name)
        if name not in self._files:
            raise FileNotPresent(name)
        return self._files[name]


def _client_over(apk: _FakeApk) -> ApkClient:
    client = ApkClient()
    client._available = True
    client._apk = lambda path: apk  # type: ignore[method-assign]
    return client


def test_read_file_returns_full_bytes_with_size_and_sha256() -> None:
    content = b"hello world config payload"
    apk = _FakeApk({"assets/app.cfg": content}, {"assets/app.cfg": len(content)})
    payload = _client_over(apk).read_file(Path("x.apk"), "assets/app.cfg")
    assert payload["name"] == "assets/app.cfg"
    assert payload["size"] == len(content)
    assert payload["returned"] == len(content)
    assert payload["truncated"] is False
    assert payload["encoding"] == "base64"
    assert base64.b64decode(payload["data"]) == content
    assert payload["sha256"] == hashlib.sha256(content).hexdigest()


def test_read_file_windows_and_flags_more_to_come() -> None:
    content = bytes(range(100))
    apk = _FakeApk({"resources.arsc": content}, {"resources.arsc": 100})
    payload = _client_over(apk).read_file(Path("x.apk"), "resources.arsc", offset=10, max_bytes=20)
    assert payload["offset"] == 10
    assert payload["returned"] == 20
    assert payload["truncated"] is True
    assert base64.b64decode(payload["data"]) == content[10:30]
    # sha256 stays over the whole entry, not the window, so it fingerprints the
    # file regardless of which slice was paged.
    assert payload["sha256"] == hashlib.sha256(content).hexdigest()


def test_read_file_past_eof_is_an_empty_read_not_an_error() -> None:
    content = b"abc"
    apk = _FakeApk({"a.txt": content}, {"a.txt": 3})
    payload = _client_over(apk).read_file(Path("x.apk"), "a.txt", offset=50)
    assert payload["returned"] == 0
    assert payload["data"] == ""
    assert payload["truncated"] is False
    assert payload["size"] == 3


def test_read_file_missing_entry_is_not_found() -> None:
    apk = _FakeApk({"present": b"x"}, {"present": 1})
    with pytest.raises(ApkError) as caught:
        _client_over(apk).read_file(Path("x.apk"), "does/not/exist")
    assert caught.value.code == "not_found"


def test_read_file_refuses_a_huge_entry_before_decompressing() -> None:
    """A directory size past the ceiling refuses the read without get_file.

    get_file decompresses the whole entry, so the too_large must fire from the
    central-directory size, not after the entry is already in memory.
    """
    apk = _FakeApk({"big.bin": b"unused"}, {"big.bin": _MAX_FILE_TOTAL + 1})
    with pytest.raises(ApkError) as caught:
        _client_over(apk).read_file(Path("x.apk"), "big.bin")
    assert caught.value.code == "too_large"
    assert caught.value.details["size"] == _MAX_FILE_TOTAL + 1
    assert apk.get_file_calls == []


def test_read_file_reads_when_the_directory_hides_the_size() -> None:
    """An entry whose size the directory does not expose still reads.

    _entry_uncompressed_size returns None then, so the pre-read guard is
    skipped and the post-read ceiling is the only bound -- a small file must
    not be refused just because its size was unknown up front.
    """
    content = b"small but sizeless"
    apk = _FakeApk({"weird": content}, {"weird": None})
    payload = _client_over(apk).read_file(Path("x.apk"), "weird")
    assert payload["size"] == len(content)
    assert base64.b64decode(payload["data"]) == content
    assert apk.get_file_calls == ["weird"]
