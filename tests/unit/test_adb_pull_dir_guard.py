"""adb.pull must refuse directories only -- not every non-regular file.

The pre-pull guard rejects a remote directory (pulling one would expand a whole
tree onto the local disk). It used ``mode & stat.S_IFDIR``, a bitwise AND against
a multi-bit type value: S_IFDIR (0o040000) is bit 14, which is *also* set in
S_IFSOCK (0o140000) and S_IFBLK (0o060000). So a socket or block device was
refused with a misleading "refusing to pull a directory", while the real intent
-- catch directories via the S_IFMT type field -- is what stat.S_ISDIR does.
"""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError


class _FileInfo:
    def __init__(self, mode: int, size: int) -> None:
        self.mode = mode
        self.size = size


class _FakeSync:
    def __init__(self, mode: int, size: int, *, payload: bytes = b"") -> None:
        self._mode = mode
        self._size = size
        self._payload = payload

    def stat(self, remote: str, timeout: float | None = None) -> _FileInfo:
        del remote, timeout
        return _FileInfo(self._mode, self._size)

    def pull(self, remote: str, local: str, timeout: float | None = None) -> None:
        del remote, timeout
        Path(local).write_bytes(self._payload)


class _FakeDevice:
    def __init__(self, sync: _FakeSync) -> None:
        self.sync = sync


def _backend_with(mode: int, size: int, *, payload: bytes) -> AdbBackend:
    backend = AdbBackend()
    fake = _FakeDevice(_FakeSync(mode, size, payload=payload))
    # Bypass the real adbutils transport; the guard under test runs entirely on
    # the FileInfo mode the sync layer reports.
    backend._device = lambda serial: fake  # type: ignore[method-assign]
    return backend


def test_pull_refuses_a_real_directory(tmp_path: Path) -> None:
    backend = _backend_with(stat.S_IFDIR | 0o755, 4096, payload=b"")
    with pytest.raises(AdbError) as caught:
        backend.pull("emulator-5554", "/sdcard/somedir", tmp_path / "out.bin")
    assert caught.value.code == "invalid_params"
    assert "directory" in caught.value.message


def test_pull_does_not_mistake_a_socket_for_a_directory(tmp_path: Path) -> None:
    payload = b"socketbytes"
    backend = _backend_with(stat.S_IFSOCK | 0o644, len(payload), payload=payload)
    out = tmp_path / "sock.bin"
    result = backend.pull("emulator-5554", "/dev/some.sock", out)
    assert result["size"] == len(payload)
    assert out.read_bytes() == payload


def test_pull_does_not_mistake_a_block_device_for_a_directory(tmp_path: Path) -> None:
    payload = b"blockbytes"
    backend = _backend_with(stat.S_IFBLK | 0o600, len(payload), payload=payload)
    out = tmp_path / "blk.bin"
    result = backend.pull("emulator-5554", "/dev/block/loop0", out)
    assert result["size"] == len(payload)
    assert out.read_bytes() == payload


def test_pull_passes_a_regular_file_through(tmp_path: Path) -> None:
    payload = b"regularfile"
    backend = _backend_with(stat.S_IFREG | 0o644, len(payload), payload=payload)
    out = tmp_path / "reg.bin"
    result = backend.pull("emulator-5554", "/sdcard/file.txt", out)
    assert result["size"] == len(payload)
    assert result["remote"] == "/sdcard/file.txt"
