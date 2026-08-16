"""A pull that wrote nothing used to look fetched."""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError


class TestPullDoesNotCallMissingFileSuccess:
    """sync.pull that wrote no bytes used to return a local path anyway.

    Measured: FakeDev.sync.pull wrote nothing, pull() returned local, file
    missing -- so a caller treats a dead path as a fetched remote.
    """

    def test_a_missing_file_is_not_a_pull(self, tmp_path: Path) -> None:
        class _Sync:
            @staticmethod
            def pull(remote: str, local: str) -> None:
                del remote, local

        class _FakeDev:
            sync = _Sync()

        backend = AdbBackend()
        backend._device = lambda serial: _FakeDev()  # type: ignore[method-assign]
        with pytest.raises(AdbError) as info:
            backend.pull("emulator-5554", "/sdcard/x.bin", tmp_path / "x.bin")
        assert info.value.code == "backend_error"

    def test_a_written_file_is_success(self, tmp_path: Path) -> None:
        out = tmp_path / "x.bin"

        class _Sync:
            @staticmethod
            def pull(remote: str, local: str) -> None:
                del remote
                Path(local).write_bytes(b"apk")

        class _FakeDev:
            sync = _Sync()

        backend = AdbBackend()
        backend._device = lambda serial: _FakeDev()  # type: ignore[method-assign]
        result = backend.pull("emulator-5554", "/sdcard/x.bin", out)
        assert result["local"] == str(out)
        assert out.is_file()
        assert out.stat().st_size > 0
