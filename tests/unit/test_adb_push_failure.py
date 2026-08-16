"""A push that wrote nothing used to look uploaded."""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError


class TestPushDoesNotCallMissingRemoteSuccess:
    """sync.push that left no remote file used to return the path anyway.

    Measured: FakeDev.sync.push wrote nothing, push() returned remote --
    so a caller treats a missing remote as an uploaded file.
    """

    def test_a_missing_remote_is_not_a_push(self, tmp_path: Path) -> None:
        local = tmp_path / "payload.bin"
        local.write_bytes(b"hello")

        class _Sync:
            @staticmethod
            def push(src: str, dst: str) -> None:
                del src, dst

            @staticmethod
            def stat(remote: str) -> None:
                raise FileNotFoundError(remote)

        class _FakeDev:
            sync = _Sync()

        backend = AdbBackend()
        backend._device = lambda serial: _FakeDev()  # type: ignore[method-assign]
        with pytest.raises(AdbError) as info:
            backend.push("emulator-5554", str(local), "/sdcard/payload.bin")
        assert info.value.code == "backend_error"

    def test_a_stated_remote_is_success(self, tmp_path: Path) -> None:
        local = tmp_path / "payload.bin"
        local.write_bytes(b"hello")

        class _Info:
            mode = 0o100644
            size = 5

        class _Sync:
            @staticmethod
            def push(src: str, dst: str) -> None:
                del src, dst

            @staticmethod
            def stat(remote: str) -> _Info:
                del remote
                return _Info()

        class _FakeDev:
            sync = _Sync()

        backend = AdbBackend()
        backend._device = lambda serial: _FakeDev()  # type: ignore[method-assign]
        result = backend.push("emulator-5554", str(local), "/sdcard/payload.bin")
        assert result["remote"] == "/sdcard/payload.bin"
        assert result["local"] == str(local)
