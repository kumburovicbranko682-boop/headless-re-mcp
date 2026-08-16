"""A screenshot that wrote nothing used to look captured."""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError


class TestScreenshotDoesNotCallMissingFileSuccess:
    """save() that wrote no bytes used to return a path anyway.

    Measured: FakeDev.screenshot().save() wrote nothing, screenshot()
    returned path, file missing -- so a caller treats a dead path as a
    captured screen.
    """

    def test_a_missing_png_is_not_a_screenshot(self, tmp_path: Path) -> None:
        class _Img:
            def save(self, path: str) -> None:
                del path

        class _FakeDev:
            def screenshot(self) -> _Img:
                return _Img()

        backend = AdbBackend()
        backend._device = lambda serial: _FakeDev()  # type: ignore[method-assign]
        with pytest.raises(AdbError) as info:
            backend.screenshot("emulator-5554", tmp_path / "shot.png")
        assert info.value.code == "backend_error"

    def test_an_empty_png_is_not_a_screenshot(self, tmp_path: Path) -> None:
        out = tmp_path / "shot.png"

        class _Img:
            def save(self, path: str) -> None:
                Path(path).write_bytes(b"")

        class _FakeDev:
            def screenshot(self) -> _Img:
                return _Img()

        backend = AdbBackend()
        backend._device = lambda serial: _FakeDev()  # type: ignore[method-assign]
        with pytest.raises(AdbError) as info:
            backend.screenshot("emulator-5554", out)
        assert info.value.code == "backend_error"

    def test_a_written_png_is_success(self, tmp_path: Path) -> None:
        out = tmp_path / "shot.png"

        class _Img:
            def save(self, path: str) -> None:
                Path(path).write_bytes(b"\x89PNG")

        class _FakeDev:
            def screenshot(self) -> _Img:
                return _Img()

        backend = AdbBackend()
        backend._device = lambda serial: _FakeDev()  # type: ignore[method-assign]
        result = backend.screenshot("emulator-5554", out)
        assert result["path"] == str(out)
        assert out.is_file()
        assert out.stat().st_size > 0
