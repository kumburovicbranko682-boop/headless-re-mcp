"""A page screenshot that wrote nothing used to look captured."""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.web.client import WebBackend, WebError


class _SyncRunner:
    def call(self, work: object) -> object:
        return work()  # type: ignore[operator]


class TestWebScreenshotDoesNotCallMissingFileSuccess:
    """page.screenshot that wrote no bytes used to return a path anyway.

    Measured: FakePage.screenshot wrote nothing, screenshot() returned
    path, file missing -- so a caller treats a dead path as a page image.
    """

    def _backend(self, save: object) -> WebBackend:
        class _Page:
            def screenshot(self, path: str, full_page: bool = False) -> None:
                save(path, full_page)

        class _Handle:
            page = _Page()

        backend = WebBackend()
        backend._get = lambda session_id: _Handle()  # type: ignore[method-assign]
        backend._runner = lambda handle: _SyncRunner()  # type: ignore[method-assign]
        return backend

    def test_a_missing_png_is_not_a_screenshot(self, tmp_path: Path) -> None:
        backend = self._backend(lambda path, full_page: None)
        with pytest.raises(WebError) as info:
            backend.screenshot("sess", tmp_path / "shot.png")
        assert info.value.code == "backend_error"

    def test_an_empty_png_is_not_a_screenshot(self, tmp_path: Path) -> None:
        def save(path: str, full_page: bool) -> None:
            del full_page
            Path(path).write_bytes(b"")

        backend = self._backend(save)
        with pytest.raises(WebError) as info:
            backend.screenshot("sess", tmp_path / "shot.png")
        assert info.value.code == "backend_error"

    def test_a_written_png_is_success(self, tmp_path: Path) -> None:
        out = tmp_path / "shot.png"

        def save(path: str, full_page: bool) -> None:
            del full_page
            Path(path).write_bytes(b"\x89PNG")

        backend = self._backend(save)
        result = backend.screenshot("sess", out)
        assert result["path"] == str(out)
        assert out.is_file()
        assert out.stat().st_size > 0
