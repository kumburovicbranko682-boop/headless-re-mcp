"""A first load that stayed on about:blank used to look opened."""

from __future__ import annotations

import sys
import types

import pytest

from headless_re_mcp.backends.web.client import WebBackend, WebError


class TestOpenDoesNotCallBlankSuccess:
    """goto that never left about:blank used to return opened=True.

    Measured: FakePage.goto left url=about:blank, open() returned
    opened=True url=about:blank -- so a caller treats a failed first
    load as a live browser on the target.
    """

    def _backend(self, monkeypatch: pytest.MonkeyPatch, landed: str) -> WebBackend:
        class _FakeCdp:
            def send(self, *args: object, **kwargs: object) -> None:
                del args, kwargs

            def on(self, *args: object, **kwargs: object) -> None:
                del args, kwargs

        class _FakePage:
            def __init__(self) -> None:
                self.url = "about:blank"

            def goto(self, url: str, timeout: float = 0, wait_until: str = "") -> None:
                del url, timeout, wait_until
                self.url = landed

            def title(self) -> str:
                return ""

        class _FakeContext:
            def new_page(self) -> _FakePage:
                return _FakePage()

            def new_cdp_session(self, page: object) -> _FakeCdp:
                del page
                return _FakeCdp()

            def close(self) -> None:
                return None

        class _FakeBrowser:
            def new_context(self, ignore_https_errors: bool = True) -> _FakeContext:
                del ignore_https_errors
                return _FakeContext()

            def close(self) -> None:
                return None

        class _FakeChromium:
            def launch(self, headless: bool = True) -> _FakeBrowser:
                del headless
                return _FakeBrowser()

        class _FakePw:
            chromium = _FakeChromium()

            def start(self) -> _FakePw:
                return self

            def stop(self) -> None:
                return None

        playwright = types.ModuleType("playwright")
        sync_api = types.ModuleType("playwright.sync_api")
        sync_api.sync_playwright = lambda: _FakePw()
        monkeypatch.setitem(sys.modules, "playwright", playwright)
        monkeypatch.setitem(sys.modules, "playwright.sync_api", sync_api)
        backend = WebBackend()
        backend._available = True
        return backend

    def test_staying_on_about_blank_is_not_open(self, monkeypatch: pytest.MonkeyPatch) -> None:
        backend = self._backend(monkeypatch, "about:blank")
        with pytest.raises(WebError) as info:
            backend.open("sess", "https://example.com/app")
        assert info.value.code == "backend_error"
        with pytest.raises(WebError):
            backend._get("sess")

    def test_a_real_url_is_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        backend = self._backend(monkeypatch, "https://example.com/app")
        try:
            result = backend.open("sess", "https://example.com/app")
            assert result["opened"] is True
            assert result["url"] == "https://example.com/app"
        finally:
            backend.close("sess")

    def test_opening_about_blank_is_allowed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        backend = self._backend(monkeypatch, "about:blank")
        try:
            result = backend.open("sess", "about:blank")
            assert result["opened"] is True
            assert result["url"] == "about:blank"
        finally:
            backend.close("sess")
