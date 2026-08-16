"""A navigation that stayed on about:blank used to look opened."""

from __future__ import annotations

import pytest

from headless_re_mcp.backends.web.client import WebBackend, WebError


class _SyncRunner:
    def call(self, work: object, timeout: float | None = None) -> object:
        del timeout
        return work()  # type: ignore[operator]


class TestNavigateDoesNotCallBlankSuccess:
    """goto that never left about:blank used to return that URL as success.

    Measured: FakePage.goto left url=about:blank, navigate() returned
    url=about:blank -- so a caller treats a failed load as the target page.
    """

    def _backend(self, landed: str) -> WebBackend:
        class _Page:
            url = landed

            def goto(self, url: str, timeout: float = 0, wait_until: str = "") -> None:
                del url, timeout, wait_until

        class _Handle:
            page = _Page()

        backend = WebBackend()
        backend._get = lambda session_id: _Handle()  # type: ignore[method-assign]
        backend._runner = lambda handle: _SyncRunner()  # type: ignore[method-assign]
        return backend

    def test_staying_on_about_blank_is_not_navigation(self) -> None:
        backend = self._backend("about:blank")
        with pytest.raises(WebError) as info:
            backend.navigate("sess", "https://example.com/app")
        assert info.value.code == "backend_error"

    def test_a_real_url_is_success(self) -> None:
        backend = self._backend("https://example.com/app")
        result = backend.navigate("sess", "https://example.com/app")
        assert result["url"] == "https://example.com/app"

    def test_opening_about_blank_is_allowed(self) -> None:
        backend = self._backend("about:blank")
        result = backend.navigate("sess", "about:blank")
        assert result["url"] == "about:blank"
