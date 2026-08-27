"""web.cookies contract: bounded, normalized, paginated cookie listing.

The jar is attacker-influenced -- a page sets however many cookies of whatever
size it likes -- so the listing must stay bounded like every other captured
web field, and the entries must use the documented snake_case names rather
than Playwright's camelCase, or the tool docstring lies to the agent.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from headless_re_mcp.backends.web.client import (
    _MAX_COOKIE_VALUE_BYTES,
    _MAX_COOKIES,
    WebBackend,
    WebError,
    _WebSession,
)


class _DirectRunner:
    """Run work inline; these tests never start a browser thread."""

    def call(self, work: Callable[[], Any], *, timeout: float = 0.0) -> Any:
        return work()


class _FakeContext:
    def __init__(self, cookies: Any) -> None:
        self._cookies = cookies

    def cookies(self) -> Any:
        if isinstance(self._cookies, Exception):
            raise self._cookies
        return self._cookies


def _backend(raw: Any) -> WebBackend:
    backend = WebBackend()
    handle = _WebSession(
        playwright=object(),
        browser=object(),
        context=_FakeContext(raw),
        page=object(),
        cdp=object(),
    )
    handle.runner = _DirectRunner()  # type: ignore[assignment]
    backend._sessions["web"] = handle
    return backend


def _playwright_cookie(**overrides: Any) -> dict[str, Any]:
    cookie: dict[str, Any] = {
        "name": "sid",
        "value": "abc123",
        "domain": ".example.com",
        "path": "/",
        "expires": 1_900_000_000.0,
        "httpOnly": True,
        "secure": True,
        "sameSite": "Lax",
    }
    cookie.update(overrides)
    return cookie


class TestCookieFieldContract:
    def test_entries_use_the_documented_snake_case_field_names(self) -> None:
        result = _backend([_playwright_cookie()]).cookies("web")

        assert result["count"] == result["total"] == 1
        assert result["offset"] == 0
        assert result["has_more"] is False
        entry = result["cookies"][0]
        assert entry == {
            "name": "sid",
            "value": "abc123",
            "domain": ".example.com",
            "path": "/",
            "expires": 1_900_000_000.0,
            "http_only": True,
            "secure": True,
            "same_site": "Lax",
        }
        # The camelCase originals must not leak through alongside them.
        assert "httpOnly" not in entry and "sameSite" not in entry

    def test_missing_flags_normalize_to_booleans(self) -> None:
        raw = _playwright_cookie()
        del raw["httpOnly"]
        del raw["secure"]

        entry = _backend([raw]).cookies("web")["cookies"][0]

        assert entry["http_only"] is False
        assert entry["secure"] is False

    def test_non_dict_entries_are_skipped_not_crashed_on(self) -> None:
        result = _backend(["junk", None, _playwright_cookie()]).cookies("web")

        assert result["total"] == 1
        assert result["cookies"][0]["name"] == "sid"

    def test_a_non_list_answer_yields_an_empty_jar(self) -> None:
        result = _backend({"unexpected": "shape"}).cookies("web")

        assert result == {
            "cookies": [],
            "count": 0,
            "total": 0,
            "offset": 0,
            "has_more": False,
        }


class TestCookieBounding:
    def test_an_oversized_value_is_cut_and_marked(self) -> None:
        huge = "v" * (_MAX_COOKIE_VALUE_BYTES + 1)

        entry = _backend([_playwright_cookie(value=huge)]).cookies("web")["cookies"][0]

        assert len(entry["value"].encode("utf-8")) == _MAX_COOKIE_VALUE_BYTES
        assert entry["value_truncated"] is True

    def test_a_value_exactly_at_the_cap_is_not_marked(self) -> None:
        exact = "v" * _MAX_COOKIE_VALUE_BYTES

        entry = _backend([_playwright_cookie(value=exact)]).cookies("web")["cookies"][0]

        assert entry["value"] == exact
        assert "value_truncated" not in entry

    def test_the_jar_itself_is_capped(self) -> None:
        raw = [_playwright_cookie(name=f"c{i}") for i in range(_MAX_COOKIES + 50)]

        result = _backend(raw).cookies("web", limit=_MAX_COOKIES)

        assert result["total"] == _MAX_COOKIES
        assert result["has_more"] is False


class TestCookiePagination:
    def test_offset_and_limit_window_the_jar(self) -> None:
        raw = [_playwright_cookie(name=f"c{i}") for i in range(5)]

        result = _backend(raw).cookies("web", offset=2, limit=2)

        assert [c["name"] for c in result["cookies"]] == ["c2", "c3"]
        assert result["count"] == 2
        assert result["total"] == 5
        assert result["offset"] == 2
        assert result["has_more"] is True

    def test_an_offset_past_the_end_returns_an_empty_page(self) -> None:
        result = _backend([_playwright_cookie()]).cookies("web", offset=10)

        assert result["cookies"] == []
        assert result["count"] == 0
        assert result["total"] == 1
        assert result["has_more"] is False


class TestCookieErrorPaths:
    def test_an_unknown_session_is_invalid_state(self) -> None:
        with pytest.raises(WebError) as info:
            WebBackend().cookies("nope")

        assert info.value.code == "invalid_state"

    def test_a_failing_context_read_is_a_backend_error(self) -> None:
        with pytest.raises(WebError) as info:
            _backend(RuntimeError("driver gone")).cookies("web")

        assert info.value.code == "backend_error"
        assert "driver gone" in info.value.message
