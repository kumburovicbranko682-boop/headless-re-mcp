"""web.open / web.navigate must refuse to drive the browser off the web.

``page.goto`` loads ``file://``, ``chrome://``, ``view-source:`` and ``data:``
just as happily as a web address, and the session's readers (``dom_snapshot``,
``network_get``) then hand back whatever the browser read. A caller navigating
to ``file:///etc/passwd`` turns the web analyzer into a local file reader,
sidestepping every path guard in the rest of the system. Pin that anything
without an explicit http(s) scheme fails closed -- before a browser launches,
before a session slot is reserved.
"""

from __future__ import annotations

from typing import Any

import pytest

from headless_re_mcp.backends.web.client import (
    _MAX_URL_BYTES,
    WebBackend,
    WebError,
    _require_http_url,
)


@pytest.mark.parametrize(
    "hostile",
    [
        "file:///etc/passwd",
        "chrome://version",
        "view-source:http://example.com",
        "javascript:alert(1)",
        "data:text/html,<script>1</script>",
        "about:blank",
        "ftp://example.com/x",
        # A control character stops the prefix from reading http(s); browsers
        # strip such characters and would still navigate, so the check must
        # reject rather than trust the raw string.
        "fi\tle:///etc/passwd",
        # Protocol-relative: the browser resolves the scheme, not the caller.
        "//example.com/app",
        "/tmp/asset.js",
        "",
    ],
)
def test_the_url_guard_rejects_everything_that_is_not_http(hostile: str) -> None:
    with pytest.raises(WebError) as excinfo:
        _require_http_url(hostile)
    assert excinfo.value.code == "invalid_params"


@pytest.mark.parametrize(
    "web",
    [
        "http://127.0.0.1:8080/app",
        "https://example.com/app?x=1#frag",
        # Scheme matching is case-insensitive, like the URL spec.
        "HTTPS://EXAMPLE.COM/APP",
        # Leading/trailing whitespace is stripped, and the stripped string is
        # what gets navigated -- so what was checked is what goes to goto.
        "  https://example.com/app  ",
    ],
)
def test_the_url_guard_accepts_real_web_targets(web: str) -> None:
    assert _require_http_url(web) == web.strip()


def test_the_url_guard_rejects_an_over_long_url_before_it_reaches_the_browser() -> None:
    """A valid-scheme but megabyte-long URL is refused, not pushed to goto.

    The selector and type-text guards hard-cap their caller input; the URL guard
    only ever used _MAX_URL_BYTES to trim the value in error metadata, so a
    well-formed http(s) URL of any length was returned verbatim and handed to
    page.goto -- an unbounded push across the CDP channel, and echoed into the
    timeline at full length. The cap now runs on the accept path too: a URL over
    16 KiB fails closed as invalid_params (carrying the measured size and a
    trimmed echo), while one right at the cap still passes.
    """
    # Multi-byte characters prove the cap counts encoded bytes, not code points.
    over = "https://example.com/" + "é" * _MAX_URL_BYTES
    with pytest.raises(WebError) as excinfo:
        _require_http_url(over)
    assert excinfo.value.code == "invalid_params"
    assert excinfo.value.details["cap"] == _MAX_URL_BYTES
    assert excinfo.value.details["bytes"] > _MAX_URL_BYTES
    # The echoed url in the error is itself bounded, never the raw megabyte input.
    assert len(str(excinfo.value.details["url"]).encode("utf-8")) <= _MAX_URL_BYTES

    # A URL whose encoded length sits exactly at the cap is still accepted, so the
    # bound refuses only what is genuinely over it.
    prefix = "https://example.com/"
    at_cap = prefix + "a" * (_MAX_URL_BYTES - len(prefix.encode("utf-8")))
    assert len(at_cap.encode("utf-8")) == _MAX_URL_BYTES
    assert _require_http_url(at_cap) == at_cap


def test_web_navigate_rejects_an_over_long_url_before_touching_the_session() -> None:
    """The length cap, like the scheme check, lands before the session lookup."""
    backend = WebBackend()

    def poisoned(_session_id: str) -> Any:
        raise AssertionError("an over-long URL must not reach the session")

    backend._get = poisoned  # type: ignore[method-assign]
    with pytest.raises(WebError) as excinfo:
        backend.navigate("s", "https://example.com/" + "a" * _MAX_URL_BYTES)
    assert excinfo.value.code == "invalid_params"


def test_web_navigate_refuses_a_file_url_before_touching_the_session() -> None:
    """A hostile URL must not reach the browser thread at all.

    Validation runs before the session lookup, so the refusal costs nothing
    and cannot wedge on a busy runner. The error is the envelope's
    invalid_params, not a backend_error dressed up by Playwright.
    """
    backend = WebBackend()

    def poisoned(_session_id: str) -> Any:
        raise AssertionError("a rejected URL must not reach the session")

    backend._get = poisoned  # type: ignore[method-assign]
    with pytest.raises(WebError) as excinfo:
        backend.navigate("s", "file:///etc/passwd")
    assert excinfo.value.code == "invalid_params"


def test_web_open_refuses_a_file_url_before_reserving_the_slot(
    monkeypatch: Any,
) -> None:
    """open must fail closed before spending a browser on a non-web target.

    The refusal has to land before the session slot is reserved: a leaked
    reservation would make the next honest open report "already open" for a
    browser that never existed. It also lands before the Playwright import,
    so the guard holds even where Playwright is not installed.
    """
    backend = WebBackend()
    monkeypatch.setattr(backend, "_check_available", lambda: None)
    with pytest.raises(WebError) as excinfo:
        backend.open("s", "file:///etc/passwd")
    assert excinfo.value.code == "invalid_params"
    assert "s" not in backend._sessions


def test_web_open_rejects_a_non_web_url_before_the_capability_gate() -> None:
    """A bad url reads as invalid_params even where Playwright is absent.

    The sibling above stubs ``_check_available`` to a no-op, so it proves the
    scheme check precedes the *slot reservation* -- but with the gate stubbed
    out it cannot see the *capability gate*'s order at all, and its docstring's
    claim that the guard "holds even where Playwright is not installed" went
    untested (and was in fact false: ``open`` used to run ``_check_available``
    first). This forces the gate live but unavailable (``_available = False``,
    as on a host with no Playwright) and asserts the non-web url still fails as
    invalid_params, not capability_unavailable. An agent routes on code, and
    "fix the url" is a different fix from "install the backend"; navigate,
    proxy.start, frida.spawn and jadx.decompile all reject caller input before
    their capability gate, and open now matches them.
    """
    backend = WebBackend()
    backend._available = False  # host without Playwright; the gate is live, not stubbed
    with pytest.raises(WebError) as excinfo:
        backend.open("s", "file:///etc/passwd")
    assert excinfo.value.code == "invalid_params"
    assert "s" not in backend._sessions
