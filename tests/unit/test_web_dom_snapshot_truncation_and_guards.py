"""web.dom.snapshot: the Python side is a second line of defence, not a passthrough.

The existing dom.snapshot test drives a page whose in-page script already cut
the HTML and reported ``truncated: True``. That leaves the client's own guards
inert -- it re-derives

    "html": text[:_MAX_INLINE_BODY],
    "truncated": bool(clipped.get("truncated")) or len(text) > _MAX_INLINE_BODY,

so a script that returns an over-cap document with ``truncated: False`` (a page
that raced the cap, or a browser that ignored the slice) is still clipped and
still flagged. It also refuses a non-dict evaluation, coerces a missing/non-string
html to "", and maps an evaluation that raises to backend_error. A page under a
deobfuscation session is adversarial, so "the script said it was fine" is not a
guarantee the client may relay.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.web.client import _MAX_INLINE_BODY, WebBackend, WebError


class _Immediate:
    def call(self, work: Any, timeout: float | None = None) -> Any:
        return work()


def _backend(evaluate: Any, *, url: str = "https://x/app", title: str = "T") -> WebBackend:
    backend = WebBackend()
    page = SimpleNamespace()
    page.url = url
    page.evaluate = evaluate
    page.title = lambda: title
    backend._get = lambda session_id: SimpleNamespace(page=page)  # type: ignore[method-assign]
    backend._runner = lambda handle: _Immediate()  # type: ignore[method-assign]
    return backend


def test_the_client_reclips_and_flags_a_document_the_script_did_not_cut() -> None:
    """Script returns an over-cap html but claims truncated False. The client
    must clip to the cap on its own and flag truncated via the length fallback --
    otherwise an over-cap document rides through inline and reads as complete.
    """
    oversize = "y" * (_MAX_INLINE_BODY + 50)
    backend = _backend(lambda script, cap: {"html": oversize, "truncated": False})

    payload = backend.dom_snapshot("s")

    assert len(payload["html"]) == _MAX_INLINE_BODY
    assert payload["truncated"] is True


def test_a_small_clean_document_is_returned_whole_and_not_flagged() -> None:
    """Both truncation signals are false: the script did not cut and the text
    fits. html is returned verbatim and truncated is False.
    """
    backend = _backend(lambda script, cap: {"html": "<html></html>", "truncated": False})

    payload = backend.dom_snapshot("s")

    assert payload["html"] == "<html></html>"
    assert payload["truncated"] is False


def test_a_non_dict_evaluation_is_a_backend_error() -> None:
    """A page evaluate that does not return the {html, truncated} object is a
    failed snapshot, not something to index into and crash on."""
    backend = _backend(lambda script, cap: "not a document")

    with pytest.raises(WebError) as caught:
        backend.dom_snapshot("s")

    assert caught.value.code == "backend_error"
    assert "no document" in caught.value.message


def test_a_missing_html_field_becomes_an_empty_document_not_a_crash() -> None:
    """A dict without an html string (or with a non-string html) must coerce to
    an empty document -- text[:cap] on a None would raise."""
    backend = _backend(lambda script, cap: {"truncated": False})

    payload = backend.dom_snapshot("s")

    assert payload["html"] == ""
    assert payload["truncated"] is False


def test_an_evaluation_that_raises_is_a_backend_error() -> None:
    """A page that tears the context down mid-evaluate raises; the client maps
    that to backend_error rather than letting the raw exception escape."""

    def boom(script: str, cap: int) -> Any:
        raise RuntimeError("execution context was destroyed")

    backend = _backend(boom)

    with pytest.raises(WebError) as caught:
        backend.dom_snapshot("s")

    assert caught.value.code == "backend_error"
    assert "dom snapshot failed" in caught.value.message
