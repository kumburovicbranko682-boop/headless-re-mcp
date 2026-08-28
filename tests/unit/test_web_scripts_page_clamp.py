"""``web.scripts`` / ``web.wasm.list`` must clamp their page window at the client.

The web tool schemas bound ``offset >= 0`` and ``limit`` within range, but only
the MCP transport runs that pydantic validation: the agent and OpenAI-bridge
transports call the bound handler directly, so an out-of-range page reaches the
backend unchecked. ``WebBackend.scripts`` therefore clamps at the source with
``start = max(0, int(offset))`` and ``cap = max(1, min(int(limit), 1000))`` --
the same guard ``apk.classes/methods/strings`` and ``proxy.flows`` /
``web.network_list`` already carry (and that ``apk``'s clamp docstring names the
"web ... list backends" as already doing).

The catch is that every existing ``.scripts(...)`` test passes a non-negative
offset and a positive limit, so both ``max`` guards are no-ops in the covered
cases: deleting them changes nothing the suite observes. A negative offset then
becomes a Python tail slice (``values[-1 : -1 + limit]`` is an empty page that
still reports ``has_more`` True), a zero/negative limit an empty or
all-but-the-tail slice read as page zero, and a huge limit walks past the 1000
-row ceiling the two transports are supposed to agree on. These pin each leg of
the clamp -- for the plain listing and for the ``wasm_only`` path, whose filter
runs *before* the clamp so the window must still be bounded after it -- with a
fake script ring so no browser is needed.
"""

from __future__ import annotations

from threading import Lock
from typing import Any

from headless_re_mcp.backends.web.client import WebBackend

# The per-page ceiling ``scripts`` enforces, kept equal to the web.scripts /
# web.wasm.list tool-schema ``limit`` maximum so the MCP path (schema-validated)
# and the agent path (clamped here) agree on the largest page.
_SCRIPTS_PAGE_CEILING = 1000


class _FakeHandle:
    """A minimal script-ring stand-in: a lock, a ``scripts`` map, a drop count."""

    def __init__(self, count: int, *, dropped: int = 0, language: str = "JavaScript") -> None:
        self.lock = Lock()
        self.scripts = {
            str(index): {
                "scriptId": str(index),
                "url": f"https://example/{index}.js",
                "language": language,
            }
            for index in range(count)
        }
        self.scripts_dropped = dropped


def _backend_with(monkeypatch: Any, handle: _FakeHandle) -> WebBackend:
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    return backend


def test_negative_offset_returns_page_zero_not_a_tail_slice(monkeypatch: Any) -> None:
    """offset=-1 must read as page zero, not ``values[-1:9]`` -- an empty page.

    Without ``max(0, ...)`` the start is -1 and the slice is empty, yet
    ``has_more`` still fires: a caller reads "there is more" from a page that
    holds nothing. The clamp makes -1 mean 0, so the first ten scripts land.
    """
    backend = _backend_with(monkeypatch, _FakeHandle(25))

    payload = backend.scripts("s", offset=-1, limit=10)

    assert payload["offset"] == 0
    assert payload["count"] == 10
    assert payload["scripts"][0]["scriptId"] == "0"
    assert payload["has_more"] is True


def test_negative_limit_clamps_to_one_row(monkeypatch: Any) -> None:
    """limit=-5 must not become ``values[0:-5]`` -- 25 scripts read as 20.

    A negative limit slices all but the tail and reports it as page zero. The
    ``max(1, ...)`` floor turns any non-positive limit into a single row, so the
    page is honest about how little it holds.
    """
    backend = _backend_with(monkeypatch, _FakeHandle(25))

    payload = backend.scripts("s", offset=0, limit=-5)

    assert payload["count"] == 1
    assert payload["scripts"][0]["scriptId"] == "0"
    assert payload["has_more"] is True


def test_zero_limit_clamps_to_one_row(monkeypatch: Any) -> None:
    """limit=0 is the boundary the ``max(1, ...)`` floor exists for.

    ``min(0, 1000)`` is 0, so without the floor the window is empty and a caller
    that asked for "a page" gets nothing while more scripts wait.
    """
    backend = _backend_with(monkeypatch, _FakeHandle(25))

    payload = backend.scripts("s", offset=0, limit=0)

    assert payload["count"] == 1
    assert payload["has_more"] is True


def test_oversized_limit_is_capped_at_the_page_ceiling(monkeypatch: Any) -> None:
    """A page larger than the ceiling must not read more than that many rows.

    The agent path can ask for any limit; ``min(int(limit), 1000)`` is what keeps
    it level with the schema maximum the MCP path enforces. Drop it and a single
    call drains the whole ring.
    """
    backend = _backend_with(monkeypatch, _FakeHandle(_SCRIPTS_PAGE_CEILING + 25))

    payload = backend.scripts("s", offset=0, limit=10**9)

    assert payload["count"] == _SCRIPTS_PAGE_CEILING
    assert payload["has_more"] is True


def test_offset_past_total_is_an_empty_final_page(monkeypatch: Any) -> None:
    """An offset beyond the held scripts is the end, not more to come.

    ``has_more`` is ``start + len(window) < total``; a window that starts past
    the end is empty, so the flag must read False. A caller paging to the tail
    has to be able to stop.
    """
    backend = _backend_with(monkeypatch, _FakeHandle(5))

    payload = backend.scripts("s", offset=100, limit=10)

    assert payload["count"] == 0
    assert payload["has_more"] is False


def test_wasm_list_clamps_after_the_wasm_filter(monkeypatch: Any) -> None:
    """``wasm_only`` filters the ring first, then the same clamp bounds the page.

    The filter runs before the window is cut, so a hostile page window must be
    clamped against the *filtered* list, not the raw ring. A negative offset
    here still has to read as page zero over the WASM modules.
    """
    backend = _backend_with(monkeypatch, _FakeHandle(25, language="WebAssembly"))

    payload = backend.scripts("s", wasm_only=True, offset=-1, limit=10)

    assert payload["offset"] == 0
    assert payload["count"] == 10
    assert payload["total"] == 25
    assert payload["has_more"] is True
