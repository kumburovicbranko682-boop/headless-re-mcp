"""``web.console`` must floor its line limit before it tail-slices the ring.

Unlike the offset/limit list readers, ``web.console`` has no offset: it hands
back the newest ``limit`` lines with ``page = held[-capped:]`` where
``capped = max(1, min(int(limit), _MAX_CONSOLE))``. The web tool schema bounds
``limit`` for the MCP transport, but the agent and OpenAI-bridge transports call
the handler directly, so a non-positive limit reaches this line unchecked.

The ``max(1, ...)`` floor is the load-bearing guard, and it is inert under every
existing console test because they all pass a positive limit. The failure it
prevents is specific to the *tail* slice: ``held[-0:]`` is ``held[0:]`` -- the
**whole** buffer -- so a ``limit=0`` that lost the floor would dump every
retained line instead of a minimal page, the opposite of a safe default; and a
negative limit like ``-5`` becomes ``held[5:]``, dropping the newest lines while
``has_more`` (``len(held) > capped``) reads True against a negative bound. The
floor turns any non-positive limit into a single newest line.

These pin both non-positive legs against the real ``_WebSession`` console ring
(a bounded ``deque``), asserting the row kept is the newest, not the oldest. The
companion ``min(..., _MAX_CONSOLE)`` ceiling is intentionally not pinned here: it
cannot be observed through this method because the ring's ``maxlen`` equals
``_MAX_CONSOLE``, so ``len(held)`` can never exceed the ceiling and a fixture
cannot drive the two apart.
"""

from __future__ import annotations

from headless_re_mcp.backends.web.client import WebBackend, _WebSession


def _session_with_console(count: int) -> _WebSession:
    handle = _WebSession(object(), object(), object(), object(), object())
    handle.console.extend({"text": str(index)} for index in range(count))
    return handle


def test_zero_limit_returns_one_newest_line_not_the_whole_buffer() -> None:
    """limit=0 must not become ``held[-0:]`` -- the entire retained buffer.

    Without the ``max(1, ...)`` floor, ``capped`` is 0 and the tail slice
    ``held[-0:]`` is ``held[0:]``: every line the ring holds, returned as one
    "page". The floor makes a zero limit mean a single newest line, so a caller
    that asks for nothing does not accidentally drain the whole console.
    """
    backend = WebBackend()
    backend._sessions["s"] = _session_with_console(10)

    result = backend.console("s", limit=0)

    assert result["count"] == 1
    assert result["console"][0]["text"] == "9"
    assert result["total"] == 10
    assert result["has_more"] is True


def test_negative_limit_returns_one_newest_line() -> None:
    """limit=-5 must not become ``held[5:]`` -- the tail with its newest cut off.

    A negative limit slices from index 5 to the end (dropping the five newest
    lines) while ``has_more`` compares against a negative bound and always reads
    True. The floor collapses any negative limit to the single newest line.
    """
    backend = WebBackend()
    backend._sessions["s"] = _session_with_console(10)

    result = backend.console("s", limit=-5)

    assert result["count"] == 1
    assert result["console"][0]["text"] == "9"
    assert result["has_more"] is True
