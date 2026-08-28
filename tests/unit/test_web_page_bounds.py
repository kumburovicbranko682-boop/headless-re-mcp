"""web.network_list/console/scripts must reject non-integer page bounds.

The web.* tool schemas type ``offset``/``limit`` as integers, but only the MCP
transport runs that pydantic validation: the agent and OpenAI-bridge transports
call the bound handler directly (``CommandCatalog.invoke`` ->
``spec.handler(**arguments)``), so a hostile page argument reaches the backend
unchecked. Before the fix these methods fed the value straight to ``int(...)``,
so a float (inf from a JSON 1e400), nan, null, a non-numeric string, or a
container raised OverflowError/ValueError/TypeError -- none a WebError, so the
service's ``except BaseException`` filed an internal_error incident for what is
only a bad page window. These pin the invalid_params guard on every reader.
"""

from __future__ import annotations

import math
from threading import Lock
from typing import Any

import pytest

from headless_re_mcp.backends.web.client import WebBackend, WebError

_HOSTILE = [
    math.inf,
    -math.inf,
    math.nan,
    None,
    "abc",
    "",
    {},
    [],
    True,
    False,
]


class _FakeHandle:
    def __init__(self, count: int) -> None:
        self.lock = Lock()
        self.requests = {
            str(i): {"requestId": str(i), "url": f"https://example/{i}"} for i in range(count)
        }
        self.requests_dropped = 0
        self.console = [{"type": "log", "text": f"m{i}"} for i in range(count)]
        self.console_dropped = 0
        self.scripts = {
            str(i): {"scriptId": str(i), "url": f"https://example/{i}.js", "language": "JavaScript"}
            for i in range(count)
        }
        self.scripts_dropped = 0


def _backend(monkeypatch: Any, count: int = 10) -> WebBackend:
    backend = WebBackend()
    handle = _FakeHandle(count)
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    return backend


@pytest.mark.parametrize("bad", _HOSTILE)
def test_network_list_hostile_offset_is_invalid_params(monkeypatch: Any, bad: object) -> None:
    backend = _backend(monkeypatch)
    with pytest.raises(WebError) as excinfo:
        backend.network_list("s", offset=bad, limit=10)  # type: ignore[arg-type]
    assert excinfo.value.code == "invalid_params"


@pytest.mark.parametrize("bad", _HOSTILE)
def test_network_list_hostile_limit_is_invalid_params(monkeypatch: Any, bad: object) -> None:
    backend = _backend(monkeypatch)
    with pytest.raises(WebError) as excinfo:
        backend.network_list("s", offset=0, limit=bad)  # type: ignore[arg-type]
    assert excinfo.value.code == "invalid_params"


@pytest.mark.parametrize("bad", _HOSTILE)
def test_console_hostile_limit_is_invalid_params(monkeypatch: Any, bad: object) -> None:
    backend = _backend(monkeypatch)
    with pytest.raises(WebError) as excinfo:
        backend.console("s", limit=bad)  # type: ignore[arg-type]
    assert excinfo.value.code == "invalid_params"


@pytest.mark.parametrize("bad", _HOSTILE)
def test_scripts_hostile_offset_is_invalid_params(monkeypatch: Any, bad: object) -> None:
    backend = _backend(monkeypatch)
    with pytest.raises(WebError) as excinfo:
        backend.scripts("s", offset=bad, limit=10)  # type: ignore[arg-type]
    assert excinfo.value.code == "invalid_params"


@pytest.mark.parametrize("bad", _HOSTILE)
def test_scripts_hostile_limit_is_invalid_params(monkeypatch: Any, bad: object) -> None:
    backend = _backend(monkeypatch)
    with pytest.raises(WebError) as excinfo:
        backend.scripts("s", offset=0, limit=bad)  # type: ignore[arg-type]
    assert excinfo.value.code == "invalid_params"


def test_valid_and_clampable_bounds_still_page(monkeypatch: Any) -> None:
    """Negative and oversized numeric bounds clamp; int-like strings still parse."""
    backend = _backend(monkeypatch, count=10)
    # Negative offset -> page zero; oversized limit -> the whole buffer.
    payload = backend.network_list("s", offset=-1, limit=10**9)
    assert payload["offset"] == 0
    assert payload["count"] == 10
    # int-like strings are valid bounds (int("2") == 2), not rejections.
    payload = backend.scripts("s", offset="2", limit="3")  # type: ignore[arg-type]
    assert payload["offset"] == 2
    assert payload["count"] == 3
    # console clamps a huge numeric limit to the ring capacity without error.
    payload = backend.console("s", limit=10**9)
    assert payload["count"] == 10
