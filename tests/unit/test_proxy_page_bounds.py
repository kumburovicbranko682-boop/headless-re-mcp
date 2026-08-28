"""proxy.flows must reject non-integer page bounds as invalid_params.

The proxy.flows tool schema types ``offset``/``limit`` as integers, but only the
MCP transport runs that pydantic validation: the agent and OpenAI-bridge
transports call the bound handler directly, so a hostile page argument reaches
the backend unchecked. Before the fix ``flows`` fed the value straight to
``int(...)``, so a float (inf from a JSON 1e400), nan, null, a non-numeric
string, or a container raised OverflowError/ValueError/TypeError -- none a
ProxyError, so the service's ``except BaseException`` filed an internal_error
incident for what is only a bad page window.
"""

from __future__ import annotations

import math
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.proxy.client import ProxyBackend, ProxyError

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


def _backend(monkeypatch: Any, count: int = 10) -> ProxyBackend:
    rows = [{"seq": i, "id": str(i)} for i in range(count)]
    recorder = SimpleNamespace(snapshot=lambda: list(rows))
    backend = ProxyBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder))
    return backend


@pytest.mark.parametrize("bad", _HOSTILE)
def test_flows_hostile_offset_is_invalid_params(monkeypatch: Any, bad: object) -> None:
    backend = _backend(monkeypatch)
    with pytest.raises(ProxyError) as excinfo:
        backend.flows("s", offset=bad, limit=10)  # type: ignore[arg-type]
    assert excinfo.value.code == "invalid_params"


@pytest.mark.parametrize("bad", _HOSTILE)
def test_flows_hostile_limit_is_invalid_params(monkeypatch: Any, bad: object) -> None:
    backend = _backend(monkeypatch)
    with pytest.raises(ProxyError) as excinfo:
        backend.flows("s", offset=0, limit=bad)  # type: ignore[arg-type]
    assert excinfo.value.code == "invalid_params"


def test_valid_and_clampable_bounds_still_page(monkeypatch: Any) -> None:
    """Negative and oversized numeric bounds clamp; int-like strings still parse."""
    backend = _backend(monkeypatch, count=10)
    payload = backend.flows("s", offset=-10, limit=10**9)
    assert payload["offset"] == 0
    assert payload["count"] == 10
    payload = backend.flows("s", offset="2", limit="3")  # type: ignore[arg-type]
    assert payload["offset"] == 2
    assert payload["count"] == 3
