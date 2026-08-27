"""proxy.flow.get / proxy.replay fail-closed guards, driven without mitmproxy.

flow_get and replay both start by resolving a flow out of the capture ring, and
both must fail precisely when it is not there: an unknown or already-evicted id
is not_found, a flow whose body was dropped (too big to retain) is too_large,
and a replay attempted while the proxy is not running is invalid_state. Those
guards run before any mitmproxy object is touched, so a fake instance whose
recorder returns the sentinel of the moment exercises them without a live proxy
-- the same _get seam test_proxy_flow_get_bounds uses. The request-side
metadata_truncated flag is pinned here too: the bounds test only flagged the
response side, leaving an oversized request method/url/header map untested.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.proxy.client import (
    _MAX_METADATA_BYTES,
    _OMITTED_BODY,
    ProxyBackend,
    ProxyError,
)


def _backend(
    monkeypatch: pytest.MonkeyPatch,
    *,
    flow: Any,
    master: Any = None,
    loop: Any = None,
) -> ProxyBackend:
    backend = ProxyBackend()
    recorder = SimpleNamespace(raw=lambda flow_id: flow)
    inst = SimpleNamespace(recorder=recorder, _master=master, _loop=loop)
    monkeypatch.setattr(backend, "_get", lambda session_id: inst)
    return backend


def test_flow_get_reports_an_unknown_id_as_not_found(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = _backend(monkeypatch, flow=None)
    with pytest.raises(ProxyError) as caught:
        backend.flow_get("s", "gone", tmp_path)
    assert caught.value.code == "not_found"
    assert caught.value.details.get("flow_id") == "gone"


def test_flow_get_reports_an_omitted_body_as_too_large(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A flow the ring kept as a summary but whose body it declined to retain
    comes back as too_large, not not_found -- the flow existed, its body did
    not."""
    backend = _backend(monkeypatch, flow=_OMITTED_BODY)
    with pytest.raises(ProxyError) as caught:
        backend.flow_get("s", "big", tmp_path)
    assert caught.value.code == "too_large"
    assert caught.value.details.get("flow_id") == "big"


def test_flow_get_flags_request_side_truncation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An oversized request method/url/header map flags the request side, the
    mirror of the response-side flag the bounds test already pins."""
    request = SimpleNamespace(
        method="M" * (_MAX_METADATA_BYTES + 20),
        pretty_url="http://x/1",
        headers={"accept": "text/plain"},
    )
    response = SimpleNamespace(status_code=200, headers={}, raw_content=b"ok")
    flow = SimpleNamespace(request=request, response=response)
    backend = _backend(monkeypatch, flow=flow)
    payload = backend.flow_get("s", "f1", tmp_path)
    assert payload["request"]["metadata_truncated"] is True
    assert len(payload["request"]["method"].encode("utf-8")) <= _MAX_METADATA_BYTES
    # No body was present on the request, so it inlines as empty and spills nothing.
    assert payload["request"]["body"] == ""
    assert list(tmp_path.iterdir()) == []


def test_replay_reports_an_unknown_id_as_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = _backend(monkeypatch, flow=None)
    with pytest.raises(ProxyError) as caught:
        backend.replay("s", "gone")
    assert caught.value.code == "not_found"


def test_replay_reports_an_omitted_body_as_too_large(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replay needs the original bytes; a flow whose body was not retained cannot
    be replayed and says so as too_large rather than failing obscurely later."""
    backend = _backend(monkeypatch, flow=_OMITTED_BODY)
    with pytest.raises(ProxyError) as caught:
        backend.replay("s", "big")
    assert caught.value.code == "too_large"


def test_replay_while_the_proxy_is_not_running_is_invalid_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A flow can outlive its proxy (status/flows still read the ring). Replay
    cannot: with no master/loop to inject into, it fails closed as invalid_state
    rather than dereferencing a None master."""
    flow = SimpleNamespace(request=SimpleNamespace(method="GET", pretty_url="http://x/1"))
    backend = _backend(monkeypatch, flow=flow, master=None, loop=None)
    with pytest.raises(ProxyError) as caught:
        backend.replay("s", "f1")
    assert caught.value.code == "invalid_state"
