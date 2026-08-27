"""proxy.replay must not report a skipped flow as replayed.

mitmproxy's ``replay.client`` command silently drops flows it cannot replay
(live, intercepted, WebSocket, or missing request/content): it logs a warning
and returns normally. Taken at face value that skip became ``replayed=True``
for a request that was never sent, so the backend asks the same addon the same
``check`` question first and surfaces its reason instead of a false success.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.proxy.client import ProxyBackend, ProxyError


class _Flow:
    def __init__(self, flow_id: str) -> None:
        self.id = flow_id

    def copy(self) -> _Flow:
        # mitmproxy's Flow.copy() assigns the copy a fresh id; mirror that so
        # the backend can hand back a distinct replayed_flow_id.
        return _Flow(f"{self.id}-copy")


class _Loop:
    def call_soon_threadsafe(self, fn: Any) -> None:
        # The real loop runs this on the proxy thread; running it inline keeps
        # the future resolution deterministic without standing up an event loop.
        fn()


class _Commands:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Any]] = []

    def call(self, name: str, args: Any) -> None:
        self.calls.append((name, args))


class _Playback:
    def __init__(self, reason: str | None) -> None:
        self._reason = reason

    def check(self, flow: Any) -> str | None:
        del flow
        return self._reason


class _Addons:
    def __init__(self, playback: _Playback | None) -> None:
        self._playback = playback

    def get(self, name: str) -> _Playback | None:
        return self._playback if name == "clientplayback" else None


def _instance(reason: str | None) -> tuple[SimpleNamespace, _Commands]:
    commands = _Commands()
    master = SimpleNamespace(addons=_Addons(_Playback(reason)), commands=commands)
    recorder = SimpleNamespace(raw=lambda flow_id: _Flow(flow_id))
    inst = SimpleNamespace(recorder=recorder, _master=master, _loop=_Loop())
    return inst, commands


def test_unreplayable_flow_is_refused_not_reported_as_replayed(monkeypatch: Any) -> None:
    inst, commands = _instance("Can't replay live flow.")
    backend = ProxyBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: inst)

    try:
        backend.replay("s", "f1")
    except ProxyError as exc:
        assert exc.code == "invalid_request"
        assert "live flow" in exc.message
    else:  # pragma: no cover - the call must not succeed
        raise AssertionError("replay reported success for an unreplayable flow")

    # The flow the addon would have skipped must never reach replay.client.
    assert commands.calls == []


def test_replayable_flow_runs_and_returns_the_replayed_flow_id(monkeypatch: Any) -> None:
    inst, commands = _instance(None)
    backend = ProxyBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: inst)

    payload = backend.replay("s", "f1")

    assert payload["replayed"] is True
    assert payload["flow_id"] == "f1"
    # Flow.copy() re-ids the flow; the caller needs that id to correlate the
    # replayed response in proxy.flows.
    assert payload["replayed_flow_id"] == "f1-copy"
    assert len(commands.calls) == 1
    name, args = commands.calls[0]
    assert name == "replay.client"
    assert [f.id for f in args] == ["f1-copy"]
