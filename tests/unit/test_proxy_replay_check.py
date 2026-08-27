"""proxy.replay refuses flows mitmproxy cannot replay, and names the replayed flow.

mitmproxy's ``replay.client`` command silently drops a flow it cannot replay --
live, intercepted, WebSocket, or missing request/content -- logging a warning and
returning normally. Taken at face value that skip became ``replayed=True`` for a
request that was never sent. These tests pin that the ``clientplayback`` addon's
own ``check()`` reason is surfaced as an ``invalid_request`` refusal, and that a
replayable flow instead returns a non-empty ``replayed_flow_id`` so its response
can be located in ``proxy.flows``.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.proxy.client import ProxyBackend, ProxyError


class _FakeLoop:
    """Runs the queued replay callback inline so the future resolves in-test."""

    def call_soon_threadsafe(self, fn: Any, *args: Any) -> None:
        fn(*args)


class _FakeCommands:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Any]] = []

    def call(self, name: str, args: Any) -> None:
        self.calls.append((name, args))


class _FakeAddons:
    def __init__(self, reason: str | None) -> None:
        self._reason = reason
        self.checked: list[Any] = []

    def get(self, name: str) -> Any:
        assert name == "clientplayback"

        def check(flow: Any) -> str | None:
            self.checked.append(flow)
            return self._reason

        return SimpleNamespace(check=check)


def _backend(reason: str | None, monkeypatch: Any) -> tuple[ProxyBackend, _FakeCommands]:
    copied = SimpleNamespace(id="copy-id")
    original = SimpleNamespace(id="orig-id", copy=lambda: copied)
    commands = _FakeCommands()
    master = SimpleNamespace(addons=_FakeAddons(reason), commands=commands)
    inst = SimpleNamespace(
        recorder=SimpleNamespace(raw=lambda flow_id: original),
        _master=master,
        _loop=_FakeLoop(),
    )
    backend = ProxyBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: inst)
    return backend, commands


def test_replay_refuses_a_flow_the_proxy_cannot_replay(monkeypatch: Any) -> None:
    backend, commands = _backend("Can't replay WebSocket flows.", monkeypatch)
    with pytest.raises(ProxyError) as excinfo:
        backend.replay("s", "f1")
    assert excinfo.value.code == "invalid_request"
    assert "WebSocket" in excinfo.value.message
    # An unreplayable flow must never be dispatched to replay.client.
    assert commands.calls == []


def test_replay_returns_the_replayed_flow_id(monkeypatch: Any) -> None:
    backend, commands = _backend(None, monkeypatch)
    result = backend.replay("s", "f1")
    assert result["replayed"] is True
    assert result["flow_id"] == "f1"
    # The replay is a fresh flow with its own id, not the source flow's id.
    assert result["replayed_flow_id"] == "copy-id"
    # A replayable flow really is dispatched.
    assert commands.calls and commands.calls[0][0] == "replay.client"
