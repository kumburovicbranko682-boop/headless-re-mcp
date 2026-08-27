"""x64dbg's public ``request`` clamps the caller deadline at the boundary.

The run-control tool schema declares ``0 < timeout <= 300``, but the agent and
OpenAI-bridge transports call the handler straight from model arguments with no
schema check. Without a boundary guard a NaN reached ``int(timeout * 1000)`` in
``_request`` and escaped as a raw "cannot convert float NaN to integer"
ValueError (surfaced as a bare invalid_request), and a huge value set an
effectively unbounded transport deadline even though the worker-side dispatch
caps at 30s. ``request`` now clamps with ``clamp_cli_timeout`` the same way the
IDA worker's ``request`` does: a non-finite or non-positive value is refused as
``invalid_params`` before any I/O, and an oversized one is capped to the schema
ceiling before it becomes the transport deadline.
"""

from __future__ import annotations

import json
import math
from collections import deque
from threading import Lock, RLock
from typing import Any

import pytest

import headless_re_mcp.backends.x64dbg.client as client_module
from headless_re_mcp.backends.x64dbg.client import XdbgClient, XdbgRpcError

JsonObject = dict[str, Any]


class _FakeProcess:
    def __init__(self) -> None:
        self.pid = 4321
        self.returncode: int | None = None

    def poll(self) -> int | None:
        return self.returncode


class _RecordingTransport:
    """Answers one request and records the deadline each I/O was granted."""

    def __init__(self) -> None:
        self.grants: list[float] = []
        self.requests: list[JsonObject] = []
        self._reads: deque[bytes] = deque()
        self.closed = False

    def write_all(self, data: bytes, *, timeout: float) -> None:
        self.grants.append(timeout)
        request = json.loads(data[4:])
        self.requests.append(request)
        response = {
            "protocol": "headless-re-xdbg",
            "version": 1,
            "id": request["id"],
            "ok": True,
            "result": {"request_id": request["id"]},
        }
        encoded = json.dumps(response, separators=(",", ":")).encode()
        self._reads.extend((len(encoded).to_bytes(4, "little"), encoded))

    def read_exact(self, size: int, *, timeout: float) -> bytes:
        self.grants.append(timeout)
        value = self._reads.popleft()
        assert len(value) == size
        return value

    def close(self) -> None:
        self.closed = True


def _client(transport: _RecordingTransport) -> XdbgClient:
    client = object.__new__(XdbgClient)
    client._request_id = 0
    client._request_lock = RLock()
    client._closed = False
    client._capabilities = frozenset({"events.read"})
    client._transport = transport  # type: ignore[assignment]
    client._process = _FakeProcess()  # type: ignore[assignment]
    client._stdout_log = deque(maxlen=10)
    client._stderr_log = deque(maxlen=10)
    client._window_lock = Lock()
    client._observed_windows = set()
    client._observed_windows_dropped = 0
    return client


@pytest.mark.parametrize("timeout", [math.nan, 0.0, -1.0, -0.5])
def test_request_rejects_a_nonfinite_or_nonpositive_timeout_before_any_io(
    timeout: float,
) -> None:
    transport = _RecordingTransport()
    client = _client(transport)

    with pytest.raises(XdbgRpcError) as caught:
        client.request("events.read", timeout=timeout)

    assert caught.value.code == "invalid_params"
    # The guard runs ahead of the capability check and the transport, so a bad
    # deadline never spends a frame.
    assert transport.requests == []
    assert transport.grants == []


@pytest.mark.parametrize("timeout", [1e18, math.inf])
def test_request_caps_a_huge_or_infinite_timeout_to_the_schema_ceiling(
    timeout: float,
) -> None:
    transport = _RecordingTransport()
    client = _client(transport)

    result = client.request("events.read", timeout=timeout)

    assert result == {"request_id": "1"}
    # The clamped deadline -- not the caller's astronomical one -- is what
    # becomes the transport budget, so the first I/O is granted ~300s.
    assert transport.grants, "the request must have reached the transport"
    ceiling = client_module._MAX_REQUEST_TIMEOUT_S
    assert transport.grants[0] <= ceiling
    assert transport.grants[0] > ceiling - 1.0
