"""The local frida probe attaches once, detaches immediately, and validates input.

frida.attach is a probe: it attaches to the session's own debuggee, confirms it
can, and detaches at once (there is no persistent session object to hand back).
The pid-scoped local ops guard their arguments before any attach -- the pid must
be the session's debuggee, module_name and size must be sane -- because these
values arrive from model arguments and an unbounded read or an attach to another
pid would be a real escape. These drive the real method bodies with an injected
fake frida module; no target process.
"""

from __future__ import annotations

import math
import time

import pytest

import headless_re_mcp.backends.frida.client as frida_client
from headless_re_mcp.backends.frida.client import (
    MAX_WORKFLOW_TIMEOUT,
    FridaClient,
    FridaError,
    _bound_timeout,
)


class _ProbeSession:
    def __init__(self) -> None:
        self.detached = False

    def detach(self) -> None:
        self.detached = True


class _ProbeFrida:
    def __init__(self) -> None:
        self.session = _ProbeSession()
        self.attached_pids: list[int] = []

    def attach(self, pid: int) -> _ProbeSession:
        self.attached_pids.append(pid)
        return self.session


def _client() -> tuple[FridaClient, _ProbeFrida]:
    client = FridaClient()
    client._available = True
    frida = _ProbeFrida()
    client._frida = frida
    return client, frida


def test_attach_probe_returns_pid_shape_and_detaches_immediately() -> None:
    """A successful probe answers pid/attached/device/note and frees the session.

    The note and the immediate detach are the contract: the reply must not imply
    a live session survives the call, so the probe tears down before returning.
    """
    client, frida = _client()
    payload = client.attach(1234, allowed_pid=1234)
    assert payload == {
        "pid": 1234,
        "attached": True,
        "device": "local",
        "note": "probe attach; detached immediately",
    }
    assert frida.attached_pids == [1234]
    assert frida.session.detached is True


def test_attach_rejects_a_non_integer_or_non_positive_pid() -> None:
    client, frida = _client()
    for bad in ("1234", 0, -5, True):
        with pytest.raises(FridaError) as info:
            client.attach(bad, allowed_pid=bad)  # type: ignore[arg-type]
        assert info.value.code == "invalid_params"
        assert "positive integer" in info.value.message
    assert frida.attached_pids == []


def test_attach_refuses_a_pid_that_is_not_the_session_debuggee() -> None:
    """The probe is limited to the one pid the session authorizes.

    Attaching to any other pid would let a web/PE session reach into an
    unrelated process, so a mismatch is permission_denied naming both pids and
    no attach is attempted.
    """
    client, frida = _client()
    with pytest.raises(FridaError) as info:
        client.attach(4321, allowed_pid=1234)
    assert info.value.code == "permission_denied"
    assert info.value.details.get("pid") == 4321
    assert info.value.details.get("allowed_pid") == 1234
    assert frida.attached_pids == []


def test_exports_requires_a_module_name() -> None:
    client, frida = _client()
    for bad in ("", "   "):
        with pytest.raises(FridaError) as info:
            client.exports(1, bad, allowed_pid=1)
        assert info.value.code == "invalid_params"
        assert "module_name is required" in info.value.message
    assert frida.attached_pids == []


def test_memory_read_bounds_the_requested_size() -> None:
    """An unbounded or non-integer size is refused before any attach.

    size drives a raw ``Memory.readByteArray``; the ceiling keeps a single read
    from being asked to pull an arbitrary span out of the target.
    """
    client, frida = _client()
    for bad in (0, -1, 256 * 1024 + 1, "16"):
        with pytest.raises(FridaError) as info:
            client.memory_read(1, 0x1000, bad, allowed_pid=1)  # type: ignore[arg-type]
        assert info.value.code == "invalid_params"
        assert "1..262144" in info.value.message
    assert frida.attached_pids == []


def test_local_ops_bound_a_wedged_rpc_and_detach(monkeypatch: pytest.MonkeyPatch) -> None:
    """A frozen target must time out each local op, not wedge the worker forever.

    _attach_local already bounds the attach, but modules/exports/memory_read then
    ran create_script/load and the exports_sync round-trip unbounded on the
    caller's thread -- and these ops drive a debuggee the session controls, a
    process that can be sitting paused at a breakpoint. The device java/hook
    paths already share _run_deadline for exactly this; the local ops now route
    their load+RPC through _script_rpc too. Drive a session whose RPC never
    returns and assert each op raises timeout and detaches (no leaked session),
    the same contract test_frida_java_perform_times_out already pins for the
    device side. The timeout is shrunk by patching the module-level _script_rpc
    (which the methods resolve at call time) because the local ops expose no
    timeout parameter.
    """
    original = frida_client._script_rpc
    monkeypatch.setattr(
        frida_client,
        "_script_rpc",
        lambda session, call, *, timeout=0.2: original(session, call, timeout=timeout),
    )

    class _HangExports:
        def modules(self, limit: int) -> dict:  # type: ignore[type-arg]
            del limit
            time.sleep(10)
            return {}

        def exports(self, name: str, count: int) -> dict:  # type: ignore[type-arg]
            del name, count
            time.sleep(10)
            return {}

        def read(self, address: int, size: int) -> list:  # type: ignore[type-arg]
            del address, size
            time.sleep(10)
            return []

    class _HangScript:
        exports_sync = _HangExports()

        def load(self) -> None:
            return None

    class _HangSession:
        def __init__(self) -> None:
            self.detached = False

        def create_script(self, source: str) -> _HangScript:
            del source
            return _HangScript()

        def detach(self) -> None:
            self.detached = True

    class _HangFrida:
        def __init__(self) -> None:
            self.session = _HangSession()

        def attach(self, pid: int) -> _HangSession:
            del pid
            return self.session

    client = FridaClient()
    client._available = True
    frida = _HangFrida()
    client._frida = frida

    ops = [
        lambda: client.modules(1, allowed_pid=1),
        lambda: client.exports(1, "libc.so", allowed_pid=1),
        lambda: client.memory_read(1, 0x1000, 16, allowed_pid=1),
    ]
    for run in ops:
        frida.session.detached = False
        started = time.monotonic()
        with pytest.raises(FridaError) as caught:
            run()
        assert time.monotonic() - started < 2.0
        assert caught.value.code == "timeout"
        assert frida.session.detached is True


def test_bound_timeout_rejects_nonpositive_and_caps_the_rest() -> None:
    assert _bound_timeout(5.0) == 5.0
    assert _bound_timeout(10**9) == MAX_WORKFLOW_TIMEOUT
    # NaN belongs on this list, not just the negatives: nan <= 0 is False, so the
    # plain guard let it through and min(nan, ceiling) stayed nan, which reaches
    # Future.result(nan) -- a non-blocking wait that returns at once and reports
    # a spurious "did not respond within nans" for a bad parameter. The MCP
    # schema's gt=0 rejects nan, but the agent transport skips the schema, which
    # is the whole reason this bound exists.
    for bad in (0.0, -1.0, math.nan):
        with pytest.raises(FridaError) as info:
            _bound_timeout(bad)
        assert info.value.code == "invalid_params"
        assert "timeout must be positive" in info.value.message
