"""The frida service must hand the client the session's OWN pids as the allow-set.

frida's live-process safety boundary has two halves that live in different layers.
The client half -- pinned by ``test_frida_authorization_boundary.py`` -- refuses a
pid that is not in the ``allowed_pids`` set it is handed. But that check is only as
strong as the set the *service* passes: ``FridaDeviceMixin._java`` hands
``java_enumerate`` the ``pids`` recorded on THIS session's ``frida_authorized``
metadata -- the pids this session itself spawned/attached -- as ``allowed_pids``.
If a refactor instead passed the requested pid (``allowed_pids=[target_pid]``, an
easy "authorize what we're targeting" slip) or a process-wide list, the client's
``pid in allowed_pids`` check would pass for any pid a caller named and the whole
boundary would be gone -- while ``test_frida_authorization_boundary.py`` kept
passing, because it drives the client in isolation with a set the test supplies.

Nothing pinned the service half. ``test_frida_spawn_closed_session.py`` pins that
spawn *records* a pid (and won't on a closed session); these tests pin that the
java tools *scope the allow-set to those recorded pids*. The stub client mirrors
the real client's gate -- refuse a pid outside ``allowed_pids`` -- and records what
the service handed it, so each test reads as the end-to-end refusal an operator
would see AND directly asserts the allow-set is the session's pids, not the
requested one. A mutation to ``allowed_pids=[target_pid]`` flips the unauthorized
call from ``permission_denied`` to ok and fails the scoping assertion at once.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.frida.client import FridaError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


def _write_minimal_pe(path: Path) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")
    path.write_bytes(image)


class _GateStub:
    """Stands in for FridaClient, mirroring the real client's pid gate.

    ``spawn`` returns a fixed pid so the service records it as authorized.
    ``java_enumerate`` records the exact ``pid`` and ``allowed_pids`` the service
    handed it, then applies the same refusal the real client does -- so a pid
    outside the set the *service* built raises ``permission_denied`` here, exactly
    as it would against real frida. The recording is what lets the tests assert the
    set is the session's pids and not the requested one.
    """

    SPAWNED_PID = 4242

    def __init__(self) -> None:
        self.java_calls: list[dict[str, Any]] = []

    def spawn(self, device_id: Any, package: str) -> dict[str, Any]:
        del device_id
        return {"package": package, "pid": self.SPAWNED_PID, "device": "usb"}

    def java_enumerate(
        self,
        device_id: Any,
        pid: int,
        *,
        allowed_pids: Any,
        mode: str,
        class_name: str | None = None,
        name_filter: str | None = None,
        limit: int = 200,
    ) -> dict[str, Any]:
        del device_id, class_name, name_filter, limit
        allowed = [int(item) for item in (allowed_pids or [])]
        self.java_calls.append({"pid": int(pid), "allowed_pids": allowed, "mode": mode})
        if int(pid) not in set(allowed):
            raise FridaError(
                "permission_denied",
                "pid is not in this session's authorized frida target set",
                pid=int(pid),
                allowed_pids=sorted(allowed),
            )
        return {"classes": [], "methods": [], "count": 0, "has_more": False}


def _service_with_authorized_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[AnalysisService, str, _GateStub]:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)

    # One shared stub across every FridaClient() the service constructs, so spawn
    # (one instance) and java_enumerate (another) record onto the same object.
    stub = _GateStub()
    monkeypatch.setattr(
        "headless_re_mcp.core.service_frida.FridaClient",
        lambda *args, **kwargs: stub,
    )

    created = service.create_session(str(binary))
    assert created.ok and created.data is not None, created.error
    session_id = created.data["session"]["id"]
    # A connected device with no spawned pids yet: the starting state every real
    # session is in right after frida.device.connect.
    service.registry.update_metadata(
        session_id,
        {"frida_authorized": {"device_id": "usb", "pids": [], "packages": []}},
    )
    return service, session_id, stub


def test_java_before_any_spawn_is_refused_without_ever_touching_the_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With no spawned pid, the java tools stop at the service, not the device.

    ``_last_pid`` raises ``invalid_state`` when the session has authorized nothing
    yet, so ``java_enumerate`` is never called -- the backend does not resolve a
    device or attach for a session that has not spawned. If this instead reached
    the client with an empty ``allowed_pids`` it would be a device touch on an
    unprivileged session; the empty ``java_calls`` pins that it does not.
    """
    service, session_id, stub = _service_with_authorized_session(tmp_path, monkeypatch)
    try:
        result = service.frida_java_classes(session_id, pid=0)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_state"
        assert stub.java_calls == []
    finally:
        service.close_all()


def test_java_scopes_the_allow_set_to_the_sessions_spawned_pid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The allow-set handed to the client is the session's pids, not the request.

    After spawning pid 4242, a default (pid=0) java call targets that pid and is
    allowed. A call naming a pid the session never spawned (5555) is refused --
    and, the crux, the ``allowed_pids`` the service handed the client on that
    refused call is still ``[4242]``, the session's own set, not ``[5555]``. A
    refactor that echoed the requested pid into the allow-set would make 5555
    "authorized" and flip this to ok; a process-wide list would do the same.
    """
    service, session_id, stub = _service_with_authorized_session(tmp_path, monkeypatch)
    try:
        spawned = service.frida_spawn(session_id, "com.example.app")
        assert spawned.ok is True, spawned.error

        allowed = service.frida_java_classes(session_id, pid=0)
        assert allowed.ok is True, allowed.error
        assert stub.java_calls[-1]["pid"] == _GateStub.SPAWNED_PID
        assert stub.java_calls[-1]["allowed_pids"] == [_GateStub.SPAWNED_PID]

        refused = service.frida_java_classes(session_id, pid=5555)
        assert refused.ok is False
        assert refused.error is not None
        assert refused.error.code == "permission_denied"
        # The service scoped the allow-set to the session's pid; it did not echo
        # the requested 5555 into it. This is the assertion the bypass fails.
        assert stub.java_calls[-1]["pid"] == 5555
        assert stub.java_calls[-1]["allowed_pids"] == [_GateStub.SPAWNED_PID]
    finally:
        service.close_all()


def test_java_methods_shares_the_same_scoped_gate_as_classes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both java entry points funnel through ``_java``; pin methods too.

    ``frida_java_methods`` is the other caller of ``_java``, so it must scope the
    allow-set identically. An unauthorized pid is refused here as well, with the
    session's pid -- not the requested one -- recorded as the set that was checked.
    """
    service, session_id, stub = _service_with_authorized_session(tmp_path, monkeypatch)
    try:
        spawned = service.frida_spawn(session_id, "com.example.app")
        assert spawned.ok is True, spawned.error

        refused = service.frida_java_methods(
            session_id, "com.example.Foo", pid=5555
        )
        assert refused.ok is False
        assert refused.error is not None
        assert refused.error.code == "permission_denied"
        assert stub.java_calls[-1]["mode"] == "methods"
        assert stub.java_calls[-1]["allowed_pids"] == [_GateStub.SPAWNED_PID]
    finally:
        service.close_all()
