"""frida.hook.template's DEVICE path must hand the client the session's OWN pids.

frida's live-process boundary has two halves in different layers. The client half
-- pinned by ``test_frida_authorization_boundary.py`` -- refuses a pid outside the
``allowed_pids`` set it is handed. That refusal is only as strong as the set the
*service* passes. ``FridaDeviceMixin._java`` (java.classes / java.methods) is
pinned to scope that set to the session's own pids by
``test_frida_service_pid_scoping.py`` -- but ``frida.hook.template`` is a SEPARATE
wiring: a different method (``AnalysisService.frida_hook_template``), in a
different file (``core/service_ext.py``), that *injects a script* into the target
rather than merely enumerating it, and it derives the target itself
(``pid = auth["pids"][-1]``, the session's most recent spawn) instead of taking a
requested pid. Its device branch hands ``hook_template_device`` both that pid and
``allowed_pids=auth.get("pids", [])`` -- the session's own authorized set.

Nothing pinned that scoping. ``test_frida_hook_template_closed_session.py`` pins
the neighbouring contracts -- a CLOSED device session is refused, an OPEN one
routes to the device method once -- but its fake ``hook_template_device`` does
``del device_id, allowed_pids`` and never inspects ``pid``, so a refactor that
handed the client an empty set, a process-wide list, or ``[pid]`` (the "authorize
what we're hooking" slip) would inject into a device process with the boundary's
service half gone, and that test would stay green. These tests close it: they
capture exactly what the service hands the client and assert the allow-set is the
session's pids (not a constant, not the echoed target) and the target is the last
spawned pid, and -- with a stub mirroring the real client's gate -- that the
handed set genuinely authorizes the handed pid, so dropping the set flips the call
from ok to ``permission_denied``.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

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


class _GatingFrida:
    """Records device/local hook calls and mirrors the real client's pid gate.

    The real ``FridaClient`` refuses a pid that is not in the ``allowed_pids`` it
    was handed (``permission_denied``). Mirroring that here means a service that
    dropped or narrowed the allow-set would surface as a refusal, exactly as an
    operator would see it -- while the recorded call still lets a test assert the
    precise set and target that were passed.
    """

    def __init__(self) -> None:
        self.device_calls: list[dict[str, Any]] = []
        self.local_calls: list[dict[str, Any]] = []

    def hook_template_device(
        self, device_id: Any, pid: int, template: str, *, allowed_pids: Any
    ) -> dict[str, Any]:
        allowed = list(allowed_pids)
        self.device_calls.append(
            {
                "device_id": device_id,
                "pid": pid,
                "template": template,
                "allowed_pids": allowed,
            }
        )
        if pid not in allowed:
            raise FridaError(
                "permission_denied",
                f"pid {pid} is not authorised for this session",
                pid=pid,
            )
        return {"pid": pid, "template": template, "loaded": True, "persisted": False}

    def hook_template(self, pid: int, template: str, *, allowed_pid: int) -> dict[str, Any]:
        self.local_calls.append({"pid": pid, "allowed_pid": allowed_pid})
        return {"pid": pid, "template": template, "loaded": True, "persisted": False}


def _device_session(
    tmp_path: Path, monkeypatch: Any, pids: list[int]
) -> tuple[AnalysisService, str, _GatingFrida]:
    stub = _GatingFrida()
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.FridaClient",
        lambda *args, **kwargs: stub,
    )
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None, created.error
    session_id = created.data["session"]["id"]
    service.registry.update_metadata(
        session_id,
        {"frida_authorized": {"device_id": "usb", "pids": list(pids), "packages": []}},
    )
    return service, session_id, stub


def test_device_hook_scopes_the_allow_set_to_the_sessions_pids_and_targets_the_last(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """hook_template_device gets the session's full pid set and its newest pid.

    The multi-pid set makes "last spawned" (3000) distinct from "first" and from
    "all", so a refactor that targeted the wrong element, or that handed a
    constant/global/echoed set instead of the session's own, fails on one of the
    two equality assertions. The local method must stay untouched -- this session
    is device-authorised, so it takes the device branch, not the PE one.
    """
    service, session_id, stub = _device_session(tmp_path, monkeypatch, [1000, 2000, 3000])
    try:
        result = service.frida_hook_template(session_id, template="noop")
        assert result.ok is True, result.error
        assert stub.local_calls == []
        assert len(stub.device_calls) == 1
        call = stub.device_calls[0]
        assert call["device_id"] == "usb"
        assert call["template"] == "noop"
        # The crux: the allow-set is the session's own pids, and the target is the
        # most recent spawn -- not the first, not an echoed/constant/global set.
        assert call["pid"] == 3000
        assert call["allowed_pids"] == [1000, 2000, 3000]
    finally:
        service.close_all()


def test_device_hook_reads_the_allow_set_from_live_session_metadata(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The set is sourced from THIS session's metadata, not a hard-coded value.

    A different session with a different authorised set must produce a different
    allow-set and target. This rules out a scoping that "happens to" match a fixed
    list: change the recorded pids and both the set and the target follow.
    """
    service, session_id, stub = _device_session(tmp_path, monkeypatch, [7777])
    try:
        result = service.frida_hook_template(session_id, template="noop")
        assert result.ok is True, result.error
        assert len(stub.device_calls) == 1
        call = stub.device_calls[0]
        assert call["pid"] == 7777
        assert call["allowed_pids"] == [7777]
    finally:
        service.close_all()
