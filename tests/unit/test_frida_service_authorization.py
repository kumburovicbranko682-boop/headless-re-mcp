"""Service-level frida authorization: the boundary that ties a session's
connected device and its spawned-pid allow-set to the client's per-pid check.

The client enforces ``permission_denied`` for a pid outside ``allowed_pids``
(test_android_backends.py) and the connect payload shape is covered
(test_frida_fields.py), but nothing drove the whole model through
``AnalysisService``: that a device-aware tool refuses before a device is
connected, that ``frida.spawn`` is what puts a pid into the session's allow-set,
that ``frida.java.*`` may only touch a pid this session produced, and that one
session's authorization never reaches another. Those are the invariants that
keep a device-aware session from touching a process it never launched, and they
are decided in the service layer from session metadata -- no hardware, so a
device-less VM can prove them deterministically with a stub frida device.

It also pins the two connect branches that decide whether a device is ever
bound to a session: a remote endpoint resolves through a different client call
than a USB alias, and connect re-checks the session after the device work so a
session that closed mid-resolve is never recorded as holding a device.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.frida.client import FridaClient
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


class _App:
    def __init__(self, index: int) -> None:
        self.identifier = f"com.app{index}"
        self.name = f"App{index}"
        self.pid = 0


class _JavaApi:
    def classes(self, name_filter: str, count: int) -> list[str]:
        del name_filter
        return [f"c{index}" for index in range(min(int(count), 3))]

    def methods(self, class_name: str, count: int) -> list[str]:
        del class_name
        return [f"m{index}" for index in range(min(int(count), 3))]


class _Script:
    exports_sync = _JavaApi()

    def load(self) -> None:
        return None


class _Session:
    def create_script(self, source: str) -> _Script:
        del source
        return _Script()

    def detach(self) -> None:
        return None


class _FakeDevice:
    """A frida device that answers structurally, so the real client logic runs."""

    def __init__(self, ident: str, spawn_pid: int) -> None:
        self.id = ident
        self.name = "Emulator"
        self.type = "usb"
        self._spawn_pid = spawn_pid

    def enumerate_applications(self) -> list[_App]:
        return [_App(index) for index in range(2)]

    def spawn(self, package: str, timeout: float | None = None) -> int:
        del package, timeout
        return self._spawn_pid

    def resume(self, pid: int, timeout: float | None = None) -> None:
        del pid, timeout

    def kill(self, pid: int) -> None:
        del pid

    def attach(self, pid: int, timeout: float | None = None) -> _Session:
        del pid, timeout
        return _Session()


def _stub_client_factory(ident: str, spawn_pid: int) -> Any:
    """A real FridaClient with a stub device, so _authorize and java_enumerate
    run their true code paths without any hardware or the frida module."""

    device = _FakeDevice(ident, spawn_pid)

    class _StubClient(FridaClient):
        def __init__(self) -> None:
            super().__init__()
            # The device resolution is stubbed below, so mark the module present
            # and let the genuine authorize/spawn/enumerate logic execute.
            self._available = True
            self._frida = object()

        def _resolve_device(self, device_id: str | None) -> Any:
            del device_id
            return device

        def add_remote_device(self, endpoint: str) -> dict[str, str]:
            # The remote path resolves through the device manager, not
            # get_usb_device; answer with the endpoint as the id, as frida does.
            return {"id": endpoint, "name": "remote", "type": "remote"}

    return _StubClient


def _service(tmp_path: Path) -> AnalysisService:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    return AnalysisService(settings)


def _web_session(service: AnalysisService) -> str:
    created = service.create_session("https://example.invalid/app", target="web")
    assert created.ok and created.data is not None, created.error
    session = created.data["session"]
    assert isinstance(session, dict)
    return str(session["id"])


def test_frida_device_tools_refuse_before_a_device_is_connected(tmp_path: Path) -> None:
    """A session that never connected a device must not reach one.

    Every device-aware tool reads the session's authorization first, so the
    refusal is a session-state decision made before any client is built --
    invalid_state, naming the connect step, not a bare backend failure the
    caller cannot act on.
    """
    service = _service(tmp_path)
    try:
        session_id = _web_session(service)

        for result in (
            service.frida_applications(session_id),
            service.frida_spawn(session_id, "com.example.app"),
            service.frida_java_classes(session_id),
            service.frida_java_methods(session_id, "java.lang.String"),
        ):
            assert result.ok is False
            assert result.error is not None
            assert result.error.code == "invalid_state", result.error
            assert "connect" in result.error.message.lower()
    finally:
        service.close_all()


def test_frida_authorizes_only_pids_this_session_spawned(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """spawn is what grants a pid; java.* on any other pid is refused.

    The service threads the session's spawned-pid set into the client's
    allow-set. Enumerating the spawned pid works; a pid this session never
    produced comes back permission_denied with the allow-set named, which is
    the boundary that stops a device-aware session from reading a process it
    did not launch.
    """
    monkeypatch.setattr(
        "headless_re_mcp.core.service_frida.FridaClient",
        _stub_client_factory("emulator-5554", spawn_pid=4242),
    )
    service = _service(tmp_path)
    try:
        session_id = _web_session(service)

        connected = service.frida_device_connect(session_id, device_id="usb")
        assert connected.ok and connected.data is not None, connected.error
        assert connected.data["device"]["id"] == "emulator-5554"
        auth = service.registry.get(session_id).metadata["frida_authorized"]
        assert auth["pids"] == []

        spawned = service.frida_spawn(session_id, "com.example.app")
        assert spawned.ok and spawned.data is not None, spawned.error
        assert spawned.data["pid"] == 4242
        auth = service.registry.get(session_id).metadata["frida_authorized"]
        assert auth["pids"] == [4242]
        assert auth["packages"] == ["com.example.app"]

        # Explicit authorized pid, and the default (most-recent) pid, both work.
        explicit = service.frida_java_classes(session_id, pid=4242)
        assert explicit.ok and explicit.data is not None, explicit.error
        assert explicit.data["classes"] == ["c0", "c1", "c2"]
        default_pid = service.frida_java_methods(session_id, "java.lang.String")
        assert default_pid.ok and default_pid.data is not None, default_pid.error
        assert default_pid.data["methods"] == ["m0", "m1", "m2"]

        # A pid this session never spawned is refused, before any device work.
        for refused in (
            service.frida_java_classes(session_id, pid=9999),
            service.frida_java_methods(session_id, "java.lang.String", pid=9999),
        ):
            assert refused.ok is False
            assert refused.error is not None
            assert refused.error.code == "permission_denied", refused.error
            assert refused.error.details["pid"] == 9999
            assert refused.error.details["allowed_pids"] == [4242]

        timeline = service.timeline_list(session_id)
        assert timeline.ok and timeline.data is not None, timeline.error
        events = {entry.get("event") for entry in timeline.data["events"]}
        assert "frida.device.connect" in events
        assert "frida.spawn" in events
    finally:
        service.close_all()


def test_frida_authorization_does_not_leak_across_sessions(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """One session's spawned pid is invisible to another.

    The allow-set lives in each session's own metadata, so a pid the first
    session launched must be permission_denied for a second session that
    connected its own device and spawned its own process.
    """
    factories = iter(
        (
            _stub_client_factory("emulator-5554", spawn_pid=100),
            _stub_client_factory("emulator-5556", spawn_pid=200),
        )
    )
    # Each session builds its client through the module symbol; hand out a
    # distinct stub device per session so their pids cannot coincide.
    current: dict[str, Any] = {}

    def _next_factory() -> Any:
        return current["factory"]()

    monkeypatch.setattr(
        "headless_re_mcp.core.service_frida.FridaClient",
        lambda: _next_factory(),
    )
    service = _service(tmp_path)
    try:
        first = _web_session(service)
        current["factory"] = next(factories)
        assert service.frida_device_connect(first, device_id="usb").ok
        assert service.frida_spawn(first, "com.first.app").ok

        second = _web_session(service)
        current["factory"] = next(factories)
        assert service.frida_device_connect(second, device_id="usb").ok
        assert service.frida_spawn(second, "com.second.app").ok

        # The second session cannot reach the first session's pid.
        cross = service.frida_java_classes(second, pid=100)
        assert cross.ok is False
        assert cross.error is not None
        assert cross.error.code == "permission_denied", cross.error
        assert cross.error.details["allowed_pids"] == [200]

        # And its own pid still works.
        own = service.frida_java_classes(second, pid=200)
        assert own.ok and own.data is not None, own.error
        assert own.data["classes"] == ["c0", "c1", "c2"]
    finally:
        service.close_all()


def test_frida_device_tools_refuse_a_closed_session(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """After close, a retained session must not enumerate or spawn.

    connect/server.ensure already fail closed (test_frida_closed_session.py);
    the enumeration and spawn tools must too, so a dead session cannot be made
    to touch a device it no longer owns.
    """
    monkeypatch.setattr(
        "headless_re_mcp.core.service_frida.FridaClient",
        _stub_client_factory("emulator-5554", spawn_pid=4242),
    )
    service = _service(tmp_path)
    try:
        session_id = _web_session(service)
        assert service.frida_device_connect(session_id, device_id="usb").ok
        assert service.frida_spawn(session_id, "com.example.app").ok
        assert service.close_session(session_id).ok

        for result in (
            service.frida_applications(session_id),
            service.frida_spawn(session_id, "com.example.app"),
            service.frida_java_classes(session_id, pid=4242),
            service.frida_java_methods(session_id, "java.lang.String", pid=4242),
        ):
            assert result.ok is False
            assert result.error is not None
            assert result.error.code == "invalid_request", result.error
            assert "closed" in result.error.message
    finally:
        service.close_all()


def test_frida_hook_template_on_a_closed_device_session_does_not_inject(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A retained CLOSED device session must not have a hook injected.

    frida.hook.template routes a device-connected session to
    hook_template_device using the last authorized pid. close_session does not
    clear frida_authorized, so without an open-session check the device branch
    would inject a probe on a device a dead session no longer owns -- the same
    fail-closed violation the connect/server.ensure guards prevent.
    """
    factory = _stub_client_factory("emulator-5554", spawn_pid=4242)
    monkeypatch.setattr(
        "headless_re_mcp.core.service_frida.FridaClient", factory
    )
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.FridaClient", factory
    )
    service = _service(tmp_path)
    try:
        session_id = _web_session(service)
        assert service.frida_device_connect(session_id, device_id="usb").ok
        assert service.frida_spawn(session_id, "com.example.app").ok
        assert service.close_session(session_id).ok

        result = service.frida_hook_template(session_id, "noop")
        assert result.ok is False, result.data
        assert result.error is not None
        assert result.error.code == "invalid_request", result.error
        assert "closed" in result.error.message
    finally:
        service.close_all()


def test_frida_hook_template_targets_the_device_pid_and_refuses_unknown_names(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """On a device session, hook.template routes to the device's authorized pid.

    The dispatch picks hook_template_device with the last spawned pid (not a
    local debuggee) and returns the probe disclosure, so the reply says nothing
    stays hooked. An unknown template is refused with the allowed list, the same
    contract the client enforces.
    """
    factory = _stub_client_factory("emulator-5554", spawn_pid=4242)
    monkeypatch.setattr(
        "headless_re_mcp.core.service_frida.FridaClient", factory
    )
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.FridaClient", factory
    )
    service = _service(tmp_path)
    try:
        session_id = _web_session(service)
        assert service.frida_device_connect(session_id, device_id="usb").ok
        assert service.frida_spawn(session_id, "com.example.app").ok

        hooked = service.frida_hook_template(session_id, "noop")
        assert hooked.ok and hooked.data is not None, hooked.error
        assert hooked.data["loaded"] is True
        assert hooked.data["pid"] == 4242
        assert hooked.data["device"] == "emulator-5554"
        assert hooked.data["persisted"] is False

        unknown = service.frida_hook_template(session_id, "totally-made-up")
        assert unknown.ok is False
        assert unknown.error is not None
        assert unknown.error.code == "invalid_params", unknown.error
        assert "android_ssl_unpin" in unknown.error.details["allowed"]
    finally:
        service.close_all()


def test_frida_remote_endpoint_connect_binds_that_device_and_still_gates_pids(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A remote endpoint resolves through a different client call than usb.

    connect over an endpoint records the resolved remote id as the session's
    device and the same allow-set rule then applies: spawn grants a pid over
    that remote device, and a pid this session never spawned is refused.
    """
    monkeypatch.setattr(
        "headless_re_mcp.core.service_frida.FridaClient",
        _stub_client_factory("10.0.0.5:27042", spawn_pid=555),
    )
    service = _service(tmp_path)
    try:
        session_id = _web_session(service)

        connected = service.frida_device_connect(
            session_id, endpoint="10.0.0.5:27042"
        )
        assert connected.ok and connected.data is not None, connected.error
        assert connected.data["device"]["id"] == "10.0.0.5:27042"
        assert connected.data["device"]["type"] == "remote"
        auth = service.registry.get(session_id).metadata["frida_authorized"]
        assert auth["device_id"] == "10.0.0.5:27042"

        spawned = service.frida_spawn(session_id, "com.remote.app")
        assert spawned.ok and spawned.data is not None, spawned.error
        assert spawned.data["pid"] == 555

        allowed = service.frida_java_classes(session_id, pid=555)
        assert allowed.ok and allowed.data is not None, allowed.error
        refused = service.frida_java_classes(session_id, pid=1)
        assert refused.ok is False
        assert refused.error is not None
        assert refused.error.code == "permission_denied", refused.error
        assert refused.error.details["allowed_pids"] == [555]
    finally:
        service.close_all()


def test_frida_connect_does_not_bind_if_the_session_closes_mid_resolve(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A close during device resolution must not leave a dead session bound.

    connect re-checks the session after resolving the device, before it writes
    frida_authorized. Without that re-check a session that closed while the USB
    device was being resolved would still be recorded as holding a device, and
    the model would follow with spawn on a session nothing can service. This is
    the connect-path twin of the frida.server.ensure mid-run guard.
    """
    service = _service(tmp_path)
    session_id = ""

    class _CloseThenResolve:
        def _resolve_device(self, device_id: str | None) -> Any:
            del device_id
            # The device came back, but the session closed while we waited.
            service.close_session(session_id)

            class _Device:
                id = "ABCD1234"
                name = "Pixel"
                type = "usb"

            return _Device()

    monkeypatch.setattr(
        "headless_re_mcp.core.service_frida.FridaClient",
        lambda *args, **kwargs: _CloseThenResolve(),
    )
    try:
        session_id = _web_session(service)
        result = service.frida_device_connect(session_id, device_id="usb")

        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request", result.error
        assert "closed" in result.error.message
        assert "frida_authorized" not in service.registry.get(session_id).metadata
    finally:
        service.close_all()
