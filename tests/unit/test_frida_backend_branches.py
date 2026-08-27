"""Frida backend guard, degradation, and honesty branches.

The live device paths (attach to a real ART process, enumerate loaded classes)
are exercised by ``tests/integration/test_m11_frida_live_gate.py`` and only run on
a machine with a device + frida-server. Everything here is the reverse: the
argument checks, deadline bounds, and error envelopes that must hold whether or
not a device is present. They drive the client through fakes so the branches
that decide *what the caller is told* -- not-found vs backend_error vs timeout,
"nothing stays hooked", "this pid is not authorized" -- run on every machine.
"""

from __future__ import annotations

from typing import Any

import pytest

from headless_re_mcp.backends.frida import client as frida_client
from headless_re_mcp.backends.frida.client import (
    FridaClient,
    FridaError,
    _accepts_timeout,
    _bound_timeout,
    _invoke,
    _is_timeout,
    _page,
    _run_deadline,
)
from headless_re_mcp.core.limits import MAX_WORKFLOW_TIMEOUT


class _Timeoutish(Exception):
    """An exception whose name trips the duck-typed timeout classifier."""

    def __init__(self) -> None:
        super().__init__("operation timed out")


def _timeout_exc() -> Exception:
    # frida raises frida.TimedError / concurrent TimeoutError; _is_timeout keys
    # off the name/text rather than a specific type, so a stand-in is faithful.
    return _Timeoutish()


class _Exports:
    """Stands in for ``script.exports_sync`` -- the RPC surface of the agent."""

    def __init__(self, payloads: dict[str, Any]) -> None:
        self._payloads = payloads

    def modules(self, cap: int) -> Any:
        return self._payloads["modules"]

    def exports(self, module_name: str, cap: int) -> Any:
        return self._payloads["exports"]

    def read(self, address: int, size: int) -> Any:
        return self._payloads["read"]

    def classes(self, name_filter: str, cap: int) -> Any:
        return self._payloads["classes"]

    def methods(self, class_name: str, cap: int) -> Any:
        return self._payloads["methods"]


class _Script:
    def __init__(self, payloads: dict[str, Any], *, load_error: BaseException | None) -> None:
        self.exports_sync = _Exports(payloads)
        self._load_error = load_error
        self.loaded = False
        self.destroyed = False

    def load(self) -> None:
        if self._load_error is not None:
            raise self._load_error
        self.loaded = True


class _Session:
    def __init__(
        self,
        payloads: dict[str, Any],
        *,
        create_error: BaseException | None,
        load_error: BaseException | None,
    ) -> None:
        self._payloads = payloads
        self._create_error = create_error
        self._load_error = load_error
        self.script: _Script | None = None
        self.detached = False

    def create_script(self, source: str) -> _Script:
        assert source
        if self._create_error is not None:
            raise self._create_error
        self.script = _Script(self._payloads, load_error=self._load_error)
        return self.script

    def detach(self) -> None:
        self.detached = True
        if self.script is not None:
            self.script.destroyed = True


class _App:
    def __init__(self, identifier: str, name: str, pid: int) -> None:
        self.identifier = identifier
        self.name = name
        self.pid = pid


class _DeviceInfo:
    def __init__(self, id_: str, name: str, type_: str) -> None:
        self.id = id_
        self.name = name
        self.type = type_


class _Device:
    """A frida device that never touches USB. Behavior is injected per test."""

    def __init__(
        self,
        *,
        payloads: dict[str, Any] | None = None,
        attach_error: BaseException | None = None,
        create_error: BaseException | None = None,
        load_error: BaseException | None = None,
        spawn_error: BaseException | None = None,
        resume_error: BaseException | None = None,
        apps_error: BaseException | None = None,
        apps: list[_App] | None = None,
    ) -> None:
        self._payloads = payloads or {}
        self._attach_error = attach_error
        self._create_error = create_error
        self._load_error = load_error
        self._spawn_error = spawn_error
        self._resume_error = resume_error
        self._apps_error = apps_error
        self._apps = apps or []
        self.killed: list[int] = []
        self.resumed: list[int] = []
        self.sessions: list[_Session] = []

    def attach(self, pid: int) -> _Session:
        if self._attach_error is not None:
            raise self._attach_error
        session = _Session(
            self._payloads, create_error=self._create_error, load_error=self._load_error
        )
        self.sessions.append(session)
        return session

    # ``timeout`` in the signature is what makes _invoke forward the deadline.
    def spawn(self, package: str, timeout: float | None = None) -> int:
        if self._spawn_error is not None:
            raise self._spawn_error
        return 5150

    def resume(self, pid: int, timeout: float | None = None) -> None:
        if self._resume_error is not None:
            raise self._resume_error
        self.resumed.append(pid)

    def kill(self, pid: int) -> None:
        self.killed.append(pid)

    def enumerate_applications(self) -> list[_App]:
        if self._apps_error is not None:
            raise self._apps_error
        return self._apps


class _DeviceManager:
    def __init__(self, *, get_error: bool, add_error: bool) -> None:
        self._get_error = get_error
        self._add_error = add_error
        self.device = _DeviceInfo("tcp@1.2.3.4:27042", "remote", "remote")

    def get_device(self, endpoint: str, timeout: float | None = None) -> _DeviceInfo:
        if self._get_error:
            raise RuntimeError("no such device")
        return self.device

    def add_remote_device(self, endpoint: str) -> _DeviceInfo:
        if self._add_error:
            raise RuntimeError("cannot reach endpoint")
        return self.device


class _Frida:
    def __init__(
        self,
        *,
        device: _Device | None = None,
        local_error: BaseException | None = None,
        enumerate_error: BaseException | None = None,
        devices: list[_DeviceInfo] | None = None,
        manager: _DeviceManager | None = None,
    ) -> None:
        self._device = device or _Device()
        self._local_error = local_error
        self._enumerate_error = enumerate_error
        self._devices = devices if devices is not None else []
        self._manager = manager

    def attach(self, pid: int) -> _Session:
        return self._device.attach(pid)

    def get_local_device(self) -> _Device:
        if self._local_error is not None:
            raise self._local_error
        return self._device

    def get_usb_device(self, timeout: float | None = None) -> _Device:
        return self._device

    def get_device(self, device_id: str, timeout: float | None = None) -> _Device:
        return self._device

    def get_device_manager(self) -> _DeviceManager:
        assert self._manager is not None
        return self._manager

    def enumerate_devices(self) -> list[_DeviceInfo]:
        if self._enumerate_error is not None:
            raise self._enumerate_error
        return self._devices


def _client(frida: _Frida) -> FridaClient:
    client = FridaClient()
    client._frida = frida
    client._available = True
    return client


# ----------------------------------------------------------------------------
# Small pure helpers
# ----------------------------------------------------------------------------
class TestHelpers:
    def test_accepts_timeout_reads_the_signature(self) -> None:
        assert _accepts_timeout(lambda a, timeout=1: a) is True
        assert _accepts_timeout(lambda a: a) is False
        # A builtin with no introspectable signature must fall back to False,
        # not blow up trying to forward a deadline into **kwargs.
        assert _accepts_timeout(range) is False

    def test_invoke_forwards_the_deadline_only_when_named(self) -> None:
        seen: dict[str, Any] = {}

        def named(value: int, timeout: float | None = None) -> int:
            seen["timeout"] = timeout
            return value

        def unnamed(value: int, **kw: Any) -> int:
            seen["kw"] = kw
            return value

        assert _invoke(named, 7, timeout=3.5) == 7
        assert seen["timeout"] == 3.5
        assert _invoke(unnamed, 9, timeout=3.5) == 9
        assert seen["kw"] == {}

    def test_bound_timeout_rejects_nonpositive_and_clamps_high(self) -> None:
        with pytest.raises(FridaError) as info:
            _bound_timeout(0)
        assert info.value.code == "invalid_params"
        with pytest.raises(FridaError):
            _bound_timeout(-1)
        assert _bound_timeout(MAX_WORKFLOW_TIMEOUT * 10) == MAX_WORKFLOW_TIMEOUT

    def test_is_timeout_matches_name_or_text(self) -> None:
        assert _is_timeout(_Timeoutish()) is True
        assert _is_timeout(TimeoutError()) is True
        assert _is_timeout(ValueError("nope")) is False

    def test_run_deadline_fires_on_timeout_callback(self) -> None:
        fired: list[str] = []

        def work() -> int:
            import time

            time.sleep(5)
            return 1

        with pytest.raises(FridaError) as info:
            _run_deadline(work, timeout=0.05, on_timeout=lambda: fired.append("x"))
        assert info.value.code == "timeout"
        assert fired == ["x"]

    def test_run_deadline_propagates_work_exception(self) -> None:
        def work() -> int:
            raise ValueError("boom")

        with pytest.raises(ValueError):
            _run_deadline(work, timeout=5)


# ----------------------------------------------------------------------------
# Availability / import degradation
# ----------------------------------------------------------------------------
class TestCapabilityUnavailable:
    def test_missing_module_degrades_not_crashes(self) -> None:
        client = FridaClient()
        client._frida = None
        client._available = False
        for call in (
            lambda: client.attach(1, allowed_pid=1),
            lambda: client.enumerate_devices(),
            lambda: client.applications("local"),
        ):
            with pytest.raises(FridaError) as info:
                call()
            assert info.value.code == "capability_unavailable"

    def test_require_reports_unavailable_even_for_allowed_pid(self) -> None:
        client = FridaClient()
        client._frida = None
        client._available = False
        with pytest.raises(FridaError) as info:
            client.modules(7, allowed_pid=7, limit=1)
        assert info.value.code == "capability_unavailable"

    def test_authorize_flags_bad_pid_and_missing_module(self) -> None:
        client = FridaClient()
        client._frida = None
        client._available = False
        with pytest.raises(FridaError) as info:
            client.java_enumerate("local", 5, allowed_pids=[5], mode="classes")
        assert info.value.code == "capability_unavailable"

        client._frida = _Frida()
        client._available = True
        with pytest.raises(FridaError) as info:
            client.java_enumerate("local", 0, allowed_pids=[0], mode="classes")
        assert info.value.code == "invalid_params"


# ----------------------------------------------------------------------------
# Local (single-pid) attach + enumeration happy/error paths
# ----------------------------------------------------------------------------
class TestLocalAttach:
    def test_attach_guards_then_succeeds(self) -> None:
        client = _client(_Frida())
        with pytest.raises(FridaError) as bad_pid:
            client.attach(0, allowed_pid=0)
        assert bad_pid.value.code == "invalid_params"
        with pytest.raises(FridaError) as denied:
            client.attach(10, allowed_pid=11)
        assert denied.value.code == "permission_denied"

        payload = client.attach(4242, allowed_pid=4242)
        assert payload == {
            "pid": 4242,
            "attached": True,
            "device": "local",
            "note": "probe attach; detached immediately",
        }

    def test_attach_failure_becomes_backend_error(self) -> None:
        client = _client(_Frida(device=_Device(attach_error=RuntimeError("denied by kernel"))))
        with pytest.raises(FridaError) as info:
            client.attach(4242, allowed_pid=4242)
        assert info.value.code == "backend_error"
        assert info.value.details["pid"] == 4242

    def test_attach_timeout_is_labelled_timeout(self) -> None:
        client = _client(_Frida(device=_Device(attach_error=_timeout_exc())))
        with pytest.raises(FridaError) as info:
            client.attach(4242, allowed_pid=4242)
        assert info.value.code == "timeout"

    def test_modules_handles_dict_and_bare_list(self) -> None:
        dict_payload = {
            "modules": [{"name": "libc.so", "base": "0x1", "size": 10, "path": "/x"}],
            "total": 3,
        }
        client = _client(_Frida(device=_Device(payloads={"modules": dict_payload})))
        result = client.modules(9, allowed_pid=9, limit=1)
        assert result["count"] == 1
        assert result["total"] == 3
        assert result["has_more"] is True

        bare = [{"name": "a", "base": "0", "size": 0, "path": ""}]
        client = _client(_Frida(device=_Device(payloads={"modules": bare})))
        result = client.modules(9, allowed_pid=9, limit=8)
        assert result["total"] == 1
        assert result["has_more"] is False

    def test_exports_requires_module_name(self) -> None:
        client = _client(_Frida(device=_Device(payloads={"exports": {}})))
        with pytest.raises(FridaError) as info:
            client.exports(9, "   ", allowed_pid=9)
        assert info.value.code == "invalid_params"

    def test_exports_rejects_non_dict_payload(self) -> None:
        client = _client(_Frida(device=_Device(payloads={"exports": ["not", "a", "dict"]})))
        with pytest.raises(FridaError) as info:
            client.exports(9, "libc.so", allowed_pid=9)
        assert info.value.code == "backend_error"

    def test_exports_pages_and_skips_malformed_rows(self) -> None:
        # A non-dict row sits *inside* the returned page so the drop branch runs,
        # not merely past the cap where it would be sliced off anyway.
        rows: list[Any] = [{"name": "e0", "address": "0x0", "type": "func"}]
        rows.append("garbage")
        rows.append({"name": "e1", "address": "0x8", "type": "func"})
        payload = {"found": True, "module": "libc.so", "base": "0x1000", "exports": rows}
        client = _client(_Frida(device=_Device(payloads={"exports": payload})))
        result = client.exports(9, "libc.so", allowed_pid=9, limit=8)
        assert result["found"] is True
        assert result["count"] == 2
        assert [row["name"] for row in result["exports"]] == ["e0", "e1"]
        assert result["has_more"] is False

    def test_memory_read_size_bounds_then_hexes(self) -> None:
        client = _client(_Frida(device=_Device(payloads={"read": [0xDE, 0xAD]})))
        with pytest.raises(FridaError) as info:
            client.memory_read(9, 0x1000, 0, allowed_pid=9)
        assert info.value.code == "invalid_params"
        result = client.memory_read(9, 0x1000, 2, allowed_pid=9)
        assert result["data"] == "dead"
        assert result["encoding"] == "hex"

    def test_attach_local_backend_error_flows_through_modules(self) -> None:
        client = _client(_Frida(device=_Device(attach_error=RuntimeError("no ptrace"))))
        with pytest.raises(FridaError) as info:
            client.modules(9, allowed_pid=9)
        assert info.value.code == "backend_error"

    def test_attach_local_timeout_flows_through_modules(self) -> None:
        client = _client(_Frida(device=_Device(attach_error=_timeout_exc())))
        with pytest.raises(FridaError) as info:
            client.modules(9, allowed_pid=9)
        assert info.value.code == "timeout"


# ----------------------------------------------------------------------------
# hook_template (local): unknown template + failure classification
# ----------------------------------------------------------------------------
class TestLocalHookTemplate:
    def test_unknown_template_lists_the_allowed_set(self) -> None:
        client = _client(_Frida())
        with pytest.raises(FridaError) as info:
            client.hook_template(9, "totally-made-up", allowed_pid=9)
        assert info.value.code == "invalid_params"
        assert "android_ssl_unpin" in info.value.details["allowed"]

    def test_a_clean_probe_reports_loaded_and_detaches(self) -> None:
        # The one local-probe success path: attach, create, load, then the
        # finally detaches. It must report loaded with the "nothing persists"
        # disclosure, the same honesty the device variant carries.
        device = _Device()
        client = _client(_Frida(device=device))
        result = client.hook_template(9, "noop", allowed_pid=9)
        assert result["loaded"] is True
        assert result["pid"] == 9
        assert result["template"] == "noop"
        assert device.sessions[0].detached is True

    def test_a_pid_outside_the_allow_set_is_denied(self) -> None:
        # _require rejects a mismatch before it ever reaches a device, so an
        # agent cannot probe a process the session was not authorized for.
        client = _client(_Frida())
        with pytest.raises(FridaError) as info:
            client.hook_template(9, "noop", allowed_pid=8)
        assert info.value.code == "permission_denied"
        assert info.value.details["pid"] == 9

    def test_load_failure_propagates_as_backend_error(self) -> None:
        client = _client(_Frida(device=_Device(load_error=RuntimeError("not an ART process"))))
        with pytest.raises(RuntimeError):
            client.hook_template(9, "android_ssl_unpin", allowed_pid=9)

    def test_load_timeout_is_labelled_timeout_and_detaches(self) -> None:
        device = _Device(load_error=_timeout_exc())
        client = _client(_Frida(device=device))
        with pytest.raises(FridaError) as info:
            client.hook_template(9, "noop", allowed_pid=9)
        assert info.value.code == "timeout"
        assert device.sessions[0].detached is True

    def test_frida_error_from_work_is_reraised_unchanged(self) -> None:
        boom = FridaError("backend_error", "explicit")
        client = _client(_Frida(device=_Device(create_error=boom)))
        with pytest.raises(FridaError) as info:
            client.hook_template(9, "noop", allowed_pid=9)
        assert info.value is boom


# ----------------------------------------------------------------------------
# Device resolution
# ----------------------------------------------------------------------------
class TestResolveDevice:
    def test_local_usb_and_named_devices_resolve(self) -> None:
        client = _client(_Frida())
        for device_id in (None, "", "local", "usb", "some-serial"):
            assert client._resolve_device(device_id) is not None

    def test_remote_endpoint_prefers_existing_registration(self) -> None:
        mgr = _DeviceManager(get_error=False, add_error=False)
        client = _client(_Frida(manager=mgr))
        assert client._resolve_device("1.2.3.4:27042") is mgr.device

    def test_remote_endpoint_falls_back_to_add(self) -> None:
        mgr = _DeviceManager(get_error=True, add_error=False)
        client = _client(_Frida(manager=mgr))
        assert client._resolve_device("1.2.3.4:27042") is mgr.device

    def test_unreachable_device_is_not_found(self) -> None:
        client = _client(_Frida(local_error=RuntimeError("no local device")))
        with pytest.raises(FridaError) as info:
            client._resolve_device("local")
        assert info.value.code == "not_found"
        assert info.value.details["device_id"] == "local"


# ----------------------------------------------------------------------------
# enumerate_devices / add_remote_device / applications
# ----------------------------------------------------------------------------
class TestDeviceEnumeration:
    def test_enumerate_devices_shapes_rows(self) -> None:
        devices = [_DeviceInfo("local", "Local System", "local")]
        client = _client(_Frida(devices=devices))
        result = client.enumerate_devices()
        assert result["count"] == 1
        assert result["devices"][0] == {"id": "local", "name": "Local System", "type": "local"}

    def test_enumerate_devices_failure_is_backend_error(self) -> None:
        client = _client(_Frida(enumerate_error=RuntimeError("frida-core died")))
        with pytest.raises(FridaError) as info:
            client.enumerate_devices()
        assert info.value.code == "backend_error"

    def test_add_remote_device_reuses_then_shapes(self) -> None:
        mgr = _DeviceManager(get_error=False, add_error=False)
        client = _client(_Frida(manager=mgr))
        result = client.add_remote_device("1.2.3.4:27042")
        assert result["type"] == "remote"

    def test_add_remote_device_failure_is_backend_error(self) -> None:
        mgr = _DeviceManager(get_error=True, add_error=True)
        client = _client(_Frida(manager=mgr))
        with pytest.raises(FridaError) as info:
            client.add_remote_device("1.2.3.4:27042")
        assert info.value.code == "backend_error"
        assert info.value.details["endpoint"] == "1.2.3.4:27042"

    def test_applications_pages_and_totals(self) -> None:
        apps = [_App(f"com.app{i}", f"App{i}", i + 100) for i in range(3)]
        client = _client(_Frida(device=_Device(apps=apps)))
        result = client.applications("local", limit=2)
        assert result["count"] == 2
        assert result["total"] == 3
        assert result["has_more"] is True

    def test_applications_failure_is_backend_error(self) -> None:
        client = _client(_Frida(device=_Device(apps_error=RuntimeError("enum failed"))))
        with pytest.raises(FridaError) as info:
            client.applications("local")
        assert info.value.code == "backend_error"


# ----------------------------------------------------------------------------
# spawn
# ----------------------------------------------------------------------------
class TestSpawn:
    def test_rejects_empty_and_malformed_packages(self) -> None:
        client = _client(_Frida())
        with pytest.raises(FridaError) as empty:
            client.spawn("local", "   ")
        assert empty.value.code == "invalid_params"
        with pytest.raises(FridaError) as bad:
            client.spawn("local", "not a package")
        assert bad.value.code == "invalid_params"

    def test_spawns_and_resumes(self) -> None:
        device = _Device()
        client = _client(_Frida(device=device))
        result = client.spawn("local", "com.example.app")
        assert result["pid"] == 5150
        assert result["package"] == "com.example.app"
        assert device.resumed == [5150]

    def test_spawn_failure_is_backend_error(self) -> None:
        device = _Device(spawn_error=RuntimeError("no such package"))
        client = _client(_Frida(device=device))
        with pytest.raises(FridaError) as info:
            client.spawn("local", "com.example.app")
        assert info.value.code == "backend_error"

    def test_spawn_timeout_is_labelled_timeout(self) -> None:
        device = _Device(spawn_error=_timeout_exc())
        client = _client(_Frida(device=device))
        with pytest.raises(FridaError) as info:
            client.spawn("local", "com.example.app")
        assert info.value.code == "timeout"

    def test_resume_failure_kills_the_spawned_process(self) -> None:
        device = _Device(resume_error=RuntimeError("resume rejected"))
        client = _client(_Frida(device=device))
        with pytest.raises(FridaError) as info:
            client.spawn("local", "com.example.app")
        assert info.value.code == "backend_error"
        assert device.killed == [5150]

    def test_resume_timeout_kills_and_labels_timeout(self) -> None:
        device = _Device(resume_error=_timeout_exc())
        client = _client(_Frida(device=device))
        with pytest.raises(FridaError) as info:
            client.spawn("local", "com.example.app")
        assert info.value.code == "timeout"
        assert device.killed == [5150]

    def test_resume_frida_error_kills_and_reraises(self) -> None:
        device = _Device(resume_error=FridaError("permission_denied", "no"))
        client = _client(_Frida(device=device))
        with pytest.raises(FridaError) as info:
            client.spawn("local", "com.example.app")
        assert info.value.code == "permission_denied"
        assert device.killed == [5150]


# ----------------------------------------------------------------------------
# java_enumerate
# ----------------------------------------------------------------------------
class TestJavaEnumerate:
    def _payloads(self, **over: Any) -> dict[str, Any]:
        base: dict[str, Any] = {"classes": [], "methods": {"found": True, "methods": []}}
        base.update(over)
        return base

    def test_unauthorized_pid_is_denied(self) -> None:
        client = _client(_Frida())
        with pytest.raises(FridaError) as info:
            client.java_enumerate("local", 99, allowed_pids=[1, 2], mode="classes")
        assert info.value.code == "permission_denied"
        assert info.value.details["pid"] == 99

    def test_classes_paged(self) -> None:
        payloads = self._payloads(classes=[f"c{i}" for i in range(3)])
        client = _client(_Frida(device=_Device(payloads=payloads)))
        result = client.java_enumerate("local", 7, allowed_pids=[7], mode="classes", limit=2)
        assert result["count"] == 2
        assert result["has_more"] is True

    def test_methods_dict_shape(self) -> None:
        payloads = self._payloads(methods={"found": False, "methods": []})
        client = _client(_Frida(device=_Device(payloads=payloads)))
        result = client.java_enumerate(
            "local", 7, allowed_pids=[7], mode="methods", class_name="a.B", limit=5
        )
        assert result["found"] is False
        assert result["methods"] == []

    def test_methods_bare_list_shape(self) -> None:
        payloads = self._payloads(methods=["m0", "m1"])
        client = _client(_Frida(device=_Device(payloads=payloads)))
        result = client.java_enumerate(
            "local", 7, allowed_pids=[7], mode="methods", class_name="a.B", limit=5
        )
        assert result["found"] is True
        assert result["methods"] == ["m0", "m1"]

    def test_methods_without_class_name_is_invalid(self) -> None:
        client = _client(_Frida(device=_Device(payloads=self._payloads())))
        with pytest.raises(FridaError) as info:
            client.java_enumerate("local", 7, allowed_pids=[7], mode="methods")
        assert info.value.code == "invalid_params"

    def test_unknown_mode_is_invalid(self) -> None:
        client = _client(_Frida(device=_Device(payloads=self._payloads())))
        with pytest.raises(FridaError) as info:
            client.java_enumerate("local", 7, allowed_pids=[7], mode="fields")
        assert info.value.code == "invalid_params"

    def test_attach_failure_is_backend_error(self) -> None:
        client = _client(_Frida(device=_Device(attach_error=RuntimeError("attach denied"))))
        with pytest.raises(FridaError) as info:
            client.java_enumerate("local", 7, allowed_pids=[7], mode="classes")
        assert info.value.code == "backend_error"

    def test_attach_timeout_is_timeout(self) -> None:
        client = _client(_Frida(device=_Device(attach_error=_timeout_exc())))
        with pytest.raises(FridaError) as info:
            client.java_enumerate("local", 7, allowed_pids=[7], mode="classes")
        assert info.value.code == "timeout"

    def test_script_failure_becomes_backend_error_and_detaches(self) -> None:
        device = _Device(payloads=self._payloads(), create_error=RuntimeError("script blew up"))
        client = _client(_Frida(device=device))
        with pytest.raises(FridaError) as info:
            client.java_enumerate("local", 7, allowed_pids=[7], mode="classes")
        assert info.value.code == "backend_error"
        assert device.sessions[0].detached is True

    def test_script_timeout_is_timeout(self) -> None:
        device = _Device(payloads=self._payloads(), create_error=_timeout_exc())
        client = _client(_Frida(device=device))
        with pytest.raises(FridaError) as info:
            client.java_enumerate("local", 7, allowed_pids=[7], mode="classes")
        assert info.value.code == "timeout"


# ----------------------------------------------------------------------------
# hook_template_device
# ----------------------------------------------------------------------------
class TestDeviceHookTemplate:
    def test_unknown_template_rejected(self) -> None:
        client = _client(_Frida())
        with pytest.raises(FridaError) as info:
            client.hook_template_device("local", 7, "nope", allowed_pids=[7])
        assert info.value.code == "invalid_params"

    def test_happy_path_reports_nothing_persisted(self) -> None:
        device = _Device()
        client = _client(_Frida(device=device))
        result = client.hook_template_device("local", 7, "noop", allowed_pids=[7])
        assert result["loaded"] is True
        assert result["persisted"] is False
        assert device.sessions[0].script.destroyed is True

    def test_attach_failure_is_backend_error(self) -> None:
        client = _client(_Frida(device=_Device(attach_error=RuntimeError("denied"))))
        with pytest.raises(FridaError) as info:
            client.hook_template_device("local", 7, "noop", allowed_pids=[7])
        assert info.value.code == "backend_error"

    def test_attach_timeout_is_timeout(self) -> None:
        client = _client(_Frida(device=_Device(attach_error=_timeout_exc())))
        with pytest.raises(FridaError) as info:
            client.hook_template_device("local", 7, "noop", allowed_pids=[7])
        assert info.value.code == "timeout"

    def test_load_failure_becomes_backend_error_and_detaches(self) -> None:
        device = _Device(load_error=RuntimeError("not ART"))
        client = _client(_Frida(device=device))
        with pytest.raises(FridaError) as info:
            client.hook_template_device("local", 7, "android_ssl_unpin", allowed_pids=[7])
        assert info.value.code == "backend_error"
        assert device.sessions[0].detached is True

    def test_load_timeout_is_timeout(self) -> None:
        device = _Device(load_error=_timeout_exc())
        client = _client(_Frida(device=device))
        with pytest.raises(FridaError) as info:
            client.hook_template_device("local", 7, "noop", allowed_pids=[7])
        assert info.value.code == "timeout"


def test_page_edges() -> None:
    assert _page(None, 5) == ([], False)
    assert _page(list(range(5)), 5) == (list(range(5)), False)
    page, more = _page(list(range(6)), 5)
    assert more is True and len(page) == 5


def test_module_exposes_frida_import_guard() -> None:
    # The constructor swallows a missing/ broken frida import; construct once to
    # prove neither branch raises regardless of what is installed on this host.
    client = frida_client.FridaClient()
    assert isinstance(client.available, bool)


def test_constructor_degrades_when_frida_import_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """A broken/absent frida package must yield ``available=False``, not an ImportError.

    Setting the module entry to ``None`` makes ``import frida`` raise ImportError,
    which is the same shape as the package not being installed at all.
    """
    import sys

    monkeypatch.setitem(sys.modules, "frida", None)
    client = frida_client.FridaClient()
    assert client.available is False
    with pytest.raises(FridaError) as info:
        client.enumerate_devices()
    assert info.value.code == "capability_unavailable"
