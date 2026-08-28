"""frida client guard paths map every failure to the promised error code.

The frida backend wraps native calls that can hang or raise a zoo of runtime
errors, so each entry point promises a specific envelope code before and after
the work: ``capability_unavailable`` when the module is absent,
``permission_denied`` outside the authorized pid set, ``invalid_params`` for a
bad pid / package / template / mode, ``not_found`` for an unreachable device,
``timeout`` when a call outruns its daemon-thread deadline (killing the spawned
process or detaching the session first), and ``backend_error`` for everything
else. These exercise those branches directly with fake frida objects (the real
module is optional and usually absent), plus the small deadline/timeout
helpers, so the whole client reaches full line and branch coverage.
"""

from __future__ import annotations

import sys
import types
from concurrent.futures import Future
from typing import Any

import pytest

from headless_re_mcp.backends.frida import client as frida_mod
from headless_re_mcp.backends.frida.client import FridaClient, FridaError

# ----------------------------------------------------------------------
# Fake frida objects: a session yields a script whose exports_sync is a
# configurable RPC stand-in; load()/attach()/spawn()/resume() can be told
# to raise so the guard branches around them are exercised.
# ----------------------------------------------------------------------


class _FakeTimeout(Exception):
    """A timeout-flavored error that is *not* ``TimeoutError``.

    ``_is_timeout`` keys off the class name, but ``concurrent.futures``'
    ``TimeoutError`` is an alias of the builtin ``TimeoutError`` on 3.11+, so a
    builtin ``TimeoutError`` that escapes the worker is caught by
    ``_run_deadline``'s own ``FutureTimeout`` handler before it can reach a
    caller's ``_is_timeout`` guard. This class name contains "timeout" yet is a
    plain ``Exception``, so it propagates all the way to the outer guard.
    """


class _Api:
    def __init__(self, **methods: Any) -> None:
        for name, fn in methods.items():
            setattr(self, name, fn)


class _Script:
    def __init__(self, api: Any, load_exc: BaseException | None) -> None:
        self.exports_sync = api
        self._load_exc = load_exc

    def load(self) -> None:
        if self._load_exc is not None:
            raise self._load_exc


class _Session:
    def __init__(self, api: Any = None, load_exc: BaseException | None = None) -> None:
        self._api = api
        self._load_exc = load_exc
        self.detached = False

    def create_script(self, source: str) -> _Script:
        del source
        return _Script(self._api, self._load_exc)

    def detach(self) -> None:
        self.detached = True


class _LocalFrida:
    def __init__(
        self, session: _Session | None = None, attach_exc: BaseException | None = None
    ) -> None:
        self._session = session
        self._attach_exc = attach_exc

    def attach(self, pid: int) -> _Session | None:
        del pid
        if self._attach_exc is not None:
            raise self._attach_exc
        return self._session


class _Device:
    def __init__(
        self,
        *,
        session: _Session | None = None,
        attach_exc: BaseException | None = None,
        spawn_result: int | None = None,
        spawn_exc: BaseException | None = None,
        resume_exc: BaseException | None = None,
        apps: list[Any] | None = None,
        apps_exc: BaseException | None = None,
    ) -> None:
        self._session = session
        self._attach_exc = attach_exc
        self._spawn_result = spawn_result
        self._spawn_exc = spawn_exc
        self._resume_exc = resume_exc
        self._apps = apps
        self._apps_exc = apps_exc
        self.killed: list[int] = []

    def attach(self, pid: int) -> _Session | None:
        del pid
        if self._attach_exc is not None:
            raise self._attach_exc
        return self._session

    def spawn(self, package: str) -> int | None:
        del package
        if self._spawn_exc is not None:
            raise self._spawn_exc
        return self._spawn_result

    def resume(self, pid: int) -> None:
        del pid
        if self._resume_exc is not None:
            raise self._resume_exc

    def kill(self, pid: int) -> None:
        self.killed.append(pid)

    def enumerate_applications(self) -> list[Any]:
        if self._apps_exc is not None:
            raise self._apps_exc
        return self._apps or []


def _unavailable_client() -> FridaClient:
    client = FridaClient()
    client._available = False
    client._frida = None
    return client


def _local_client(frida: Any) -> FridaClient:
    client = FridaClient()
    client._available = True
    client._frida = frida
    return client


def _device_client(device: _Device) -> FridaClient:
    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: device  # type: ignore[method-assign]
    return client


# ----------------------------------------------------------------------
# Module-level helpers.
# ----------------------------------------------------------------------


def test_accepts_timeout_is_false_when_the_signature_cannot_be_read() -> None:
    # A bare int is not introspectable; signature() raises and the helper
    # must report "no timeout parameter" rather than propagate the error.
    assert frida_mod._accepts_timeout(3) is False


def test_bound_timeout_rejects_a_non_positive_deadline() -> None:
    with pytest.raises(FridaError) as caught:
        frida_mod._bound_timeout(0)

    assert caught.value.code == "invalid_params"


def test_invoke_passes_a_timeout_only_when_the_callable_names_it() -> None:
    def with_timeout(value: int, timeout: float) -> tuple[int, float]:
        return value, timeout

    assert frida_mod._invoke(with_timeout, 5, timeout=1.5) == (5, 1.5)


def test_run_deadline_tolerates_a_future_resolved_before_its_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The worker's set_result marks the future done and then raises; the
    # except clause must see done() is already True and not double-set it.
    class _PreDoneFuture(Future):  # type: ignore[type-arg]
        def set_result(self, result: Any) -> None:
            super().set_result(result)
            raise RuntimeError("late failure after the result stuck")

    monkeypatch.setattr(frida_mod, "Future", _PreDoneFuture)

    assert frida_mod._run_deadline(lambda: 11, timeout=5.0) == 11


def test_client_marks_itself_available_when_frida_imports(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = types.ModuleType("frida")
    monkeypatch.setitem(sys.modules, "frida", fake)

    client = FridaClient()

    assert client.available is True
    assert client._frida is fake


def test_client_marks_itself_unavailable_when_frida_is_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A None entry in sys.modules makes ``import frida`` raise, the same as a
    # real missing install. Construction must swallow that and degrade to
    # unavailable (so callers get capability_unavailable) rather than letting the
    # ImportError escape the constructor.
    monkeypatch.setitem(sys.modules, "frida", None)

    client = FridaClient()

    assert client.available is False
    assert client._frida is None


# ----------------------------------------------------------------------
# attach (local) and its authorization guards.
# ----------------------------------------------------------------------


def test_attach_without_the_module_is_capability_unavailable() -> None:
    with pytest.raises(FridaError) as caught:
        _unavailable_client().attach(1, allowed_pid=1)

    assert caught.value.code == "capability_unavailable"
    # The refusal names the extra that installs frida so the fix travels with the
    # error, not only in the README.
    assert "pip install '.[android]'" in caught.value.message


def test_attach_rejects_a_non_positive_pid() -> None:
    client = _local_client(object())

    with pytest.raises(FridaError) as caught:
        client.attach(0, allowed_pid=1)

    assert caught.value.code == "invalid_params"


def test_attach_refuses_a_pid_outside_the_session() -> None:
    client = _local_client(object())

    with pytest.raises(FridaError) as caught:
        client.attach(2, allowed_pid=1)

    assert caught.value.code == "permission_denied"


def test_attach_returns_a_probe_result_and_detaches() -> None:
    session = _Session()
    client = _local_client(_LocalFrida(session=session))

    payload = client.attach(1, allowed_pid=1)

    assert payload["attached"] is True
    assert payload["device"] == "local"
    assert session.detached is True


def test_attach_local_maps_a_generic_attach_failure_to_backend_error() -> None:
    client = _local_client(_LocalFrida(attach_exc=RuntimeError("no such process")))

    with pytest.raises(FridaError) as caught:
        client._attach_local(1)

    assert caught.value.code == "backend_error"
    assert "attach failed" in caught.value.message


def test_attach_local_maps_a_timeout_flavored_failure_to_timeout() -> None:
    client = _local_client(_LocalFrida(attach_exc=_FakeTimeout("attach timed out")))

    with pytest.raises(FridaError) as caught:
        client._attach_local(1)

    assert caught.value.code == "timeout"


# ----------------------------------------------------------------------
# modules / exports / memory_read payload shaping and _require.
# ----------------------------------------------------------------------


def test_modules_reads_the_dict_shaped_enumeration() -> None:
    api = _Api(
        modules=lambda offset, cap: {
            "modules": [{"name": "a", "base": "0x1", "size": 1, "path": "/a"}],
            "total": 30,
        }
    )
    client = _local_client(_LocalFrida(session=_Session(api=api)))

    payload = client.modules(1, allowed_pid=1, limit=5)

    assert payload["count"] == 1
    assert payload["total"] == 30
    assert payload["offset"] == 0
    assert payload["has_more"] is True


def test_modules_tolerates_the_bare_list_older_script_shape() -> None:
    """An older injected script returns a bare list, not {modules, total}.

    modules keeps reading that shape rather than raising: with no total it treats
    the window as the tail (total = offset + count) so has_more stays False, the
    degraded-shape fallback the else branch documents. This is the reason modules
    (unlike exports, which always expects the dict) tolerates a non-dict payload.
    """
    api = _Api(
        modules=lambda offset, cap: [
            {"name": "a", "base": "0x1", "size": 1, "path": "/a"},
            {"name": "b", "base": "0x2", "size": 2, "path": "/b"},
        ]
    )
    client = _local_client(_LocalFrida(session=_Session(api=api)))

    payload = client.modules(1, allowed_pid=1, limit=5)

    assert payload["count"] == 2
    assert payload["total"] == 2
    assert payload["offset"] == 0
    assert payload["has_more"] is False


def test_modules_offset_pages_past_a_filled_limit() -> None:
    """offset must reach the modules a filled first page hides.

    frida.modules advertised total and has_more but took no offset, so a process
    with more native modules than the limit could report has_more True yet give
    no way to read the rest -- the same broken contract frida.applications had.
    The probe skips offset on the target and returns the true total, so the
    client must forward offset, return it, and compute has_more against the far
    edge. Here a 30-module process paged at offset 25 limit 5 is the terminal
    page (offset 25, has_more False), and a negative offset (the agent/OpenAI
    transports bypass the schema's offset >= 0 bound) must clamp to the head.
    """
    seen: dict[str, int] = {}

    def _modules(offset: int, cap: int) -> dict[str, Any]:
        seen["offset"] = offset
        seen["cap"] = cap
        # Emulate the target-side skip: window [offset, offset+cap) of 30 modules.
        window = [
            {"name": f"m{i}", "base": hex(i), "size": i, "path": f"/m{i}"}
            for i in range(offset, min(offset + cap, 30))
        ]
        return {"modules": window, "total": 30}

    client = _local_client(_LocalFrida(session=_Session(api=_Api(modules=_modules))))

    tail = client.modules(1, allowed_pid=1, offset=25, limit=5)
    assert seen == {"offset": 25, "cap": 5}
    assert tail["offset"] == 25
    assert tail["count"] == 5
    assert tail["total"] == 30
    assert tail["has_more"] is False
    assert [m["name"] for m in tail["modules"]] == [f"m{i}" for i in range(25, 30)]

    negative = client.modules(1, allowed_pid=1, offset=-5, limit=4)
    assert negative["offset"] == 0
    assert seen["offset"] == 0
    assert [m["name"] for m in negative["modules"]] == [f"m{i}" for i in range(0, 4)]
    assert negative["has_more"] is True


def test_exports_rejects_a_blank_module_name() -> None:
    client = _local_client(_LocalFrida(session=_Session()))

    with pytest.raises(FridaError) as caught:
        client.exports(1, "   ", allowed_pid=1)

    assert caught.value.code == "invalid_params"


def test_exports_rejects_a_non_dict_payload() -> None:
    api = _Api(exports=lambda name, offset, count: ["not", "a", "dict"])
    client = _local_client(_LocalFrida(session=_Session(api=api)))

    with pytest.raises(FridaError) as caught:
        client.exports(1, "ntdll.dll", allowed_pid=1)

    assert caught.value.code == "backend_error"


def test_exports_skips_non_dict_rows() -> None:
    api = _Api(
        exports=lambda name, offset, count: {
            "found": True,
            "module": name,
            "base": "0x1",
            "exports": [{"name": "e", "address": "0x2", "type": "function"}, "junk"],
        }
    )
    client = _local_client(_LocalFrida(session=_Session(api=api)))

    payload = client.exports(1, "ntdll.dll", allowed_pid=1)

    assert payload["count"] == 1
    assert payload["exports"][0]["name"] == "e"


def test_memory_read_rejects_a_size_outside_the_window() -> None:
    client = _local_client(_LocalFrida(session=_Session(api=_Api())))

    with pytest.raises(FridaError) as caught:
        client.memory_read(1, 0x1000, 0, allowed_pid=1)

    assert caught.value.code == "invalid_params"


def test_memory_read_returns_hex_encoded_bytes() -> None:
    api = _Api(read=lambda address, size: [0xDE, 0xAD, 0xBE, 0xEF])
    client = _local_client(_LocalFrida(session=_Session(api=api)))

    payload = client.memory_read(1, 0x1000, 4, allowed_pid=1)

    assert payload["encoding"] == "hex"
    assert payload["data"] == "deadbeef"


def test_require_refuses_a_pid_outside_the_session() -> None:
    client = _local_client(object())

    with pytest.raises(FridaError) as caught:
        client.modules(1, allowed_pid=2)

    assert caught.value.code == "permission_denied"


def test_require_reports_capability_unavailable_for_the_authorized_pid() -> None:
    with pytest.raises(FridaError) as caught:
        _unavailable_client().modules(1, allowed_pid=1)

    assert caught.value.code == "capability_unavailable"


# ----------------------------------------------------------------------
# hook_template (local).
# ----------------------------------------------------------------------


def test_hook_template_rejects_an_unknown_template() -> None:
    client = _local_client(_LocalFrida(session=_Session()))

    with pytest.raises(FridaError) as caught:
        client.hook_template(1, "does_not_exist", allowed_pid=1)

    assert caught.value.code == "invalid_params"


def test_hook_template_passes_through_a_backend_error_from_load() -> None:
    session = _Session(load_exc=FridaError("backend_error", "script would not load"))
    client = _local_client(_LocalFrida(session=session))

    with pytest.raises(FridaError) as caught:
        client.hook_template(1, "noop", allowed_pid=1)

    assert caught.value.code == "backend_error"


def test_hook_template_maps_a_timeout_flavored_load_to_timeout() -> None:
    session = _Session(load_exc=_FakeTimeout("script load timed out"))
    client = _local_client(_LocalFrida(session=session))

    with pytest.raises(FridaError) as caught:
        client.hook_template(1, "noop", allowed_pid=1)

    assert caught.value.code == "timeout"


def test_hook_template_reraises_an_unexpected_load_error() -> None:
    session = _Session(load_exc=RuntimeError("boom"))
    client = _local_client(_LocalFrida(session=session))

    with pytest.raises(RuntimeError):
        client.hook_template(1, "noop", allowed_pid=1)


# ----------------------------------------------------------------------
# _resolve_device across the local / usb / remote / plain branches.
# ----------------------------------------------------------------------


def test_resolve_device_returns_the_local_device() -> None:
    device = object()

    class _Frida:
        def get_local_device(self) -> object:
            return device

    client = _local_client(_Frida())

    assert client._resolve_device(None) is device
    assert client._resolve_device("local") is device


def test_resolve_device_reuses_a_registered_remote_device() -> None:
    device = object()

    class _Manager:
        def get_device(self, device_id: str, timeout: int = 1) -> object:
            del device_id, timeout
            return device

    class _Frida:
        def get_device_manager(self) -> _Manager:
            return _Manager()

    client = _local_client(_Frida())

    assert client._resolve_device("10.0.0.1:27042") is device


def test_resolve_device_adds_an_unregistered_remote_device() -> None:
    device = object()

    class _Manager:
        def get_device(self, device_id: str, timeout: int = 1) -> object:
            del device_id, timeout
            raise RuntimeError("not registered")

        def add_remote_device(self, device_id: str) -> object:
            del device_id
            return device

    class _Frida:
        def get_device_manager(self) -> _Manager:
            return _Manager()

    client = _local_client(_Frida())

    assert client._resolve_device("10.0.0.1:27042") is device


def test_resolve_device_uses_get_device_for_a_plain_id() -> None:
    device = object()

    class _Frida:
        def get_device(self, device_id: str, timeout: int = 5) -> object:
            del device_id, timeout
            return device

    client = _local_client(_Frida())

    assert client._resolve_device("emulator-5554") is device


def test_resolve_device_maps_a_generic_lookup_failure_to_not_found() -> None:
    class _Frida:
        def get_local_device(self) -> object:
            raise RuntimeError("no frida-server")

    client = _local_client(_Frida())

    with pytest.raises(FridaError) as caught:
        client._resolve_device(None)

    assert caught.value.code == "not_found"


# ----------------------------------------------------------------------
# enumerate_devices / add_remote_device / applications error paths.
# ----------------------------------------------------------------------


def test_device_operations_need_the_module() -> None:
    with pytest.raises(FridaError) as caught:
        _unavailable_client().enumerate_devices()

    assert caught.value.code == "capability_unavailable"


def test_enumerate_devices_maps_a_failure_to_backend_error() -> None:
    class _Frida:
        def enumerate_devices(self) -> list[Any]:
            raise RuntimeError("device manager down")

    client = _local_client(_Frida())

    with pytest.raises(FridaError) as caught:
        client.enumerate_devices()

    assert caught.value.code == "backend_error"


def test_add_remote_device_maps_a_failure_to_backend_error() -> None:
    class _Manager:
        def get_device(self, endpoint: str, timeout: int = 1) -> object:
            del endpoint, timeout
            raise RuntimeError("not registered")

        def add_remote_device(self, endpoint: str) -> object:
            del endpoint
            raise RuntimeError("connection refused")

    class _Frida:
        def get_device_manager(self) -> _Manager:
            return _Manager()

    client = _local_client(_Frida())

    with pytest.raises(FridaError) as caught:
        client.add_remote_device("127.0.0.1:27042")

    assert caught.value.code == "backend_error"


def test_applications_maps_an_enumeration_failure_to_backend_error() -> None:
    client = _device_client(_Device(apps_exc=RuntimeError("no applications")))

    with pytest.raises(FridaError) as caught:
        client.applications("usb")

    assert caught.value.code == "backend_error"


# ----------------------------------------------------------------------
# spawn: package validation, spawn/resume failures, outer guard.
# ----------------------------------------------------------------------


def test_spawn_requires_a_package() -> None:
    client = _device_client(_Device())

    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "   ")

    assert caught.value.code == "invalid_params"


def test_spawn_maps_a_generic_spawn_failure_to_backend_error() -> None:
    client = _device_client(_Device(spawn_exc=RuntimeError("no such package")))

    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "com.example.app")

    assert caught.value.code == "backend_error"


def test_spawn_maps_a_timeout_flavored_spawn_failure_to_timeout() -> None:
    client = _device_client(_Device(spawn_exc=TimeoutError("spawn timed out")))

    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "com.example.app")

    assert caught.value.code == "timeout"


def test_spawn_kills_the_process_when_resume_raises_a_backend_error() -> None:
    device = _Device(
        spawn_result=4242,
        resume_exc=FridaError("backend_error", "resume rejected"),
    )
    client = _device_client(device)

    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "com.example.app")

    assert caught.value.code == "backend_error"
    assert device.killed == [4242]


def test_spawn_kills_the_process_when_resume_times_out() -> None:
    device = _Device(spawn_result=4242, resume_exc=TimeoutError("resume timed out"))
    client = _device_client(device)

    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "com.example.app")

    assert caught.value.code == "timeout"
    assert device.killed == [4242]


def test_spawn_maps_an_unexpected_runner_failure_to_backend_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(work: Any, *, timeout: float, on_timeout: Any = None) -> Any:
        del work, timeout, on_timeout
        raise RuntimeError("runner blew up")

    monkeypatch.setattr(frida_mod, "_run_deadline", boom)
    client = _device_client(_Device())

    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "com.example.app")

    assert caught.value.code == "backend_error"


def test_spawn_maps_an_unexpected_runner_timeout_to_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(work: Any, *, timeout: float, on_timeout: Any = None) -> Any:
        del work, timeout, on_timeout
        raise TimeoutError("runner timed out")

    monkeypatch.setattr(frida_mod, "_run_deadline", boom)
    client = _device_client(_Device())

    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "com.example.app")

    assert caught.value.code == "timeout"


# ----------------------------------------------------------------------
# java_enumerate: attach failures, mode validation, outer guard.
# ----------------------------------------------------------------------


def test_java_enumerate_maps_a_generic_attach_failure_to_backend_error() -> None:
    client = _device_client(_Device(attach_exc=RuntimeError("attach refused")))

    with pytest.raises(FridaError) as caught:
        client.java_enumerate(None, 1, allowed_pids={1}, mode="classes")

    assert caught.value.code == "backend_error"


def test_java_enumerate_maps_a_timeout_flavored_attach_failure_to_timeout() -> None:
    client = _device_client(_Device(attach_exc=TimeoutError("attach timed out")))

    with pytest.raises(FridaError) as caught:
        client.java_enumerate(None, 1, allowed_pids={1}, mode="classes")

    assert caught.value.code == "timeout"


def test_java_enumerate_methods_requires_a_class_name() -> None:
    api = _Api(
        classes=lambda f, o, c: {"classes": [], "total": 0},
        methods=lambda cn, c: {"found": True, "methods": []},
    )
    client = _device_client(_Device(session=_Session(api=api)))

    with pytest.raises(FridaError) as caught:
        client.java_enumerate(None, 1, allowed_pids={1}, mode="methods")

    assert caught.value.code == "invalid_params"


def test_java_enumerate_rejects_an_unknown_mode() -> None:
    api = _Api(
        classes=lambda f, o, c: {"classes": [], "total": 0},
        methods=lambda cn, c: {"found": True, "methods": []},
    )
    client = _device_client(_Device(session=_Session(api=api)))

    with pytest.raises(FridaError) as caught:
        client.java_enumerate(None, 1, allowed_pids={1}, mode="bogus")

    assert caught.value.code == "invalid_params"


def test_java_enumerate_maps_a_generic_script_failure_to_backend_error() -> None:
    client = _device_client(_Device(session=_Session(load_exc=RuntimeError("load boom"))))

    with pytest.raises(FridaError) as caught:
        client.java_enumerate(None, 1, allowed_pids={1}, mode="classes")

    assert caught.value.code == "backend_error"


def test_java_enumerate_maps_a_timeout_flavored_script_failure_to_timeout() -> None:
    client = _device_client(_Device(session=_Session(load_exc=_FakeTimeout("load timed out"))))

    with pytest.raises(FridaError) as caught:
        client.java_enumerate(None, 1, allowed_pids={1}, mode="classes")

    assert caught.value.code == "timeout"


# ----------------------------------------------------------------------
# hook_template_device and _authorize.
# ----------------------------------------------------------------------


def test_hook_template_device_rejects_an_unknown_template() -> None:
    client = _device_client(_Device())

    with pytest.raises(FridaError) as caught:
        client.hook_template_device(None, 1, "nope", allowed_pids={1})

    assert caught.value.code == "invalid_params"


def test_hook_template_device_maps_a_generic_attach_failure_to_backend_error() -> None:
    client = _device_client(_Device(attach_exc=RuntimeError("attach refused")))

    with pytest.raises(FridaError) as caught:
        client.hook_template_device(None, 1, "noop", allowed_pids={1})

    assert caught.value.code == "backend_error"


def test_hook_template_device_maps_a_timeout_flavored_attach_failure_to_timeout() -> None:
    client = _device_client(_Device(attach_exc=TimeoutError("attach timed out")))

    with pytest.raises(FridaError) as caught:
        client.hook_template_device(None, 1, "noop", allowed_pids={1})

    assert caught.value.code == "timeout"


def test_hook_template_device_maps_a_generic_load_failure_to_backend_error() -> None:
    client = _device_client(_Device(session=_Session(load_exc=RuntimeError("load boom"))))

    with pytest.raises(FridaError) as caught:
        client.hook_template_device(None, 1, "noop", allowed_pids={1})

    assert caught.value.code == "backend_error"


def test_hook_template_device_maps_a_timeout_flavored_load_failure_to_timeout() -> None:
    client = _device_client(_Device(session=_Session(load_exc=_FakeTimeout("load timed out"))))

    with pytest.raises(FridaError) as caught:
        client.hook_template_device(None, 1, "noop", allowed_pids={1})

    assert caught.value.code == "timeout"


def test_authorize_reports_capability_unavailable_without_the_module() -> None:
    with pytest.raises(FridaError) as caught:
        _unavailable_client().java_enumerate(None, 1, allowed_pids={1}, mode="classes")

    assert caught.value.code == "capability_unavailable"


def test_authorize_rejects_a_non_positive_pid() -> None:
    client = _local_client(object())

    with pytest.raises(FridaError) as caught:
        client.java_enumerate(None, 0, allowed_pids={1}, mode="classes")

    assert caught.value.code == "invalid_params"


def test_authorize_refuses_a_pid_outside_the_allowed_set() -> None:
    client = _local_client(object())

    with pytest.raises(FridaError) as caught:
        client.java_enumerate(None, 5, allowed_pids={1}, mode="classes")

    assert caught.value.code == "permission_denied"
