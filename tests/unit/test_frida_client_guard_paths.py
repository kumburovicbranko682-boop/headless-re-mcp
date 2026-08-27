"""Guard and error branches of the Frida backend client.

The live frida runtime cannot run in CI, so these exercise the honesty
contract around it: every guard raises a typed ``FridaError`` with a stable
code, attach/spawn/enumerate failures are wrapped (never leaked raw), timeouts
are named ``timeout`` and clean up the session or spawned pid, and the device
resolver routes local/usb/remote/default ids without holding a worker. The
happy-path field shapes are covered by ``test_frida_fields``; this file is the
non-happy-path complement.
"""

from __future__ import annotations

import sys
from typing import Any

import pytest

from headless_re_mcp.backends.frida.client import (
    FridaClient,
    FridaError,
    _accepts_timeout,
    _bound_timeout,
    _invoke,
    _is_timeout,
)


# ----------------------------------------------------------------------------
# Small fakes. Every session/device records whether it was detached/killed so
# the cleanup-on-failure contract can be asserted, not just the raised code.
# ----------------------------------------------------------------------------
class _Script:
    def __init__(self, api: Any, *, load_exc: BaseException | None = None) -> None:
        self.exports_sync = api
        self._load_exc = load_exc

    def load(self) -> None:
        if self._load_exc is not None:
            raise self._load_exc


class _Session:
    def __init__(self, script: _Script) -> None:
        self._script = script
        self.detached = False

    def create_script(self, source: str) -> _Script:
        del source
        return self._script

    def detach(self) -> None:
        self.detached = True


class _AttachFrida:
    """Local ``frida`` module stand-in whose ``attach`` returns/raises."""

    def __init__(self, session: _Session | None = None, exc: BaseException | None = None) -> None:
        self._session = session
        self._exc = exc

    def attach(self, pid: int) -> _Session:
        del pid
        if self._exc is not None:
            raise self._exc
        assert self._session is not None
        return self._session


def _client(frida: Any) -> FridaClient:
    client = FridaClient()
    client._available = True
    client._frida = frida
    return client


# ----------------------------------------------------------------------------
# Pure helpers.
# ----------------------------------------------------------------------------
def test_accepts_timeout_is_false_when_signature_cannot_be_read() -> None:
    # A non-callable has no signature; the helper must fail closed to False
    # rather than raise, so _invoke never passes timeout= to something that
    # would choke on it.
    assert _accepts_timeout(object()) is False


def test_accepts_timeout_is_false_for_kwargs_only_callable() -> None:
    def spawn_like(*args: Any, **kwargs: Any) -> None:
        del args, kwargs

    # **kwargs is not the same as naming timeout: passing a deadline there
    # would become a spawn aux option, not a hang bound.
    assert _accepts_timeout(spawn_like) is False


def test_accepts_timeout_is_true_when_named() -> None:
    def call(a: int, timeout: float = 1.0) -> None:
        del a, timeout

    assert _accepts_timeout(call) is True


def test_invoke_passes_timeout_only_to_callables_that_name_it() -> None:
    def named(a: int, *, timeout: float | None = None) -> tuple[int, float | None]:
        return a, timeout

    assert _invoke(named, 7, timeout=5.0) == (7, 5.0)

    def unnamed(a: int) -> int:
        return a

    assert _invoke(unnamed, 7, timeout=5.0) == 7


def test_bound_timeout_rejects_non_positive() -> None:
    with pytest.raises(FridaError) as caught:
        _bound_timeout(0)
    assert caught.value.code == "invalid_params"


def test_is_timeout_matches_name_or_message() -> None:
    assert _is_timeout(TimeoutError("boom")) is True
    assert _is_timeout(RuntimeError("operation timed out")) is True
    assert _is_timeout(RuntimeError("something else")) is False


# ----------------------------------------------------------------------------
# Construction: a missing frida module is a capability gap, not a crash.
# ----------------------------------------------------------------------------
def test_construction_without_frida_module_is_unavailable(monkeypatch: Any) -> None:
    monkeypatch.setitem(sys.modules, "frida", None)
    client = FridaClient()
    assert client.available is False
    with pytest.raises(FridaError) as caught:
        client.attach(1, allowed_pid=1)
    assert caught.value.code == "capability_unavailable"


# ----------------------------------------------------------------------------
# attach() guards and the immediate-detach success shape.
# ----------------------------------------------------------------------------
def test_attach_rejects_non_positive_pid() -> None:
    client = _client(_AttachFrida(_Session(_Script(object()))))
    with pytest.raises(FridaError) as caught:
        client.attach(0, allowed_pid=0)
    assert caught.value.code == "invalid_params"


def test_attach_refuses_a_pid_outside_the_session_debuggee() -> None:
    client = _client(_AttachFrida(_Session(_Script(object()))))
    with pytest.raises(FridaError) as caught:
        client.attach(2, allowed_pid=1)
    assert caught.value.code == "permission_denied"


def test_attach_probe_detaches_immediately() -> None:
    session = _Session(_Script(object()))
    client = _client(_AttachFrida(session))
    payload = client.attach(4321, allowed_pid=4321)
    assert payload["attached"] is True
    assert payload["pid"] == 4321
    assert payload["device"] == "local"
    assert session.detached is True


# ----------------------------------------------------------------------------
# modules(): tolerate the bare-list script shape.
# ----------------------------------------------------------------------------
def test_modules_tolerates_a_bare_list_payload() -> None:
    class _Api:
        def modules(self, limit: int) -> list[dict[str, Any]]:
            del limit
            return [{"name": "libc", "base": "0x1", "size": 4, "path": "/x"}]

    client = _client(_AttachFrida(_Session(_Script(_Api()))))
    payload = client.modules(9, allowed_pid=9, limit=8)
    assert payload["count"] == 1
    assert payload["total"] == 1
    assert payload["modules"][0]["name"] == "libc"
    assert payload["has_more"] is False


def test_modules_uses_total_from_a_dict_payload() -> None:
    class _Api:
        def modules(self, limit: int) -> dict[str, Any]:
            return {
                "modules": [
                    {"name": f"m{i}", "base": "0x1", "size": 1, "path": ""}
                    for i in range(limit)
                ],
                "total": 999,
            }

    client = _client(_AttachFrida(_Session(_Script(_Api()))))
    payload = client.modules(9, allowed_pid=9, limit=3)
    # total comes from the script, not the page length, so has_more is honest.
    assert payload["count"] == 3
    assert payload["total"] == 999
    assert payload["has_more"] is True


# ----------------------------------------------------------------------------
# exports() guards.
# ----------------------------------------------------------------------------
def test_exports_requires_a_module_name() -> None:
    client = _client(object())
    with pytest.raises(FridaError) as caught:
        client.exports(1, "   ", allowed_pid=1)
    assert caught.value.code == "invalid_params"


def test_exports_rejects_a_non_dict_payload() -> None:
    class _Api:
        def exports(self, name: str, count: int) -> list[Any]:
            del name, count
            return []

    client = _client(_AttachFrida(_Session(_Script(_Api()))))
    with pytest.raises(FridaError) as caught:
        client.exports(1, "libc.so", allowed_pid=1)
    assert caught.value.code == "backend_error"


def test_exports_skips_non_dict_rows() -> None:
    class _Api:
        def exports(self, name: str, count: int) -> dict[str, Any]:
            del name, count
            return {
                "found": True,
                "module": "libc.so",
                "base": "0x0",
                "exports": [{"name": "open", "address": "0x1", "type": "function"}, "junk"],
            }

    client = _client(_AttachFrida(_Session(_Script(_Api()))))
    payload = client.exports(1, "libc.so", allowed_pid=1, limit=10)
    assert payload["count"] == 1
    assert payload["exports"][0]["name"] == "open"


# ----------------------------------------------------------------------------
# memory_read(): size bound and the hex success shape.
# ----------------------------------------------------------------------------
def test_memory_read_rejects_out_of_range_size() -> None:
    client = _client(object())
    with pytest.raises(FridaError) as caught:
        client.memory_read(1, 0x1000, 0, allowed_pid=1)
    assert caught.value.code == "invalid_params"


def test_memory_read_returns_hex() -> None:
    class _Api:
        def read(self, address: int, size: int) -> list[int]:
            del address
            return list(range(size))

    session = _Session(_Script(_Api()))
    client = _client(_AttachFrida(session))
    payload = client.memory_read(1, 0x1000, 4, allowed_pid=1)
    assert payload["encoding"] == "hex"
    assert payload["data"] == "00010203"
    assert payload["size"] == 4
    assert session.detached is True


# ----------------------------------------------------------------------------
# hook_template() (local device): unknown template + exception handling.
# ----------------------------------------------------------------------------
def test_hook_template_rejects_an_unknown_template() -> None:
    client = _client(object())
    with pytest.raises(FridaError) as caught:
        client.hook_template(1, "does_not_exist", allowed_pid=1)
    assert caught.value.code == "invalid_params"
    assert "noop" in caught.value.details["allowed"]


def test_hook_template_reraises_a_frida_error_from_attach() -> None:
    boom = FridaError("permission_denied", "nope")
    client = _client(_AttachFrida(exc=boom))
    with pytest.raises(FridaError) as caught:
        client.hook_template(1, "noop", allowed_pid=1)
    assert caught.value.code == "permission_denied"


def test_hook_template_maps_a_load_timeout_and_detaches() -> None:
    # frida's own timeout error is not concurrent.futures.TimeoutError, so the
    # method's outer except -- not the _run_deadline wrapper -- classifies it.
    session = _Session(_Script(object(), load_exc=RuntimeError("script load timed out")))
    client = _client(_AttachFrida(session))
    with pytest.raises(FridaError) as caught:
        client.hook_template(1, "noop", allowed_pid=1)
    assert caught.value.code == "timeout"
    assert session.detached is True


def test_hook_template_local_success_discloses_non_persistence() -> None:
    session = _Session(_Script(object()))
    client = _client(_AttachFrida(session))
    payload = client.hook_template(1, "noop", allowed_pid=1)
    assert payload["loaded"] is True
    assert payload["template"] == "noop"
    assert payload["device"] == "local"
    # The probe detaches, which destroys the script; the reply must say so.
    assert payload["persisted"] is False
    assert session.detached is True


def test_hook_template_reraises_a_plain_load_error() -> None:
    session = _Session(_Script(object(), load_exc=RuntimeError("script rejected")))
    client = _client(_AttachFrida(session))
    with pytest.raises(RuntimeError, match="script rejected"):
        client.hook_template(1, "noop", allowed_pid=1)
    assert session.detached is True


# ----------------------------------------------------------------------------
# _attach_local() failure wrapping.
# ----------------------------------------------------------------------------
def test_attach_local_wraps_a_plain_error_as_backend_error() -> None:
    client = _client(_AttachFrida(exc=RuntimeError("no such process")))
    with pytest.raises(FridaError) as caught:
        client._attach_local(1)
    assert caught.value.code == "backend_error"


def test_attach_local_maps_a_timeout_named_error() -> None:
    client = _client(_AttachFrida(exc=RuntimeError("attach timed out")))
    with pytest.raises(FridaError) as caught:
        client._attach_local(1)
    assert caught.value.code == "timeout"


# ----------------------------------------------------------------------------
# _require(): capability gap after the pid check passes.
# ----------------------------------------------------------------------------
def test_require_reports_capability_gap_when_module_absent() -> None:
    client = FridaClient()
    client._available = False
    client._frida = None
    with pytest.raises(FridaError) as caught:
        client.modules(1, allowed_pid=1)
    assert caught.value.code == "capability_unavailable"


# ----------------------------------------------------------------------------
# _resolve_device(): local / remote-reuse / remote-add / default / not_found.
# ----------------------------------------------------------------------------
class _Dev:
    def __init__(self, ident: str) -> None:
        self.id = ident
        self.name = ident
        self.type = "test"


def test_resolve_device_local() -> None:
    class _Frida:
        def get_local_device(self) -> _Dev:
            return _Dev("local")

    assert _client(_Frida())._resolve_device(None).id == "local"


def test_resolve_device_reuses_a_registered_remote() -> None:
    class _Manager:
        def get_device(self, endpoint: str, timeout: int = 1) -> _Dev:
            del timeout
            return _Dev(endpoint)

    class _Frida:
        def get_device_manager(self) -> _Manager:
            return _Manager()

    assert _client(_Frida())._resolve_device("10.0.0.1:27042").id == "10.0.0.1:27042"


def test_resolve_device_adds_an_unregistered_remote() -> None:
    class _Manager:
        def get_device(self, endpoint: str, timeout: int = 1) -> _Dev:
            del endpoint, timeout
            raise RuntimeError("not registered")

        def add_remote_device(self, endpoint: str) -> _Dev:
            return _Dev(endpoint)

    class _Frida:
        def get_device_manager(self) -> _Manager:
            return _Manager()

    assert _client(_Frida())._resolve_device("10.0.0.2:27042").id == "10.0.0.2:27042"


def test_resolve_device_by_explicit_id() -> None:
    class _Frida:
        def get_device(self, device_id: str, timeout: int = 5) -> _Dev:
            del timeout
            return _Dev(device_id)

    assert _client(_Frida())._resolve_device("emulator-5554").id == "emulator-5554"


def test_resolve_device_maps_lookup_failure_to_not_found() -> None:
    class _Frida:
        def get_local_device(self) -> _Dev:
            raise RuntimeError("no daemon")

    with pytest.raises(FridaError) as caught:
        _client(_Frida())._resolve_device(None)
    assert caught.value.code == "not_found"


# ----------------------------------------------------------------------------
# enumerate_devices() / add_remote_device() failure wrapping.
# ----------------------------------------------------------------------------
def test_enumerate_devices_reports_capability_gap_when_module_absent() -> None:
    client = FridaClient()
    client._available = False
    client._frida = None
    with pytest.raises(FridaError) as caught:
        client.enumerate_devices()
    assert caught.value.code == "capability_unavailable"


def test_enumerate_devices_wraps_failure() -> None:
    class _Frida:
        def enumerate_devices(self) -> list[Any]:
            raise RuntimeError("bus error")

    with pytest.raises(FridaError) as caught:
        _client(_Frida()).enumerate_devices()
    assert caught.value.code == "backend_error"


def test_add_remote_device_wraps_a_plain_add_failure() -> None:
    class _Manager:
        def get_device(self, endpoint: str, timeout: int = 1) -> _Dev:
            del endpoint, timeout
            raise RuntimeError("not registered")

        def add_remote_device(self, endpoint: str) -> _Dev:
            del endpoint
            raise RuntimeError("connection refused")

    class _Frida:
        def get_device_manager(self) -> _Manager:
            return _Manager()

    with pytest.raises(FridaError) as caught:
        _client(_Frida()).add_remote_device("127.0.0.1:1")
    assert caught.value.code == "backend_error"


# ----------------------------------------------------------------------------
# applications() failure wrapping.
# ----------------------------------------------------------------------------
def test_applications_wraps_failure() -> None:
    class _Device:
        def enumerate_applications(self) -> list[Any]:
            raise RuntimeError("device asleep")

    client = _client(object())
    client._resolve_device = lambda device_id: _Device()  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.applications("usb")
    assert caught.value.code == "backend_error"


# ----------------------------------------------------------------------------
# spawn(): package guard and spawn/resume failure branches.
# ----------------------------------------------------------------------------
def _spawn_client(device: Any) -> FridaClient:
    client = _client(object())
    client._resolve_device = lambda device_id: device  # type: ignore[method-assign]
    return client


def test_spawn_requires_a_package() -> None:
    client = _spawn_client(object())
    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "   ")
    assert caught.value.code == "invalid_params"


def test_spawn_wraps_a_plain_spawn_failure() -> None:
    class _Device:
        def spawn(self, package: str) -> int:
            del package
            raise RuntimeError("activity not found")

    with pytest.raises(FridaError) as caught:
        _spawn_client(_Device()).spawn("usb", "com.example.app")
    assert caught.value.code == "backend_error"


def test_spawn_maps_a_spawn_timeout() -> None:
    class _Device:
        def spawn(self, package: str) -> int:
            del package
            raise TimeoutError("usb wedged")

    with pytest.raises(FridaError) as caught:
        _spawn_client(_Device()).spawn("usb", "com.example.app")
    assert caught.value.code == "timeout"


def test_spawn_kills_the_pid_when_resume_raises_frida_error() -> None:
    killed: list[int] = []

    class _Device:
        def spawn(self, package: str) -> int:
            del package
            return 555

        def resume(self, pid: int) -> None:
            del pid
            raise FridaError("permission_denied", "cannot resume")

        def kill(self, pid: int) -> None:
            killed.append(pid)

    with pytest.raises(FridaError) as caught:
        _spawn_client(_Device()).spawn("usb", "com.example.app")
    assert caught.value.code == "permission_denied"
    assert killed == [555]


def test_spawn_maps_a_resume_timeout_and_kills() -> None:
    killed: list[int] = []

    class _Device:
        def spawn(self, package: str) -> int:
            del package
            return 556

        def resume(self, pid: int) -> None:
            del pid
            raise TimeoutError("resume stuck")

        def kill(self, pid: int) -> None:
            killed.append(pid)

    with pytest.raises(FridaError) as caught:
        _spawn_client(_Device()).spawn("usb", "com.example.app")
    assert caught.value.code == "timeout"
    assert killed == [556]


def test_spawn_wraps_a_plain_resume_failure_and_kills() -> None:
    killed: list[int] = []

    class _Device:
        def spawn(self, package: str) -> int:
            del package
            return 557

        def resume(self, pid: int) -> None:
            del pid
            raise RuntimeError("resume refused")

        def kill(self, pid: int) -> None:
            killed.append(pid)

    with pytest.raises(FridaError) as caught:
        _spawn_client(_Device()).spawn("usb", "com.example.app")
    assert caught.value.code == "backend_error"
    assert killed == [557]


# ----------------------------------------------------------------------------
# java_enumerate(): attach failure, mode guards, script failure.
# ----------------------------------------------------------------------------
def _device_client(device: Any) -> FridaClient:
    client = _client(object())
    client._resolve_device = lambda device_id: device  # type: ignore[method-assign]
    return client


def test_java_enumerate_wraps_an_attach_failure() -> None:
    class _Device:
        def attach(self, pid: int) -> Any:
            del pid
            raise RuntimeError("attach denied")

    with pytest.raises(FridaError) as caught:
        _device_client(_Device()).java_enumerate(
            None, 1, allowed_pids={1}, mode="classes"
        )
    assert caught.value.code == "backend_error"


def test_java_enumerate_maps_an_attach_timeout() -> None:
    class _Device:
        def attach(self, pid: int) -> Any:
            del pid
            raise TimeoutError("attach stuck")

    with pytest.raises(FridaError) as caught:
        _device_client(_Device()).java_enumerate(
            None, 1, allowed_pids={1}, mode="classes"
        )
    assert caught.value.code == "timeout"


def test_java_enumerate_methods_requires_a_class_name() -> None:
    class _Device:
        def attach(self, pid: int) -> _Session:
            del pid
            return _Session(_Script(object()))

    with pytest.raises(FridaError) as caught:
        _device_client(_Device()).java_enumerate(
            None, 1, allowed_pids={1}, mode="methods"
        )
    assert caught.value.code == "invalid_params"


def test_java_enumerate_rejects_an_unknown_mode() -> None:
    class _Device:
        def attach(self, pid: int) -> _Session:
            del pid
            return _Session(_Script(object()))

    with pytest.raises(FridaError) as caught:
        _device_client(_Device()).java_enumerate(
            None, 1, allowed_pids={1}, mode="sideways"
        )
    assert caught.value.code == "invalid_params"


def test_java_enumerate_wraps_a_script_load_failure() -> None:
    class _Device:
        def attach(self, pid: int) -> _Session:
            del pid
            return _Session(_Script(object(), load_exc=RuntimeError("no ART")))

    with pytest.raises(FridaError) as caught:
        _device_client(_Device()).java_enumerate(
            None, 1, allowed_pids={1}, mode="classes"
        )
    assert caught.value.code == "backend_error"


def test_java_enumerate_maps_a_script_timeout() -> None:
    class _Device:
        def attach(self, pid: int) -> _Session:
            del pid
            return _Session(_Script(object(), load_exc=RuntimeError("perform timed out")))

    with pytest.raises(FridaError) as caught:
        _device_client(_Device()).java_enumerate(
            None, 1, allowed_pids={1}, mode="classes"
        )
    assert caught.value.code == "timeout"


# ----------------------------------------------------------------------------
# hook_template_device(): attach and script failures.
# ----------------------------------------------------------------------------
def test_hook_template_device_wraps_an_attach_failure() -> None:
    class _Device:
        def attach(self, pid: int) -> Any:
            del pid
            raise RuntimeError("attach denied")

    with pytest.raises(FridaError) as caught:
        _device_client(_Device()).hook_template_device(
            None, 1, "noop", allowed_pids={1}
        )
    assert caught.value.code == "backend_error"


def test_hook_template_device_maps_an_attach_timeout() -> None:
    class _Device:
        def attach(self, pid: int) -> Any:
            del pid
            raise TimeoutError("attach stuck")

    with pytest.raises(FridaError) as caught:
        _device_client(_Device()).hook_template_device(
            None, 1, "noop", allowed_pids={1}
        )
    assert caught.value.code == "timeout"


def test_hook_template_device_wraps_a_script_load_failure() -> None:
    class _Device:
        def attach(self, pid: int) -> _Session:
            del pid
            return _Session(_Script(object(), load_exc=RuntimeError("load failed")))

    with pytest.raises(FridaError) as caught:
        _device_client(_Device()).hook_template_device(
            None, 1, "noop", allowed_pids={1}
        )
    assert caught.value.code == "backend_error"


def test_hook_template_device_maps_a_script_timeout() -> None:
    class _Device:
        def attach(self, pid: int) -> _Session:
            del pid
            return _Session(_Script(object(), load_exc=RuntimeError("load timed out")))

    with pytest.raises(FridaError) as caught:
        _device_client(_Device()).hook_template_device(
            None, 1, "noop", allowed_pids={1}
        )
    assert caught.value.code == "timeout"


def test_hook_template_device_success_discloses_non_persistence() -> None:
    class _Device:
        def attach(self, pid: int) -> _Session:
            del pid
            return _Session(_Script(object()))

    payload = _device_client(_Device()).hook_template_device(
        None, 1, "android_ssl_unpin", allowed_pids={1}
    )
    assert payload["loaded"] is True
    assert payload["template"] == "android_ssl_unpin"
    assert payload["persisted"] is False


# ----------------------------------------------------------------------------
# _authorize(): capability gap and pid validation before the allow-set check.
# ----------------------------------------------------------------------------
def test_authorize_reports_capability_gap() -> None:
    client = FridaClient()
    client._available = False
    client._frida = None
    with pytest.raises(FridaError) as caught:
        client.java_enumerate(None, 1, allowed_pids={1}, mode="classes")
    assert caught.value.code == "capability_unavailable"


def test_authorize_rejects_a_non_positive_pid() -> None:
    client = _client(object())
    with pytest.raises(FridaError) as caught:
        client.java_enumerate(None, -1, allowed_pids={1}, mode="classes")
    assert caught.value.code == "invalid_params"
