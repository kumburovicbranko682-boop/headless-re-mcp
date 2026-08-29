"""frida tool descriptions must name the fields the backends return."""

from __future__ import annotations

import ast
import time
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.frida.client import FridaClient, FridaError
from headless_re_mcp.tools.frida import build_frida_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_frida_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            for keyword in decorator.keywords:
                if (
                    keyword.arg == "name"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value == name
                ):
                    return ast.get_docstring(node) or ""
    return ""


class _Exports:
    def modules(self, limit: int = 64) -> list[dict[str, Any]]:
        del limit
        return [
            {"name": f"m{index}", "base": "0x1", "size": 1, "path": ""}
            for index in range(25)
        ]


class _Script:
    exports_sync = _Exports()

    def load(self) -> None:
        return None


class _Session:
    def create_script(self, source: str) -> _Script:
        return _Script()

    def detach(self) -> None:
        return None


class _Frida:
    def attach(self, pid: int) -> _Session:
        return _Session()


def test_frida_modules_says_when_the_page_is_not_the_whole_list() -> None:
    """The catalog named count and total and stopped there.

    Measured: 25 modules, limit 10 -> count 10, total 25, has_more True.
    An overnight pass that treated the page as complete because has_more
    was unnamed had no field to notice the rest.
    """
    client = FridaClient()
    client._available = True
    client._frida = _Frida()
    payload = client.modules(1, allowed_pid=1, limit=10)
    assert payload["count"] == 10
    assert payload["total"] == 25
    assert len(payload["modules"]) == 10
    assert payload["has_more"] is True
    doc = _tool_docstring("frida.modules")
    assert "has_more" in doc

class _ExportApi:
    """Fake exports RPC: a module with ``total`` exports, page bounded by count.

    Mirrors the embedded JS -- it enumerates every export, returns at most the
    requested page, and reports the full ``total`` (all.length) independently of
    the page size -- so a truncated page carries the real count, not len(page).
    """

    def __init__(self, total: int = 200) -> None:
        self._total = total

    def exports(self, name: str, count: int) -> dict[str, Any]:
        emitted = min(int(count), self._total)
        return {
            "found": True,
            "module": name,
            "base": "0x1",
            "exports": [
                {"name": f"e{index}", "address": "0x2", "type": "function"}
                for index in range(emitted)
            ],
            "total": self._total,
        }


class _ExportScript:
    def __init__(self, total: int) -> None:
        self.exports_sync = _ExportApi(total=total)

    def load(self) -> None:
        return None


class _ExportSession:
    def __init__(self, total: int) -> None:
        self._total = total

    def create_script(self, source: str) -> _ExportScript:
        return _ExportScript(self._total)

    def detach(self) -> None:
        return None


class _ExportFrida:
    def __init__(self, total: int = 200) -> None:
        self._total = total

    def attach(self, pid: int) -> _ExportSession:
        return _ExportSession(self._total)


def test_frida_exports_says_when_the_page_is_not_the_whole_table() -> None:
    """The catalog named found, module, base and exports, and stopped there.

    Measured: a module of 200 exports, page of 10 -> count 10, total 200,
    has_more True. An overnight pass that treated exports as the whole table
    had no field to notice the rest.
    """
    client = FridaClient()
    client._available = True
    client._frida = _ExportFrida()
    payload = client.exports(1, "ntdll.dll", allowed_pid=1, limit=10)
    assert payload["count"] == 10
    assert len(payload["exports"]) == 10
    assert payload["total"] == 200
    assert payload["has_more"] is True
    doc = _tool_docstring("frida.exports")
    assert "has_more" in doc
    assert "total" in doc


def test_frida_exports_of_a_small_module_reports_the_real_total_and_no_more() -> None:
    """A module with fewer exports than the page reports total == count, no more.

    The complementary branch to the truncated case: total is read from the
    script's field on both sides, so a small module (5 exports, page of 10) must
    come back count 5, total 5, has_more False -- not an inflated total that
    fakes a next page, and not a has_more that sends an agent chasing exports
    that are not there.
    """
    client = FridaClient()
    client._available = True
    client._frida = _ExportFrida(total=5)
    payload = client.exports(1, "libc.so", allowed_pid=1, limit=10)
    assert payload["count"] == 5
    assert payload["total"] == 5
    assert payload["has_more"] is False


class _ModulesDictExports:
    """The newer enum script answers modules() with a {modules, total} object.

    The device caps the returned list itself and reports the true total
    alongside it, so ``total`` here (200) is deliberately larger than the page
    it hands back (10) -- the two must not be conflated.
    """

    def modules(self, limit: int = 64) -> dict[str, Any]:
        del limit
        return {
            "modules": [
                {"name": f"m{index}", "base": "0x1", "size": 1, "path": ""}
                for index in range(10)
            ],
            "total": 200,
        }


class _ModulesDictScript:
    exports_sync = _ModulesDictExports()

    def load(self) -> None:
        return None


class _ModulesDictSession:
    def create_script(self, source: str) -> _ModulesDictScript:
        del source
        return _ModulesDictScript()

    def detach(self) -> None:
        return None


class _ModulesDictFrida:
    def attach(self, pid: int) -> _ModulesDictSession:
        del pid
        return _ModulesDictSession()


def test_frida_modules_dict_payload_trusts_the_device_total_over_the_page() -> None:
    """When the enum script returns an object, total comes from the device.

    Two payload shapes reach here across frida/enum-script versions: a bare list
    (the sibling test above) and a ``{modules, total}`` object. In the object
    form the device has already capped the list it sends and reports the real
    count separately, so ``total`` must be read from that field, not recomputed
    as ``len(page)``. Collapsing them would report ``total == count`` for a
    truncated page -- has_more False -- and an agent enumerating a large process's
    modules would stop at the first page believing it saw them all. Pin that the
    embedded 200 survives while the page stays the 10 rows actually returned.
    """
    client = FridaClient()
    client._available = True
    client._frida = _ModulesDictFrida()
    payload = client.modules(1, allowed_pid=1, limit=64)
    assert payload["count"] == 10
    assert len(payload["modules"]) == 10
    assert payload["total"] == 200
    assert payload["has_more"] is True


class _NonDictExportApi:
    """A script whose exports() answers with the wrong shape (a list, not a map)."""

    def exports(self, name: str, count: int) -> list[Any]:
        del name, count
        return ["not", "a", "dict"]


class _NonDictExportScript:
    exports_sync = _NonDictExportApi()

    def load(self) -> None:
        return None


class _NonDictExportSession:
    def create_script(self, source: str) -> _NonDictExportScript:
        del source
        return _NonDictExportScript()

    def detach(self) -> None:
        return None


class _NonDictExportFrida:
    def attach(self, pid: int) -> _NonDictExportSession:
        del pid
        return _NonDictExportSession()


def test_frida_exports_rejects_a_payload_that_is_not_an_object() -> None:
    """A malformed exports payload is a backend_error, not a crash on .get.

    exports reads found/module/base/exports off the RPC result with ``.get``, so
    a result that is not a dict -- a script that returned a bare list, or a
    protocol hiccup -- would raise AttributeError and be filed as an
    internal_error incident. The explicit isinstance check turns that into an
    honest backend_error naming the bad payload, the same class of device-outcome
    error the enumeration failures already use.
    """
    client = FridaClient()
    client._available = True
    client._frida = _NonDictExportFrida()
    with pytest.raises(FridaError) as caught:
        client.exports(1, "libc.so", allowed_pid=1)
    assert caught.value.code == "backend_error"
    assert "unexpected frida exports payload" in caught.value.message


class _Dev:
    def __init__(self, ident: str, name: str, kind: str) -> None:
        self.id = ident
        self.name = name
        self.type = kind


class _DeviceFrida:
    def enumerate_devices(self) -> list[_Dev]:
        return [
            _Dev("local", "Local System", "local"),
            _Dev("usb", "Pixel", "usb"),
        ]


def test_frida_devices_puts_the_list_in_devices_not_items() -> None:
    """The catalog never named the list field.

    Measured: two devices -> count 2, field is devices not items or
    enumerations. Looking for items after a successful call reads as Frida
    seeing none.
    """
    client = FridaClient()
    client._available = True
    client._frida = _DeviceFrida()
    payload = client.enumerate_devices()
    assert "items" not in payload
    assert "enumerations" not in payload
    assert payload["count"] == 2
    assert len(payload["devices"]) == 2
    assert payload["devices"][0]["id"] == "local"
    assert payload["devices"][0]["type"] == "local"
    doc = _tool_docstring("frida.devices")
    assert "Answers with devices" in doc
    assert "count" in doc

class _App:
    def __init__(self, index: int) -> None:
        self.identifier = f"com.app{index}"
        self.name = f"App{index}"
        self.pid = 0


class _Device:
    def enumerate_applications(self) -> list[_App]:
        return [_App(index) for index in range(25)]


def test_frida_applications_puts_the_list_in_applications_and_says_when_it_stopped() -> None:
    """The catalog never named the payload.

    Measured: 25 apps, limit 10 -> count 10, total 25, has_more True, field
    is applications not apps or packages. Looking for those after a
    successful call reads as an empty device, and a full page with no
    has_more reads as every installed app.
    """
    client = FridaClient()
    client._resolve_device = lambda device_id: _Device()  # type: ignore[method-assign]
    payload = client.applications("usb", limit=10)
    assert "apps" not in payload
    assert "packages" not in payload
    assert payload["count"] == 10
    assert payload["total"] == 25
    assert len(payload["applications"]) == 10
    assert payload["has_more"] is True
    doc = _tool_docstring("frida.applications")
    assert "Answers with applications" in doc
    assert "has_more" in doc
    # identifier is the spawn join key: the doc must say it is what frida.spawn
    # takes as package, or an agent cannot tell which of identifier/name to feed
    # spawn (and name -- a display label -- would be refused).
    assert "identifier" in doc
    assert "frida.spawn" in doc

class _JavaApi:
    def classes(self, name_filter: str, count: int) -> list[str]:
        return [f"c{index}" for index in range(int(count))]

    def methods(self, class_name: str, limit: int) -> dict[str, Any]:
        # Newer script shape: the page is bounded by the limit while total is
        # the class's full declared-method count. Model a class with one more
        # method than the page holds so has_more must fire off total, not off a
        # fetched extra.
        page = [f"m{index}" for index in range(int(limit))]
        return {"found": True, "methods": page, "total": int(limit) + 1}


class _JavaScript:
    exports_sync = _JavaApi()

    def load(self) -> None:
        return None


class _JavaSession:
    def create_script(self, source: str) -> _JavaScript:
        return _JavaScript()

    def detach(self) -> None:
        return None


class _JavaDevice:
    def attach(self, pid: int) -> _JavaSession:
        return _JavaSession()


def test_frida_java_classes_puts_the_list_in_classes_and_says_when_it_stopped() -> None:
    """The catalog never named the payload.

    Measured: 11 classes requested for a page of 10 -> count 10, has_more
    True, field is classes. Looking for class_list after a successful call
    reads as no classes, and a full page with no has_more reads as every
    loaded class.
    """
    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: _JavaDevice()  # type: ignore[method-assign]
    payload = client.java_enumerate(
        None, 1, allowed_pids={1}, mode="classes", limit=10
    )
    assert "class_list" not in payload
    assert payload["count"] == 10
    assert len(payload["classes"]) == 10
    assert payload["has_more"] is True
    doc = _tool_docstring("frida.java.classes")
    assert "Answers with classes" in doc
    assert "has_more" in doc

def test_frida_java_methods_puts_the_list_in_methods_and_says_when_it_stopped() -> None:
    """The catalog never named the payload.

    Measured: 11 methods requested for a page of 10 -> count 10, has_more
    True, field is methods. Looking for method_list after a successful call
    reads as no methods, and a full page with no has_more reads as every
    declared method.
    """
    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: _JavaDevice()  # type: ignore[method-assign]
    payload = client.java_enumerate(
        None, 1, allowed_pids={1}, mode="methods", class_name="Foo", limit=10
    )
    assert "method_list" not in payload
    assert payload["class_name"] == "Foo"
    assert payload["count"] == 10
    assert len(payload["methods"]) == 10
    assert payload["has_more"] is True
    # total is the class's full declared-method count, not the page: the fake
    # models 11 methods for a page of 10, so has_more must come off total, and
    # an agent learns the real size rather than only "there is more".
    assert payload["total"] == 11
    assert payload["found"] is True
    doc = _tool_docstring("frida.java.methods")
    assert "Answers with methods" in doc
    assert "has_more" in doc
    assert "total" in doc
    assert "found" in doc


class _JavaApiFound:
    """Newer script shape: methods() returns {found, methods}."""

    def __init__(self, *, found: bool, count: int) -> None:
        self._found = found
        self._count = count

    def methods(self, class_name: str, limit: int) -> dict[str, Any]:
        del class_name
        # Real JS caps the page at the limit but returns the full declared
        # count as total, so the fake does the same.
        page = [f"m{index}" for index in range(min(self._count, int(limit)))]
        return {
            "found": self._found,
            "methods": page,
            "total": self._count,
        }


def _java_client_returning(api: object) -> FridaClient:
    script = type("_S", (), {"exports_sync": api, "load": lambda self: None})()
    session = type(
        "_Sess",
        (),
        {"create_script": lambda self, source: script, "detach": lambda self: None},
    )()
    device = type("_Dev", (), {"attach": lambda self, pid: session})()
    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: device  # type: ignore[method-assign]
    return client


def test_frida_java_methods_reports_a_class_that_is_not_loaded_as_not_found() -> None:
    """found false with an empty list means the class name did not resolve.

    An unattended agent that read only the empty list would conclude the class
    has no methods, when in truth it was never loaded on the target.
    """
    client = _java_client_returning(_JavaApiFound(found=False, count=0))
    payload = client.java_enumerate(
        None, 1, allowed_pids={1}, mode="methods", class_name="Nope", limit=10
    )
    assert payload["found"] is False
    assert payload["methods"] == []
    assert payload["count"] == 0
    assert payload["has_more"] is False


def test_frida_java_methods_reports_a_loaded_class_with_methods_as_found() -> None:
    """found true with a full page still paginates via has_more."""
    client = _java_client_returning(_JavaApiFound(found=True, count=11))
    payload = client.java_enumerate(
        None, 1, allowed_pids={1}, mode="methods", class_name="Foo", limit=10
    )
    assert payload["found"] is True
    assert payload["count"] == 10
    assert payload["total"] == 11
    assert payload["has_more"] is True


def test_frida_java_methods_reports_a_loaded_class_with_no_methods_as_found() -> None:
    """found true with an empty list: loaded, but declares none of its own."""
    client = _java_client_returning(_JavaApiFound(found=True, count=0))
    payload = client.java_enumerate(
        None, 1, allowed_pids={1}, mode="methods", class_name="Marker", limit=10
    )
    assert payload["found"] is True
    assert payload["methods"] == []
    assert payload["count"] == 0
    assert payload["total"] == 0
    assert payload["has_more"] is False


class _JavaApiBareMethods:
    """Older script shape: methods() returns a bare list, no found/total."""

    def methods(self, class_name: str, limit: int) -> list[str]:
        del class_name
        return [f"m{index}" for index in range(min(3, int(limit)))]


def test_frida_java_methods_tolerates_a_bare_array_from_an_older_script() -> None:
    """A pre-dict script shape stays readable: found true, total the page.

    The dict shape carries found and total; a bare list (the older script)
    carries neither, so found falls back to true and total to the page length --
    the same defensive fallback modules and exports keep. It must not crash on
    the missing keys.
    """
    client = _java_client_returning(_JavaApiBareMethods())
    payload = client.java_enumerate(
        None, 1, allowed_pids={1}, mode="methods", class_name="Foo", limit=10
    )
    assert payload["found"] is True
    assert payload["methods"] == ["m0", "m1", "m2"]
    assert payload["count"] == 3
    assert payload["total"] == 3
    assert payload["has_more"] is False


def test_frida_java_methods_without_a_class_name_is_invalid_params() -> None:
    """methods mode has to name a class; the empty request is a caller error.

    The mode is chosen and the target attached, but with no class_name there is
    nothing to enumerate. Returning an empty methods list here would read as a
    real class that declares nothing, so the refusal must be invalid_params --
    a caller mistake -- not backend_error or a silent empty answer. Raised from
    inside the worker, it still has to arrive with its own code intact rather
    than being reclassified by the outer catch.
    """
    client = _java_client_returning(_JavaApi())
    with pytest.raises(FridaError) as info:
        client.java_enumerate(None, 1, allowed_pids={1}, mode="methods")
    assert info.value.code == "invalid_params"
    assert "class_name" in info.value.message


def test_frida_java_rejects_an_unknown_mode() -> None:
    """Only classes and methods exist; anything else is a caller error.

    A typo'd mode reaches the worker (device attached, script loaded) and then
    matches neither branch. It must be refused as invalid_params naming the two
    modes, not swallowed as an empty result that would look like a target with
    no classes and no methods.
    """
    client = _java_client_returning(_JavaApi())
    with pytest.raises(FridaError) as info:
        client.java_enumerate(None, 1, allowed_pids={1}, mode="everything")
    assert info.value.code == "invalid_params"
    assert "classes or methods" in info.value.message


class _AttachFailsDevice:
    def attach(self, pid: int) -> Any:
        raise RuntimeError("device offline")


def _java_client_with_device(device: object) -> FridaClient:
    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: device  # type: ignore[method-assign]
    return client


def test_frida_java_attach_failure_is_backend_error_naming_the_pid() -> None:
    """A frida error from attach is a target outcome, not an internal fault.

    When ``device.attach(pid)`` raises, the raw frida exception would otherwise
    reach the failure handler and be minted as an internal_error incident for
    what is a normal condition -- the pid exited, or the process refuses
    injection. java_enumerate classifies it as backend_error and carries the
    pid so the caller knows which target could not be reached. No session was
    opened, so there is nothing to leak.
    """
    client = _java_client_with_device(_AttachFailsDevice())
    with pytest.raises(FridaError) as info:
        client.java_enumerate(None, 7, allowed_pids={7}, mode="classes")
    assert info.value.code == "backend_error"
    assert "attach failed" in info.value.message
    assert info.value.details.get("pid") == 7


class _LoadFailsScript:
    exports_sync = _JavaApi()

    def load(self) -> None:
        raise RuntimeError("script would not compile")


class _LoadFailsSession:
    def __init__(self) -> None:
        self.detached = 0

    def create_script(self, source: str) -> Any:
        return _LoadFailsScript()

    def detach(self) -> None:
        self.detached += 1


class _LoadFailsDevice:
    def __init__(self) -> None:
        self.session = _LoadFailsSession()

    def attach(self, pid: int) -> Any:
        return self.session


def test_frida_java_script_failure_detaches_the_session_and_is_backend_error() -> None:
    """A script that will not load must not strand the attached session.

    Once attach succeeds the session is live; if ``script.load()`` then raises,
    the worker's finally has to detach it before the error leaves -- otherwise
    every failed enumeration leaks a frida session against the target. The
    failure itself is a backend outcome (a script this runtime rejects), so it
    surfaces as backend_error, not an internal_error incident.
    """
    device = _LoadFailsDevice()
    client = _java_client_with_device(device)
    with pytest.raises(FridaError) as info:
        client.java_enumerate(None, 1, allowed_pids={1}, mode="classes")
    assert info.value.code == "backend_error"
    assert "java enumeration failed" in info.value.message
    assert device.session.detached >= 1


class _SpawnDevice:
    def spawn(self, argv: list[str]) -> int:
        return 4242

    def resume(self, pid: int) -> None:
        return None


def test_frida_spawn_names_pid_not_process_id() -> None:
    """The catalog said spawn and never named the pid field.

    Measured: package com.example.app -> pid 4242, package, device usb.
    There is no process_id or spawned field. Looking for process_id after a
    successful spawn reads as a launch that returned no process.
    """
    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: _SpawnDevice()  # type: ignore[method-assign]
    payload = client.spawn("usb", "com.example.app")
    assert "process_id" not in payload
    assert "spawned" not in payload
    assert payload["pid"] == 4242
    assert payload["package"] == "com.example.app"
    assert payload["device"] == "usb"


def test_frida_spawn_refuses_a_path_or_bare_name() -> None:
    from headless_re_mcp.backends.frida.client import FridaError

    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: _SpawnDevice()  # type: ignore[method-assign]
    for package in (r"C:\Windows\notepad.exe", "/system/bin/sh", "notapackage"):
        with pytest.raises(FridaError) as caught:
            client.spawn("usb", package)
        assert caught.value.code == "invalid_params"
    doc = _tool_docstring("frida.spawn")
    assert "Answers with pid" in doc
    assert "There is no process_id" in doc
    # The package spawn wants is the identifier frida.applications reports; the
    # doc must name that source so an agent knows where a valid value comes from
    # and that a display name or apk path (refused here) is not it.
    assert "frida.applications" in doc


def test_frida_spawn_times_out_and_kills_the_probe_process() -> None:
    """device.spawn / resume with no deadline parked a worker forever.

    Measured: resume that never returned left the spawned pid running and the
    caller blocked. The probe now kills that pid and raises timeout.
    """
    killed: list[int] = []

    class _Device:
        def spawn(self, package: str) -> int:
            del package
            return 4242

        def resume(self, pid: int) -> None:
            del pid
            time.sleep(10)

        def kill(self, pid: int) -> None:
            killed.append(pid)

    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: _Device()  # type: ignore[method-assign]
    started = time.monotonic()
    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "com.example.app", timeout=0.2)
    assert time.monotonic() - started < 2.0
    assert caught.value.code == "timeout"
    assert killed == [4242]


def test_frida_spawn_kills_the_suspended_process_when_resume_fails() -> None:
    """A spawn that cannot be resumed must not leak a suspended process.

    frida.spawn starts the target suspended and a separate resume runs it. If
    resume raises -- a device that went busy, a process that died between the two
    calls -- the pid is already occupying the device in a frozen state, so the
    backend kills it before failing rather than leaving it parked. The error is a
    backend_error (a device outcome, not a fault in this process) that names the
    pid it killed so the caller knows the launch was cleaned up, not abandoned.
    """
    killed: list[int] = []

    class _ResumeFails:
        def spawn(self, package: str) -> int:
            del package
            return 4242

        def resume(self, pid: int) -> None:
            del pid
            raise RuntimeError("device busy")

        def kill(self, pid: int) -> None:
            killed.append(pid)

    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: _ResumeFails()  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "com.example.app")
    assert caught.value.code == "backend_error"
    # The spawned pid is torn down, not left frozen on the device.
    assert killed == [4242]
    assert caught.value.details.get("pid") == 4242
    assert caught.value.details.get("package") == "com.example.app"
    assert "resume failed" in caught.value.message
    assert "killed" in caught.value.message


def test_frida_spawn_that_never_starts_reports_backend_error_and_kills_nothing() -> None:
    """A spawn that fails outright has no pid to reclaim.

    When ``device.spawn`` itself raises, no process was created, so there is
    nothing to kill -- the failure is classified as a backend_error (the same
    device-outcome code the resume path uses) and no kill is attempted. This is
    the branch distinct from the resume rollback: no pid was ever captured.
    """
    killed: list[int] = []

    class _SpawnFails:
        def spawn(self, package: str) -> int:
            del package
            raise RuntimeError("no such package on this device")

        def resume(self, pid: int) -> None:  # pragma: no cover - never reached
            del pid

        def kill(self, pid: int) -> None:
            killed.append(pid)

    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: _SpawnFails()  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "com.example.app")
    assert caught.value.code == "backend_error"
    assert "spawn failed" in caught.value.message
    assert killed == []


def test_frida_java_perform_times_out_and_detaches_the_probe() -> None:
    """Java.perform on a non-JIT process used to occupy the worker forever.

    Measured: exports_sync.classes that never returned left the session
    attached. The probe now detaches and raises timeout.
    """
    state = {"detached": False}

    class _HangApi:
        def classes(self, name_filter: str, count: int) -> list[str]:
            del name_filter, count
            time.sleep(10)
            return []

    class _HangScript:
        exports_sync = _HangApi()

        def load(self) -> None:
            return None

    class _HangSession:
        def create_script(self, source: str) -> _HangScript:
            del source
            return _HangScript()

        def detach(self) -> None:
            state["detached"] = True

    class _HangDevice:
        def attach(self, pid: int) -> _HangSession:
            del pid
            return _HangSession()

    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: _HangDevice()  # type: ignore[method-assign]
    started = time.monotonic()
    with pytest.raises(FridaError) as caught:
        client.java_enumerate(None, 1, allowed_pids={1}, mode="classes", timeout=0.2)
    assert time.monotonic() - started < 2.0
    assert caught.value.code == "timeout"
    assert state["detached"] is True


def test_frida_resolve_device_times_out_on_a_wedged_usb_lookup(monkeypatch: Any) -> None:
    """A USB lookup that never returns used to hold the worker forever.

    Measured: get_usb_device(timeout=5) that slept 10s still returned only
    after 10.000s -- frida's timeout= kwarg is not a deadline this side can
    enforce. spawn / applications resolve the device before their own
    deadline starts, so the lookup now shares the daemon-thread deadline and
    raises timeout instead of wedging.
    """
    monkeypatch.setattr("headless_re_mcp.backends.frida.client._PROBE_TIMEOUT_S", 0.2)

    class _WedgedFrida:
        def get_usb_device(self, timeout: int = 0) -> Any:
            del timeout
            time.sleep(10)
            return object()

    client = FridaClient()
    client._available = True
    client._frida = _WedgedFrida()
    started = time.monotonic()
    with pytest.raises(FridaError) as caught:
        client._resolve_device("usb")
    assert time.monotonic() - started < 2.0
    assert caught.value.code == "timeout"


def test_frida_add_remote_device_times_out_on_a_wedged_endpoint(
    monkeypatch: Any,
) -> None:
    """A host:port add that never returns used to hold the worker forever.

    Measured: add_remote_device that slept 10s still returned only after
    10.000s. The add now shares the daemon-thread deadline and raises
    timeout instead of holding the worker until the process dies.
    """
    monkeypatch.setattr("headless_re_mcp.backends.frida.client._PROBE_TIMEOUT_S", 0.2)

    class _Manager:
        def get_device(self, endpoint: str, timeout: int = 0) -> Any:
            del endpoint, timeout
            raise RuntimeError("not registered")

        def add_remote_device(self, endpoint: str) -> Any:
            del endpoint
            time.sleep(10)
            return object()

    class _WedgedFrida:
        def get_device_manager(self) -> _Manager:
            return _Manager()

    client = FridaClient()
    client._available = True
    client._frida = _WedgedFrida()
    started = time.monotonic()
    with pytest.raises(FridaError) as caught:
        client.add_remote_device("127.0.0.1:27042")
    assert time.monotonic() - started < 2.0
    assert caught.value.code == "timeout"


def test_frida_device_connect_names_connected_and_device(monkeypatch: Any) -> None:
    """The catalog said bind a device and never named the payload.

    Measured against the USB path: connected True and device holding the
    resolved id/name/type, not the usb alias. There is no top-level
    device_id or ok field. Looking for device_id after a successful
    connect reads as a bind that returned no device.
    """
    from headless_re_mcp.core.service_frida import FridaDeviceMixin
    from headless_re_mcp.core.session import SessionRegistry

    class _UsbDevice:
        id = "ABCD1234"
        name = "Pixel 8"
        type = "usb"

    class _Client:
        def _resolve_device(self, device_id: str) -> _UsbDevice:
            assert device_id == "usb"
            return _UsbDevice()

    class _Repo:
        def record_backend(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

        def append_timeline(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

    class _Service(FridaDeviceMixin):
        def __init__(self) -> None:
            self.registry = SessionRegistry()
            self.repository = _Repo()

    monkeypatch.setattr(
        "headless_re_mcp.core.service_frida.FridaClient", lambda: _Client()
    )
    service = _Service()
    session = service.registry.create("https://example.invalid")
    result = service.frida_device_connect(session.id, device_id="usb")
    assert result.ok
    assert result.data is not None
    assert "device_id" not in result.data
    assert "ok" not in result.data
    assert result.data["connected"] is True
    assert result.data["device"] == {
        "id": "ABCD1234",
        "name": "Pixel 8",
        "type": "usb",
    }
    auth = service.registry.get(session.id).metadata["frida_authorized"]
    assert auth["device_id"] == "ABCD1234"
    doc = _tool_docstring("frida.device.connect")
    assert "Answers with connected" in doc
    assert "There is no top-level device_id" in doc

def test_frida_server_ensure_description_names_running_not_ok() -> None:
    """The catalog said start frida-server and never named the success field.

    Measured against AdbBackend.ensure_frida_server: every return carries
    running, pushed and port, plus note when the process is not visible.
    There is no ok, started or server field. Envelope success with running
    false means the process is not visible. Looking for started after a
    successful call when the server was already up (running true, pushed
    false) reads as a failed start, so the agent pushes and launches again.
    """
    from headless_re_mcp.backends.adb.client import AdbBackend

    source = Path(AdbBackend.ensure_frida_server.__code__.co_filename).read_text(
        encoding="utf-8"
    )
    start = source.index("def ensure_frida_server")
    chunk = source[start : source.index("\n    def forward(", start)]
    returned = chunk[chunk.index("if visible:") :]
    assert '"running"' in returned
    assert '"pushed"' in returned
    assert '"port"' in returned
    assert '"ok"' not in returned
    assert '"started"' not in returned
    described = _tool_docstring("frida.server.ensure")
    assert "Answers with running" in described
    assert "pushed" in described
    assert "no ok field" in described


def test_add_remote_device_reuses_a_device_already_registered() -> None:
    """Re-adding the same endpoint used to churn the device manager."""

    class _Device:
        id = "10.0.0.1:27042"
        name = "remote"
        type = "remote"

    class _Manager:
        def __init__(self) -> None:
            self.added = 0

        def get_device(self, endpoint: str, timeout: int = 1) -> _Device:
            del endpoint, timeout
            return _Device()

        def add_remote_device(self, endpoint: str) -> _Device:
            del endpoint
            self.added += 1
            return _Device()

    class _Frida:
        def __init__(self) -> None:
            self.manager = _Manager()

        def get_device_manager(self) -> _Manager:
            return self.manager

    client = FridaClient()
    client._available = True
    client._frida = _Frida()
    first = client.add_remote_device("10.0.0.1:27042")
    second = client.add_remote_device("10.0.0.1:27042")
    assert first["id"] == "10.0.0.1:27042"
    assert second["id"] == "10.0.0.1:27042"
    assert client._frida.manager.added == 0
