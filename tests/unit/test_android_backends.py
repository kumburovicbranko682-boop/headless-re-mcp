"""Android backend boundaries: argument validation, no shell passthrough, auth.

These cover the properties that make the Android surface safe to expose, not the
happy paths (which need a real device and live in the integration gates).
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError, _check_package, _check_serial
from headless_re_mcp.backends.apktool import ApktoolClient, ApktoolError
from headless_re_mcp.backends.frida.client import FridaClient, FridaError
from headless_re_mcp.core.models import TargetKind
from headless_re_mcp.core.session import classify_target, describe_apk
from headless_re_mcp.tools.catalog import COMMAND_CATALOG, CommandTransport


def _apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", b"dex\n035\x00")
        archive.writestr("lib/arm64-v8a/libx.so", b"\x7fELF")
        archive.writestr("META-INF/CERT.RSA", b"sig")
    return path


class TestNoShellPassthrough:
    def test_catalog_exposes_no_generic_device_shell(self) -> None:
        """The debugger surface has no dynamic.command; devices get the same rule."""
        names = {spec.name for spec in COMMAND_CATALOG.for_transport(CommandTransport.MCP)}
        assert "device.shell" not in names
        assert "device.exec" not in names
        assert not any(name.endswith((".shell", ".command", ".exec")) for name in names)

    def test_adb_backend_has_no_public_shell_method(self) -> None:
        public = {name for name in dir(AdbBackend) if not name.startswith("_")}
        assert "shell" not in public
        assert "exec" not in public


class TestAdbArgumentValidation:
    @pytest.mark.parametrize(
        "serial",
        ["", "a b", "127.0.0.1:5555; rm -rf /", "dev|cat", "$(whoami)", "x" * 200],
    )
    def test_hostile_serials_are_rejected(self, serial: str) -> None:
        with pytest.raises(AdbError) as info:
            _check_serial(serial)
        assert info.value.code == "invalid_params"

    @pytest.mark.parametrize("serial", ["127.0.0.1:5555", "emulator-5554", "ZY223KDTM7"])
    def test_valid_serials_pass(self, serial: str) -> None:
        assert _check_serial(serial) == serial

    @pytest.mark.parametrize(
        "package",
        ["", "notapackage", "com.x; id", "com.x/../y", "com .x", "-rf"],
    )
    def test_hostile_package_names_are_rejected(self, package: str) -> None:
        with pytest.raises(AdbError) as info:
            _check_package(package)
        assert info.value.code == "invalid_params"

    @pytest.mark.parametrize("package", ["com.example.app", "a.b", "com.foo_bar.baz2"])
    def test_valid_package_names_pass(self, package: str) -> None:
        assert _check_package(package) == package

    def test_properties_at_the_cap_say_so_and_getprop_is_bounded(self) -> None:
        """A full getprop used to be cut at `limit` with only count.

        Measured: 10 properties, limit 3, reply was count=3 and no total or
        has_more, and getprop was invoked with timeout=None. An unattended
        agent treated the page as the device, and a wedged adb held the
        worker until the process was killed.
        """

        class _Dev:
            def __init__(self) -> None:
                self.timeout: object = "unset"

            def shell(self, cmd: object, timeout: object = None) -> str:
                self.timeout = timeout
                return "\n".join(f"[ro.prop.{index}]: [{index}]" for index in range(10))

        class _Backend(AdbBackend):
            def __init__(self, device: _Dev) -> None:
                self._adbutils = object()
                self._available = True
                self._adb_path = None
                self.device = device

            def _device(self, serial: str) -> _Dev:
                assert serial
                return self.device

        device = _Dev()
        result = _Backend(device).properties("emulator-5554", limit=3)
        assert device.timeout == 15.0
        assert result["count"] == 3
        assert result["total"] == 10
        assert result["has_more"] is True
        whole = _Backend(_Dev()).properties("emulator-5554", limit=20)
        assert whole["has_more"] is False
        assert whole["total"] == 10

    def test_packages_at_the_cap_say_so_and_pm_is_bounded(self) -> None:
        """pm list used to return every package and wait on adb forever.

        Measured: 80 packages, no limit in the reply, timeout=None. A busy
        emulator listing is a full page that looks complete, and a wedged
        adb holds the worker.
        """

        class _Dev:
            def __init__(self) -> None:
                self.timeout: object = "unset"

            def shell(self, cmd: object, timeout: object = None) -> str:
                self.timeout = timeout
                return "\n".join(f"package:com.app{index}" for index in range(80))

        class _Backend(AdbBackend):
            def __init__(self, device: _Dev) -> None:
                self._adbutils = object()
                self._available = True
                self._adb_path = None
                self.device = device

            def _device(self, serial: str) -> _Dev:
                return self.device

        device = _Dev()
        result = _Backend(device).packages("emulator-5554", limit=10)
        assert device.timeout == 15.0
        assert result["count"] == 10
        assert result["total"] == 80
        assert result["has_more"] is True
        assert len(result["packages"]) == 10

    def test_logcat_does_not_wait_on_adb_forever(self) -> None:
        """logcat -d still has to come back if adb has stopped answering.

        Measured: the dump was invoked with timeout=None. A wedged adb
        held the worker; the -t line cap does not bound the wait.
        """

        class _Dev:
            def __init__(self) -> None:
                self.timeout: object = "unset"

            def shell(self, cmd: object, timeout: object = None) -> str:
                self.timeout = timeout
                return "line\n"

        class _Backend(AdbBackend):
            def __init__(self, device: _Dev) -> None:
                self._adbutils = object()
                self._available = True
                self._adb_path = None
                self.device = device

            def _device(self, serial: str) -> _Dev:
                return self.device

        device = _Dev()
        result = _Backend(device).logcat("emulator-5554", lines=10)
        assert device.timeout == 15.0
        assert result["requested"] == 10

    def test_logcat_says_when_the_dump_was_cut(self) -> None:
        """A 5-line page used to look like the whole dump.

        Measured: 20 dumped lines, lines=5, reply had 5 lines and only
        requested. The other 15 looked like they were never logged.
        """

        class _Dev:
            def shell(self, cmd: object, timeout: object = None) -> str:
                return "\n".join(f"line {index}" for index in range(20))

        class _Backend(AdbBackend):
            def __init__(self, device: _Dev) -> None:
                self._adbutils = object()
                self._available = True
                self._adb_path = None
                self.device = device

            def _device(self, serial: str) -> _Dev:
                return self.device

        result = _Backend(_Dev()).logcat("emulator-5554", lines=5)
        assert result["count"] == 5
        assert result["total"] == 20
        assert result["has_more"] is True
        assert result["lines"][0] == "line 15"

        complete = _Backend(_Dev()).logcat("emulator-5554", lines=20)
        assert complete["has_more"] is False
        assert complete["total"] == 20

    def test_launch_does_not_wait_on_adb_forever(self) -> None:
        """monkey used to be invoked with no deadline.

        Measured: timeout=None. A wedged adb or a monkey that never
        returns held the worker for the life of the process.
        """

        class _Dev:
            def __init__(self) -> None:
                self.timeout: object = "unset"

            def shell(self, cmd: object, timeout: object = None) -> str:
                self.timeout = timeout
                return "Events injected: 1"

        class _Backend(AdbBackend):
            def __init__(self, device: _Dev) -> None:
                self._adbutils = object()
                self._available = True
                self._adb_path = None
                self.device = device

            def _device(self, serial: str) -> _Dev:
                return self.device

        device = _Dev()
        result = _Backend(device).launch("emulator-5554", "com.example.app")
        assert device.timeout == 15.0
        assert result["launched"] is True

    def test_launch_is_false_when_monkey_did_not_inject(self) -> None:
        """A returned monkey command used to be reported as launched.

        Measured: empty output, 'No activities found', and an argv error
        all came back launched=True. An unattended agent then waited for
        an activity that never appeared.
        """

        class _Dev:
            def __init__(self, text: str) -> None:
                self.text = text

            def shell(self, cmd: object, timeout: object = None) -> str:
                return self.text

        class _Backend(AdbBackend):
            def __init__(self, device: _Dev) -> None:
                self._adbutils = object()
                self._available = True
                self._adb_path = None
                self.device = device

            def _device(self, serial: str) -> _Dev:
                return self.device

        aborted = _Backend(_Dev("** No activities found to run, monkey aborted.")).launch(
            "emulator-5554", "com.example.app"
        )
        assert aborted["launched"] is False
        assert "No activities found" in str(aborted.get("note"))

        empty = _Backend(_Dev("")).launch("emulator-5554", "com.example.app")
        assert empty["launched"] is False

        injected = _Backend(_Dev("arg: -p\nEvents injected: 1\n")).launch(
            "emulator-5554", "com.example.app"
        )
        assert injected["launched"] is True
        assert "note" not in injected

    def test_screenshot_does_not_wait_on_adb_forever(self, tmp_path: Path) -> None:
        """adbutils screenshot used to run with no deadline.

        Measured: screenshot() was invoked with no timeout. A wedged adb
        held the worker for the life of the process.
        """

        class _Dev:
            def __init__(self) -> None:
                self.timeout: object = "unset"

            def shell(
                self, cmd: object, timeout: object = None, encoding: object = "utf-8"
            ) -> bytes:
                self.timeout = timeout
                self.encoding = encoding
                return b"\x89PNG\r\n\x1a\n" + b"\x00" * 8

            def screenshot(self) -> object:
                raise AssertionError("unbounded screenshot")

        class _Backend(AdbBackend):
            def __init__(self, device: _Dev) -> None:
                self._adbutils = object()
                self._available = True
                self._adb_path = None
                self.device = device

            def _device(self, serial: str) -> _Dev:
                return self.device

        device = _Dev()
        out = tmp_path / "shot.png"
        result = _Backend(device).screenshot("emulator-5554", out)
        assert device.timeout == 20.0
        assert out.is_file()
        assert out.read_bytes().startswith(b"\x89PNG")
        assert result["path"] == str(out)

    def test_uninstall_does_not_wait_on_adb_forever(self) -> None:
        """adbutils uninstall used to run with no deadline.

        Measured: uninstall(pkg) was invoked with no timeout. A wedged
        adb held the worker for the life of the process.
        """

        class _Dev:
            def __init__(self) -> None:
                self.timeout: object = "unset"
                self.cmd: object = None

            def shell(self, cmd: object, timeout: object = None) -> str:
                self.cmd = cmd
                self.timeout = timeout
                return "Success"

            def uninstall(self, pkg: str) -> None:
                raise AssertionError("unbounded uninstall")

        class _Backend(AdbBackend):
            def __init__(self, device: _Dev) -> None:
                self._adbutils = object()
                self._available = True
                self._adb_path = None
                self.device = device

            def _device(self, serial: str) -> _Dev:
                return self.device

        device = _Dev()
        result = _Backend(device).uninstall("emulator-5554", "com.example.app")
        assert device.timeout == 30.0
        assert device.cmd == ["pm", "uninstall", "com.example.app"]
        assert result["uninstalled"] is True

    def test_force_stop_does_not_wait_on_adb_forever(self) -> None:
        """am force-stop used to be invoked with no deadline.

        Measured: timeout=None. A wedged adb held the worker for the
        life of the process. The command itself is short; the wait is not.
        """

        class _Dev:
            def __init__(self) -> None:
                self.timeout: object = "unset"

            def shell(self, cmd: object, timeout: object = None) -> str:
                self.timeout = timeout
                return ""

        class _Backend(AdbBackend):
            def __init__(self, device: _Dev) -> None:
                self._adbutils = object()
                self._available = True
                self._adb_path = None
                self.device = device

            def _device(self, serial: str) -> _Dev:
                return self.device

        device = _Dev()
        result = _Backend(device).force_stop("emulator-5554", "com.example.app")
        assert device.timeout == 15.0
        assert result["stopped"] is True

    def test_current_activity_does_not_wait_on_adb_forever(self) -> None:
        """app_current used three dumpsys calls with no deadline.

        Measured: app_current() was invoked with no timeout. adbutils
        retries and defaults the socket to 600s. A wedged adb held the
        worker; the window dump also had no size cap.
        """

        class _Dev:
            def __init__(self) -> None:
                self.timeouts: list[object] = []

            def shell(self, cmd: object, timeout: object = None) -> str:
                self.timeouts.append(timeout)
                return (
                    "mCurrentFocus=Window{41b37570 u0 com.example.app/.MainActivity}"
                )

            def app_current(self) -> object:
                raise AssertionError("unbounded app_current")

        class _Backend(AdbBackend):
            def __init__(self, device: _Dev) -> None:
                self._adbutils = object()
                self._available = True
                self._adb_path = None
                self.device = device

            def _device(self, serial: str) -> _Dev:
                return self.device

        device = _Dev()
        result = _Backend(device).current_activity("emulator-5554")
        assert device.timeouts == [15.0]
        assert result["package"] == "com.example.app"
        assert result["activity"] == ".MainActivity"

    def test_list_devices_does_not_wait_on_get_state(self) -> None:
        """Each listed serial used to trigger an unbounded get_state.

        Measured: device_list then get_state per device, no timeout.
        Two serials meant two more adb hops. A wedged adb held the
        worker; device_list already only yields state=device.
        """

        class _Listed:
            def __init__(self, serial: str) -> None:
                self.serial = serial

        class _Client:
            def __init__(self) -> None:
                self.get_state_calls = 0

            def device_list(self) -> list[_Listed]:
                return [_Listed("emu-1"), _Listed("emu-2")]

            def device(self, serial: str | None = None) -> object:
                outer = self

                class _Dev:
                    def get_state(self) -> str:
                        outer.get_state_calls += 1
                        return "device"

                return _Dev()

        class _Backend(AdbBackend):
            def __init__(self, client: _Client) -> None:
                self._adbutils = object()
                self._available = True
                self._adb_path = None
                self._c = client

            def _client(self) -> _Client:
                return self._c

        client = _Client()
        result = _Backend(client).list_devices()
        assert client.get_state_calls == 0
        assert result["count"] == 2
        assert [item["state"] for item in result["devices"]] == ["device", "device"]

    def test_info_does_not_wait_on_adb_forever(self) -> None:
        """info used six unbounded adbutils calls.

        Measured: get_state, prop.model, prop.device, and three getprop
        keys were invoked with no timeout. A wedged adb held the worker
        for the life of the process.
        """

        class _Dev:
            def __init__(self) -> None:
                self.timeout: object = "unset"
                self.cmd: object = None

            def shell(self, cmd: object, timeout: object = None) -> str:
                self.cmd = cmd
                self.timeout = timeout
                return (
                    "[ro.product.model]: [Pixel]\n"
                    "[ro.product.device]: [pixel]\n"
                    "[ro.build.version.sdk]: [33]\n"
                    "[ro.build.version.release]: [13]\n"
                    "[ro.product.cpu.abi]: [arm64-v8a]\n"
                )

            def get_state(self) -> str:
                raise AssertionError("unbounded get_state")

            def getprop(self, name: str) -> str:
                raise AssertionError(f"unbounded getprop {name}")

        class _Backend(AdbBackend):
            def __init__(self, device: _Dev) -> None:
                self._adbutils = object()
                self._available = True
                self._adb_path = None
                self.device = device

            def _device(self, serial: str) -> _Dev:
                return self.device

        device = _Dev()
        result = _Backend(device).info("emulator-5554")
        assert device.timeout == 15.0
        assert device.cmd == "getprop"
        assert result["model"] == "Pixel"
        assert result["sdk"] == "33"
        assert result["state"] == "device"

    def test_missing_adbutils_degrades_instead_of_raising_import_error(self) -> None:
        backend = AdbBackend()
        if backend.available:
            pytest.skip("adbutils installed — degradation path not exercised (skip != pass)")
        with pytest.raises(AdbError) as info:
            backend.list_devices()
        assert info.value.code == "capability_unavailable"


class TestDeviceScreenshotIsNotARegisteredArtifact:
    def test_description_matches_the_empty_artifact_table(self, tmp_path: Path) -> None:
        """The tool said PNG artifact; artifacts.list stayed empty.

        Measured: device.screenshot wrote a file and returned path, with
        no artifact_id. list_artifacts count=0. An unattended agent then
        called artifacts.read and concluded the capture had failed.
        """
        from dataclasses import replace

        from headless_re_mcp.config import Settings
        from headless_re_mcp.core.service import AnalysisService
        from headless_re_mcp.tools.device import build_device_tools

        class _Fake(AdbBackend):
            def __init__(self) -> None:
                self._adbutils = object()
                self._available = True
                self._adb_path = None

            def screenshot(self, serial: str, out_path: Path) -> dict[str, Any]:
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_bytes(b"\x89PNG\r\n")
                return {"path": str(out_path), "serial": serial}

        settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
        service = AnalysisService(settings)
        try:
            service._backend = lambda: _Fake()  # type: ignore[method-assign]
            result = service.device_screenshot("emulator-5554")
            assert result.ok and result.data is not None
            assert "artifact_id" not in result.data
            listed = service.repository.list_artifacts()
            assert listed["count"] == 0
            assert listed["total"] == 0

            tools = {item.name: item for item in build_device_tools(service)}
            doc = tools["device.screenshot"].handler.__doc__ or ""
            assert "not a registered artifact" in doc
            assert "path" in doc
        finally:
            service.close_all()


class TestDevicePullIsNotARegisteredArtifact:
    def test_description_matches_the_empty_artifact_table(self, tmp_path: Path) -> None:
        """The tool said local artifact; artifacts.list stayed empty.

        Measured: device.pull wrote a file and returned local, with no
        artifact_id. list_artifacts count=0.
        """
        from dataclasses import replace

        from headless_re_mcp.config import Settings
        from headless_re_mcp.core.service import AnalysisService
        from headless_re_mcp.tools.device import build_device_tools

        class _Fake(AdbBackend):
            def __init__(self) -> None:
                self._adbutils = object()
                self._available = True
                self._adb_path = None

            def pull(self, serial: str, remote_path: str, local_path: Path) -> dict[str, Any]:
                local_path.parent.mkdir(parents=True, exist_ok=True)
                local_path.write_bytes(b"data")
                return {"remote": remote_path, "local": str(local_path)}

        settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
        service = AnalysisService(settings)
        try:
            service._backend = lambda: _Fake()  # type: ignore[method-assign]
            result = service.device_pull("emulator-5554", "/sdcard/x.bin")
            assert result.ok and result.data is not None
            assert "artifact_id" not in result.data
            listed = service.repository.list_artifacts()
            assert listed["count"] == 0
            assert listed["total"] == 0

            tools = {item.name: item for item in build_device_tools(service)}
            doc = tools["device.pull"].handler.__doc__ or ""
            assert "not a registered artifact" in doc
            assert "local" in doc
        finally:
            service.close_all()


class TestFridaTargetAuthorization:
    def test_device_operations_refuse_unauthorized_pid(self) -> None:
        client = FridaClient()
        if not client.available:
            pytest.skip("frida not installed — authorization path not exercised (skip != pass)")
        with pytest.raises(FridaError) as info:
            client.java_enumerate(
                "usb", 4242, allowed_pids=[1, 2, 3], mode="classes", limit=1
            )
        assert info.value.code == "permission_denied"
        assert info.value.details["pid"] == 4242

    def test_device_hook_refuses_unauthorized_pid(self) -> None:
        client = FridaClient()
        if not client.available:
            pytest.skip("frida not installed — authorization path not exercised (skip != pass)")
        with pytest.raises(FridaError) as info:
            client.hook_template_device("usb", 99, "noop", allowed_pids=[7])
        assert info.value.code == "permission_denied"

    def test_local_single_pid_rule_is_unchanged(self) -> None:
        """The pre-existing PE contract must survive the device generalisation."""
        client = FridaClient()
        if not client.available:
            pytest.skip("frida not installed — authorization path not exercised (skip != pass)")
        with pytest.raises(FridaError) as info:
            client.modules(4242, allowed_pid=4243, limit=1)
        assert info.value.code == "permission_denied"

    def test_unknown_hook_template_is_rejected_with_allowed_list(self) -> None:
        client = FridaClient()
        if not client.available:
            pytest.skip("frida not installed — template path not exercised (skip != pass)")
        with pytest.raises(FridaError) as info:
            client.hook_template_device("usb", 5, "arbitrary-script", allowed_pids=[5])
        assert info.value.code == "invalid_params"
        assert "android_ssl_unpin" in info.value.details["allowed"]


class _FakeScript:
    def __init__(self) -> None:
        self.loaded = False
        self.destroyed = False

    def load(self) -> None:
        self.loaded = True


class _FakeSession:
    def __init__(self) -> None:
        self.script = _FakeScript()
        self.detached = False

    def create_script(self, source: str) -> _FakeScript:
        assert source
        return self.script

    def detach(self) -> None:
        # What frida really does: detaching destroys every script in the
        # session. Measured on 16.5.9 via script.is_destroyed.
        self.detached = True
        self.script.destroyed = True


class _FakeFrida:
    def __init__(self) -> None:
        self.session = _FakeSession()

    def attach(self, pid: int) -> _FakeSession:
        assert pid > 0
        return self.session

    def get_usb_device(self, **_: object) -> _FakeFrida:
        return self

    def get_local_device(self) -> _FakeFrida:
        return self

    def get_device(self, device_id: str, **_: object) -> _FakeFrida:
        assert device_id
        return self


class TestHookTemplateSaysWhatItActuallyLeavesBehind:
    """The hook is gone before the caller reads the reply.

    Every operation detaches in a finally, which is what stops a failed call
    leaving an agent resident in someone else's process -- but for a hook that
    means the thing the caller asked for stops existing immediately. Reporting
    only ``loaded: True`` reads as "it is hooked now", and an unattended agent
    would then wait for output that can never arrive.
    """

    def _client(self) -> tuple[FridaClient, _FakeFrida]:
        client = FridaClient()
        fake = _FakeFrida()
        client._frida = fake
        client._available = True
        return client, fake

    def test_local_hook_reports_that_nothing_stays_hooked(self) -> None:
        client, fake = self._client()
        payload = client.hook_template(4242, "noop", allowed_pid=4242)

        assert payload["loaded"] is True
        assert payload["persisted"] is False
        assert "nothing stays hooked" in payload["note"]
        # The disclosure has to match the behaviour, not just soften it.
        assert fake.session.detached is True
        assert fake.session.script.destroyed is True

    def test_device_hook_reports_the_same(self) -> None:
        client, fake = self._client()
        payload = client.hook_template_device("usb", 4242, "noop", allowed_pids=[4242])

        assert payload["loaded"] is True
        assert payload["persisted"] is False
        assert fake.session.script.destroyed is True


class _FakeCall:
    def __init__(self, index: int) -> None:
        self.class_name = f"Lcom/example/Caller{index};"
        self.name = "invoke"


class _FakeMethod:
    def __init__(self, name: str, callers: int) -> None:
        self.name = name
        self._callers = callers

    def is_external(self) -> bool:
        return False

    def get_xref_from(self) -> list[tuple[object, _FakeCall, int]]:
        return [(None, _FakeCall(index), index) for index in range(self._callers)]


class _FakeParsed:
    def __init__(self, methods: list[_FakeMethod]) -> None:
        self.analysis = self
        self._methods = methods

    def get_methods(self) -> list[_FakeMethod]:
        return self._methods


class TestApkXrefsSayWhenTheyStopped:
    """A caller list that hit the cap looks exactly like one that ended."""

    def _client(self, monkeypatch: pytest.MonkeyPatch, callers: int) -> Any:
        from headless_re_mcp.backends.apk.client import ApkClient

        client = ApkClient()
        monkeypatch.setattr(
            ApkClient,
            "_parsed",
            lambda self, path: _FakeParsed([_FakeMethod("decrypt", callers)]),
        )
        return client

    def test_hitting_the_cap_is_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = self._client(monkeypatch, callers=25)
        result = client.xrefs(tmp_path / "app.apk", "decrypt", limit=10)

        assert result["count"] == 10
        assert result["has_more"] is True

    def test_a_complete_answer_is_not_labelled_partial(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = self._client(monkeypatch, callers=3)
        result = client.xrefs(tmp_path / "app.apk", "decrypt", limit=10)

        assert result["count"] == 3
        assert result["has_more"] is False

    def test_a_result_that_exactly_fills_the_page_is_complete(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = self._client(monkeypatch, callers=10)
        result = client.xrefs(tmp_path / "app.apk", "decrypt", limit=10)

        assert result["count"] == 10
        assert result["has_more"] is False


class TestFridaEnumerationsSayWhenTheyStopped:
    """`count` alone cannot distinguish "that is all" from "that is your page"."""

    def test_a_full_page_reports_more(self) -> None:
        from headless_re_mcp.backends.frida.client import _page

        page, has_more = _page(list(range(25)), 10)
        assert page == list(range(10))
        assert has_more is True

    def test_a_short_answer_is_complete(self) -> None:
        from headless_re_mcp.backends.frida.client import _page

        page, has_more = _page(["a", "b"], 10)
        assert page == ["a", "b"]
        assert has_more is False

    def test_exactly_one_page_with_nothing_behind_it_is_complete(self) -> None:
        """The enumerations ask for limit+1, so this is what "exactly full" looks like."""
        from headless_re_mcp.backends.frida.client import _page

        page, has_more = _page(list(range(10)), 10)
        assert len(page) == 10
        assert has_more is False

    def test_nothing_at_all_is_not_partial(self) -> None:
        from headless_re_mcp.backends.frida.client import _page

        assert _page(None, 10) == ([], False)
        assert _page([], 10) == ([], False)


class TestApkClassification:
    def test_apk_is_detected_by_extension_and_by_content(self, tmp_path: Path) -> None:
        named = _apk(tmp_path / "app.apk")
        assert classify_target(named) is TargetKind.APK
        unnamed = _apk(tmp_path / "app.bin")
        assert classify_target(unnamed) is TargetKind.APK

    def test_plain_zip_is_not_an_apk(self, tmp_path: Path) -> None:
        plain = tmp_path / "archive.bin"
        with zipfile.ZipFile(plain, "w") as archive:
            archive.writestr("readme.txt", "hello")
        assert classify_target(plain) is TargetKind.PE

    def test_describe_apk_reads_abis_without_androguard(self, tmp_path: Path) -> None:
        info = describe_apk(_apk(tmp_path / "app.apk"))["apk"]
        assert info["native_abis"] == ["arm64-v8a"]
        assert info["dex_count"] == 1
        assert info["signed_v1"] is True

    def test_describe_apk_rejects_archive_without_manifest(self, tmp_path: Path) -> None:
        plain = tmp_path / "archive.zip"
        with zipfile.ZipFile(plain, "w") as archive:
            archive.writestr("readme.txt", "hello")
        with pytest.raises(ValueError):
            describe_apk(plain)


class TestApktoolBoundaries:
    def test_missing_apktool_degrades(self, tmp_path: Path) -> None:
        client = ApktoolClient(None, None)
        with pytest.raises(ApktoolError) as info:
            client.decode(_apk(tmp_path / "a.apk"), tmp_path / "out")
        assert info.value.code == "capability_unavailable"

    def test_build_rejects_a_directory_that_is_not_a_decode_tree(self, tmp_path: Path) -> None:
        fake_tool = tmp_path / "apktool.bat"
        fake_tool.write_text("@echo off\n", encoding="utf-8")
        source = tmp_path / "tree"
        source.mkdir()
        client = ApktoolClient(fake_tool, None)
        with pytest.raises(ApktoolError) as info:
            client.build(source, tmp_path / "out.apk")
        assert info.value.code == "invalid_params"

    def test_sign_without_apksigner_degrades(self, tmp_path: Path) -> None:
        client = ApktoolClient(None, None)
        with pytest.raises(ApktoolError) as info:
            client.sign(_apk(tmp_path / "a.apk"), tmp_path / "signed.apk")
        assert info.value.code == "capability_unavailable"


class _PsThenLaunchDevice:
    """An adb device whose process list never contains frida-server."""

    def __init__(self, *, after_launch: str = "init\n  1 root  /init\n") -> None:
        self.calls: list[tuple[object, object]] = []
        self._after_launch = after_launch
        self._launched = False

    def shell(self, cmd: object, timeout: object = None) -> str:
        self.calls.append((cmd, timeout))
        text = cmd if isinstance(cmd, str) else " ".join(str(part) for part in cmd)
        if "su" in text or "nohup" in text:
            self._launched = True
            return ""
        if "ps" in text:
            if self._launched:
                return self._after_launch
            return "init\n  1 root  /init\n"
        return ""


class _EnsureBackend(AdbBackend):
    def __init__(self, device: _PsThenLaunchDevice) -> None:
        self._adbutils = object()
        self._available = True
        self._adb_path = None
        self.device = device

    def _device(self, serial: str) -> _PsThenLaunchDevice:
        assert serial
        return self.device


class TestFridaServerEnsureIsHonest:
    def test_a_launch_that_leaves_no_process_is_not_reported_running(self) -> None:
        """ensure used to return running=True after the su command came back.

        The process list was only consulted before the launch. A su that
        printed nothing -- no binary, no root, a nohup that died -- still
        answered running=True. Measured here: ps never listed frida-server,
        and the reply still claimed it was up. An unattended agent then
        waits for hooks that will never appear.
        """
        device = _PsThenLaunchDevice()
        result = _EnsureBackend(device).ensure_frida_server("emulator-5554")

        assert result["running"] is False
        texts = [
            cmd if isinstance(cmd, str) else " ".join(str(part) for part in cmd)
            for cmd, _timeout in device.calls
        ]
        launch_at = next(i for i, text in enumerate(texts) if "nohup" in text)
        assert any("ps" in text for text in texts[launch_at + 1 :]), (
            "the process list has to be read after the launch, not only before it"
        )

    def test_a_process_that_is_already_there_is_still_reported_running(self) -> None:
        device = _PsThenLaunchDevice()

        def already_running(cmd: object, timeout: object = None) -> str:
            device.calls.append((cmd, timeout))
            return "root  99  1  /data/local/tmp/frida-server -l 0.0.0.0:27042\n"

        device.shell = already_running  # type: ignore[method-assign]
        result = _EnsureBackend(device).ensure_frida_server("emulator-5554")
        assert result["running"] is True
        assert result["pushed"] is False
        assert not any("nohup" in str(cmd) for cmd, _timeout in device.calls)

    def test_a_launch_that_really_starts_the_process_is_reported_running(self) -> None:
        device = _PsThenLaunchDevice(
            after_launch="root  99  1  /data/local/tmp/frida-server -l 0.0.0.0:27042\n"
        )
        result = _EnsureBackend(device).ensure_frida_server("emulator-5554")
        assert result["running"] is True
        assert result["pushed"] is False
