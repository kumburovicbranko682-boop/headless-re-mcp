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

    def test_missing_adbutils_degrades_instead_of_raising_import_error(self) -> None:
        backend = AdbBackend()
        if backend.available:
            pytest.skip("adbutils installed — degradation path not exercised (skip != pass)")
        with pytest.raises(AdbError) as info:
            backend.list_devices()
        assert info.value.code == "capability_unavailable"


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


class TestApkManifestSaysWhenItWasCut:
    """A manifest that hit the cap looks exactly like one that ended.

    ``apk.manifest`` is the document an agent reads to decide exported
    components and permissions. It was sliced at 200_000 characters with
    nothing to say so, so a large app's tail -- often the interesting
    parts -- vanished while the reply still looked complete.
    """

    def _client(self, monkeypatch: pytest.MonkeyPatch, xml: str) -> Any:
        from headless_re_mcp.backends.apk.client import ApkClient

        class _FakeAx:
            def get_xml(self) -> bytes:
                return xml.encode("utf-8")

        class _FakeApk:
            def get_package(self) -> str:
                return "com.example.app"

            def get_android_manifest_axml(self) -> _FakeAx:
                return _FakeAx()

        client = ApkClient()
        monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _FakeApk())
        return client

    def test_hitting_the_cap_is_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        xml = "<manifest>" + ("<uses-permission android:name='p'/>" * 8000) + "</manifest>"
        assert len(xml) > 200_000
        result = self._client(monkeypatch, xml).manifest(tmp_path / "app.apk")

        assert result["truncated"] is True
        assert result["bytes"] == len(xml)
        assert len(result["manifest_xml"]) == 200_000
        assert not result["manifest_xml"].endswith("</manifest>")

    def test_a_complete_manifest_is_not_labelled_partial(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        xml = "<manifest><application/></manifest>"
        result = self._client(monkeypatch, xml).manifest(tmp_path / "app.apk")

        assert result["truncated"] is False
        assert result["bytes"] == len(xml)
        assert result["manifest_xml"] == xml


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


class TestFridaApplicationsSayWhenTheyStopped:
    """An app page that hit the cap looks exactly like one that ended.

    Measured: 800 apps, limit 256, count=256, total=800, no has_more.
    """

    def _client(self, n: int) -> Any:
        from headless_re_mcp.backends.frida.client import FridaClient

        class _App:
            def __init__(self, index: int) -> None:
                self.identifier = f"com.app{index}"
                self.name = f"App{index}"
                self.pid = 0

        class _Dev:
            def enumerate_applications(self) -> list[_App]:
                return [_App(index) for index in range(n)]

        client = FridaClient()
        client._resolve_device = lambda device_id: _Dev()  # type: ignore[method-assign]
        return client

    def test_hitting_the_cap_is_reported(self) -> None:
        result = self._client(800).applications(None, limit=256)
        assert result["count"] == 256
        assert result["total"] == 800
        assert result["has_more"] is True

    def test_a_complete_answer_is_not_labelled_partial(self) -> None:
        result = self._client(3).applications(None, limit=256)
        assert result["count"] == 3
        assert result["has_more"] is False

    def test_a_result_that_exactly_fills_the_page_is_complete(self) -> None:
        result = self._client(256).applications(None, limit=256)
        assert result["count"] == 256
        assert result["has_more"] is False


class TestFridaModulesSayWhenTheyStopped:
    """A module page that hit the cap looks exactly like one that ended.

    Measured: 200 modules, limit 64, count=64, total=200, no has_more -- so
    a caller that only looks at the page thinks it has the whole process map.
    """

    def _client(self, n: int) -> Any:
        from headless_re_mcp.backends.frida.client import FridaClient

        class _Exports:
            def modules(self) -> list[dict[str, Any]]:
                return [
                    {
                        "name": f"libmod{index}.so",
                        "base": hex(0x70000000 + index * 0x1000),
                        "size": 4096,
                        "path": f"/system/lib64/libmod{index}.so",
                    }
                    for index in range(n)
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

        client = FridaClient()
        client._available = True
        client._frida = type("F", (), {"attach": staticmethod(lambda pid: _Session())})()
        return client

    def test_hitting_the_cap_is_reported(self) -> None:
        result = self._client(200).modules(1234, allowed_pid=1234, limit=64)
        assert result["count"] == 64
        assert result["total"] == 200
        assert result["has_more"] is True

    def test_a_complete_answer_is_not_labelled_partial(self) -> None:
        result = self._client(3).modules(1234, allowed_pid=1234, limit=64)
        assert result["count"] == 3
        assert result["has_more"] is False

    def test_a_result_that_exactly_fills_the_page_is_complete(self) -> None:
        result = self._client(64).modules(1234, allowed_pid=1234, limit=64)
        assert result["count"] == 64
        assert result["has_more"] is False


class TestDeviceUninstallDoesNotInventSuccess:
    """adbutils returning False used to be reported as uninstalled=True."""

    def _backend(self, outcome: object) -> Any:
        from headless_re_mcp.backends.adb.client import AdbBackend

        class _FakeDev:
            def uninstall(self, package: str) -> object:
                return outcome

        backend = AdbBackend()
        backend._available = True
        backend._adbutils = object()
        backend._device = lambda serial: _FakeDev()  # type: ignore[method-assign]
        return backend

    def test_false_is_a_failure(self) -> None:
        with pytest.raises(AdbError) as info:
            self._backend(False).uninstall("emulator-5554", "com.example.app")
        assert info.value.code == "backend_error"
        assert "not installed" in str(info.value)

    def test_true_or_none_is_uninstalled(self) -> None:
        for outcome in (True, None):
            result = self._backend(outcome).uninstall("emulator-5554", "com.example.app")
            assert result == {"uninstalled": True, "package": "com.example.app"}


class TestDeviceInstallDoesNotInventSuccess:
    """A failed pm install used to be reported as installed=True.

    Measured: ``Failure [INSTALL_FAILED_INVALID_APK]`` and ``False`` both
    produced ``{"installed": true}``. An unattended agent then launches a
    package that is not on the device.
    """

    def _backend(self, outcome: object) -> Any:
        from headless_re_mcp.backends.adb.client import AdbBackend

        class _FakeDev:
            def install(self, *args: object, **kwargs: object) -> object:
                return outcome

        backend = AdbBackend()
        backend._available = True
        backend._adbutils = object()
        backend._device = lambda serial: _FakeDev()  # type: ignore[method-assign]
        return backend

    def test_a_failure_line_is_a_failure(self, tmp_path: Path) -> None:
        apk = tmp_path / "a.apk"
        apk.write_bytes(b"PK")
        backend = self._backend("Failure [INSTALL_FAILED_INVALID_APK]")
        with pytest.raises(AdbError) as info:
            backend.install("emulator-5554", str(apk))
        assert info.value.code == "backend_error"
        assert "INSTALL_FAILED_INVALID_APK" in str(info.value)

    def test_false_is_a_failure(self, tmp_path: Path) -> None:
        apk = tmp_path / "a.apk"
        apk.write_bytes(b"PK")
        with pytest.raises(AdbError) as info:
            self._backend(False).install("emulator-5554", str(apk))
        assert info.value.code == "backend_error"

    def test_success_or_none_is_installed(self, tmp_path: Path) -> None:
        apk = tmp_path / "a.apk"
        apk.write_bytes(b"PK")
        for outcome in (None, "Success"):
            result = self._backend(outcome).install("emulator-5554", str(apk))
            assert result["installed"] is True
            assert result["path"] == str(apk)


class TestDeviceLaunchDoesNotInventSuccess:
    """monkey aborting used to be reported as launched=True.

    Measured: ``** No activities found to run, monkey aborted.`` / Events
    injected: 0 still produced ``{"launched": true}``. An unattended agent
    then attaches, screenshots, or traces a process that is not there.
    """

    def _backend(self, output: str) -> Any:
        from headless_re_mcp.backends.adb.client import AdbBackend

        class _FakeDev:
            def shell(self, cmd: object, timeout: float | None = None) -> str:
                return output

        backend = AdbBackend()
        backend._available = True
        backend._adbutils = object()
        backend._device = lambda serial: _FakeDev()  # type: ignore[method-assign]
        return backend

    def test_no_launcher_activity_is_a_failure(self) -> None:
        backend = self._backend(
            "** No activities found to run, monkey aborted.\nEvents injected: 0\n"
        )
        with pytest.raises(AdbError) as info:
            backend.launch("emulator-5554", "com.example.app")
        assert info.value.code == "backend_error"
        assert "no launcher activity" in str(info.value)
        assert "monkey aborted" in str(info.value.details.get("output", "")).casefold()

    def test_a_monkey_that_injected_is_launched(self) -> None:
        result = self._backend("Events injected: 1\n").launch(
            "emulator-5554", "com.example.app"
        )
        assert result == {"launched": True, "package": "com.example.app"}


class TestDeviceForceStopDoesNotInventSuccess:
    """am force-stop used to be reported as stopped=True for any package.

    Measured: ``com.no.such.app`` with empty stdout still produced
    ``{"stopped": true}``. An unattended agent then traces or screenshots
    a process that is not there.
    """

    def _backend(self, path_out: str) -> Any:
        from headless_re_mcp.backends.adb.client import AdbBackend

        class _FakeDev:
            def shell(self, cmd: object, timeout: float | None = None) -> str:
                if isinstance(cmd, list) and cmd[:2] == ["pm", "path"]:
                    return path_out
                return ""

        backend = AdbBackend()
        backend._available = True
        backend._adbutils = object()
        backend._device = lambda serial: _FakeDev()  # type: ignore[method-assign]
        return backend

    def test_a_missing_package_is_a_failure(self) -> None:
        with pytest.raises(AdbError) as info:
            self._backend("").force_stop("emulator-5554", "com.no.such.app")
        assert info.value.code == "backend_error"
        assert "not installed" in str(info.value)

    def test_an_installed_package_is_stopped(self) -> None:
        result = self._backend("package:/data/app/com.example.app/base.apk\n").force_stop(
            "emulator-5554", "com.example.app"
        )
        assert result == {"stopped": True, "package": "com.example.app"}


class TestDeviceLogcatSaysWhenItStopped:
    """A logcat page that hit the cap looks exactly like one that ended."""

    def _backend(self, count: int) -> Any:
        from headless_re_mcp.backends.adb.client import AdbBackend

        class _FakeDev:
            def shell(self, cmd: object, timeout: float | None = None) -> str:
                asked = int(cmd[-1]) if isinstance(cmd, list) else count
                start = max(0, count - asked)
                return "\n".join(f"line{index}" for index in range(start, count))

        backend = AdbBackend()
        backend._available = True
        backend._adbutils = object()
        backend._device = lambda serial: _FakeDev()  # type: ignore[method-assign]
        return backend

    def test_hitting_the_cap_is_reported(self) -> None:
        result = self._backend(600).logcat("emulator-5554", lines=200)
        assert len(result["lines"]) == 200
        assert result["has_more"] is True
        assert result["requested"] == 200

    def test_a_short_buffer_is_complete(self) -> None:
        result = self._backend(3).logcat("emulator-5554", lines=200)
        assert len(result["lines"]) == 3
        assert result["has_more"] is False

    def test_a_result_that_exactly_fills_the_page_is_complete(self) -> None:
        result = self._backend(200).logcat("emulator-5554", lines=200)
        assert len(result["lines"]) == 200
        assert result["has_more"] is False


class TestDevicePackagesAreBounded:
    """An emulator image can carry thousands of packages; the list had no cap."""

    def _backend(self, count: int) -> Any:
        from headless_re_mcp.backends.adb.client import AdbBackend

        class _FakeDev:
            def shell(self, cmd: object, timeout: float | None = None) -> str:
                return "\n".join(f"package:com.vendor.app{index}" for index in range(count))

        backend = AdbBackend()
        backend._available = True
        backend._adbutils = object()
        backend._device = lambda serial: _FakeDev()  # type: ignore[method-assign]
        return backend

    def test_hitting_the_cap_is_reported(self) -> None:
        result = self._backend(8000).packages("emulator-5554", limit=1000)
        assert result["count"] == 1000
        assert result["has_more"] is True
        assert len(result["packages"]) == 1000

    def test_a_complete_answer_is_not_labelled_partial(self) -> None:
        result = self._backend(3).packages("emulator-5554", limit=1000)
        assert result["count"] == 3
        assert result["has_more"] is False

    def test_a_result_that_exactly_fills_the_page_is_complete(self) -> None:
        result = self._backend(1000).packages("emulator-5554", limit=1000)
        assert result["count"] == 1000
        assert result["has_more"] is False


class TestDevicePropertiesSayWhenTheyStopped:
    """A getprop page that hit the cap looks exactly like one that ended."""

    def _backend(self, lines: int) -> Any:
        from headless_re_mcp.backends.adb.client import AdbBackend

        class _FakeDev:
            def shell(self, cmd: object, timeout: float | None = None) -> str:
                return "\n".join(f"[ro.prop.{index}]: [v{index}]" for index in range(lines))

        backend = AdbBackend()
        backend._available = True
        backend._adbutils = object()
        backend._device = lambda serial: _FakeDev()  # type: ignore[method-assign]
        return backend

    def test_hitting_the_cap_is_reported(self) -> None:
        result = self._backend(800).properties("emulator-5554", limit=500)
        assert result["count"] == 500
        assert result["has_more"] is True
        assert len(result["properties"]) == 500

    def test_a_complete_answer_is_not_labelled_partial(self) -> None:
        result = self._backend(3).properties("emulator-5554", limit=500)
        assert result["count"] == 3
        assert result["has_more"] is False

    def test_a_result_that_exactly_fills_the_page_is_complete(self) -> None:
        result = self._backend(500).properties("emulator-5554", limit=500)
        assert result["count"] == 500
        assert result["has_more"] is False


class TestFridaServerEnsureDoesNotInventARunningServer:
    """A launch that returned 0 used to be reported as running=True.

    ``su -c 'nohup frida-server &'`` succeeding means the shell accepted the
    line, not that a server is listening. Measured: ps showed only init, the
    launch returned empty, and the payload still said running=True -- so an
    unattended agent would attach to a server that is not there.
    """

    def _backend(self, *, ps_output: str, launch_output: str = "") -> Any:
        from headless_re_mcp.backends.adb.client import AdbBackend

        class _FakeDev:
            def __init__(self) -> None:
                self.shells: list[object] = []

            def shell(self, cmd: object, timeout: float | None = None) -> str:
                self.shells.append(cmd)
                if isinstance(cmd, str) and cmd.startswith("ps"):
                    return ps_output
                if isinstance(cmd, str) and cmd.startswith("su"):
                    return launch_output
                return ""

        backend = AdbBackend()
        backend._available = True
        backend._adbutils = object()
        fake = _FakeDev()
        backend._device = lambda serial: fake  # type: ignore[method-assign]
        return backend, fake

    def test_a_launch_that_left_nothing_is_not_running(self) -> None:
        backend, fake = self._backend(ps_output="root 1 0 init")
        result = backend.ensure_frida_server("emulator-5554")

        assert result["running"] is False
        assert any(isinstance(cmd, str) and cmd.startswith("su") for cmd in fake.shells)
        # It has to look again after the launch, not just trust the shell.
        assert sum(1 for cmd in fake.shells if isinstance(cmd, str) and cmd.startswith("ps")) >= 3

    def test_a_server_that_is_already_up_is_left_alone(self) -> None:
        backend, fake = self._backend(ps_output="root 88 1 frida-server")
        result = backend.ensure_frida_server("emulator-5554")

        assert result["running"] is True
        assert result["pushed"] is False
        assert not any(isinstance(cmd, str) and cmd.startswith("su") for cmd in fake.shells)

    def test_a_launch_that_actually_starts_is_running(self) -> None:
        backend, fake = self._backend(ps_output="root 1 0 init")
        seen = {"launched": False}

        def shell(cmd: object, timeout: float | None = None) -> str:
            fake.shells.append(cmd)
            if isinstance(cmd, str) and cmd.startswith("su"):
                seen["launched"] = True
                return ""
            if isinstance(cmd, str) and cmd.startswith("ps"):
                return "root 88 1 frida-server" if seen["launched"] else "root 1 0 init"
            return ""

        fake.shell = shell  # type: ignore[method-assign]
        result = backend.ensure_frida_server("emulator-5554")
        assert result["running"] is True


class TestApkComponentsAreBounded:
    """A large app can declare thousands of components; the lists had no cap.

    Measured: 3000 activities + 500/400/100 others, 65 KiB, no has_more.
    """

    def _client(self, activities: int, services: int = 0) -> Any:
        from headless_re_mcp.backends.apk.client import ApkClient

        class _Apk:
            def get_activities(self) -> list[str]:
                return [f"com.app.A{index}" for index in range(activities)]

            def get_services(self) -> list[str]:
                return [f"com.app.S{index}" for index in range(services)]

            def get_receivers(self) -> list[str]:
                return []

            def get_providers(self) -> list[str]:
                return []

            def get_main_activity(self) -> str:
                return "com.app.A0"

        client = ApkClient()
        client._apk = lambda path: _Apk()  # type: ignore[method-assign]
        return client

    def test_hitting_the_cap_is_reported(self, tmp_path: Path) -> None:
        result = self._client(3000).components(tmp_path / "a.apk", limit=1000)
        assert len(result["activities"]) == 1000
        assert result["has_more"] is True

    def test_a_complete_answer_is_not_labelled_partial(self, tmp_path: Path) -> None:
        result = self._client(3, services=2).components(tmp_path / "a.apk", limit=1000)
        assert result["activities"] == ["com.app.A0", "com.app.A1", "com.app.A2"]
        assert result["has_more"] is False

    def test_a_result_that_exactly_fills_the_page_is_complete(self, tmp_path: Path) -> None:
        result = self._client(1000).components(tmp_path / "a.apk", limit=1000)
        assert len(result["activities"]) == 1000
        assert result["has_more"] is False


class TestApkXrefsDescriptionMatchesTheCut:
    """apk.xrefs already cuts the caller list, but the tool text hid that.

    Measured: 150 callers, limit 100, count=100, has_more=true, while the
    description said "every method" and never mentioned has_more -- so a
    model that trusts the text treats a page as the complete xref set.
    """

    def test_the_tool_text_says_to_check_has_more(self) -> None:
        from headless_re_mcp.core.service import AnalysisService
        from headless_re_mcp.tools.apk import build_apk_tools

        service = AnalysisService()
        try:
            tools = {item.name: item for item in build_apk_tools(service)}
            doc = tools["apk.xrefs"].handler.__doc__ or ""
        finally:
            service.close_all()
        assert "has_more" in doc


class TestApkCertificatesAreBounded:
    """A certificate list that hit the cap looks exactly like one that ended.

    Measured: 200 certificates + 200 signature files, 116 KiB, no has_more.
    """

    def _client(self, n: int) -> Any:
        from headless_re_mcp.backends.apk.client import ApkClient

        class _Cert:
            subject = "CN=example"
            issuer = "CN=example"
            serial_number = 1
            sha256_fingerprint = "ab" * 32

        class _Apk:
            def get_signature_names(self) -> list[str]:
                return [f"META-INF/CERT{index}.RSA" for index in range(n)]

            def get_certificates(self) -> list[_Cert]:
                return [_Cert() for _ in range(n)]

        client = ApkClient()
        client._apk = lambda path: _Apk()  # type: ignore[method-assign]
        return client

    def test_hitting_the_cap_is_reported(self, tmp_path: Path) -> None:
        result = self._client(200).certificates(tmp_path / "a.apk", limit=32)
        assert result["count"] == 32
        assert result["total"] == 200
        assert result["has_more"] is True
        assert len(result["certificates"]) == 32
        assert len(result["signature_files"]) == 32

    def test_a_complete_answer_is_not_labelled_partial(self, tmp_path: Path) -> None:
        result = self._client(3).certificates(tmp_path / "a.apk", limit=32)
        assert result["count"] == 3
        assert result["has_more"] is False

    def test_a_result_that_exactly_fills_the_page_is_complete(self, tmp_path: Path) -> None:
        result = self._client(32).certificates(tmp_path / "a.apk", limit=32)
        assert result["count"] == 32
        assert result["has_more"] is False


class TestApkPermissionsAreBounded:
    """A permission list that hit the cap looks exactly like one that ended.

    Measured: 3000 declared + 3000 requested, 141 KiB, no has_more -- so an
    unattended caller dumps both full tables in one tool result.
    """

    def _client(self, n: int) -> Any:
        from headless_re_mcp.backends.apk.client import ApkClient

        class _Apk:
            def get_permissions(self) -> list[str]:
                return [f"com.example.PERM_{index}" for index in range(n)]

            def get_requested_permissions(self) -> list[str]:
                return [f"com.example.REQ_{index}" for index in range(n)]

        client = ApkClient()
        client._apk = lambda path: _Apk()  # type: ignore[method-assign]
        return client

    def test_hitting_the_cap_is_reported(self, tmp_path: Path) -> None:
        result = self._client(3000).permissions(tmp_path / "a.apk", limit=500)
        assert result["count"] == 500
        assert result["total"] == 3000
        assert result["has_more"] is True
        assert len(result["permissions"]) == 500
        assert len(result["requested_permissions"]) == 500

    def test_a_complete_answer_is_not_labelled_partial(self, tmp_path: Path) -> None:
        result = self._client(3).permissions(tmp_path / "a.apk", limit=500)
        assert result["count"] == 3
        assert result["has_more"] is False

    def test_a_result_that_exactly_fills_the_page_is_complete(self, tmp_path: Path) -> None:
        result = self._client(500).permissions(tmp_path / "a.apk", limit=500)
        assert result["count"] == 500
        assert result["has_more"] is False


class TestApkNativeLibsAreBounded:
    """A fat APK can ship thousands of .so files; the list had no cap.

    Measured: 8000 libs, 229 KiB, no has_more.
    """

    def _client(self, n: int) -> Any:
        from headless_re_mcp.backends.apk.client import ApkClient

        class _Apk:
            def get_files(self) -> list[str]:
                return [f"lib/arm64-v8a/lib{index}.so" for index in range(n)] + ["classes.dex"]

        client = ApkClient()
        client._apk = lambda path: _Apk()  # type: ignore[method-assign]
        return client

    def test_hitting_the_cap_is_reported(self, tmp_path: Path) -> None:
        result = self._client(8000).native_libs(tmp_path / "a.apk", limit=1000)
        assert result["count"] == 1000
        assert result["total"] == 8000
        assert result["has_more"] is True
        assert result["abis"] == ["arm64-v8a"]

    def test_a_complete_answer_is_not_labelled_partial(self, tmp_path: Path) -> None:
        result = self._client(3).native_libs(tmp_path / "a.apk", limit=1000)
        assert result["count"] == 3
        assert result["has_more"] is False

    def test_a_result_that_exactly_fills_the_page_is_complete(self, tmp_path: Path) -> None:
        result = self._client(1000).native_libs(tmp_path / "a.apk", limit=1000)
        assert result["count"] == 1000
        assert result["has_more"] is False


class TestApkStringsSayWhenTheyStopped:
    """A string page that hit the cap looks exactly like one that ended."""

    def _client(self, n: int) -> Any:
        from headless_re_mcp.backends.apk.client import ApkClient

        class _Item:
            def __init__(self, value: str) -> None:
                self._value = value

            def get_value(self) -> str:
                return self._value

        class _Parsed:
            def __init__(self) -> None:
                self.analysis = self

            def get_strings(self) -> list[_Item]:
                return [_Item(f"s{index}") for index in range(n)]

        client = ApkClient()
        client._parsed = lambda path: _Parsed()  # type: ignore[method-assign]
        return client

    def test_hitting_the_cap_is_reported(self, tmp_path: Path) -> None:
        result = self._client(500).strings(tmp_path / "a.apk", limit=200)
        assert result["count"] == 200
        assert result["total"] == 500
        assert result["has_more"] is True

    def test_a_complete_answer_is_not_labelled_partial(self, tmp_path: Path) -> None:
        result = self._client(3).strings(tmp_path / "a.apk", limit=200)
        assert result["count"] == 3
        assert result["has_more"] is False

    def test_a_result_that_exactly_fills_the_page_is_complete(self, tmp_path: Path) -> None:
        result = self._client(200).strings(tmp_path / "a.apk", limit=200)
        assert result["count"] == 200
        assert result["has_more"] is False


class TestApkMethodsSayWhenTheyStopped:
    """A method page that hit the cap looks exactly like one that ended."""

    def _client(self, n: int) -> Any:
        from headless_re_mcp.backends.apk.client import ApkClient

        class _Method:
            def __init__(self, name: str) -> None:
                self.name = name
                self.descriptor = "()V"
                self.access = "public"

        class _Klass:
            name = "Lcom/example/A;"

            def get_methods(self) -> list[_Method]:
                return [_Method(f"m{index}") for index in range(n)]

        class _Parsed:
            def __init__(self) -> None:
                self.analysis = self

            def get_classes(self) -> list[_Klass]:
                return [_Klass()]

        client = ApkClient()
        client._parsed = lambda path: _Parsed()  # type: ignore[method-assign]
        return client

    def test_hitting_the_cap_is_reported(self, tmp_path: Path) -> None:
        result = self._client(250).methods(tmp_path / "a.apk", "Lcom/example/A;", limit=100)
        assert result["count"] == 100
        assert result["total"] == 250
        assert result["has_more"] is True

    def test_a_complete_answer_is_not_labelled_partial(self, tmp_path: Path) -> None:
        result = self._client(3).methods(tmp_path / "a.apk", "Lcom/example/A;", limit=100)
        assert result["count"] == 3
        assert result["has_more"] is False

    def test_a_result_that_exactly_fills_the_page_is_complete(self, tmp_path: Path) -> None:
        result = self._client(100).methods(tmp_path / "a.apk", "Lcom/example/A;", limit=100)
        assert result["count"] == 100
        assert result["has_more"] is False


class TestApkClassesSayWhenTheyStopped:
    """A class page that hit the cap looks exactly like one that ended.

    Measured: 250 classes, limit 100, count=100, total=250, no has_more.
    """

    def _client(self, n: int) -> Any:
        from headless_re_mcp.backends.apk.client import ApkClient

        class _Klass:
            def __init__(self, name: str) -> None:
                self.name = name

            def is_external(self) -> bool:
                return False

        class _Parsed:
            def __init__(self) -> None:
                self.analysis = self

            def get_classes(self) -> list[_Klass]:
                return [_Klass(f"L{index};") for index in range(n)]

        client = ApkClient()
        client._parsed = lambda path: _Parsed()  # type: ignore[method-assign]
        return client

    def test_hitting_the_cap_is_reported(self, tmp_path: Path) -> None:
        result = self._client(250).classes(tmp_path / "a.apk", limit=100)
        assert result["count"] == 100
        assert result["total"] == 250
        assert result["has_more"] is True

    def test_a_complete_answer_is_not_labelled_partial(self, tmp_path: Path) -> None:
        result = self._client(3).classes(tmp_path / "a.apk", limit=100)
        assert result["count"] == 3
        assert result["has_more"] is False

    def test_a_result_that_exactly_fills_the_page_is_complete(self, tmp_path: Path) -> None:
        result = self._client(100).classes(tmp_path / "a.apk", limit=100)
        assert result["count"] == 100
        assert result["has_more"] is False


class TestJadxExportSaysWhenItStopped:
    """A java_files page that hit the cap looks exactly like one that ended.

    Measured: 2500 .java files, java_file_count=2500, java_files length 2000,
    no has_more -- so the last 500 class names vanished while the reply
    looked like the whole tree.
    """

    def _client(self, tmp_path: Path, n: int) -> Any:
        from headless_re_mcp.backends.jadx.client import JadxClient

        exe = tmp_path / "jadx"
        exe.write_text("x", encoding="utf-8")
        out = tmp_path / "out"
        (out / "sources").mkdir(parents=True)
        for index in range(n):
            (out / "sources" / f"C{index}.java").write_text("class X {}", encoding="utf-8")
        client = JadxClient(exe)
        client._run = lambda *args, **kwargs: ("", "", 0)  # type: ignore[method-assign]
        apk = _apk(tmp_path / "a.apk")
        return client.export_sources(apk, out)

    def test_hitting_the_cap_is_reported(self, tmp_path: Path) -> None:
        result = self._client(tmp_path, 2500)
        assert result["java_file_count"] == 2500
        assert len(result["java_files"]) == 2000
        assert result["has_more"] is True

    def test_a_complete_answer_is_not_labelled_partial(self, tmp_path: Path) -> None:
        result = self._client(tmp_path, 3)
        assert result["java_file_count"] == 3
        assert result["has_more"] is False

    def test_a_result_that_exactly_fills_the_page_is_complete(self, tmp_path: Path) -> None:
        result = self._client(tmp_path, 2000)
        assert result["java_file_count"] == 2000
        assert result["has_more"] is False


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


class TestApkSignIsRegistered:
    """apk.sign writes signed.apk and never registered it.

    Measured: 5 signs overwrite the same file, 0 artifact rows.
    """

    def test_signed_apk_is_a_readable_artifact(self, tmp_path: Path) -> None:
        from dataclasses import replace

        from headless_re_mcp.config import Settings
        from headless_re_mcp.core.service import AnalysisService

        settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
        service = AnalysisService(settings)
        try:
            created = service.create_session(str(_apk(tmp_path / "app.apk")), target="apk")
            session_id = str(created.data["session"]["id"])

            class _Fake:
                def sign(self, source: Path, out_apk: Path, **kwargs: object) -> dict[str, Any]:
                    out_apk.parent.mkdir(parents=True, exist_ok=True)
                    out_apk.write_bytes(b"PK" + b"s" * 64)
                    return {"apk": str(out_apk), "size": out_apk.stat().st_size, "signed": True}

            service._apktool_client = lambda: _Fake()  # type: ignore[method-assign]
            result = service.apk_sign(session_id)
            assert result.ok, result.error
            assert result.data is not None
            assert result.data.get("artifact_id")

            listed = service.artifacts_list(session_id)
            assert listed.ok and listed.data is not None
            assert listed.data["total"] == 1
            assert listed.data["artifacts"][0]["kind"] == "apk_signed"
        finally:
            service.close_all()


class TestApkRepackIsRegistered:
    """apk.repack writes repacked.apk and never registered it.

    Measured: 5 repacks overwrite the same file, 0 artifact rows, so the
    rebuilt APK cannot be read back or reclaimed.
    """

    def test_repacked_apk_is_a_readable_artifact(self, tmp_path: Path) -> None:
        from dataclasses import replace

        from headless_re_mcp.config import Settings
        from headless_re_mcp.core.service import AnalysisService

        settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
        service = AnalysisService(settings)
        try:
            created = service.create_session(str(_apk(tmp_path / "app.apk")), target="apk")
            session_id = str(created.data["session"]["id"])

            class _Fake:
                def build(
                    self, source: Path, out_apk: Path, *, timeout: float = 600.0
                ) -> dict[str, Any]:
                    out_apk.parent.mkdir(parents=True, exist_ok=True)
                    out_apk.write_bytes(b"PK" + b"x" * 64)
                    return {"apk": str(out_apk), "size": out_apk.stat().st_size, "signed": False}

            service._apktool_client = lambda: _Fake()  # type: ignore[method-assign]
            result = service.apk_repack(session_id)
            assert result.ok, result.error
            assert result.data is not None
            assert result.data.get("artifact_id")

            listed = service.artifacts_list(session_id)
            assert listed.ok and listed.data is not None
            assert listed.data["total"] == 1
            assert listed.data["artifacts"][0]["kind"] == "apk_repacked"

            read = service.artifacts_read(str(result.data["artifact_id"]), offset=0, limit=2)
            assert read.ok and read.data is not None
            assert read.data["data"].startswith("504b")
        finally:
            service.close_all()
