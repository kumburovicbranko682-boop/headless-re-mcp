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
