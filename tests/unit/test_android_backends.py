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
    """A 200_000-character slice used to look exactly like the whole manifest."""

    def test_an_oversized_manifest_is_marked_truncated(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from headless_re_mcp.backends.apk.client import _MAX_MANIFEST_CHARS, ApkClient

        class _Axm:
            def get_xml(self) -> bytes:
                return ("<manifest>" + ("<uses-permission/>" * 20_000) + "</manifest>").encode()

        class _Apk:
            def get_package(self) -> str:
                return "com.example"

            def get_android_manifest_axml(self) -> _Axm:
                return _Axm()

        client = ApkClient()
        monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _Apk())
        result = client.manifest(tmp_path / "app.apk")

        assert result["truncated"] is True
        assert result["bytes"] > _MAX_MANIFEST_CHARS
        assert len(result["manifest_xml"]) == _MAX_MANIFEST_CHARS
        assert not result["manifest_xml"].rstrip().endswith("</manifest>")

    def test_a_short_manifest_is_not_labelled_partial(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from headless_re_mcp.backends.apk.client import ApkClient

        class _Axm:
            def get_xml(self) -> bytes:
                return b"<manifest package='com.example'/>"

        class _Apk:
            def get_package(self) -> str:
                return "com.example"

            def get_android_manifest_axml(self) -> _Axm:
                return _Axm()

        client = ApkClient()
        monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _Apk())
        result = client.manifest(tmp_path / "app.apk")

        assert result["truncated"] is False
        assert result["bytes"] == len(result["manifest_xml"])
        assert result["manifest_xml"].endswith("/>")


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


class _PsDevice:
    """An adb device that answers ``ps`` from a script and treats everything else as launch."""

    def __init__(
        self,
        listings: list[str],
        *,
        launch: str | BaseException = "",
    ) -> None:
        self.listings = list(listings)
        self.launch = launch
        self.commands: list[object] = []

    def shell(self, cmd: object, timeout: float | None = None) -> str:
        self.commands.append(cmd)
        text = str(cmd)
        if "ps" in text and "su" not in text and "nohup" not in text:
            if self.listings:
                return self.listings.pop(0)
            return "root      1     0     0  init"
        if isinstance(self.launch, BaseException):
            raise self.launch
        return self.launch


class TestEnsureFridaServerDoesNotInventARunningProcess:
    """``running: True`` used to mean the launch command returned, not that a process existed.

    Measured: a device whose ``ps`` never lists frida-server, and whose ``su``
    launch returns empty stdout (success), still answered
    ``{'running': True, 'pushed': False, 'port': 27042}``. There was no
    post-launch ``ps``. An unattended agent then attaches to a server that was
    never started and treats the empty listen as a target problem.
    """

    def _backend(self, device: _PsDevice) -> AdbBackend:
        backend = AdbBackend()
        backend._available = True
        backend._adbutils = object()
        backend._device = lambda serial: device  # type: ignore[method-assign]
        return backend

    def test_a_launch_that_starts_nothing_is_not_reported_running(self) -> None:
        device = _PsDevice(["root 1 0 init", "root 1 0 init"])
        backend = self._backend(device)

        with pytest.raises(AdbError) as info:
            backend.ensure_frida_server("emulator-5554")

        assert info.value.code == "backend_error"
        assert info.value.details.get("running") is not True
        # The launch ran; the lie was skipping the check that would have seen it fail.
        assert any("nohup" in str(cmd) or "su" in str(cmd) for cmd in device.commands)
        assert any("ps" in str(cmd) for cmd in device.commands[2:])

    def test_already_running_is_still_true_and_does_not_relaunch(self) -> None:
        device = _PsDevice(["root 42 0 frida-server -l 0.0.0.0:27042"])
        result = self._backend(device).ensure_frida_server("emulator-5554")

        assert result["running"] is True
        assert result["pushed"] is False
        assert not any("nohup" in str(cmd) or "su -c" in str(cmd) for cmd in device.commands)

    def test_a_launch_that_then_appears_in_ps_is_running(self) -> None:
        device = _PsDevice(
            [
                "root 1 0 init",
                "root 1 0 init",
                "root 99 0 frida-server -l 0.0.0.0:27042",
            ]
        )
        result = self._backend(device).ensure_frida_server("emulator-5554")

        assert result["running"] is True
        assert any("nohup" in str(cmd) or "su" in str(cmd) for cmd in device.commands)

    def test_a_timed_out_launch_is_running_only_if_ps_then_shows_it(self) -> None:
        """The old path treated a blocking su as 'probably launched' and said None.

        If the process is actually there after the timeout, say so. If it is
        not, that is a failure, not a success with a footnote.
        """
        appeared = _PsDevice(
            ["root 1 0 init", "root 1 0 init", "root 7 0 /data/local/tmp/frida-server"],
            launch=TimeoutError("su prompt"),
        )
        result = self._backend(appeared).ensure_frida_server("emulator-5554")
        assert result["running"] is True

        missing = _PsDevice(
            ["root 1 0 init", "root 1 0 init", "root 1 0 init", "root 1 0 init"],
            launch=TimeoutError("su prompt"),
        )
        with pytest.raises(AdbError) as info:
            self._backend(missing).ensure_frida_server("emulator-5554")
        assert info.value.code == "backend_error"
        assert info.value.details.get("running") is not True

    def test_the_tool_envelope_is_a_failure_not_an_ensured_timeline(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from dataclasses import replace

        from headless_re_mcp.config import Settings
        from headless_re_mcp.core.service import AnalysisService

        device = _PsDevice(["root 1 0 init", "root 1 0 init"])
        backend = self._backend(device)
        monkeypatch.setattr(
            "headless_re_mcp.core.service_frida.AdbBackend",
            lambda *args, **kwargs: backend,
        )
        apk = tmp_path / "app.apk"
        import zipfile

        with zipfile.ZipFile(apk, "w") as archive:
            archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00m")
        settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
        service = AnalysisService(settings)
        try:
            created = service.create_session(str(apk), target="apk")
            assert created.data is not None
            session_id = str(created.data["session"]["id"])
            result = service.frida_server_ensure(session_id, "emulator-5554")
            assert result.ok is False
            assert result.error is not None
            assert result.error.code == "backend_error"
            timeline = service.timeline_list(session_id)
            events = (timeline.data or {}).get("events") or []
            assert not any(
                "ensured" in str(event.get("message", "")).lower()
                for event in events
                if isinstance(event, dict)
            )
        finally:
            service.close_all()


class TestDeviceShellCallsAreBounded:
    """A wedged adb used to park the tool worker for as long as it liked.

    Measured: logcat, getprop and pm list all passed timeout=None and waited
    out a 2.5s block in full. The same device with a 30s block would have
    held the worker until the process died. ``ensure_frida_server`` already
    passed a timeout to ``su``; the rest of the surface did not.
    """

    def _backend(self, device: Any) -> AdbBackend:
        backend = AdbBackend()
        backend._available = True
        backend._adbutils = object()
        backend._device = lambda serial: device  # type: ignore[method-assign]
        return backend

    def test_logcat_properties_and_packages_pass_a_deadline(self) -> None:
        class _Recorder:
            def __init__(self) -> None:
                self.timeouts: list[float | None] = []

            def shell(self, cmd: object, timeout: float | None = None) -> str:
                self.timeouts.append(timeout)
                return ""

        device = _Recorder()
        backend = self._backend(device)
        backend.logcat("emulator-5554", lines=10)
        backend.properties("emulator-5554")
        backend.packages("emulator-5554")
        assert device.timeouts
        assert all(t is not None and t > 0 for t in device.timeouts)

    def test_a_blocking_shell_fails_instead_of_waiting_it_out(self) -> None:
        class _Blocker:
            def shell(self, cmd: object, timeout: float | None = None) -> str:
                if timeout is None:
                    raise AssertionError("unbounded shell would wait forever")
                raise TimeoutError(f"adb timed out after {timeout}")

        backend = self._backend(_Blocker())
        with pytest.raises(AdbError) as info:
            backend.logcat("emulator-5554", lines=10)
        assert info.value.code == "backend_error"
        assert "timed out" in info.value.message.lower() or "logcat" in info.value.message


class TestLaunchDoesNotInventSuccess:
    """``launched: True`` used to mean the monkey command returned, not that it started.

    Measured: a device whose monkey printed
    ``No activities found to run, monkey aborted`` still answered
    ``{'launched': True, 'package': 'com.missing.app'}``. An unattended agent
    then waits for an activity that was never in the foreground.
    """

    def _backend(self, output: str) -> AdbBackend:
        class _Dev:
            def shell(self, cmd: object, timeout: float | None = None) -> str:
                return output

        backend = AdbBackend()
        backend._available = True
        backend._adbutils = object()
        backend._device = lambda serial: _Dev()  # type: ignore[method-assign]
        return backend

    def test_a_monkey_abort_is_not_launched(self) -> None:
        with pytest.raises(AdbError) as info:
            self._backend(
                "** Error: monkey aborted\nNo activities found to run, monkey aborted."
            ).launch("emulator-5554", "com.missing.app")
        assert info.value.code == "backend_error"
        assert info.value.details.get("launched") is not True

    def test_an_unknown_package_is_not_launched(self) -> None:
        with pytest.raises(AdbError) as info:
            self._backend("** Error: Unknown package: com.missing.app").launch(
                "emulator-5554", "com.missing.app"
            )
        assert info.value.code == "backend_error"

    def test_empty_output_is_not_evidence_of_a_launch(self) -> None:
        with pytest.raises(AdbError) as info:
            self._backend("").launch("emulator-5554", "com.example.app")
        assert info.value.code == "backend_error"

    def test_an_injection_confirmation_is_launched(self) -> None:
        result = self._backend("Events injected: 1\n## Network stats: elapsed time=12ms").launch(
            "emulator-5554", "com.example.app"
        )
        assert result["launched"] is True
        assert result["package"] == "com.example.app"


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
