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


class TestAdbValidationPrecedesAvailability:
    """Injection is rejected before adbutils is consulted, on any host.

    The validators are exercised directly above, but that only proves the regex;
    it does not prove the method paths reach them before touching the optional
    backend. Force adbutils absent and drive the real methods: a hostile serial,
    package, or port must still surface invalid_params rather than the
    capability_unavailable that would otherwise mask it -- so the injection
    guarantee holds on a machine without adbutils (skip != pass).
    """

    def _unavailable_backend(self) -> AdbBackend:
        backend = AdbBackend()
        backend._available = False
        backend._adbutils = None
        return backend

    def test_connect_rejects_bad_port_without_adbutils(self) -> None:
        backend = self._unavailable_backend()
        with pytest.raises(AdbError) as info:
            backend.connect(port=99999)
        assert info.value.code == "invalid_params"

    def test_connect_rejects_bool_port_without_adbutils(self) -> None:
        backend = self._unavailable_backend()
        with pytest.raises(AdbError) as info:
            backend.connect(port=True)  # type: ignore[arg-type]
        assert info.value.code == "invalid_params"

    def test_connect_rejects_injection_in_host_without_adbutils(self) -> None:
        backend = self._unavailable_backend()
        with pytest.raises(AdbError) as info:
            backend.connect(host="127.0.0.1; rm -rf /", port=5555)
        assert info.value.code == "invalid_params"

    @pytest.mark.parametrize("method", ["uninstall", "launch", "force_stop"])
    def test_package_methods_reject_injection_without_adbutils(self, method: str) -> None:
        backend = self._unavailable_backend()
        with pytest.raises(AdbError) as info:
            getattr(backend, method)("emulator-5554", "com.x; id")
        assert info.value.code == "invalid_params"

    @pytest.mark.parametrize(
        "method", ["info", "properties", "packages", "logcat", "current_activity"]
    )
    def test_device_methods_reject_bad_serial_without_adbutils(self, method: str) -> None:
        backend = self._unavailable_backend()
        with pytest.raises(AdbError) as info:
            getattr(backend, method)("bad serial; rm -rf /")
        assert info.value.code == "invalid_params"


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


class TestFridaSpawnValidationPrecedesAvailability:
    """A malformed package is rejected before the device is resolved.

    frida.spawn drives the Android path (device_id="usb"), where resolving the
    device is a multi-second USB probe or a capability_unavailable when frida is
    absent. The package regex is the injection guard, so it must run first:
    force frida unavailable and confirm a hostile package still surfaces
    invalid_params rather than the capability_unavailable that would mask it, on
    any host (skip != pass).
    """

    def _unavailable_client(self) -> FridaClient:
        client = FridaClient()
        client._available = False
        client._frida = None
        return client

    @pytest.mark.parametrize(
        "package",
        [
            "com.example; rm -rf /",
            "com.example && id",
            "../../etc/passwd",
            "not a package",
            "nodots",
            "",
            "   ",
        ],
    )
    def test_spawn_rejects_a_bad_package_without_frida(self, package: str) -> None:
        client = self._unavailable_client()
        with pytest.raises(FridaError) as info:
            client.spawn("usb", package)
        assert info.value.code == "invalid_params"

    def test_spawn_of_a_valid_package_still_reports_the_missing_backend(self) -> None:
        client = self._unavailable_client()
        with pytest.raises(FridaError) as info:
            client.spawn("usb", "com.example.app")
        assert info.value.code == "capability_unavailable"


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


class TestApkRequiredArgsAreCheckedBeforeParsing:
    """An empty class/method name is rejected before the DEX is analysed.

    apk.methods and apk.xrefs run a full androguard analysis (seconds, tens of
    MB) or degrade to capability_unavailable when androguard is absent. The
    required-name check is cheap and can never pass, so it must run first: force
    androguard unavailable and confirm an empty name still surfaces
    invalid_params rather than the capability_unavailable (or wasted parse) that
    would otherwise mask it, while a real name falls through to the missing
    backend on any host (skip != pass).
    """

    def _unavailable_client(self) -> Any:
        from headless_re_mcp.backends.apk.client import ApkClient

        client = ApkClient()
        client._available = False
        client._androguard = None
        return client

    @pytest.mark.parametrize("op", ["methods", "xrefs"])
    @pytest.mark.parametrize("bad", ["", "   "])
    def test_empty_required_name_is_invalid_params(
        self, tmp_path: Path, op: str, bad: str
    ) -> None:
        from headless_re_mcp.backends.apk.client import ApkError

        client = self._unavailable_client()
        with pytest.raises(ApkError) as info:
            getattr(client, op)(tmp_path / "app.apk", bad)
        assert info.value.code == "invalid_params"

    @pytest.mark.parametrize("op", ["methods", "xrefs"])
    def test_a_real_name_falls_through_to_the_missing_backend(
        self, tmp_path: Path, op: str
    ) -> None:
        from headless_re_mcp.backends.apk.client import ApkError

        client = self._unavailable_client()
        with pytest.raises(ApkError) as info:
            getattr(client, op)(tmp_path / "app.apk", "decrypt")
        assert info.value.code == "capability_unavailable"


class TestApkMalformedInputIsStructured:
    """A malformed-but-openable APK reads as backend_error, never internal_error.

    androguard's ``APK`` constructor is lenient: on a file whose
    AndroidManifest.xml is not valid AXML it logs the problem and still returns
    an object, so the manifest getters are what fail -- ``get_package`` raises
    ``KeyError``. A malformed APK is hostile input, not a server defect, so every
    manifest-level read must surface a structured ``ApkError(backend_error)``
    rather than letting a raw exception escape (which the service maps to an
    ``internal_error`` incident). androguard must be present to reach the getters
    at all, so this skips rather than passes when it is absent (skip != pass).
    """

    def test_open_on_a_bad_manifest_is_backend_error(self, tmp_path: Path) -> None:
        pytest.importorskip("androguard")
        from headless_re_mcp.backends.apk.client import ApkClient, ApkError

        apk = _apk(tmp_path / "app.apk")
        client = ApkClient()
        with pytest.raises(ApkError) as info:
            client.open(apk)
        assert info.value.code == "backend_error"

    @pytest.mark.parametrize(
        "op",
        ["open", "manifest", "permissions", "certificates", "components", "native_libs"],
    )
    def test_manifest_reads_never_raise_unstructured(self, tmp_path: Path, op: str) -> None:
        pytest.importorskip("androguard")
        from headless_re_mcp.backends.apk.client import ApkClient, ApkError

        apk = _apk(tmp_path / "app.apk")
        client = ApkClient()
        # A raw (non-ApkError) exception would not be caught here and would fail
        # the test loudly -- which is exactly the internal_error leak we forbid.
        try:
            result = getattr(client, op)(apk)
        except ApkError as exc:
            assert exc.code == "backend_error"
        else:
            assert isinstance(result, dict)


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

    def test_decode_does_not_call_a_nonzero_exit_a_success(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A broken decode that still wrote a manifest was returned as success.

        Measured: apktool exit 1 plus AndroidManifest.xml on disk produced a
        normal decoded_dir payload with no exit_code. The agent then edits
        smali in a tree apktool already said was wrong. Build already refuses
        a nonzero exit; decode did not.
        """
        fake_tool = tmp_path / "apktool.bat"
        fake_tool.write_text("@echo off\n", encoding="utf-8")
        apk = _apk(tmp_path / "a.apk")
        out = tmp_path / "decoded"
        out.mkdir()
        (out / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")

        def fake_run(*_args: Any, **_kwargs: Any) -> tuple[str, str, int]:
            return "", "Could not decode resources", 1

        monkeypatch.setattr("headless_re_mcp.backends.apktool.client._run", fake_run)
        client = ApktoolClient(fake_tool, None)
        with pytest.raises(ApktoolError) as info:
            client.decode(apk, out)
        assert info.value.code == "backend_error"
        assert info.value.details.get("exit_code") == 1


class TestPeOnlyToolsRefuseApkSessions:
    def test_detect_dotnet_and_unpack_return_target_mismatch(self, tmp_path: Path) -> None:
        from dataclasses import replace

        from headless_re_mcp.config import Settings
        from headless_re_mcp.core.service import AnalysisService

        # Hosted quality has no UPX; the target check must still win.
        service = AnalysisService(
            replace(Settings.load(), artifact_root=tmp_path / "artifacts", upx=None)
        )
        try:
            created = service.create_session(str(_apk(tmp_path / "app.apk")), target="apk")
            assert created.ok, created.error
            session_id = str(created.data["session"]["id"])
            detect = service.detect_scan(session_id, use_die=False)
            assert detect.ok is False
            assert detect.error is not None
            assert detect.error.code == "target_mismatch"
            dotnet = service.dotnet_inspect(session_id)
            assert dotnet.ok is False
            assert dotnet.error is not None
            assert dotnet.error.code == "target_mismatch"
            unpack = service.unpack_upx_test(session_id)
            assert unpack.ok is False
            assert unpack.error is not None
            assert unpack.error.code == "target_mismatch"
        finally:
            service.close_all()

    def test_static_and_dynamic_open_leave_an_apk_session_created(
        self, tmp_path: Path
    ) -> None:
        from headless_re_mcp.core.service import AnalysisService

        service = AnalysisService()
        try:
            created = service.create_session(str(_apk(tmp_path / "app.apk")), target="apk")
            session_id = str(created.data["session"]["id"])
            static = service.open_static(session_id)
            assert static.ok is False
            assert static.error is not None
            assert static.error.code == "target_mismatch"
            assert service.get_session(session_id).data["session"]["state"] == "created"
            dynamic = service.open_dynamic(session_id)
            assert dynamic.ok is False
            assert dynamic.error is not None
            assert dynamic.error.code == "target_mismatch"
            assert service.get_session(session_id).data["session"]["state"] == "created"
        finally:
            service.close_all()

    def test_apk_repack_and_sign_refuse_host_paths(self, tmp_path: Path) -> None:
        from headless_re_mcp.config import Settings
        from headless_re_mcp.core.service import AnalysisService

        service = AnalysisService(
            Settings(
                ida_home=None,
                x64dbg_source=None,
                x64dbg_headless_x64=None,
                x64dbg_headless_x86=None,
                artifact_root=tmp_path / "artifacts",
            )
        )
        try:
            created = service.create_session(str(_apk(tmp_path / "app.apk")), target="apk")
            session_id = str(created.data["session"]["id"])
            outside = tmp_path / "host-decoded"
            outside.mkdir()
            (outside / "apktool.yml").write_text("x\n", encoding="utf-8")
            host_apk = tmp_path / "host.apk"
            host_apk.write_bytes(b"PK")
            host_ks = tmp_path / "host.keystore"
            host_ks.write_bytes(b"ks")
            repack = service.apk_repack(session_id, decoded_dir=str(outside))
            assert repack.ok is False
            assert repack.error is not None
            assert repack.error.code == "invalid_params"
            signed = service.apk_sign(
                session_id, apk_path=str(host_apk), keystore=str(host_ks)
            )
            assert signed.ok is False
            assert signed.error is not None
            assert signed.error.code == "invalid_params"
        finally:
            service.close_all()
