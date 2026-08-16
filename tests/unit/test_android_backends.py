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


class TestApkNativeLibsAreBounded:
    """A native-lib list used to be every .so in the APK with no way to see a cut."""

    def _client(self, monkeypatch: pytest.MonkeyPatch, count: int) -> Any:
        from headless_re_mcp.backends.apk.client import ApkClient

        class _Apk:
            def get_files(self) -> list[str]:
                return [f"lib/arm64-v8a/lib{index}.so" for index in range(count)]

        client = ApkClient()
        monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _Apk())
        return client

    def test_a_large_lib_list_is_cut_and_said_so(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = self._client(monkeypatch, 2500).native_libs(tmp_path / "app.apk", limit=500)
        assert len(result["native_libs"]) == 500
        assert result["count"] == 500
        assert result["total"] == 2500
        assert result["has_more"] is True
        assert result["abis"] == ["arm64-v8a"]

    def test_a_short_list_is_not_labelled_partial(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = self._client(monkeypatch, 3).native_libs(tmp_path / "app.apk", limit=500)
        assert result["has_more"] is False
        assert result["total"] == 3
        assert result["count"] == 3

    def test_a_page_that_exactly_fills_is_complete(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = self._client(monkeypatch, 500).native_libs(tmp_path / "app.apk", limit=500)
        assert result["count"] == 500
        assert result["has_more"] is False


class TestApkStringsSayWhenTheyStopped:
    """A string page that filled used to look like every constant if count was all you read."""

    def _client(self, monkeypatch: pytest.MonkeyPatch, count: int) -> Any:
        from headless_re_mcp.backends.apk.client import ApkClient

        class _Str:
            def __init__(self, value: str) -> None:
                self._value = value

            def get_value(self) -> str:
                return self._value

        class _Parsed:
            def __init__(self) -> None:
                self.analysis = self

            def get_strings(self) -> list[_Str]:
                return [_Str(f"s{index}") for index in range(count)]

        client = ApkClient()
        monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: _Parsed())
        return client

    def test_a_full_page_is_marked(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = self._client(monkeypatch, 500).strings(tmp_path / "app.apk", limit=200)
        assert result["count"] == 200
        assert result["total"] == 500
        assert result["has_more"] is True

    def test_a_short_list_is_not_labelled_partial(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = self._client(monkeypatch, 3).strings(tmp_path / "app.apk", limit=200)
        assert result["has_more"] is False
        assert result["total"] == 3


class TestApkMethodsSayWhenTheyStopped:
    """A method page that filled used to look like every method if count was all you read."""

    def _client(self, monkeypatch: pytest.MonkeyPatch, count: int) -> Any:
        from headless_re_mcp.backends.apk.client import ApkClient

        class _Method:
            def __init__(self, name: str) -> None:
                self.name = name
                self.descriptor = "()V"
                self.access = "public"

        class _Klass:
            name = "Lcom/ex/A;"

            def get_methods(self) -> list[_Method]:
                return [_Method(f"m{index}") for index in range(count)]

        class _Parsed:
            def __init__(self) -> None:
                self.analysis = self

            def get_classes(self) -> list[_Klass]:
                return [_Klass()]

        client = ApkClient()
        monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: _Parsed())
        return client

    def test_a_full_page_is_marked(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = self._client(monkeypatch, 250).methods(
            tmp_path / "app.apk", "Lcom/ex/A;", limit=100
        )
        assert result["count"] == 100
        assert result["total"] == 250
        assert result["has_more"] is True

    def test_a_short_list_is_not_labelled_partial(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = self._client(monkeypatch, 3).methods(
            tmp_path / "app.apk", "Lcom/ex/A;", limit=100
        )
        assert result["has_more"] is False
        assert result["total"] == 3


class TestApkClassesSayWhenTheyStopped:
    """A class page that filled used to look like the whole DEX if count was all you read."""

    def _client(self, monkeypatch: pytest.MonkeyPatch, count: int) -> Any:
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
                return [_Klass(f"L{index};") for index in range(count)]

        client = ApkClient()
        monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: _Parsed())
        return client

    def test_a_full_page_is_marked(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = self._client(monkeypatch, 250).classes(tmp_path / "app.apk", limit=100)
        assert result["count"] == 100
        assert result["total"] == 250
        assert result["has_more"] is True

    def test_a_short_list_is_not_labelled_partial(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = self._client(monkeypatch, 3).classes(tmp_path / "app.apk", limit=100)
        assert result["has_more"] is False
        assert result["total"] == 3

    def test_a_page_that_exactly_fills_is_complete(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = self._client(monkeypatch, 100).classes(tmp_path / "app.apk", limit=100)
        assert result["count"] == 100
        assert result["has_more"] is False


class TestApkCertificatesAreBounded:
    """A certificate list used to be every signer with no way to see a cut."""

    def _client(self, monkeypatch: pytest.MonkeyPatch, count: int) -> Any:
        from headless_re_mcp.backends.apk.client import ApkClient

        class _Cert:
            def __init__(self, index: int) -> None:
                self.subject = f"CN=c{index}"
                self.issuer = f"CN=i{index}"
                self.serial_number = index
                self.sha256_fingerprint = "aa" * 32

        class _Apk:
            def get_signature_names(self) -> list[str]:
                return [f"CERT{index}.RSA" for index in range(count)]

            def get_certificates(self) -> list[_Cert]:
                return [_Cert(index) for index in range(count)]

        client = ApkClient()
        monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _Apk())
        return client

    def test_a_large_list_is_cut_and_said_so(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = self._client(monkeypatch, 200).certificates(tmp_path / "app.apk", limit=50)
        assert len(result["certificates"]) == 50
        assert result["totals"]["certificates"] == 200
        assert result["has_more"] is True

    def test_a_short_list_is_not_labelled_partial(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = self._client(monkeypatch, 2).certificates(tmp_path / "app.apk", limit=50)
        assert result["has_more"] is False
        assert result["totals"]["certificates"] == 2


class TestApkPermissionsAreBounded:
    """A permission list used to be the whole manifest with no way to see a cut."""

    def _client(self, monkeypatch: pytest.MonkeyPatch, count: int) -> Any:
        from headless_re_mcp.backends.apk.client import ApkClient

        class _Apk:
            def get_permissions(self) -> list[str]:
                return [f"android.permission.P{index}" for index in range(count)]

            def get_requested_permissions(self) -> list[str]:
                return [f"android.permission.P{index}" for index in range(count)]

        client = ApkClient()
        monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _Apk())
        return client

    def test_a_large_permission_list_is_cut_and_said_so(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = self._client(monkeypatch, 800).permissions(tmp_path / "app.apk", limit=500)
        assert len(result["permissions"]) == 500
        assert result["count"] == 500
        assert result["totals"]["permissions"] == 800
        assert result["has_more"] is True

    def test_a_short_list_is_not_labelled_partial(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = self._client(monkeypatch, 3).permissions(tmp_path / "app.apk", limit=500)
        assert result["has_more"] is False
        assert result["totals"]["permissions"] == 3
        assert result["count"] == 3

    def test_a_page_that_exactly_fills_is_complete(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = self._client(monkeypatch, 500).permissions(tmp_path / "app.apk", limit=500)
        assert result["count"] == 500
        assert result["has_more"] is False


class TestApkComponentsAreBounded:
    """A component list used to be the whole manifest with no way to see a cut."""

    def _client(self, monkeypatch: pytest.MonkeyPatch, activities: int) -> Any:
        from headless_re_mcp.backends.apk.client import ApkClient

        class _Apk:
            def get_activities(self) -> list[str]:
                return [f"A{index}" for index in range(activities)]

            def get_services(self) -> list[str]:
                return ["S0"]

            def get_receivers(self) -> list[str]:
                return []

            def get_providers(self) -> list[str]:
                return []

            def get_main_activity(self) -> str:
                return "A0"

        client = ApkClient()
        monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _Apk())
        return client

    def test_a_large_activity_list_is_cut_and_said_so(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = self._client(monkeypatch, 3000).components(tmp_path / "app.apk", limit=500)
        assert len(result["activities"]) == 500
        assert result["totals"]["activities"] == 3000
        assert result["has_more"] is True

    def test_a_short_list_is_not_labelled_partial(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = self._client(monkeypatch, 3).components(tmp_path / "app.apk", limit=500)
        assert result["has_more"] is False
        assert result["totals"]["activities"] == 3


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


class TestFridaDevicesSayWhenTheyStopped:
    """A device listing that filled used to look like every device if count was all you read."""

    def _client(self, count: int) -> FridaClient:
        class _Dev:
            def __init__(self, index: int) -> None:
                self.id = f"dev{index}"
                self.name = f"Device {index}"
                self.type = "usb"

        class _Frida:
            def enumerate_devices(self) -> list[_Dev]:
                return [_Dev(index) for index in range(count)]

        client = FridaClient()
        client._available = True
        client._frida = _Frida()
        return client

    def test_a_full_page_is_marked(self) -> None:
        result = self._client(50).enumerate_devices(limit=32)
        assert result["count"] == 32
        assert result["total"] == 50
        assert result["has_more"] is True

    def test_a_short_list_is_not_labelled_partial(self) -> None:
        result = self._client(3).enumerate_devices(limit=32)
        assert result["has_more"] is False
        assert result["total"] == 3


class TestFridaApplicationsSayWhenTheyStopped:
    """An application page that filled used to look like every package if count was all you read."""

    def _client(self, count: int) -> FridaClient:
        class _App:
            def __init__(self, index: int) -> None:
                self.identifier = f"com.app{index}"
                self.name = f"App{index}"
                self.pid = 0

        class _Dev:
            def enumerate_applications(self) -> list[_App]:
                return [_App(index) for index in range(count)]

        client = FridaClient()
        client._available = True
        client._frida = object()
        client._resolve_device = lambda device_id: _Dev()  # type: ignore[method-assign]
        return client

    def test_a_full_page_is_marked(self) -> None:
        result = self._client(400).applications("usb", limit=256)
        assert result["count"] == 256
        assert result["total"] == 400
        assert result["has_more"] is True

    def test_a_short_list_is_not_labelled_partial(self) -> None:
        result = self._client(3).applications("usb", limit=256)
        assert result["has_more"] is False
        assert result["total"] == 3


class TestFridaModulesSayWhenTheyStopped:
    """A module page that filled used to look like every mapping if count was all you read."""

    def _client(self, count: int) -> FridaClient:
        class _Exports:
            def modules(self) -> list[dict[str, object]]:
                return [
                    {"name": f"m{index}", "base": "0x1", "size": 1, "path": f"/lib/{index}"}
                    for index in range(count)
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

        client = FridaClient()
        client._available = True
        client._frida = _Frida()
        return client

    def test_a_full_page_is_marked(self) -> None:
        result = self._client(100).modules(1, allowed_pid=1, limit=64)
        assert result["count"] == 64
        assert result["total"] == 100
        assert result["has_more"] is True

    def test_a_short_list_is_not_labelled_partial(self) -> None:
        result = self._client(3).modules(1, allowed_pid=1, limit=64)
        assert result["has_more"] is False
        assert result["total"] == 3


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


class TestEnsureFridaServerPushIsBounded:
    """Pushing frida-server used the same unbounded sync.push as device.push.

    Measured: a 2.5s block on push was waited out in full before the
    post-launch ps ran.
    """

    def test_a_blocking_push_fails_instead_of_waiting_it_out(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import time

        from headless_re_mcp.backends.adb import client as adb_client

        monkeypatch.setattr(adb_client, "_PUSH_TIMEOUT", 0.2)
        binary = tmp_path / "frida-server"
        binary.write_bytes(b"x")

        class _Sync:
            def push(self, src: str, dst: str) -> int:
                time.sleep(5)
                return 1

        class _Dev:
            sync = _Sync()

            def shell(self, cmd: object, timeout: float | None = None) -> str:
                return "root 1 0 init"

        backend = AdbBackend()
        backend._available = True
        backend._adbutils = object()
        backend._device = lambda serial: _Dev()  # type: ignore[method-assign]
        started = time.monotonic()
        with pytest.raises(AdbError) as info:
            backend.ensure_frida_server("emulator-5554", server_binary=str(binary))
        assert info.value.code == "backend_error"
        assert time.monotonic() - started < 1.5


class TestDevicePropertiesSayWhenTheyStopped:
    """A getprop page that hit the cap used to look like the whole property set."""

    def _backend(self, count: int) -> AdbBackend:
        class _Dev:
            def shell(self, cmd: object, timeout: float | None = None) -> str:
                return "\n".join(f"[ro.k{index}]: [v{index}]" for index in range(count))

        backend = AdbBackend()
        backend._available = True
        backend._adbutils = object()
        backend._device = lambda serial: _Dev()  # type: ignore[method-assign]
        return backend

    def test_hitting_the_cap_is_reported(self) -> None:
        result = self._backend(2000).properties("emulator-5554", limit=500)
        assert result["count"] == 500
        assert result["total"] == 2000
        assert result["has_more"] is True
        assert len(result["properties"]) == 500

    def test_a_short_answer_is_not_labelled_partial(self) -> None:
        result = self._backend(3).properties("emulator-5554", limit=500)
        assert result["count"] == 3
        assert result["has_more"] is False

    def test_a_page_that_exactly_fills_is_complete(self) -> None:
        result = self._backend(500).properties("emulator-5554", limit=500)
        assert result["count"] == 500
        assert result["has_more"] is False


class TestDevicePackagesAreBounded:
    """A device image can list thousands of packages; the reply used to be all of them."""

    def _backend(self, count: int) -> AdbBackend:
        class _Dev:
            def shell(self, cmd: object, timeout: float | None = None) -> str:
                return "\n".join(f"package:com.example.app{index}" for index in range(count))

        backend = AdbBackend()
        backend._available = True
        backend._adbutils = object()
        backend._device = lambda serial: _Dev()  # type: ignore[method-assign]
        return backend

    def test_a_full_device_is_not_returned_as_one_page(self) -> None:
        result = self._backend(8000).packages("emulator-5554", limit=500)
        assert result["count"] == 500
        assert result["total"] == 8000
        assert result["has_more"] is True
        assert len(result["packages"]) == 500

    def test_a_short_list_is_not_labelled_partial(self) -> None:
        result = self._backend(3).packages("emulator-5554", limit=500)
        assert result["count"] == 3
        assert result["total"] == 3
        assert result["has_more"] is False

    def test_a_page_that_exactly_fills_is_complete(self) -> None:
        result = self._backend(500).packages("emulator-5554", limit=500)
        assert result["count"] == 500
        assert result["has_more"] is False


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


class TestDeviceInstallIsBounded:
    """A wedged adbutils.install used to park the tool worker with no deadline.

    Measured: device.install called install() with no timeout, so a 2.5s
    block was waited out in full and still answered installed=True.
    """

    def _backend(self, device: Any) -> AdbBackend:
        backend = AdbBackend()
        backend._available = True
        backend._adbutils = object()
        backend._device = lambda serial: device  # type: ignore[method-assign]
        return backend

    def test_a_blocking_install_fails_instead_of_waiting_it_out(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import time

        from headless_re_mcp.backends.adb import client as adb_client

        monkeypatch.setattr(adb_client, "_INSTALL_TIMEOUT", 0.2)
        apk = tmp_path / "app.apk"
        apk.write_bytes(b"PK")

        class _Dev:
            def install(self, *args: object, **kwargs: object) -> None:
                time.sleep(5)

        started = time.monotonic()
        with pytest.raises(AdbError) as info:
            self._backend(_Dev()).install("emulator-5554", str(apk))
        assert info.value.code == "backend_error"
        assert time.monotonic() - started < 1.5

    def test_a_finished_install_is_success(self, tmp_path: Path) -> None:
        apk = tmp_path / "app.apk"
        apk.write_bytes(b"PK")

        class _Dev:
            def install(self, *args: object, **kwargs: object) -> None:
                return None

        result = self._backend(_Dev()).install("emulator-5554", str(apk))
        assert result["installed"] is True


class TestDeviceForwardIsBounded:
    """A wedged adb forward used to park the tool worker with no deadline.

    Measured: device.forward called adbutils.forward with no timeout, so a
    2.5s block was waited out in full and still returned the mapping.
    """

    def _backend(self, device: Any) -> AdbBackend:
        backend = AdbBackend()
        backend._available = True
        backend._adbutils = object()
        backend._device = lambda serial: device  # type: ignore[method-assign]
        return backend

    def test_a_blocking_forward_fails_instead_of_waiting_it_out(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import time

        from headless_re_mcp.backends.adb import client as adb_client

        monkeypatch.setattr(adb_client, "_SHELL_TIMEOUT", 0.2)

        class _Dev:
            def forward(self, local: str, remote: str) -> None:
                time.sleep(5)

        started = time.monotonic()
        with pytest.raises(AdbError) as info:
            self._backend(_Dev()).forward("emulator-5554", "tcp:27042", "tcp:27042")
        assert info.value.code == "backend_error"
        assert time.monotonic() - started < 1.5

    def test_a_finished_forward_is_success(self) -> None:
        class _Dev:
            def forward(self, local: str, remote: str) -> None:
                return None

        result = self._backend(_Dev()).forward("emulator-5554", "tcp:27042", "tcp:27042")
        assert result["local"] == "tcp:27042"


class TestDevicePushIsBounded:
    """A wedged sync.push used to park the tool worker for as long as adb liked.

    Measured: device.push called sync.push with no deadline, so a 2.5s block
    was waited out in full and still returned success. adbutils opens that
    transport with timeout=None (library default 600s).
    """

    def _backend(self, device: Any) -> AdbBackend:
        backend = AdbBackend()
        backend._available = True
        backend._adbutils = object()
        backend._device = lambda serial: device  # type: ignore[method-assign]
        return backend

    def test_a_blocking_push_fails_instead_of_waiting_it_out(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import time

        from headless_re_mcp.backends.adb import client as adb_client

        monkeypatch.setattr(adb_client, "_PUSH_TIMEOUT", 0.2)
        local = tmp_path / "x.bin"
        local.write_bytes(b"x")

        class _Sync:
            def push(self, src: str, dst: str) -> int:
                time.sleep(5)
                return 1

        class _Dev:
            sync = _Sync()

        started = time.monotonic()
        with pytest.raises(AdbError) as info:
            self._backend(_Dev()).push("emulator-5554", str(local), "/data/local/tmp/x")
        assert info.value.code == "backend_error"
        assert time.monotonic() - started < 1.5

    def test_a_finished_push_is_success(self, tmp_path: Path) -> None:
        local = tmp_path / "x.bin"
        local.write_bytes(b"x")

        class _Sync:
            def push(self, src: str, dst: str) -> int:
                return 1

        class _Dev:
            sync = _Sync()

        result = self._backend(_Dev()).push(
            "emulator-5554", str(local), "/data/local/tmp/x"
        )
        assert result["remote"] == "/data/local/tmp/x"


class TestDevicePullIsBounded:
    """A wedged sync.pull used to park the tool worker with no deadline.

    Measured: device.pull called sync.pull with no timeout, so a 2.5s block
    was waited out in full and still returned a path.
    """

    def test_a_blocking_pull_fails_instead_of_waiting_it_out(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import time

        from headless_re_mcp.backends.adb import client as adb_client

        monkeypatch.setattr(adb_client, "_PULL_TIMEOUT", 0.2)

        class _Sync:
            def pull(self, src: str, dst: str) -> int:
                time.sleep(5)
                return 0

        class _Dev:
            sync = _Sync()

        backend = AdbBackend()
        backend._available = True
        backend._adbutils = object()
        backend._device = lambda serial: _Dev()  # type: ignore[method-assign]
        started = time.monotonic()
        with pytest.raises(AdbError) as info:
            backend.pull("emulator-5554", "/sdcard/x.bin", tmp_path / "x.bin")
        assert info.value.code == "backend_error"
        assert time.monotonic() - started < 1.5


class TestPullDoesNotInventAFile:
    """A pull that wrote nothing used to return a local path as if it had.

    Measured: ``sync.pull`` returning 0 without creating the destination
    still answered ``{'remote': ..., 'local': <missing path>}``. An
    unattended agent then treats a missing file as captured evidence.
    """

    def _backend(self, device: Any) -> AdbBackend:
        backend = AdbBackend()
        backend._available = True
        backend._adbutils = object()
        backend._device = lambda serial: device  # type: ignore[method-assign]
        return backend

    def test_a_missing_local_file_is_not_a_pull(self, tmp_path: Path) -> None:
        class _Sync:
            def pull(self, src: str, dst: str) -> int:
                return 0

        class _Dev:
            sync = _Sync()

        with pytest.raises(AdbError) as info:
            self._backend(_Dev()).pull("emulator-5554", "/sdcard/x.bin", tmp_path / "x.bin")
        assert info.value.code == "backend_error"
        assert not (tmp_path / "x.bin").exists()

    def test_a_written_file_is_a_pull(self, tmp_path: Path) -> None:
        class _Sync:
            def pull(self, src: str, dst: str) -> int:
                Path(dst).write_bytes(b"data")
                return 4

        class _Dev:
            sync = _Sync()

        result = self._backend(_Dev()).pull(
            "emulator-5554", "/sdcard/x.bin", tmp_path / "x.bin"
        )
        assert Path(result["local"]).read_bytes() == b"data"


class TestDeviceListDoesNotProbeState:
    """Listing devices used to call get_state once per serial with no deadline.

    Measured: three devices whose get_state blocked 0.4s each made
    list_devices wait 1.2s. adbutils.device_list() already yields only
    state=device, so the extra probe was both unbounded and redundant.
    """

    def test_a_blocking_get_state_is_not_consulted(self) -> None:
        class _Listed:
            serial = "emulator-5554"

        class _Client:
            def device_list(self) -> list[_Listed]:
                return [_Listed(), _Listed(), _Listed()]

            def device(self, serial: str | None = None) -> Any:
                raise AssertionError("get_state probe would wait forever")

        backend = AdbBackend()
        backend._available = True
        backend._adbutils = object()
        backend._client = lambda: _Client()  # type: ignore[method-assign]
        result = backend.list_devices()
        assert result["count"] == 3
        assert all(item["state"] == "device" for item in result["devices"])


class TestDeviceListIsBounded:
    """A wedged host:devices used to park the tool worker with no deadline.

    Measured: device.list called adbutils.device_list with no timeout, so a
    2.5s block was waited out in full and still returned the listing.
    """

    def test_a_blocking_device_list_fails_instead_of_waiting_it_out(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import time

        from headless_re_mcp.backends.adb import client as adb_client

        monkeypatch.setattr(adb_client, "_SHELL_TIMEOUT", 0.2)

        class _Client:
            def device_list(self) -> list[object]:
                time.sleep(5)
                return []

        backend = AdbBackend()
        backend._available = True
        backend._adbutils = object()
        backend._client = lambda: _Client()  # type: ignore[method-assign]
        started = time.monotonic()
        with pytest.raises(AdbError) as info:
            backend.list_devices()
        assert info.value.code == "backend_error"
        assert time.monotonic() - started < 1.5

    def test_a_finished_device_list_is_success(self) -> None:
        class _Listed:
            serial = "emulator-5554"

        class _Client:
            def device_list(self) -> list[_Listed]:
                return [_Listed()]

        backend = AdbBackend()
        backend._available = True
        backend._adbutils = object()
        backend._client = lambda: _Client()  # type: ignore[method-assign]
        result = backend.list_devices()
        assert result["count"] == 1
        assert result["devices"][0]["serial"] == "emulator-5554"


class TestDeviceInfoIsBounded:
    """device.info used to read properties through adbutils getprop with no deadline.

    Measured: six untimed property reads waited out 2.4s of blocks in full.
    The same device with adbutils' 600s shell default would have held the
    worker for each field.
    """

    def _backend(self, device: Any) -> AdbBackend:
        backend = AdbBackend()
        backend._available = True
        backend._adbutils = object()
        backend._device = lambda serial: device  # type: ignore[method-assign]
        return backend

    def test_property_reads_pass_a_deadline(self) -> None:
        class _Recorder:
            def __init__(self) -> None:
                self.timeouts: list[float | None] = []

            def get_state(self) -> str:
                return "device"

            def shell(self, cmd: object, timeout: float | None = None) -> str:
                self.timeouts.append(timeout)
                return "value"

        device = _Recorder()
        result = self._backend(device).info("emulator-5554")
        assert result["model"] == "value"
        assert device.timeouts
        assert all(t is not None and t > 0 for t in device.timeouts)

    def test_a_blocking_getprop_fails_instead_of_waiting_it_out(self) -> None:
        class _Blocker:
            def get_state(self) -> str:
                return "device"

            def shell(self, cmd: object, timeout: float | None = None) -> str:
                if timeout is None:
                    raise AssertionError("unbounded getprop would wait forever")
                raise TimeoutError(f"adb timed out after {timeout}")

        with pytest.raises(AdbError) as info:
            self._backend(_Blocker()).info("emulator-5554")
        assert info.value.code == "backend_error"

    def test_a_blocking_get_state_fails_instead_of_waiting_it_out(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import time

        from headless_re_mcp.backends.adb import client as adb_client

        monkeypatch.setattr(adb_client, "_SHELL_TIMEOUT", 0.2)

        class _Wedged:
            def get_state(self) -> str:
                time.sleep(5)
                return "device"

            def shell(self, cmd: object, timeout: float | None = None) -> str:
                return "value"

        started = time.monotonic()
        with pytest.raises(AdbError) as info:
            self._backend(_Wedged()).info("emulator-5554")
        assert info.value.code == "backend_error"
        assert time.monotonic() - started < 1.5
        assert "timed out" in info.value.message.lower() or "info" in info.value.message


class TestDeviceScreenshotIsBounded:
    """A wedged screencap used to park the tool worker for as long as adb liked.

    Measured: ``dev.screenshot()`` has no timeout argument, so a 2.5s block
    was waited out in full and still returned a path. The same device with
    adbutils' 600s shell default would have held the worker for ten minutes.
    """

    def _backend(self, device: Any) -> AdbBackend:
        backend = AdbBackend()
        backend._available = True
        backend._adbutils = object()
        backend._device = lambda serial: device  # type: ignore[method-assign]
        return backend

    def test_screencap_passes_a_deadline(self, tmp_path: Path) -> None:
        class _Recorder:
            def __init__(self) -> None:
                self.timeouts: list[float | None] = []

            def shell(
                self,
                cmd: object,
                timeout: float | None = None,
                encoding: str | None = "utf-8",
            ) -> bytes:
                self.timeouts.append(timeout)
                return b"\x89PNG\r\n\x1a\n"

        device = _Recorder()
        result = self._backend(device).screenshot("emulator-5554", tmp_path / "shot.png")
        assert device.timeouts
        assert all(t is not None and t > 0 for t in device.timeouts)
        assert Path(result["path"]).read_bytes().startswith(b"\x89PNG")

    def test_a_blocking_screencap_fails_instead_of_waiting_it_out(
        self, tmp_path: Path
    ) -> None:
        class _Blocker:
            def shell(
                self,
                cmd: object,
                timeout: float | None = None,
                encoding: str | None = "utf-8",
            ) -> bytes:
                if timeout is None:
                    raise AssertionError("unbounded screenshot would wait forever")
                raise TimeoutError(f"adb timed out after {timeout}")

        with pytest.raises(AdbError) as info:
            self._backend(_Blocker()).screenshot("emulator-5554", tmp_path / "shot.png")
        assert info.value.code == "backend_error"
        assert "timed out" in info.value.message.lower() or "screenshot" in info.value.message

    def test_empty_output_is_not_a_screenshot(self, tmp_path: Path) -> None:
        class _Empty:
            def shell(
                self,
                cmd: object,
                timeout: float | None = None,
                encoding: str | None = "utf-8",
            ) -> bytes:
                return b""

        with pytest.raises(AdbError) as info:
            self._backend(_Empty()).screenshot("emulator-5554", tmp_path / "shot.png")
        assert info.value.code == "backend_error"
        assert not (tmp_path / "shot.png").exists()


class TestUninstallDoesNotInventSuccess:
    """``uninstalled: True`` used to mean the command returned, not that pm removed it.

    Measured: a device whose ``pm uninstall`` printed
    ``Failure [DELETE_FAILED_INTERNAL_ERROR]`` still answered
    ``{'uninstalled': True, 'package': 'com.missing.app'}``. An unattended
    agent then treats a still-installed (or never-installed) package as gone.
    """

    def _backend(self, output: object) -> AdbBackend:
        class _Dev:
            def uninstall(self, package: str) -> object:
                return output

        backend = AdbBackend()
        backend._available = True
        backend._adbutils = object()
        backend._device = lambda serial: _Dev()  # type: ignore[method-assign]
        return backend

    def test_a_pm_failure_is_not_uninstalled(self) -> None:
        with pytest.raises(AdbError) as info:
            self._backend("Failure [DELETE_FAILED_INTERNAL_ERROR]").uninstall(
                "emulator-5554", "com.missing.app"
            )
        assert info.value.code == "backend_error"
        assert info.value.details.get("uninstalled") is not True
        assert "not remove" in info.value.message

    def test_empty_output_is_not_evidence_of_an_uninstall(self) -> None:
        with pytest.raises(AdbError) as info:
            self._backend("").uninstall("emulator-5554", "com.example.app")
        assert info.value.code == "backend_error"

    def test_a_success_line_is_uninstalled(self) -> None:
        result = self._backend("Success").uninstall("emulator-5554", "com.example.app")
        assert result["uninstalled"] is True
        assert result["package"] == "com.example.app"


class TestDeviceUninstallIsBounded:
    """A wedged adbutils.uninstall used to park the tool worker with no deadline.

    Measured: device.uninstall called uninstall() with no timeout, so a 2.5s
    block was waited out in full and still answered uninstalled=True.
    """

    def _backend(self, device: Any) -> AdbBackend:
        backend = AdbBackend()
        backend._available = True
        backend._adbutils = object()
        backend._device = lambda serial: device  # type: ignore[method-assign]
        return backend

    def test_a_blocking_uninstall_fails_instead_of_waiting_it_out(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import time

        from headless_re_mcp.backends.adb import client as adb_client

        monkeypatch.setattr(adb_client, "_UNINSTALL_TIMEOUT", 0.2)

        class _Dev:
            def uninstall(self, package: str) -> str:
                time.sleep(5)
                return "Success"

        started = time.monotonic()
        with pytest.raises(AdbError) as info:
            self._backend(_Dev()).uninstall("emulator-5554", "com.example.app")
        assert info.value.code == "backend_error"
        assert time.monotonic() - started < 1.5

    def test_a_finished_uninstall_is_success(self) -> None:
        class _Dev:
            def uninstall(self, package: str) -> str:
                return "Success"

        result = self._backend(_Dev()).uninstall("emulator-5554", "com.example.app")
        assert result["uninstalled"] is True


class TestForceStopDoesNotInventSuccess:
    """``stopped: True`` used to mean the am command returned, not that it stopped.

    Measured: a device whose force-stop printed
    ``Error type 3 / Error: Activity class does not exist.`` still answered
    ``{'stopped': True, 'package': 'com.missing.app'}``.
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

    def test_an_error_line_is_not_stopped(self) -> None:
        with pytest.raises(AdbError) as info:
            self._backend("Error type 3\nError: Activity class does not exist.").force_stop(
                "emulator-5554", "com.missing.app"
            )
        assert info.value.code == "backend_error"
        assert info.value.details.get("stopped") is not True

    def test_empty_output_is_stopped(self) -> None:
        result = self._backend("").force_stop("emulator-5554", "com.example.app")
        assert result["stopped"] is True
        assert result["package"] == "com.example.app"


class TestCurrentActivityIsBounded:
    """A wedged app_current used to park the tool worker with no deadline.

    Measured: device.current_activity called app_current() with no timeout,
    so a 2.5s block was waited out in full and still returned a package.
    """

    def _backend(self, device: Any) -> AdbBackend:
        backend = AdbBackend()
        backend._available = True
        backend._adbutils = object()
        backend._device = lambda serial: device  # type: ignore[method-assign]
        return backend

    def test_a_blocking_app_current_fails_instead_of_waiting_it_out(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import time
        from types import SimpleNamespace

        from headless_re_mcp.backends.adb import client as adb_client

        monkeypatch.setattr(adb_client, "_SHELL_TIMEOUT", 0.2)

        class _Dev:
            def app_current(self) -> SimpleNamespace:
                time.sleep(5)
                return SimpleNamespace(package="com.example.app", activity=".Main")

        started = time.monotonic()
        with pytest.raises(AdbError) as info:
            self._backend(_Dev()).current_activity("emulator-5554")
        assert info.value.code == "backend_error"
        assert time.monotonic() - started < 1.5

    def test_a_finished_app_current_is_success(self) -> None:
        from types import SimpleNamespace

        class _Dev:
            def app_current(self) -> SimpleNamespace:
                return SimpleNamespace(package="com.example.app", activity=".Main")

        result = self._backend(_Dev()).current_activity("emulator-5554")
        assert result["package"] == "com.example.app"
        assert result["activity"] == ".Main"


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


class TestJadxExportSaysWhenTheFileListWasCut:
    """java_file_count used to be the whole tree while the list silently stopped at 2000."""

    def _client(self, monkeypatch: pytest.MonkeyPatch) -> Any:
        from headless_re_mcp.backends.jadx.client import JadxClient

        monkeypatch.setattr(
            JadxClient, "_run", lambda self, apk, extra, out_dir, timeout=0: ("", "", 0)
        )
        return JadxClient(None)

    def test_a_cut_list_is_marked(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        out = tmp_path / "jadx" / "sources"
        out.mkdir(parents=True)
        for index in range(2500):
            (out / f"C{index}.java").write_text("class X{}", encoding="utf-8")
        result = self._client(monkeypatch).export_sources(tmp_path / "a.apk", tmp_path / "jadx")

        assert result["java_file_count"] == 2500
        assert len(result["java_files"]) == 2000
        assert result["has_more"] is True

    def test_a_short_tree_is_not_labelled_partial(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        out = tmp_path / "jadx" / "sources"
        out.mkdir(parents=True)
        (out / "Main.java").write_text("class Main{}", encoding="utf-8")
        result = self._client(monkeypatch).export_sources(tmp_path / "a.apk", tmp_path / "jadx")

        assert result["java_file_count"] == 1
        assert result["has_more"] is False


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
