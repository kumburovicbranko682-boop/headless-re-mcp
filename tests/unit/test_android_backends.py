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

    def _modules_client(self, count: int) -> Any:
        from headless_re_mcp.backends.frida.client import FridaClient

        class FakeExports:
            def modules(self) -> list[dict[str, object]]:
                return [
                    {"name": f"m{index}", "base": "0x1", "size": 1, "path": f"/m{index}"}
                    for index in range(count)
                ]

        class FakeScript:
            exports_sync = FakeExports()

            def load(self) -> None:
                return None

        class FakeSession:
            def create_script(self, source: str) -> FakeScript:
                del source
                return FakeScript()

            def detach(self) -> None:
                return None

        class FakeFrida:
            def attach(self, pid: int) -> FakeSession:
                del pid
                return FakeSession()

        client = FridaClient()
        client._available = True
        client._frida = FakeFrida()
        return client

    def test_a_module_page_says_what_was_left_out(self) -> None:
        result = self._modules_client(200).modules(1, allowed_pid=1, limit=64)
        assert result["count"] == 64
        assert result["total"] == 200
        assert result["has_more"] is True
        assert len(result["modules"]) == 64

    def test_a_short_module_list_is_complete(self) -> None:
        result = self._modules_client(3).modules(1, allowed_pid=1, limit=64)
        assert result["count"] == 3
        assert result["total"] == 3
        assert result["has_more"] is False


class TestFridaApplicationsSayWhenTheyStopped:
    """A device app list that hit the cap looked complete except for total.

    Measured: 400 applications came back as count=256, total=400, and no
    has_more.
    """

    def _client(self, count: int) -> Any:
        from headless_re_mcp.backends.frida.client import FridaClient

        class App:
            def __init__(self, index: int) -> None:
                self.identifier = f"com.app{index}"
                self.name = f"App{index}"
                self.pid = 0

        class Device:
            def enumerate_applications(self) -> list[App]:
                return [App(index) for index in range(count)]

        client = FridaClient()
        client._available = True
        client._frida = object()
        client._resolve_device = lambda device_id: Device()  # type: ignore[method-assign]
        return client

    def test_a_long_list_says_what_was_left_out(self) -> None:
        result = self._client(400).applications("usb", limit=256)
        assert result["count"] == 256
        assert result["total"] == 400
        assert result["has_more"] is True
        assert len(result["applications"]) == 256

    def test_a_short_list_is_complete(self) -> None:
        result = self._client(3).applications("usb", limit=256)
        assert result["count"] == 3
        assert result["total"] == 3
        assert result["has_more"] is False


class TestFridaDeviceOpsCannotHoldAWorker:
    """frida device calls wait forever when the device never answers.

    Measured: enumerate_devices, add_remote_device, enumerate_applications
    and spawn were still running after 400ms.
    """

    def test_wedged_device_calls_come_back_as_timeout(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import threading
        import time

        from headless_re_mcp.backends.frida import client as frida_client
        from headless_re_mcp.backends.frida.client import FridaClient, FridaError

        monkeypatch.setattr(frida_client, "_DEVICE_TIMEOUT", 0.05)

        class HungFrida:
            def enumerate_devices(self) -> list[object]:
                threading.Event().wait()
                return []

            def get_device_manager(self) -> HungFrida:
                return self

            def add_remote_device(self, endpoint: str) -> object:
                del endpoint
                threading.Event().wait()
                return object()

        client = FridaClient()
        client._available = True
        client._frida = HungFrida()
        started = time.monotonic()
        with pytest.raises(FridaError) as caught:
            client.enumerate_devices()
        assert caught.value.code == "timeout"
        assert caught.value.details["op"] == "enumerate_devices"
        assert time.monotonic() - started < 1.0

        started = time.monotonic()
        with pytest.raises(FridaError) as caught:
            client.add_remote_device("127.0.0.1:27042")
        assert caught.value.code == "timeout"
        assert caught.value.details["op"] == "add_remote_device"
        assert time.monotonic() - started < 1.0

        class HungDevice:
            def enumerate_applications(self) -> list[object]:
                threading.Event().wait()
                return []

            def spawn(self, args: list[str]) -> int:
                del args
                threading.Event().wait()
                return 1

            def resume(self, pid: int) -> None:
                del pid

        client._resolve_device = lambda device_id: HungDevice()  # type: ignore[method-assign]
        started = time.monotonic()
        with pytest.raises(FridaError) as caught:
            client.applications("usb", limit=10)
        assert caught.value.code == "timeout"
        assert caught.value.details["op"] == "applications"
        assert time.monotonic() - started < 1.0

        started = time.monotonic()
        with pytest.raises(FridaError) as caught:
            client.spawn("usb", "com.example.app")
        assert caught.value.code == "timeout"
        assert caught.value.details["op"] == "spawn"
        assert time.monotonic() - started < 1.0

    def test_a_device_list_that_finishes_is_untouched(self) -> None:
        from headless_re_mcp.backends.frida.client import FridaClient

        class Dev:
            id = "local"
            name = "Local System"
            type = "local"

        class Frida:
            def enumerate_devices(self) -> list[Dev]:
                return [Dev()]

        client = FridaClient()
        client._available = True
        client._frida = Frida()
        result = client.enumerate_devices()
        assert result["count"] == 1
        assert result["devices"][0]["id"] == "local"

    def test_a_wedged_attach_comes_back_as_timeout(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import threading
        import time

        from headless_re_mcp.backends.frida import client as frida_client
        from headless_re_mcp.backends.frida.client import FridaClient, FridaError

        monkeypatch.setattr(frida_client, "_DEVICE_TIMEOUT", 0.05)

        class HungFrida:
            def attach(self, pid: int) -> object:
                del pid
                threading.Event().wait()
                return object()

        client = FridaClient()
        client._available = True
        client._frida = HungFrida()
        started = time.monotonic()
        with pytest.raises(FridaError) as caught:
            client.modules(1, allowed_pid=1, limit=1)
        assert caught.value.code == "timeout"
        assert caught.value.details["op"] == "attach"
        assert time.monotonic() - started < 1.0

    def test_a_wedged_local_device_comes_back_as_timeout(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import threading
        import time

        from headless_re_mcp.backends.frida import client as frida_client
        from headless_re_mcp.backends.frida.client import FridaClient, FridaError

        monkeypatch.setattr(frida_client, "_DEVICE_TIMEOUT", 0.05)

        class HungFrida:
            def get_local_device(self) -> object:
                threading.Event().wait()
                return object()

        client = FridaClient()
        client._available = True
        client._frida = HungFrida()
        started = time.monotonic()
        with pytest.raises(FridaError) as caught:
            client.applications("local", limit=1)
        assert caught.value.code == "timeout"
        assert caught.value.details["op"] == "get_local_device"
        assert time.monotonic() - started < 1.0


class TestApkManifestSaysWhenItStopped:
    """The tool text says this is the decoded manifest.

    Measured: a 250020-character manifest came back as 200000 characters, no
    truncated field, and the XML no longer closed. An agent then treats a
    permission or component that lived past the cut as absent.
    """

    def _client(self, monkeypatch: pytest.MonkeyPatch, xml: str) -> Any:
        from headless_re_mcp.backends.apk.client import ApkClient

        class FakeApk:
            def get_package(self) -> str:
                return "com.example.app"

            def get_android_manifest_axml(self) -> Any:
                class Body:
                    def get_xml(self) -> bytes:
                        return xml.encode("utf-8")

                return Body()

        client = ApkClient()
        monkeypatch.setattr(ApkClient, "_apk", lambda self, path: FakeApk())
        return client

    def test_a_cut_manifest_is_labelled(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from headless_re_mcp.backends.apk.client import _MAX_MANIFEST_CHARS

        xml = "<manifest>" + ("x" * 250_000) + "</manifest>"
        result = self._client(monkeypatch, xml).manifest(tmp_path / "app.apk")

        assert result["truncated"] is True
        assert result["bytes"] == len(xml)
        assert len(result["manifest_xml"]) == _MAX_MANIFEST_CHARS
        assert result["package"] == "com.example.app"

    def test_a_short_manifest_is_complete(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        xml = "<manifest package='com.example.app'/>"
        result = self._client(monkeypatch, xml).manifest(tmp_path / "app.apk")

        assert result["truncated"] is False
        assert result["bytes"] == len(xml)
        assert result["manifest_xml"] == xml


class TestApkCertificatesSayWhenTheySkipped:
    """An unreadable cert used to vanish, leaving a shorter signer list.

    Measured: one certificate that raised next to one that parsed came back
    as a single certificate and v1_signed=True, so an agent treats the APK
    as having exactly one signer.
    """

    def _client(self, monkeypatch: pytest.MonkeyPatch, certs: list[Any]) -> Any:
        from headless_re_mcp.backends.apk.client import ApkClient

        class FakeApk:
            def get_signature_names(self) -> list[str]:
                return ["CERT.RSA"]

            def get_certificates(self) -> list[Any]:
                return certs

        client = ApkClient()
        monkeypatch.setattr(ApkClient, "_apk", lambda self, path: FakeApk())
        return client

    def test_a_skipped_cert_is_counted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class Bad:
            @property
            def subject(self) -> str:
                raise RuntimeError("unreadable")

        good = type(
            "Good",
            (),
            {
                "subject": "CN=ok",
                "issuer": "CN=ca",
                "serial_number": 1,
                "sha256_fingerprint": "aa",
            },
        )()
        result = self._client(monkeypatch, [Bad(), good]).certificates(tmp_path / "app.apk")
        assert result["skipped"] == 1
        assert result["truncated"] is True
        assert len(result["certificates"]) == 1
        assert result["certificates"][0]["subject"] == "CN=ok"

    def test_a_complete_list_is_not_labelled_partial(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        good = type(
            "Good",
            (),
            {
                "subject": "CN=ok",
                "issuer": "CN=ca",
                "serial_number": 1,
                "sha256_fingerprint": "aa",
            },
        )()
        result = self._client(monkeypatch, [good]).certificates(tmp_path / "app.apk")
        assert result["skipped"] == 0
        assert result["truncated"] is False
        assert len(result["certificates"]) == 1

    def test_failed_signature_names_are_not_unsigned(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from headless_re_mcp.backends.apk.client import ApkClient

        class FakeApk:
            def get_signature_names(self) -> list[str]:
                raise RuntimeError("androguard exploded")

            def get_certificates(self) -> list[Any]:
                return [
                    type(
                        "Good",
                        (),
                        {
                            "subject": "CN=ok",
                            "issuer": "CN=ca",
                            "serial_number": 1,
                            "sha256_fingerprint": "aa",
                        },
                    )()
                ]

        client = ApkClient()
        monkeypatch.setattr(ApkClient, "_apk", lambda self, path: FakeApk())
        result = client.certificates(tmp_path / "app.apk")
        assert result["v1_signed"] is True
        assert result["skipped"] == 1
        assert result["truncated"] is True
        assert result["signature_files"] == []
        assert len(result["certificates"]) == 1

    def test_failed_signature_names_with_no_certs_are_an_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from headless_re_mcp.backends.apk.client import ApkClient, ApkError

        class FakeApk:
            def get_signature_names(self) -> list[str]:
                raise RuntimeError("androguard exploded")

            def get_certificates(self) -> list[Any]:
                return []

        client = ApkClient()
        monkeypatch.setattr(ApkClient, "_apk", lambda self, path: FakeApk())
        with pytest.raises(ApkError) as caught:
            client.certificates(tmp_path / "app.apk")
        assert caught.value.code == "backend_error"


class TestApkPermissionsArePaged:
    """A permission list has no page size; a fat SDK dump is thousands of names.

    Measured: 3000 declared and 2500 requested came back in full with only
    count=3000. An overnight agent then ships every permission into context.
    """

    def _client(self, monkeypatch: pytest.MonkeyPatch, declared: int, requested: int) -> Any:
        from headless_re_mcp.backends.apk.client import ApkClient

        class FakeApk:
            def get_permissions(self) -> list[str]:
                return [f"android.permission.P{index}" for index in range(declared)]

            def get_requested_permissions(self) -> list[str]:
                return [f"android.permission.R{index}" for index in range(requested)]

        client = ApkClient()
        monkeypatch.setattr(ApkClient, "_apk", lambda self, path: FakeApk())
        return client

    def test_a_long_list_says_what_was_left_out(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = self._client(monkeypatch, 3000, 2500).permissions(
            tmp_path / "app.apk", limit=500
        )
        assert result["count"] == 500
        assert result["total"] == 3000
        assert result["requested_total"] == 2500
        assert result["has_more"] is True
        assert len(result["permissions"]) == 500
        assert len(result["requested_permissions"]) == 500

    def test_a_short_list_is_complete(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = self._client(monkeypatch, 2, 2).permissions(tmp_path / "app.apk", limit=500)
        assert result["count"] == 2
        assert result["total"] == 2
        assert result["requested_total"] == 2
        assert result["has_more"] is False


class TestApkComponentsArePaged:
    """Component lists have no page size; a plugin host is thousands of names.

    Measured: 2000 activities, 800 services, 400 receivers and 100 providers
    came back in full with no total or has_more.
    """

    def _client(
        self,
        monkeypatch: pytest.MonkeyPatch,
        *,
        activities: int,
        services: int,
        receivers: int,
        providers: int,
    ) -> Any:
        from headless_re_mcp.backends.apk.client import ApkClient

        class FakeApk:
            def get_activities(self) -> list[str]:
                return [f"com.app.A{index}" for index in range(activities)]

            def get_services(self) -> list[str]:
                return [f"com.app.S{index}" for index in range(services)]

            def get_receivers(self) -> list[str]:
                return [f"com.app.R{index}" for index in range(receivers)]

            def get_providers(self) -> list[str]:
                return [f"com.app.P{index}" for index in range(providers)]

            def get_main_activity(self) -> str:
                return "com.app.A0"

        client = ApkClient()
        monkeypatch.setattr(ApkClient, "_apk", lambda self, path: FakeApk())
        return client

    def test_a_long_list_says_what_was_left_out(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = self._client(
            monkeypatch, activities=2000, services=800, receivers=400, providers=100
        ).components(tmp_path / "app.apk", limit=500)
        assert len(result["activities"]) == 500
        assert len(result["services"]) == 500
        assert result["totals"] == {
            "activities": 2000,
            "services": 800,
            "receivers": 400,
            "providers": 100,
        }
        assert result["has_more"] is True
        assert result["main_activity"] == "com.app.A0"

    def test_a_short_list_is_complete(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = self._client(
            monkeypatch, activities=2, services=1, receivers=1, providers=1
        ).components(tmp_path / "app.apk", limit=500)
        assert result["has_more"] is False
        assert result["totals"]["activities"] == 2
        assert len(result["activities"]) == 2


class TestApkNativeLibsArePaged:
    """A fat APK can ship thousands of .so paths in one reply.

    Measured: 2500 lib/ entries came back as count=2500 with no has_more.
    """

    def _client(self, monkeypatch: pytest.MonkeyPatch, count: int) -> Any:
        from headless_re_mcp.backends.apk.client import ApkClient

        class FakeApk:
            def get_files(self) -> list[str]:
                return [f"lib/arm64-v8a/lib{index}.so" for index in range(count)]

        client = ApkClient()
        monkeypatch.setattr(ApkClient, "_apk", lambda self, path: FakeApk())
        return client

    def test_a_long_list_says_what_was_left_out(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = self._client(monkeypatch, 2500).native_libs(tmp_path / "app.apk", limit=500)
        assert result["count"] == 500
        assert result["total"] == 2500
        assert result["has_more"] is True
        assert len(result["native_libs"]) == 500
        assert result["abis"] == ["arm64-v8a"]

    def test_a_short_list_is_complete(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = self._client(monkeypatch, 2).native_libs(tmp_path / "app.apk", limit=500)
        assert result["count"] == 2
        assert result["total"] == 2
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


class TestExportListingsSayWhenTheyStopped:
    """The file list is a window; the count is the tree.

    Measured: 2500 jadx sources and 2500 unpacked JS modules both came back
    as 2000 names and no truncated field. An agent that only reads the list
    treats the rest of the tree as missing.
    """

    def test_jadx_marks_a_cut_listing(self, tmp_path: Path) -> None:
        from headless_re_mcp.backends.jadx.client import _MAX_LISTED_FILES, JadxClient

        out = tmp_path / "out"
        for index in range(_MAX_LISTED_FILES + 500):
            path = out / "sources" / f"C{index}.java"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("class X {}", encoding="utf-8")
        stub = tmp_path / "jadx"
        stub.write_text("x", encoding="utf-8")
        apk = tmp_path / "a.apk"
        apk.write_bytes(b"PK")
        client = JadxClient(stub)
        client._run = lambda *args, **kwargs: ("", "", 0)  # type: ignore[method-assign]
        result = client.export_sources(apk, out)
        assert result["java_file_count"] == _MAX_LISTED_FILES + 500
        assert len(result["java_files"]) == _MAX_LISTED_FILES
        assert result["truncated"] is True

    def test_jadx_marks_a_short_listing_complete(self, tmp_path: Path) -> None:
        from headless_re_mcp.backends.jadx.client import JadxClient

        out = tmp_path / "out"
        path = out / "sources" / "A.java"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("class A {}", encoding="utf-8")
        stub = tmp_path / "jadx"
        stub.write_text("x", encoding="utf-8")
        apk = tmp_path / "a.apk"
        apk.write_bytes(b"PK")
        client = JadxClient(stub)
        client._run = lambda *args, **kwargs: ("", "", 0)  # type: ignore[method-assign]
        result = client.export_sources(apk, out)
        assert result["java_file_count"] == 1
        assert result["truncated"] is False

    def test_webcrack_marks_a_cut_listing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from headless_re_mcp.backends.jsre import client as jsre
        from headless_re_mcp.backends.jsre.client import _MAX_LISTED_FILES, JsClient

        out = tmp_path / "jsout"
        out.mkdir()
        for index in range(_MAX_LISTED_FILES + 500):
            (out / f"m{index}.js").write_text("x", encoding="utf-8")
        stub = tmp_path / "webcrack"
        stub.write_text("x", encoding="utf-8")
        src = tmp_path / "bundle.js"
        src.write_text("x", encoding="utf-8")
        monkeypatch.setattr(jsre, "_run", lambda *args, **kwargs: ("", "", 0))
        result = JsClient(stub).unpack_bundle(src, out)
        assert result["file_count"] == _MAX_LISTED_FILES + 500
        assert len(result["files"]) == _MAX_LISTED_FILES
        assert result["truncated"] is True
