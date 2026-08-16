"""Android backend boundaries: argument validation, no shell passthrough, auth.

These cover the properties that make the Android surface safe to expose, not the
happy paths (which need a real device and live in the integration gates).
"""

from __future__ import annotations

import threading
import time
import zipfile
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError, _check_package, _check_serial
from headless_re_mcp.backends.apk.client import ApkClient
from headless_re_mcp.backends.apktool import ApktoolClient, ApktoolError
from headless_re_mcp.backends.frida.client import FridaClient, FridaError
from headless_re_mcp.backends.jadx.client import JadxClient
from headless_re_mcp.core.models import TargetKind
from headless_re_mcp.core.session import classify_target, describe_apk
from headless_re_mcp.tools.catalog import COMMAND_CATALOG, CommandTransport
from headless_re_mcp.tools.device import build_device_tools


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


class TestFridaApplicationsSayWhenTheyStopped:
    """An application page that hit the cap looks exactly like one that ended.

    Measured: 500 apps with limit=20 came back as count=20 and total=500,
    with no has_more.
    """

    def _client(self, n: int) -> FridaClient:
        class _App:
            def __init__(self, index: int) -> None:
                self.identifier = f"com.app{index}"
                self.name = f"App{index}"
                self.pid = 0

        class _Dev:
            def enumerate_applications(self) -> list[_App]:
                return [_App(index) for index in range(n)]

        client = FridaClient()
        client._available = True
        client._frida = object()
        client._resolve_device = lambda device_id: _Dev()  # type: ignore[method-assign]
        return client

    def test_hitting_the_cap_is_reported(self) -> None:
        page = self._client(500).applications("usb", limit=20)
        assert page["count"] == 20
        assert page["total"] == 500
        assert page["has_more"] is True

    def test_a_complete_answer_is_not_labelled_partial(self) -> None:
        page = self._client(3).applications("usb", limit=20)
        assert page["has_more"] is False


class TestFridaModulesSayWhenTheyStopped:
    """A module page that hit the cap looks exactly like one that ended.

    Measured: 200 modules with limit=20 came back as count=20 and total=200,
    with no has_more.
    """

    def _client(self, n: int) -> FridaClient:
        class _Exports:
            def modules(self) -> list[dict[str, object]]:
                return [
                    {"name": f"m{index}", "base": hex(index), "size": 1, "path": f"/lib/{index}"}
                    for index in range(n)
                ]

        class _Script:
            exports_sync = _Exports()

            def load(self) -> None:
                return None

        class _Session:
            def create_script(self, source: str) -> _Script:
                del source
                return _Script()

            def detach(self) -> None:
                return None

        class _Frida:
            def attach(self, pid: int) -> _Session:
                del pid
                return _Session()

        client = FridaClient()
        client._available = True
        client._frida = _Frida()
        return client

    def test_hitting_the_cap_is_reported(self) -> None:
        page = self._client(200).modules(4242, allowed_pid=4242, limit=20)
        assert page["count"] == 20
        assert page["total"] == 200
        assert page["has_more"] is True

    def test_a_complete_answer_is_not_labelled_partial(self) -> None:
        page = self._client(3).modules(4242, allowed_pid=4242, limit=20)
        assert page["has_more"] is False


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


class TestApkManifestSaysWhenItWasCut:
    """A capped manifest used to look exactly like a complete one.

    Measured: a 250,021-character manifest came back as 200,000 characters
    with no `truncated` field, so a caller would treat a mid-file slice as
    the whole AndroidManifest.xml.
    """

    def _client(self, xml: str) -> ApkClient:
        class _Axml:
            def get_xml(self) -> bytes:
                return xml.encode("utf-8")

        class _Apk:
            def get_package(self) -> str:
                return "com.example.app"

            def get_android_manifest_axml(self) -> _Axml:
                return _Axml()

        client = ApkClient()
        client._available = True
        client._apk = lambda path: _Apk()  # type: ignore[method-assign]
        return client

    def test_a_cut_manifest_is_labelled(self, tmp_path: Path) -> None:
        xml = "<manifest>" + ("x" * 250_000) + "</manifest>"
        result = self._client(xml).manifest(tmp_path / "app.apk")
        assert result["truncated"] is True
        assert result["bytes"] == len(xml)
        assert len(result["manifest_xml"]) == 200_000

    def test_a_short_manifest_is_not_labelled_partial(self, tmp_path: Path) -> None:
        xml = "<manifest package='com.example.app'/>"
        result = self._client(xml).manifest(tmp_path / "app.apk")
        assert result["truncated"] is False
        assert result["manifest_xml"] == xml


class TestApkComponentsAreCapped:
    """The component lists had no page and no signal that they had stopped.

    Measured: 2000 activities came back in one 42 KiB reply, with no has_more.
    """

    def _client(self, n: int) -> ApkClient:
        class _Apk:
            def get_activities(self) -> list[str]:
                return [f"com.example.A{i}" for i in range(n)]

            def get_services(self) -> list[str]:
                return ["com.example.S0"]

            def get_receivers(self) -> list[str]:
                return []

            def get_providers(self) -> list[str]:
                return []

            def get_main_activity(self) -> str:
                return "com.example.A0"

        client = ApkClient()
        client._available = True
        client._apk = lambda path: _Apk()  # type: ignore[method-assign]
        return client

    def test_hitting_the_cap_is_reported(self, tmp_path: Path) -> None:
        page = self._client(2000).components(tmp_path / "app.apk", limit=10)
        assert len(page["activities"]) == 10
        assert page["totals"]["activities"] == 2000
        assert page["has_more"] is True

    def test_a_complete_answer_is_not_labelled_partial(self, tmp_path: Path) -> None:
        page = self._client(3).components(tmp_path / "app.apk", limit=10)
        assert page["has_more"] is False
        assert page["totals"]["activities"] == 3


class TestApkNativeLibsAreCapped:
    """The native-lib list had no page and no signal that it had stopped.

    Measured: 3100 lib/ paths came back in one 85 KiB reply, with no has_more.
    """

    def _client(self, n: int) -> ApkClient:
        class _Apk:
            def get_files(self) -> list[str]:
                return [f"lib/arm64-v8a/lib{i}.so" for i in range(n)] + [
                    "res/layout/main.xml"
                ]

        client = ApkClient()
        client._available = True
        client._apk = lambda path: _Apk()  # type: ignore[method-assign]
        return client

    def test_hitting_the_cap_is_reported(self, tmp_path: Path) -> None:
        page = self._client(3100).native_libs(tmp_path / "app.apk", limit=10)
        assert page["count"] == 10
        assert page["total"] == 3100
        assert page["has_more"] is True
        assert len(page["native_libs"]) == 10

    def test_a_complete_answer_is_not_labelled_partial(self, tmp_path: Path) -> None:
        page = self._client(3).native_libs(tmp_path / "app.apk", limit=10)
        assert page["count"] == 3
        assert page["has_more"] is False
        assert page["abis"] == ["arm64-v8a"]


class TestJadxExportSourcesSayWhenTheListStopped:
    """The java_files index was cut at 2000 with no signal that it had stopped.

    Measured: 2500 .java paths came back as 2000, with no has_more. The on-disk
    tree was complete; a caller reading only the list would miss later classes.
    """

    def _client(self, tmp_path: Path, n: int) -> tuple[JadxClient, Path, Path]:
        apk = tmp_path / "app.apk"
        apk.write_bytes(b"PK")
        out = tmp_path / "out"
        for index in range(n):
            path = out / "sources" / "com" / "ex" / f"C{index}.java"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("class C {}\n")
        stub = tmp_path / "jadx"
        stub.write_text("#!/bin/sh\n")
        client = JadxClient(executable=stub)
        client._run = lambda *args, **kwargs: ("", "", 0)  # type: ignore[method-assign]
        return client, apk, out

    def test_hitting_the_cap_is_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import headless_re_mcp.backends.jadx.client as jadx_mod

        monkeypatch.setattr(jadx_mod, "_MAX_JAVA_FILES", 10)
        client, apk, out = self._client(tmp_path, 25)
        page = client.export_sources(apk, out)
        assert page["java_file_count"] == 25
        assert len(page["java_files"]) == 10
        assert page["has_more"] is True

    def test_a_complete_tree_is_not_labelled_partial(self, tmp_path: Path) -> None:
        client, apk, out = self._client(tmp_path, 3)
        page = client.export_sources(apk, out)
        assert page["java_file_count"] == 3
        assert page["has_more"] is False


class TestApkStringsDoNotMergeAtTheCap:
    """Long strings were sliced before dedup, so distinct values disappeared.

    Measured: two 2500-character strings that differed only after the
    2000-character cap became one 2000-character value, with no truncated.
    """

    def _client(self, values: list[str]) -> ApkClient:
        class _Item:
            def __init__(self, value: str) -> None:
                self._value = value

            def get_value(self) -> str:
                return self._value

        class _Parsed:
            def __init__(self) -> None:
                self.analysis = type(
                    "Analysis",
                    (),
                    {"get_strings": lambda _self: [_Item(value) for value in values]},
                )()

        client = ApkClient()
        client._available = True
        client._parsed = lambda path: _Parsed()  # type: ignore[method-assign]
        return client

    def test_distinct_long_strings_stay_distinct(self, tmp_path: Path) -> None:
        page = self._client(["A" * 2500 + "LEFT", "A" * 2500 + "RIGHT", "short"]).strings(
            tmp_path / "app.apk"
        )
        assert page["total"] == 3
        assert page["truncated"] is True
        assert sum(1 for item in page["strings"] if len(item) == 2000) == 2

    def test_short_strings_are_not_labelled_partial(self, tmp_path: Path) -> None:
        page = self._client(["alpha", "beta"]).strings(tmp_path / "app.apk")
        assert page["total"] == 2
        assert page["truncated"] is False


class TestApkPermissionsAreCapped:
    """The permission lists had no page and no signal that they had stopped.

    Measured: 2000 declared plus 1500 requested came back in one 95 KiB
    reply, with no has_more.
    """

    def _client(self, declared: int, requested: int) -> ApkClient:
        class _Apk:
            def get_permissions(self) -> list[str]:
                return [f"android.permission.P{index}" for index in range(declared)]

            def get_requested_permissions(self) -> list[str]:
                return [f"android.permission.R{index}" for index in range(requested)]

        client = ApkClient()
        client._available = True
        client._apk = lambda path: _Apk()  # type: ignore[method-assign]
        return client

    def test_hitting_the_cap_is_reported(self, tmp_path: Path) -> None:
        page = self._client(2000, 1500).permissions(tmp_path / "app.apk", limit=10)
        assert page["count"] == 10
        assert page["totals"]["permissions"] == 2000
        assert page["totals"]["requested_permissions"] == 1500
        assert page["has_more"] is True
        assert len(page["permissions"]) == 10
        assert len(page["requested_permissions"]) == 10

    def test_a_complete_answer_is_not_labelled_partial(self, tmp_path: Path) -> None:
        page = self._client(3, 2).permissions(tmp_path / "app.apk", limit=10)
        assert page["has_more"] is False
        assert page["totals"]["permissions"] == 3


class TestApkClassesSayWhenTheyStopped:
    """A class page that hit the cap looks exactly like one that ended.

    Measured: 80 internal classes with limit=10 came back as count=10 and
    total=80, with no has_more.
    """

    def _client(self, n: int) -> ApkClient:
        class _Klass:
            def __init__(self, name: str) -> None:
                self.name = name

            def is_external(self) -> bool:
                return False

        class _Parsed:
            def __init__(self) -> None:
                self.analysis = type(
                    "Analysis",
                    (),
                    {
                        "get_classes": lambda _self: [
                            _Klass(f"Lcom/ex/C{index};") for index in range(n)
                        ]
                    },
                )()

        client = ApkClient()
        client._available = True
        client._parsed = lambda path: _Parsed()  # type: ignore[method-assign]
        return client

    def test_hitting_the_cap_is_reported(self, tmp_path: Path) -> None:
        page = self._client(80).classes(tmp_path / "app.apk", offset=0, limit=10)
        assert page["count"] == 10
        assert page["total"] == 80
        assert page["has_more"] is True

    def test_a_complete_answer_is_not_labelled_partial(self, tmp_path: Path) -> None:
        page = self._client(3).classes(tmp_path / "app.apk", offset=0, limit=10)
        assert page["has_more"] is False


class TestApkMethodsSayWhenTheyStopped:
    """A method page that hit the cap looks exactly like one that ended.

    Measured: 80 methods with limit=10 came back as count=10 and total=80,
    with no has_more.
    """

    def _client(self, n: int) -> ApkClient:
        class _Meth:
            def __init__(self, name: str) -> None:
                self.name = name
                self.descriptor = "()V"
                self.access = "public"

        class _Klass:
            name = "Lcom/ex/C;"

            def get_methods(self) -> list[_Meth]:
                return [_Meth(f"m{index}") for index in range(n)]

        class _Parsed:
            def __init__(self) -> None:
                self.analysis = type(
                    "Analysis", (), {"get_classes": lambda _self: [_Klass()]}
                )()

        client = ApkClient()
        client._available = True
        client._parsed = lambda path: _Parsed()  # type: ignore[method-assign]
        return client

    def test_hitting_the_cap_is_reported(self, tmp_path: Path) -> None:
        page = self._client(80).methods(
            tmp_path / "app.apk", "Lcom/ex/C;", offset=0, limit=10
        )
        assert page["count"] == 10
        assert page["total"] == 80
        assert page["has_more"] is True

    def test_a_complete_answer_is_not_labelled_partial(self, tmp_path: Path) -> None:
        page = self._client(3).methods(
            tmp_path / "app.apk", "Lcom/ex/C;", offset=0, limit=10
        )
        assert page["has_more"] is False


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


class _HungDevice:
    """A device whose shell never returns — the adb-server-wedged case."""

    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()

    def shell(self, *args: object, **kwargs: object) -> str:
        del args, kwargs
        self.entered.set()
        self.release.wait()
        return ""


class TestAdbCallsHaveADeadline:
    """A wedged adb server used to park the caller for as long as it stayed wedged.

    Measured here: ``properties()`` against a ``shell()`` that slept 8s returned
    only after 8.000s, and was still running at 2s. ``connect`` already had a
    timeout; the other named operations did not. An unattended agent that hits
    a device which stopped answering then holds a worker until the process dies.
    """

    def _backend(self, device: _HungDevice, *, timeout: float = 0.3) -> AdbBackend:
        backend = AdbBackend(timeout=timeout)
        backend._available = True
        backend._adbutils = object()
        backend._device = lambda serial: device  # type: ignore[method-assign]
        return backend

    def test_a_hung_shell_returns_timeout_instead_of_blocking(self) -> None:
        device = _HungDevice()
        backend = self._backend(device)
        started = time.monotonic()
        with pytest.raises(AdbError) as info:
            backend.properties("emulator-5554", limit=10)
        elapsed = time.monotonic() - started

        assert info.value.code == "timeout"
        assert elapsed < 1.0
        assert device.entered.is_set()
        device.release.set()

    def test_logcat_and_packages_share_the_same_deadline(self) -> None:
        for op in ("logcat", "packages"):
            device = _HungDevice()
            backend = self._backend(device)
            started = time.monotonic()
            with pytest.raises(AdbError) as info:
                getattr(backend, op)("emulator-5554")
            assert info.value.code == "timeout", op
            assert time.monotonic() - started < 1.0, op
            device.release.set()

    def test_the_tool_envelope_names_timeout_and_is_retryable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from types import SimpleNamespace

        from headless_re_mcp.core.service_device import DeviceAnalysisMixin

        device = _HungDevice()
        backend = self._backend(device)
        monkeypatch.setattr(DeviceAnalysisMixin, "_backend", lambda self: backend)

        class _Svc(DeviceAnalysisMixin):
            settings = SimpleNamespace(adb=None)

        started = time.monotonic()
        result = _Svc().device_properties("emulator-5554")
        elapsed = time.monotonic() - started
        device.release.set()

        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "timeout"
        assert result.error.retryable is True
        assert elapsed < 1.0

    def test_a_live_device_is_not_slowed_down_by_the_deadline(self) -> None:
        class _Live:
            def shell(self, *args: object, **kwargs: object) -> str:
                del args, kwargs
                return "[ro.build.version.sdk]: [34]\n"

        backend = AdbBackend(timeout=0.3)
        backend._available = True
        backend._adbutils = object()
        backend._device = lambda serial: _Live()  # type: ignore[method-assign]
        started = time.monotonic()
        payload = backend.properties("emulator-5554", limit=10)
        assert payload["count"] == 1
        assert time.monotonic() - started < 0.3


class TestEnsureFridaServerDoesNotInventAProcess:
    """A successful su command is not evidence that frida-server is running.

    Measured: a device whose ``ps`` never listed frida-server, and whose launch
    shell returned empty, still answered ``running: True``. An unattended agent
    then attaches and waits for a server that is not there.
    """

    def _backend(self, device: object) -> AdbBackend:
        backend = AdbBackend(timeout=2.0)
        backend._available = True
        backend._adbutils = object()
        backend._device = lambda serial: device  # type: ignore[method-assign]
        return backend

    def test_launch_without_a_process_is_a_failure(self) -> None:
        class _Dead:
            def shell(self, cmd: object, **kwargs: object) -> str:
                del kwargs
                if "ps" in str(cmd):
                    return "root         1     0  init"
                return ""

        with pytest.raises(AdbError) as info:
            self._backend(_Dead()).ensure_frida_server("emulator-5554")
        assert info.value.code == "backend_error"
        assert info.value.details.get("running") is False

    def test_already_running_is_still_success(self) -> None:
        class _Already:
            def shell(self, cmd: object, **kwargs: object) -> str:
                del kwargs
                if "ps" in str(cmd):
                    return "root        99     1  frida-server"
                raise AssertionError(f"should not launch: {cmd}")

        payload = self._backend(_Already()).ensure_frida_server("emulator-5554")
        assert payload["running"] is True
        assert payload["pushed"] is False

    def test_a_launch_that_actually_appears_in_ps_is_success(self) -> None:
        class _Starts:
            def __init__(self) -> None:
                self.launched = False

            def shell(self, cmd: object, **kwargs: object) -> str:
                del kwargs
                text = str(cmd)
                if "nohup" in text or "su -c" in text:
                    self.launched = True
                    return ""
                if "ps" in text:
                    return "root 99 frida-server" if self.launched else "root 1 init"
                return ""

        payload = self._backend(_Starts()).ensure_frida_server("emulator-5554")
        assert payload["running"] is True

    def test_a_launch_timeout_is_not_success_when_ps_is_empty(self) -> None:
        class _Blocked:
            def shell(self, cmd: object, **kwargs: object) -> str:
                del kwargs
                if "ps" in str(cmd):
                    return "root         1     0  init"
                raise TimeoutError("su blocked")

        with pytest.raises(AdbError) as info:
            self._backend(_Blocked()).ensure_frida_server("emulator-5554")
        assert info.value.code == "backend_error"
        assert info.value.details.get("running") is False

    def test_a_launch_timeout_is_success_only_if_ps_then_lists_it(self) -> None:
        class _SlowStart:
            def __init__(self) -> None:
                self.launched = False

            def shell(self, cmd: object, **kwargs: object) -> str:
                del kwargs
                text = str(cmd)
                if "ps" in text:
                    return "root 99 frida-server" if self.launched else "root 1 init"
                self.launched = True
                raise TimeoutError("su returned after the process started")

        payload = self._backend(_SlowStart()).ensure_frida_server("emulator-5554")
        assert payload["running"] is True


class TestDevicePropertiesSayWhenTheyStopped:
    """A page that hit the cap looks exactly like one that ended.

    Measured: 80 properties with limit=10 came back as count=10 and no
    has_more, so a caller reading the reply would conclude that was the
    whole getprop table.
    """

    def _backend(self, n: int) -> AdbBackend:
        class _Props:
            def shell(self, *args: object, **kwargs: object) -> str:
                del args, kwargs
                return "\n".join(f"[ro.p.{i}]: [{i}]" for i in range(n))

        backend = AdbBackend(timeout=2.0)
        backend._available = True
        backend._adbutils = object()
        backend._device = lambda serial: _Props()  # type: ignore[method-assign]
        return backend

    def test_hitting_the_cap_is_reported(self) -> None:
        page = self._backend(80).properties("emulator-5554", limit=10)
        assert page["count"] == 10
        assert page["has_more"] is True

    def test_a_complete_answer_is_not_labelled_partial(self) -> None:
        page = self._backend(3).properties("emulator-5554", limit=10)
        assert page["count"] == 3
        assert page["has_more"] is False

    def test_a_result_that_exactly_fills_the_page_is_complete(self) -> None:
        page = self._backend(10).properties("emulator-5554", limit=10)
        assert page["count"] == 10
        assert page["has_more"] is False


class TestDeviceConnectDoesNotInventSuccess:
    """Substring matching treated a refusal as a connection.

    Measured: ``not connected`` and ``already in use`` both became
    ``connected: True``, because the check was ``"connected" in text or
    "already" in text``.
    """

    def _backend(self, message: str) -> AdbBackend:
        backend = AdbBackend(timeout=2.0)
        backend._available = True
        backend._adbutils = object()

        class _Client:
            def connect(self, endpoint: str, timeout: float = 10.0) -> str:
                del endpoint, timeout
                return message

        backend._client = lambda: _Client()  # type: ignore[method-assign]
        return backend

    @pytest.mark.parametrize(
        "message",
        [
            "not connected",
            "cannot be connected",
            "already in use",
            "failed to connect to 127.0.0.1:5555",
            "unable to connect to 127.0.0.1:5555: Connection refused",
        ],
    )
    def test_a_refusal_is_not_connected(self, message: str) -> None:
        with pytest.raises(AdbError) as info:
            self._backend(message).connect("127.0.0.1", 5555)
        assert info.value.code == "backend_error", message
        assert info.value.details.get("connected") is False, message

    @pytest.mark.parametrize(
        "message",
        [
            "connected to 127.0.0.1:5555",
            "already connected to 127.0.0.1:5555",
        ],
    )
    def test_a_real_connection_is_still_connected(self, message: str) -> None:
        payload = self._backend(message).connect("127.0.0.1", 5555)
        assert payload["connected"] is True, message


class TestDeviceLaunchDoesNotInventSuccess:
    """monkey aborting is not a launched app.

    Measured: a device whose monkey output was
    ``No activities found to run, monkey aborted.`` still answered
    ``launched: True``. An unattended agent then talks to an activity that
    never started.
    """

    def _backend(self, output: str) -> AdbBackend:
        class _Dev:
            def shell(self, *args: object, **kwargs: object) -> str:
                del args, kwargs
                return output

        backend = AdbBackend(timeout=2.0)
        backend._available = True
        backend._adbutils = object()
        backend._device = lambda serial: _Dev()  # type: ignore[method-assign]
        return backend

    def test_monkey_abort_is_a_failure(self) -> None:
        with pytest.raises(AdbError) as info:
            self._backend("** No activities found to run, monkey aborted.\n").launch(
                "emulator-5554", "com.missing.app"
            )
        assert info.value.code == "backend_error"
        assert info.value.details.get("launched") is False

    def test_a_real_injection_is_still_success(self) -> None:
        payload = self._backend("Events injected: 1\n").launch(
            "emulator-5554", "com.example.app"
        )
        assert payload["launched"] is True


class TestDevicePackagesAreCapped:
    """The package list had no page and no signal that it had stopped.

    Measured: 2000 package names came back in one reply, with no has_more.
    """

    def _backend(self, n: int) -> AdbBackend:
        class _Pkgs:
            def shell(self, *args: object, **kwargs: object) -> str:
                del args, kwargs
                return "\n".join(f"package:com.app{i}" for i in range(n))

        backend = AdbBackend(timeout=2.0)
        backend._available = True
        backend._adbutils = object()
        backend._device = lambda serial: _Pkgs()  # type: ignore[method-assign]
        return backend

    def test_hitting_the_cap_is_reported(self) -> None:
        page = self._backend(2000).packages("emulator-5554", limit=10)
        assert page["count"] == 10
        assert page["has_more"] is True
        assert len(page["packages"]) == 10

    def test_a_complete_answer_is_not_labelled_partial(self) -> None:
        page = self._backend(3).packages("emulator-5554", limit=10)
        assert page["count"] == 3
        assert page["has_more"] is False


class TestDeviceInstallDoesNotInventSuccess:
    """A refused install was still reported as installed.

    Measured: a device whose install() returned False still answered
    {installed: True}. An unattended agent then launches a package that
    is not on the device. adbutils itself returns None on success, so
    only an explicit False is a refusal.
    """

    def _backend(self, result: object) -> AdbBackend:
        class _Dev:
            def install(self, *args: object, **kwargs: object) -> object:
                del args, kwargs
                return result

        backend = AdbBackend(timeout=2.0)
        backend._available = True
        backend._adbutils = object()
        backend._device = lambda serial: _Dev()  # type: ignore[method-assign]
        return backend

    def test_a_refused_install_is_a_failure(self, tmp_path: Path) -> None:
        apk = tmp_path / "app.apk"
        apk.write_bytes(b"PK")
        with pytest.raises(AdbError) as info:
            self._backend(False).install("emulator-5554", str(apk))
        assert info.value.code == "backend_error"
        assert info.value.details.get("installed") is False

    def test_a_none_return_is_still_success(self, tmp_path: Path) -> None:
        apk = tmp_path / "app.apk"
        apk.write_bytes(b"PK")
        page = self._backend(None).install("emulator-5554", str(apk))
        assert page["installed"] is True


class TestDeviceUninstallDoesNotInventSuccess:
    """A refused uninstall was still reported as uninstalled.

    Measured: a device whose uninstall() returned False still answered
    {uninstalled: True}. An unattended agent then treats the package as gone.
    """

    def _backend(self, result: object) -> AdbBackend:
        class _Dev:
            def uninstall(self, *args: object, **kwargs: object) -> object:
                del args, kwargs
                return result

        backend = AdbBackend(timeout=2.0)
        backend._available = True
        backend._adbutils = object()
        backend._device = lambda serial: _Dev()  # type: ignore[method-assign]
        return backend

    def test_a_refused_uninstall_is_a_failure(self) -> None:
        with pytest.raises(AdbError) as info:
            self._backend(False).uninstall("emulator-5554", "com.example.app")
        assert info.value.code == "backend_error"
        assert info.value.details.get("uninstalled") is False

    def test_a_true_return_is_still_success(self) -> None:
        page = self._backend(True).uninstall("emulator-5554", "com.example.app")
        assert page["uninstalled"] is True


class TestDeviceScreenshotDoesNotClaimAnArtifact:
    """The tool described a registered artifact and returned a bare path.

    Measured: the docstring said "PNG artifact"; the reply keys were path
    and serial, with no artifact_id. An unattended agent then called
    artifacts.read on a file the store cannot see.
    """

    def test_the_reply_is_a_path(self, tmp_path: Path) -> None:
        class _Image:
            def save(self, path: str) -> None:
                Path(path).write_bytes(b"PNG")

        class _Dev:
            def screenshot(self) -> _Image:
                return _Image()

        backend = AdbBackend(timeout=2.0)
        backend._available = True
        backend._adbutils = object()
        backend._device = lambda serial: _Dev()  # type: ignore[method-assign]
        page = backend.screenshot("emulator-5554", tmp_path / "shot.png")
        assert page["path"] == str(tmp_path / "shot.png")
        assert "artifact_id" not in page

    def test_the_tool_doc_says_it_is_not_registered(self) -> None:
        docs = {
            binding.name: binding.handler.__doc__ or ""
            for binding in build_device_tools(object())  # type: ignore[arg-type]
        }
        doc = docs["device.screenshot"]
        assert "not a registered artifact" in doc
        assert "PNG artifact" not in doc


class TestDevicePullDoesNotClaimAnArtifact:
    """The tool described a registered artifact and returned a bare path.

    Measured: the docstring said "local artifact"; the reply keys were
    local and remote, with no artifact_id.
    """

    def test_the_reply_is_a_path(self, tmp_path: Path) -> None:
        class _Sync:
            def pull(self, remote: str, local: str) -> None:
                del remote
                Path(local).write_bytes(b"data")

        class _Dev:
            sync = _Sync()

        backend = AdbBackend(timeout=2.0)
        backend._available = True
        backend._adbutils = object()
        backend._device = lambda serial: _Dev()  # type: ignore[method-assign]
        page = backend.pull("emulator-5554", "/sdcard/x.bin", tmp_path / "x.bin")
        assert page["local"] == str(tmp_path / "x.bin")
        assert "artifact_id" not in page

    def test_the_tool_doc_says_it_is_not_registered(self) -> None:
        docs = {
            binding.name: binding.handler.__doc__ or ""
            for binding in build_device_tools(object())  # type: ignore[arg-type]
        }
        doc = docs["device.pull"]
        assert "not a registered artifact" in doc
        assert "local artifact" not in doc


class TestDeviceLogcatSaysWhenItStopped:
    """An oversized logcat dump was sliced with no signal.

    Measured: 500 lines with lines=20 came back as 20 lines and requested=20,
    with no has_more, so a caller would treat a slice as the whole buffer.
    """

    def _backend(self, n: int) -> AdbBackend:
        class _Dev:
            def shell(self, *args: object, **kwargs: object) -> str:
                del args, kwargs
                return "\n".join(f"line {index}" for index in range(n))

        backend = AdbBackend(timeout=2.0)
        backend._available = True
        backend._adbutils = object()
        backend._device = lambda serial: _Dev()  # type: ignore[method-assign]
        return backend

    def test_hitting_the_cap_is_reported(self) -> None:
        page = self._backend(500).logcat("emulator-5554", lines=20)
        assert page["count"] == 20
        assert page["requested"] == 20
        assert page["has_more"] is True

    def test_a_complete_answer_is_not_labelled_partial(self) -> None:
        page = self._backend(3).logcat("emulator-5554", lines=20)
        assert page["count"] == 3
        assert page["has_more"] is False
