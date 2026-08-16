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


def test_frida_modules_says_when_the_page_is_not_the_whole_set() -> None:
    """100 modules, limit=64 returned count=64 and total=100 but no has_more.

    A caller that reads count the way other list tools taught it to misses
    the rest.
    """
    from headless_re_mcp.backends.frida.client import FridaClient

    class _Exports:
        def modules(self) -> list[dict[str, object]]:
            return [
                {"name": f"m{i}", "base": hex(i), "size": 1, "path": f"/m{i}"}
                for i in range(100)
            ]

    class _Script:
        def load(self) -> None:
            return None

        @property
        def exports_sync(self) -> _Exports:
            return _Exports()

    class _Session:
        def create_script(self, _source: str) -> _Script:
            return _Script()

        def detach(self) -> None:
            return None

    class _Frida:
        def attach(self, _pid: int) -> _Session:
            return _Session()

    client = FridaClient()
    client._available = True
    client._frida = _Frida()
    got = client.modules(1, allowed_pid=1, limit=64)
    assert got["count"] == 64
    assert got["total"] == 100
    assert got["has_more"] is True


def test_frida_applications_says_when_the_page_is_not_the_whole_set() -> None:
    """400 apps, limit=256 returned count=256 and total=400 but no has_more."""
    from headless_re_mcp.backends.frida.client import FridaClient

    class _App:
        def __init__(self, index: int) -> None:
            self.identifier = f"com.app{index}"
            self.name = f"App{index}"
            self.pid = 0

    class _Device:
        def enumerate_applications(self) -> list[_App]:
            return [_App(i) for i in range(400)]

    class _Frida:
        def get_local_device(self) -> _Device:
            return _Device()

    client = FridaClient()
    client._available = True
    client._frida = _Frida()
    got = client.applications("local", limit=256)
    assert got["count"] == 256
    assert got["total"] == 400
    assert got["has_more"] is True


def test_apk_strings_does_not_merge_long_values_or_hide_the_cut() -> None:
    """Two 5000-character strings that share a 2000-character prefix became one.

    Measured: the set was taken after the slice, so distinct constants
    collapsed and the reply had no truncated flag. An agent searching for the
    suffix concluded the string was never in the APK.
    """
    from headless_re_mcp.backends.apk.client import _MAX_STRING_LEN, ApkClient

    class _Str:
        def __init__(self, value: str) -> None:
            self._value = value

        def get_value(self) -> str:
            return self._value

    class _Analysis:
        def get_strings(self) -> list[_Str]:
            prefix = "A" * _MAX_STRING_LEN
            return [_Str(prefix + "one"), _Str(prefix + "two")]

    class _Parsed:
        analysis = _Analysis()

    client = ApkClient()
    client._available = True
    client._parsed = lambda _path: _Parsed()  # type: ignore[method-assign]
    got = client.strings(Path("dummy.apk"), limit=200)
    assert got["total"] == 2
    assert got["values_truncated"] is True
    assert got["truncated_value_count"] == 2
    assert all(len(item) == _MAX_STRING_LEN for item in got["strings"])


def test_apk_strings_says_when_the_page_is_not_the_whole_set() -> None:
    """500 strings, limit=200 returned count=200 and total=500 but no has_more."""
    from headless_re_mcp.backends.apk.client import ApkClient

    class _Str:
        def __init__(self, value: str) -> None:
            self._value = value

        def get_value(self) -> str:
            return self._value

    class _Analysis:
        def get_strings(self) -> list[_Str]:
            return [_Str(f"s{i}") for i in range(500)]

    class _Parsed:
        analysis = _Analysis()

    client = ApkClient()
    client._available = True
    client._parsed = lambda _path: _Parsed()  # type: ignore[method-assign]
    got = client.strings(Path("dummy.apk"), limit=200)
    assert got["count"] == 200
    assert got["total"] == 500
    assert got["has_more"] is True


def test_apk_methods_says_when_the_page_is_not_the_whole_set() -> None:
    """180 methods, limit=100 returned count=100 and total=180 but no has_more."""
    from headless_re_mcp.backends.apk.client import ApkClient

    class _Meth:
        def __init__(self, index: int) -> None:
            self.name = f"m{index}"
            self.descriptor = "()V"
            self.access = "public"

    class _Klass:
        name = "Lcom/foo/Bar;"

        def get_methods(self) -> list[_Meth]:
            return [_Meth(i) for i in range(180)]

    class _Analysis:
        def get_classes(self) -> list[_Klass]:
            return [_Klass()]

    class _Parsed:
        analysis = _Analysis()

    client = ApkClient()
    client._available = True
    client._parsed = lambda _path: _Parsed()  # type: ignore[method-assign]
    got = client.methods(Path("dummy.apk"), "com.foo.Bar", limit=100)
    assert got["count"] == 100
    assert got["total"] == 180
    assert got["has_more"] is True


def test_apk_classes_says_when_the_page_is_not_the_whole_set() -> None:
    """250 classes, limit=100 returned count=100 and total=250 but no has_more."""
    from headless_re_mcp.backends.apk.client import ApkClient

    class _Klass:
        def __init__(self, name: str) -> None:
            self.name = name

        def is_external(self) -> bool:
            return False

    class _Analysis:
        def get_classes(self) -> list[_Klass]:
            return [_Klass(f"Lfoo/Bar{i};") for i in range(250)]

    class _Parsed:
        analysis = _Analysis()

    client = ApkClient()
    client._available = True
    client._parsed = lambda _path: _Parsed()  # type: ignore[method-assign]
    got = client.classes(Path("dummy.apk"), limit=100)
    assert got["count"] == 100
    assert got["total"] == 250
    assert got["has_more"] is True


def test_apk_manifest_says_when_the_xml_was_cut() -> None:
    """A 250_000-character manifest came back as 200_000 with no truncated flag.

    An agent grepping that text for a component past the cap concludes it was
    never declared.
    """
    from headless_re_mcp.backends.apk.client import ApkClient

    class _FakeAxml:
        def get_xml(self) -> bytes:
            return b"M" * 250_000

    class _FakeApk:
        def get_package(self) -> str:
            return "com.example.app"

        def get_android_manifest_axml(self) -> _FakeAxml:
            return _FakeAxml()

    client = ApkClient()
    client._available = True
    client._apk = lambda _path: _FakeApk()  # type: ignore[method-assign]
    got = client.manifest(Path("dummy.apk"))
    assert len(got["manifest_xml"]) == 200_000
    assert got["truncated"] is True
    assert got["manifest_chars"] == 250_000


def test_device_logcat_says_when_the_page_filled_the_cap() -> None:
    """A 200-line snapshot looked like the whole buffer.

    Measured: requested=200, 200 lines, keys were only lines/requested.
    """
    from headless_re_mcp.backends.adb.client import AdbBackend

    class _FakeDev:
        def shell(self, cmd: object, timeout: float | None = None) -> str:
            n = int(cmd[3]) if isinstance(cmd, list) else 200
            return "\n".join(f"line {i}" for i in range(n))

    backend = AdbBackend()
    backend._device = lambda serial: _FakeDev()  # type: ignore[method-assign]
    got = backend.logcat("emulator-5554", lines=200)
    assert got["count"] == 200
    assert got["has_more"] is True


def test_ensure_frida_server_does_not_call_a_missing_process_running() -> None:
    """A successful empty shell was reported as running.

    Measured: ps listed only init, the launch command returned '', and the
    reply was running=True. An unattended hook path then attached to nothing.
    """
    from headless_re_mcp.backends.adb.client import AdbBackend

    class _FakeDev:
        def shell(self, cmd: object, timeout: float | None = None) -> str:
            if isinstance(cmd, str) and "ps" in cmd:
                return "USER PID NAME\nroot 1 init\n"
            return ""

    backend = AdbBackend()
    backend._device = lambda serial: _FakeDev()  # type: ignore[method-assign]
    got = backend.ensure_frida_server("emulator-5554")
    assert got["running"] is False
    assert "process list" in str(got.get("note", ""))


def test_device_packages_does_not_return_every_package_as_if_it_were_small() -> None:
    """pm list was unbounded. Measured: 5000 packages serialised to 113_946 bytes
    and the reply had no total/has_more, so a page looked like the whole device.
    """
    from headless_re_mcp.backends.adb.client import AdbBackend

    class _FakeDev:
        def shell(self, _cmd: str) -> str:
            return "\n".join(f"package:com.example.app{i}" for i in range(5000))

    backend = AdbBackend()
    backend._device = lambda serial: _FakeDev()  # type: ignore[method-assign]
    got = backend.packages("emulator-5554")
    assert got["count"] == 2000
    assert got["total"] == 5000
    assert got["has_more"] is True
    assert len(got["packages"]) == 2000


def test_device_properties_says_when_the_page_is_not_the_whole_set() -> None:
    """The cap was applied; the reply looked like the whole getprop.

    Measured: 600 properties with limit=500 returned count=500 and only the
    keys properties/count. A model that stopped there missed the rest.
    """
    from headless_re_mcp.backends.adb.client import AdbBackend

    class _FakeDev:
        def shell(self, _cmd: str) -> str:
            return "\n".join(f"[k{i}]: [v{i}]" for i in range(600))

    backend = AdbBackend()
    backend._device = lambda serial: _FakeDev()  # type: ignore[method-assign]
    got = backend.properties("emulator-5554", limit=500)
    assert got["count"] == 500
    assert got["total"] == 600
    assert got["has_more"] is True
    assert len(got["properties"]) == 500


def test_device_file_tools_do_not_call_the_path_an_artifact(tmp_path: Path) -> None:
    """The docs said artifact; artifacts.list did not have the file.

    Measured: device.screenshot wrote a PNG under artifact_root/device and
    returned ok, then artifacts.list reported total=0. A model that went to
    artifacts.read next was looking in the wrong table.
    """
    from unittest.mock import MagicMock

    from headless_re_mcp.config import Settings
    from headless_re_mcp.core.service import AnalysisService
    from headless_re_mcp.tools.device import build_device_tools

    class _FakeAdb:
        def screenshot(self, serial: str, out_path: Path) -> dict[str, str]:
            Path(out_path).write_bytes(b"PNG")
            return {"path": str(out_path), "serial": serial}

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
        service._backend = lambda: _FakeAdb()  # type: ignore[method-assign]
        result = service.device_screenshot("emulator-5554")
        assert result.ok and result.data is not None
        assert Path(str(result.data["path"])).is_file()
        listed = service.artifacts_list()
        assert listed.ok and listed.data is not None
        assert listed.data["total"] == 0
    finally:
        service.close_all()

    tools = {item.name: item for item in build_device_tools(MagicMock())}
    shot = (tools["device.screenshot"].handler.__doc__ or "").casefold()
    pull = (tools["device.pull"].handler.__doc__ or "").casefold()
    assert "not registered" in shot and "artifacts.list" in shot
    assert "not registered" in pull and "artifacts.list" in pull
    assert "png artifact" not in shot
    assert "local artifact" not in pull
