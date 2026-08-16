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

    def test_the_tool_description_names_persisted(self) -> None:
        import ast
        import inspect

        from headless_re_mcp.tools import frida as frida_mod

        tree = ast.parse(inspect.getsource(frida_mod.build_frida_tools))
        docs = {
            node.name: ast.get_docstring(node)
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef)
        }
        assert docs["frida_hook_template"]
        assert "persisted" in docs["frida_hook_template"]


class TestFridaAttachSaysItDetaches:
    """The reply already said probe attach; the description was empty.

    An agent that only reads the tool text treats attached=True as a live
    session and then issues follow-up calls against a process that is no
    longer attached.
    """

    def test_the_tool_description_says_the_probe_is_gone(self) -> None:
        import ast
        import inspect

        from headless_re_mcp.tools import frida as frida_mod

        tree = ast.parse(inspect.getsource(frida_mod.build_frida_tools))
        docs = {
            node.name: ast.get_docstring(node)
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef)
        }
        assert docs["frida_attach"]
        assert "detach" in docs["frida_attach"]


class TestFridaMemoryReadDoesNotPadAShortBuffer:
    """A short read used to come back with size equal to the request.

    Measured: Memory.read returned 4 bytes and the reply still said size=16.
    An unattended agent then treats a truncated buffer as the whole read.
    """

    def _read(self, returned: list[int], size: int) -> dict[str, Any]:
        class _Exports:
            def read(self, address: int, count: int) -> list[int]:
                assert count == size
                return returned

        class _Script:
            def __init__(self) -> None:
                self.exports_sync = _Exports()

            def load(self) -> None:
                return None

        class _Session:
            def create_script(self, source: str) -> _Script:
                assert source
                return _Script()

            def detach(self) -> None:
                return None

        class _Frida:
            def attach(self, pid: int) -> _Session:
                assert pid == 7
                return _Session()

        client = FridaClient()
        client._frida = _Frida()
        client._available = True
        return client.memory_read(7, 0x1000, size, allowed_pid=7)

    def test_a_short_read_is_not_the_requested_size(self) -> None:
        result = self._read([1, 2, 3, 4], 16)
        assert result["size"] == 4
        assert result["requested"] == 16
        assert result["data"] == "01020304"
        assert result["truncated"] is True
        assert "fewer bytes" in result["note"]

    def test_a_full_read_is_not_labelled_truncated(self) -> None:
        result = self._read([1, 2, 3, 4], 4)
        assert result["size"] == 4
        assert result["requested"] == 4
        assert result["data"] == "01020304"
        assert "truncated" not in result
        assert "note" not in result

    def test_the_tool_description_names_the_short_read_fields(self) -> None:
        import ast
        import inspect

        from headless_re_mcp.tools import frida as frida_mod

        tree = ast.parse(inspect.getsource(frida_mod.build_frida_tools))
        docs = {
            node.name: ast.get_docstring(node)
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef)
        }
        assert docs["frida_memory_read"]
        assert "requested" in docs["frida_memory_read"]
        assert "truncated" in docs["frida_memory_read"]


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
    """A 250 KiB manifest used to come back as 200_000 characters, unmarked.

    Measured: a 250_011-character document was returned as 200_000 characters
    with no truncated flag. The tool claims to return the decoded manifest, so
    an agent treating that XML as complete would miss whatever lived past the
    cut -- exported activities, intent filters -- and keep going.
    """

    def _client(self, monkeypatch: pytest.MonkeyPatch, xml: str) -> Any:
        from headless_re_mcp.backends.apk.client import ApkClient

        class _FakeApk:
            def get_package(self) -> str:
                return "com.example.app"

            def get_android_manifest_axml(self) -> Any:
                class _Axml:
                    def get_xml(self) -> bytes:
                        return xml.encode("utf-8")

                return _Axml()

        client = ApkClient()
        monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _FakeApk())
        return client

    def test_an_oversized_manifest_is_marked_truncated(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from headless_re_mcp.backends.apk.client import _MAX_MANIFEST_CHARS

        xml = "<manifest>" + ("x" * 250_000) + "</manifest>"
        result = self._client(monkeypatch, xml).manifest(tmp_path / "app.apk")

        assert result["truncated"] is True
        assert result["bytes"] == len(xml)
        assert len(result["manifest_xml"]) == _MAX_MANIFEST_CHARS
        assert result["manifest_xml"] == xml[:_MAX_MANIFEST_CHARS]

    def test_a_complete_manifest_is_not_labelled_partial(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        xml = "<manifest package='com.example.app'/>"
        result = self._client(monkeypatch, xml).manifest(tmp_path / "app.apk")

        assert result["truncated"] is False
        assert result["bytes"] == len(xml)
        assert result["manifest_xml"] == xml


class TestApkCertificatesSayWhenSomeWereSkipped:
    """5 certificates with 2 raising used to come back as 3 items, unmarked.

    The parse errors were swallowed. An unattended agent treats those 3 as
    every signer and never notices the broken ones.
    """

    def _certs(self, *, good: int, bad: int) -> dict[str, Any]:
        from headless_re_mcp.backends.apk.client import ApkClient

        class _Good:
            subject = "CN=Good"
            issuer = "CN=CA"
            serial_number = 1
            sha256_fingerprint = "aa"

        class _Bad:
            @property
            def subject(self) -> str:
                raise RuntimeError("broken cert")

        class _FakeApk:
            def get_signature_names(self) -> list[str]:
                return ["META-INF/CERT.RSA"]

            def get_certificates(self) -> list[object]:
                return [_Good()] * good + [_Bad()] * bad

        client = ApkClient()
        client._apk = lambda path: _FakeApk()  # type: ignore[method-assign]
        return client.certificates(Path("app.apk"))

    def test_skipped_certificates_are_counted(self) -> None:
        result = self._certs(good=3, bad=2)
        assert result["count"] == 3
        assert result["skipped"] == 2
        assert len(result["certificates"]) == 3

    def test_a_complete_read_is_not_labelled_partial(self) -> None:
        result = self._certs(good=2, bad=0)
        assert result["count"] == 2
        assert result["skipped"] == 0
        assert result["v1_signed"] is True

    def test_a_failed_name_list_is_not_called_unsigned(self) -> None:
        from headless_re_mcp.backends.apk.client import ApkClient

        class _Good:
            subject = "CN=Good"
            issuer = "CN=CA"
            serial_number = 1
            sha256_fingerprint = "aa"

        class _FakeApk:
            def get_signature_names(self) -> list[str]:
                raise RuntimeError("androguard has no names")

            def get_certificates(self) -> list[object]:
                return [_Good(), _Good()]

        client = ApkClient()
        client._apk = lambda path: _FakeApk()  # type: ignore[method-assign]
        result = client.certificates(Path("app.apk"))
        assert result["count"] == 2
        assert result["v1_signed"] is None
        assert "no names" in result["signature_files_error"]


class TestApkNativeLibsSayWhenTheyStopped:
    """3000 native libs used to come back as count=3000 with no has_more."""

    def _libs(self, n: int, *, limit: int = 500) -> dict[str, Any]:
        from headless_re_mcp.backends.apk.client import ApkClient

        class _FakeApk:
            def get_files(self) -> list[str]:
                return [f"lib/arm64-v8a/lib{index}.so" for index in range(n)] + [
                    "classes.dex"
                ]

        client = ApkClient()
        client._apk = lambda path: _FakeApk()  # type: ignore[method-assign]
        return client.native_libs(Path("app.apk"), limit=limit)

    def test_hitting_the_cap_is_reported(self) -> None:
        result = self._libs(3000, limit=500)
        assert result["count"] == 500
        assert result["total"] == 3000
        assert result["has_more"] is True
        assert result["abis"] == ["arm64-v8a"]

    def test_a_complete_answer_is_not_labelled_partial(self) -> None:
        result = self._libs(3, limit=500)
        assert result["count"] == 3
        assert result["total"] == 3
        assert result["has_more"] is False

    def test_a_result_that_exactly_fills_the_page_is_complete(self) -> None:
        result = self._libs(500, limit=500)
        assert result["count"] == 500
        assert result["total"] == 500
        assert result["has_more"] is False


class TestApkComponentsSayWhenTheyStopped:
    """2000 activities used to come back as 2000 names with no has_more."""

    def _components(self, n: int, *, limit: int = 500) -> dict[str, Any]:
        from headless_re_mcp.backends.apk.client import ApkClient

        class _FakeApk:
            def get_activities(self) -> list[str]:
                return [f"A{index}" for index in range(n)]

            def get_services(self) -> list[str]:
                return [f"S{index}" for index in range(min(n, 2))]

            def get_receivers(self) -> list[str]:
                return []

            def get_providers(self) -> list[str]:
                return []

            def get_main_activity(self) -> str:
                return "A0"

        client = ApkClient()
        client._apk = lambda path: _FakeApk()  # type: ignore[method-assign]
        return client.components(Path("app.apk"), limit=limit)

    def test_hitting_the_cap_is_reported(self) -> None:
        result = self._components(2000, limit=500)
        assert len(result["activities"]) == 500
        assert result["totals"]["activities"] == 2000
        assert result["has_more"] is True

    def test_a_complete_answer_is_not_labelled_partial(self) -> None:
        result = self._components(3, limit=500)
        assert result["activities"] == ["A0", "A1", "A2"]
        assert result["totals"]["activities"] == 3
        assert result["has_more"] is False

    def test_a_result_that_exactly_fills_the_page_is_complete(self) -> None:
        result = self._components(500, limit=500)
        assert len(result["activities"]) == 500
        assert result["totals"]["activities"] == 500
        assert result["has_more"] is False


class TestApkPermissionsSayWhenTheyStopped:
    """5000 permissions used to come back as count=5000 with no limit.

    Measured: 5000 names, 277839 bytes, keys were only permissions/
    requested_permissions/count. A hostile manifest can grow without bound,
    and an unattended agent cannot tell a full grant list from a cut.
    """

    def _permissions(self, n: int, *, limit: int = 500) -> dict[str, Any]:
        from headless_re_mcp.backends.apk.client import ApkClient

        class _FakeApk:
            def get_permissions(self) -> list[str]:
                return [f"android.permission.P{index}" for index in range(n)]

            def get_requested_permissions(self) -> list[str]:
                return self.get_permissions()

        client = ApkClient()
        client._apk = lambda path: _FakeApk()  # type: ignore[method-assign]
        return client.permissions(Path("app.apk"), limit=limit)

    def test_hitting_the_cap_is_reported(self) -> None:
        result = self._permissions(5000, limit=500)
        assert result["count"] == 500
        assert result["total"] == 5000
        assert result["requested_total"] == 5000
        assert result["has_more"] is True
        assert len(result["permissions"]) == 500

    def test_a_complete_answer_is_not_labelled_partial(self) -> None:
        result = self._permissions(3, limit=500)
        assert result["count"] == 3
        assert result["total"] == 3
        assert result["has_more"] is False

    def test_a_result_that_exactly_fills_the_page_is_complete(self) -> None:
        result = self._permissions(500, limit=500)
        assert result["count"] == 500
        assert result["total"] == 500
        assert result["has_more"] is False


class TestApkStringsDoNotCollapseAfterTheCut:
    """Two long strings that differed only past the cap used to become one.

    Measured: prefixes of 2000 characters plus distinct suffixes A and B
    came back as total=2 (the short one plus one cut prefix). The later
    unique suffix disappeared, so an unattended agent thinks the DEX has
    fewer constants than it does.
    """

    def test_distinct_strings_survive_the_inline_cap(self) -> None:
        from headless_re_mcp.backends.apk.client import _MAX_STRING_LEN, ApkClient

        class _Item:
            def __init__(self, value: str) -> None:
                self._value = value

            def get_value(self) -> str:
                return self._value

        class _Parsed:
            def __init__(self) -> None:
                self.analysis = self

            def get_strings(self) -> list[_Item]:
                return [
                    _Item(("x" * _MAX_STRING_LEN) + "A"),
                    _Item(("x" * _MAX_STRING_LEN) + "B"),
                    _Item("short"),
                ]

        client = ApkClient()
        client._parsed = lambda path: _Parsed()  # type: ignore[method-assign]
        result = client.strings(Path("app.apk"), limit=10)
        assert result["total"] == 3
        assert result["count"] == 3
        assert result["truncated_values"] == 2
        assert result["has_more"] is False


class TestApkStringsSayWhenTheyStopped:
    """250 strings with limit=200 used to come back as count=200, no has_more."""

    def _strings(self, n: int, *, offset: int = 0, limit: int = 200) -> dict[str, Any]:
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
        return client.strings(Path("app.apk"), offset=offset, limit=limit)

    def test_hitting_the_cap_is_reported(self) -> None:
        result = self._strings(250, limit=200)
        assert result["count"] == 200
        assert result["total"] == 250
        assert result["has_more"] is True

    def test_a_complete_answer_is_not_labelled_partial(self) -> None:
        result = self._strings(3, limit=200)
        assert result["count"] == 3
        assert result["total"] == 3
        assert result["has_more"] is False

    def test_a_result_that_exactly_fills_the_page_is_complete(self) -> None:
        result = self._strings(200, limit=200)
        assert result["count"] == 200
        assert result["total"] == 200
        assert result["has_more"] is False


class TestApkMethodsSayWhenTheyStopped:
    """150 methods with limit=100 used to come back as count=100, no has_more."""

    def _methods(self, n: int, *, offset: int = 0, limit: int = 100) -> dict[str, Any]:
        from headless_re_mcp.backends.apk.client import ApkClient

        class _Method:
            def __init__(self, name: str) -> None:
                self.name = name
                self.descriptor = "()V"
                self.access = "public"

        class _Klass:
            name = "Lcom/example/Foo;"

            def get_methods(self) -> list[_Method]:
                return [_Method(f"m{index}") for index in range(n)]

        class _Parsed:
            def __init__(self) -> None:
                self.analysis = self

            def get_classes(self) -> list[_Klass]:
                return [_Klass()]

        client = ApkClient()
        client._parsed = lambda path: _Parsed()  # type: ignore[method-assign]
        return client.methods(Path("app.apk"), "com.example.Foo", offset=offset, limit=limit)

    def test_hitting_the_cap_is_reported(self) -> None:
        result = self._methods(150, limit=100)
        assert result["count"] == 100
        assert result["total"] == 150
        assert result["has_more"] is True

    def test_a_complete_answer_is_not_labelled_partial(self) -> None:
        result = self._methods(3, limit=100)
        assert result["count"] == 3
        assert result["total"] == 3
        assert result["has_more"] is False

    def test_a_result_that_exactly_fills_the_page_is_complete(self) -> None:
        result = self._methods(100, limit=100)
        assert result["count"] == 100
        assert result["total"] == 100
        assert result["has_more"] is False


class TestApkClassesSayWhenTheyStopped:
    """150 classes with limit=100 used to come back as count=100, no has_more.

    total was there, but every other capped list on this surface now carries
    has_more, and an agent that only reads that flag treats a full page as
    the whole DEX.
    """

    def _classes(self, n: int, *, offset: int = 0, limit: int = 100) -> dict[str, Any]:
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
                return [_Klass(f"Lfoo/C{index};") for index in range(n)]

        client = ApkClient()
        client._parsed = lambda path: _Parsed()  # type: ignore[method-assign]
        return client.classes(Path("app.apk"), offset=offset, limit=limit)

    def test_hitting_the_cap_is_reported(self) -> None:
        result = self._classes(150, limit=100)
        assert result["count"] == 100
        assert result["total"] == 150
        assert result["has_more"] is True
        assert len(result["classes"]) == 100

    def test_a_complete_answer_is_not_labelled_partial(self) -> None:
        result = self._classes(3, limit=100)
        assert result["count"] == 3
        assert result["total"] == 3
        assert result["has_more"] is False

    def test_a_result_that_exactly_fills_the_page_is_complete(self) -> None:
        result = self._classes(100, limit=100)
        assert result["count"] == 100
        assert result["total"] == 100
        assert result["has_more"] is False


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

    def test_the_tool_description_names_the_page_flag(self) -> None:
        import ast
        import inspect

        from headless_re_mcp.tools import apk as apk_mod

        tree = ast.parse(inspect.getsource(apk_mod.build_apk_tools))
        docs = {
            node.name: ast.get_docstring(node)
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef)
        }
        assert docs["apk_xrefs"]
        assert "has_more" in docs["apk_xrefs"]


class TestFridaModulesSayWhenTheyStopped:
    """100 modules with limit=64 used to come back as count=64, no has_more."""

    def _modules(self, n: int, *, limit: int = 64) -> dict[str, Any]:
        from headless_re_mcp.backends.frida.client import FridaClient

        class _Sync:
            def modules(self) -> list[dict[str, object]]:
                return [
                    {"name": f"m{index}", "base": "0x1", "size": 1, "path": ""}
                    for index in range(n)
                ]

        class _Script:
            exports_sync = _Sync()

            def load(self) -> None:
                return None

        class _Session:
            def create_script(self, source: str) -> _Script:
                assert source
                return _Script()

            def detach(self) -> None:
                return None

        class _Frida:
            def attach(self, pid: int) -> _Session:
                assert pid == 7
                return _Session()

        client = FridaClient()
        client._require = lambda pid, allowed_pid: None  # type: ignore[method-assign]
        client._frida = _Frida()
        return client.modules(7, allowed_pid=7, limit=limit)

    def test_hitting_the_cap_is_reported(self) -> None:
        result = self._modules(100, limit=64)
        assert result["count"] == 64
        assert result["total"] == 100
        assert result["has_more"] is True

    def test_a_complete_answer_is_not_labelled_partial(self) -> None:
        result = self._modules(3, limit=64)
        assert result["count"] == 3
        assert result["total"] == 3
        assert result["has_more"] is False

    def test_a_result_that_exactly_fills_the_page_is_complete(self) -> None:
        result = self._modules(64, limit=64)
        assert result["count"] == 64
        assert result["total"] == 64
        assert result["has_more"] is False


class TestFridaApplicationsSayWhenTheyStopped:
    """300 applications with limit=256 used to come back as count=256, no has_more."""

    def _apps(self, n: int, *, limit: int = 256) -> dict[str, Any]:
        from headless_re_mcp.backends.frida.client import FridaClient

        class _App:
            def __init__(self, index: int) -> None:
                self.identifier = f"com.example.app{index}"
                self.name = f"App {index}"
                self.pid = 0

        class _Dev:
            def enumerate_applications(self) -> list[_App]:
                return [_App(index) for index in range(n)]

        client = FridaClient()
        client._resolve_device = lambda device_id: _Dev()  # type: ignore[method-assign]
        return client.applications("usb", limit=limit)

    def test_hitting_the_cap_is_reported(self) -> None:
        result = self._apps(300, limit=256)
        assert result["count"] == 256
        assert result["total"] == 300
        assert result["has_more"] is True

    def test_a_complete_answer_is_not_labelled_partial(self) -> None:
        result = self._apps(3, limit=256)
        assert result["count"] == 3
        assert result["total"] == 3
        assert result["has_more"] is False

    def test_a_result_that_exactly_fills_the_page_is_complete(self) -> None:
        result = self._apps(256, limit=256)
        assert result["count"] == 256
        assert result["total"] == 256
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

    def test_the_tool_descriptions_name_the_page_flag(self) -> None:
        """exports/classes/methods already returned has_more, but the docs did not.

        An agent that only reads the description treats a full page as the
        whole module or class.
        """
        import ast
        import inspect

        from headless_re_mcp.tools import frida as frida_mod

        tree = ast.parse(inspect.getsource(frida_mod.build_frida_tools))
        docs = {
            node.name: ast.get_docstring(node)
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef)
        }
        for name in ("frida_exports", "frida_java_classes", "frida_java_methods"):
            assert docs[name], name
            assert "has_more" in docs[name], name


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


class TestFridaServerEnsureDoesNotReportAGhost:
    """A launch command that returned used to be reported as running=True.

    Measured: ps listed only init, su returned empty success, and the reply
    said running=True. An unattended agent then attaches to a server that is
    not there and burns the mission on a target that never started.
    """

    def _backend(self, *, after_launch: str) -> Any:
        from headless_re_mcp.backends.adb.client import AdbBackend

        class _Dev:
            def __init__(self) -> None:
                self.phase = "before"

            def shell(self, args: object, timeout: float | None = None) -> str:
                if isinstance(args, str) and args.startswith("su "):
                    self.phase = "after"
                    return ""
                if self.phase == "after":
                    return after_launch
                return "root 1 0 init"

        backend = AdbBackend()
        backend._device = lambda serial: _Dev()  # type: ignore[method-assign]
        return backend

    def test_a_launch_that_left_nothing_is_not_running(self) -> None:
        result = self._backend(after_launch="root 1 0 init").ensure_frida_server(
            "emulator-5554"
        )
        assert result["running"] is False
        assert "not in the process list" in result["note"]

    def test_a_process_that_actually_appeared_is_running(self) -> None:
        result = self._backend(
            after_launch="root 99 1 frida-server"
        ).ensure_frida_server("emulator-5554")
        assert result["running"] is True
        assert "note" not in result

    def test_a_similarly_named_process_is_not_the_server(self) -> None:
        from headless_re_mcp.backends.adb.client import AdbBackend

        class _Dev:
            def shell(self, args: object, timeout: float | None = None) -> str:
                return "root 1 0 not-frida-server"

        backend = AdbBackend()
        backend._device = lambda serial: _Dev()  # type: ignore[method-assign]
        result = backend.ensure_frida_server("emulator-5554")
        assert result["running"] is False
        assert "not in the process list" in result["note"]

    def test_already_running_is_still_a_no_op(self) -> None:
        from headless_re_mcp.backends.adb.client import AdbBackend

        class _Dev:
            def shell(self, args: object, timeout: float | None = None) -> str:
                return "root 99 1 /data/local/tmp/frida-server"

        backend = AdbBackend()
        backend._device = lambda serial: _Dev()  # type: ignore[method-assign]
        result = backend.ensure_frida_server("emulator-5554")
        assert result == {"running": True, "pushed": False, "port": 27042}


class TestDeviceInstallDoesNotReportAGhost:
    """A Failure string used to be reported as installed=True.

    Measured: Device.install returned 'Failure [INSTALL_FAILED_ALREADY_EXISTS]'
    (and the older one-argument signature did the same) and the reply still
    said installed=True. An unattended agent then talks to a package that
    never landed.
    """

    def _install(self, tmp_path: Path, device: object) -> dict[str, Any]:
        from headless_re_mcp.backends.adb.client import AdbBackend

        apk = tmp_path / "app.apk"
        apk.write_bytes(b"PK")
        backend = AdbBackend()
        backend._device = lambda serial: device  # type: ignore[method-assign]
        return backend.install("emulator-5554", str(apk))

    def test_a_failure_string_is_not_installed(self, tmp_path: Path) -> None:
        class _Dev:
            def install(self, *args: object, **kwargs: object) -> str:
                return "Failure [INSTALL_FAILED_ALREADY_EXISTS]"

        result = self._install(tmp_path, _Dev())
        assert result["installed"] is False
        assert "did not report Success" in result["note"]
        assert "INSTALL_FAILED_ALREADY_EXISTS" in result["result"]

    def test_an_old_signature_failure_is_not_installed(self, tmp_path: Path) -> None:
        class _Dev:
            def install(self, *args: object, **kwargs: object) -> str:
                if kwargs:
                    raise TypeError("unexpected keyword argument")
                return "Performing Streamed Install\nFailure [INSTALL_FAILED_UPDATE_INCOMPATIBLE]"

        result = self._install(tmp_path, _Dev())
        assert result["installed"] is False
        assert "INSTALL_FAILED_UPDATE_INCOMPATIBLE" in result["result"]

    def test_a_none_return_is_still_installed(self, tmp_path: Path) -> None:
        class _Dev:
            def install(self, *args: object, **kwargs: object) -> None:
                return None

        result = self._install(tmp_path, _Dev())
        assert result["installed"] is True
        assert "note" not in result

    def test_pm_success_wording_is_still_installed(self, tmp_path: Path) -> None:
        class _Dev:
            def install(self, *args: object, **kwargs: object) -> str:
                return "Performing Streamed Install\nSuccess"

        result = self._install(tmp_path, _Dev())
        assert result["installed"] is True
        assert "note" not in result

    def test_the_tool_description_names_the_installed_flag(self) -> None:
        import ast
        import inspect

        from headless_re_mcp.tools import device as device_mod

        tree = ast.parse(inspect.getsource(device_mod.build_device_tools))
        docs = {
            node.name: ast.get_docstring(node)
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef)
        }
        assert docs["device_install"]
        assert "installed" in docs["device_install"]
        assert "Success" in docs["device_install"]


class TestDeviceUninstallDoesNotReportAGhost:
    """adbutils returning False used to be reported as uninstalled=True.

    Measured: Device.uninstall returned False (package not on the device) and
    the reply still said uninstalled=True. An unattended agent then treats a
    missing package as gone and continues as if the uninstall happened.
    """

    def _uninstall(self, removed: object) -> dict[str, Any]:
        from headless_re_mcp.backends.adb.client import AdbBackend

        class _Dev:
            def uninstall(self, package: str) -> object:
                assert package == "com.example.app"
                return removed

        backend = AdbBackend()
        backend._device = lambda serial: _Dev()  # type: ignore[method-assign]
        return backend.uninstall("emulator-5554", "com.example.app")

    def test_a_missing_package_is_not_uninstalled(self) -> None:
        result = self._uninstall(False)
        assert result["uninstalled"] is False
        assert "not installed" in result["note"]

    def test_a_removed_package_is_uninstalled(self) -> None:
        assert self._uninstall(True) == {
            "uninstalled": True,
            "package": "com.example.app",
        }

    def test_a_none_return_is_still_uninstalled(self) -> None:
        assert self._uninstall(None)["uninstalled"] is True


class TestDeviceLaunchDoesNotReportAGhost:
    """A monkey abort used to be reported as launched=True.

    Measured: 'No activities found to run, monkey aborted.' came back
    launched=True. An unattended agent then talks to an activity that never
    came up and burns the mission on a package that is not in the foreground.
    """

    def _launch(self, message: str) -> dict[str, Any]:
        from headless_re_mcp.backends.adb.client import AdbBackend

        class _Dev:
            def shell(self, args: object) -> str:
                return message

        backend = AdbBackend()
        backend._device = lambda serial: _Dev()  # type: ignore[method-assign]
        return backend.launch("emulator-5554", "com.example.app")

    def test_an_abort_is_not_launched(self) -> None:
        result = self._launch("** No activities found to run, monkey aborted.")
        assert result["launched"] is False
        assert "not inject" in result["note"]
        assert "monkey aborted" in result["result"]

    def test_empty_output_is_not_launched(self) -> None:
        result = self._launch("")
        assert result["launched"] is False
        assert "result" not in result

    def test_events_injected_is_launched(self) -> None:
        result = self._launch("Events injected: 1\n## Network stats: elapsed time=12ms")
        assert result == {"launched": True, "package": "com.example.app"}


class TestDeviceConnectDoesNotReportAGhost:
    """A refusal whose text mentioned 'connected' used to be connected=True.

    Measured: 'not connected to 127.0.0.1:5555', 'disconnected from
    127.0.0.1:5555', and 'already in use' all came back connected=True because
    the check was a substring. An unattended agent then talks to an emulator
    that never accepted the connection.
    """

    def _connect(self, message: str) -> dict[str, Any]:
        from headless_re_mcp.backends.adb.client import AdbBackend

        class _Client:
            def connect(self, endpoint: str, timeout: float = 10.0) -> str:
                assert endpoint == "127.0.0.1:5555"
                assert timeout == 10.0
                return message

        backend = AdbBackend()
        backend._client = lambda: _Client()  # type: ignore[method-assign]
        return backend.connect("127.0.0.1", 5555)

    def test_a_refusal_that_mentions_connected_is_not_connected(self) -> None:
        for message in (
            "not connected to 127.0.0.1:5555",
            "disconnected from 127.0.0.1:5555",
            "already in use",
            "failed to connect to 127.0.0.1:5555",
            "unable to connect to 127.0.0.1:5555: Connection refused",
        ):
            result = self._connect(message)
            assert result["connected"] is False, message
            assert result["result"] == message

    def test_adb_success_wording_is_still_connected(self) -> None:
        for message in (
            "connected to 127.0.0.1:5555",
            "already connected to 127.0.0.1:5555",
        ):
            result = self._connect(message)
            assert result["connected"] is True, message
            assert result["endpoint"] == "127.0.0.1:5555"


class TestDeviceLogcatSaysWhenItIsATail:
    """200 requested lines used to come back as 200 lines and no has_more.

    Measured: a buffer with 250 lines, asked for 200, reply had only lines and
    requested. An unattended agent treats that as the whole log and never
    asks for more of a crash that scrolled off the page.
    """

    def _logcat(self, available: int, *, lines: int = 200) -> dict[str, Any]:
        from headless_re_mcp.backends.adb.client import AdbBackend

        class _Dev:
            def shell(self, args: object) -> str:
                asked = int(args[3])  # type: ignore[index]
                buf = [f"line {index}" for index in range(available)]
                return "\n".join(buf[-asked:])

        backend = AdbBackend()
        backend._device = lambda serial: _Dev()  # type: ignore[method-assign]
        return backend.logcat("emulator-5554", lines=lines)

    def test_a_tail_past_the_request_reports_more(self) -> None:
        result = self._logcat(250, lines=200)
        assert result["count"] == 200
        assert result["requested"] == 200
        assert result["has_more"] is True
        assert result["lines"][0] == "line 50"
        assert result["lines"][-1] == "line 249"

    def test_a_log_that_fits_is_complete(self) -> None:
        result = self._logcat(3, lines=200)
        assert result["count"] == 3
        assert result["has_more"] is False
        assert result["lines"] == ["line 0", "line 1", "line 2"]

    def test_a_result_that_exactly_fills_the_page_is_complete(self) -> None:
        result = self._logcat(200, lines=200)
        assert result["count"] == 200
        assert result["has_more"] is False


class TestDevicePackagesSayWhenTheyStopped:
    """5000 packages used to come back as count=5000 with no limit and no has_more.

    Measured: 5000 names, 113946 bytes, keys were only packages/count/
    third_party_only. A device image or a hostile pm list can grow without
    bound; an unattended agent also cannot tell a full inventory from a cut.
    """

    def _packages(self, n: int, *, limit: int = 500) -> dict[str, Any]:
        from headless_re_mcp.backends.adb.client import AdbBackend

        class _Dev:
            def shell(self, args: object) -> str:
                return "\n".join(f"package:com.example.app{index}" for index in range(n))

        backend = AdbBackend()
        backend._device = lambda serial: _Dev()  # type: ignore[method-assign]
        return backend.packages("emulator-5554", limit=limit)

    def test_hitting_the_cap_is_reported(self) -> None:
        result = self._packages(5000, limit=500)
        assert result["count"] == 500
        assert result["total"] == 5000
        assert result["limit"] == 500
        assert result["has_more"] is True
        assert len(result["packages"]) == 500

    def test_a_complete_answer_is_not_labelled_partial(self) -> None:
        result = self._packages(3, limit=500)
        assert result["count"] == 3
        assert result["total"] == 3
        assert result["has_more"] is False

    def test_a_result_that_exactly_fills_the_page_is_complete(self) -> None:
        result = self._packages(500, limit=500)
        assert result["count"] == 500
        assert result["total"] == 500
        assert result["has_more"] is False


class TestDevicePropertiesSayWhenTheyStopped:
    """800 properties with limit=500 used to come back as count=500, unmarked."""

    def _properties(self, n: int, *, limit: int = 500) -> dict[str, Any]:
        from headless_re_mcp.backends.adb.client import AdbBackend

        class _Dev:
            def shell(self, args: object) -> str:
                return "\n".join(f"[ro.prop.{index}]: [v{index}]" for index in range(n))

        backend = AdbBackend()
        backend._device = lambda serial: _Dev()  # type: ignore[method-assign]
        return backend.properties("emulator-5554", limit=limit)

    def test_hitting_the_cap_is_reported(self) -> None:
        result = self._properties(800, limit=500)
        assert result["count"] == 500
        assert result["total"] == 800
        assert result["limit"] == 500
        assert result["has_more"] is True

    def test_a_complete_answer_is_not_labelled_partial(self) -> None:
        result = self._properties(3, limit=500)
        assert result["count"] == 3
        assert result["total"] == 3
        assert result["has_more"] is False

    def test_a_result_that_exactly_fills_the_page_is_complete(self) -> None:
        result = self._properties(500, limit=500)
        assert result["count"] == 500
        assert result["total"] == 500
        assert result["has_more"] is False


class TestJadxExportSaysWhenTheFileListWasCut:
    """java_file_count said 2500 while java_files held 2000, with no has_more.

    An agent walking the list thinks it has every class. The ones past the cut
    are on disk but unnamed, so they are never opened.
    """

    def _export(self, tmp_path: Path, n: int) -> dict[str, Any]:
        from headless_re_mcp.backends.jadx.client import JadxClient

        exe = tmp_path / "jadx"
        exe.write_text("#!/bin/sh\n", encoding="utf-8")
        out = tmp_path / "out"
        sources = out / "sources"
        sources.mkdir(parents=True)
        for index in range(n):
            (sources / f"C{index}.java").write_text("class X {}", encoding="utf-8")
        client = JadxClient(exe)
        client._run = lambda *args, **kwargs: ("", "", 0)  # type: ignore[method-assign]
        return client.export_sources(tmp_path / "a.apk", out)

    def test_a_tree_past_the_cap_reports_more(self, tmp_path: Path) -> None:
        from headless_re_mcp.backends.jadx.client import _MAX_FILE_LIST

        result = self._export(tmp_path, _MAX_FILE_LIST + 5)
        assert result["java_file_count"] == _MAX_FILE_LIST + 5
        assert len(result["java_files"]) == _MAX_FILE_LIST
        assert result["limit"] == _MAX_FILE_LIST
        assert result["has_more"] is True

    def test_a_tree_that_fits_is_complete(self, tmp_path: Path) -> None:
        result = self._export(tmp_path, 3)
        assert result["java_file_count"] == 3
        assert result["java_files"] == [
            "sources/C0.java",
            "sources/C1.java",
            "sources/C2.java",
        ]
        assert result["has_more"] is False
        assert result["partial"] is False
        assert result["exit_code"] == 0


class TestJadxSaysWhenTheDecompileWasPartial:
    """jadx exit 1 with sources on disk used to come back as a clean tree.

    The comment already knew this is a partial failure. The reply did not, so
    an agent treated two classes as the whole program.
    """

    def _client(self, tmp_path: Path, *, code: int, stderr: str = "") -> Any:
        from headless_re_mcp.backends.jadx.client import JadxClient

        exe = tmp_path / "jadx"
        exe.write_text("#!/bin/sh\n", encoding="utf-8")
        apk = tmp_path / "a.apk"
        apk.write_bytes(b"PK")
        out = tmp_path / "out"
        sources = out / "sources"
        sources.mkdir(parents=True)
        (sources / "A.java").write_text("class A {}", encoding="utf-8")
        (sources / "B.java").write_text("class B {}", encoding="utf-8")
        client = JadxClient(exe)
        client._run = lambda *args, **kwargs: ("", stderr, code)  # type: ignore[method-assign]
        return client, apk, out

    def test_a_nonzero_exit_with_sources_is_partial(self, tmp_path: Path) -> None:
        client, apk, out = self._client(
            tmp_path, code=1, stderr="ERROR - finished with errors\n"
        )
        result = client.export_sources(apk, out)
        assert result["java_file_count"] == 2
        assert result["partial"] is True
        assert result["exit_code"] == 1
        assert "missing or broken" in str(result["note"])
        assert "finished with errors" in str(result["stderr"])

    def test_a_clean_exit_is_not_partial(self, tmp_path: Path) -> None:
        client, apk, out = self._client(tmp_path, code=0)
        result = client.export_sources(apk, out)
        assert result["partial"] is False
        assert result["exit_code"] == 0
        assert "note" not in result
        assert "stderr" not in result

    def test_one_class_carries_the_partial_mark(self, tmp_path: Path) -> None:
        client, apk, out = self._client(tmp_path, code=1, stderr="ERROR\n")
        result = client.decompile(apk, out, "A")
        assert result["partial"] is True
        assert result["exit_code"] == 1
        assert "class A" in result["source"]


class TestJadxKeepsTheHardFailErrorTail:
    """A long jadx failure used to come back as the opening 8000 characters.

    Measured: 10019 characters of stderr ending in 'ERROR no dex files' still
    raised with 8000 leading I's. The ERROR line was gone, so an agent retried
    a decompile it could not see.
    """

    def test_a_hard_fail_keeps_the_error_line(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from headless_re_mcp.backends.common.bounded_run import Completed
        from headless_re_mcp.backends.jadx import client as jadx_mod
        from headless_re_mcp.backends.jadx.client import _MAX_STDERR, JadxClient, JadxError

        body = ("I" * 10_000) + "ERROR no dex files\n"

        def fake_bounded(cmd: list[str], **kwargs: object) -> Completed:
            return Completed(1, b"", body.encode("utf-8"))

        monkeypatch.setattr(jadx_mod, "run_bounded", fake_bounded)
        exe = tmp_path / "jadx"
        exe.write_text("x", encoding="utf-8")
        apk = tmp_path / "a.apk"
        apk.write_bytes(b"PK")
        client = JadxClient(exe)
        with pytest.raises(JadxError) as caught:
            client.export_sources(apk, tmp_path / "out")
        assert caught.value.code == "backend_error"
        err = str(caught.value.details.get("stderr") or "")
        assert "ERROR no dex files" in err
        assert len(err) == _MAX_STDERR

    def test_a_partial_tree_keeps_the_error_line(self, tmp_path: Path) -> None:
        from headless_re_mcp.backends.jadx.client import _MAX_STDERR, JadxClient

        body = ("I" * 10_000) + "ERROR class X failed\n"
        exe = tmp_path / "jadx"
        exe.write_text("x", encoding="utf-8")
        out = tmp_path / "out"
        out.mkdir()
        (out / "A.java").write_text("class A {}", encoding="utf-8")
        apk = tmp_path / "a.apk"
        apk.write_bytes(b"PK")
        client = JadxClient(exe)
        client._run = lambda *args, **kwargs: ("", body, 1)  # type: ignore[method-assign]
        result = client.export_sources(apk, out)
        assert result["partial"] is True
        assert "class X failed" in str(result["stderr"])
        assert len(str(result["stderr"])) == _MAX_STDERR


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


class TestApktoolSaysWhenTheDecodeWasPartial:
    """apktool exit 1 with a manifest on disk used to come back as a clean tree.

    The hard-fail path only trips when nothing landed. A warning-and-write
    still looked like the whole package.
    """

    def _decode(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        *,
        code: int,
        stderr: str = "",
    ) -> dict[str, Any]:
        import headless_re_mcp.backends.apktool.client as apktool_mod

        fake_tool = tmp_path / "apktool"
        fake_tool.write_text("#!/bin/sh\n", encoding="utf-8")
        out = tmp_path / "decoded"
        out.mkdir()
        (out / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")
        (out / "smali").mkdir()
        monkeypatch.setattr(apktool_mod, "_run", lambda *args, **kwargs: ("", stderr, code))
        client = ApktoolClient(fake_tool, None)
        return client.decode(_apk(tmp_path / "a.apk"), out)

    def test_a_nonzero_exit_with_a_manifest_is_partial(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = self._decode(
            tmp_path, monkeypatch, code=1, stderr="W: could not decode resource\n"
        )
        assert result["manifest"]
        assert result["smali_dirs"] == ["smali"]
        assert result["partial"] is True
        assert result["exit_code"] == 1
        assert "incomplete" in str(result["note"])
        assert "could not decode resource" in str(result["stderr"])

    def test_a_clean_exit_is_not_partial(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = self._decode(tmp_path, monkeypatch, code=0)
        assert result["partial"] is False
        assert result["exit_code"] == 0
        assert "note" not in result
        assert "stderr" not in result


class TestApktoolKeepsTheHardFailErrorTail:
    """A long apktool failure used to come back as the opening 8000 characters.

    Measured: 10038 characters of stderr ending in AndrolibException still
    raised with 8000 leading I's. The exception line was gone, so an agent
    retried a decode it could not see.
    """

    def test_a_hard_fail_keeps_the_error_line(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from headless_re_mcp.backends.apktool import client as apktool_mod
        from headless_re_mcp.backends.apktool.client import _MAX_STDERR
        from headless_re_mcp.backends.common.bounded_run import Completed

        body = ("I" * 10_000) + "ERROR brut.androlib.AndrolibException\n"

        def fake_bounded(cmd: list[str], **kwargs: object) -> Completed:
            return Completed(1, b"", body.encode("utf-8"))

        monkeypatch.setattr(apktool_mod, "run_bounded", fake_bounded)
        fake_tool = tmp_path / "apktool"
        fake_tool.write_text("x", encoding="utf-8")
        client = ApktoolClient(fake_tool, None)
        with pytest.raises(ApktoolError) as caught:
            client.decode(_apk(tmp_path / "a.apk"), tmp_path / "out")
        assert caught.value.code == "backend_error"
        err = str(caught.value.details.get("stderr") or "")
        assert "AndrolibException" in err
        assert len(err) == _MAX_STDERR


class TestDevicePullDoesNotReportAGhost:
    """A pull that left no file used to be reported as a local path.

    Measured: adbutils pull_dir on a missing remote makedirs the destination
    and returns 0; a no-op pull returns 0 and writes nothing. Both replies
    still named a local path. An unattended agent then reads an artifact that
    was never written.
    """

    def _pull(self, tmp_path: Path, sync: object) -> dict[str, Any]:
        from headless_re_mcp.backends.adb.client import AdbBackend

        class _Dev:
            def __init__(self) -> None:
                self.sync = sync

        backend = AdbBackend()
        backend._device = lambda serial: _Dev()  # type: ignore[method-assign]
        return backend.pull("emulator-5554", "/sdcard/missing.bin", tmp_path / "pulled.bin")

    def test_a_directory_at_the_destination_is_not_a_pull(self, tmp_path: Path) -> None:
        from headless_re_mcp.backends.adb.client import AdbError

        class _Sync:
            def pull(self, remote: str, local: str) -> int:
                Path(local).mkdir(parents=True, exist_ok=True)
                return 0

        try:
            self._pull(tmp_path, _Sync())
        except AdbError as exc:
            assert exc.code == "backend_error"
            assert "did not produce a local file" in exc.message
            return
        raise AssertionError("missing remote was reported as a pulled file")

    def test_a_no_op_pull_is_not_a_file(self, tmp_path: Path) -> None:
        from headless_re_mcp.backends.adb.client import AdbError

        class _Sync:
            def pull(self, remote: str, local: str) -> int:
                return 0

        try:
            self._pull(tmp_path, _Sync())
        except AdbError as exc:
            assert exc.code == "backend_error"
            assert "did not produce a local file" in exc.message
            return
        raise AssertionError("no-op pull was reported as a pulled file")

    def test_a_written_file_is_still_pulled(self, tmp_path: Path) -> None:
        class _Sync:
            def pull(self, remote: str, local: str) -> int:
                Path(local).write_bytes(b"abc")
                return 3

        dest = tmp_path / "pulled.bin"
        result = self._pull(tmp_path, _Sync())
        assert result == {"remote": "/sdcard/missing.bin", "local": str(dest)}
        assert dest.is_file()
        assert dest.read_bytes() == b"abc"


class TestDeviceScreenshotDoesNotReportAGhost:
    """A screenshot that wrote nothing used to be reported as a PNG path.

    Measured: image.save was a no-op and the reply still named the path. An
    unattended agent then reads a screenshot that was never captured.
    """

    def _shot(self, tmp_path: Path, image: object) -> dict[str, Any]:
        from headless_re_mcp.backends.adb.client import AdbBackend

        class _Dev:
            def screenshot(self) -> object:
                return image

        backend = AdbBackend()
        backend._device = lambda serial: _Dev()  # type: ignore[method-assign]
        return backend.screenshot("emulator-5554", tmp_path / "shot.png")

    def test_a_save_that_wrote_nothing_is_not_a_screenshot(self, tmp_path: Path) -> None:
        from headless_re_mcp.backends.adb.client import AdbError

        class _Img:
            def save(self, path: str) -> None:
                return None

        try:
            self._shot(tmp_path, _Img())
        except AdbError as exc:
            assert exc.code == "backend_error"
            assert "did not produce a local file" in exc.message
            return
        raise AssertionError("empty save was reported as a screenshot")

    def test_a_written_png_is_still_a_screenshot(self, tmp_path: Path) -> None:
        class _Img:
            def save(self, path: str) -> None:
                Path(path).write_bytes(b"\x89PNG\r\n\x1a\n")

        dest = tmp_path / "shot.png"
        result = self._shot(tmp_path, _Img())
        assert result == {"path": str(dest), "serial": "emulator-5554"}
        assert dest.is_file()


class TestDevicePushDoesNotReportAGhost:
    """A push that left no remote file used to be reported as a remote path.

    Measured: sync.push was a no-op and the reply still named the remote.
    An unattended agent then reads a device file that was never written.
    """

    def _push(self, tmp_path: Path, sync: object) -> dict[str, Any]:
        from headless_re_mcp.backends.adb.client import AdbBackend

        local = tmp_path / "payload.bin"
        local.write_bytes(b"abc")

        class _Dev:
            def __init__(self) -> None:
                self.sync = sync

        backend = AdbBackend()
        backend._device = lambda serial: _Dev()  # type: ignore[method-assign]
        return backend.push("emulator-5554", str(local), "/data/local/tmp/payload.bin")

    def test_a_no_op_push_is_not_a_remote_file(self, tmp_path: Path) -> None:
        from headless_re_mcp.backends.adb.client import AdbError

        class _Sync:
            def push(self, local: str, remote: str) -> int:
                return 0

            def stat(self, remote: str) -> object:
                raise FileNotFoundError(remote)

        try:
            self._push(tmp_path, _Sync())
        except AdbError as exc:
            assert exc.code == "backend_error"
            assert "did not produce a remote file" in exc.message
            return
        raise AssertionError("no-op push was reported as a remote file")

    def test_a_directory_at_the_destination_is_not_a_push(self, tmp_path: Path) -> None:
        from headless_re_mcp.backends.adb.client import AdbError

        class _Info:
            mode = 0o040755
            is_dir = True

        class _Sync:
            def push(self, local: str, remote: str) -> int:
                return 0

            def stat(self, remote: str) -> object:
                return _Info()

        try:
            self._push(tmp_path, _Sync())
        except AdbError as exc:
            assert exc.code == "backend_error"
            assert "did not produce a remote file" in exc.message
            return
        raise AssertionError("directory destination was reported as a pushed file")

    def test_a_remote_file_is_still_pushed(self, tmp_path: Path) -> None:
        class _Info:
            mode = 0o100644
            is_dir = False

        class _Sync:
            def push(self, local: str, remote: str) -> int:
                return 3

            def stat(self, remote: str) -> object:
                return _Info()

        result = self._push(tmp_path, _Sync())
        assert result["remote"] == "/data/local/tmp/payload.bin"
        assert result["local"].endswith("payload.bin")


class TestDeviceForwardDoesNotReportAGhost:
    """A forward that left no tunnel used to be reported as the port pair.

    Measured: Device.forward was a no-op and the reply still named the
    ports. An unattended agent then talks through a tunnel that was never
    installed.
    """

    def _forward(self, device: object) -> dict[str, Any]:
        from headless_re_mcp.backends.adb.client import AdbBackend

        backend = AdbBackend()
        backend._device = lambda serial: device  # type: ignore[method-assign]
        return backend.forward("emulator-5554", "tcp:27042", "tcp:27042")

    def test_a_no_op_forward_is_not_installed(self) -> None:
        from headless_re_mcp.backends.adb.client import AdbError

        class _Dev:
            def forward(self, local: str, remote: str) -> None:
                return None

            def forward_list(self) -> list[object]:
                return []

        try:
            self._forward(_Dev())
        except AdbError as exc:
            assert exc.code == "backend_error"
            assert "did not appear in the device list" in exc.message
            return
        raise AssertionError("no-op forward was reported as installed")

    def test_a_listed_forward_is_still_installed(self) -> None:
        class _Item:
            local = "tcp:27042"
            remote = "tcp:27042"

        class _Dev:
            def forward(self, local: str, remote: str) -> None:
                return None

            def forward_list(self) -> list[object]:
                return [_Item()]

        assert self._forward(_Dev()) == {"local": "tcp:27042", "remote": "tcp:27042"}
