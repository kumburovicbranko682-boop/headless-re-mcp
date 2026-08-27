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


class _RecordingDevice:
    """A fake adbutils device that records the argv every shell call receives."""

    def __init__(self, output: str) -> None:
        self.calls: list[list[str]] = []
        self._output = output

    def shell(self, args: list[str], timeout: float | None = None) -> str:
        self.calls.append(list(args))
        return self._output


class TestLogcatPriorityFilter:
    def _backend(self, dev: _RecordingDevice) -> AdbBackend:
        backend = AdbBackend()
        backend._device = lambda serial: dev  # type: ignore[method-assign]
        return backend

    def test_min_priority_appends_a_logcat_filterspec(self) -> None:
        dev = _RecordingDevice("boot\n")
        backend = self._backend(dev)
        backend.logcat("emulator-5554", lines=50, min_priority="e")
        assert dev.calls == [["logcat", "-d", "-t", "50", "*:E"]]

    def test_no_min_priority_leaves_the_command_unfiltered(self) -> None:
        dev = _RecordingDevice("boot\n")
        backend = self._backend(dev)
        backend.logcat("emulator-5554", lines=10)
        assert dev.calls == [["logcat", "-d", "-t", "10"]]

    @pytest.mark.parametrize("level", ["X", "error", "3", "*:E", "e;id"])
    def test_unknown_level_is_invalid_params_and_never_reaches_the_device(
        self, level: str
    ) -> None:
        dev = _RecordingDevice("boot\n")
        backend = self._backend(dev)
        with pytest.raises(AdbError) as info:
            backend.logcat("emulator-5554", min_priority=level)
        assert info.value.code == "invalid_params"
        assert dev.calls == []


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

    def test_offset_pages_past_the_first_window(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The old xrefs had no offset, so callers of a hot method past the first
        # page were simply unreachable. Now a second page continues the list.
        client = self._client(monkeypatch, callers=25)
        first = client.xrefs(tmp_path / "app.apk", "decrypt", offset=0, limit=10)
        second = client.xrefs(tmp_path / "app.apk", "decrypt", offset=10, limit=10)
        third = client.xrefs(tmp_path / "app.apk", "decrypt", offset=20, limit=10)

        assert first["total"] == 25
        assert first["offset"] == 0
        assert [caller["class"] for caller in first["callers"]][0] == "Lcom/example/Caller0;"
        assert second["offset"] == 10
        assert second["count"] == 10
        assert second["callers"][0]["class"] == "Lcom/example/Caller10;"
        assert second["has_more"] is True
        assert third["count"] == 5
        assert third["has_more"] is False

    def test_a_negative_offset_is_clamped_not_a_tail_slice(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The agent transport skips schema validation, so a negative offset must
        # be clamped to zero here rather than tail-slicing the caller list.
        client = self._client(monkeypatch, callers=25)
        result = client.xrefs(tmp_path / "app.apk", "decrypt", offset=-5, limit=10)

        assert result["offset"] == 0
        assert result["callers"][0]["class"] == "Lcom/example/Caller0;"

    def test_collection_ceiling_is_disclosed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from headless_re_mcp.backends.apk.client import _MAX_XREFS_COLLECT

        client = self._client(monkeypatch, callers=_MAX_XREFS_COLLECT + 50)
        result = client.xrefs(tmp_path / "app.apk", "decrypt", limit=10)

        assert result["scan_capped"] is True
        assert result["total"] == _MAX_XREFS_COLLECT


class _FakeDexString:
    def __init__(self, value: str) -> None:
        self._value = value

    def get_value(self) -> str:
        return self._value


class _FakeDexClass:
    def __init__(self, name: str) -> None:
        self.name = name

    def is_external(self) -> bool:
        return False


class _FakePagedParsed:
    def __init__(
        self,
        classes: list[_FakeDexClass] | None = None,
        strings: list[_FakeDexString] | None = None,
    ) -> None:
        self.analysis = self
        self._classes = classes or []
        self._strings = strings or []

    def get_classes(self) -> list[_FakeDexClass]:
        return self._classes

    def get_strings(self) -> list[_FakeDexString]:
        return self._strings


class TestApkPaginationIsClampedInTheBackend:
    """The MCP schema bounds offset>=0 and limit<=cap, but the agent transport
    reaches these handlers through catalog.invoke -> handler(**arguments),
    which skips pydantic value validation. A negative offset would tail-slice
    the list and return its end as page zero; an oversized limit would ignore
    the cap. The backend now clamps, so both transports behave the same.
    """

    def _client(self, monkeypatch: pytest.MonkeyPatch, parsed: Any) -> Any:
        from headless_re_mcp.backends.apk.client import ApkClient

        client = ApkClient()
        monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: parsed)
        return client

    def test_negative_class_offset_reads_page_zero_not_the_tail(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        parsed = _FakePagedParsed(
            classes=[_FakeDexClass(f"Lc/{index};") for index in range(10)]
        )
        client = self._client(monkeypatch, parsed)
        result = client.classes(tmp_path / "app.apk", offset=-1, limit=100)

        assert result["offset"] == 0
        assert result["count"] == 10
        assert result["classes"][0] == "Lc/0;"
        assert result["has_more"] is False

    def test_oversized_class_limit_is_capped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from headless_re_mcp.backends.apk.client import _MAX_CLASSES_PAGE

        parsed = _FakePagedParsed(
            classes=[_FakeDexClass(f"Lc/{index:05d};") for index in range(_MAX_CLASSES_PAGE + 25)]
        )
        client = self._client(monkeypatch, parsed)
        result = client.classes(tmp_path / "app.apk", offset=0, limit=10_000_000)

        assert result["count"] == _MAX_CLASSES_PAGE
        assert result["has_more"] is True

    def test_negative_string_offset_reads_page_zero_not_the_tail(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        parsed = _FakePagedParsed(
            strings=[_FakeDexString(f"s{index:03d}") for index in range(10)]
        )
        client = self._client(monkeypatch, parsed)
        result = client.strings(tmp_path / "app.apk", offset=-5, limit=200)

        assert result["offset"] == 0
        assert result["count"] == 10
        assert result["strings"][0] == "s000"

    def test_oversized_xref_limit_is_capped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from headless_re_mcp.backends.apk.client import _MAX_XREFS_PAGE

        parsed = _FakeParsed([_FakeMethod("decrypt", _MAX_XREFS_PAGE + 25)])
        client = self._client(monkeypatch, parsed)
        result = client.xrefs(tmp_path / "app.apk", "decrypt", limit=10_000_000)

        assert result["count"] == _MAX_XREFS_PAGE
        assert result["has_more"] is True


class TestApkAnalysisIsBoundedByADeadline:
    """androguard runs in-process with no timeout, unlike the jadx/apktool
    subprocess tools. A hostile or pathologically large APK would otherwise
    park the calling MCP worker forever with no honest fault. The parse now
    runs under a wall-clock deadline that frees the worker and reports a
    structured timeout.
    """

    def test_the_deadline_returns_a_result_and_reraises_work_errors(self) -> None:
        from headless_re_mcp.backends.apk.client import _run_deadline

        assert _run_deadline(lambda: 42, timeout=5.0) == 42

        class _Boom(RuntimeError):
            pass

        def _raise() -> int:
            raise _Boom("androguard blew up")

        with pytest.raises(_Boom):
            _run_deadline(_raise, timeout=5.0)

    def test_a_hung_parse_times_out_instead_of_parking_the_caller(self) -> None:
        import time

        from headless_re_mcp.backends.apk.client import ApkError, _run_deadline

        started = time.monotonic()
        with pytest.raises(ApkError) as excinfo:
            _run_deadline(lambda: time.sleep(30), timeout=0.2)
        assert excinfo.value.code == "timeout"
        # The caller was freed at the deadline, not held for the full sleep.
        assert time.monotonic() - started < 5.0

    def test_a_stuck_analysis_surfaces_as_timeout_through_the_client(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import time

        pytest.importorskip("androguard")
        import androguard.misc as androguard_misc

        from headless_re_mcp.backends.apk import client as apk_client
        from headless_re_mcp.backends.apk.client import ApkClient, ApkError

        client = ApkClient()
        if not client.available:
            pytest.skip("androguard not importable")

        def _hang(_path: str) -> Any:
            time.sleep(30)

        monkeypatch.setattr(androguard_misc, "AnalyzeAPK", _hang)
        monkeypatch.setattr(apk_client, "_PARSE_TIMEOUT_S", 0.2)

        apk = _apk(tmp_path / "app.apk")
        with pytest.raises(ApkError) as excinfo:
            client.classes(apk, offset=0, limit=10)
        assert excinfo.value.code == "timeout"


class TestApkAnalysisRefusesDecompressionBombs:
    """androguard decompresses dex/arsc/manifest into memory before parsing, so
    a member that inflates to gigabytes would OOM the process at that read --
    before the wall-clock deadline could fire. The client refuses such an APK
    from the central-directory metadata alone, without decompressing anything.
    """

    def test_a_bomb_member_is_refused_by_the_gate(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from headless_re_mcp.backends.apk import client as apk_client
        from headless_re_mcp.backends.apk.client import ApkError, _refuse_decompression_bomb

        monkeypatch.setattr(apk_client, "_MAX_ANALYZE_UNCOMPRESSED_BYTES", 1024)
        bomb = tmp_path / "bomb.apk"
        with zipfile.ZipFile(bomb, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            # 64 KiB declared uncompressed from a trivially small compressed blob.
            archive.writestr("resources.arsc", b"\x00" * 65536)

        with pytest.raises(ApkError) as excinfo:
            _refuse_decompression_bomb(bomb)
        assert excinfo.value.code == "too_large"
        assert excinfo.value.details["uncompressed_bytes"] == 65536

    def test_unanalysed_members_do_not_count(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from headless_re_mcp.backends.apk import client as apk_client
        from headless_re_mcp.backends.apk.client import _refuse_decompression_bomb

        monkeypatch.setattr(apk_client, "_MAX_ANALYZE_UNCOMPRESSED_BYTES", 4 * 1024 * 1024)
        app = tmp_path / "app.apk"
        with zipfile.ZipFile(app, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("classes.dex", b"\x00" * (1 * 1024 * 1024))  # 1 MiB analysed
            # A large asset/native lib androguard never decompresses must not count.
            archive.writestr("assets/blob.bin", b"\x00" * (64 * 1024 * 1024))
            archive.writestr("lib/arm64-v8a/libx.so", b"\x00" * (64 * 1024 * 1024))

        # Only the 1 MiB dex counts, under the 4 MiB cap: must not raise.
        _refuse_decompression_bomb(app)

    def test_a_bomb_apk_is_refused_before_androguard_runs(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pytest.importorskip("androguard")
        import androguard.misc as androguard_misc

        from headless_re_mcp.backends.apk import client as apk_client
        from headless_re_mcp.backends.apk.client import ApkClient, ApkError

        client = ApkClient()
        if not client.available:
            pytest.skip("androguard not importable")

        def _must_not_run(_path: str) -> Any:
            raise AssertionError("androguard must not be reached for a bomb APK")

        monkeypatch.setattr(androguard_misc, "AnalyzeAPK", _must_not_run)
        monkeypatch.setattr(apk_client, "_MAX_ANALYZE_UNCOMPRESSED_BYTES", 1024)

        bomb = tmp_path / "bomb.apk"
        with zipfile.ZipFile(bomb, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("classes.dex", b"\x00" * 4096)

        with pytest.raises(ApkError) as excinfo:
            client.classes(bomb, offset=0, limit=10)
        assert excinfo.value.code == "too_large"


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


class TestApkManifestReadIsBounded:
    """install() reads the manifest of a caller-supplied, possibly hostile APK.

    ZipFile.read() decompresses the whole member into memory before any slice,
    so a manifest crafted to inflate to gigabytes (a zip bomb) would OOM the
    process. The reader now streams a bounded window instead.
    """

    def test_a_decompression_bomb_manifest_does_not_load_into_memory(
        self, tmp_path: Path
    ) -> None:
        import tracemalloc

        from headless_re_mcp.backends.adb.client import _MANIFEST_SCAN_BYTES, _apk_package_name

        # A valid package id in the scanned window, then ~48 MiB of highly
        # compressible filler: with the old whole-member read this inflates in
        # memory; with the bounded stream only the window is decompressed.
        bomb = tmp_path / "bomb.apk"
        payload = b'package="com.bomb.app"\n' + b"A" * (48 * 1024 * 1024)
        assert len(payload) > _MANIFEST_SCAN_BYTES * 16
        with zipfile.ZipFile(bomb, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("AndroidManifest.xml", payload)

        tracemalloc.start()
        try:
            name = _apk_package_name(bomb)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

        # Correctness: the package in the window is still recovered.
        assert name == "com.bomb.app"
        # Boundedness: nowhere near the 48 MiB the whole-member read would take.
        assert peak < 4 * 1024 * 1024, f"read {peak} bytes; manifest window is not bounded"

    def test_a_normal_manifest_still_yields_its_package(self, tmp_path: Path) -> None:
        from headless_re_mcp.backends.adb.client import _apk_package_name

        apk = tmp_path / "app.apk"
        with zipfile.ZipFile(apk, "w") as archive:
            archive.writestr("AndroidManifest.xml", b'package="com.example.app"\n')
        assert _apk_package_name(apk) == "com.example.app"


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
