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
    def __init__(self, name: str, callers: int, callees: int = 0) -> None:
        self.name = name
        self._callers = callers
        self._callees = callees

    def is_external(self) -> bool:
        return False

    def get_xref_from(self) -> list[tuple[object, _FakeCall, int]]:
        return [(None, _FakeCall(index), index) for index in range(self._callers)]

    def get_xref_to(self) -> list[tuple[object, _FakeCall, int]]:
        return [(None, _FakeCall(index), index) for index in range(self._callees)]


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


class TestApkXrefsWalkBothDirections:
    """callers walks xref_from; callees walks xref_to -- forward and backward."""

    def _client(
        self, monkeypatch: pytest.MonkeyPatch, *, callers: int = 0, callees: int = 0
    ) -> Any:
        from headless_re_mcp.backends.apk.client import ApkClient

        client = ApkClient()
        monkeypatch.setattr(
            ApkClient,
            "_parsed",
            lambda self, path: _FakeParsed([_FakeMethod("decrypt", callers, callees)]),
        )
        return client

    def test_default_direction_stays_callers(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = self._client(monkeypatch, callers=2, callees=99)
        result = client.xrefs(tmp_path / "app.apk", "decrypt")

        assert result["direction"] == "callers"
        assert result["count"] == 2
        assert "callers" in result
        assert "callees" not in result

    def test_callees_direction_walks_xref_to(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = self._client(monkeypatch, callers=99, callees=3)
        result = client.xrefs(tmp_path / "app.apk", "decrypt", direction="callees", limit=10)

        assert result["direction"] == "callees"
        assert result["count"] == 3
        assert result["has_more"] is False
        assert "callees" in result
        assert "callers" not in result
        assert all(set(edge) == {"class", "method"} for edge in result["callees"])

    def test_callees_report_when_they_hit_the_cap(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = self._client(monkeypatch, callees=25)
        result = client.xrefs(tmp_path / "app.apk", "decrypt", direction="callees", limit=10)

        assert result["count"] == 10
        assert result["has_more"] is True

    def test_an_unknown_direction_is_rejected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from headless_re_mcp.backends.apk.client import ApkError

        client = self._client(monkeypatch, callers=1)
        with pytest.raises(ApkError) as excinfo:
            client.xrefs(tmp_path / "app.apk", "decrypt", direction="sideways")
        assert excinfo.value.code == "invalid_params"


class _FakeMethodRef:
    def __init__(self, class_name: str, name: str) -> None:
        self.class_name = class_name
        self.name = name


class _FakeStringAnalysis:
    def __init__(self, value: str, refs: list[tuple[str, str]]) -> None:
        self._value = value
        self._refs = refs

    def get_value(self) -> str:
        return self._value

    def get_xref_from(self) -> set[tuple[object, _FakeMethodRef]]:
        return {(object(), _FakeMethodRef(cls, name)) for cls, name in self._refs}


class _FakeStringParsed:
    def __init__(self, strings: list[_FakeStringAnalysis]) -> None:
        self.analysis = self
        self._strings = strings

    def get_strings(self) -> list[_FakeStringAnalysis]:
        return self._strings


class TestApkStringXrefs:
    """Pivoting from a string constant to the methods that reference it."""

    def _client(
        self, monkeypatch: pytest.MonkeyPatch, strings: list[_FakeStringAnalysis]
    ) -> Any:
        from headless_re_mcp.backends.apk.client import ApkClient

        client = ApkClient()
        monkeypatch.setattr(
            ApkClient, "_parsed", lambda self, path: _FakeStringParsed(strings)
        )
        return client

    def test_a_found_string_lists_its_referencing_methods(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        strings = [
            _FakeStringAnalysis("https://api.example.com", [("Lcom/example/App;", "main")]),
            _FakeStringAnalysis("other", [("Lcom/example/App;", "onCreate")]),
        ]
        client = self._client(monkeypatch, strings)
        result = client.string_xrefs(tmp_path / "app.apk", "https://api.example.com")

        assert result["found"] is True
        assert result["value"] == "https://api.example.com"
        assert result["total"] == 1
        assert result["xrefs"] == [{"class": "Lcom/example/App;", "method": "main"}]
        assert result["has_more"] is False
        assert result["scan_capped"] is False

    def test_an_absent_string_is_found_false_with_no_xrefs(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = self._client(
            monkeypatch, [_FakeStringAnalysis("present", [("La;", "x")])]
        )
        result = client.string_xrefs(tmp_path / "app.apk", "missing")

        assert result["found"] is False
        assert result["total"] == 0
        assert result["xrefs"] == []

    def test_a_present_but_unreferenced_string_is_found_true_and_empty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = self._client(monkeypatch, [_FakeStringAnalysis("lonely", [])])
        result = client.string_xrefs(tmp_path / "app.apk", "lonely")

        # found True with an empty list -- the opposite of an absent string.
        assert result["found"] is True
        assert result["total"] == 0
        assert result["xrefs"] == []

    def test_the_referencing_methods_paginate(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        refs = [(f"Lc{index};", f"m{index}") for index in range(5)]
        client = self._client(monkeypatch, [_FakeStringAnalysis("s", refs)])

        page = client.string_xrefs(tmp_path / "app.apk", "s", offset=0, limit=2)
        assert page["total"] == 5
        assert page["count"] == 2
        assert page["offset"] == 0
        assert page["has_more"] is True

        tail = client.string_xrefs(tmp_path / "app.apk", "s", offset=4, limit=2)
        assert tail["count"] == 1
        assert tail["has_more"] is False

    def test_an_empty_value_is_rejected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from headless_re_mcp.backends.apk.client import ApkError

        client = self._client(monkeypatch, [])
        with pytest.raises(ApkError) as excinfo:
            client.string_xrefs(tmp_path / "app.apk", "")
        assert excinfo.value.code == "invalid_params"


class _FakeCert:
    def __init__(self, tag: str) -> None:
        self.subject = f"CN={tag}"
        self.issuer = f"CN={tag}"
        self.serial_number = 1
        self.sha256_fingerprint = tag * 2


class _FakeSignedApk:
    """An androguard APK stub with configurable signing-scheme predicates."""

    def __init__(
        self,
        *,
        v1: bool,
        v2: bool,
        v3: bool,
        names: list[str] | None = None,
        certs: list[_FakeCert] | None = None,
        drop: set[str] | None = None,
    ) -> None:
        self._v = {"is_signed_v1": v1, "is_signed_v2": v2, "is_signed_v3": v3}
        self._names = names or []
        self._certs = certs or []
        # Predicate names an older androguard would not expose at all.
        for missing in drop or set():
            delattr_marker = f"is_signed_v{missing}"
            self._v.pop(delattr_marker, None)

    def get_signature_names(self) -> list[str]:
        return self._names

    def get_certificates(self) -> list[_FakeCert]:
        return self._certs

    def __getattr__(self, name: str) -> Any:
        # Only the scheme predicates are dynamic; anything else is a real miss.
        if name in {"is_signed_v1", "is_signed_v2", "is_signed_v3"}:
            values = self.__dict__.get("_v", {})
            if name not in values:
                raise AttributeError(name)
            return lambda: values[name]
        raise AttributeError(name)


class TestApkCertificatesReportSigningSchemes:
    """apk.certificates must say which of v1/v2/v3 signed the APK, not just that
    a certificate exists -- v1 is tamperable, v2/v3 are not, and modern APKs
    leave no META-INF signature files at all."""

    def _run(self, monkeypatch: pytest.MonkeyPatch, apk: _FakeSignedApk) -> dict[str, Any]:
        from headless_re_mcp.backends.apk.client import ApkClient

        monkeypatch.setattr(ApkClient, "_apk", lambda self, path: apk)
        return ApkClient().certificates(Path("/tmp/app.apk"))

    def test_unsigned_apk_reports_no_schemes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        data = self._run(monkeypatch, _FakeSignedApk(v1=False, v2=False, v3=False))
        assert data["v1_signed"] is False
        assert data["v2_signed"] is False
        assert data["v3_signed"] is False
        assert data["signing_schemes"] == []

    def test_v2_v3_only_apk_reports_both_without_meta_inf_files(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A v2/v3-signed APK has no CERT.RSA files, so bool(names) would miss it."""
        apk = _FakeSignedApk(
            v1=False, v2=True, v3=True, names=[], certs=[_FakeCert("aa")]
        )
        data = self._run(monkeypatch, apk)
        assert data["v1_signed"] is False
        assert data["v2_signed"] is True
        assert data["v3_signed"] is True
        assert data["signing_schemes"] == ["v2", "v3"]
        assert data["certificates"], "v2/v3 certs must still be listed"

    def test_v1_signed_apk_reports_v1(self, monkeypatch: pytest.MonkeyPatch) -> None:
        apk = _FakeSignedApk(v1=True, v2=False, v3=False, names=["META-INF/CERT.RSA"])
        data = self._run(monkeypatch, apk)
        assert data["v1_signed"] is True
        assert data["signing_schemes"] == ["v1"]
        assert data["signature_files"] == ["META-INF/CERT.RSA"]

    def test_missing_v2_predicate_falls_back_to_false(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An older androguard without is_signed_v2 must not fail the read."""
        apk = _FakeSignedApk(
            v1=True, v2=False, v3=False, names=["META-INF/CERT.RSA"], drop={"2", "3"}
        )
        data = self._run(monkeypatch, apk)
        assert data["v1_signed"] is True
        assert data["v2_signed"] is False
        assert data["v3_signed"] is False
        assert data["signing_schemes"] == ["v1"]


class _HostileApk:
    """Stands in for an androguard APK whose every accessor raises.

    ``APK(path)`` logs and swallows a broken AndroidManifest.xml rather than
    raising, so the object exists but its accessors then raise raw KeyError /
    AttributeError from deep in the library. This reproduces that shape without
    needing a crafted binary on disk.
    """

    def __getattr__(self, _name: str) -> Any:
        def raiser(*_args: Any, **_kwargs: Any) -> Any:
            raise KeyError("Name")

        return raiser


class TestApkManifestReadersMapFaultsCleanly:
    """A corrupt APK whose accessors raise must degrade to backend_error.

    Left unwrapped, an accessor KeyError reaches the service's BaseException
    branch and is filed as internal_error -- the leaked-exception bucket that
    also mints an incident -- for what is really an unparseable input. Every
    manifest-level reader routes through ``_read_manifest`` so it maps such a
    fault to a clean, actionable backend_error instead. Asserting this at the
    client keeps the contract testable without androguard emitting a specific
    exception type for a specific corruption, which varies across versions.
    """

    @pytest.mark.parametrize(
        "op",
        ["open", "manifest", "permissions", "certificates", "components", "native_libs"],
    )
    def test_reader_maps_accessor_fault_to_backend_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, op: str
    ) -> None:
        from headless_re_mcp.backends.apk.client import ApkClient, ApkError

        monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _HostileApk())
        client = ApkClient()
        with pytest.raises(ApkError) as info:
            getattr(client, op)(tmp_path / "app.apk")
        assert info.value.code == "backend_error"


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
