"""Android backend boundaries: argument validation, no shell passthrough, auth.

These cover the properties that make the Android surface safe to expose, not the
happy paths (which need a real device and live in the integration gates).
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import (
    _MAX_MANIFEST_BYTES,
    AdbBackend,
    AdbError,
    _apk_package_name,
    _check_package,
    _check_serial,
)
from headless_re_mcp.backends.apk.client import ApkClient, ApkError
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


class TestFridaServerEnsurePortContract:
    """ensure_frida_server judges its port and remote_path before the gate.

    Both are interpolated into an ``su -c`` command line, so they are properties
    of the request and must be settled the same way on every host -- before the
    adbutils capability gate and before the serial is resolved. The reservation
    ``int(port)`` made the splice injection-proof, but a bad port used to reach
    either ValueError (an internal_error incident) or the shell unchecked; the
    range check now answers ``invalid_params`` the way proxy.start's port does.
    """

    def _tripwire_backend(self) -> tuple[AdbBackend, list[str]]:
        backend = AdbBackend()
        reached: list[str] = []

        def _device(serial: str) -> Any:
            reached.append(serial)
            raise AssertionError("the capability gate must not be reached")

        backend._device = _device  # type: ignore[method-assign]
        return backend, reached

    @pytest.mark.parametrize("port", [0, -1, 65536, 70000])
    def test_an_out_of_range_port_is_invalid_params_before_the_gate(self, port: int) -> None:
        backend, reached = self._tripwire_backend()
        with pytest.raises(AdbError) as info:
            backend.ensure_frida_server("emulator-5554", port=port)
        assert info.value.code == "invalid_params"
        assert reached == []

    @pytest.mark.parametrize("port", ["27042", 27042.0, None])
    def test_a_non_int_port_is_invalid_params_not_internal_error(self, port: Any) -> None:
        backend, reached = self._tripwire_backend()
        with pytest.raises(AdbError) as info:
            backend.ensure_frida_server("emulator-5554", port=port)
        assert info.value.code == "invalid_params"
        assert reached == []

    def test_a_bad_remote_path_is_invalid_params_before_the_gate(self) -> None:
        backend, reached = self._tripwire_backend()
        with pytest.raises(AdbError) as info:
            backend.ensure_frida_server(
                "emulator-5554", remote_path="/data/local/tmp/frida; rm -rf /"
            )
        assert info.value.code == "invalid_params"
        assert reached == []

    def test_a_valid_request_passes_validation_and_reaches_the_device(self) -> None:
        class _Dev:
            def shell(self, args: Any, timeout: float | None = None) -> str:
                del args, timeout
                return "root 99 /data/local/tmp/frida-server"

        backend = AdbBackend()
        backend._device = lambda serial: _Dev()  # type: ignore[method-assign]
        result = backend.ensure_frida_server("emulator-5554", port=27042)
        assert result == {"running": True, "pushed": False, "port": 27042}


class TestAdbInputBeforeCapabilityGate:
    """Serial, package and port are settled before the adbutils capability gate.

    adbutils is optional, so a host without it answering capability_unavailable
    for a malformed serial/package/port -- while a host with it answers
    invalid_params -- is one bad input with two verdicts, and the optional
    module means the no-adbutils host is the common one. ``forward`` already
    validated its specs before the gate; ``_device`` (the choke point every
    device verb shares), ``connect`` and the package verbs now match, the way
    proxy.start's port and ensure_frida_server's port do. A tripwire ``_client``
    stands in for the gate on any host: it must never be reached for a malformed
    request, and must be reached once a well-formed one clears validation.
    """

    def _gated_backend(self) -> tuple[AdbBackend, list[str]]:
        backend = AdbBackend()
        reached: list[str] = []

        def _client(*args: Any, **kwargs: Any) -> Any:
            del args, kwargs
            reached.append("client")
            raise AssertionError("the capability gate must not be reached")

        backend._client = _client  # type: ignore[method-assign]
        return backend, reached

    @pytest.mark.parametrize("serial", ["bad serial", "x;rm -rf /", "$(id)", ""])
    def test_a_bad_serial_is_invalid_params_before_the_gate(self, serial: str) -> None:
        backend, reached = self._gated_backend()
        with pytest.raises(AdbError) as info:
            backend.info(serial)
        assert info.value.code == "invalid_params"
        assert reached == []

    def test_a_valid_serial_reaches_the_capability_gate(self) -> None:
        """The reorder does not smother real capability gaps: a good serial hits it."""
        backend, reached = self._gated_backend()
        with pytest.raises(AssertionError):
            backend.info("emulator-5554")
        assert reached == ["client"]

    @pytest.mark.parametrize("package", ["bad package", "com.x;id", "com.x/../y", ""])
    def test_a_bad_package_is_invalid_params_before_the_gate(self, package: str) -> None:
        backend, reached = self._gated_backend()
        for verb in (backend.uninstall, backend.launch, backend.force_stop):
            with pytest.raises(AdbError) as info:
                verb("emulator-5554", package)
            assert info.value.code == "invalid_params"
        assert reached == []

    @pytest.mark.parametrize("port", [0, -1, 65536, "5555", None])
    def test_connect_rejects_a_bad_port_before_the_gate(self, port: Any) -> None:
        backend, reached = self._gated_backend()
        with pytest.raises(AdbError) as info:
            backend.connect("127.0.0.1", port)
        assert info.value.code == "invalid_params"
        assert reached == []


class TestFridaTargetAuthorization:
    """The target boundary holds whether or not the frida module is installed.

    Authorization is a property of the request, so it is settled before the
    capability gate on both the local (`_authorize_local`) and device
    (`_authorize`) paths. That is what lets these assertions run unconditionally: an
    unauthorized pid is refused with `permission_denied` -- not masked as
    `capability_unavailable` -- on a host with no frida, and none of these
    calls reaches a real device (the refusal fires first).
    """

    def _unavailable_client(self) -> FridaClient:
        """A client that behaves as if frida were not installed, on any host."""
        client = FridaClient()
        client._frida = None
        client._available = False
        return client

    def test_device_operations_refuse_unauthorized_pid(self) -> None:
        client = self._unavailable_client()
        with pytest.raises(FridaError) as info:
            client.java_enumerate(
                "usb", 4242, allowed_pids=[1, 2, 3], mode="classes", limit=1
            )
        assert info.value.code == "permission_denied"
        assert info.value.details["pid"] == 4242

    def test_device_hook_refuses_unauthorized_pid(self) -> None:
        client = self._unavailable_client()
        with pytest.raises(FridaError) as info:
            client.hook_template_device("usb", 99, "noop", allowed_pids=[7])
        assert info.value.code == "permission_denied"

    def test_device_authorization_precedes_the_capability_gate(self) -> None:
        """A malformed pid is invalid_params, not capability_unavailable."""
        client = self._unavailable_client()
        with pytest.raises(FridaError) as info:
            client.java_enumerate("usb", -1, allowed_pids=[1], mode="classes", limit=1)
        assert info.value.code == "invalid_params"

    def test_local_single_pid_rule_is_unchanged(self) -> None:
        """The pre-existing PE contract must survive the device generalisation."""
        client = self._unavailable_client()
        with pytest.raises(FridaError) as info:
            client.modules(4242, allowed_pid=4243, limit=1)
        assert info.value.code == "permission_denied"

    def test_unknown_hook_template_is_rejected_with_allowed_list(self) -> None:
        client = self._unavailable_client()
        with pytest.raises(FridaError) as info:
            client.hook_template_device("usb", 5, "arbitrary-script", allowed_pids=[5])
        assert info.value.code == "invalid_params"
        assert "android_ssl_unpin" in info.value.details["allowed"]


class TestApkNameValidationPrecedesParse:
    """apk.methods/xrefs judge their required name before parsing the APK.

    ``_parsed`` runs the androguard capability gate and then a full-APK DEX
    analysis. A missing class_name/method_name is a property of the request, so
    it must be settled first: otherwise an empty name answers
    capability_unavailable on a host without androguard, and pays for an entire
    DEX analysis before rejecting a request malformed on its face. The tripwire
    ``_parsed`` proves neither reaches the parse.
    """

    def _tripwire_client(self) -> ApkClient:
        client = ApkClient()

        def _parsed(_path: Any) -> Any:
            raise AssertionError("the APK must not be parsed for a malformed request")

        client._parsed = _parsed  # type: ignore[method-assign]
        return client

    @pytest.mark.parametrize("class_name", ["", "   "])
    def test_methods_requires_class_name_before_the_parse(self, class_name: str) -> None:
        with pytest.raises(ApkError) as info:
            self._tripwire_client().methods(Path("app.apk"), class_name)
        assert info.value.code == "invalid_params"

    @pytest.mark.parametrize("method_name", ["", "   "])
    def test_xrefs_requires_method_name_before_the_parse(self, method_name: str) -> None:
        with pytest.raises(ApkError) as info:
            self._tripwire_client().xrefs(Path("app.apk"), method_name)
        assert info.value.code == "invalid_params"


class TestFridaJavaEnumerateInputContract:
    """java_enumerate settles mode/class_name before the gate, like the template.

    An authorized pid gets past `_authorize`, so these reach the mode/class_name
    checks. Because those now run before `_resolve_device`, a malformed request
    is `invalid_params` on a host without frida rather than
    `capability_unavailable`, and no device is ever attached. A well-formed
    request, by contrast, does reach the gate and reports the capability there.
    """

    def _unavailable_client(self) -> FridaClient:
        client = FridaClient()
        client._frida = None
        client._available = False
        return client

    def test_an_unknown_mode_is_invalid_params_before_the_gate(self) -> None:
        client = self._unavailable_client()
        with pytest.raises(FridaError) as info:
            client.java_enumerate("usb", 5, allowed_pids=[5], mode="dump", limit=1)
        assert info.value.code == "invalid_params"
        assert info.value.details.get("mode") == "dump"

    def test_methods_without_a_class_name_is_invalid_params_before_the_gate(self) -> None:
        client = self._unavailable_client()
        with pytest.raises(FridaError) as info:
            client.java_enumerate(
                "usb", 5, allowed_pids=[5], mode="methods", class_name="", limit=1
            )
        assert info.value.code == "invalid_params"

    def test_methods_with_class_name_none_is_invalid_params(self) -> None:
        client = self._unavailable_client()
        with pytest.raises(FridaError) as info:
            client.java_enumerate(
                "usb", 5, allowed_pids=[5], mode="methods", class_name=None, limit=1
            )
        assert info.value.code == "invalid_params"

    def test_a_well_formed_request_reaches_the_capability_gate(self) -> None:
        """Valid mode/class_name pass the input checks and hit _resolve_device."""
        client = self._unavailable_client()
        with pytest.raises(FridaError) as info:
            client.java_enumerate(
                "usb", 5, allowed_pids=[5], mode="methods", class_name="Foo", limit=1
            )
        assert info.value.code == "capability_unavailable"


class TestFridaLocalAttachInputContract:
    """frida.attach settles pid shape and authorization before the gate.

    attach used to check the capability gate first, so a frida-less host
    answered capability_unavailable for a malformed or unauthorized pid that a
    host with frida rejects as invalid_params / permission_denied -- one bad
    request, two verdicts, and the very permission contract _authorize documents
    hidden from every run without the optional module. The order is now shape ->
    auth -> gate, matching the device path; a well-formed authorized pid still
    reaches the gate and reports the capability there.
    """

    def _unavailable_client(self) -> FridaClient:
        client = FridaClient()
        client._frida = None
        client._available = False
        return client

    @pytest.mark.parametrize("pid", [0, -1, "5", 5.0, None])
    def test_a_malformed_pid_is_invalid_params_before_the_gate(self, pid: Any) -> None:
        client = self._unavailable_client()
        with pytest.raises(FridaError) as info:
            client.attach(pid, allowed_pid=pid if isinstance(pid, int) else 5)
        assert info.value.code == "invalid_params"

    def test_an_unauthorized_pid_is_permission_denied_before_the_gate(self) -> None:
        client = self._unavailable_client()
        with pytest.raises(FridaError) as info:
            client.attach(4242, allowed_pid=7)
        assert info.value.code == "permission_denied"

    def test_a_well_formed_authorized_pid_reaches_the_capability_gate(self) -> None:
        """The reorder does not smother the real capability gap."""
        client = self._unavailable_client()
        with pytest.raises(FridaError) as info:
            client.attach(5, allowed_pid=5)
        assert info.value.code == "capability_unavailable"


class TestFridaSpawnInputContract:
    """frida.spawn settles the package before the capability gate.

    spawn resolved the device (the gate, via _resolve_device -> _need) before
    validating the package, unlike its siblings java_enumerate and
    hook_template_device which judge mode/class_name/template first. So a
    frida-less host answered capability_unavailable for a package malformed on
    its face, while a host with frida rejects it as invalid_params. The package
    now settles first; a well-formed package still reaches the gate.
    """

    def _unavailable_client(self) -> FridaClient:
        client = FridaClient()
        client._frida = None
        client._available = False
        return client

    @pytest.mark.parametrize("package", ["", "   ", "not a package", "com.x/../y", "-rf"])
    def test_a_bad_package_is_invalid_params_before_the_gate(self, package: str) -> None:
        client = self._unavailable_client()
        with pytest.raises(FridaError) as info:
            client.spawn("usb", package)
        assert info.value.code == "invalid_params"

    def test_a_well_formed_package_reaches_the_capability_gate(self) -> None:
        client = self._unavailable_client()
        with pytest.raises(FridaError) as info:
            client.spawn("usb", "com.example.app")
        assert info.value.code == "capability_unavailable"


class TestFridaLocalShapeBeforeGate:
    """exports/memory_read/hook_template judge their shape before the gate.

    The local reads used to run the old _require (pid-auth then capability gate)
    and only then check module_name/window/template. On a frida-less host that
    made a shape malformed on its face answer capability_unavailable, while a
    host with frida rejects it as invalid_params -- one bad request, two
    verdicts, the split the device siblings already avoid. _require is now split
    into a pure-auth _authorize_local plus an explicit _need(), so the order is
    pid-auth -> shape -> gate. pid-auth still leads, so a wrong pid is refused
    even alongside a bad shape; a well-formed shape reaches the gate.
    """

    def _unavailable_client(self) -> FridaClient:
        client = FridaClient()
        client._frida = None
        client._available = False
        return client

    @pytest.mark.parametrize("module_name", ["", "   "])
    def test_exports_empty_module_name_is_invalid_params(self, module_name: str) -> None:
        client = self._unavailable_client()
        with pytest.raises(FridaError) as info:
            client.exports(5, module_name, allowed_pid=5)
        assert info.value.code == "invalid_params"

    def test_exports_well_formed_reaches_the_gate(self) -> None:
        client = self._unavailable_client()
        with pytest.raises(FridaError) as info:
            client.exports(5, "libc.so", allowed_pid=5)
        assert info.value.code == "capability_unavailable"

    @pytest.mark.parametrize(
        ("address", "size"), [(-1, 16), (0, 0), (0, 10**9), ("0", 16), (0, "16")]
    )
    def test_memory_read_bad_window_is_invalid_params(self, address: Any, size: Any) -> None:
        client = self._unavailable_client()
        with pytest.raises(FridaError) as info:
            client.memory_read(5, address, size, allowed_pid=5)
        assert info.value.code == "invalid_params"

    def test_memory_read_well_formed_reaches_the_gate(self) -> None:
        client = self._unavailable_client()
        with pytest.raises(FridaError) as info:
            client.memory_read(5, 0x1000, 16, allowed_pid=5)
        assert info.value.code == "capability_unavailable"

    def test_hook_template_unknown_is_invalid_params(self) -> None:
        client = self._unavailable_client()
        with pytest.raises(FridaError) as info:
            client.hook_template(5, "bogus", allowed_pid=5)
        assert info.value.code == "invalid_params"

    def test_hook_template_known_reaches_the_gate(self) -> None:
        client = self._unavailable_client()
        with pytest.raises(FridaError) as info:
            client.hook_template(5, "noop", allowed_pid=5)
        assert info.value.code == "capability_unavailable"

    def test_pid_authorization_precedes_shape_and_gate(self) -> None:
        """A wrong pid is permission_denied even with a deliberately empty name."""
        client = self._unavailable_client()
        with pytest.raises(FridaError) as info:
            client.exports(4242, "", allowed_pid=7)
        assert info.value.code == "permission_denied"


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


class TestApkPackageNameIsBounded:
    """The cheap package-id probe must not decompress a whole manifest.

    ``_apk_package_name`` runs on device.connect to match a pulled APK to its
    installed package, on an operator-supplied file. Reading the member with
    ``ZipFile.read`` would inflate the entire (attacker-controlled) manifest
    into memory before slicing, so a zip-bombed AndroidManifest.xml was an
    unattended OOM. The read is now streamed and capped.
    """

    def test_a_zip_bombed_manifest_is_not_fully_decompressed(self, tmp_path: Path) -> None:
        import tracemalloc

        bomb = tmp_path / "bomb.apk"
        # ~64 MiB of a single byte compresses to a handful of KiB on disk but
        # would balloon back to 64 MiB if read whole. The package id sits in the
        # first bytes, within the cap, so a bounded read still finds it.
        manifest = b'<manifest package="com.example.bomb">\n' + b"A" * (64 * 1024 * 1024)
        with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("AndroidManifest.xml", manifest)
            archive.writestr("classes.dex", b"dex\n035\x00")

        tracemalloc.start()
        try:
            result = _apk_package_name(bomb)
            _current, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

        assert result == "com.example.bomb"
        # A bounded read holds ~64 KiB; decompressing the whole member would
        # peak orders of magnitude above this ceiling.
        assert peak < 8 * 1024 * 1024, (
            f"peak {peak} bytes suggests the whole manifest member was decompressed"
        )

    def test_only_the_capped_prefix_of_the_manifest_is_consulted(
        self, tmp_path: Path
    ) -> None:
        past_cap = tmp_path / "late.apk"
        # Push the only package marker past the read cap; a bounded read must not
        # see it, so the probe reports "unknown" rather than scanning the rest.
        filler = b"A" * (_MAX_MANIFEST_BYTES + 4096)
        manifest = filler + b'<manifest package="com.example.late">'
        with zipfile.ZipFile(past_cap, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("AndroidManifest.xml", manifest)
        assert _apk_package_name(past_cap) is None


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
