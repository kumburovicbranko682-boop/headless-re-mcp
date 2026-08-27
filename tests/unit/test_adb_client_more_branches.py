"""Remaining guard, reraise, and degradation branches of the ADB backend.

``test_adb_backend_branches.py`` covers the bulk of the surface; this file
finishes the reachable edges that file left: the low-level probe helpers'
error returns, the AdbError-passthrough arms of every operation (a structured
error must not be re-wrapped into a vaguer one), the client/device
timeout-vs-unreachable split, the post-transfer caps, and the forward
table's reserve/release bookkeeping when a slot was already held.

The generic ``except Exception`` arms of launch/force-stop are intentionally
not exercised: their only call is ``_device_shell``, which converts every
failure to AdbError, so the reraise arm is the only one a caller can reach.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

# Reuse the fakes the sibling suite already defines.
from test_adb_backend_branches import (  # type: ignore[import-not-found]
    _apk_file,
    _backend_with_dev,
    _FakeClientList,
    _FakeDev,
    _Sync,
    _TimeoutError,
)

from headless_re_mcp.backends.adb import client as adb_client
from headless_re_mcp.backends.adb.client import (
    AdbBackend,
    AdbError,
    _apk_package_name,
    _bind_open_transport,
    _frida_server_visible,
    _pids_for_package,
    _pm_path,
)

MP = pytest.MonkeyPatch


class _ShellDev:
    """Minimal device exposing only ``shell`` for the probe helpers."""

    def __init__(
        self, mapping: dict[str, str], errors: dict[str, BaseException] | None = None
    ) -> None:
        self._mapping = mapping
        self._errors = errors or {}

    def shell(self, args: str | list[str], timeout: float | None = None) -> str:
        key = args if isinstance(args, str) else " ".join(args)
        if key in self._errors:
            raise self._errors[key]
        return self._mapping.get(key, "")


# ----------------------------------------------------------------------------
# Probe helpers
# ----------------------------------------------------------------------------
class TestProbeHelpers:
    def test_frida_visible_is_none_when_ps_fails(self) -> None:
        dev = _ShellDev({}, errors={"ps -A": RuntimeError("shell died")})
        assert _frida_server_visible(dev) is None

    def test_pm_path_returns_none_when_no_package_line(self) -> None:
        dev = _ShellDev({"pm path com.example.app": "some other line\n"})
        assert _pm_path(dev, "com.example.app") is None

    def test_pids_none_when_ps_fallback_fails(self) -> None:
        dev = _ShellDev(
            {"pidof com.example.app": "pidof: not found"},
            errors={"ps -A": AdbError("timeout", "adb timed out")},
        )
        assert _pids_for_package(dev, "com.example.app") is None

    def test_pids_skips_a_ps_line_with_no_numeric_column(self) -> None:
        dev = _ShellDev(
            {
                "pidof com.example.app": "not found",
                "ps -A": "com.example.app aa bb cc",
            }
        )
        assert _pids_for_package(dev, "com.example.app") == []

    def test_pids_from_ps_stops_at_sixteen(self) -> None:
        rows = "\n".join("com.example.app 100" for _ in range(20))
        dev = _ShellDev(
            {"pidof com.example.app": "not found", "ps -A": rows}
        )
        pids = _pids_for_package(dev, "com.example.app")
        assert pids is not None
        assert len(pids) == 16

    def test_pids_none_when_pidof_has_no_digits(self) -> None:
        dev = _ShellDev({"pidof com.example.app": "garbage"})
        assert _pids_for_package(dev, "com.example.app") is None

    def test_apk_package_scanned_without_the_word_package(self, tmp_path: Path) -> None:
        # utf-8 decode fails on the BOM lead byte, and the utf-16 text never
        # contains "package", so the marker search misses and the whole blob is
        # scanned for a candidate instead.
        payload = b"\xff\xfe" + "com.example.app".encode("utf-16-le")
        apk = tmp_path / "a.apk"
        with zipfile.ZipFile(apk, "w") as archive:
            archive.writestr("AndroidManifest.xml", payload)
        assert _apk_package_name(apk) == "com.example.app"


# ----------------------------------------------------------------------------
# _bind_open_transport positional fallbacks
# ----------------------------------------------------------------------------
class TestBindOpenTransportFallbacks:
    def test_falls_back_to_two_positional_args(self) -> None:
        class _Dev:
            def __init__(self) -> None:
                self.calls: list[tuple[Any, ...]] = []

            def open_transport(self, *args: Any, **kwargs: Any) -> str:
                if kwargs:
                    raise TypeError("no keywords here")
                self.calls.append(args)
                return "two-ok"

        dev = _Dev()
        bound = _bind_open_transport(dev, 9.0)
        assert bound.open_transport() == "two-ok"
        assert dev.calls == [(None, 9.0)]

    def test_falls_back_to_one_positional_arg(self) -> None:
        class _Dev:
            def open_transport(self, *args: Any, **kwargs: Any) -> str:
                if kwargs:
                    raise TypeError("no keywords")
                if len(args) >= 2:
                    raise TypeError("too many positionals")
                return "one-ok"

        dev = _Dev()
        bound = _bind_open_transport(dev, 3.0)
        assert bound.open_transport() == "one-ok"


# ----------------------------------------------------------------------------
# _client / _device
# ----------------------------------------------------------------------------
class TestClientAndDevice:
    def test_client_sets_the_adb_path_env(self, monkeypatch: MP) -> None:
        class _Client:
            pass

        class _Adbutils:
            def AdbClient(self, host: str = "", port: int = 0, **kw: Any) -> Any:
                return _Client()

        # A pre-set value makes setdefault a no-op the monkeypatch will restore,
        # so the branch runs without leaking a real path into the environment.
        monkeypatch.setenv("ADBUTILS_ADB_PATH", "sentinel")
        backend = AdbBackend(adb_path=Path("/opt/platform-tools/adb"))
        backend._available = True
        backend._adbutils = _Adbutils()
        assert isinstance(backend._client(), _Client)

    def test_client_passes_through_an_adb_error(self) -> None:
        class _Adbutils:
            def AdbClient(self, **kw: Any) -> Any:
                raise AdbError("invalid_state", "already structured")

        backend = AdbBackend()
        backend._available = True
        backend._adbutils = _Adbutils()
        with pytest.raises(AdbError) as info:
            backend._client()
        assert info.value.code == "invalid_state"

    def test_device_passes_through_an_adb_error(self, monkeypatch: MP) -> None:
        class _Client:
            def device(self, serial: str | None = None) -> Any:
                raise AdbError("invalid_state", "device busy")

        backend = AdbBackend()
        backend._available = True
        monkeypatch.setattr(backend, "_client", lambda **kw: _Client())
        with pytest.raises(AdbError) as info:
            backend._device("emulator-5554")
        assert info.value.code == "invalid_state"

    def test_device_labels_a_transport_timeout(self, monkeypatch: MP) -> None:
        class _Client:
            def device(self, serial: str | None = None) -> Any:
                raise _TimeoutError()

        backend = AdbBackend()
        backend._available = True
        monkeypatch.setattr(backend, "_client", lambda **kw: _Client())
        with pytest.raises(AdbError) as info:
            backend._device("emulator-5554")
        assert info.value.code == "timeout"

    def test_device_returns_the_resolved_device(self, monkeypatch: MP) -> None:
        dev = SimpleNamespace()  # no open_transport, so bind returns it unchanged

        class _Client:
            def device(self, serial: str | None = None) -> Any:
                return dev

        backend = AdbBackend()
        backend._available = True
        monkeypatch.setattr(backend, "_client", lambda **kw: _Client())
        assert backend._device("emulator-5554") is dev

    def test_list_devices_passes_through_an_adb_error(self, monkeypatch: MP) -> None:
        backend = AdbBackend()
        backend._available = True
        monkeypatch.setattr(
            backend,
            "_client",
            lambda **kw: _FakeClientList(infos=[], error=AdbError("invalid_state", "x")),
        )
        with pytest.raises(AdbError) as info:
            backend.list_devices()
        assert info.value.code == "invalid_state"

    def test_list_devices_labels_a_timeout(self, monkeypatch: MP) -> None:
        backend = AdbBackend()
        backend._available = True
        monkeypatch.setattr(
            backend,
            "_client",
            lambda **kw: _FakeClientList(infos=[], error=_TimeoutError()),
        )
        with pytest.raises(AdbError) as info:
            backend.list_devices()
        assert info.value.code == "timeout"


# ----------------------------------------------------------------------------
# Read operations that skip non-matching lines
# ----------------------------------------------------------------------------
class TestReadSkips:
    def test_properties_skips_a_line_it_cannot_parse(self, monkeypatch: MP) -> None:
        dev = _FakeDev(shell_map={"getprop": "garbage line without brackets"})
        backend = _backend_with_dev(dev, monkeypatch)
        result = backend.properties("emulator-5554")
        assert result["count"] == 0

    def test_packages_skips_a_non_package_line(self, monkeypatch: MP) -> None:
        dev = _FakeDev(
            shell_map={"pm list packages": "noise header\npackage:com.a"}
        )
        backend = _backend_with_dev(dev, monkeypatch)
        result = backend.packages("emulator-5554")
        assert result["packages"] == ["com.a"]


# ----------------------------------------------------------------------------
# AdbError passthrough on the lifecycle operations
# ----------------------------------------------------------------------------
class TestAdbErrorPassthrough:
    def test_install_passes_through_an_adb_error(
        self, monkeypatch: MP, tmp_path: Path
    ) -> None:
        apk = _apk_file(tmp_path / "app.apk")
        dev = _FakeDev(install_error=AdbError("invalid_state", "device busy"))
        backend = _backend_with_dev(dev, monkeypatch)
        with pytest.raises(AdbError) as info:
            backend.install("emulator-5554", str(apk))
        assert info.value.code == "invalid_state"

    def test_uninstall_passes_through_an_adb_error(self, monkeypatch: MP) -> None:
        dev = _FakeDev(uninstall_error=AdbError("invalid_state", "device busy"))
        backend = _backend_with_dev(dev, monkeypatch)
        with pytest.raises(AdbError) as info:
            backend.uninstall("emulator-5554", "com.example.app")
        assert info.value.code == "invalid_state"

    def test_current_activity_passes_through_an_adb_error(self, monkeypatch: MP) -> None:
        dev = _FakeDev(app_current_error=AdbError("timeout", "adb timed out"))
        backend = _backend_with_dev(dev, monkeypatch)
        with pytest.raises(AdbError) as info:
            backend.current_activity("emulator-5554")
        assert info.value.code == "timeout"

    def test_screenshot_passes_through_an_adb_error(
        self, monkeypatch: MP, tmp_path: Path
    ) -> None:
        dev = _FakeDev(screenshot_error=AdbError("invalid_state", "no surface"))
        backend = _backend_with_dev(dev, monkeypatch)
        with pytest.raises(AdbError) as info:
            backend.screenshot("emulator-5554", tmp_path / "shot.png")
        assert info.value.code == "invalid_state"


# ----------------------------------------------------------------------------
# pull / push edges
# ----------------------------------------------------------------------------
class TestTransferEdges:
    def test_pull_without_a_sync_api_reports_a_backend_error(
        self, monkeypatch: MP, tmp_path: Path
    ) -> None:
        dev = SimpleNamespace()  # no sync attribute at all
        backend = _backend_with_dev(dev, monkeypatch)
        with pytest.raises(AdbError) as info:
            backend.pull("emulator-5554", "/sdcard/f.bin", tmp_path / "out.bin")
        assert info.value.code == "backend_error"

    def test_pull_passes_through_an_adb_error(
        self, monkeypatch: MP, tmp_path: Path
    ) -> None:
        sync = _Sync(
            stat_error=RuntimeError("no stat"),
            pull_error=AdbError("invalid_state", "device busy"),
        )
        dev = _FakeDev(sync=sync)
        backend = _backend_with_dev(dev, monkeypatch)
        with pytest.raises(AdbError) as info:
            backend.pull("emulator-5554", "/sdcard/f.bin", tmp_path / "out.bin")
        assert info.value.code == "invalid_state"

    def test_pull_refuses_a_file_that_is_only_oversized_after_transfer(
        self, monkeypatch: MP, tmp_path: Path
    ) -> None:
        # No pre-stat (it raised), so the cap is enforced on the pulled bytes.
        monkeypatch.setattr(adb_client, "UNREGISTERED_CAPTURE_MAX_BYTES", 4)
        sync = _Sync(stat_error=RuntimeError("no stat"), pull_writes=b"12345678")
        dev = _FakeDev(sync=sync)
        backend = _backend_with_dev(dev, monkeypatch)
        with pytest.raises(AdbError) as info:
            backend.pull("emulator-5554", "/sdcard/big.bin", tmp_path / "out.bin")
        assert info.value.code == "too_large"

    def test_push_reports_a_stat_failure(
        self, monkeypatch: MP, tmp_path: Path
    ) -> None:
        local = tmp_path / "f.bin"
        local.write_bytes(b"payload")

        def boom_stat(self: Path, *a: Any, **k: Any) -> Any:
            raise OSError("stat blocked")

        monkeypatch.setattr(Path, "is_file", lambda self: True)
        monkeypatch.setattr(Path, "stat", boom_stat)
        dev = _FakeDev()
        backend = _backend_with_dev(dev, monkeypatch)
        with pytest.raises(AdbError) as info:
            backend.push("emulator-5554", str(local), "/sdcard/x")
        assert info.value.code == "backend_error"

    def test_push_passes_through_an_adb_error(
        self, monkeypatch: MP, tmp_path: Path
    ) -> None:
        local = tmp_path / "f.bin"
        local.write_bytes(b"payload")
        dev = _FakeDev(sync=_Sync(push_error=AdbError("invalid_state", "device busy")))
        backend = _backend_with_dev(dev, monkeypatch)
        with pytest.raises(AdbError) as info:
            backend.push("emulator-5554", str(local), "/sdcard/f.bin")
        assert info.value.code == "invalid_state"


# ----------------------------------------------------------------------------
# ensure_frida_server push + late-visibility
# ----------------------------------------------------------------------------
class TestEnsureFridaEdges:
    def test_push_passes_through_an_adb_error(
        self, monkeypatch: MP, tmp_path: Path
    ) -> None:
        binary = tmp_path / "frida-server"
        binary.write_bytes(b"\x7fELF")
        dev = _FakeDev(
            shell_map={"ps -A": "", "ps": ""},
            sync=_Sync(push_error=AdbError("invalid_state", "device busy")),
        )
        backend = _backend_with_dev(dev, monkeypatch)
        with pytest.raises(AdbError) as info:
            backend.ensure_frida_server("emulator-5554", server_binary=str(binary))
        assert info.value.code == "invalid_state"

    def test_push_wraps_a_generic_failure(
        self, monkeypatch: MP, tmp_path: Path
    ) -> None:
        binary = tmp_path / "frida-server"
        binary.write_bytes(b"\x7fELF")
        dev = _FakeDev(
            shell_map={"ps -A": "", "ps": ""},
            sync=_Sync(push_error=RuntimeError("no space")),
        )
        backend = _backend_with_dev(dev, monkeypatch)
        with pytest.raises(AdbError) as info:
            backend.ensure_frida_server("emulator-5554", server_binary=str(binary))
        assert info.value.code == "backend_error"

    def test_reports_running_when_visible_only_after_launch(
        self, monkeypatch: MP
    ) -> None:
        dev = _FakeDev(shell_map={"ps -A": "", "ps": ""})
        state = {"launched": False}
        original = dev.shell

        def stateful(args: str | list[str], timeout: float | None = None) -> str:
            key = args if isinstance(args, str) else " ".join(args)
            if key.startswith("su -c"):
                state["launched"] = True
                return ""
            if key in ("ps -A", "ps") and state["launched"]:
                return "root 1 frida-server"
            return original(args, timeout=timeout)

        monkeypatch.setattr(dev, "shell", stateful)
        backend = _backend_with_dev(dev, monkeypatch)
        result = backend.ensure_frida_server("emulator-5554")
        assert result["running"] is True
        assert result["pushed"] is False


# ----------------------------------------------------------------------------
# forward reserve/release bookkeeping
# ----------------------------------------------------------------------------
class TestForwardBookkeeping:
    def test_forward_passthrough_when_slot_was_already_held(
        self, monkeypatch: MP
    ) -> None:
        # The key is already in the table, so this call reserves nothing and must
        # not remove a slot it did not take when the bind fails.
        dev = _FakeDev(forward_error=AdbError("invalid_state", "device busy"))
        backend = _backend_with_dev(dev, monkeypatch)
        key = ("emulator-5554", "tcp:27042")
        backend._forwards = [key]
        with pytest.raises(AdbError) as info:
            backend.forward("emulator-5554", "tcp:27042", "tcp:27042")
        assert info.value.code == "invalid_state"
        assert backend._forwards == [key]

    def test_forward_generic_failure_keeps_a_held_slot(self, monkeypatch: MP) -> None:
        dev = _FakeDev(forward_error=RuntimeError("bind refused"))
        backend = _backend_with_dev(dev, monkeypatch)
        key = ("emulator-5554", "tcp:27042")
        backend._forwards = [key]
        with pytest.raises(AdbError) as info:
            backend.forward("emulator-5554", "tcp:27042", "tcp:27042")
        assert info.value.code == "backend_error"
        assert backend._forwards == [key]

    def test_release_dedupes_when_rescheduling_a_repeated_forward(
        self, monkeypatch: MP
    ) -> None:
        backend = AdbBackend()
        backend._available = True
        key = ("emulator-5554", "tcp:27042")
        backend._forwards = [key, key]  # a duplicate slipped in
        monkeypatch.setattr(backend, "_device", lambda serial: SimpleNamespace())
        result = backend.release_forwards()
        assert result["count"] == 0
        assert backend._forwards == [key]  # rescheduled once, not twice
