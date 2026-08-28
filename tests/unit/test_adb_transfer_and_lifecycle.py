"""AdbBackend install/uninstall/pull/push must verify and bound honestly.

Four device operations make a claim a caller acts on and that adb's own return
does not justify:

* ``install`` / ``uninstall`` report a tri-state -- true, false, or null when
  the follow-up ``pm path`` check could not run -- because a zero exit from adb
  is not proof the package is now present or gone.
* ``pull`` / ``push`` guard the 64 MiB capture budget and refuse a directory,
  so a single transfer cannot fill the disk or smuggle a tree onto it.

These paths only run through the live adbutils backend, so they are pinned here
with an injected fake device and real temp files -- no adbutils, no emulator.
"""

from __future__ import annotations

import stat
import zipfile
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError
from headless_re_mcp.core.limits import UNREGISTERED_CAPTURE_MAX_BYTES


class _StatResult:
    def __init__(self, *, mode: int, size: int) -> None:
        self.mode = mode
        self.size = size


class _Sync:
    """A fake adbutils sync channel backed by a real local file."""

    def __init__(self, *, stat_result: _StatResult | None, pull_bytes: bytes = b"data") -> None:
        self._stat = stat_result
        self._pull_bytes = pull_bytes
        self.pushed: tuple[str, str] | None = None

    def stat(self, remote: str, timeout: float | None = None) -> _StatResult:
        del remote, timeout
        if self._stat is None:
            raise RuntimeError("stat unavailable")
        return self._stat

    def pull(self, remote: str, local: str, timeout: float | None = None) -> None:
        del remote, timeout
        Path(local).write_bytes(self._pull_bytes)

    def push(self, local: str, remote: str, timeout: float | None = None) -> None:
        del timeout
        self.pushed = (local, remote)


class _FakeDev:
    """Routes install/uninstall/shell/sync for the lifecycle and transfer tests."""

    def __init__(
        self,
        *,
        pm_path_output: str = "",
        pm_path_raises: bool = False,
        sync: _Sync | None = None,
    ) -> None:
        self._pm_path_output = pm_path_output
        self._pm_path_raises = pm_path_raises
        self.sync = sync
        self.installed: str | None = None
        self.uninstalled: str | None = None

    def install(self, path: str, timeout: float | None = None, **kwargs: Any) -> None:
        del timeout, kwargs
        self.installed = path

    def uninstall(self, package: str, timeout: float | None = None) -> None:
        del timeout
        self.uninstalled = package

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        tokens = tuple(args) if isinstance(args, list) else tuple(str(args).split())
        if tokens[:2] == ("pm", "path"):
            if self._pm_path_raises:
                raise RuntimeError("device stalled")
            return self._pm_path_output
        return ""


def _backend_with(dev: _FakeDev) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: dev  # type: ignore[method-assign]
    return backend


def _apk_with_package(path: Path, package: str | None) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        if package is not None:
            archive.writestr("AndroidManifest.xml", f'<manifest package="{package}"/>')
        else:
            # A valid zip without the manifest: the package id cannot be read.
            archive.writestr("classes.dex", b"\x00")


def test_install_confirms_a_package_pm_path_can_see(tmp_path: Path) -> None:
    """pm path returning a path means the package is installed."""
    apk = tmp_path / "app.apk"
    _apk_with_package(apk, "com.example.app")
    dev = _FakeDev(pm_path_output="package:/data/app/com.example.app/base.apk")
    payload = _backend_with(dev).install("emulator-5554", str(apk), reinstall=True)
    assert payload["installed"] is True
    assert payload["package"] == "com.example.app"
    assert dev.installed == str(apk)


def test_install_reports_false_when_pm_path_cannot_see_it(tmp_path: Path) -> None:
    """A clean adb return but no pm path entry is installed False, not True."""
    apk = tmp_path / "app.apk"
    _apk_with_package(apk, "com.example.app")
    dev = _FakeDev(pm_path_output="")
    payload = _backend_with(dev).install("emulator-5554", str(apk))
    assert payload["installed"] is False
    assert "note" in payload


def test_install_is_null_when_the_package_id_is_unreadable(tmp_path: Path) -> None:
    """No readable package id means installed cannot be verified: null, not true."""
    apk = tmp_path / "nopkg.apk"
    _apk_with_package(apk, None)
    dev = _FakeDev(pm_path_output="package:/whatever")
    payload = _backend_with(dev).install("emulator-5554", str(apk))
    assert payload["installed"] is None
    assert "package" not in payload
    assert "note" in payload


def test_install_is_null_when_verification_cannot_run(tmp_path: Path) -> None:
    """A pm path probe that fails leaves installed null rather than a guess."""
    apk = tmp_path / "app.apk"
    _apk_with_package(apk, "com.example.app")
    dev = _FakeDev(pm_path_raises=True)
    payload = _backend_with(dev).install("emulator-5554", str(apk))
    assert payload["installed"] is None
    assert payload["package"] == "com.example.app"
    assert "note" in payload


def test_install_is_null_when_pm_path_returns_a_host_error(tmp_path: Path) -> None:
    """A host error from pm path is "could not verify", not installed False.

    adbutils can return the adb host's own error line as stdout without raising
    (a device that went offline between install and the pm path check). Reading
    that as "no package: line" reported a real install as installed False; it
    must be null with a note, like a probe that raised.
    """
    apk = tmp_path / "app.apk"
    _apk_with_package(apk, "com.example.app")
    dev = _FakeDev(pm_path_output="error: device offline")
    payload = _backend_with(dev).install("emulator-5554", str(apk))
    assert payload["installed"] is None
    assert payload["package"] == "com.example.app"
    assert "could not verify" in payload.get("note", "")


def test_uninstall_is_null_when_pm_path_returns_a_host_error() -> None:
    """A host error from pm path must not read as a confirmed uninstall.

    The empty-output case means the package is gone (uninstalled True); a host
    error means the verify never ran, so uninstalled is null, not True.
    """
    dev = _FakeDev(pm_path_output="adb: device 'emulator-5554' not found")
    payload = _backend_with(dev).uninstall("emulator-5554", "com.example.app")
    assert payload["uninstalled"] is None
    assert "could not verify" in payload.get("note", "")


def test_install_rejects_a_missing_apk(tmp_path: Path) -> None:
    """A path that is not a file never reaches adb."""
    dev = _FakeDev()
    with pytest.raises(AdbError) as excinfo:
        _backend_with(dev).install("emulator-5554", str(tmp_path / "does-not-exist.apk"))
    assert excinfo.value.code == "not_found"
    assert dev.installed is None


def test_install_rejects_a_non_apk_before_the_device_transfer(tmp_path: Path) -> None:
    """A real file that is not a zip is refused before adb install runs.

    An APK is a zip; ``adb install`` would otherwise push the whole file and let
    ``pm install`` fail with an opaque device error. The precheck turns that into
    a precise invalid_params, and the device install is never reached.
    """
    not_apk = tmp_path / "notes.txt"
    not_apk.write_bytes(b"this is a plain text file, not an apk")
    dev = _FakeDev()
    with pytest.raises(AdbError) as excinfo:
        _backend_with(dev).install("emulator-5554", str(not_apk))
    assert excinfo.value.code == "invalid_params"
    assert dev.installed is None


def test_uninstall_confirms_removal_when_pm_path_is_empty() -> None:
    """pm path returning nothing means the package is gone."""
    dev = _FakeDev(pm_path_output="")
    payload = _backend_with(dev).uninstall("emulator-5554", "com.example.app")
    assert payload["uninstalled"] is True
    assert dev.uninstalled == "com.example.app"


def test_uninstall_reports_false_when_the_package_survives() -> None:
    """A package still visible to pm path is uninstalled False, with a note."""
    dev = _FakeDev(pm_path_output="package:/data/app/com.example.app/base.apk")
    payload = _backend_with(dev).uninstall("emulator-5554", "com.example.app")
    assert payload["uninstalled"] is False
    assert "note" in payload


def test_pull_refuses_a_directory(tmp_path: Path) -> None:
    """A remote directory is refused before any bytes move."""
    sync = _Sync(stat_result=_StatResult(mode=stat.S_IFDIR | 0o755, size=0))
    dev = _FakeDev(sync=sync)
    with pytest.raises(AdbError) as excinfo:
        _backend_with(dev).pull("emulator-5554", "/sdcard/somedir", tmp_path / "pulled_dir")
    assert excinfo.value.code == "invalid_params"


def test_pull_refuses_a_file_over_the_capture_cap(tmp_path: Path) -> None:
    """A remote file whose stat exceeds the cap is refused before transfer."""
    oversize = _StatResult(mode=stat.S_IFREG | 0o644, size=UNREGISTERED_CAPTURE_MAX_BYTES + 1)
    dev = _FakeDev(sync=_Sync(stat_result=oversize))
    local = tmp_path / "too_big"
    with pytest.raises(AdbError) as excinfo:
        _backend_with(dev).pull("emulator-5554", "/sdcard/big.bin", local)
    assert excinfo.value.code == "too_large"
    assert not local.exists()


def test_pull_returns_the_size_on_success(tmp_path: Path) -> None:
    """A small file pulls through and its byte size is reported."""
    sync = _Sync(
        stat_result=_StatResult(mode=stat.S_IFREG | 0o644, size=4),
        pull_bytes=b"data",
    )
    dev = _FakeDev(sync=sync)
    local = tmp_path / "ok.bin"
    payload = _backend_with(dev).pull("emulator-5554", "/sdcard/ok.bin", local)
    assert payload["size"] == 4
    assert payload["remote"] == "/sdcard/ok.bin"
    assert local.read_bytes() == b"data"


def test_pull_refuses_an_empty_file_for_a_non_empty_remote(tmp_path: Path) -> None:
    """A clean pull that writes nothing for a sized remote must not read success.

    The pre-pull stat saw four bytes, but sync.pull left an empty file (the
    remote vanished mid-transfer, or the transfer was cut). Returned as size 0
    the caller opens the empty file as the remote's content; the backend must
    delete it and raise instead.
    """
    sync = _Sync(
        stat_result=_StatResult(mode=stat.S_IFREG | 0o644, size=4),
        pull_bytes=b"",
    )
    dev = _FakeDev(sync=sync)
    local = tmp_path / "short.bin"
    with pytest.raises(AdbError) as excinfo:
        _backend_with(dev).pull("emulator-5554", "/sdcard/short.bin", local)
    assert excinfo.value.code == "backend_error"
    assert "empty local file" in str(excinfo.value)
    assert not local.exists()


def test_pull_allows_a_genuinely_empty_remote(tmp_path: Path) -> None:
    """A remote that stats as zero bytes pulls through as a real empty file.

    The short-pull guard keys off a non-empty remote, so a truly empty file is
    a valid size-0 result the caller can keep, not an interrupted transfer.
    """
    sync = _Sync(
        stat_result=_StatResult(mode=stat.S_IFREG | 0o644, size=0),
        pull_bytes=b"",
    )
    dev = _FakeDev(sync=sync)
    local = tmp_path / "empty.bin"
    payload = _backend_with(dev).pull("emulator-5554", "/sdcard/empty.bin", local)
    assert payload["size"] == 0
    assert local.is_file()


def test_push_rejects_a_missing_local_file(tmp_path: Path) -> None:
    """A local path that is not a file never reaches adb."""
    dev = _FakeDev(sync=_Sync(stat_result=None))
    with pytest.raises(AdbError) as excinfo:
        _backend_with(dev).push("emulator-5554", str(tmp_path / "nope.bin"), "/sdcard/x")
    assert excinfo.value.code == "not_found"


def test_push_refuses_a_local_file_over_the_cap(tmp_path: Path) -> None:
    """A local file over the cap is refused before the transfer starts.

    The file is made sparse with truncate so the test does not write 64 MiB;
    stat still reports the oversize length the guard reads.
    """
    big = tmp_path / "sparse_big.bin"
    with big.open("wb") as handle:
        handle.truncate(UNREGISTERED_CAPTURE_MAX_BYTES + 1)
    sync = _Sync(stat_result=None)
    dev = _FakeDev(sync=sync)
    with pytest.raises(AdbError) as excinfo:
        _backend_with(dev).push("emulator-5554", str(big), "/sdcard/big.bin")
    assert excinfo.value.code == "too_large"
    assert sync.pushed is None


def test_push_returns_the_size_on_success(tmp_path: Path) -> None:
    """A small local file pushes through and reports its size."""
    small = tmp_path / "small.bin"
    small.write_bytes(b"hello")
    sync = _Sync(stat_result=None)
    dev = _FakeDev(sync=sync)
    payload = _backend_with(dev).push("emulator-5554", str(small), "/sdcard/small.bin")
    assert payload["size"] == 5
    assert payload["remote"] == "/sdcard/small.bin"
    assert sync.pushed == (str(small), "/sdcard/small.bin")
