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


class _OpRaisingDev:
    """A resolved device whose install/uninstall op itself raises.

    Distinct from a device that fails to resolve (that is _device's own
    classification): here the device is in hand and the mutating call fails --
    storage full, an incompatible or policy-blocked package, a mid-transfer
    disconnect -- which is what the op's own except arm must classify.
    """

    def __init__(self, exc: BaseException) -> None:
        self._exc = exc

    def install(self, path: str, timeout: float | None = None, **kwargs: Any) -> None:
        del path, timeout, kwargs
        raise self._exc

    def uninstall(self, package: str, timeout: float | None = None) -> None:
        del package, timeout
        raise self._exc


def test_install_device_failure_is_a_backend_error_not_an_incident(tmp_path: Path) -> None:
    """A failed install is a device outcome (backend_error), not an internal bug.

    adb rejecting the install -- INSUFFICIENT_STORAGE, an incompatible ABI -- is a
    normal, actionable device condition. It must classify as backend_error naming
    the apk, not reach _failure as an internal_error incident telling an agent to
    file a bug.
    """
    apk = tmp_path / "app.apk"
    _apk_with_package(apk, "com.example.app")
    dev = _OpRaisingDev(RuntimeError("INSTALL_FAILED_INSUFFICIENT_STORAGE"))
    with pytest.raises(AdbError) as excinfo:
        _backend_with(dev).install("emulator-5554", str(apk))
    assert excinfo.value.code == "backend_error"
    assert "install failed" in excinfo.value.message
    assert excinfo.value.details.get("path") == str(apk)


def test_install_timeout_stays_a_timeout(tmp_path: Path) -> None:
    """An install that outruns the transfer deadline keeps its timeout code."""
    apk = tmp_path / "app.apk"
    _apk_with_package(apk, "com.example.app")
    dev = _OpRaisingDev(TimeoutError("install timed out"))
    with pytest.raises(AdbError) as excinfo:
        _backend_with(dev).install("emulator-5554", str(apk))
    assert excinfo.value.code == "timeout"


def test_uninstall_device_failure_is_a_backend_error_not_an_incident() -> None:
    dev = _OpRaisingDev(RuntimeError("DELETE_FAILED_DEVICE_POLICY_MANAGER"))
    with pytest.raises(AdbError) as excinfo:
        _backend_with(dev).uninstall("emulator-5554", "com.example.app")
    assert excinfo.value.code == "backend_error"
    assert "uninstall failed" in excinfo.value.message
    assert excinfo.value.details.get("package") == "com.example.app"


def test_uninstall_timeout_stays_a_timeout() -> None:
    dev = _OpRaisingDev(TimeoutError("uninstall timed out"))
    with pytest.raises(AdbError) as excinfo:
        _backend_with(dev).uninstall("emulator-5554", "com.example.app")
    assert excinfo.value.code == "timeout"


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


class _PullSync:
    """A sync whose stat probe 404s and whose pull is scripted by ``writer``.

    The pre-stat in ``pull`` is best-effort -- older adbutils has no ``sync.stat``
    or it raises for a path that is not there -- so this fake raises from stat to
    drive that fallthrough, then hands ``writer`` the local path to decide what
    the transfer left behind: nothing, a directory, or an oversized file. That is
    what makes the post-pull guards (which only run when the pre-stat could not)
    the sole line of defence being exercised here.
    """

    def __init__(self, writer: Any) -> None:
        self._writer = writer
        self.pulled = False

    def stat(self, remote: str, timeout: float | None = None) -> Any:
        del remote, timeout
        raise RuntimeError("stat: no such remote path")

    def pull(self, remote: str, local: str, timeout: float | None = None) -> None:
        del remote, timeout
        self.pulled = True
        self._writer(Path(local))


def test_pull_reports_not_found_when_the_transfer_wrote_nothing(tmp_path: Path) -> None:
    """A remote path that does not exist must not read as a 0-byte success.

    adb sync can report a clean pull yet move no bytes when the remote path is
    absent -- older adbutils does not raise, and the pre-stat probe is
    best-effort. ``capped_file_size`` returns 0 for a missing file, so without
    the explicit check the reply would be a size-0 success a caller opens as a
    real empty file. The transfer is attempted (proving this is the post-pull
    guard, not a pre-stat refusal), then the absent local file becomes not_found
    with the remote path in the details.
    """
    sync = _PullSync(lambda _path: None)
    dev = _FakeDev(sync=sync)
    local = tmp_path / "sub" / "missing.bin"
    with pytest.raises(AdbError) as excinfo:
        _backend_with(dev).pull("emulator-5554", "/sdcard/does-not-exist", local)
    assert excinfo.value.code == "not_found"
    assert excinfo.value.details.get("remote") == "/sdcard/does-not-exist"
    assert sync.pulled is True
    assert not local.exists()


def test_pull_refuses_and_cleans_up_a_directory_the_transfer_created(tmp_path: Path) -> None:
    """A pull that materialises a directory locally is refused, not kept.

    The pre-stat directory check cannot fire when stat is unavailable, so if the
    transfer itself lands a directory at the local path -- adb pulling a remote
    dir despite the best-effort probe -- it must be removed and reported as
    invalid_params rather than left on disk as a bogus "file".
    """
    sync = _PullSync(lambda path: path.mkdir(parents=True, exist_ok=True))
    dev = _FakeDev(sync=sync)
    local = tmp_path / "sub" / "as_dir"
    with pytest.raises(AdbError) as excinfo:
        _backend_with(dev).pull("emulator-5554", "/sdcard/somedir", local)
    assert excinfo.value.code == "invalid_params"
    # The stray directory is torn down, not left behind as a fake result.
    assert not local.exists()


def test_pull_enforces_the_capture_cap_after_the_transfer(tmp_path: Path) -> None:
    """When the pre-stat could not size it, the post-pull cap is the real guard.

    The pre-stat refusal only fires when ``sync.stat`` answered; with stat
    unavailable, an oversized file is caught only after it lands, so the pulled
    file must be refused too_large and removed rather than left occupying the
    capture budget for the life of the process. The local file is made sparse so
    the test does not write 64 MiB; ``capped_file_size`` reads the stat length.
    """

    def _write_oversized(path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("wb") as handle:
            handle.truncate(UNREGISTERED_CAPTURE_MAX_BYTES + 1)

    sync = _PullSync(_write_oversized)
    dev = _FakeDev(sync=sync)
    local = tmp_path / "sub" / "big.bin"
    with pytest.raises(AdbError) as excinfo:
        _backend_with(dev).pull("emulator-5554", "/sdcard/big.bin", local)
    assert excinfo.value.code == "too_large"
    assert excinfo.value.details.get("size") == UNREGISTERED_CAPTURE_MAX_BYTES + 1
    # capped_file_size deletes an over-cap file it was asked to measure.
    assert not local.exists()


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


class _TransferRaisingSync:
    """A sync whose pre-stat passes but whose transfer raises a chosen error.

    stat answers a small regular file so the pre-stat guards in ``pull`` accept
    it; the transfer itself then raises, which is what drives the error-
    classification arms both transfers share. push ignores stat, so the same
    fake serves both.
    """

    def __init__(self, exc: Exception) -> None:
        self._exc = exc
        self.pushed: tuple[str, str] | None = None

    def stat(self, remote: str, timeout: float | None = None) -> _StatResult:
        del remote, timeout
        return _StatResult(mode=stat.S_IFREG | 0o644, size=4)

    def pull(self, remote: str, local: str, timeout: float | None = None) -> None:
        del remote, local, timeout
        raise self._exc

    def push(self, local: str, remote: str, timeout: float | None = None) -> None:
        del local, remote, timeout
        raise self._exc


def test_pull_transfer_failure_is_a_backend_error_not_an_incident(tmp_path: Path) -> None:
    """A device that fails mid-pull is a backend outcome, not a server defect.

    ``dev.sync.pull`` raising a non-timeout error is the device's problem -- a
    reset transport, an unreadable remote file. Uncaught it would reach the
    service envelope as an internal_error incident; the backend classifies it as
    backend_error with the remote path, the same shape as every other adb device
    failure.
    """
    dev = _FakeDev(sync=_TransferRaisingSync(RuntimeError("transport reset")))
    with pytest.raises(AdbError) as excinfo:
        _backend_with(dev).pull("emulator-5554", "/sdcard/ok.bin", tmp_path / "out.bin")
    assert excinfo.value.code == "backend_error"
    assert "pull failed" in excinfo.value.message
    assert excinfo.value.details.get("remote") == "/sdcard/ok.bin"


def test_pull_transfer_timeout_stays_a_timeout(tmp_path: Path) -> None:
    """A transfer that times out keeps the timeout code, not backend_error.

    ``_call`` promotes a timeout-named failure to AdbError('timeout'); pull's
    ``except AdbError`` arm must let that through unchanged rather than fold it
    into the generic backend_error, so a caller can tell "the device is slow"
    from "the device refused".
    """
    dev = _FakeDev(sync=_TransferRaisingSync(RuntimeError("operation timed out")))
    with pytest.raises(AdbError) as excinfo:
        _backend_with(dev).pull("emulator-5554", "/sdcard/ok.bin", tmp_path / "out.bin")
    assert excinfo.value.code == "timeout"


def test_push_transfer_failure_is_a_backend_error_not_an_incident(tmp_path: Path) -> None:
    """A device that fails mid-push is backend_error with the remote path."""
    small = tmp_path / "small.bin"
    small.write_bytes(b"hello")
    dev = _FakeDev(sync=_TransferRaisingSync(RuntimeError("broken pipe")))
    with pytest.raises(AdbError) as excinfo:
        _backend_with(dev).push("emulator-5554", str(small), "/sdcard/small.bin")
    assert excinfo.value.code == "backend_error"
    assert "push failed" in excinfo.value.message
    assert excinfo.value.details.get("remote") == "/sdcard/small.bin"


def test_push_transfer_timeout_stays_a_timeout(tmp_path: Path) -> None:
    """A push that times out keeps the timeout code through the passthrough arm."""
    small = tmp_path / "small.bin"
    small.write_bytes(b"hello")
    dev = _FakeDev(sync=_TransferRaisingSync(RuntimeError("push timed out")))
    with pytest.raises(AdbError) as excinfo:
        _backend_with(dev).push("emulator-5554", str(small), "/sdcard/small.bin")
    assert excinfo.value.code == "timeout"


def test_push_reports_an_unstattable_local_file_as_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A file that exists at the is_file check but cannot be stat'd is backend_error.

    The size guard stats the file right after confirming it exists; a stat that
    fails there -- a permission change or the file vanishing between the two
    calls -- must be a structured backend_error, not an uncaught OSError that
    becomes an internal_error incident. is_file is forced true so only the stat
    failure is exercised.
    """
    monkeypatch.setattr(Path, "is_file", lambda self: True)

    def _raise_stat(self: Path, *args: Any, **kwargs: Any) -> Any:
        raise OSError("stat: permission denied")

    monkeypatch.setattr(Path, "stat", _raise_stat)
    dev = _FakeDev(sync=_Sync(stat_result=None))
    with pytest.raises(AdbError) as excinfo:
        _backend_with(dev).push("emulator-5554", str(tmp_path / "x.bin"), "/sdcard/x")
    assert excinfo.value.code == "backend_error"
    assert "cannot stat local file" in excinfo.value.message
