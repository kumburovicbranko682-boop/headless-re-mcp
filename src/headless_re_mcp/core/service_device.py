"""ADB device-control service methods.

Device enumeration and connection are session-independent (you connect a device
before binding an APK to it). Actions that mutate a device are bounded, named
operations; there is no raw-shell passthrough by design.
"""

from __future__ import annotations

from contextlib import suppress
from pathlib import Path, PurePosixPath
from typing import Any
from uuid import uuid4

from headless_re_mcp.backends.adb import AdbBackend, AdbError
from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.limits import (
    MAX_MODULE_DUMP_BYTES,
    UNREGISTERED_CAPTURE_MAX_BYTES,
    UNREGISTERED_CAPTURE_MAX_ENTRIES,
    prune_capped_dir,
)
from headless_re_mcp.core.models import Result, RpcError
from headless_re_mcp.core.results import _failure, _success

JsonObject = dict[str, Any]

# device.screenshot / device.pull write under artifact_root/device/ and never
# register the file: those tools key by serial, and the artifact table needs a
# session_id. Retention therefore never sees them. Measured: 80 screenshots of
# 256 KiB left 20.0 MiB that nothing could reclaim.
_MAX_DEVICE_ARTIFACTS = 32


def _safe_pull_suffix(remote_path: str) -> str:
    """Keep a short portable extension, never a local path or NTFS stream."""
    suffix = PurePosixPath(remote_path).suffix
    extension = suffix[1:]
    if (
        suffix.startswith(".")
        and 1 <= len(extension) <= 16
        and extension.isascii()
        and extension.isalnum()
    ):
        return suffix
    return ".bin"


def prune_device_artifacts(directory: Path, *, keep: int = _MAX_DEVICE_ARTIFACTS) -> None:
    """Drop the oldest device captures once the directory is full."""
    try:
        files = [path for path in directory.iterdir() if path.is_file()]
    except OSError:
        return
    extra = len(files) - max(0, keep)
    if extra <= 0:
        return

    def _mtime(path: Path) -> int:
        try:
            return path.stat().st_mtime_ns
        except OSError:
            return 0

    files.sort(key=_mtime)
    for stale in files[:extra]:
        with suppress(OSError):
            stale.unlink()


def refuse_oversized_device_file(
    path: Path, *, limit: int = MAX_MODULE_DUMP_BYTES
) -> Result[JsonObject] | None:
    """Delete a capture that is larger than one module dump and say so.

    The directory bound is a count. 32 unbounded pulls is still unbounded
    bytes. The transfer itself cannot be stopped mid-stream -- adbutils
    writes the whole file -- so this is after the fact: the bytes hit disk,
    then they are removed and the caller is told.
    """
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size <= limit:
        return None
    with suppress(OSError):
        path.unlink()
    return Result[JsonObject](
        ok=False,
        error=RpcError(
            code="output_too_large",
            message=(
                f"device file is {size} bytes, over the {limit} byte limit; "
                "pull a smaller path"
            ),
            details={"path": str(path), "size": size, "limit": limit},
        ),
    )


def _as_rpc(exc: AdbError) -> XdbgRpcError:
    return XdbgRpcError(exc.code, exc.message, details=dict(exc.details))


class DeviceAnalysisMixin:
    """Bounded ADB operations exposed as device.* tools."""

    settings: Settings
    # Owned by AnalysisService so forwards created here can be removed on
    # close_all. Constructing a backend per call would forget every forward.
    _adb_backend: AdbBackend

    def _backend(self) -> AdbBackend:
        owned = getattr(self, "_adb_backend", None)
        if isinstance(owned, AdbBackend):
            return owned
        return AdbBackend(getattr(self.settings, "adb", None))

    def _device_artifact_path(self, name: str, suffix: str) -> Path:
        root = self.settings.artifact_root.expanduser().resolve() / "device"
        root.mkdir(parents=True, exist_ok=True)
        return root / f"{name}-{uuid4().hex}{suffix}"

    def _adb_wrap(self, op: str, /, **kwargs: Any) -> Result[JsonObject]:
        try:
            method = getattr(self._backend(), op)
            data = method(**kwargs)
            return _success(data, backend="adb")
        except AdbError as exc:
            return _failure(_as_rpc(exc))
        except BaseException as exc:
            return _failure(exc)

    def device_list(self) -> Result[JsonObject]:
        return self._adb_wrap("list_devices")

    def device_connect(self, host: str = "127.0.0.1", port: int = 5555) -> Result[JsonObject]:
        result = self._adb_wrap("connect", host=host, port=port)
        if result.ok:
            data = result.data if isinstance(result.data, dict) else {}
            if not data.get("connected"):
                # adbutils returns a status string and does not raise. The
                # client used to pass that through as an ok envelope with
                # connected false, so a caller that only reads ok then
                # installed onto a device that was never there.
                detail = data.get("result") or "adb reported no connection"
                return _failure(
                    _as_rpc(
                        AdbError(
                            "backend_error",
                            f"connect failed: {detail}",
                            endpoint=data.get("endpoint") or f"{host}:{port}",
                            result=data.get("result"),
                        )
                    )
                )
        return result

    def device_info(self, serial: str) -> Result[JsonObject]:
        return self._adb_wrap("info", serial=serial)

    def device_uptime(self, serial: str) -> Result[JsonObject]:
        return self._adb_wrap("uptime", serial=serial)

    def device_properties(self, serial: str, limit: int = 500) -> Result[JsonObject]:
        return self._adb_wrap("properties", serial=serial, limit=limit)

    def device_packages(
        self, serial: str, third_party_only: bool = False, limit: int = 500
    ) -> Result[JsonObject]:
        return self._adb_wrap(
            "packages", serial=serial, third_party_only=third_party_only, limit=limit
        )

    def device_install(
        self, serial: str, apk_path: str, reinstall: bool = True
    ) -> Result[JsonObject]:
        return self._adb_wrap("install", serial=serial, apk_path=apk_path, reinstall=reinstall)

    def device_uninstall(self, serial: str, package: str) -> Result[JsonObject]:
        return self._adb_wrap("uninstall", serial=serial, package=package)

    def device_launch(self, serial: str, package: str) -> Result[JsonObject]:
        return self._adb_wrap("launch", serial=serial, package=package)

    def device_force_stop(self, serial: str, package: str) -> Result[JsonObject]:
        return self._adb_wrap("force_stop", serial=serial, package=package)

    def device_current_activity(self, serial: str) -> Result[JsonObject]:
        return self._adb_wrap("current_activity", serial=serial)

    def device_logcat(self, serial: str, lines: int = 200) -> Result[JsonObject]:
        return self._adb_wrap("logcat", serial=serial, lines=lines)

    def device_screenshot(self, serial: str) -> Result[JsonObject]:
        out = self._device_artifact_path("screenshot", ".png")
        result = self._adb_wrap("screenshot", serial=serial, out_path=out)
        if result.ok:
            oversized = refuse_oversized_device_file(out)
            if oversized is not None:
                prune_capped_dir(
                    out.parent,
                    max_entries=UNREGISTERED_CAPTURE_MAX_ENTRIES,
                    max_bytes=UNREGISTERED_CAPTURE_MAX_BYTES,
                )
                return oversized
        prune_capped_dir(
            out.parent,
            max_entries=UNREGISTERED_CAPTURE_MAX_ENTRIES,
            max_bytes=UNREGISTERED_CAPTURE_MAX_BYTES,
        )
        return result

    def device_pull(self, serial: str, remote_path: str) -> Result[JsonObject]:
        out = self._device_artifact_path("pull", _safe_pull_suffix(remote_path))
        result = self._adb_wrap("pull", serial=serial, remote_path=remote_path, local_path=out)
        if result.ok:
            oversized = refuse_oversized_device_file(out)
            if oversized is not None:
                prune_capped_dir(
                    out.parent,
                    max_entries=UNREGISTERED_CAPTURE_MAX_ENTRIES,
                    max_bytes=UNREGISTERED_CAPTURE_MAX_BYTES,
                )
                return oversized
        prune_capped_dir(
            out.parent,
            max_entries=UNREGISTERED_CAPTURE_MAX_ENTRIES,
            max_bytes=UNREGISTERED_CAPTURE_MAX_BYTES,
        )
        return result

    def device_push(
        self, serial: str, local_path: str, remote_path: str
    ) -> Result[JsonObject]:
        return self._adb_wrap("push", serial=serial, local_path=local_path, remote_path=remote_path)

    def device_forward(self, serial: str, local: str, remote: str) -> Result[JsonObject]:
        return self._adb_wrap("forward", serial=serial, local=local, remote=remote)
