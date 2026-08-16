"""ADB device-control service methods.

Device enumeration and connection are session-independent (you connect a device
before binding an APK to it). Actions that mutate a device are bounded, named
operations; there is no raw-shell passthrough by design.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from uuid import uuid4

from headless_re_mcp.backends.adb import AdbBackend, AdbError
from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Result
from headless_re_mcp.core.results import _failure, _success
from headless_re_mcp.core.service_ext import _register_capture

JsonObject = dict[str, Any]

# Device tools are session-independent, but the artifact table still needs a
# session key. A reserved id keeps captures listable and reclaimable without
# inventing a fake analysis session.
_DEVICE_CAPTURE_SESSION = "device"


def _as_rpc(exc: AdbError) -> XdbgRpcError:
    return XdbgRpcError(exc.code, exc.message, details=dict(exc.details))


class DeviceAnalysisMixin:
    """Bounded ADB operations exposed as device.* tools."""

    settings: Settings

    def _backend(self) -> AdbBackend:
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
        return self._adb_wrap("connect", host=host, port=port)

    def device_info(self, serial: str) -> Result[JsonObject]:
        return self._adb_wrap("info", serial=serial)

    def device_properties(self, serial: str, limit: int = 500) -> Result[JsonObject]:
        return self._adb_wrap("properties", serial=serial, limit=limit)

    def device_packages(
        self, serial: str, third_party_only: bool = False
    ) -> Result[JsonObject]:
        return self._adb_wrap("packages", serial=serial, third_party_only=third_party_only)

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
        return self._register_device_capture(
            result, out, kind="device_screenshot", source="device.screenshot"
        )

    def device_pull(self, serial: str, remote_path: str) -> Result[JsonObject]:
        out = self._device_artifact_path("pull", Path(remote_path).suffix or ".bin")
        result = self._adb_wrap("pull", serial=serial, remote_path=remote_path, local_path=out)
        return self._register_device_capture(
            result, out, kind="device_pull", source="device.pull"
        )

    def _register_device_capture(
        self,
        result: Result[JsonObject],
        path: Path,
        *,
        kind: str,
        source: str,
    ) -> Result[JsonObject]:
        if not result.ok or result.data is None:
            return result
        data = _register_capture(
            self,
            _DEVICE_CAPTURE_SESSION,
            path,
            kind=kind,
            source=source,
            payload=result.data,
        )
        return _success(data, backend="adb")

    def device_push(
        self, serial: str, local_path: str, remote_path: str
    ) -> Result[JsonObject]:
        return self._adb_wrap("push", serial=serial, local_path=local_path, remote_path=remote_path)

    def device_forward(self, serial: str, local: str, remote: str) -> Result[JsonObject]:
        return self._adb_wrap("forward", serial=serial, local=local, remote=remote)
