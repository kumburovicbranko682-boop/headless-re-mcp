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
from headless_re_mcp.core.service_ext import _ensure_repository

JsonObject = dict[str, Any]

# device.screenshot / device.pull write under artifact_root/device/ and never
# register the file: those tools key by serial, and the artifact table needs a
# session_id. Retention therefore never sees them, so the directory itself has
# to be the bound -- device_screenshot / device_pull sweep it with
# prune_capped_dir under the shared UNREGISTERED_CAPTURE_MAX_ENTRIES (32) /
# UNREGISTERED_CAPTURE_MAX_BYTES (64 MiB) caps, which is what enforces both the
# count and the byte ceiling. Measured: 80 screenshots of 256 KiB left 20.0 MiB
# that nothing could reclaim.


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

    def _audit_device(
        self,
        action: str,
        result: Result[JsonObject],
        params: JsonObject,
        *fields: str,
    ) -> None:
        """Record a side-effecting device operation in the global audit log.

        device.* operations are keyed by serial, not a session, so unlike
        apk.* / frida.* / web.* they have no per-session timeline to land in.
        Two groups need a record and used to have none: the mutations (connect,
        install, uninstall, launch, force-stop, push, forward), which are the
        high-stakes changes an operator reviewing an unattended run must be able
        to see; and the captures (pull, screenshot), which write a file under
        artifact_root/device/ that -- because the artifact table needs a
        session_id these ops do not have -- is never registered, so this line
        is the *only* provenance the pulled file or screenshot ever gets. Pure
        reads (info, properties, packages, logcat, current_activity) return data
        and touch nothing, so they are not audited. append_audit takes
        session_id=None for exactly this: a serial-scoped action that belongs in
        the audit trail but owns no session, visible through audit.list's
        unfiltered listing. Best-effort -- an audit write that fails must not
        turn a device operation that already happened into a failed tool call --
        and it copies only the named, structural result fields (serials, package
        ids, verification booleans, ports, capture paths and sizes) which carry
        no secrets; the store redacts regardless. A failed call is still
        recorded, with its error code, the way ui.drive audits both outcomes.
        """
        if result.ok and isinstance(result.data, dict):
            summary: JsonObject = {name: result.data.get(name) for name in fields}
        else:
            summary = {}
            if result.error is not None:
                summary["code"] = result.error.code
        with suppress(Exception):
            _ensure_repository(self).append_audit(
                session_id=None,
                action=action,
                params_summary=params,
                ok=result.ok,
                result_summary=summary,
            )

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
                result = _failure(
                    _as_rpc(
                        AdbError(
                            "backend_error",
                            f"connect failed: {detail}",
                            endpoint=data.get("endpoint") or f"{host}:{port}",
                            result=data.get("result"),
                        )
                    )
                )
        # Audit the final outcome, so a connect that adb reported but that the
        # connected-check downgraded to a failure lands as ok=False, not ok=True.
        self._audit_device(
            "device.connect", result, {"endpoint": f"{host}:{port}"}, "connected", "endpoint"
        )
        return result

    def device_info(self, serial: str) -> Result[JsonObject]:
        return self._adb_wrap("info", serial=serial)

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
        result = self._adb_wrap("install", serial=serial, apk_path=apk_path, reinstall=reinstall)
        self._audit_device(
            "device.install", result, {"serial": serial}, "installed", "package"
        )
        return result

    def device_uninstall(self, serial: str, package: str) -> Result[JsonObject]:
        result = self._adb_wrap("uninstall", serial=serial, package=package)
        self._audit_device(
            "device.uninstall", result, {"serial": serial, "package": package}, "uninstalled"
        )
        return result

    def device_launch(self, serial: str, package: str) -> Result[JsonObject]:
        result = self._adb_wrap("launch", serial=serial, package=package)
        self._audit_device(
            "device.launch", result, {"serial": serial, "package": package}, "launched"
        )
        return result

    def device_force_stop(self, serial: str, package: str) -> Result[JsonObject]:
        result = self._adb_wrap("force_stop", serial=serial, package=package)
        self._audit_device(
            "device.force_stop", result, {"serial": serial, "package": package}, "stopped"
        )
        return result

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
                # The capture hit disk, exceeded the cap and was deleted; the
                # audit below then records the too_large outcome, not a success.
                result = oversized
        prune_capped_dir(
            out.parent,
            max_entries=UNREGISTERED_CAPTURE_MAX_ENTRIES,
            max_bytes=UNREGISTERED_CAPTURE_MAX_BYTES,
        )
        # Screenshots key by serial, so they never enter the artifact table and
        # own no session timeline: this audit line is the only record that a
        # capture happened and where it landed.
        self._audit_device("device.screenshot", result, {"serial": serial}, "path", "size")
        return result

    def device_pull(self, serial: str, remote_path: str) -> Result[JsonObject]:
        out = self._device_artifact_path("pull", _safe_pull_suffix(remote_path))
        result = self._adb_wrap("pull", serial=serial, remote_path=remote_path, local_path=out)
        if result.ok:
            oversized = refuse_oversized_device_file(out)
            if oversized is not None:
                # The file was pulled, exceeded the cap and was deleted; the
                # audit below then records the too_large outcome, not a success.
                result = oversized
        prune_capped_dir(
            out.parent,
            max_entries=UNREGISTERED_CAPTURE_MAX_ENTRIES,
            max_bytes=UNREGISTERED_CAPTURE_MAX_BYTES,
        )
        # Like screenshot, a pulled file never enters the artifact table and has
        # no session timeline, so this is its only provenance: which remote path
        # was read off which device, where it landed locally and how big it was.
        self._audit_device(
            "device.pull", result, {"serial": serial}, "remote", "local", "size"
        )
        return result

    def device_push(
        self, serial: str, local_path: str, remote_path: str
    ) -> Result[JsonObject]:
        result = self._adb_wrap(
            "push", serial=serial, local_path=local_path, remote_path=remote_path
        )
        self._audit_device(
            "device.push", result, {"serial": serial, "remote_path": remote_path}, "remote", "size"
        )
        return result

    def device_forward(self, serial: str, local: str, remote: str) -> Result[JsonObject]:
        result = self._adb_wrap("forward", serial=serial, local=local, remote=remote)
        self._audit_device(
            "device.forward",
            result,
            {"serial": serial, "local": local, "remote": remote},
            "local",
            "remote",
        )
        return result
