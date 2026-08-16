"""Bounded ADB device control via adbutils.

Deliberately no raw-shell tool: every capability is a named, argument-checked
operation, the same principle as the debugger surface having no
``dynamic.command``. adbutils is optional; a missing module degrades to
``capability_unavailable`` rather than blocking readiness. All identifiers that
reach an internal ``shell`` call are validated against strict patterns so a
package name or serial can never smuggle extra arguments.
"""

from __future__ import annotations

import re
import threading
from collections.abc import Callable
from concurrent.futures import Future
from concurrent.futures import TimeoutError as FutureTimeout
from pathlib import Path
from typing import Any, TypeVar

JsonObject = dict[str, Any]
T = TypeVar("T")

# A wedged adb server used to hold the caller for as long as it stayed wedged.
# connect() already had a timeout; the other named operations did not. Measured
# here: properties() against a shell() that slept 8s returned only after 8.000s
# and was still running at 2s. The deadline lives on this side because adbutils
# honouring timeout= is not something a stuck socket read can be trusted to do.
_ADB_TIMEOUT = 30.0
_ADB_INSTALL_TIMEOUT = 180.0
_ADB_TRANSFER_TIMEOUT = 120.0

# A serial is either an emulator/host:port endpoint or a device id. Both are
# constrained so nothing that reaches a shell command can carry metacharacters.
_SERIAL_RE = re.compile(r"^[A-Za-z0-9._:\-]{1,128}$")
_PACKAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$")
_COMPONENT_RE = re.compile(r"^[A-Za-z0-9_.]+/[A-Za-z0-9_.$]+$")
_MAX_LOGCAT_LINES = 5000

# Well-known local ADB ports for the common Windows emulators, so a caller can
# connect without memorising them.
EMULATOR_PORTS: dict[str, int] = {
    "ldplayer": 5555,
    "mumu": 7555,
    "nox": 62001,
    "memu": 21503,
    "bluestacks": 5555,
    "avd": 5554,
}


class AdbError(RuntimeError):
    def __init__(self, code: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


def _check_serial(serial: str) -> str:
    value = (serial or "").strip()
    if not _SERIAL_RE.match(value):
        raise AdbError("invalid_params", "invalid device serial", serial=serial)
    return value


def _check_package(package: str) -> str:
    value = (package or "").strip()
    if not _PACKAGE_RE.match(value):
        raise AdbError("invalid_params", "invalid package name", package=package)
    return value


class AdbBackend:
    def __init__(self, adb_path: Path | None = None, *, timeout: float | None = None) -> None:
        self._adbutils: Any = None
        self._available = False
        self._adb_path = adb_path
        if timeout is None:
            self._timeout = _ADB_TIMEOUT
            self._install_timeout = _ADB_INSTALL_TIMEOUT
            self._transfer_timeout = _ADB_TRANSFER_TIMEOUT
        else:
            value = float(timeout)
            if value <= 0:
                raise AdbError("invalid_params", "timeout must be positive", timeout=value)
            self._timeout = value
            self._install_timeout = value
            self._transfer_timeout = value
        try:
            import adbutils

            self._adbutils = adbutils
            self._available = True
        except Exception:
            self._adbutils = None
            self._available = False

    @property
    def available(self) -> bool:
        return self._available

    def _call(self, op: str, work: Callable[[], T], *, timeout: float | None = None) -> T:
        """Run one device operation, or return rather than wait it out.

        The thread cannot be interrupted if adb itself is stuck; it is a daemon,
        so it costs the process a thread and nothing else. The caller gets a
        timeout instead of parking a worker for the rest of the process life.
        """
        deadline = self._timeout if timeout is None else timeout
        future: Future[T] = Future()

        def run() -> None:
            try:
                future.set_result(work())
            except BaseException as exc:  # noqa: BLE001 - handed to the caller
                if not future.done():
                    future.set_exception(exc)

        threading.Thread(target=run, name=f"adb-{op}", daemon=True).start()
        try:
            return future.result(timeout=deadline)
        except FutureTimeout as exc:
            raise AdbError(
                "timeout",
                f"{op} did not finish within {deadline:g}s",
                op=op,
                timeout=deadline,
            ) from exc

    def _client(self) -> Any:
        if not self._available or self._adbutils is None:
            raise AdbError("capability_unavailable", "adbutils is not installed")
        if self._adb_path is not None:
            # adbutils honours this env var to find the adb executable and to
            # auto-spawn a server if one is not already running.
            import os

            os.environ.setdefault("ADBUTILS_ADB_PATH", str(self._adb_path))
        try:
            return self._adbutils.AdbClient(host="127.0.0.1", port=5037)
        except Exception as exc:  # noqa: BLE001 - adbutils raises broad types
            raise AdbError("backend_error", f"cannot reach adb server: {exc}") from exc

    def _device(self, serial: str) -> Any:
        client = self._client()
        try:
            return client.device(serial=_check_serial(serial))
        except AdbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AdbError("not_found", f"device unavailable: {exc}", serial=serial) from exc

    def list_devices(self) -> JsonObject:
        def work() -> JsonObject:
            client = self._client()
            try:
                devices = client.device_list()
            except Exception as exc:  # noqa: BLE001
                raise AdbError("backend_error", f"failed to list devices: {exc}") from exc
            items = []
            for dev in devices:
                serial = getattr(dev, "serial", "")
                state = "device"
                try:
                    state = client.device(serial=serial).get_state()
                except Exception:  # noqa: BLE001
                    state = "unknown"
                items.append({"serial": serial, "state": state})
            return {"devices": items, "count": len(items)}

        return self._call("list_devices", work)

    def connect(self, host: str = "127.0.0.1", port: int = 5555) -> JsonObject:
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise AdbError("invalid_params", "port must be 1..65535", port=port)
        endpoint = f"{host}:{port}"
        _check_serial(endpoint)

        def work() -> JsonObject:
            client = self._client()
            try:
                message = client.connect(endpoint, timeout=min(10.0, self._timeout))
            except Exception as exc:  # noqa: BLE001
                raise AdbError(
                    "backend_error", f"connect failed: {exc}", endpoint=endpoint
                ) from exc
            return {
                "endpoint": endpoint,
                "result": str(message),
                "connected": "connected" in str(message).lower()
                or "already" in str(message).lower(),
            }

        return self._call("connect", work)

    def info(self, serial: str) -> JsonObject:
        def work() -> JsonObject:
            dev = self._device(serial)
            try:
                return {
                    "serial": _check_serial(serial),
                    "state": dev.get_state(),
                    "model": dev.prop.model,
                    "device": dev.prop.device,
                    "sdk": dev.getprop("ro.build.version.sdk"),
                    "release": dev.getprop("ro.build.version.release"),
                    "abi": dev.getprop("ro.product.cpu.abi"),
                }
            except Exception as exc:  # noqa: BLE001
                raise AdbError("backend_error", f"failed to read device info: {exc}") from exc

        return self._call("info", work)

    def properties(self, serial: str, *, limit: int = 500) -> JsonObject:
        def work() -> JsonObject:
            dev = self._device(serial)
            try:
                raw = dev.shell("getprop")
            except Exception as exc:  # noqa: BLE001
                raise AdbError("backend_error", f"getprop failed: {exc}") from exc
            props: dict[str, str] = {}
            for line in str(raw).splitlines():
                match = re.match(r"^\[(.+?)\]:\s*\[(.*)\]$", line.strip())
                if match:
                    props[match.group(1)] = match.group(2)
                if len(props) >= limit:
                    break
            return {"properties": props, "count": len(props)}

        return self._call("properties", work)

    def packages(self, serial: str, *, third_party_only: bool = False) -> JsonObject:
        def work() -> JsonObject:
            dev = self._device(serial)
            args = "pm list packages -3" if third_party_only else "pm list packages"
            try:
                raw = dev.shell(args)
            except Exception as exc:  # noqa: BLE001
                raise AdbError("backend_error", f"pm list failed: {exc}") from exc
            pkgs = sorted(
                line.split(":", 1)[1].strip()
                for line in str(raw).splitlines()
                if line.startswith("package:")
            )
            return {"packages": pkgs, "count": len(pkgs), "third_party_only": third_party_only}

        return self._call("packages", work)

    def install(self, serial: str, apk_path: str, *, reinstall: bool = True) -> JsonObject:
        def work() -> JsonObject:
            dev = self._device(serial)
            path = Path(apk_path).expanduser()
            if not path.is_file():
                raise AdbError("not_found", "apk not found", path=str(path))
            try:
                dev.install(
                    str(path), nolaunch=True, uninstall=False, flags=["-r"] if reinstall else []
                )
            except TypeError:
                # Older adbutils signatures accept only the path.
                dev.install(str(path))
            except Exception as exc:  # noqa: BLE001
                raise AdbError("backend_error", f"install failed: {exc}", path=str(path)) from exc
            return {"installed": True, "path": str(path), "serial": _check_serial(serial)}

        return self._call("install", work, timeout=self._install_timeout)

    def uninstall(self, serial: str, package: str) -> JsonObject:
        def work() -> JsonObject:
            dev = self._device(serial)
            pkg = _check_package(package)
            try:
                dev.uninstall(pkg)
            except Exception as exc:  # noqa: BLE001
                raise AdbError("backend_error", f"uninstall failed: {exc}", package=pkg) from exc
            return {"uninstalled": True, "package": pkg}

        return self._call("uninstall", work)

    def launch(self, serial: str, package: str) -> JsonObject:
        def work() -> JsonObject:
            dev = self._device(serial)
            pkg = _check_package(package)
            try:
                dev.shell(["monkey", "-p", pkg, "-c", "android.intent.category.LAUNCHER", "1"])
            except Exception as exc:  # noqa: BLE001
                raise AdbError("backend_error", f"launch failed: {exc}", package=pkg) from exc
            return {"launched": True, "package": pkg}

        return self._call("launch", work)

    def force_stop(self, serial: str, package: str) -> JsonObject:
        def work() -> JsonObject:
            dev = self._device(serial)
            pkg = _check_package(package)
            try:
                dev.shell(["am", "force-stop", pkg])
            except Exception as exc:  # noqa: BLE001
                raise AdbError("backend_error", f"force-stop failed: {exc}", package=pkg) from exc
            return {"stopped": True, "package": pkg}

        return self._call("force_stop", work)

    def current_activity(self, serial: str) -> JsonObject:
        def work() -> JsonObject:
            dev = self._device(serial)
            try:
                current = dev.app_current()
            except Exception as exc:  # noqa: BLE001
                raise AdbError("backend_error", f"failed to read current activity: {exc}") from exc
            return {
                "package": getattr(current, "package", None),
                "activity": getattr(current, "activity", None),
            }

        return self._call("current_activity", work)

    def logcat(self, serial: str, *, lines: int = 200) -> JsonObject:
        def work() -> JsonObject:
            dev = self._device(serial)
            capped = max(1, min(int(lines), _MAX_LOGCAT_LINES))
            try:
                raw = dev.shell(["logcat", "-d", "-t", str(capped)])
            except Exception as exc:  # noqa: BLE001
                raise AdbError("backend_error", f"logcat failed: {exc}") from exc
            text = str(raw)
            return {"lines": text.splitlines()[-capped:], "requested": capped}

        return self._call("logcat", work)

    def screenshot(self, serial: str, out_path: Path) -> JsonObject:
        def work() -> JsonObject:
            dev = self._device(serial)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                image = dev.screenshot()
                image.save(str(out_path))
            except Exception as exc:  # noqa: BLE001
                raise AdbError("backend_error", f"screenshot failed: {exc}") from exc
            return {"path": str(out_path), "serial": _check_serial(serial)}

        return self._call("screenshot", work)

    def pull(self, serial: str, remote_path: str, local_path: Path) -> JsonObject:
        def work() -> JsonObject:
            dev = self._device(serial)
            local_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                dev.sync.pull(remote_path, str(local_path))
            except Exception as exc:  # noqa: BLE001
                raise AdbError("backend_error", f"pull failed: {exc}", remote=remote_path) from exc
            return {"remote": remote_path, "local": str(local_path)}

        return self._call("pull", work, timeout=self._transfer_timeout)

    def push(self, serial: str, local_path: str, remote_path: str) -> JsonObject:
        def work() -> JsonObject:
            dev = self._device(serial)
            path = Path(local_path).expanduser()
            if not path.is_file():
                raise AdbError("not_found", "local file not found", path=str(path))
            try:
                dev.sync.push(str(path), remote_path)
            except Exception as exc:  # noqa: BLE001
                raise AdbError("backend_error", f"push failed: {exc}", remote=remote_path) from exc
            return {"local": str(path), "remote": remote_path}

        return self._call("push", work, timeout=self._transfer_timeout)

    def ensure_frida_server(
        self,
        serial: str,
        *,
        server_binary: str | None = None,
        remote_path: str = "/data/local/tmp/frida-server",
        port: int = 27042,
    ) -> JsonObject:
        """Best-effort: push and start frida-server on a rooted device/emulator.

        Idempotent-ish: if a frida-server process is already running it does
        nothing. Requires root (su) on the device; failures surface as
        structured errors rather than exceptions.
        """
        if not re.match(r"^/[\w./\-]+$", remote_path):
            raise AdbError("invalid_params", "invalid remote_path", remote_path=remote_path)

        def work() -> JsonObject:
            dev = self._device(serial)
            try:
                running = "frida-server" in str(dev.shell("ps -A")) or "frida-server" in str(
                    dev.shell("ps")
                )
            except Exception:  # noqa: BLE001
                running = False
            if running:
                return {"running": True, "pushed": False, "port": port}
            pushed = False
            if server_binary:
                path = Path(server_binary).expanduser()
                if not path.is_file():
                    raise AdbError("not_found", "frida-server binary not found", path=str(path))
                try:
                    dev.sync.push(str(path), remote_path)
                    dev.shell(["chmod", "755", remote_path])
                    pushed = True
                except Exception as exc:  # noqa: BLE001
                    raise AdbError("backend_error", f"failed to push frida-server: {exc}") from exc
            try:
                # Launch detached under root; bounded so a blocking su prompt cannot hang.
                dev.shell(
                    f"su -c 'nohup {remote_path} -l 0.0.0.0:{int(port)} >/dev/null 2>&1 &'",
                    timeout=min(8.0, self._timeout),
                )
            except Exception as exc:  # noqa: BLE001 - a timeout here often means it launched
                return {
                    "running": None,
                    "pushed": pushed,
                    "port": port,
                    "note": f"launch attempted; verify manually ({exc})",
                }
            return {"running": True, "pushed": pushed, "port": port}

        return self._call("ensure_frida_server", work)

    def forward(self, serial: str, local: str, remote: str) -> JsonObject:
        if not re.match(r"^(tcp:\d{1,5}|localabstract:[\w.\-]+)$", local):
            raise AdbError("invalid_params", "invalid local forward spec", local=local)
        if not re.match(r"^(tcp:\d{1,5}|localabstract:[\w.\-]+|jdwp:\d+)$", remote):
            raise AdbError("invalid_params", "invalid remote forward spec", remote=remote)

        def work() -> JsonObject:
            dev = self._device(serial)
            try:
                dev.forward(local, remote)
            except Exception as exc:  # noqa: BLE001
                raise AdbError("backend_error", f"forward failed: {exc}") from exc
            return {"local": local, "remote": remote}

        return self._call("forward", work)
