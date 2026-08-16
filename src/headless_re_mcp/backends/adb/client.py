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

# A serial is either an emulator/host:port endpoint or a device id. Both are
# constrained so nothing that reaches a shell command can carry metacharacters.
_SERIAL_RE = re.compile(r"^[A-Za-z0-9._:\-]{1,128}$")
_PACKAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$")
_COMPONENT_RE = re.compile(r"^[A-Za-z0-9_.]+/[A-Za-z0-9_.$]+$")
_MAX_LOGCAT_LINES = 5000
# adbutils' shell() waits forever when timeout is omitted. The MCP transport
# parks each call on a 16-thread pool with no deadline of its own, so a wedged
# device (offline, su prompt, hung adbd) holds a slot until it answers -- which
# for an unattended overnight run is never. Sixteen of those and the rest of
# the server stops answering. 30s is long enough for a slow emulator and short
# enough that a stuck pool recovers in minutes, not in the morning.
_SHELL_TIMEOUT = 30.0
# install / pull / push have no timeout argument on the adbutils methods we
# call. A large APK can legitimately outlast a shell snapshot; it cannot
# legitimately last the night.
_TRANSFER_TIMEOUT = 120.0

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


def _is_timeout(exc: BaseException) -> bool:
    if isinstance(exc, TimeoutError):
        return True
    if "timeout" in type(exc).__name__.lower():
        return True
    return "timed out" in str(exc).lower()


def _call_bounded(work: Callable[[], T], *, timeout: float, op: str) -> T:
    """Bound an adbutils call that has no timeout of its own.

    screenshot / install / pull / push / uninstall / app_current / forward
    wait forever when the device is wedged, and so do AdbClient() and
    client.device(). Measured: each was still running after 400ms against a
    client that never answers. The thread started here is a daemon -- we
    cannot interrupt the socket -- but the tool-pool slot is freed, which
    is what keeps the rest of the server answering.
    """
    future: Future[T] = Future()

    def run() -> None:
        if not future.set_running_or_notify_cancel():
            return
        try:
            future.set_result(work())
        except BaseException as exc:  # noqa: BLE001 - handed to the caller
            future.set_exception(exc)

    threading.Thread(target=run, name=f"adb-{op}", daemon=True).start()
    try:
        return future.result(timeout=timeout)
    except FutureTimeout as exc:
        raise AdbError(
            "timeout",
            f"adb {op} timed out after {timeout:g}s",
            timeout=timeout,
            op=op,
        ) from exc


def _shell(dev: Any, cmd: str | list[str], *, timeout: float = _SHELL_TIMEOUT) -> Any:
    """Run one adb shell with a deadline the caller cannot forget."""
    try:
        return dev.shell(cmd, timeout=timeout)
    except AdbError:
        raise
    except Exception as exc:
        if _is_timeout(exc):
            raise AdbError(
                "timeout",
                f"adb shell timed out after {timeout:g}s",
                timeout=timeout,
            ) from exc
        raise


def _frida_server_present(dev: Any) -> bool:
    """True only when a process listing actually names frida-server."""
    try:
        return "frida-server" in str(_shell(dev, "ps -A")) or "frida-server" in str(
            _shell(dev, "ps")
        )
    except AdbError:
        raise
    except Exception:  # noqa: BLE001 - a missing ps is "not running", not a hang
        return False


class AdbBackend:
    def __init__(self, adb_path: Path | None = None) -> None:
        self._adbutils: Any = None
        self._available = False
        self._adb_path = adb_path
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

    def _client(self) -> Any:
        if not self._available or self._adbutils is None:
            raise AdbError("capability_unavailable", "adbutils is not installed")
        if self._adb_path is not None:
            # adbutils honours this env var to find the adb executable and to
            # auto-spawn a server if one is not already running.
            import os

            os.environ.setdefault("ADBUTILS_ADB_PATH", str(self._adb_path))
        try:
            return _call_bounded(
                lambda: self._adbutils.AdbClient(host="127.0.0.1", port=5037),
                timeout=_SHELL_TIMEOUT,
                op="client",
            )
        except AdbError:
            raise
        except Exception as exc:  # noqa: BLE001 - adbutils raises broad types
            raise AdbError("backend_error", f"cannot reach adb server: {exc}") from exc

    def _device(self, serial: str) -> Any:
        client = self._client()
        try:
            return _call_bounded(
                lambda: client.device(serial=_check_serial(serial)),
                timeout=_SHELL_TIMEOUT,
                op="device",
            )
        except AdbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AdbError("not_found", f"device unavailable: {exc}", serial=serial) from exc

    def list_devices(self) -> JsonObject:
        client = self._client()
        try:
            devices = _call_bounded(
                client.device_list, timeout=_SHELL_TIMEOUT, op="device_list"
            )
        except AdbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"failed to list devices: {exc}") from exc
        items = []
        for dev in devices:
            serial = getattr(dev, "serial", "")
            try:
                state = _call_bounded(
                    client.device(serial=serial).get_state,
                    timeout=_SHELL_TIMEOUT,
                    op="get_state",
                )
            except AdbError as exc:
                # One wedged device must not hide the rest of the list.
                state = "timeout" if exc.code == "timeout" else "unknown"
            except Exception:  # noqa: BLE001
                state = "unknown"
            items.append({"serial": serial, "state": str(state)})
        return {"devices": items, "count": len(items)}

    def connect(self, host: str = "127.0.0.1", port: int = 5555) -> JsonObject:
        client = self._client()
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise AdbError("invalid_params", "port must be 1..65535", port=port)
        endpoint = f"{host}:{port}"
        _check_serial(endpoint)
        try:
            message = client.connect(endpoint, timeout=10.0)
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"connect failed: {exc}", endpoint=endpoint) from exc
        text = str(message).lower()
        # adb prints "connected to HOST:PORT" or "already connected to HOST:PORT".
        # Matching the bare word "already" invented success: measured
        # "failed to authenticate: already in use" and "cannot connect:
        # connection already closed" both came back as connected=True.
        connected = "already connected" in text or "connected to" in text
        return {
            "endpoint": endpoint,
            "result": str(message),
            "connected": connected,
        }

    def info(self, serial: str) -> JsonObject:
        dev = self._device(serial)

        def work() -> JsonObject:
            return {
                "serial": _check_serial(serial),
                "state": dev.get_state(),
                "model": dev.prop.model,
                "device": dev.prop.device,
                "sdk": dev.getprop("ro.build.version.sdk"),
                "release": dev.getprop("ro.build.version.release"),
                "abi": dev.getprop("ro.product.cpu.abi"),
            }

        try:
            return _call_bounded(work, timeout=_SHELL_TIMEOUT, op="info")
        except AdbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"failed to read device info: {exc}") from exc

    def properties(self, serial: str, *, limit: int = 500) -> JsonObject:
        dev = self._device(serial)
        try:
            raw = _shell(dev, "getprop")
        except AdbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"getprop failed: {exc}") from exc
        props: dict[str, str] = {}
        for line in str(raw).splitlines():
            match = re.match(r"^\[(.+?)\]:\s*\[(.*)\]$", line.strip())
            if match:
                props[match.group(1)] = match.group(2)
        cap = max(1, int(limit))
        keys = list(props)
        window = {key: props[key] for key in keys[:cap]}
        # Measured: 600 getprop rows came back as count=500 with no total or
        # has_more. The remaining 100 keys vanished, so an agent treats the
        # page as the whole property set.
        return {
            "properties": window,
            "count": len(window),
            "total": len(props),
            "has_more": len(props) > cap,
        }

    def packages(
        self, serial: str, *, third_party_only: bool = False, limit: int = 500
    ) -> JsonObject:
        dev = self._device(serial)
        args = "pm list packages -3" if third_party_only else "pm list packages"
        try:
            raw = _shell(dev, args)
        except AdbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"pm list failed: {exc}") from exc
        pkgs = sorted(
            line.split(":", 1)[1].strip()
            for line in str(raw).splitlines()
            if line.startswith("package:")
        )
        cap = max(1, int(limit))
        window = pkgs[:cap]
        return {
            "packages": window,
            "count": len(window),
            "total": len(pkgs),
            "has_more": len(pkgs) > cap,
            "third_party_only": third_party_only,
        }

    def install(self, serial: str, apk_path: str, *, reinstall: bool = True) -> JsonObject:
        dev = self._device(serial)
        path = Path(apk_path).expanduser()
        if not path.is_file():
            raise AdbError("not_found", "apk not found", path=str(path))
        def work() -> object:
            try:
                return dev.install(
                    str(path), nolaunch=True, uninstall=False, flags=["-r"] if reinstall else []
                )
            except TypeError:
                # Older adbutils signatures accept only the path.
                return dev.install(str(path))

        try:
            outcome = _call_bounded(work, timeout=_TRANSFER_TIMEOUT, op="install")
        except AdbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"install failed: {exc}", path=str(path)) from exc
        # adbutils returns False when pm install failed. Measured: that still
        # came back as installed=True. None is the usual success return.
        if outcome is False:
            raise AdbError("backend_error", "pm install reported failure", path=str(path))
        return {"installed": True, "path": str(path), "serial": _check_serial(serial)}

    def uninstall(self, serial: str, package: str) -> JsonObject:
        dev = self._device(serial)
        pkg = _check_package(package)
        try:
            outcome = _call_bounded(
                lambda: dev.uninstall(pkg), timeout=_SHELL_TIMEOUT, op="uninstall"
            )
        except AdbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"uninstall failed: {exc}", package=pkg) from exc
        # adbutils returns False when the package was not removed. Treating
        # that as uninstalled=True is how an agent concludes the app is gone.
        if outcome is False:
            raise AdbError("backend_error", "uninstall did not remove the package", package=pkg)
        return {"uninstalled": True, "package": pkg}

    def launch(self, serial: str, package: str) -> JsonObject:
        dev = self._device(serial)
        pkg = _check_package(package)
        try:
            raw = _shell(
                dev, ["monkey", "-p", pkg, "-c", "android.intent.category.LAUNCHER", "1"]
            )
        except AdbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"launch failed: {exc}", package=pkg) from exc
        text = str(raw)
        lowered = text.lower()
        # monkey writes these and still exits 0. Measured: "No activities
        # found to run, monkey aborted" and a CRASH line both came back as
        # launched=True.
        if "no activities found" in lowered or "monkey aborted" in lowered:
            raise AdbError(
                "backend_error",
                "launch failed: no launcher activity",
                package=pkg,
            )
        if "crash:" in lowered:
            raise AdbError("backend_error", "launch crashed", package=pkg)
        return {"launched": True, "package": pkg}

    def force_stop(self, serial: str, package: str) -> JsonObject:
        dev = self._device(serial)
        pkg = _check_package(package)
        try:
            raw = _shell(dev, ["am", "force-stop", pkg])
        except AdbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"force-stop failed: {exc}", package=pkg) from exc
        text = str(raw)
        if "error:" in text.lower() or "unknown package" in text.lower():
            raise AdbError(
                "backend_error",
                "force-stop failed",
                package=pkg,
                output=text[:300],
            )
        return {"stopped": True, "package": pkg}

    def current_activity(self, serial: str) -> JsonObject:
        dev = self._device(serial)
        try:
            current = _call_bounded(dev.app_current, timeout=_SHELL_TIMEOUT, op="current_activity")
        except AdbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"failed to read current activity: {exc}") from exc
        return {
            "package": getattr(current, "package", None),
            "activity": getattr(current, "activity", None),
        }

    def logcat(self, serial: str, *, lines: int = 200) -> JsonObject:
        dev = self._device(serial)
        capped = max(1, min(int(lines), _MAX_LOGCAT_LINES))
        try:
            # Ask for one extra line so a full page is distinguishable from
            # the end of the buffer. Measured: 500 lines on the device and
            # requested=200 came back as 200 lines with no has_more.
            raw = _shell(dev, ["logcat", "-d", "-t", str(capped + 1)])
        except AdbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"logcat failed: {exc}") from exc
        collected = str(raw).splitlines()
        return {
            "lines": collected[-capped:],
            "requested": capped,
            "count": min(len(collected), capped),
            "has_more": len(collected) > capped,
        }

    def screenshot(self, serial: str, out_path: Path) -> JsonObject:
        dev = self._device(serial)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        def work() -> None:
            image = dev.screenshot()
            image.save(str(out_path))

        try:
            _call_bounded(work, timeout=_SHELL_TIMEOUT, op="screenshot")
        except AdbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"screenshot failed: {exc}") from exc
        # Measured: a screenshot whose save() wrote nothing still came back
        # as a path. The caller then reads an artifact that does not exist.
        if not out_path.is_file():
            raise AdbError("backend_error", "screenshot did not write an image", path=str(out_path))
        return {"path": str(out_path), "serial": _check_serial(serial)}

    def pull(self, serial: str, remote_path: str, local_path: Path) -> JsonObject:
        dev = self._device(serial)
        local_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            _call_bounded(
                lambda: dev.sync.pull(remote_path, str(local_path)),
                timeout=_TRANSFER_TIMEOUT,
                op="pull",
            )
        except AdbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"pull failed: {exc}", remote=remote_path) from exc
        # Measured: a pull that never created the local file still returned
        # local= that path. The caller then treats the capture as stored.
        if not local_path.is_file():
            raise AdbError(
                "backend_error",
                "pull did not write a local file",
                remote=remote_path,
                local=str(local_path),
            )
        return {"remote": remote_path, "local": str(local_path)}

    def push(self, serial: str, local_path: str, remote_path: str) -> JsonObject:
        dev = self._device(serial)
        path = Path(local_path).expanduser()
        if not path.is_file():
            raise AdbError("not_found", "local file not found", path=str(path))
        try:
            outcome = _call_bounded(
                lambda: dev.sync.push(str(path), remote_path),
                timeout=_TRANSFER_TIMEOUT,
                op="push",
            )
        except AdbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"push failed: {exc}", remote=remote_path) from exc
        # Measured: push returning False still came back as a local/remote
        # pair. An overnight agent then treats the file as on the device.
        if outcome is False:
            raise AdbError("backend_error", "adb push reported failure", remote=remote_path)
        return {"local": str(path), "remote": remote_path}

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
        dev = self._device(serial)
        if not re.match(r"^/[\w./\-]+$", remote_path):
            raise AdbError("invalid_params", "invalid remote_path", remote_path=remote_path)
        if _frida_server_present(dev):
            return {"running": True, "pushed": False, "port": port}
        pushed = False
        if server_binary:
            path = Path(server_binary).expanduser()
            if not path.is_file():
                raise AdbError("not_found", "frida-server binary not found", path=str(path))
            try:
                _call_bounded(
                    lambda: dev.sync.push(str(path), remote_path),
                    timeout=_TRANSFER_TIMEOUT,
                    op="push",
                )
                _shell(dev, ["chmod", "755", remote_path])
                pushed = True
            except AdbError:
                raise
            except Exception as exc:  # noqa: BLE001
                raise AdbError("backend_error", f"failed to push frida-server: {exc}") from exc
        try:
            # Launch detached under root; bounded so a blocking su prompt cannot hang.
            _shell(
                dev,
                f"su -c 'nohup {remote_path} -l 0.0.0.0:{int(port)} >/dev/null 2>&1 &'",
                timeout=8.0,
            )
        except Exception as exc:  # noqa: BLE001 - a timeout here often means it launched
            # Re-check rather than guess. The previous reply was running=None
            # inside a success envelope, and the service then wrote
            # "frida-server ensured" on the timeline. An unattended agent
            # treats that as a started server.
            if _frida_server_present(dev):
                return {"running": True, "pushed": pushed, "port": port}
            raise AdbError(
                "timeout" if _is_timeout(exc) else "backend_error",
                f"frida-server launch did not confirm ({exc})",
                pushed=pushed,
                port=port,
            ) from exc
        # The launch command returning is not the process existing. Measured:
        # `su: not found` and an empty su both came back as running=True, and
        # nothing re-checked ps, so an unattended agent would attach to a
        # server that was never started.
        if not _frida_server_present(dev):
            raise AdbError(
                "backend_error",
                "frida-server did not start",
                pushed=pushed,
                port=port,
            )
        return {"running": True, "pushed": pushed, "port": port}

    def forward(self, serial: str, local: str, remote: str) -> JsonObject:
        dev = self._device(serial)
        if not re.match(r"^(tcp:\d{1,5}|localabstract:[\w.\-]+)$", local):
            raise AdbError("invalid_params", "invalid local forward spec", local=local)
        if not re.match(r"^(tcp:\d{1,5}|localabstract:[\w.\-]+|jdwp:\d+)$", remote):
            raise AdbError("invalid_params", "invalid remote forward spec", remote=remote)
        try:
            outcome = _call_bounded(
                lambda: dev.forward(local, remote), timeout=_SHELL_TIMEOUT, op="forward"
            )
        except AdbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"forward failed: {exc}") from exc
        # Measured: forward returning False still came back as a local/remote
        # pair with no error. An overnight agent then talks through a port
        # that was never forwarded.
        if outcome is False:
            raise AdbError("backend_error", "adb forward reported failure")
        return {"local": local, "remote": remote}
