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
_MAX_PACKAGES = 5000
# adbutils.shell has no default deadline. A wedged adb server then parks the
# tool worker until the process dies -- measured: logcat / getprop / pm list
# all passed timeout=None and waited out a 2.5s block in full. Twenty seconds
# is longer than any of these commands need and shorter than the 60s tool
# budget, so a stuck device costs one call, not a thread.
_SHELL_TIMEOUT = 20.0
# sync.push opens a transport with timeout=None. Measured: a 2.5s block was
# waited out in full and still returned success. Sixty seconds is the tool
# budget: a large file can use it, a wedged adb cannot keep the worker.
_PUSH_TIMEOUT = 60.0
_PULL_TIMEOUT = 60.0
# adbutils.install has no timeout and internally pushes then pm install.
# Measured: a 2.5s block was waited out in full and still answered
# installed=True. Three minutes is longer than a normal APK install and
# shorter than an unattended worker parked until the process dies.
_INSTALL_TIMEOUT = 180.0
# adbutils.uninstall has no timeout either. Measured: a 2.5s block was
# waited out in full and still answered uninstalled=True. Sixty seconds
# is longer than a normal pm uninstall and shorter than a parked worker.
_UNINSTALL_TIMEOUT = 60.0

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


def _deadline(fn: Callable[[], T], *, timeout: float) -> T:
    """Run a blocking adbutils call that has no timeout argument.

    The worker is a daemon so a timeout returns to the tool thread; the
    blocked call may still sit on the socket until adbutils' own 600s
    default. That costs a thread, not the worker that serves tools.
    """
    box: list[T] = []
    err: list[BaseException] = []

    def run() -> None:
        try:
            box.append(fn())
        except BaseException as exc:  # noqa: BLE001
            err.append(exc)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        raise AdbError("backend_error", f"adb timed out after {timeout}")
    if err:
        raise err[0]
    return box[0]


def _shell(dev: Any, cmd: str | list[str], *, timeout: float = _SHELL_TIMEOUT) -> str:
    """Run one device shell command with a deadline.

    ``timeout`` is passed through to adbutils; callers that used to omit it
    blocked for as long as the adb server did.
    """
    return str(dev.shell(cmd, timeout=timeout))


def _frida_server_running(dev: Any) -> bool:
    """Whether ``ps`` currently lists a frida-server process.

    A launch command returning is not evidence: ``su`` can print nothing and
    still have started nothing, and a timeout can mean the prompt blocked
    after the process actually started. Only a live listing is ``running``.
    """
    try:
        listing = _shell(dev, "ps -A")
    except Exception:  # noqa: BLE001
        listing = ""
    if "frida-server" in listing:
        return True
    try:
        listing = _shell(dev, "ps")
    except Exception:  # noqa: BLE001
        return False
    return "frida-server" in listing


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

    def list_devices(self, *, limit: int = 32) -> JsonObject:
        client = self._client()
        try:
            # adbutils.device_list talks to the host with no timeout.
            # Measured: a 2.5s block was waited out in full and still
            # returned the listing.
            devices = _deadline(client.device_list, timeout=_SHELL_TIMEOUT)
        except AdbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"failed to list devices: {exc}") from exc
        # device_list() already yields only state=device. A follow-up
        # get_state() per serial used to park the worker: measured 1.2s
        # for three devices whose get_state blocked 0.4s each.
        items = [
            {"serial": getattr(dev, "serial", ""), "state": "device"}
            for dev in devices
        ]
        capped = max(1, min(int(limit), 256))
        window = items[:capped]
        # Measured: 50 devices came back as one page with only count, so an
        # agent that only read the listing treated it as every device.
        return {
            "devices": window,
            "count": len(window),
            "total": len(items),
            "has_more": len(items) > capped,
        }

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
        return {
            "endpoint": endpoint,
            "result": str(message),
            "connected": "connected" in str(message).lower() or "already" in str(message).lower(),
        }

    def info(self, serial: str) -> JsonObject:
        dev = self._device(serial)
        # adbutils getprop / prop.* call shell with no timeout. Measured:
        # those reads waited out 2.4s of blocks in full. They now use
        # _shell. get_state is a host command: measured 2.5s block waited
        # out in full after the getprop path was already bounded.
        try:
            return {
                "serial": _check_serial(serial),
                "state": str(_deadline(dev.get_state, timeout=_SHELL_TIMEOUT)),
                "model": _shell(dev, ["getprop", "ro.product.model"]).strip(),
                "device": _shell(dev, ["getprop", "ro.product.device"]).strip(),
                "sdk": _shell(dev, ["getprop", "ro.build.version.sdk"]).strip(),
                "release": _shell(dev, ["getprop", "ro.build.version.release"]).strip(),
                "abi": _shell(dev, ["getprop", "ro.product.cpu.abi"]).strip(),
            }
        except AdbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"failed to read device info: {exc}") from exc

    def properties(self, serial: str, *, limit: int = 500) -> JsonObject:
        dev = self._device(serial)
        try:
            raw = _shell(dev, "getprop")
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"getprop failed: {exc}") from exc
        parsed: list[tuple[str, str]] = []
        for line in str(raw).splitlines():
            match = re.match(r"^\[(.+?)\]:\s*\[(.*)\]$", line.strip())
            if match:
                parsed.append((match.group(1), match.group(2)))
        capped = max(1, min(int(limit), 2000))
        window = parsed[:capped]
        # The loop used to stop at `limit` and return only count, so a page
        # that filled looked like the whole getprop. Measured: 2000 keys,
        # limit 500, count 500, no has_more.
        return {
            "properties": dict(window),
            "count": len(window),
            "total": len(parsed),
            "has_more": len(parsed) > capped,
        }

    def packages(
        self, serial: str, *, third_party_only: bool = False, limit: int = 500
    ) -> JsonObject:
        dev = self._device(serial)
        args = "pm list packages -3" if third_party_only else "pm list packages"
        try:
            raw = _shell(dev, args)
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"pm list failed: {exc}") from exc
        pkgs = sorted(
            line.split(":", 1)[1].strip()
            for line in str(raw).splitlines()
            if line.startswith("package:")
        )
        capped = max(1, min(int(limit), _MAX_PACKAGES))
        # A full device image can list thousands of packages. Returning all of
        # them looked like "that is every package" and blew the tool result
        # budget. Measured: 8000 names, no cap, no has_more.
        return {
            "packages": pkgs[:capped],
            "count": min(len(pkgs), capped),
            "total": len(pkgs),
            "has_more": len(pkgs) > capped,
            "third_party_only": third_party_only,
        }

    def install(self, serial: str, apk_path: str, *, reinstall: bool = True) -> JsonObject:
        dev = self._device(serial)
        path = Path(apk_path).expanduser()
        if not path.is_file():
            raise AdbError("not_found", "apk not found", path=str(path))
        def _do_install() -> object:
            try:
                return dev.install(
                    str(path), nolaunch=True, uninstall=False, flags=["-r"] if reinstall else []
                )
            except TypeError:
                # Older adbutils signatures accept only the path.
                return dev.install(str(path))

        try:
            raw = _deadline(_do_install, timeout=_INSTALL_TIMEOUT)
        except AdbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"install failed: {exc}", path=str(path)) from exc
        # adbutils.install returns the `pm install` text, not a bool. Older
        # signatures return None. Measured: "Failure [INSTALL_FAILED_INVALID_APK]"
        # still answered installed=True, so an agent treated a rejected APK as
        # present. None/empty is the old success path; a Failure line is not.
        text = "" if raw is None else str(raw)
        if "failure" in text.lower():
            raise AdbError(
                "backend_error",
                "install did not install the package",
                path=str(path),
                installed=False,
                output=text[:800],
            )
        return {"installed": True, "path": str(path), "serial": _check_serial(serial)}

    def uninstall(self, serial: str, package: str) -> JsonObject:
        dev = self._device(serial)
        pkg = _check_package(package)
        try:
            # Measured: a 2.5s block in uninstall() was waited out in full
            # and still answered uninstalled=True. The library call has no
            # timeout argument.
            raw = _deadline(lambda: dev.uninstall(pkg), timeout=_UNINSTALL_TIMEOUT)
        except AdbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"uninstall failed: {exc}", package=pkg) from exc
        # adbutils.uninstall returns the `pm uninstall` text, not a bool.
        # Measured: "Failure [DELETE_FAILED_INTERNAL_ERROR]" still answered
        # uninstalled=True, so an agent treated a missing package as gone.
        text = str(raw or "")
        if "success" not in text.lower():
            raise AdbError(
                "backend_error",
                "uninstall did not remove the package",
                package=pkg,
                uninstalled=False,
                output=text[:800],
            )
        return {"uninstalled": True, "package": pkg}

    def launch(self, serial: str, package: str) -> JsonObject:
        dev = self._device(serial)
        pkg = _check_package(package)
        try:
            raw = _shell(
                dev, ["monkey", "-p", pkg, "-c", "android.intent.category.LAUNCHER", "1"]
            )
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"launch failed: {exc}", package=pkg) from exc
        text = str(raw)
        lowered = text.lower()
        # monkey prints "Events injected: N" on success and "Error" / "aborted"
        # on failure, then returns. Treating a return as launched=True made a
        # missing package look like a running one.
        if "error" in lowered or "aborted" in lowered or "injected" not in lowered:
            raise AdbError(
                "backend_error",
                "launch did not start the package",
                package=pkg,
                launched=False,
                output=text[:800],
            )
        return {"launched": True, "package": pkg}

    def force_stop(self, serial: str, package: str) -> JsonObject:
        dev = self._device(serial)
        pkg = _check_package(package)
        try:
            raw = _shell(dev, ["am", "force-stop", pkg])
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"force-stop failed: {exc}", package=pkg) from exc
        text = str(raw)
        # Measured: "Error type 3\nError: Activity class does not exist."
        # still answered stopped=True. Empty output is the success case;
        # an Error line is not evidence the package was stopped.
        if "error" in text.lower():
            raise AdbError(
                "backend_error",
                "force-stop reported an error",
                package=pkg,
                stopped=False,
                output=text[:800],
            )
        return {"stopped": True, "package": pkg}

    def current_activity(self, serial: str) -> JsonObject:
        dev = self._device(serial)
        try:
            # adbutils.app_current() dumpsys with no timeout. Measured: a
            # 2.5s block was waited out in full and still returned a
            # package/activity pair.
            current = _deadline(dev.app_current, timeout=_SHELL_TIMEOUT)
        except AdbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"failed to read current activity: {exc}") from exc
        # Measured: app_current() returning None still answered
        # {'package': None, 'activity': None} as success, so an agent
        # treated a failed dumpsys as an empty foreground.
        if current is None:
            raise AdbError("backend_error", "no current activity")
        return {
            "package": getattr(current, "package", None),
            "activity": getattr(current, "activity", None),
        }

    def logcat(self, serial: str, *, lines: int = 200) -> JsonObject:
        dev = self._device(serial)
        capped = max(1, min(int(lines), _MAX_LOGCAT_LINES))
        try:
            raw = _shell(dev, ["logcat", "-d", "-t", str(capped)])
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"logcat failed: {exc}") from exc
        text = str(raw)
        return {"lines": text.splitlines()[-capped:], "requested": capped}

    def screenshot(self, serial: str, out_path: Path) -> JsonObject:
        dev = self._device(serial)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        # adbutils.screenshot() calls shell with no timeout (library default
        # 600s) and, on a bad capture, returns a black image. Measured: a
        # 2.5s block was waited out in full and still produced a path.
        try:
            raw = dev.shell(["screencap", "-p"], timeout=_SHELL_TIMEOUT, encoding=None)
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"screenshot failed: {exc}") from exc
        data = bytes(raw) if isinstance(raw, (bytes, bytearray)) else b""
        if not data.startswith(b"\x89PNG"):
            raise AdbError(
                "backend_error",
                "screenshot returned no image",
                bytes=len(data),
            )
        out_path.write_bytes(data)
        return {"path": str(out_path), "serial": _check_serial(serial)}

    def pull(self, serial: str, remote_path: str, local_path: Path) -> JsonObject:
        dev = self._device(serial)
        local_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            # Measured: a 2.5s block in sync.pull was waited out in full and
            # still returned a path. The transport opens with timeout=None.
            _deadline(
                lambda: dev.sync.pull(remote_path, str(local_path)),
                timeout=_PULL_TIMEOUT,
            )
        except AdbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"pull failed: {exc}", remote=remote_path) from exc
        # Measured: a pull that wrote nothing still answered
        # {'remote': ..., 'local': <missing path>}. An agent then treats a
        # missing file as captured evidence.
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
            _deadline(
                lambda: dev.sync.push(str(path), remote_path),
                timeout=_PUSH_TIMEOUT,
            )
        except AdbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"push failed: {exc}", remote=remote_path) from exc
        return {"local": str(path), "remote": remote_path}

    def ensure_frida_server(
        self,
        serial: str,
        *,
        server_binary: str | None = None,
        remote_path: str = "/data/local/tmp/frida-server",
        port: int = 27042,
    ) -> JsonObject:
        """Push and start frida-server on a rooted device/emulator.

        Idempotent: if a frida-server process is already running it does
        nothing. Requires root (su) on the device. ``running: True`` means a
        process was seen in ``ps``, not that a launch command returned.
        """
        dev = self._device(serial)
        if not re.match(r"^/[\w./\-]+$", remote_path):
            raise AdbError("invalid_params", "invalid remote_path", remote_path=remote_path)
        if _frida_server_running(dev):
            return {"running": True, "pushed": False, "port": port}
        pushed = False
        if server_binary:
            path = Path(server_binary).expanduser()
            if not path.is_file():
                raise AdbError("not_found", "frida-server binary not found", path=str(path))
            try:
                # Same unbounded sync.push as device.push. Measured: a 2.5s
                # block was waited out in full before the post-launch ps.
                _deadline(
                    lambda: dev.sync.push(str(path), remote_path),
                    timeout=_PUSH_TIMEOUT,
                )
                _shell(dev, ["chmod", "755", remote_path])
                pushed = True
            except AdbError:
                raise
            except Exception as exc:  # noqa: BLE001
                raise AdbError("backend_error", f"failed to push frida-server: {exc}") from exc
        launch_error: str | None = None
        try:
            # Launch detached under root; bounded so a blocking su prompt cannot hang.
            # A timeout here often means su blocked after the process started, so
            # the verdict is the post-launch ``ps``, not the exception.
            _shell(
                dev,
                f"su -c 'nohup {remote_path} -l 0.0.0.0:{int(port)} >/dev/null 2>&1 &'",
                timeout=8.0,
            )
        except Exception as exc:  # noqa: BLE001
            launch_error = f"{type(exc).__name__}: {exc}"
        if _frida_server_running(dev):
            return {"running": True, "pushed": pushed, "port": port}
        raise AdbError(
            "backend_error",
            "frida-server did not start",
            port=port,
            pushed=pushed,
            running=False,
            **({"launch_error": launch_error} if launch_error else {}),
        )

    def forward(self, serial: str, local: str, remote: str) -> JsonObject:
        dev = self._device(serial)
        if not re.match(r"^(tcp:\d{1,5}|localabstract:[\w.\-]+)$", local):
            raise AdbError("invalid_params", "invalid local forward spec", local=local)
        if not re.match(r"^(tcp:\d{1,5}|localabstract:[\w.\-]+|jdwp:\d+)$", remote):
            raise AdbError("invalid_params", "invalid remote forward spec", remote=remote)
        try:
            # Measured: a 2.5s block in forward() was waited out in full and
            # still returned the mapping. The host command has no timeout.
            _deadline(lambda: dev.forward(local, remote), timeout=_SHELL_TIMEOUT)
        except AdbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"forward failed: {exc}") from exc
        return {"local": local, "remote": remote}
