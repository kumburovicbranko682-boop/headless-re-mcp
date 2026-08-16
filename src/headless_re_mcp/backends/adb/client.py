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
from pathlib import Path
from typing import Any

JsonObject = dict[str, Any]

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

    def list_devices(self, offset: int = 0, limit: int = 32) -> JsonObject:
        client = self._client()
        try:
            devices = list(client.device_list())
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"failed to list devices: {exc}") from exc
        # Measured: 200 serials, count=200, 8.3 KiB, no has_more -- and
        # get_state ran for every one before the caller saw a page.
        start = max(0, int(offset))
        cap = min(256, max(1, int(limit)))
        window = devices[start : start + cap]
        items = []
        for dev in window:
            serial = getattr(dev, "serial", "")
            state = "device"
            try:
                state = client.device(serial=serial).get_state()
            except Exception:  # noqa: BLE001
                state = "unknown"
            items.append({"serial": serial, "state": state})
        return {
            "devices": items,
            "count": len(items),
            "total": len(devices),
            "offset": start,
            "has_more": start + len(window) < len(devices),
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

    def properties(self, serial: str, *, limit: int = 500) -> JsonObject:
        dev = self._device(serial)
        try:
            raw = dev.shell("getprop")
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"getprop failed: {exc}") from exc
        cap = max(1, int(limit))
        props: dict[str, str] = {}
        has_more = False
        for line in str(raw).splitlines():
            match = re.match(r"^\[(.+?)\]:\s*\[(.*)\]$", line.strip())
            if not match:
                continue
            if len(props) >= cap:
                # Only set once something was actually left out, so a result
                # that happens to fill the page is not reported as partial.
                has_more = True
                break
            props[match.group(1)] = match.group(2)
        return {"properties": props, "count": len(props), "has_more": has_more}

    def packages(
        self, serial: str, *, third_party_only: bool = False, limit: int = 1000
    ) -> JsonObject:
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
        cap = max(1, int(limit))
        window = pkgs[:cap]
        return {
            "packages": window,
            "count": len(window),
            "has_more": len(pkgs) > cap,
            "third_party_only": third_party_only,
        }

    def install(self, serial: str, apk_path: str, *, reinstall: bool = True) -> JsonObject:
        dev = self._device(serial)
        path = Path(apk_path).expanduser()
        if not path.is_file():
            raise AdbError("not_found", "apk not found", path=str(path))
        try:
            outcome = dev.install(
                str(path), nolaunch=True, uninstall=False, flags=["-r"] if reinstall else []
            )
        except TypeError:
            # Older adbutils signatures accept only the path.
            outcome = dev.install(str(path))
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"install failed: {exc}", path=str(path)) from exc
        # Modern adbutils raises; older ones return the pm line. Measured:
        # "Failure [INSTALL_FAILED_INVALID_APK]" and False both became
        # installed=True, so an unattended agent then launched a package
        # that is not on the device.
        text = "" if outcome is None else str(outcome)
        if outcome is False or "failure" in text.casefold():
            raise AdbError(
                "backend_error",
                f"install failed: {text or 'install returned false'}",
                path=str(path),
            )
        return {"installed": True, "path": str(path), "serial": _check_serial(serial)}

    def uninstall(self, serial: str, package: str) -> JsonObject:
        dev = self._device(serial)
        pkg = _check_package(package)
        try:
            outcome = dev.uninstall(pkg)
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"uninstall failed: {exc}", package=pkg) from exc
        # adbutils returns False when the package was not on the device.
        # Measured: that still became uninstalled=True.
        if outcome is False:
            raise AdbError(
                "backend_error",
                "uninstall failed: package was not installed",
                package=pkg,
            )
        text = "" if outcome is None else str(outcome)
        if "failure" in text.casefold():
            raise AdbError("backend_error", f"uninstall failed: {text}", package=pkg)
        return {"uninstalled": True, "package": pkg}

    def launch(self, serial: str, package: str) -> JsonObject:
        dev = self._device(serial)
        pkg = _check_package(package)
        try:
            raw = dev.shell(["monkey", "-p", pkg, "-c", "android.intent.category.LAUNCHER", "1"])
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"launch failed: {exc}", package=pkg) from exc
        text = str(raw)
        lowered = text.casefold()
        # monkey writes this and still exits 0. Treating the shell returning as
        # launched=True is how an unattended agent then hooks a process that
        # never started.
        if "no activities found" in lowered or "monkey aborted" in lowered:
            raise AdbError(
                "backend_error",
                "launch failed: no launcher activity",
                package=pkg,
                output=text[:2000],
            )
        return {"launched": True, "package": pkg}

    def force_stop(self, serial: str, package: str) -> JsonObject:
        dev = self._device(serial)
        pkg = _check_package(package)
        try:
            # am force-stop exits 0 with empty output even when the package
            # was never installed. Measured: com.no.such.app still became
            # stopped=True, so an unattended agent then traces a process
            # that is not there.
            path_out = str(dev.shell(["pm", "path", pkg]))
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"force-stop failed: {exc}", package=pkg) from exc
        if "package:" not in path_out.casefold():
            raise AdbError(
                "backend_error",
                "force-stop failed: package is not installed",
                package=pkg,
                output=path_out[:2000],
            )
        try:
            dev.shell(["am", "force-stop", pkg])
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"force-stop failed: {exc}", package=pkg) from exc
        return {"stopped": True, "package": pkg}

    def current_activity(self, serial: str) -> JsonObject:
        dev = self._device(serial)
        try:
            current = dev.app_current()
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
            # Ask for one extra so a full page is distinguishable from the
            # end of the buffer. Measured: 600 lines available, limit 200,
            # returned 200 with no has_more -- looked complete.
            raw = dev.shell(["logcat", "-d", "-t", str(capped + 1)])
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"logcat failed: {exc}") from exc
        all_lines = str(raw).splitlines()
        return {
            "lines": all_lines[-capped:],
            "requested": capped,
            "has_more": len(all_lines) > capped,
        }

    def screenshot(self, serial: str, out_path: Path) -> JsonObject:
        dev = self._device(serial)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            image = dev.screenshot()
            image.save(str(out_path))
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"screenshot failed: {exc}") from exc
        # Measured: save() that wrote nothing still returned path, so an
        # unattended agent treats a missing PNG as a captured screen.
        if not out_path.is_file() or out_path.stat().st_size <= 0:
            raise AdbError(
                "backend_error",
                "screenshot produced no image",
                path=str(out_path),
            )
        return {"path": str(out_path), "serial": _check_serial(serial)}

    def pull(self, serial: str, remote_path: str, local_path: Path) -> JsonObject:
        dev = self._device(serial)
        local_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            dev.sync.pull(remote_path, str(local_path))
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"pull failed: {exc}", remote=remote_path) from exc
        # Measured: pull() that wrote nothing still returned local, so an
        # unattended agent treats a missing file as a fetched remote.
        if not local_path.is_file():
            raise AdbError(
                "backend_error",
                "pull produced no file",
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
            dev.sync.push(str(path), remote_path)
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"push failed: {exc}", remote=remote_path) from exc
        # Measured: FakeDev.sync.push wrote nothing, push() still returned
        # remote -- so a caller treats a missing remote as an uploaded file.
        try:
            info = dev.sync.stat(remote_path)
        except Exception as exc:  # noqa: BLE001
            raise AdbError(
                "backend_error",
                "push produced no remote file",
                local=str(path),
                remote=remote_path,
            ) from exc
        if info is None:
            raise AdbError(
                "backend_error",
                "push produced no remote file",
                local=str(path),
                remote=remote_path,
            )
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
        def _is_running() -> bool:
            try:
                return "frida-server" in str(dev.shell("ps -A")) or "frida-server" in str(
                    dev.shell("ps")
                )
            except Exception:  # noqa: BLE001
                return False

        if _is_running():
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
        launch_note = ""
        try:
            # Launch detached under root; bounded so a blocking su prompt cannot hang.
            dev.shell(
                f"su -c 'nohup {remote_path} -l 0.0.0.0:{int(port)} >/dev/null 2>&1 &'",
                timeout=8.0,
            )
        except Exception as exc:  # noqa: BLE001 - a timeout here often means it launched
            launch_note = f"launch attempted; verify manually ({exc})"
        # su returning 0 means the shell accepted the line, not that a server
        # is listening. Measured: ps showed only init and the payload still
        # said running=True.
        if _is_running():
            return {"running": True, "pushed": pushed, "port": port}
        return {
            "running": False,
            "pushed": pushed,
            "port": port,
            "note": launch_note or "frida-server did not appear in ps after launch",
        }

    def forward(self, serial: str, local: str, remote: str) -> JsonObject:
        dev = self._device(serial)
        if not re.match(r"^(tcp:\d{1,5}|localabstract:[\w.\-]+)$", local):
            raise AdbError("invalid_params", "invalid local forward spec", local=local)
        if not re.match(r"^(tcp:\d{1,5}|localabstract:[\w.\-]+|jdwp:\d+)$", remote):
            raise AdbError("invalid_params", "invalid remote forward spec", remote=remote)
        try:
            dev.forward(local, remote)
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"forward failed: {exc}") from exc
        return {"local": local, "remote": remote}
