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
_FOCUSED_WINDOW_RE = re.compile(
    r"mCurrentFocus=Window\{.*\s+(?P<package>[^\s]+)/(?P<activity>[^\s]+)\}"
)
_RESUMED_ACTIVITY_RE = re.compile(
    r"mResumedActivity: ActivityRecord\{.*?\s+(?P<package>[^\s]+)/(?P<activity>[^\s]+)\s.*?\}"
)

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

    def list_devices(self) -> JsonObject:
        """List devices the adb server already reported.

        A follow-up ``get_state`` per serial used to run with no deadline.
        adbutils ``device_list`` only yields transports already in the
        ``device`` state, so that second hop only held the worker when adb
        had stopped answering. Use the listing; do not ask again.
        """
        client = self._client()
        try:
            devices = client.device_list()
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"failed to list devices: {exc}") from exc
        items = []
        for dev in devices:
            serial = getattr(dev, "serial", "")
            state = getattr(dev, "state", None) or "device"
            items.append({"serial": serial, "state": state})
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
        return {
            "endpoint": endpoint,
            "result": str(message),
            "connected": "connected" in str(message).lower() or "already" in str(message).lower(),
        }

    def info(self, serial: str) -> JsonObject:
        """Read a few well-known properties. Every adb hop is bounded.

        ``get_state`` / ``prop.*`` / ``getprop`` used to be invoked with no
        deadline. Six of those in a row held the worker for the life of the
        process when adb had stopped answering. A successful ``getprop``
        already means the device accepted a shell, so ``state`` is ``device``.
        """
        dev = self._device(serial)
        try:
            raw = dev.shell("getprop", timeout=15.0)
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"failed to read device info: {exc}") from exc
        props: dict[str, str] = {}
        for line in str(raw).splitlines():
            match = re.match(r"^\[(.+?)\]:\s*\[(.*)\]$", line.strip())
            if match:
                props[match.group(1)] = match.group(2)
        return {
            "serial": _check_serial(serial),
            "state": "device",
            "model": props.get("ro.product.model"),
            "device": props.get("ro.product.device"),
            "sdk": props.get("ro.build.version.sdk"),
            "release": props.get("ro.build.version.release"),
            "abi": props.get("ro.product.cpu.abi"),
        }

    def properties(self, serial: str, *, limit: int = 500) -> JsonObject:
        dev = self._device(serial)
        capped = max(1, min(int(limit), 2000))
        try:
            # Bounded: an adb that has stopped answering used to hold the
            # worker forever. Fifteen seconds is enough for getprop.
            raw = dev.shell("getprop", timeout=15.0)
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"getprop failed: {exc}") from exc
        props: dict[str, str] = {}
        total = 0
        for line in str(raw).splitlines():
            match = re.match(r"^\[(.+?)\]:\s*\[(.*)\]$", line.strip())
            if not match:
                continue
            total += 1
            if len(props) < capped:
                props[match.group(1)] = match.group(2)
        return {
            "properties": props,
            "count": len(props),
            "total": total,
            "has_more": total > len(props),
        }

    def packages(
        self, serial: str, *, third_party_only: bool = False, limit: int = 500
    ) -> JsonObject:
        dev = self._device(serial)
        capped = max(1, min(int(limit), 2000))
        args = "pm list packages -3" if third_party_only else "pm list packages"
        try:
            raw = dev.shell(args, timeout=15.0)
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"pm list failed: {exc}") from exc
        pkgs = sorted(
            line.split(":", 1)[1].strip()
            for line in str(raw).splitlines()
            if line.startswith("package:")
        )
        total = len(pkgs)
        page = pkgs[:capped]
        return {
            "packages": page,
            "count": len(page),
            "total": total,
            "has_more": total > len(page),
            "third_party_only": third_party_only,
        }

    def install(self, serial: str, apk_path: str, *, reinstall: bool = True) -> JsonObject:
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

    def uninstall(self, serial: str, package: str) -> JsonObject:
        dev = self._device(serial)
        pkg = _check_package(package)
        try:
            dev.uninstall(pkg)
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"uninstall failed: {exc}", package=pkg) from exc
        return {"uninstalled": True, "package": pkg}

    def launch(self, serial: str, package: str) -> JsonObject:
        """Start the launcher activity. ``launched`` is True only when monkey
        reports that it injected an event — a returned shell is not enough.
        """
        dev = self._device(serial)
        pkg = _check_package(package)
        try:
            raw = dev.shell(
                ["monkey", "-p", pkg, "-c", "android.intent.category.LAUNCHER", "1"],
                timeout=15.0,
            )
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"launch failed: {exc}", package=pkg) from exc
        text = str(raw)
        if "Events injected" in text:
            return {"launched": True, "package": pkg}
        snippet = " ".join(text.split())[:240]
        return {
            "launched": False,
            "package": pkg,
            "note": snippet
            or "monkey returned but did not report Events injected",
        }

    def force_stop(self, serial: str, package: str) -> JsonObject:
        dev = self._device(serial)
        pkg = _check_package(package)
        try:
            dev.shell(["am", "force-stop", pkg], timeout=15.0)
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"force-stop failed: {exc}", package=pkg) from exc
        return {"stopped": True, "package": pkg}

    def current_activity(self, serial: str) -> JsonObject:
        """Read the foreground component. Every dumpsys hop is bounded.

        adbutils ``app_current`` used to run up to three dumpsys commands
        with the library's 600s socket default and retry them. A wedged
        adb held the worker; a large window dump also had no size cap.
        Grep on the device keeps the reply small.
        """
        dev = self._device(serial)
        try:
            focused = str(
                dev.shell("dumpsys window windows | grep mCurrentFocus", timeout=15.0)
            )
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"failed to read current activity: {exc}") from exc
        match = _FOCUSED_WINDOW_RE.search(focused)
        if match:
            return {"package": match.group("package"), "activity": match.group("activity")}
        try:
            resumed = str(
                dev.shell(
                    "dumpsys activity activities | grep mResumedActivity",
                    timeout=15.0,
                )
            )
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"failed to read current activity: {exc}") from exc
        match = _RESUMED_ACTIVITY_RE.search(resumed)
        if match:
            return {"package": match.group("package"), "activity": match.group("activity")}
        return {"package": None, "activity": None}

    def logcat(self, serial: str, *, lines: int = 200) -> JsonObject:
        dev = self._device(serial)
        capped = max(1, min(int(lines), _MAX_LOGCAT_LINES))
        try:
            raw = dev.shell(["logcat", "-d", "-t", str(capped)], timeout=15.0)
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"logcat failed: {exc}") from exc
        text = str(raw)
        return {"lines": text.splitlines()[-capped:], "requested": capped}

    def screenshot(self, serial: str, out_path: Path) -> JsonObject:
        dev = self._device(serial)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            image = dev.screenshot()
            image.save(str(out_path))
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"screenshot failed: {exc}") from exc
        return {"path": str(out_path), "serial": _check_serial(serial)}

    def pull(self, serial: str, remote_path: str, local_path: Path) -> JsonObject:
        dev = self._device(serial)
        local_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            dev.sync.pull(remote_path, str(local_path))
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"pull failed: {exc}", remote=remote_path) from exc
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

        ``running`` is True only when the process is visible in ``ps``
        afterwards. The launch command coming back is not enough: a missing
        binary, a refused su, or a nohup that dies all look like success
        from the shell, and reporting them as running left an unattended
        agent waiting for hooks that never appear.
        """
        dev = self._device(serial)
        if not re.match(r"^/[\w./\-]+$", remote_path):
            raise AdbError("invalid_params", "invalid remote_path", remote_path=remote_path)
        if self._frida_server_visible(dev):
            return {"running": True, "pushed": False, "port": port}
        pushed = False
        if server_binary:
            path = Path(server_binary).expanduser()
            if not path.is_file():
                raise AdbError("not_found", "frida-server binary not found", path=str(path))
            try:
                dev.sync.push(str(path), remote_path)
                dev.shell(["chmod", "755", remote_path], timeout=8.0)
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
        if self._frida_server_visible(dev):
            result: JsonObject = {"running": True, "pushed": pushed, "port": port}
            if launch_note:
                result["note"] = launch_note
            return result
        return {
            "running": False,
            "pushed": pushed,
            "port": port,
            "note": launch_note
            or "launch command returned but frida-server is not in the process list",
        }

    @staticmethod
    def _frida_server_visible(dev: Any) -> bool:
        """True only when ps lists a frida-server process, not when a command ran."""
        for command in ("ps -A", "ps"):
            try:
                listing = str(dev.shell(command, timeout=5.0))
            except Exception:  # noqa: BLE001
                continue
            if "frida-server" in listing:
                return True
        return False

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
