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
import shutil
import stat
import threading
import zipfile
from contextlib import suppress
from inspect import Parameter, signature
from pathlib import Path
from typing import Any

from headless_re_mcp.core.limits import UNREGISTERED_CAPTURE_MAX_BYTES, capped_file_size

JsonObject = dict[str, Any]

# A serial is either an emulator/host:port endpoint or a device id. Both are
# constrained so nothing that reaches a shell command can carry metacharacters.
_SERIAL_RE = re.compile(r"^[A-Za-z0-9._:\-]{1,128}$")
_PACKAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$")
_MAX_LOGCAT_LINES = 5000
_MAX_LOGCAT_CHARS = 200_000
# logcat priority letters, ascending; a min_priority filterspec is *:<letter>.
_LOGCAT_PRIORITIES = ("V", "D", "I", "W", "E", "F")
_MAX_PACKAGES = 2000
_MAX_PROPERTIES = 2000
# An app installed from an app bundle splits into a base plus per-density,
# per-language and per-ABI config APKs. A real app has a handful; cap the list
# so a device that reports a pathological number cannot grow the answer without
# bound (paths_truncated when hit).
_MAX_PACKAGE_PATHS = 64
# A device runs a few hundred processes; cap the collection so a device that
# reports a pathological number (or a wedged ps that never stops) cannot grow
# the answer without bound (collection_truncated when hit).
_MAX_PROCESSES = 8192
_MAX_PROCESSES_PAGE = 2000
# device.ls lists a directory over the adb sync protocol. A real directory holds
# at most a few hundred entries; cap the collection so a pathological one cannot
# grow the answer without bound (collection_truncated when hit), and page it.
_MAX_LS_ENTRIES = 4096
_MAX_LS_PAGE = 1000
_REMOTE_PATH_MAX = 4096
_MAX_DEVICES = 64
# Only the head of AndroidManifest.xml is scanned for a package id, and it is
# read as a bounded stream so a decompression-bomb manifest cannot OOM install().
_MANIFEST_SCAN_BYTES = 64 * 1024
# adb forwards live on the adb server until removed. A loop that binds a new
# local port every call would otherwise accumulate until the server refuses.
_MAX_FORWARDS = 32
# adbutils shell/sync calls otherwise wait forever when the device stalls.
_ADB_SHELL_TIMEOUT_S = 30.0
_ADB_PROBE_TIMEOUT_S = 8.0
_ADB_TRANSFER_TIMEOUT_S = 120.0
# adbutils open_transport defaults to 600s. That is a hang, not a deadline.
_ADB_TRANSPORT_TIMEOUT_S = _ADB_TRANSFER_TIMEOUT_S
_PACKAGE_IN_TEXT = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+){1,10}")

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
    name = type(exc).__name__.lower()
    return "timeout" in name or "timed out" in str(exc).lower()


def _accepts_timeout(func: Any) -> bool:
    """Whether ``timeout`` can be passed without catching TypeError from the body."""
    target = getattr(func, "__func__", func)
    try:
        params = signature(target).parameters
    except (TypeError, ValueError):
        return False
    return "timeout" in params or any(p.kind is Parameter.VAR_KEYWORD for p in params.values())


def _accepted_kwargs(func: Any, extra: dict[str, Any]) -> dict[str, Any]:
    target = getattr(func, "__func__", func)
    try:
        params = signature(target).parameters
    except (TypeError, ValueError):
        return {}
    if any(p.kind is Parameter.VAR_KEYWORD for p in params.values()):
        return extra
    return {key: value for key, value in extra.items() if key in params}


def _device_shell(dev: Any, args: str | list[str], *, timeout: float = _ADB_SHELL_TIMEOUT_S) -> str:
    """Call ``device.shell`` with a deadline, including older adbutils."""
    try:
        raw = (
            dev.shell(args, timeout=timeout) if _accepts_timeout(dev.shell) else dev.shell(args)
        )
    except AdbError:
        raise
    except Exception as exc:  # noqa: BLE001
        if _is_timeout(exc):
            raise AdbError("timeout", f"adb timed out after {timeout:g}s") from exc
        raise AdbError("backend_error", f"adb shell failed: {exc}") from exc
    return str(raw)


def _call(method: Any, *args: Any, timeout: float | None = None, **kwargs: Any) -> Any:
    """Invoke an adbutils method, passing timeout when the signature allows it."""
    extra = dict(kwargs)
    if timeout is not None and _accepts_timeout(method):
        extra["timeout"] = timeout
    try:
        return method(*args, **extra)
    except AdbError:
        raise
    except Exception as exc:  # noqa: BLE001
        if timeout is not None and _is_timeout(exc):
            raise AdbError("timeout", f"adb timed out after {timeout:g}s") from exc
        raise


def _frida_server_visible(dev: Any) -> bool | None:
    try:
        text = _device_shell(dev, "ps -A", timeout=_ADB_PROBE_TIMEOUT_S)
        if "frida-server" in text:
            return True
        return "frida-server" in _device_shell(dev, "ps", timeout=_ADB_PROBE_TIMEOUT_S)
    except Exception:  # noqa: BLE001
        return None


def _bind_open_transport(dev: Any, timeout: float) -> Any:
    """Replace adbutils' 600s transport default with a real hang ceiling.

    ``get_state`` / ``forward`` / ``install`` go through ``open_transport``
    and do not accept a timeout argument, so ``_call(..., timeout=)`` hits
    TypeError and falls through to a ten-minute wait. Bound methods on this
    instance keep their own default; only the default changes.
    """
    original = getattr(dev, "open_transport", None)
    if not callable(original):
        return dev

    def open_transport(command: Any = None, timeout: float | None = timeout) -> Any:
        try:
            return original(command=command, timeout=timeout)
        except TypeError:
            try:
                return original(command, timeout)
            except TypeError:
                return original(command)

    try:
        dev.open_transport = open_transport
    except Exception:  # noqa: BLE001
        return dev
    return dev


def _device_info_row(info: Any) -> JsonObject:
    serial = str(getattr(info, "serial", "") or "")
    state = str(getattr(info, "state", "") or "")
    if not serial and isinstance(info, (tuple, list)) and info:
        serial = str(info[0])
        if len(info) > 1:
            state = str(info[1])
    return {"serial": serial, "state": state or "unknown"}


def _apk_package_name(path: Path) -> str | None:
    """Best-effort package id from the APK, without pulling androguard in."""
    try:
        # Stream a bounded window rather than ZipFile.read(), which decompresses
        # the whole member into memory first: install() runs this on a
        # caller-supplied, possibly hostile APK, and a manifest crafted to
        # inflate to gigabytes (a zip bomb) would OOM the process before the
        # slice ran. archive.open(...).read(n) stops after n decompressed bytes.
        with zipfile.ZipFile(path) as archive, archive.open("AndroidManifest.xml") as member:
            data = member.read(_MANIFEST_SCAN_BYTES)
    except Exception:  # noqa: BLE001
        return None
    try:
        text = data.decode("utf-8")
        match = re.search(r'package="([^"]+)"', text)
        if match and _PACKAGE_RE.match(match.group(1)):
            return match.group(1)
    except Exception:  # noqa: BLE001
        pass
    decoded = data.decode("utf-16-le", errors="ignore")
    window = decoded
    marker = decoded.find("package")
    if marker >= 0:
        window = decoded[marker : marker + 400]
    for blob in (window, decoded):
        for candidate in _PACKAGE_IN_TEXT.findall(blob):
            if candidate.startswith("android.") or candidate.startswith("com.android."):
                continue
            if _PACKAGE_RE.match(candidate):
                return str(candidate)
    return None


def _pm_path(dev: Any, package: str) -> str | None:
    raw = _device_shell(dev, ["pm", "path", package], timeout=_ADB_PROBE_TIMEOUT_S)
    for line in str(raw).splitlines():
        line = line.strip()
        if line.startswith("package:"):
            return line.split(":", 1)[1].strip() or line
    return None


def _pids_for_package(dev: Any, package: str) -> list[int] | None:
    try:
        raw = _device_shell(dev, ["pidof", package], timeout=_ADB_PROBE_TIMEOUT_S)
    except AdbError:
        return None
    text = str(raw).strip()
    if not text:
        return []
    lower = text.lower()
    if "not found" in lower or "unknown" in lower or "no such" in lower:
        try:
            ps = _device_shell(dev, "ps -A", timeout=_ADB_PROBE_TIMEOUT_S)
        except AdbError:
            return None
        pids: list[int] = []
        for line in str(ps).splitlines():
            if package not in line:
                continue
            for token in line.split()[:3]:
                if token.isdigit():
                    pids.append(int(token))
                    break
            if len(pids) >= 16:
                break
        return pids
    pids = [int(token) for token in text.replace(",", " ").split() if token.isdigit()]
    if not pids:
        return None
    return pids


def _parse_ps(raw: str) -> tuple[list[JsonObject], bool]:
    """Turn ``ps -A`` output into ``[{pid, name, user, ppid}]`` rows.

    Android's toybox ``ps`` prints a header (``USER PID PPID ... NAME``) whose
    column order is not fixed across versions, so the header is read to locate
    the PID, USER/UID, PPID and NAME/CMD columns by name rather than assuming a
    layout. Every column before NAME is a single token, so the process name --
    the only field that can carry spaces (an ARGS-style ps) -- is everything
    from the name column to end of line. A row whose PID is not a number is
    skipped (the header itself, a blank line, a wrapped banner). Collection
    stops at the ceiling; the second return value is True when it did, so the
    caller can flag a truncated list rather than silently dropping the tail.
    """
    lines = [line for line in raw.splitlines() if line.strip()]
    if not lines:
        return [], False
    header = lines[0].split()
    try:
        pid_idx = header.index("PID")
    except ValueError as exc:
        raise AdbError(
            "backend_error", "could not parse ps output (no PID column)"
        ) from exc
    user_idx = next(
        (i for i, tok in enumerate(header) if tok in ("USER", "UID")), None
    )
    ppid_idx = next((i for i, tok in enumerate(header) if tok == "PPID"), None)
    name_idx = next(
        (i for i, tok in enumerate(header) if tok in ("NAME", "CMD", "COMMAND", "ARGS")),
        len(header) - 1,
    )
    name_is_last = name_idx >= len(header) - 1
    rows: list[JsonObject] = []
    truncated = False
    for line in lines[1:]:
        tokens = line.split()
        if pid_idx >= len(tokens):
            continue
        pid_token = tokens[pid_idx]
        if not pid_token.isdigit():
            continue
        if name_is_last:
            name = " ".join(tokens[name_idx:]) if name_idx < len(tokens) else ""
        else:
            name = tokens[name_idx] if name_idx < len(tokens) else ""
        if not name:
            continue
        if len(rows) >= _MAX_PROCESSES:
            truncated = True
            break
        row: JsonObject = {"pid": int(pid_token), "name": name}
        if user_idx is not None and user_idx < len(tokens):
            row["user"] = tokens[user_idx]
        if ppid_idx is not None and ppid_idx < len(tokens):
            ppid_token = tokens[ppid_idx]
            if ppid_token.isdigit():
                row["ppid"] = int(ppid_token)
        rows.append(row)
    return rows, truncated


def _check_remote_path(path: str) -> str:
    """Validate an on-device absolute path for the sync (LIST/STAT) protocol.

    The path travels over the adb file-sync channel, not a device shell, so it
    is not a shell-injection vector; still, an absolute POSIX path with no
    control characters is required so a relative or malformed value fails here
    with invalid_params rather than confusing adbd.
    """
    if not isinstance(path, str) or not path.strip():
        raise AdbError("invalid_params", "path is required")
    p = path.strip()
    if not p.startswith("/"):
        raise AdbError("invalid_params", "path must be absolute (start with /)", path=p)
    if any(ord(ch) < 0x20 for ch in p):
        raise AdbError("invalid_params", "path contains control characters")
    if len(p) > _REMOTE_PATH_MAX:
        raise AdbError("invalid_params", "path is too long", cap=_REMOTE_PATH_MAX)
    return p


def _ls_entry_kind(mode: int) -> str:
    if stat.S_ISDIR(mode):
        return "dir"
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISLNK(mode):
        return "symlink"
    return "other"


def _shape_ls_entry(mode: int, size: int, mtime: Any, name: str) -> JsonObject:
    row: JsonObject = {
        "name": name,
        "type": _ls_entry_kind(mode),
        "size": int(size),
        # Permission bits only (drop the S_IF* type bits); an octal string the
        # way ls -l's mode reads, so 0644/0755 are recognisable at a glance.
        "mode": format(mode & 0o7777, "04o"),
    }
    if mtime is not None:
        with suppress(OSError, OverflowError, ValueError, AttributeError):
            row["mtime"] = int(mtime.timestamp())
    return row


def _file_mode_size(info: Any) -> tuple[int, int]:
    mode = int(getattr(info, "mode", 0) or 0)
    size = int(getattr(info, "size", 0) or 0)
    if isinstance(info, (tuple, list)) and len(info) >= 2:
        mode = int(info[0] or 0)
        size = int(info[1] or 0)
    return mode, size


class AdbBackend:
    def __init__(self, adb_path: Path | None = None) -> None:
        self._adbutils: Any = None
        self._available = False
        self._adb_path = adb_path
        self._forward_lock = threading.Lock()
        # (serial, local) -> remote for every forward this process created. adb
        # keeps forwards until they are removed or the adb server dies, so
        # close_all has to know; the remote is kept so device.forwards can report
        # the full triple, and a local endpoint maps to one remote (re-forwarding
        # replaces it), which is why (serial, local) alone is the key.
        self._forwards: dict[tuple[str, str], str] = {}
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

    def _client(self, *, socket_timeout: float = _ADB_SHELL_TIMEOUT_S) -> Any:
        if not self._available or self._adbutils is None:
            raise AdbError("capability_unavailable", "adbutils is not installed")
        if self._adb_path is not None:
            # adbutils honours this env var to find the adb executable and to
            # auto-spawn a server if one is not already running.
            import os

            os.environ.setdefault("ADBUTILS_ADB_PATH", str(self._adb_path))
        try:
            try:
                return self._adbutils.AdbClient(
                    host="127.0.0.1", port=5037, socket_timeout=socket_timeout
                )
            except TypeError:
                return self._adbutils.AdbClient(host="127.0.0.1", port=5037)
        except AdbError:
            raise
        except Exception as exc:  # noqa: BLE001 - adbutils raises broad types
            if _is_timeout(exc):
                raise AdbError(
                    "timeout", f"adb timed out after {socket_timeout:g}s"
                ) from exc
            raise AdbError("backend_error", f"cannot reach adb server: {exc}") from exc

    def _device(self, serial: str) -> Any:
        client = self._client(socket_timeout=_ADB_TRANSPORT_TIMEOUT_S)
        try:
            dev = client.device(serial=_check_serial(serial))
        except AdbError:
            raise
        except Exception as exc:  # noqa: BLE001
            if _is_timeout(exc):
                raise AdbError(
                    "timeout", f"adb timed out after {_ADB_TRANSPORT_TIMEOUT_S:g}s"
                ) from exc
            raise AdbError("not_found", f"device unavailable: {exc}", serial=serial) from exc
        return _bind_open_transport(dev, _ADB_TRANSPORT_TIMEOUT_S)

    def list_devices(self) -> JsonObject:
        client = self._client(socket_timeout=_ADB_PROBE_TIMEOUT_S)
        try:
            lister = getattr(client, "list", None)
            if callable(lister):
                infos = lister()
                items = [_device_info_row(info) for info in infos]
            else:
                devices = client.device_list()
                items = [
                    {"serial": str(getattr(dev, "serial", "") or ""), "state": "device"}
                    for dev in devices
                ]
        except AdbError:
            raise
        except Exception as exc:  # noqa: BLE001
            if _is_timeout(exc):
                raise AdbError(
                    "timeout", f"adb timed out after {_ADB_PROBE_TIMEOUT_S:g}s"
                ) from exc
            raise AdbError("backend_error", f"failed to list devices: {exc}") from exc
        has_more = len(items) > _MAX_DEVICES
        page = items[:_MAX_DEVICES]
        return {"devices": page, "count": len(page), "has_more": has_more}

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
                "state": _call(dev.get_state, timeout=_ADB_PROBE_TIMEOUT_S),
                "model": _device_shell(
                    dev, "getprop ro.product.model", timeout=_ADB_PROBE_TIMEOUT_S
                ).strip(),
                "device": _device_shell(
                    dev, "getprop ro.product.device", timeout=_ADB_PROBE_TIMEOUT_S
                ).strip(),
                "sdk": _device_shell(
                    dev, "getprop ro.build.version.sdk", timeout=_ADB_PROBE_TIMEOUT_S
                ).strip(),
                "release": _device_shell(
                    dev, "getprop ro.build.version.release", timeout=_ADB_PROBE_TIMEOUT_S
                ).strip(),
                "abi": _device_shell(
                    dev, "getprop ro.product.cpu.abi", timeout=_ADB_PROBE_TIMEOUT_S
                ).strip(),
            }
        except AdbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"failed to read device info: {exc}") from exc

    def properties(self, serial: str, *, limit: int = 500) -> JsonObject:
        dev = self._device(serial)
        capped = max(1, min(int(limit), _MAX_PROPERTIES))
        raw = _device_shell(dev, "getprop")
        props: dict[str, str] = {}
        has_more = False
        for line in str(raw).splitlines():
            match = re.match(r"^\[(.+?)\]:\s*\[(.*)\]$", line.strip())
            if not match:
                continue
            if len(props) >= capped:
                has_more = True
                break
            props[match.group(1)] = match.group(2)
        return {"properties": props, "count": len(props), "has_more": has_more}

    def packages(
        self,
        serial: str,
        *,
        third_party_only: bool = False,
        limit: int = 500,
        name_filter: str = "",
    ) -> JsonObject:
        dev = self._device(serial)
        capped = max(1, min(int(limit), _MAX_PACKAGES))
        args = "pm list packages -3" if third_party_only else "pm list packages"
        raw = _device_shell(dev, args)
        # Filter in Python, not by appending to the pm command: dev.shell runs a
        # string through the device's sh, so a caller-supplied argument there
        # would be a shell-injection vector. Applied before the cap so a target
        # past the first `limit` packages is still reachable on a busy device --
        # the same idiom as apk.classes and the web/proxy list filters.
        needle = name_filter.strip().lower() if isinstance(name_filter, str) else ""
        pkgs: list[str] = []
        has_more = False
        for line in str(raw).splitlines():
            if not line.startswith("package:"):
                continue
            name = line.split(":", 1)[1].strip()
            if not name:
                continue
            if needle and needle not in name.lower():
                continue
            if len(pkgs) >= capped:
                has_more = True
                break
            pkgs.append(name)
        pkgs.sort()
        return {
            "packages": pkgs,
            "count": len(pkgs),
            "has_more": has_more,
            "third_party_only": third_party_only,
        }

    def processes(
        self,
        serial: str,
        *,
        offset: int = 0,
        limit: int = 200,
        name_filter: str = "",
    ) -> JsonObject:
        """What is actually running on the device right now (``ps -A``).

        device.packages lists what is installed; this lists what is live, with
        each process's pid -- the bridge to frida.attach/frida.spawn and to
        device.pull of a process's own files, since an app id is not a running
        target until zygote has forked it. Reads ``ps -A`` and shapes each row
        into {pid, name, user, ppid}; the app process is the row whose name is
        the package id (or package:process for a declared process). Rows are
        ordered by pid. name_filter keeps only rows whose name contains that
        substring (case-insensitive), applied before paging so total is the
        match count -- the way to find one app's process on a device running
        hundreds. Read-only: it only observes, and ``ps -A`` takes no
        caller-supplied token, so nothing here can inject a shell command.
        """
        dev = self._device(serial)
        raw = _device_shell(dev, ["ps", "-A"], timeout=_ADB_PROBE_TIMEOUT_S)
        rows, collection_truncated = _parse_ps(str(raw))
        needle = name_filter.strip().lower() if isinstance(name_filter, str) else ""
        if needle:
            rows = [row for row in rows if needle in str(row["name"]).lower()]
        rows.sort(key=lambda row: int(row["pid"]))
        start = max(0, int(offset))
        cap = max(1, min(int(limit), _MAX_PROCESSES_PAGE))
        window = rows[start : start + cap]
        result: JsonObject = {
            "processes": window,
            "count": len(window),
            "total": len(rows),
            "offset": start,
            "has_more": start + len(window) < len(rows),
        }
        if collection_truncated:
            result["collection_truncated"] = True
        return result

    def ls(
        self,
        serial: str,
        path: str,
        *,
        offset: int = 0,
        limit: int = 200,
    ) -> JsonObject:
        """List a directory on the device over the adb sync protocol.

        The bridge from "which app / which process" to device.pull: an analyst
        who has a package (device.package_paths) or a process still has to find
        the file worth pulling -- the sqlite db, the shared_prefs xml, the token
        cache, the log under /sdcard or /data/local/tmp. This lists a directory's
        entries with type/size/mode/mtime so device.pull can then fetch one, and
        it reads them over the adb file-sync LIST/STAT channel, not a device
        shell, so the path is never interpreted as a command. A file path lists
        just that file (its own stat), like ``ls <file>``. A directory adbd
        cannot read (an app-private /data/data/<pkg> without root) comes back
        empty rather than as an error, since the sync protocol reports no entries
        rather than a permission fault. Entries are ordered directories-first
        then by name; the collection is bounded (collection_truncated when hit)
        and paged.
        """
        p = _check_remote_path(path)
        dev = self._device(serial)
        sync = getattr(dev, "sync", None)
        if sync is None:
            raise AdbError("capability_unavailable", "adb sync is unavailable")
        try:
            info = _call(sync.stat, p, timeout=_ADB_PROBE_TIMEOUT_S)
        except AdbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"cannot stat path: {exc}", path=p) from exc
        mode = int(getattr(info, "mode", 0) or 0)
        if mode == 0:
            # sync STAT reports mode 0 for a path that does not exist (or that
            # adbd cannot stat at all); either way there is nothing to list.
            raise AdbError(
                "not_found", "path does not exist or is not accessible", path=p
            )
        is_dir = bool(stat.S_ISDIR(mode))
        rows: list[JsonObject] = []
        collection_truncated = False
        if is_dir:
            try:
                listed = _call(sync.list, p, timeout=_ADB_SHELL_TIMEOUT_S)
            except AdbError:
                raise
            except Exception as exc:  # noqa: BLE001
                raise AdbError(
                    "backend_error", f"cannot list directory: {exc}", path=p
                ) from exc
            for entry in listed:
                name = str(getattr(entry, "path", "") or "")
                if name in ("", ".", ".."):
                    continue
                if len(rows) >= _MAX_LS_ENTRIES:
                    collection_truncated = True
                    break
                rows.append(
                    _shape_ls_entry(
                        int(getattr(entry, "mode", 0) or 0),
                        int(getattr(entry, "size", 0) or 0),
                        getattr(entry, "mtime", None),
                        name,
                    )
                )
            # Directories first, then by name, so the tree reads top-down and
            # paging is stable across calls.
            rows.sort(key=lambda row: (row["type"] != "dir", str(row["name"])))
        else:
            rows.append(
                _shape_ls_entry(
                    mode,
                    int(getattr(info, "size", 0) or 0),
                    getattr(info, "mtime", None),
                    p.rsplit("/", 1)[-1] or p,
                )
            )
        total = len(rows)
        start = max(0, int(offset))
        cap = max(1, min(int(limit), _MAX_LS_PAGE))
        window = rows[start : start + cap]
        result: JsonObject = {
            "path": p,
            "is_dir": is_dir,
            "entries": window,
            "count": len(window),
            "total": total,
            "offset": start,
            "has_more": start + len(window) < total,
        }
        if collection_truncated:
            result["collection_truncated"] = True
        return result

    def package_paths(self, serial: str, package: str) -> JsonObject:
        """Where an installed package's APK(s) live on the device.

        The bridge from the dynamic device line to the static apk line: given a
        package id (from device.packages), return its on-device APK path(s) so
        device.pull can fetch the file and the apk.* tools can analyse it,
        without shipping the APK off the device by hand. ``pm path`` lists the
        base APK plus every split (per-density/language/abi config APK) an app
        installed from a bundle carries. The package id is validated and passed
        as a single argv token to ``pm path`` (never interpolated into a shell
        string), so it cannot inject a shell command. A package that is not
        installed -- ``pm path`` prints nothing -- is not_found.
        """
        pkg = _check_package(package)
        dev = self._device(serial)
        raw = _device_shell(dev, ["pm", "path", pkg], timeout=_ADB_PROBE_TIMEOUT_S)
        paths: list[str] = []
        truncated = False
        for line in str(raw).splitlines():
            line = line.strip()
            if not line.startswith("package:"):
                continue
            path = line.split(":", 1)[1].strip()
            if not path or path in paths:
                continue
            if len(paths) >= _MAX_PACKAGE_PATHS:
                truncated = True
                break
            paths.append(path)
        if not paths:
            raise AdbError(
                "not_found", "package not installed or has no apk path", package=pkg
            )
        # Prefer the member literally named base.apk; fall back to the first path
        # so a device that names it differently still yields a usable base_apk.
        base = next(
            (path for path in paths if path.rsplit("/", 1)[-1] == "base.apk"), paths[0]
        )
        result: JsonObject = {
            "package": pkg,
            "paths": paths,
            "count": len(paths),
            "base_apk": base,
            "split": len(paths) > 1,
        }
        if truncated:
            result["paths_truncated"] = True
        return result

    def install(self, serial: str, apk_path: str, *, reinstall: bool = True) -> JsonObject:
        dev = self._device(serial)
        path = Path(apk_path).expanduser()
        if not path.is_file():
            raise AdbError("not_found", "apk not found", path=str(path))
        try:
            extra = _accepted_kwargs(
                dev.install,
                {
                    "nolaunch": True,
                    "uninstall": False,
                    "flags": ["-r"] if reinstall else [],
                },
            )
            _call(dev.install, str(path), timeout=_ADB_TRANSFER_TIMEOUT_S, **extra)
        except AdbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"install failed: {exc}", path=str(path)) from exc
        pkg = _apk_package_name(path)
        if not pkg:
            return {
                "installed": None,
                "path": str(path),
                "serial": _check_serial(serial),
                "note": "install returned; package name not readable from the APK",
            }
        try:
            on_device = _pm_path(dev, pkg)
        except AdbError as exc:
            return {
                "installed": None,
                "package": pkg,
                "path": str(path),
                "serial": _check_serial(serial),
                "note": f"install returned; could not verify ({exc})",
            }
        result: JsonObject = {
            "installed": on_device is not None,
            "package": pkg,
            "path": str(path),
            "serial": _check_serial(serial),
        }
        if on_device is None:
            result["note"] = "install returned; package is not visible to pm path"
        return result

    def uninstall(self, serial: str, package: str) -> JsonObject:
        dev = self._device(serial)
        pkg = _check_package(package)
        try:
            _call(dev.uninstall, pkg, timeout=_ADB_TRANSFER_TIMEOUT_S)
        except AdbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"uninstall failed: {exc}", package=pkg) from exc
        try:
            still = _pm_path(dev, pkg)
        except AdbError as exc:
            return {
                "uninstalled": None,
                "package": pkg,
                "note": f"uninstall returned; could not verify ({exc})",
            }
        result: JsonObject = {"uninstalled": still is None, "package": pkg}
        if still is not None:
            result["note"] = "uninstall returned; package still visible to pm path"
        return result

    def launch(self, serial: str, package: str) -> JsonObject:
        dev = self._device(serial)
        pkg = _check_package(package)
        try:
            _device_shell(
                dev, ["monkey", "-p", pkg, "-c", "android.intent.category.LAUNCHER", "1"]
            )
        except AdbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"launch failed: {exc}", package=pkg) from exc
        try:
            current = _call(dev.app_current, timeout=_ADB_PROBE_TIMEOUT_S)
            foreground = getattr(current, "package", None)
        except Exception as exc:  # noqa: BLE001
            return {
                "launched": None,
                "package": pkg,
                "note": f"monkey ran; could not read foreground ({exc})",
            }
        return {
            "launched": foreground == pkg,
            "package": pkg,
            "foreground": foreground,
        }

    def force_stop(self, serial: str, package: str) -> JsonObject:
        dev = self._device(serial)
        pkg = _check_package(package)
        try:
            _device_shell(dev, ["am", "force-stop", pkg])
        except AdbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"force-stop failed: {exc}", package=pkg) from exc
        pids = _pids_for_package(dev, pkg)
        if pids is None:
            return {
                "stopped": None,
                "package": pkg,
                "note": "force-stop ran; could not read process list",
            }
        return {"stopped": pids == [], "package": pkg, "remaining_pids": pids}

    def current_activity(self, serial: str) -> JsonObject:
        dev = self._device(serial)
        try:
            current = _call(dev.app_current, timeout=_ADB_SHELL_TIMEOUT_S)
        except AdbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"failed to read current activity: {exc}") from exc
        return {
            "package": getattr(current, "package", None),
            "activity": getattr(current, "activity", None),
        }

    def logcat(self, serial: str, *, lines: int = 200, min_priority: str = "") -> JsonObject:
        dev = self._device(serial)
        capped = max(1, min(int(lines), _MAX_LOGCAT_LINES))
        args = ["logcat", "-d", "-t", str(capped)]
        # A min-priority filterspec (V/D/I/W/E/F) applied by logcat itself, so
        # -t returns the last N *matching* lines rather than N raw lines a client
        # filter would then thin to a handful -- the device-log analogue of the
        # console type_filter. The level is validated against the fixed set and
        # passed as its own argv entry, so it can never smuggle a shell token.
        level = (min_priority or "").strip().upper()
        if level:
            if level not in _LOGCAT_PRIORITIES:
                raise AdbError(
                    "invalid_params",
                    "min_priority must be one of V, D, I, W, E, F",
                    min_priority=min_priority,
                )
            args.append(f"*:{level}")
        raw = _device_shell(dev, args)
        text = str(raw)
        truncated = len(text) > _MAX_LOGCAT_CHARS
        if truncated:
            text = text[-_MAX_LOGCAT_CHARS:]
        return {
            "lines": text.splitlines()[-capped:],
            "requested": capped,
            "truncated": truncated,
        }

    def screenshot(self, serial: str, out_path: Path) -> JsonObject:
        dev = self._device(serial)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            image = _call(dev.screenshot, timeout=_ADB_SHELL_TIMEOUT_S)
            image.save(str(out_path))
        except AdbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"screenshot failed: {exc}") from exc
        size, over = capped_file_size(out_path, cap=UNREGISTERED_CAPTURE_MAX_BYTES)
        if over:
            raise AdbError(
                "too_large",
                "screenshot exceeds capture cap",
                size=size,
                cap=UNREGISTERED_CAPTURE_MAX_BYTES,
            )
        return {
            "path": str(out_path),
            "serial": _check_serial(serial),
            "size": size,
        }

    def pull(self, serial: str, remote_path: str, local_path: Path) -> JsonObject:
        dev = self._device(serial)
        local_path.parent.mkdir(parents=True, exist_ok=True)
        cap = UNREGISTERED_CAPTURE_MAX_BYTES
        sync = getattr(dev, "sync", None)
        if sync is not None:
            try:
                info = _call(sync.stat, remote_path, timeout=_ADB_PROBE_TIMEOUT_S)
            except Exception:  # noqa: BLE001
                info = None
            else:
                mode, size = _file_mode_size(info)
                if mode & stat.S_IFDIR:
                    raise AdbError(
                        "invalid_params",
                        "refusing to pull a directory",
                        remote=remote_path,
                    )
                if size > cap:
                    raise AdbError(
                        "too_large",
                        "remote file exceeds pull cap",
                        remote=remote_path,
                        size=size,
                        cap=cap,
                    )
        # Stream the file with a running byte cap instead of pulling it whole and
        # checking the size afterwards. The stat pre-check only fires when stat
        # succeeds and the device reports honestly; without a bound on the write
        # itself, a stat failure (or an under-reporting device) lets adbutils
        # write the entire -- possibly multi-GB -- file into the artifact dir
        # before the post-pull check could delete it, filling the local disk
        # mid-transfer. iter_content yields it in chunks so the write stops the
        # moment it crosses the cap.
        streamer = getattr(sync, "iter_content", None) if sync is not None else None
        if streamer is not None:
            pulled = self._stream_pull(streamer, remote_path, local_path, cap=cap)
            return {"remote": remote_path, "local": str(local_path), "size": pulled}
        try:
            _call(dev.sync.pull, remote_path, str(local_path), timeout=_ADB_TRANSFER_TIMEOUT_S)
        except AdbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"pull failed: {exc}", remote=remote_path) from exc
        if local_path.is_dir():
            shutil.rmtree(local_path, ignore_errors=True)
            raise AdbError(
                "invalid_params",
                "refusing to keep a pulled directory",
                remote=remote_path,
            )
        pulled, over = capped_file_size(local_path, cap=cap)
        if over:
            raise AdbError(
                "too_large",
                "pulled file exceeds capture cap",
                remote=remote_path,
                size=pulled,
                cap=cap,
            )
        return {"remote": remote_path, "local": str(local_path), "size": pulled}

    def _stream_pull(
        self, streamer: Any, remote_path: str, local_path: Path, *, cap: int
    ) -> int:
        """Copy a remote file to disk chunk by chunk, refusing once it passes cap.

        The crossing chunk is never written, so at most ``cap`` bytes ever land
        on disk; a file that overruns is deleted and reported as too_large. Any
        transport error deletes the partial file rather than leaving a truncated
        artifact that would read as a complete pull.
        """
        written = 0
        try:
            with open(local_path, "wb") as handle:
                for chunk in streamer(remote_path):
                    if not chunk:
                        continue
                    if written + len(chunk) > cap:
                        raise AdbError(
                            "too_large",
                            "remote file exceeds pull cap",
                            remote=remote_path,
                            size=written + len(chunk),
                            cap=cap,
                        )
                    handle.write(chunk)
                    written += len(chunk)
        except AdbError:
            with suppress(OSError):
                local_path.unlink()
            raise
        except Exception as exc:  # noqa: BLE001
            with suppress(OSError):
                local_path.unlink()
            if _is_timeout(exc):
                raise AdbError(
                    "timeout", f"adb timed out pulling {remote_path}", remote=remote_path
                ) from exc
            raise AdbError("backend_error", f"pull failed: {exc}", remote=remote_path) from exc
        return written

    def push(self, serial: str, local_path: str, remote_path: str) -> JsonObject:
        dev = self._device(serial)
        path = Path(local_path).expanduser()
        if not path.is_file():
            raise AdbError("not_found", "local file not found", path=str(path))
        try:
            size = int(path.stat().st_size)
        except OSError as exc:
            raise AdbError(
                "backend_error", f"cannot stat local file: {exc}", path=str(path)
            ) from exc
        cap = UNREGISTERED_CAPTURE_MAX_BYTES
        if size > cap:
            raise AdbError(
                "too_large",
                "local file exceeds push cap",
                path=str(path),
                size=size,
                cap=cap,
            )
        try:
            _call(dev.sync.push, str(path), remote_path, timeout=_ADB_TRANSFER_TIMEOUT_S)
        except AdbError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AdbError("backend_error", f"push failed: {exc}", remote=remote_path) from exc
        return {"local": str(path), "remote": remote_path, "size": size}

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
        visible = _frida_server_visible(dev)
        if visible:
            return {"running": True, "pushed": False, "port": port}
        pushed = False
        if server_binary:
            path = Path(server_binary).expanduser()
            if not path.is_file():
                raise AdbError("not_found", "frida-server binary not found", path=str(path))
            try:
                _call(dev.sync.push, str(path), remote_path, timeout=_ADB_TRANSFER_TIMEOUT_S)
                _device_shell(dev, ["chmod", "755", remote_path])
                pushed = True
            except AdbError:
                raise
            except Exception as exc:  # noqa: BLE001
                raise AdbError("backend_error", f"failed to push frida-server: {exc}") from exc
        try:
            # Launch detached under root; bounded so a blocking su prompt cannot hang.
            _device_shell(
                dev,
                f"su -c 'nohup {remote_path} -l 0.0.0.0:{int(port)} >/dev/null 2>&1 &'",
                timeout=8.0,
            )
        except Exception as exc:  # noqa: BLE001 - a timeout here often means it launched
            return {
                "running": _frida_server_visible(dev),
                "pushed": pushed,
                "port": port,
                "note": f"launch attempted; verify manually ({exc})",
            }
        visible = _frida_server_visible(dev)
        if visible:
            return {"running": True, "pushed": pushed, "port": port}
        return {
            "running": visible,
            "pushed": pushed,
            "port": port,
            "note": "launch command returned; frida-server not visible in ps",
        }

    def forward(self, serial: str, local: str, remote: str) -> JsonObject:
        if not re.match(r"^(tcp:\d{1,5}|localabstract:[\w.\-]+)$", local):
            raise AdbError("invalid_params", "invalid local forward spec", local=local)
        if not re.match(r"^(tcp:\d{1,5}|localabstract:[\w.\-]+|jdwp:\d+)$", remote):
            raise AdbError("invalid_params", "invalid remote forward spec", remote=remote)
        serial_id = _check_serial(serial)
        key = (serial_id, local)
        # Resolve the device before occupying a slot: a failed lookup used to
        # leak the reservation until the process hit the cap permanently.
        dev = self._device(serial)
        reserved = False
        with self._forward_lock:
            if key not in self._forwards:
                if len(self._forwards) >= _MAX_FORWARDS:
                    raise AdbError(
                        "invalid_state",
                        "too many adb forwards",
                        cap=_MAX_FORWARDS,
                        held=len(self._forwards),
                    )
                self._forwards[key] = remote
                reserved = True
        try:
            _call(dev.forward, local, remote, timeout=_ADB_SHELL_TIMEOUT_S)
        except AdbError:
            if reserved:
                with self._forward_lock:
                    self._forwards.pop(key, None)
            raise
        except Exception as exc:  # noqa: BLE001
            if reserved:
                with self._forward_lock:
                    self._forwards.pop(key, None)
            raise AdbError("backend_error", f"forward failed: {exc}") from exc
        # Re-forwarding an existing local to a new remote succeeds on adb, so
        # keep the stored remote in step: device.forwards must report what adb
        # actually holds, not the remote this local was first bound to.
        with self._forward_lock:
            self._forwards[key] = remote
        return {"local": local, "remote": remote}

    def list_forwards(self) -> JsonObject:
        """Report the adb forwards this process created and still holds.

        The read side of the forward table ``device.forward`` counts against:
        each entry is the (serial, local, remote) triple that occupies a slot,
        so a caller that hit "too many adb forwards" can see what is held and
        free one with ``remove_forward`` instead of tearing every session down
        with ``close_all``. This is the process's own reservation table, not
        adb's global list -- a forward made by another tool is not shown -- and
        it is read from memory, so it needs no device and cannot time out.
        """
        with self._forward_lock:
            held = list(self._forwards.items())
        forwards = [
            {"serial": serial, "local": local, "remote": remote}
            for (serial, local), remote in held
        ]
        return {"forwards": forwards, "count": len(forwards), "cap": _MAX_FORWARDS}

    def remove_forward(self, serial: str, local: str) -> JsonObject:
        """Remove one adb forward this process created, freeing a slot.

        The per-forward inverse of :meth:`release_forwards` (which drops them
        all at close_all): a caller that hit the forward cap reclaims exactly
        the slot it no longer needs. The ``local`` endpoint identifies the
        forward -- adb keeps one remote per local -- and ``serial`` names the
        device. Removing a forward this process is not tracking is a no-op, not
        an error (adb is still asked, and a "not found" from adb is swallowed),
        so the call is idempotent; ``removed`` is true only when the table
        actually held it. A removal that fails while the table does hold the
        forward keeps the entry so the next close_all retries it, matching
        release_forwards.
        """
        if not re.match(r"^(tcp:\d{1,5}|localabstract:[\w.\-]+)$", local):
            raise AdbError("invalid_params", "invalid local forward spec", local=local)
        serial_id = _check_serial(serial)
        key = (serial_id, local)
        with self._forward_lock:
            tracked = key in self._forwards
        dev = self._device(serial)
        remover = getattr(dev, "forward_remove", None) or getattr(
            dev, "remove_forward", None
        )
        if remover is None:
            raise AdbError("backend_error", "device has no forward-remove API")
        try:
            _call(remover, local, timeout=_ADB_SHELL_TIMEOUT_S)
        except AdbError:
            raise
        except Exception as exc:  # noqa: BLE001
            if tracked:
                # adb still holds our forward; keep the reservation so close_all
                # retries it rather than silently leaking the slot.
                raise AdbError(
                    "backend_error", f"forward remove failed: {exc}", local=local
                ) from exc
            # Not ours and adb has no such forward: nothing to reclaim.
            return {"serial": serial_id, "local": local, "removed": False}
        with self._forward_lock:
            removed = self._forwards.pop(key, None) is not None
        return {"serial": serial_id, "local": local, "removed": removed}

    def release_forwards(self) -> JsonObject:
        """Drop every forward this process created.

        ``adb forward`` lives on the adb server, not in this process: closing
        sessions does not remove them, and a long-lived agent that forwards
        frida or a debug port every night eventually cannot bind another.
        """
        with self._forward_lock:
            held = list(self._forwards.items())
            self._forwards.clear()
        removed: list[JsonObject] = []
        failed: list[JsonObject] = []
        retry: list[tuple[tuple[str, str], str]] = []
        for (serial, local), remote in held:
            try:
                dev = self._device(serial)
                remover = getattr(dev, "forward_remove", None) or getattr(
                    dev, "remove_forward", None
                )
                if remover is None:
                    failed.append(
                        {
                            "serial": serial,
                            "local": local,
                            "error": "device has no forward-remove API",
                        }
                    )
                    retry.append(((serial, local), remote))
                    continue
                _call(remover, local, timeout=_ADB_SHELL_TIMEOUT_S)
                removed.append({"serial": serial, "local": local})
            except Exception as exc:  # noqa: BLE001
                failed.append({"serial": serial, "local": local, "error": str(exc)})
                retry.append(((serial, local), remote))
        if retry:
            # A disconnected device at close_all must not make us forget the
            # forward: adb still has it, and the next close_all is the retry.
            with self._forward_lock:
                for key, remote in retry:
                    if key not in self._forwards:
                        self._forwards[key] = remote
        return {"removed": removed, "failed": failed, "count": len(removed)}
