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
from inspect import Parameter, signature
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.common.paths import is_regular_file
from headless_re_mcp.core.limits import UNREGISTERED_CAPTURE_MAX_BYTES, capped_file_size

JsonObject = dict[str, Any]

# A serial is either an emulator/host:port endpoint or a device id. Both are
# constrained so nothing that reaches a shell command can carry metacharacters.
_SERIAL_RE = re.compile(r"^[A-Za-z0-9._:\-]{1,128}$")
_PACKAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$")
# _PACKAGE_RE constrains structure but not length, unlike _SERIAL_RE's {1,128}.
# A structurally valid but arbitrarily long id ("a.a.a..." repeated) would pass
# and reach a device shell command line, so bound it the way the serial already
# is. Real package ids sit far under this; the cap matches the frida backend's
# RPC-name bound for cross-backend parity.
_MAX_PACKAGE_LEN = 512
# frida-server's -l listen host. An IPv4 address or a simple hostname; the
# strict set keeps a value that reaches the su -c command line from carrying
# shell metacharacters, quotes, or the colon that separates host from port.
_BIND_HOST_RE = re.compile(r"^[A-Za-z0-9.\-]{1,64}$")
_MAX_LOGCAT_LINES = 5000
_MAX_LOGCAT_CHARS = 200_000
# Only the package attribute near the top of the manifest is needed. Reading
# the whole member first would let a bomb-compressed AndroidManifest.xml -- a
# few KiB on disk that inflates to gigabytes -- decompress in full before the
# slice ever ran.
_MAX_MANIFEST_BYTES = 64 * 1024
_MAX_PACKAGES = 2000
_MAX_PROPERTIES = 2000
_MAX_DEVICES = 64
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
    # Length first, before the (length-unbounded) pattern: a megabyte-long but
    # structurally valid id must be refused as the resource abuse it is, not run
    # through the regex and onto a shell command line.
    if len(value) > _MAX_PACKAGE_LEN:
        raise AdbError(
            "invalid_params", "package name too long", package=package, cap=_MAX_PACKAGE_LEN
        )
    if not _PACKAGE_RE.match(value):
        raise AdbError("invalid_params", "invalid package name", package=package)
    return value


def _require_apk_zip(path: Path) -> None:
    """Refuse a non-APK before pushing it to the device.

    ``adb install`` transfers the file to the device and runs ``pm install``;
    an APK is a zip, so a non-zip -- a truncated download, a path pointing at
    the wrong file, a decoded resource mistaken for the rebuilt apk -- can only
    fail after the whole transfer, and ``pm`` reports it as an opaque device
    error rather than the parameter mistake it is. ``zipfile.is_zipfile`` reads
    only the archive's tail (it does not decompress, so the check itself has no
    zip-bomb exposure) and refuses it up front, the same fail-fast shape apktool
    and apksigner use before launching their JVM.
    """
    if not zipfile.is_zipfile(path):
        raise AdbError(
            "invalid_params",
            "input is not a valid APK (not a zip archive)",
            path=str(path),
        )


def _check_forward_spec(spec: str, *, side: str, allow_jdwp: bool = False) -> None:
    """Validate an adb forward endpoint, port range included.

    The patterns already block shell metacharacters, but ``\\d{1,5}`` also admits
    ``tcp:70000`` -- five digits that are not a port. ``connect`` already refuses
    a port outside 1..65535; this makes ``forward`` say the same thing at the
    boundary instead of handing adb a bind request it can only reject with an
    opaque error. ``tcp:0`` is refused on both sides: adb reads a local 0 as
    "allocate a free port", but adbutils discards the reply payload naming that
    port, so the caller would get ``tcp:0`` back with no way to learn where to
    connect -- and ``release_forwards`` removes by the requested spec, which can
    never match the listener adb registered under the real port. Every such
    forward would leak an adb-server listener and pin one of the tracked slots
    until the cap locks the process out. A remote 0 is simply not connectable.
    """
    tcp = re.match(r"^tcp:(\d{1,5})$", spec or "")
    if tcp is not None:
        if not 1 <= int(tcp.group(1)) <= 65535:
            raise AdbError(
                "invalid_params", f"{side} tcp port must be 1..65535", **{side: spec}
            )
        return
    if re.match(r"^localabstract:[\w.\-]+$", spec or ""):
        return
    if allow_jdwp and re.match(r"^jdwp:\d+$", spec or ""):
        return
    raise AdbError("invalid_params", f"invalid {side} forward spec", **{side: spec})


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


def _is_host_error_output(text: str) -> bool:
    """Whether adb handed back only host-error text instead of a real result.

    adbutils' ``shell`` can return the adb host's own ``error:`` / ``adb:``
    message as stdout rather than raising, so a dead or offline device answers
    a text command with an error string. A reply whose every non-blank line is
    such a line is a failure, not an empty-but-successful result. A real result
    -- even a logcat line that merely mentions "error" -- has at least one line
    that does not start with those prefixes.
    """
    captured = [line for line in text.splitlines() if line.strip()]
    return bool(captured) and all(
        line.lstrip().lower().startswith(("error:", "adb:")) for line in captured
    )


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
        with (
            zipfile.ZipFile(path) as archive,
            archive.open("AndroidManifest.xml") as manifest,
        ):
            # read(n) on the member stream decompresses at most n bytes; the old
            # read()[:n] inflated the entire entry into memory before slicing.
            data = manifest.read(_MAX_MANIFEST_BYTES)
    except Exception:  # noqa: BLE001
        return None
    try:
        text = data.decode("utf-8")
        match = re.search(r'package="([^"]+)"', text)
        if match and _PACKAGE_RE.match(match.group(1)):
            return match.group(1)
    except Exception:  # noqa: BLE001
        pass
    # Binary AXML stores its strings in a pool that is UTF-16LE in classic builds
    # and UTF-8 in aapt2's default for many modern ones. Decoding only UTF-16LE
    # left the package string unreadable in a UTF-8-pool APK, so device.install
    # hedged to "package name not readable" on an install that actually
    # succeeded. Try both encodings; the ASCII-only token regexes cannot match
    # the byte-paired noise a UTF-16LE read makes of a UTF-8 pool (or the reverse),
    # so the wrong decode contributes no false package rather than a garbage one.
    for encoding in ("utf-16-le", "utf-8"):
        decoded = data.decode(encoding, errors="ignore")
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
    text = str(raw)
    # adbutils can hand back the adb host's own "error:" / "adb:" line as stdout
    # rather than raising -- an offline device answers pm path with a host error,
    # the same way it does getprop / pm list. Read as "no package: line" that
    # would report a real install as installed=False and an uninstall as
    # uninstalled=True: the verify never ran. Raise so install/uninstall report
    # None ("could not verify"), the honest answer their handlers already emit
    # when the probe cannot run. A genuinely absent package answers with empty
    # output (exit 1, no text), which is not a host error and stays None.
    if _is_host_error_output(text):
        raise AdbError("backend_error", "pm path failed", output=text[:800])
    for line in text.splitlines():
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
        # (serial, local) pairs this process created. adb keeps forwards until
        # they are removed or the adb server dies, so close_all has to know.
        self._forwards: list[tuple[str, str]] = []
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
        # Validate the serial before the capability probe, so a malformed serial
        # reads as invalid_params even where adbutils is absent -- the order
        # connect() spells out and web.open / proxy.start settled on, rather than
        # letting _client()'s capability_unavailable mask a caller mistake. Every
        # method that resolves a device flows through here, so hoisting the check
        # fixes them all at once. _check_serial is pure, so it costs nothing up
        # front and its normalised value is reused for the lookup below.
        checked = _check_serial(serial)
        client = self._client(socket_timeout=_ADB_TRANSPORT_TIMEOUT_S)
        try:
            dev = client.device(serial=checked)
        except AdbError:
            raise
        except Exception as exc:  # noqa: BLE001
            if _is_timeout(exc):
                raise AdbError(
                    "timeout", f"adb timed out after {_ADB_TRANSPORT_TIMEOUT_S:g}s"
                ) from exc
            raise AdbError("not_found", f"device unavailable: {exc}", serial=serial) from exc
        return _bind_open_transport(dev, _ADB_TRANSPORT_TIMEOUT_S)

    def list_devices(self, *, offset: int = 0, limit: int = _MAX_DEVICES) -> JsonObject:
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
        # Sort before the page, not after: adb hands devices back in its own
        # order, so a farm with more than _MAX_DEVICES attached would return an
        # arbitrary slice -- which serials are visible, and which are stranded
        # past the cap, would shift run to run. Sort by serial (the id every
        # other device call keys on) so the page is a real alphabetical slice,
        # the same honesty packages and properties already hold: a serial that
        # sorts within the page but is absent is genuinely not attached. And
        # offset makes that hold for the whole farm, not just the first page: a
        # farm larger than the cap can page to the stranded serials rather than
        # never seeing (or being able to drive) a device past position cap --
        # the apk.classes / device.packages offset contract this comment already
        # invoked but the reader itself had only the sort-before-cap half of.
        start = max(0, int(offset))
        cap = max(1, min(int(limit), _MAX_DEVICES))
        items.sort(key=lambda row: row["serial"])
        total = len(items)
        page = items[start : start + cap]
        return {
            "devices": page,
            "count": len(page),
            "total": total,
            "offset": start,
            "has_more": start + len(page) < total,
        }

    def connect(self, host: str = "127.0.0.1", port: int = 5555) -> JsonObject:
        # Validate the cheap local inputs before touching the adb client, so a
        # bad port or endpoint fails as invalid_params even when adbutils is
        # absent -- matching proxy.start and the fail-fast convention rather than
        # letting _client()'s capability_unavailable mask the parameter mistake.
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise AdbError("invalid_params", "port must be 1..65535", port=port)
        endpoint = f"{host}:{port}"
        _check_serial(endpoint)
        client = self._client()
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

    def properties(self, serial: str, *, limit: int = 500, offset: int = 0) -> JsonObject:
        dev = self._device(serial)
        capped = max(1, min(int(limit), _MAX_PROPERTIES))
        start = max(0, int(offset))
        raw = _device_shell(dev, "getprop")
        text = str(raw)
        if _is_host_error_output(text):
            raise AdbError("backend_error", "getprop failed", output=text[:800])
        props: dict[str, str] = {}
        for line in text.splitlines():
            match = re.match(r"^\[(.+?)\]:\s*\[(.*)\]$", line.strip())
            if match:
                props[match.group(1)] = match.group(2)
        # Page the sorted-by-key map, matching packages: a paged map must be a
        # deterministic alphabetical slice so a caller can tell "this key is
        # absent within the page" from "this key may sit past the cap". getprop
        # lists every property deterministically, so offset makes the tail past
        # _MAX_PROPERTIES reachable -- without it a key sorting past the cap was
        # only flagged by has_more, never resolvable to set/unset, so the
        # absent-within-the-page reasoning held for the first page alone.
        items = sorted(props.items())
        total = len(items)
        page = items[start : start + capped]
        return {
            "properties": dict(page),
            "count": len(page),
            "total": total,
            "offset": start,
            "has_more": start + len(page) < total,
        }

    def packages(
        self,
        serial: str,
        *,
        third_party_only: bool = False,
        limit: int = 500,
        offset: int = 0,
    ) -> JsonObject:
        dev = self._device(serial)
        capped = max(1, min(int(limit), _MAX_PACKAGES))
        start = max(0, int(offset))
        args = "pm list packages -3" if third_party_only else "pm list packages"
        raw = _device_shell(dev, args)
        text = str(raw)
        if _is_host_error_output(text):
            raise AdbError("backend_error", "pm list failed", output=text[:800])
        names: list[str] = []
        for line in text.splitlines():
            if not line.startswith("package:"):
                continue
            name = line.split(":", 1)[1].strip()
            if name:
                names.append(name)
        # Sort before the page, not after: a paged list must be a real
        # alphabetical slice, not an arbitrary install-order one that was merely
        # sorted for display. Only then can a caller reading a name's absence
        # conclude "it sorts within this page and is not installed" -- and only
        # offset makes that conclusion cover the whole set. pm list returns every
        # package deterministically, so paging past _MAX_PACKAGES reaches the
        # tail that a lone capped first page (has_more true) leaves unreachable,
        # closing the gap where a real install sorting past the cap read as "not
        # installed". This is the apk.classes / apk.strings offset contract, the
        # sibling those readers' comments already name device.packages as.
        names.sort()
        total = len(names)
        page = names[start : start + capped]
        return {
            "packages": page,
            "count": len(page),
            "total": total,
            "offset": start,
            "has_more": start + len(page) < total,
            "third_party_only": third_party_only,
        }

    def install(self, serial: str, apk_path: str, *, reinstall: bool = True) -> JsonObject:
        # Check the local APK before resolving the device: a missing file is a
        # cheap local fact and the most common caller mistake, while _device
        # reaches the adb server. Ordering it first means a bad path fails fast
        # as not_found instead of being masked by a device error when the server
        # or device is also unreachable.
        path = Path(apk_path).expanduser()
        if not is_regular_file(path):
            raise AdbError("not_found", "apk not found", path=str(path))
        _require_apk_zip(path)
        dev = self._device(serial)
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
        # Validate the package before resolving the device, matching install()
        # and forward(): a bad package id is a cheap local fact that should fail
        # fast as invalid_params, not be masked by a device error when the adb
        # server or device is also unreachable.
        pkg = _check_package(package)
        dev = self._device(serial)
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
        pkg = _check_package(package)
        dev = self._device(serial)
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
        pkg = _check_package(package)
        dev = self._device(serial)
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
        package = getattr(current, "package", None) if current is not None else None
        activity = getattr(current, "activity", None) if current is not None else None
        # Measured: app_current() returning None still answered
        # {package: None, activity: None} as success, so an agent treated a
        # failed dumpsys as an empty foreground rather than a read that failed.
        if not package:
            raise AdbError(
                "backend_error",
                "failed to read current activity",
                package=package or None,
                activity=activity or None,
            )
        return {"package": package, "activity": activity}

    def logcat(self, serial: str, *, lines: int = 200) -> JsonObject:
        dev = self._device(serial)
        capped = max(1, min(int(lines), _MAX_LOGCAT_LINES))
        raw = _device_shell(dev, ["logcat", "-d", "-t", str(capped)])
        text = str(raw)
        if _is_host_error_output(text):
            raise AdbError("backend_error", "logcat failed", output=text[:800])
        truncated = len(text) > _MAX_LOGCAT_CHARS
        if truncated:
            # Keep the newest bytes, but that slice starts mid-line, so drop
            # the leading partial fragment. Returned as lines[0] it reads as a
            # complete log entry and mis-parses -- the truncated flag says
            # bytes were cut, not that the first line is half a line.
            text = text[-_MAX_LOGCAT_CHARS:]
            newline = text.find("\n")
            text = text[newline + 1 :] if newline != -1 else ""
        out_lines = text.splitlines()[-capped:]
        return {
            "lines": out_lines,
            "count": len(out_lines),
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
        if not local_path.exists():
            # adb sync can report a clean pull yet write nothing when the remote
            # path does not exist -- older adbutils does not raise, and the
            # pre-stat probe above is best-effort. capped_file_size returns 0 for
            # a missing file, so without this the reply would be a size-0
            # success the caller reads as a real empty file it can open.
            raise AdbError(
                "not_found",
                "pull wrote no local file; the remote path may not exist",
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

    def push(self, serial: str, local_path: str, remote_path: str) -> JsonObject:
        # Validate the local file (exists, stat, size cap) before resolving the
        # device: all cheap local facts, and a bad path or oversized file should
        # fail fast rather than after a device round-trip -- or be masked by a
        # device error when the adb server is unreachable.
        path = Path(local_path).expanduser()
        if not is_regular_file(path):
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
        dev = self._device(serial)
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
        bind_host: str = "127.0.0.1",
    ) -> JsonObject:
        """Best-effort: push and start frida-server on a rooted device/emulator.

        Idempotent-ish: if a frida-server process is already running it does
        nothing. Requires root (su) on the device; failures surface as
        structured errors rather than exceptions.

        bind_host is the interface frida-server listens on. It defaults to
        loopback: frida then only accepts connections over the USB/adb transport
        or an adb forward, not from any host that can route to the device. Pass
        ``0.0.0.0`` to expose it on the network for a remote-by-IP connection.
        """
        # Validate the cheap local inputs before resolving the device (which
        # reaches the adb server), matching install()/push()/forward(): a bad
        # remote_path or bind_host, or a missing server_binary, should fail fast
        # and precisely rather than be masked by a device error when the adb
        # server or device is also unreachable.
        if not re.match(r"^/[\w./\-]+$", remote_path):
            raise AdbError("invalid_params", "invalid remote_path", remote_path=remote_path)
        if not _BIND_HOST_RE.match(bind_host or ""):
            raise AdbError("invalid_params", "invalid bind_host", bind_host=bind_host)
        # The tool schema bounds port to 1..65535, but the agent / OpenAI-bridge
        # transports call the handler directly and skip that pydantic check --
        # only the MCP path runs it. Re-validate here, like proxy.start and the
        # forward-spec parser, so an out-of-range port fails as invalid_params
        # rather than being interpolated into the `su -c '... -l host:port ...'`
        # launch line and surfacing as an opaque frida-server bind failure.
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise AdbError("invalid_params", "port must be 1..65535", port=port)
        local_path: Path | None = None
        if server_binary:
            local_path = Path(server_binary).expanduser()
            if not is_regular_file(local_path):
                raise AdbError(
                    "not_found", "frida-server binary not found", path=str(local_path)
                )
        dev = self._device(serial)
        visible = _frida_server_visible(dev)
        if visible:
            return {"running": True, "pushed": False, "port": port}
        pushed = False
        if local_path is not None:
            try:
                _call(dev.sync.push, str(local_path), remote_path, timeout=_ADB_TRANSFER_TIMEOUT_S)
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
                f"su -c 'nohup {remote_path} -l {bind_host}:{int(port)} >/dev/null 2>&1 &'",
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
        _check_forward_spec(local, side="local")
        _check_forward_spec(remote, side="remote", allow_jdwp=True)
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
                self._forwards.append(key)
                reserved = True
        try:
            _call(dev.forward, local, remote, timeout=_ADB_SHELL_TIMEOUT_S)
        except AdbError:
            if reserved:
                with self._forward_lock:
                    if key in self._forwards:
                        self._forwards.remove(key)
            raise
        except Exception as exc:  # noqa: BLE001
            if reserved:
                with self._forward_lock:
                    if key in self._forwards:
                        self._forwards.remove(key)
            raise AdbError("backend_error", f"forward failed: {exc}") from exc
        return {"local": local, "remote": remote}

    def release_forwards(self) -> JsonObject:
        """Drop every forward this process created.

        ``adb forward`` lives on the adb server, not in this process: closing
        sessions does not remove them, and a long-lived agent that forwards
        frida or a debug port every night eventually cannot bind another.
        """
        with self._forward_lock:
            held = list(self._forwards)
            self._forwards.clear()
        removed: list[JsonObject] = []
        failed: list[JsonObject] = []
        retry: list[tuple[str, str]] = []
        for serial, local in held:
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
                    retry.append((serial, local))
                    continue
                _call(remover, local, timeout=_ADB_SHELL_TIMEOUT_S)
                removed.append({"serial": serial, "local": local})
            except Exception as exc:  # noqa: BLE001
                failed.append({"serial": serial, "local": local, "error": str(exc)})
                retry.append((serial, local))
        if retry:
            # A disconnected device at close_all must not make us forget the
            # forward: adb still has it, and the next close_all is the retry.
            with self._forward_lock:
                for key in retry:
                    if key not in self._forwards:
                        self._forwards.append(key)
        return {"removed": removed, "failed": failed, "count": len(removed)}
