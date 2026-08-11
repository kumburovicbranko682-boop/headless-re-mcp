"""Win32 hidden-desktop lifecycle, process launch, and passive monitoring.

The desktop is created inside the caller's interactive window station and is
never switched to the input desktop.  Processes must be created with an
explicit ``STARTUPINFO.lpDesktop``; Python's ``subprocess.STARTUPINFO`` does not
expose that field, so this module owns the small CreateProcessW wrapper needed
for the x64dbg worker.
"""

from __future__ import annotations

import ctypes
import io
import os
import subprocess
from collections.abc import Mapping, Sequence
from contextlib import suppress
from pathlib import Path
from threading import RLock
from typing import Any, TextIO
from uuid import uuid4

JsonObject = dict[str, Any]

_DESKTOP_ALL_ACCESS = 0x01FF
_CREATE_NO_WINDOW = 0x08000000
_CREATE_UNICODE_ENVIRONMENT = 0x00000400
_STARTF_USESHOWWINDOW = 0x00000001
_STARTF_USESTDHANDLES = 0x00000100
_SW_HIDE = 0
_WAIT_OBJECT_0 = 0
_WAIT_TIMEOUT = 258
_WAIT_FAILED = 0xFFFFFFFF
_INFINITE = 0xFFFFFFFF
_STILL_ACTIVE = 259
_UOI_NAME = 2


class HiddenDesktopError(RuntimeError):
    """Raised when the isolated desktop cannot be created or inspected."""


class _STARTUPINFOW(ctypes.Structure):
    _fields_ = (
        ("cb", ctypes.c_ulong),
        ("lpReserved", ctypes.c_wchar_p),
        ("lpDesktop", ctypes.c_wchar_p),
        ("lpTitle", ctypes.c_wchar_p),
        ("dwX", ctypes.c_ulong),
        ("dwY", ctypes.c_ulong),
        ("dwXSize", ctypes.c_ulong),
        ("dwYSize", ctypes.c_ulong),
        ("dwXCountChars", ctypes.c_ulong),
        ("dwYCountChars", ctypes.c_ulong),
        ("dwFillAttribute", ctypes.c_ulong),
        ("dwFlags", ctypes.c_ulong),
        ("wShowWindow", ctypes.c_ushort),
        ("cbReserved2", ctypes.c_ushort),
        ("lpReserved2", ctypes.POINTER(ctypes.c_ubyte)),
        ("hStdInput", ctypes.c_void_p),
        ("hStdOutput", ctypes.c_void_p),
        ("hStdError", ctypes.c_void_p),
    )


class _PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = (
        ("hProcess", ctypes.c_void_p),
        ("hThread", ctypes.c_void_p),
        ("dwProcessId", ctypes.c_ulong),
        ("dwThreadId", ctypes.c_ulong),
    )


class _RECT(ctypes.Structure):
    _fields_ = (
        ("left", ctypes.c_long),
        ("top", ctypes.c_long),
        ("right", ctypes.c_long),
        ("bottom", ctypes.c_long),
    )


def _require_windows() -> None:
    if os.name != "nt":
        raise HiddenDesktopError("hidden desktops require Windows")


def _api() -> tuple[Any, Any]:
    _require_windows()
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    user32.CreateDesktopW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_void_p,
    ]
    user32.CreateDesktopW.restype = ctypes.c_void_p
    user32.CloseDesktop.argtypes = [ctypes.c_void_p]
    user32.CloseDesktop.restype = ctypes.c_bool
    user32.EnumDesktopWindows.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    user32.EnumDesktopWindows.restype = ctypes.c_bool
    user32.GetWindowThreadProcessId.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_ulong),
    ]
    user32.GetWindowThreadProcessId.restype = ctypes.c_ulong
    user32.GetWindowTextLengthW.argtypes = [ctypes.c_void_p]
    user32.GetWindowTextLengthW.restype = ctypes.c_int
    user32.GetWindowTextW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_int]
    user32.GetWindowTextW.restype = ctypes.c_int
    user32.GetClassNameW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_int]
    user32.GetClassNameW.restype = ctypes.c_int
    user32.GetWindowRect.argtypes = [ctypes.c_void_p, ctypes.POINTER(_RECT)]
    user32.GetWindowRect.restype = ctypes.c_bool
    user32.IsWindowVisible.argtypes = [ctypes.c_void_p]
    user32.IsWindowVisible.restype = ctypes.c_bool
    user32.IsWindowEnabled.argtypes = [ctypes.c_void_p]
    user32.IsWindowEnabled.restype = ctypes.c_bool
    user32.IsIconic.argtypes = [ctypes.c_void_p]
    user32.IsIconic.restype = ctypes.c_bool
    user32.GetUserObjectInformationW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_ulong),
    ]
    user32.GetUserObjectInformationW.restype = ctypes.c_bool
    kernel32.CreateProcessW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_bool,
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.POINTER(_STARTUPINFOW),
        ctypes.POINTER(_PROCESS_INFORMATION),
    ]
    kernel32.CreateProcessW.restype = ctypes.c_bool
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_bool
    kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    kernel32.WaitForSingleObject.restype = ctypes.c_ulong
    kernel32.GetExitCodeProcess.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_ulong),
    ]
    kernel32.GetExitCodeProcess.restype = ctypes.c_bool
    kernel32.TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint]
    kernel32.TerminateProcess.restype = ctypes.c_bool
    return user32, kernel32


def _desktop_name(user32: Any, handle: int) -> str:
    required = ctypes.c_ulong()
    user32.GetUserObjectInformationW(
        ctypes.c_void_p(handle), _UOI_NAME, None, 0, ctypes.byref(required)
    )
    if required.value == 0:
        return ""
    buffer = ctypes.create_unicode_buffer(max(1, required.value // ctypes.sizeof(ctypes.c_wchar)))
    if not user32.GetUserObjectInformationW(
        ctypes.c_void_p(handle),
        _UOI_NAME,
        buffer,
        ctypes.sizeof(buffer),
        ctypes.byref(required),
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    return buffer.value


def _environment_block(environment: Mapping[str, str]) -> ctypes.Array[Any]:
    entries = [f"{key}={value}" for key, value in environment.items()]
    entries.sort(key=str.casefold)
    return ctypes.create_unicode_buffer("\0".join(entries) + "\0\0")


class DesktopProcess:
    """Small Popen-compatible wrapper around CreateProcessW."""

    def __init__(
        self,
        *,
        args: Sequence[str],
        process_handle: int,
        pid: int,
        stdin: TextIO,
        stdout: TextIO,
        stderr: TextIO,
    ) -> None:
        self.args = list(args)
        self.pid = pid
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.returncode: int | None = None
        self._handle = process_handle
        self._lock = RLock()
        self._handle_closed = False

    def _exit_code(self) -> int:
        _, kernel32 = _api()
        value = ctypes.c_ulong()
        if not kernel32.GetExitCodeProcess(
            ctypes.c_void_p(self._handle), ctypes.byref(value)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return int(value.value)

    def poll(self) -> int | None:
        with self._lock:
            if self.returncode is not None:
                return self.returncode
            _, kernel32 = _api()
            result = int(
                kernel32.WaitForSingleObject(ctypes.c_void_p(self._handle), 0)
            )
            if result == _WAIT_OBJECT_0:
                self.returncode = self._exit_code()
                self._close_handle()
                return self.returncode
            if result == _WAIT_FAILED:
                raise ctypes.WinError(ctypes.get_last_error())
            return None

    def wait(self, timeout: float | None = None) -> int:
        with self._lock:
            if self.returncode is not None:
                return self.returncode
            _, kernel32 = _api()
            milliseconds = (
                _INFINITE if timeout is None else max(0, min(0xFFFFFFFE, int(timeout * 1000)))
            )
            result = int(
                kernel32.WaitForSingleObject(
                    ctypes.c_void_p(self._handle), milliseconds
                )
            )
            if result == _WAIT_TIMEOUT:
                raise subprocess.TimeoutExpired(
                    self.args, timeout if timeout is not None else 0.0
                )
            if result != _WAIT_OBJECT_0:
                raise ctypes.WinError(ctypes.get_last_error())
            self.returncode = self._exit_code()
            self._close_handle()
            return self.returncode

    def terminate(self) -> None:
        with self._lock:
            if self.poll() is not None:
                return
            _, kernel32 = _api()
            if not kernel32.TerminateProcess(ctypes.c_void_p(self._handle), 1):
                raise ctypes.WinError(ctypes.get_last_error())

    def kill(self) -> None:
        self.terminate()

    def _close_handle(self) -> None:
        if self._handle_closed:
            return
        _, kernel32 = _api()
        kernel32.CloseHandle(ctypes.c_void_p(self._handle))
        self._handle_closed = True

    def __del__(self) -> None:  # pragma: no cover - best-effort leak guard
        with suppress(BaseException):
            self._close_handle()


def _text_stream(fd: int, mode: str, *, encoding: str, errors: str) -> TextIO:
    binary = os.fdopen(fd, mode, buffering=0)
    return io.TextIOWrapper(
        binary,
        encoding=encoding,
        errors=errors,
        newline=None,
        write_through="w" in mode,
    )


def create_process_on_desktop(
    args: Sequence[str | os.PathLike[str]],
    desktop: str,
    *,
    environment: Mapping[str, str] | None = None,
    cwd: str | os.PathLike[str] | None = None,
    encoding: str = "utf-8",
    errors: str = "replace",
) -> DesktopProcess:
    """Create a redirected child on an explicit Win32 desktop."""
    _require_windows()
    import msvcrt

    argv = [os.fspath(item) for item in args]
    if not argv:
        raise ValueError("args must not be empty")
    user32, kernel32 = _api()
    _ = user32
    stdin_read, stdin_write = os.pipe()
    stdout_read, stdout_write = os.pipe()
    stderr_read, stderr_write = os.pipe()
    all_fds = [stdin_read, stdin_write, stdout_read, stdout_write, stderr_read, stderr_write]
    child_fds = [stdin_read, stdout_write, stderr_write]
    parent_fds = [stdin_write, stdout_read, stderr_read]
    try:
        for fd in child_fds:
            os.set_inheritable(fd, True)
        for fd in parent_fds:
            os.set_inheritable(fd, False)
        startup = _STARTUPINFOW()
        startup.cb = ctypes.sizeof(_STARTUPINFOW)
        startup.lpDesktop = desktop
        startup.dwFlags = _STARTF_USESTDHANDLES | _STARTF_USESHOWWINDOW
        startup.wShowWindow = _SW_HIDE
        startup.hStdInput = ctypes.c_void_p(msvcrt.get_osfhandle(stdin_read))
        startup.hStdOutput = ctypes.c_void_p(msvcrt.get_osfhandle(stdout_write))
        startup.hStdError = ctypes.c_void_p(msvcrt.get_osfhandle(stderr_write))
        process = _PROCESS_INFORMATION()
        command_line = ctypes.create_unicode_buffer(subprocess.list2cmdline(argv))
        env = dict(os.environ if environment is None else environment)
        env_buffer = _environment_block(env)
        ok = kernel32.CreateProcessW(
            None,
            command_line,
            None,
            None,
            True,
            _CREATE_NO_WINDOW | _CREATE_UNICODE_ENVIRONMENT,
            ctypes.cast(env_buffer, ctypes.c_void_p),
            os.fspath(cwd) if cwd is not None else None,
            ctypes.byref(startup),
            ctypes.byref(process),
        )
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())
        kernel32.CloseHandle(process.hThread)
        for fd in child_fds:
            os.close(fd)
        return DesktopProcess(
            args=argv,
            process_handle=int(process.hProcess),
            pid=int(process.dwProcessId),
            stdin=_text_stream(stdin_write, "wb", encoding=encoding, errors=errors),
            stdout=_text_stream(stdout_read, "rb", encoding=encoding, errors=errors),
            stderr=_text_stream(stderr_read, "rb", encoding=encoding, errors=errors),
        )
    except BaseException:
        for fd in all_fds:
            with suppress(OSError):
                os.close(fd)
        raise


class HiddenDesktop:
    """Own one non-input desktop and expose bounded passive inspection."""

    def __init__(self, name: str, handle: int) -> None:
        self.name = name
        self._handle = handle
        self._closed = False
        self._lock = RLock()

    @classmethod
    def create(cls, *, prefix: str = "HeadlessRE") -> HiddenDesktop:
        user32, _ = _api()
        name = f"{prefix}-{uuid4().hex}"
        handle = user32.CreateDesktopW(name, None, None, 0, _DESKTOP_ALL_ACCESS, None)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        actual = _desktop_name(user32, int(handle))
        if actual != name:
            user32.CloseDesktop(handle)
            raise HiddenDesktopError("created desktop identity did not round-trip")
        return cls(name, int(handle))

    @property
    def qualified_name(self) -> str:
        return rf"WinSta0\{self.name}"

    def spawn(
        self,
        args: Sequence[str | os.PathLike[str]],
        *,
        environment: Mapping[str, str] | None = None,
        cwd: str | os.PathLike[str] | None = None,
        encoding: str = "utf-8",
        errors: str = "replace",
    ) -> DesktopProcess:
        if self._closed:
            raise HiddenDesktopError("desktop is closed")
        return create_process_on_desktop(
            args,
            self.qualified_name,
            environment=environment,
            cwd=cwd,
            encoding=encoding,
            errors=errors,
        )

    def windows(self, *, allowed_pids: frozenset[int] | None = None) -> list[JsonObject]:
        if self._closed:
            return []
        user32, _ = _api()
        rows: list[JsonObject] = []
        callback_type = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)

        def callback(hwnd: int, _: int) -> bool:
            owner = ctypes.c_ulong()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
            pid = int(owner.value)
            if allowed_pids is not None and pid not in allowed_pids:
                return True
            length = max(0, int(user32.GetWindowTextLengthW(hwnd)))
            title = ctypes.create_unicode_buffer(min(length, 4096) + 1)
            user32.GetWindowTextW(hwnd, title, len(title))
            class_name = ctypes.create_unicode_buffer(256)
            user32.GetClassNameW(hwnd, class_name, len(class_name))
            rect = _RECT()
            user32.GetWindowRect(hwnd, ctypes.byref(rect))
            width = max(0, int(rect.right - rect.left))
            height = max(0, int(rect.bottom - rect.top))
            rows.append(
                {
                    "hwnd": int(hwnd),
                    "pid": pid,
                    "title": title.value,
                    "class_name": class_name.value,
                    "visible": bool(user32.IsWindowVisible(hwnd)),
                    "enabled": bool(user32.IsWindowEnabled(hwnd)),
                    "minimized": bool(user32.IsIconic(hwnd)),
                    "rect": {
                        "left": int(rect.left),
                        "top": int(rect.top),
                        "right": int(rect.right),
                        "bottom": int(rect.bottom),
                        "width": width,
                        "height": height,
                    },
                    "area": width * height,
                }
            )
            return True

        cb = callback_type(callback)
        ctypes.set_last_error(0)
        enumerated = user32.EnumDesktopWindows(
            ctypes.c_void_p(self._handle), cb, None
        )
        if not enumerated:
            error = ctypes.get_last_error()
            if error:
                raise ctypes.WinError(error)
        return rows

    def process_window_descriptions(self, pid: int) -> list[str]:
        descriptions: list[str] = []
        for row in self.windows(allowed_pids=frozenset({pid})):
            descriptions.append(
                f"{row['class_name']}:{row['title']} (hwnd={row['hwnd']})"
            )
        return descriptions

    def snapshot(self, *, allowed_pids: frozenset[int] | None = None) -> JsonObject:
        rows = self.windows(allowed_pids=allowed_pids)
        return {
            "available": True,
            "mode": "hidden_win32",
            "name": self.name,
            "qualified_name": self.qualified_name,
            "input_desktop": False,
            "window_count": len(rows),
            "windows": rows,
        }

    def capture(
        self,
        hwnd: int,
        *,
        allowed_pids: frozenset[int],
        output_path: str | Path,
    ) -> JsonObject:
        desktop_hwnds = {
            int(row["hwnd"]) for row in self.windows(allowed_pids=allowed_pids)
        }
        if hwnd not in desktop_hwnds:
            raise HiddenDesktopError("window is not on the authorized hidden desktop")
        from headless_re_mcp.core.ui_win32 import capture_hwnd_screenshot

        return capture_hwnd_screenshot(hwnd, allowed_pids, output_path)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            user32, _ = _api()
            if not user32.CloseDesktop(ctypes.c_void_p(self._handle)):
                raise ctypes.WinError(ctypes.get_last_error())
            self._closed = True

    def __enter__(self) -> HiddenDesktop:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
