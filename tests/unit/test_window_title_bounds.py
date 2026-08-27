"""A hostile window title must not size the enumeration buffer.

``list_process_windows`` is called against the debuggee PID (ui.windows.list
builds ``debuggee_windows`` from it, and the desktop monitors poll it), and a
sample controls its own titles: ``SetWindowText`` takes an arbitrary-length
string and ``GetWindowTextLengthW`` reports it back. Sizing
``create_unicode_buffer`` from that raw length let a hostile title make every
enumeration pass allocate hundreds of megabytes per window. The sibling
``list_input_desktop_windows`` already clamped the length; this pins the same
clamp on ``list_process_windows`` without needing a real Win32 desktop.
"""

from __future__ import annotations

import pytest

import headless_re_mcp.core.windows as winmod


class _FakeULong:
    def __init__(self, value: int = 0) -> None:
        self.value = value


class _FakeBuffer:
    def __init__(self, size: int) -> None:
        self.size = int(size)
        self._text = ""

    def __len__(self) -> int:
        return self.size

    @property
    def value(self) -> str:
        return self._text


class _FakeUser32:
    """Just enough of user32 to drive one window through the callback."""

    def __init__(self, *, title_len: int, target_pid: int) -> None:
        self._title_len = title_len
        self._target_pid = target_pid

    def GetWindowThreadProcessId(self, hwnd: int, ref: _FakeULong) -> int:
        ref.value = self._target_pid
        return 1

    def GetWindowTextLengthW(self, hwnd: int) -> int:
        return self._title_len

    def GetWindowTextW(self, hwnd: int, buf: _FakeBuffer, count: int) -> int:
        # Win32 copies at most count-1 chars plus the terminator.
        written = max(0, min(self._title_len, count - 1))
        buf._text = "A" * written
        return written

    def GetClassNameW(self, hwnd: int, buf: _FakeBuffer, count: int) -> int:
        buf._text = "Cls"
        return 3

    def IsWindowVisible(self, hwnd: int) -> int:
        return 1

    def EnumWindows(self, callback: object, lparam: int) -> int:
        callback(0x1234, 0)  # type: ignore[operator]
        return 1


class _FakeWinDLL:
    def __init__(self, user32: _FakeUser32) -> None:
        self.user32 = user32


class _FakeCtypes:
    def __init__(self, user32: _FakeUser32, sizes: list[int]) -> None:
        self.windll = _FakeWinDLL(user32)
        self.c_ulong = _FakeULong
        self.byref = lambda obj: obj

        def create_unicode_buffer(size: int) -> _FakeBuffer:
            sizes.append(int(size))
            return _FakeBuffer(size)

        self.create_unicode_buffer = create_unicode_buffer


def _drive(monkeypatch: pytest.MonkeyPatch, *, title_len: int) -> tuple[list[dict], list[int]]:
    pid = 4242
    sizes: list[int] = []
    fake = _FakeCtypes(_FakeUser32(title_len=title_len, target_pid=pid), sizes)
    monkeypatch.setattr(winmod.os, "name", "nt")
    # Identity factory: callback_type(callback) returns the Python callback, so
    # the fake EnumWindows can invoke it directly without real ctypes plumbing.
    monkeypatch.setattr(winmod, "wnd_enum_callback_type", lambda: lambda fn: fn)
    monkeypatch.setattr(winmod, "ctypes", fake)
    rows = winmod.list_process_windows(pid)
    return rows, sizes


def test_a_giant_title_does_not_size_the_buffer(monkeypatch: pytest.MonkeyPatch) -> None:
    rows, sizes = _drive(monkeypatch, title_len=300_000_000)
    assert len(rows) == 1
    # The title buffer request is clamped; only the 256 class-name buffer and
    # the capped title buffer are ever asked for.
    assert max(sizes) <= winmod._MAX_WINDOW_TITLE_CHARS + 1
    assert len(rows[0]["title"]) <= winmod._MAX_WINDOW_TITLE_CHARS


def test_a_normal_title_is_not_truncated(monkeypatch: pytest.MonkeyPatch) -> None:
    rows, sizes = _drive(monkeypatch, title_len=10)
    assert len(rows) == 1
    assert len(rows[0]["title"]) == 10
    # Sized exactly to the real title, not the cap.
    assert (10 + 1) in sizes


def test_a_negative_length_does_not_raise(monkeypatch: pytest.MonkeyPatch) -> None:
    # GetWindowTextLengthW can report an error as a negative value; the old
    # ``length + 1`` then asked for a zero-length buffer (ValueError).
    rows, sizes = _drive(monkeypatch, title_len=-1)
    assert len(rows) == 1
    assert rows[0]["title"] == ""
    assert min(sizes) >= 1
