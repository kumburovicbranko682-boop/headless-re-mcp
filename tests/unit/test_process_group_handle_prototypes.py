"""Guard the Win64 HANDLE marshalling of the process-group job wiring.

The job-object safety net in :mod:`headless_re_mcp.process_group` is best
effort, but a *silently broken* net is worse than an absent one. On 64-bit
Windows a HANDLE is pointer-width; a WinDLL function left at its ``c_int``
default truncates the handle CreateJobObjectW/OpenProcess return and then
marshals the truncated value back into Assign/SetInformation/CloseHandle. These
tests pin the declared prototypes so the handle stays full width, and prove --
with real ctypes marshalling -- why the pointer-width type is required.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes

import pytest

from headless_re_mcp import process_group as pg


class _FakeFn:
    """Stand-in for a WinDLL export, defaulting like the real thing.

    A freshly resolved WinDLL function has ``argtypes is None`` and
    ``restype is c_int``; start there so the assertions below only pass once
    the module has actively widened the handle-carrying prototypes.
    """

    def __init__(self) -> None:
        self.argtypes = None
        self.restype = ctypes.c_int


class _FakeKernel32:
    def __init__(self) -> None:
        self.CreateJobObjectW = _FakeFn()
        self.SetInformationJobObject = _FakeFn()
        self.OpenProcess = _FakeFn()
        self.AssignProcessToJobObject = _FakeFn()
        self.CloseHandle = _FakeFn()


def _load_fake_kernel32(monkeypatch: pytest.MonkeyPatch) -> _FakeKernel32:
    fake = _FakeKernel32()

    def _factory(name: str, *args: object, **kwargs: object) -> _FakeKernel32:
        assert name == "kernel32"
        return fake

    # WinDLL does not exist on non-Windows hosts, so create it for the patch.
    monkeypatch.setattr(pg.ctypes, "WinDLL", _factory, raising=False)
    return fake


def test_handle_returns_are_pointer_width(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _load_fake_kernel32(monkeypatch)

    kernel32 = pg._kernel32()

    assert kernel32 is fake
    # The two functions that hand back a HANDLE must not report it as c_int.
    assert kernel32.CreateJobObjectW.restype is wintypes.HANDLE
    assert kernel32.OpenProcess.restype is wintypes.HANDLE
    assert wintypes.HANDLE is not ctypes.c_int


def test_handle_arguments_are_pointer_width(monkeypatch: pytest.MonkeyPatch) -> None:
    _load_fake_kernel32(monkeypatch)

    kernel32 = pg._kernel32()

    # Every argument that carries a handle back into the kernel must be
    # pointer-width so a 64-bit handle is not clipped to its low 32 bits.
    assert kernel32.AssignProcessToJobObject.argtypes == [
        wintypes.HANDLE,
        wintypes.HANDLE,
    ]
    assert kernel32.CloseHandle.argtypes == [wintypes.HANDLE]
    assert kernel32.SetInformationJobObject.argtypes[0] is wintypes.HANDLE
    assert kernel32.OpenProcess.argtypes == [
        wintypes.DWORD,
        wintypes.BOOL,
        wintypes.DWORD,
    ]
    assert kernel32.CreateJobObjectW.argtypes == [
        wintypes.LPVOID,
        wintypes.LPCWSTR,
    ]


def test_info_pointer_argument_accepts_the_limits_struct() -> None:
    # SetInformationJobObject is called with ctypes.byref(_ExtendedLimits()),
    # so its declared pointer type must be POINTER(_ExtendedLimits).
    fake = _FakeKernel32()
    pg._configure_prototypes(fake)

    info_arg = fake.SetInformationJobObject.argtypes[2]
    assert info_arg is ctypes.POINTER(pg._ExtendedLimits)
    # A byref of the real struct is accepted by that argtype (no TypeError).
    limits = pg._ExtendedLimits()
    assert ctypes.byref(limits)._obj is limits  # type: ignore[attr-defined]


def test_pointer_width_is_required_to_survive_a_real_64bit_handle() -> None:
    # The regression this fix prevents, demonstrated with real ctypes
    # marshalling: c_int (the WinDLL default) truncates a 64-bit handle while
    # the declared HANDLE type preserves it. Skipped on the (unused) 32-bit
    # build where a pointer is itself only 32 bits.
    if ctypes.sizeof(ctypes.c_void_p) < 8:
        pytest.skip("pointer width is 32-bit on this build")
    assert ctypes.sizeof(wintypes.HANDLE) == ctypes.sizeof(ctypes.c_void_p)

    handle_value = (1 << 33) | 0x89ABCDEF
    assert ctypes.c_void_p(handle_value).value == handle_value
    assert ctypes.c_int(handle_value).value != handle_value


def test_assign_refuses_off_windows() -> None:
    # The real os.name on this runner is not "nt"; the wiring must decline
    # rather than reach into a WinDLL that does not exist here.
    assert pg.assign_to_process_group(4321) is False


def test_assign_refuses_nonpositive_pid(monkeypatch: pytest.MonkeyPatch) -> None:
    # With the platform gate satisfied, a bad pid is still refused before any
    # kernel handle is opened.
    monkeypatch.setattr(pg.os, "name", "nt")
    assert pg.assign_to_process_group(0) is False
    assert pg.assign_to_process_group(-7) is False
