"""Coverage for the optional OCR backends (Windows.Media.Ocr + tesseract).

The Windows engine lives behind the ``winsdk`` package, which is absent on
Linux, so the WinRT paths install a fake ``winsdk`` module tree in
``sys.modules`` and drive the async pipeline directly. Subprocess-backed
backends fake ``run_bounded`` so no real tesseract/worker is launched.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.core.ui_ocr as ocr
from headless_re_mcp.backends.common.bounded_run import Completed, TimedOut
from headless_re_mcp.core.ui_ocr import (
    _ocr_backend_key,
    _OcrOutput,
    _read_bounded_bmp,
    _run_async,
    _run_ocr,
    discover_tesseract,
    ocr_bmp_tesseract,
    ocr_bmp_windows,
    ocr_hwnd,
    windows_ocr_available,
)
from headless_re_mcp.core.windows import UiPidBoundaryError


def _bmp(tmp_path: Path) -> Path:
    path = tmp_path / "shot.bmp"
    path.write_bytes(b"BM" + b"\x00" * 40)
    return path


# --------------------------------------------------------------------------
# _run_ocr / _read_bounded_bmp
# --------------------------------------------------------------------------


def test_run_ocr_decodes_bounded_output(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def fake_run_bounded(command: list[str], **kwargs: Any) -> Completed:
        seen["command"] = command
        seen["kwargs"] = kwargs
        return Completed(returncode=0, stdout=b"hello\xff", stderr=b"warn")

    monkeypatch.setattr(ocr, "run_bounded", fake_run_bounded)
    out = _run_ocr(["tool", "x"], timeout=5.0, env={"A": "B"})
    assert isinstance(out, _OcrOutput)
    assert out.returncode == 0
    assert out.stdout.startswith("hello")
    assert out.stderr == "warn"
    assert seen["kwargs"]["timeout"] == 5.0
    assert seen["kwargs"]["env"] == {"A": "B"}


def test_read_bounded_bmp_rejects_an_empty_file(tmp_path: Path) -> None:
    empty = tmp_path / "empty.bmp"
    empty.write_bytes(b"")
    with pytest.raises(UiPidBoundaryError, match="empty"):
        _read_bounded_bmp(empty)


# --------------------------------------------------------------------------
# discover_tesseract
# --------------------------------------------------------------------------


def test_discover_tesseract_honors_a_configured_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "tesseract"
    exe.write_text("#!/bin/sh\n")
    monkeypatch.setenv("HEADLESS_RE_TESSERACT", str(exe))
    assert discover_tesseract() == exe


def test_discover_tesseract_ignores_a_configured_nonfile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HEADLESS_RE_TESSERACT", str(tmp_path / "missing"))
    monkeypatch.setattr(shutil, "which", lambda name: None)
    monkeypatch.setattr(Path, "is_file", lambda self: False)
    assert discover_tesseract() is None


def test_discover_tesseract_falls_back_to_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("HEADLESS_RE_TESSERACT", raising=False)
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/tesseract")
    assert discover_tesseract() == Path("/usr/bin/tesseract")


def test_discover_tesseract_uses_a_windows_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("HEADLESS_RE_TESSERACT", raising=False)
    monkeypatch.setattr(shutil, "which", lambda name: None)
    monkeypatch.setattr(Path, "is_file", lambda self: True)
    found = discover_tesseract()
    assert found is not None
    assert str(found).endswith("tesseract.exe")


# --------------------------------------------------------------------------
# windows_ocr_available
# --------------------------------------------------------------------------


def _install_winsdk(monkeypatch: pytest.MonkeyPatch, *, ocr_engine: Any) -> None:
    glob = types.ModuleType("winsdk.windows.globalization")
    glob.Language = lambda lang=None: SimpleNamespace(lang=lang)  # type: ignore[attr-defined]
    imaging = types.ModuleType("winsdk.windows.graphics.imaging")
    imaging.BitmapDecoder = _BitmapDecoder  # type: ignore[attr-defined]
    ocr_mod = types.ModuleType("winsdk.windows.media.ocr")
    ocr_mod.OcrEngine = ocr_engine  # type: ignore[attr-defined]
    streams = types.ModuleType("winsdk.windows.storage.streams")
    streams.DataWriter = _DataWriter  # type: ignore[attr-defined]
    streams.InMemoryRandomAccessStream = _Stream  # type: ignore[attr-defined]
    tree = {
        "winsdk": types.ModuleType("winsdk"),
        "winsdk.windows": types.ModuleType("winsdk.windows"),
        "winsdk.windows.globalization": glob,
        "winsdk.windows.graphics": types.ModuleType("winsdk.windows.graphics"),
        "winsdk.windows.graphics.imaging": imaging,
        "winsdk.windows.media": types.ModuleType("winsdk.windows.media"),
        "winsdk.windows.media.ocr": ocr_mod,
        "winsdk.windows.storage": types.ModuleType("winsdk.windows.storage"),
        "winsdk.windows.storage.streams": streams,
    }
    for name, module in tree.items():
        monkeypatch.setitem(sys.modules, name, module)


class _Stream:
    def seek(self, offset: int) -> None:
        return None


class _DataWriter:
    def __init__(self, stream: Any) -> None:
        self._stream = stream

    def write_bytes(self, data: Any) -> None:
        return None

    async def store_async(self) -> None:
        return None

    async def flush_async(self) -> None:
        return None

    def detach_stream(self) -> None:
        return None


class _FakeDecoder:
    async def get_software_bitmap_async(self) -> Any:
        return object()


class _BitmapDecoder:
    @staticmethod
    async def create_async(stream: Any) -> _FakeDecoder:
        return _FakeDecoder()


class _Line:
    def __init__(self, text: str) -> None:
        self.text = text


class _Result:
    def __init__(self, lines: Any, text: str) -> None:
        self.lines = lines
        self.text = text


class _Engine:
    def __init__(self, result: _Result) -> None:
        self._result = result

    async def recognize_async(self, bitmap: Any) -> _Result:
        return self._result


def test_windows_ocr_available_is_false_off_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(os, "name", "posix")
    assert windows_ocr_available() is False


def test_windows_ocr_available_true_when_engine_creates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(os, "name", "nt")
    engine = SimpleNamespace(try_create_from_user_profile_languages=lambda: object())
    _install_winsdk(monkeypatch, ocr_engine=engine)
    assert windows_ocr_available() is True


def test_windows_ocr_available_false_when_engine_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(os, "name", "nt")
    engine = SimpleNamespace(try_create_from_user_profile_languages=lambda: None)
    _install_winsdk(monkeypatch, ocr_engine=engine)
    assert windows_ocr_available() is False


def test_windows_ocr_available_false_when_import_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(os, "name", "nt")

    def boom() -> Any:
        raise RuntimeError("engine exploded")

    engine = SimpleNamespace(try_create_from_user_profile_languages=boom)
    _install_winsdk(monkeypatch, ocr_engine=engine)
    assert windows_ocr_available() is False


# --------------------------------------------------------------------------
# _run_async
# --------------------------------------------------------------------------


def test_run_async_runs_without_a_loop() -> None:
    async def coro() -> int:
        return 7

    assert _run_async(coro()) == 7


def test_run_async_offloads_when_a_loop_is_running(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(asyncio, "get_running_loop", lambda: object())

    async def coro() -> int:
        return 11

    assert _run_async(coro()) == 11


# --------------------------------------------------------------------------
# _ocr_bmp_windows_async / _ocr_bmp_windows_inprocess
# --------------------------------------------------------------------------


def test_ocr_windows_async_returns_recognized_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = _Result(lines=[_Line("first"), _Line("second")], text="first\nsecond")
    engine = SimpleNamespace(
        try_create_from_language=lambda lang: _Engine(result),
        try_create_from_user_profile_languages=lambda: None,
    )
    _install_winsdk(monkeypatch, ocr_engine=engine)
    out = asyncio.run(ocr._ocr_bmp_windows_async(_bmp(tmp_path), language="en-US"))
    assert out["backend"] == "windows_ocr"
    assert out["lines"] == ["first", "second"]


def test_ocr_windows_async_falls_back_to_profile_engine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = _Result(lines=None, text="only text")
    engine = SimpleNamespace(
        try_create_from_language=lambda lang: None,
        try_create_from_user_profile_languages=lambda: _Engine(result),
    )
    _install_winsdk(monkeypatch, ocr_engine=engine)
    out = asyncio.run(ocr._ocr_bmp_windows_async(_bmp(tmp_path)))
    assert out["lines"] == []
    assert out["text"] == "only text"


def test_ocr_windows_async_raises_without_any_engine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine = SimpleNamespace(
        try_create_from_language=lambda lang: None,
        try_create_from_user_profile_languages=lambda: None,
    )
    _install_winsdk(monkeypatch, ocr_engine=engine)
    with pytest.raises(UiPidBoundaryError) as info:
        asyncio.run(ocr._ocr_bmp_windows_async(_bmp(tmp_path)))
    assert info.value.code == "capability_unavailable"


def test_ocr_windows_inprocess_wraps_the_async_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = _Result(lines=[_Line("x")], text="x")
    engine = SimpleNamespace(
        try_create_from_language=lambda lang: _Engine(result),
        try_create_from_user_profile_languages=lambda: None,
    )
    _install_winsdk(monkeypatch, ocr_engine=engine)
    out = ocr._ocr_bmp_windows_inprocess(_bmp(tmp_path))
    assert out["text"] == "x"


# --------------------------------------------------------------------------
# ocr_bmp_windows (subprocess worker)
# --------------------------------------------------------------------------


def test_ocr_bmp_windows_requires_a_present_bmp(tmp_path: Path) -> None:
    with pytest.raises(UiPidBoundaryError, match="BMP missing"):
        ocr_bmp_windows(tmp_path / "missing.bmp")


def test_ocr_bmp_windows_maps_a_timeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: Any, **kwargs: Any) -> Any:
        raise TimedOut(30.0, [123])

    monkeypatch.setattr(ocr, "_run_ocr", boom)
    with pytest.raises(UiPidBoundaryError) as info:
        ocr_bmp_windows(_bmp(tmp_path))
    assert info.value.code == "timeout"
    assert info.value.details["killed_pids"] == [123]


def test_ocr_bmp_windows_maps_a_nonzero_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ocr, "_run_ocr", lambda *a, **k: _OcrOutput(2, "", "boom"))
    with pytest.raises(UiPidBoundaryError) as info:
        ocr_bmp_windows(_bmp(tmp_path))
    assert info.value.code == "backend_error"
    assert info.value.details["exit_code"] == 2


def test_ocr_bmp_windows_requires_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ocr, "_run_ocr", lambda *a, **k: _OcrOutput(0, "   \n", ""))
    with pytest.raises(UiPidBoundaryError, match="no output"):
        ocr_bmp_windows(_bmp(tmp_path))


def test_ocr_bmp_windows_rejects_a_non_object_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ocr, "_run_ocr", lambda *a, **k: _OcrOutput(0, "[1, 2]\n", ""))
    with pytest.raises(UiPidBoundaryError, match="non-object"):
        ocr_bmp_windows(_bmp(tmp_path))


def test_ocr_bmp_windows_returns_the_worker_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        ocr,
        "_run_ocr",
        lambda *a, **k: _OcrOutput(0, 'noise\n{"backend": "windows_ocr"}\n', ""),
    )
    payload = ocr_bmp_windows(_bmp(tmp_path))
    assert payload == {"backend": "windows_ocr"}


# --------------------------------------------------------------------------
# ocr_bmp_tesseract
# --------------------------------------------------------------------------


def test_ocr_tesseract_requires_a_configured_binary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ocr, "discover_tesseract", lambda: None)
    with pytest.raises(UiPidBoundaryError) as info:
        ocr_bmp_tesseract(_bmp(tmp_path))
    assert info.value.code == "capability_unavailable"


def test_ocr_tesseract_requires_a_present_bmp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "tesseract"
    exe.write_text("x")
    with pytest.raises(UiPidBoundaryError, match="BMP missing"):
        ocr_bmp_tesseract(tmp_path / "missing.bmp", tesseract=exe)


def test_ocr_tesseract_maps_a_timeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    exe = tmp_path / "tesseract"
    exe.write_text("x")

    def boom(*args: Any, **kwargs: Any) -> Any:
        raise TimedOut(30.0, [7])

    monkeypatch.setattr(ocr, "_run_ocr", boom)
    with pytest.raises(UiPidBoundaryError) as info:
        ocr_bmp_tesseract(_bmp(tmp_path), tesseract=exe)
    assert info.value.code == "timeout"


def test_ocr_tesseract_maps_a_spawn_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "tesseract"
    exe.write_text("x")

    def boom(*args: Any, **kwargs: Any) -> Any:
        raise OSError("not executable")

    monkeypatch.setattr(ocr, "_run_ocr", boom)
    with pytest.raises(UiPidBoundaryError) as info:
        ocr_bmp_tesseract(_bmp(tmp_path), tesseract=exe)
    assert info.value.code == "backend_error"
    assert "failed to launch" in str(info.value)


def test_ocr_tesseract_maps_a_nonzero_exit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    exe = tmp_path / "tesseract"
    exe.write_text("x")
    monkeypatch.setattr(ocr, "_run_ocr", lambda *a, **k: _OcrOutput(3, "", "err"))
    with pytest.raises(UiPidBoundaryError) as info:
        ocr_bmp_tesseract(_bmp(tmp_path), tesseract=exe)
    assert info.value.details["exit_code"] == 3


def test_ocr_tesseract_returns_text(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    exe = tmp_path / "tesseract"
    exe.write_text("x")
    monkeypatch.setattr(
        ocr, "_run_ocr", lambda *a, **k: _OcrOutput(0, "line one\n\nline two\n", "")
    )
    out = ocr_bmp_tesseract(_bmp(tmp_path), tesseract=exe)
    assert out["backend"] == "tesseract"
    assert out["lines"] == ["line one", "line two"]
    assert out["tesseract"] == str(exe)


# --------------------------------------------------------------------------
# ocr_hwnd dispatcher
# --------------------------------------------------------------------------


def _capture(monkeypatch: pytest.MonkeyPatch, artifact: Path | None) -> None:
    monkeypatch.setattr(ocr, "require_allowed_hwnd", lambda hwnd, allowed: None)
    monkeypatch.setattr(
        ocr,
        "capture_hwnd_screenshot",
        lambda hwnd, allowed, out, *, client_only=False: {
            "artifact": str(artifact) if artifact else "",
            "size": 4,
        },
    )


def test_ocr_hwnd_fails_when_the_capture_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _capture(monkeypatch, tmp_path / "gone.bmp")
    with pytest.raises(UiPidBoundaryError, match="screenshot artifact missing"):
        ocr_hwnd(5, frozenset({7}), tmp_path / "o.bmp")


def test_ocr_hwnd_explicit_windows_backend(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    shot = _bmp(tmp_path)
    _capture(monkeypatch, shot)
    monkeypatch.setattr(
        ocr,
        "ocr_bmp_windows",
        lambda path, language="en-US": {"backend": "windows_ocr", "text": "w"},
    )
    out = ocr_hwnd(5, frozenset({7}), tmp_path / "o.bmp", backend="windows")
    assert out["ocr_backend"] == "windows_ocr"
    assert out["size"] == 4


def test_ocr_hwnd_explicit_windows_backend_reraises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _capture(monkeypatch, _bmp(tmp_path))

    def boom(path: Any, language: str = "en-US") -> Any:
        raise UiPidBoundaryError("backend_error", "winrt down")

    monkeypatch.setattr(ocr, "ocr_bmp_windows", boom)
    with pytest.raises(UiPidBoundaryError, match="winrt down"):
        ocr_hwnd(5, frozenset({7}), tmp_path / "o.bmp", backend="windows")


def test_ocr_hwnd_auto_falls_back_to_tesseract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _capture(monkeypatch, _bmp(tmp_path))
    monkeypatch.setattr(ocr, "windows_ocr_available", lambda: True)

    def win_boom(path: Any, language: str = "en-US") -> Any:
        raise RuntimeError("no engine")

    monkeypatch.setattr(ocr, "ocr_bmp_windows", win_boom)
    monkeypatch.setattr(
        ocr,
        "ocr_bmp_tesseract",
        lambda path, tesseract=None: {"backend": "tesseract", "text": "t"},
    )
    out = ocr_hwnd(5, frozenset({7}), tmp_path / "o.bmp", backend="auto")
    assert out["ocr_backend"] == "tesseract"


def test_ocr_hwnd_auto_skips_windows_when_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _capture(monkeypatch, _bmp(tmp_path))
    monkeypatch.setattr(ocr, "windows_ocr_available", lambda: False)
    monkeypatch.setattr(
        ocr,
        "ocr_bmp_tesseract",
        lambda path, tesseract=None: {"backend": "tesseract", "text": "t"},
    )
    out = ocr_hwnd(5, frozenset({7}), tmp_path / "o.bmp")
    assert out["ocr_backend"] == "tesseract"


def test_ocr_hwnd_explicit_tesseract_reraises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _capture(monkeypatch, _bmp(tmp_path))

    def boom(path: Any, tesseract: Any = None) -> Any:
        raise UiPidBoundaryError("capability_unavailable", "no tesseract")

    monkeypatch.setattr(ocr, "ocr_bmp_tesseract", boom)
    with pytest.raises(UiPidBoundaryError, match="no tesseract"):
        ocr_hwnd(5, frozenset({7}), tmp_path / "o.bmp", backend="tesseract")


def test_ocr_hwnd_rejects_an_unknown_backend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _capture(monkeypatch, _bmp(tmp_path))
    with pytest.raises(UiPidBoundaryError) as info:
        ocr_hwnd(5, frozenset({7}), tmp_path / "o.bmp", backend="bogus")
    assert info.value.code == "capability_unavailable"
    assert info.value.details["tried"] == ["bogus"]


def test_ocr_hwnd_auto_reports_when_all_backends_fail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _capture(monkeypatch, _bmp(tmp_path))
    monkeypatch.setattr(ocr, "windows_ocr_available", lambda: True)

    def win_boom(path: Any, language: str = "en-US") -> Any:
        raise RuntimeError("winrt")

    def tess_boom(path: Any, tesseract: Any = None) -> Any:
        raise RuntimeError("tess")

    monkeypatch.setattr(ocr, "ocr_bmp_windows", win_boom)
    monkeypatch.setattr(ocr, "ocr_bmp_tesseract", tess_boom)
    with pytest.raises(UiPidBoundaryError) as info:
        ocr_hwnd(5, frozenset({7}), tmp_path / "o.bmp")
    assert info.value.code == "capability_unavailable"
    tried = info.value.details["tried"]
    assert isinstance(tried, list)
    assert len(tried) == 2


# --------------------------------------------------------------------------
# _ocr_backend_key (OCR backend selector normalization)
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, "auto"),
        ("", "auto"),
        ("   ", "auto"),
        ("auto", "auto"),
        ("Windows", "windows"),
        ("  Tesseract  ", "tesseract"),
        ("WINRT", "winrt"),
        ("bogus", "bogus"),
    ],
)
def test_ocr_backend_key_normalizes_strings(value: Any, expected: str) -> None:
    assert _ocr_backend_key(value) == expected


@pytest.mark.parametrize("value", [0, 1, 5, 1.5, [1], {"a": 1}, (), b"auto", True, False])
def test_ocr_backend_key_rejects_non_strings(value: Any) -> None:
    with pytest.raises(UiPidBoundaryError) as info:
        _ocr_backend_key(value)
    assert info.value.code == "invalid_params"
    assert info.value.details["got"] == type(value).__name__


@pytest.mark.parametrize("bad", [5, 1.5, [1], {"a": 1}, b"auto", True])
def test_ocr_hwnd_refuses_a_non_string_backend_before_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad: Any
) -> None:
    # A malformed backend must be refused as a caller fault without ever taking
    # the PID-bounded screenshot; the old raw ``.strip()`` crashed *after* the
    # capture and surfaced as an internal_error incident instead.
    monkeypatch.setattr(ocr, "require_allowed_hwnd", lambda hwnd, allowed: None)

    def forbidden_capture(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("capture must not run for a malformed backend")

    monkeypatch.setattr(ocr, "capture_hwnd_screenshot", forbidden_capture)
    with pytest.raises(UiPidBoundaryError) as info:
        ocr_hwnd(5, frozenset({7}), tmp_path / "o.bmp", backend=bad)
    assert info.value.code == "invalid_params"
    assert info.value.details["got"] == type(bad).__name__
