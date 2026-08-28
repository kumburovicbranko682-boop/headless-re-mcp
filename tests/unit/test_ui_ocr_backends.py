"""OCR backend discovery, WinRT/tesseract adapters, and the ocr_hwnd chain.

``core.ui_ocr`` runs on every ``ui.ocr`` call. The bulk of it -- WinRT OCR via
``winsdk`` (absent off Windows), the tesseract subprocess adapter, and the
capture-then-recognise ``ocr_hwnd`` fallback chain -- never ran on a hosted
runner, leaving it ~26% covered. These tests fake the ``winsdk`` module tree so
the async WinRT decode path executes, mock ``_run_ocr``/``TimedOut`` so the
subprocess adapters hit every timeout/error/success arc, and stub the capture +
backend helpers so ``ocr_hwnd`` exercises the auto fallback and explicit-backend
propagation the UI loop relies on.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.core.ui_ocr as ui_ocr
from headless_re_mcp.backends.common.bounded_run import TimedOut
from headless_re_mcp.core.ui_ocr import _OcrOutput
from headless_re_mcp.core.windows import UiPidBoundaryError


def _out(returncode: int = 0, stdout: str = "", stderr: str = "") -> _OcrOutput:
    return _OcrOutput(returncode, stdout, stderr)


# ---------------------------------------------------------------------------
# _run_ocr / _OcrOutput


def test_run_ocr_decodes_completed_process(monkeypatch: pytest.MonkeyPatch) -> None:
    completed = SimpleNamespace(returncode=0, stdout=b"out", stderr=b"err")
    monkeypatch.setattr(ui_ocr, "run_bounded", lambda *_a, **_k: completed)
    result = ui_ocr._run_ocr(["tool"], timeout=1.0)
    assert result.returncode == 0
    assert result.stdout == "out"
    assert result.stderr == "err"


# ---------------------------------------------------------------------------
# discover_tesseract


def test_discover_tesseract_prefers_the_env_override(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    exe = tmp_path / "tesseract"
    exe.write_text("stub")
    monkeypatch.setenv("HEADLESS_RE_TESSERACT", str(exe))
    assert ui_ocr.discover_tesseract() == exe


def test_discover_tesseract_skips_missing_env_then_uses_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HEADLESS_RE_TESSERACT", "/definitely/not/here")
    monkeypatch.setattr(shutil, "which", lambda _n: "/usr/bin/tesseract")
    assert ui_ocr.discover_tesseract() == Path("/usr/bin/tesseract")


def test_discover_tesseract_falls_back_to_known_install_dirs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("HEADLESS_RE_TESSERACT", raising=False)
    monkeypatch.setattr(shutil, "which", lambda _n: None)
    monkeypatch.setattr(Path, "is_file", lambda _self: True)
    assert ui_ocr.discover_tesseract() == Path(r"C:\Program Files\Tesseract-OCR\tesseract.exe")


def test_discover_tesseract_returns_none_when_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HEADLESS_RE_TESSERACT", raising=False)
    monkeypatch.setattr(shutil, "which", lambda _n: None)
    monkeypatch.setattr(Path, "is_file", lambda _self: False)
    assert ui_ocr.discover_tesseract() is None


# ---------------------------------------------------------------------------
# fake winsdk module tree


_UNSET = object()


class _FakeLanguage:
    def __init__(self, language: str) -> None:
        self.language = language


class _FakeLine:
    def __init__(self, text: str) -> None:
        self.text = text


class _FakeResult:
    def __init__(self, lines: Any, text: Any = _UNSET) -> None:
        self.lines = lines
        if text is not _UNSET:
            self.text = text


class _FakeEngine:
    def __init__(self, result: _FakeResult) -> None:
        self._result = result

    async def recognize_async(self, _bitmap: Any) -> _FakeResult:
        return self._result


class _FakeBitmap:
    pass


class _FakeDecoder:
    async def get_software_bitmap_async(self) -> _FakeBitmap:
        return _FakeBitmap()


class _FakeBitmapDecoder:
    @staticmethod
    async def create_async(_stream: Any) -> _FakeDecoder:
        return _FakeDecoder()


class _FakeStream:
    def seek(self, _pos: int) -> None:
        return None


class _FakeDataWriter:
    def __init__(self, _stream: Any) -> None:
        self.written: bytes | None = None

    def write_bytes(self, data: Any) -> None:
        self.written = bytes(data)

    async def store_async(self) -> None:
        return None

    async def flush_async(self) -> None:
        return None

    def detach_stream(self) -> None:
        return None


def _make_ocr_engine(*, from_language: Any, from_profile: Any) -> type:
    class _OcrEngine:
        @staticmethod
        def try_create_from_language(_lang: Any) -> Any:
            return from_language

        @staticmethod
        def try_create_from_user_profile_languages() -> Any:
            return from_profile

    return _OcrEngine


def _reg(monkeypatch: pytest.MonkeyPatch, dotted: str, **attrs: Any) -> None:
    monkeypatch.setitem(sys.modules, dotted, SimpleNamespace(__name__=dotted, **attrs))


def _install_winsdk(monkeypatch: pytest.MonkeyPatch, *, ocr_engine: type) -> None:
    _reg(monkeypatch, "winsdk.windows.globalization", Language=_FakeLanguage)
    _reg(monkeypatch, "winsdk.windows.graphics.imaging", BitmapDecoder=_FakeBitmapDecoder)
    _reg(monkeypatch, "winsdk.windows.media.ocr", OcrEngine=ocr_engine)
    _reg(
        monkeypatch,
        "winsdk.windows.storage.streams",
        DataWriter=_FakeDataWriter,
        InMemoryRandomAccessStream=_FakeStream,
    )


# ---------------------------------------------------------------------------
# windows_ocr_available


def test_windows_ocr_available_is_false_off_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "posix")
    assert ui_ocr.windows_ocr_available() is False


def test_windows_ocr_available_true_with_engine(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "nt")
    _reg(
        monkeypatch,
        "winsdk.windows.media.ocr",
        OcrEngine=_make_ocr_engine(from_language=None, from_profile=object()),
    )
    assert ui_ocr.windows_ocr_available() is True


def test_windows_ocr_available_false_without_engine(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "nt")
    _reg(
        monkeypatch,
        "winsdk.windows.media.ocr",
        OcrEngine=_make_ocr_engine(from_language=None, from_profile=None),
    )
    assert ui_ocr.windows_ocr_available() is False


def test_windows_ocr_available_false_when_winsdk_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setitem(sys.modules, "winsdk.windows.media.ocr", None)
    assert ui_ocr.windows_ocr_available() is False


# ---------------------------------------------------------------------------
# _read_bounded_bmp


def test_read_bounded_bmp_rejects_empty(tmp_path: Path) -> None:
    empty = tmp_path / "empty.bmp"
    empty.write_bytes(b"")
    with pytest.raises(UiPidBoundaryError, match="empty"):
        ui_ocr._read_bounded_bmp(empty)


def test_read_bounded_bmp_rejects_oversized(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(ui_ocr, "_MAX_OCR_INPUT_BYTES", 4)
    big = tmp_path / "big.bmp"
    big.write_bytes(b"12345")
    with pytest.raises(UiPidBoundaryError, match="safety limit"):
        ui_ocr._read_bounded_bmp(big)


def test_read_bounded_bmp_returns_data(tmp_path: Path) -> None:
    ok = tmp_path / "ok.bmp"
    ok.write_bytes(b"BMcontent")
    assert ui_ocr._read_bounded_bmp(ok) == b"BMcontent"


# ---------------------------------------------------------------------------
# _run_async


def test_run_async_runs_without_a_loop() -> None:
    async def value() -> int:
        return 7

    assert ui_ocr._run_async(value()) == 7


def test_run_async_offloads_when_a_loop_is_running() -> None:
    async def outer() -> int:
        async def inner() -> int:
            return 11

        return ui_ocr._run_async(inner())

    assert asyncio.run(outer()) == 11


# ---------------------------------------------------------------------------
# _ocr_bmp_windows_async / _ocr_bmp_windows_inprocess


def test_windows_async_recognises_text(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    bmp = tmp_path / "x.bmp"
    bmp.write_bytes(b"BMdata")
    engine = _FakeEngine(_FakeResult([_FakeLine("Hello")], text="Hello"))
    ocr_engine = _make_ocr_engine(from_language=engine, from_profile=None)
    _install_winsdk(monkeypatch, ocr_engine=ocr_engine)
    out = ui_ocr._ocr_bmp_windows_inprocess(bmp, language="en-US")
    assert out["backend"] == "windows_ocr"
    assert out["text"] == "Hello"
    assert out["lines"] == ["Hello"]
    assert out["path"] == str(bmp)


def test_windows_async_falls_back_to_profile_engine(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    bmp = tmp_path / "x.bmp"
    bmp.write_bytes(b"BMdata")
    engine = _FakeEngine(_FakeResult([_FakeLine("A"), _FakeLine("B")]))
    ocr_engine = _make_ocr_engine(from_language=None, from_profile=engine)
    _install_winsdk(monkeypatch, ocr_engine=ocr_engine)
    out = asyncio.run(ui_ocr._ocr_bmp_windows_async(bmp))
    # No text attribute -> text is joined from the recognised lines.
    assert out["lines"] == ["A", "B"]
    assert out["text"] == "A\nB"


def test_windows_async_raises_without_any_engine(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    bmp = tmp_path / "x.bmp"
    bmp.write_bytes(b"BMdata")
    _install_winsdk(monkeypatch, ocr_engine=_make_ocr_engine(from_language=None, from_profile=None))
    with pytest.raises(UiPidBoundaryError, match="engine unavailable"):
        asyncio.run(ui_ocr._ocr_bmp_windows_async(bmp))


# ---------------------------------------------------------------------------
# ocr_bmp_windows (subprocess worker orchestration)


def test_ocr_bmp_windows_missing_input(tmp_path: Path) -> None:
    with pytest.raises(UiPidBoundaryError, match="BMP missing"):
        ui_ocr.ocr_bmp_windows(tmp_path / "nope.bmp")


def test_ocr_bmp_windows_times_out(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    bmp = tmp_path / "x.bmp"
    bmp.write_bytes(b"BM")

    def boom(*_a: Any, **_k: Any) -> _OcrOutput:
        raise TimedOut(30.0, [123])

    monkeypatch.setattr(ui_ocr, "_run_ocr", boom)
    with pytest.raises(UiPidBoundaryError, match="timed out") as exc:
        ui_ocr.ocr_bmp_windows(bmp)
    assert exc.value.details["killed_pids"] == [123]


def test_ocr_bmp_windows_reports_nonzero_exit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    bmp = tmp_path / "x.bmp"
    bmp.write_bytes(b"BM")
    monkeypatch.setattr(ui_ocr, "_run_ocr", lambda *_a, **_k: _out(2, "", "worker boom"))
    with pytest.raises(UiPidBoundaryError, match="subprocess failed"):
        ui_ocr.ocr_bmp_windows(bmp)


def test_ocr_bmp_windows_requires_output(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    bmp = tmp_path / "x.bmp"
    bmp.write_bytes(b"BM")
    monkeypatch.setattr(ui_ocr, "_run_ocr", lambda *_a, **_k: _out(0, "   \n\n", ""))
    with pytest.raises(UiPidBoundaryError, match="no output"):
        ui_ocr.ocr_bmp_windows(bmp)


def test_ocr_bmp_windows_rejects_non_object(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    bmp = tmp_path / "x.bmp"
    bmp.write_bytes(b"BM")
    monkeypatch.setattr(ui_ocr, "_run_ocr", lambda *_a, **_k: _out(0, json.dumps([1, 2]), ""))
    with pytest.raises(UiPidBoundaryError, match="non-object"):
        ui_ocr.ocr_bmp_windows(bmp)


def test_ocr_bmp_windows_returns_payload(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    bmp = tmp_path / "x.bmp"
    bmp.write_bytes(b"BM")
    payload = {"backend": "windows_ocr", "text": "hi", "lines": ["hi"]}
    monkeypatch.setattr(
        ui_ocr, "_run_ocr", lambda *_a, **_k: _out(0, "log\n" + json.dumps(payload), "")
    )
    assert ui_ocr.ocr_bmp_windows(bmp)["text"] == "hi"


# ---------------------------------------------------------------------------
# ocr_bmp_tesseract


def test_ocr_bmp_tesseract_needs_a_binary(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(ui_ocr, "discover_tesseract", lambda: None)
    with pytest.raises(UiPidBoundaryError, match="tesseract not configured"):
        ui_ocr.ocr_bmp_tesseract(tmp_path / "x.bmp")


def test_ocr_bmp_tesseract_missing_input(tmp_path: Path) -> None:
    exe = tmp_path / "tess"
    exe.write_text("stub")
    with pytest.raises(UiPidBoundaryError, match="BMP missing"):
        ui_ocr.ocr_bmp_tesseract(tmp_path / "nope.bmp", tesseract=exe)


def test_ocr_bmp_tesseract_times_out(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    exe = tmp_path / "tess"
    exe.write_text("stub")
    bmp = tmp_path / "x.bmp"
    bmp.write_bytes(b"BM")

    def boom(*_a: Any, **_k: Any) -> _OcrOutput:
        raise TimedOut(30.0, [7])

    monkeypatch.setattr(ui_ocr, "_run_ocr", boom)
    with pytest.raises(UiPidBoundaryError, match="tesseract OCR timed out"):
        ui_ocr.ocr_bmp_tesseract(bmp, tesseract=exe)


def test_ocr_bmp_tesseract_wraps_launch_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    exe = tmp_path / "tess"
    exe.write_text("stub")
    bmp = tmp_path / "x.bmp"
    bmp.write_bytes(b"BM")

    def boom(*_a: Any, **_k: Any) -> _OcrOutput:
        raise OSError("not executable")

    monkeypatch.setattr(ui_ocr, "_run_ocr", boom)
    with pytest.raises(UiPidBoundaryError, match="failed to launch tesseract"):
        ui_ocr.ocr_bmp_tesseract(bmp, tesseract=exe)


def test_ocr_bmp_tesseract_reports_nonzero_exit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    exe = tmp_path / "tess"
    exe.write_text("stub")
    bmp = tmp_path / "x.bmp"
    bmp.write_bytes(b"BM")
    monkeypatch.setattr(ui_ocr, "_run_ocr", lambda *_a, **_k: _out(1, "", "bad"))
    with pytest.raises(UiPidBoundaryError, match="exited non-zero"):
        ui_ocr.ocr_bmp_tesseract(bmp, tesseract=exe)


def test_ocr_bmp_tesseract_returns_text(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    exe = tmp_path / "tess"
    exe.write_text("stub")
    bmp = tmp_path / "x.bmp"
    bmp.write_bytes(b"BM")
    monkeypatch.setattr(ui_ocr, "_run_ocr", lambda *_a, **_k: _out(0, "one\n\ntwo\n", ""))
    result = ui_ocr.ocr_bmp_tesseract(bmp, tesseract=exe)
    assert result["backend"] == "tesseract"
    assert result["text"] == "one\n\ntwo"
    assert result["lines"] == ["one", "two"]
    assert result["tesseract"] == str(exe)


# ---------------------------------------------------------------------------
# ocr_hwnd fallback chain


def _shot_with_artifact(tmp_path: Path) -> tuple[dict[str, Any], Path]:
    artifact = tmp_path / "shot.bmp"
    artifact.write_bytes(b"BM")
    return {"artifact": str(artifact), "hwnd": 5}, artifact


def _wire_capture(monkeypatch: pytest.MonkeyPatch, shot: dict[str, Any]) -> None:
    monkeypatch.setattr(ui_ocr, "require_allowed_hwnd", lambda *_a, **_k: None)
    monkeypatch.setattr(ui_ocr, "capture_hwnd_screenshot", lambda *_a, **_k: shot)


def test_ocr_hwnd_reports_missing_artifact(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _wire_capture(monkeypatch, {"path": str(tmp_path / "gone.bmp")})
    with pytest.raises(UiPidBoundaryError, match="screenshot artifact missing"):
        ui_ocr.ocr_hwnd(5, frozenset({7}), tmp_path / "out.bmp")


def test_ocr_hwnd_uses_windows_backend(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    shot, _ = _shot_with_artifact(tmp_path)
    _wire_capture(monkeypatch, shot)
    monkeypatch.setattr(ui_ocr, "windows_ocr_available", lambda: True)

    def fake_windows(_p: Any, language: str = "en-US") -> dict[str, Any]:
        return {"backend": "windows_ocr", "text": "w"}

    monkeypatch.setattr(ui_ocr, "ocr_bmp_windows", fake_windows)
    result = ui_ocr.ocr_hwnd(5, frozenset({7}), tmp_path / "out.bmp")
    assert result["ocr_backend"] == "windows_ocr"
    assert result["text"] == "w"
    assert result["hwnd"] == 5


def test_ocr_hwnd_auto_falls_back_to_tesseract(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    shot, _ = _shot_with_artifact(tmp_path)
    _wire_capture(monkeypatch, shot)
    monkeypatch.setattr(ui_ocr, "windows_ocr_available", lambda: True)

    def windows_boom(_p: Any, language: str = "en-US") -> dict[str, Any]:
        raise UiPidBoundaryError("backend_error", "winrt exploded")

    monkeypatch.setattr(ui_ocr, "ocr_bmp_windows", windows_boom)

    def fake_tess(_p: Any, tesseract: Any = None) -> dict[str, Any]:
        return {"backend": "tesseract", "text": "t"}

    monkeypatch.setattr(ui_ocr, "ocr_bmp_tesseract", fake_tess)
    result = ui_ocr.ocr_hwnd(5, frozenset({7}), tmp_path / "out.bmp")
    assert result["ocr_backend"] == "tesseract"


def test_ocr_hwnd_explicit_windows_propagates(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    shot, _ = _shot_with_artifact(tmp_path)
    _wire_capture(monkeypatch, shot)

    def windows_boom(_p: Any, language: str = "en-US") -> dict[str, Any]:
        raise UiPidBoundaryError("backend_error", "winrt exploded")

    monkeypatch.setattr(ui_ocr, "ocr_bmp_windows", windows_boom)
    with pytest.raises(UiPidBoundaryError, match="winrt exploded"):
        ui_ocr.ocr_hwnd(5, frozenset({7}), tmp_path / "out.bmp", backend="windows")


def test_ocr_hwnd_explicit_tesseract_propagates(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    shot, _ = _shot_with_artifact(tmp_path)
    _wire_capture(monkeypatch, shot)

    def tess_boom(_p: Any, tesseract: Any = None) -> dict[str, Any]:
        raise UiPidBoundaryError("backend_error", "tess exploded")

    monkeypatch.setattr(ui_ocr, "ocr_bmp_tesseract", tess_boom)
    with pytest.raises(UiPidBoundaryError, match="tess exploded"):
        ui_ocr.ocr_hwnd(5, frozenset({7}), tmp_path / "out.bmp", backend="tesseract")


def test_ocr_hwnd_rejects_an_unknown_backend(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    shot, _ = _shot_with_artifact(tmp_path)
    _wire_capture(monkeypatch, shot)
    # An unknown backend matches neither the windows nor the tesseract arm.
    with pytest.raises(UiPidBoundaryError, match="no OCR backend available") as exc:
        ui_ocr.ocr_hwnd(5, frozenset({7}), tmp_path / "out.bmp", backend="garbage")
    assert exc.value.details["tried"] == ["garbage"]


def test_ocr_hwnd_reports_no_backend(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    shot, _ = _shot_with_artifact(tmp_path)
    _wire_capture(monkeypatch, shot)
    monkeypatch.setattr(ui_ocr, "windows_ocr_available", lambda: False)

    def tess_boom(_p: Any, tesseract: Any = None) -> dict[str, Any]:
        raise UiPidBoundaryError("capability_unavailable", "no tesseract")

    monkeypatch.setattr(ui_ocr, "ocr_bmp_tesseract", tess_boom)
    with pytest.raises(UiPidBoundaryError, match="no OCR backend available"):
        ui_ocr.ocr_hwnd(5, frozenset({7}), tmp_path / "out.bmp")
