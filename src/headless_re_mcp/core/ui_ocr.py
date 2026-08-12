"""Optional OCR backends: Windows.Media.Ocr (winsdk) and external tesseract."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Coroutine
from pathlib import Path
from typing import Any, TypeVar

from headless_re_mcp.core.ui_win32 import capture_hwnd_screenshot, require_allowed_hwnd
from headless_re_mcp.core.windows import UiPidBoundaryError

JsonObject = dict[str, Any]
_MAX_OCR_SECONDS = 30.0
_T = TypeVar("_T")


def discover_tesseract() -> Path | None:
    configured = os.environ.get("HEADLESS_RE_TESSERACT")
    if configured:
        path = Path(configured)
        if path.is_file():
            return path
    which = shutil.which("tesseract")
    if which:
        return Path(which)
    for candidate in (
        Path(r"C:\Program Files\Tesseract-OCR\tesseract.exe"),
        Path(r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe"),
    ):
        if candidate.is_file():
            return candidate
    return None


def windows_ocr_available() -> bool:
    if os.name != "nt":
        return False
    try:
        from winsdk.windows.media.ocr import OcrEngine

        engine = OcrEngine.try_create_from_user_profile_languages()
        return engine is not None
    except Exception:
        return False


def _run_async(coro: Coroutine[Any, Any, _T]) -> _T:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result(timeout=_MAX_OCR_SECONDS)


async def _ocr_bmp_windows_async(path: Path, *, language: str = "en-US") -> JsonObject:
    from winsdk.windows.globalization import Language
    from winsdk.windows.graphics.imaging import BitmapDecoder
    from winsdk.windows.media.ocr import OcrEngine
    from winsdk.windows.storage.streams import DataWriter, InMemoryRandomAccessStream

    data = path.read_bytes()
    if not data:
        raise UiPidBoundaryError("invalid_params", "OCR input BMP is empty")
    stream = InMemoryRandomAccessStream()
    # The winsdk stubs type these parameters as the IOutputStream and
    # IRandomAccessStream interfaces without recording that
    # InMemoryRandomAccessStream implements both.
    writer = DataWriter(stream)  # type: ignore[call-overload]
    writer.write_bytes(bytearray(data))
    await writer.store_async()
    await writer.flush_async()
    writer.detach_stream()
    stream.seek(0)
    decoder = await BitmapDecoder.create_async(stream)  # type: ignore[call-overload]
    bitmap = await decoder.get_software_bitmap_async()
    engine = OcrEngine.try_create_from_language(Language(language))
    if engine is None:
        engine = OcrEngine.try_create_from_user_profile_languages()
    if engine is None:
        raise UiPidBoundaryError(
            "capability_unavailable",
            "Windows.Media.Ocr engine unavailable",
            language=language,
        )
    result = await engine.recognize_async(bitmap)
    # A result with no recognised lines reports them as None rather than empty.
    lines = [str(line.text) for line in (result.lines or [])]
    text = str(getattr(result, "text", "") or "\n".join(lines))
    return {
        "backend": "windows_ocr",
        "language": language,
        "text": text,
        "lines": lines,
        "path": str(path),
    }


def _ocr_bmp_windows_inprocess(path: str | Path, *, language: str = "en-US") -> JsonObject:
    return _run_async(_ocr_bmp_windows_async(Path(path), language=language))


def ocr_bmp_windows(path: str | Path, *, language: str = "en-US") -> JsonObject:
    """Run WinRT OCR in an isolated subprocess to avoid UIA/COM conflicts."""
    bmp = Path(path)
    if not bmp.is_file():
        raise UiPidBoundaryError("invalid_params", "OCR input BMP missing", path=str(bmp))
    worker = Path(__file__).with_name("_windows_ocr_worker.py")
    env = os.environ.copy()
    src_root = str(Path(__file__).resolve().parents[2])
    prev = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = os.pathsep.join([p for p in [src_root, prev] if p])
    try:
        completed = subprocess.run(
            [sys.executable, str(worker), str(bmp), language],
            capture_output=True,
            text=True,
            timeout=_MAX_OCR_SECONDS,
            check=False,
            env=env,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired as exc:
        raise UiPidBoundaryError(
            "timeout",
            "Windows OCR subprocess timed out",
            timeout_seconds=_MAX_OCR_SECONDS,
        ) from exc
    if completed.returncode != 0:
        raise UiPidBoundaryError(
            "backend_error",
            "Windows OCR subprocess failed",
            exit_code=completed.returncode,
            stderr=(completed.stderr or "")[:500],
            stdout=(completed.stdout or "")[:200],
        )
    lines_out = [ln for ln in (completed.stdout or "").splitlines() if ln.strip()]
    if not lines_out:
        raise UiPidBoundaryError("backend_error", "Windows OCR subprocess produced no output")
    payload = json.loads(lines_out[-1])
    if not isinstance(payload, dict):
        raise UiPidBoundaryError("backend_error", "Windows OCR returned non-object")
    return payload


def ocr_bmp_tesseract(path: str | Path, *, tesseract: Path | None = None) -> JsonObject:
    exe = tesseract or discover_tesseract()
    if exe is None or not exe.is_file():
        raise UiPidBoundaryError(
            "capability_unavailable",
            "tesseract not configured (set HEADLESS_RE_TESSERACT)",
        )
    bmp = Path(path)
    if not bmp.is_file():
        raise UiPidBoundaryError("invalid_params", "OCR input BMP missing", path=str(bmp))
    try:
        completed = subprocess.run(
            [str(exe), str(bmp), "stdout", "-l", "eng"],
            capture_output=True,
            text=True,
            timeout=_MAX_OCR_SECONDS,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired as exc:
        raise UiPidBoundaryError(
            "timeout",
            "tesseract OCR timed out",
            timeout_seconds=_MAX_OCR_SECONDS,
        ) from exc
    if completed.returncode != 0:
        raise UiPidBoundaryError(
            "backend_error",
            "tesseract exited non-zero",
            exit_code=completed.returncode,
            stderr=(completed.stderr or "")[:500],
        )
    text = completed.stdout or ""
    return {
        "backend": "tesseract",
        "text": text.strip(),
        "lines": [line for line in text.splitlines() if line.strip()],
        "path": str(bmp),
        "tesseract": str(exe),
    }


def ocr_hwnd(
    hwnd: int,
    allowed_pids: frozenset[int],
    output_path: str | Path,
    *,
    backend: str = "auto",
    language: str = "en-US",
    client_only: bool = False,
    tesseract: Path | None = None,
) -> JsonObject:
    """Capture a PID-bounded hwnd screenshot then OCR it."""
    require_allowed_hwnd(hwnd, allowed_pids)
    shot = capture_hwnd_screenshot(
        hwnd,
        allowed_pids,
        output_path,
        client_only=client_only,
    )
    path = Path(str(shot.get("artifact") or shot.get("path") or ""))
    if not path.is_file():
        raise UiPidBoundaryError(
            "backend_error",
            "screenshot artifact missing after capture",
            shot=shot,
        )
    key = (backend or "auto").strip().casefold()
    errors: list[str] = []
    if key in {"windows", "windows_ocr", "winrt", "auto"} and (
        windows_ocr_available() or key != "auto"
    ):
        try:
            result = ocr_bmp_windows(path, language=language)
            return {**shot, **result, "ocr_backend": result["backend"]}
        except Exception as exc:
            if key != "auto":
                raise
            errors.append(f"windows_ocr:{exc}")
    if key in {"tesseract", "auto"}:
        try:
            result = ocr_bmp_tesseract(path, tesseract=tesseract)
            return {**shot, **result, "ocr_backend": result["backend"]}
        except Exception as exc:
            if key != "auto":
                raise
            errors.append(f"tesseract:{exc}")
    raise UiPidBoundaryError(
        "capability_unavailable",
        "no OCR backend available",
        tried=errors or [key],
    )
