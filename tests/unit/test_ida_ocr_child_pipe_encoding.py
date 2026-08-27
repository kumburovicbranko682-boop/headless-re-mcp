"""The Python child pipes are pinned to UTF-8 on every locale.

The idalib gate worker, the idalib session worker and the Windows OCR worker
all print ``ensure_ascii=False`` JSON to a pipe. A piped Python child on
Windows encodes its stdio with the ANSI code page while every parent here
decodes UTF-8, so non-ASCII data (strings extracted from a sample, an NTFS
path, OCR of a non-English UI) came back garbled -- and a character outside
the child's code page killed the child itself with UnicodeEncodeError
mid-reply. The parents now pin both pipe ends: ``PYTHONIOENCODING`` in the
child environment and ``encoding``/``errors`` on their own side. The gate and
worker tests spawn a real child through the production kwargs and require an
exact non-ASCII round trip, so on a Windows runner they fail outright if the
pin is dropped; the kwargs assertions keep the contract visible on Linux too.
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.ida import client as client_mod
from headless_re_mcp.backends.ida import gate as gate_mod
from headless_re_mcp.backends.ida.client import IdaWorkerClient
from headless_re_mcp.backends.ida.gate import run_idalib_gate
from headless_re_mcp.config import Settings
from headless_re_mcp.core import ui_ocr

_NON_ASCII = "\u89e3\u5305\u5668"  # CJK; not representable in cp1252

_GATE_CHILD = (
    "import json\n"
    f"print(json.dumps({{'ok': True, 'name': {_NON_ASCII!r}}}, ensure_ascii=False))\n"
)

_WORKER_CHILD = (
    "import json, sys\n"
    "print(json.dumps({'event': 'ready', 'data': "
    f"{{'capabilities': [], 'name': {_NON_ASCII!r}}}}}, ensure_ascii=False), flush=True)\n"
    "sys.stdin.read()\n"
)


def _fake_settings(tmp_path: Path) -> Settings:
    fake_ida = tmp_path / "IDA"
    fake_ida.mkdir()
    return replace(Settings.load(), ida_home=fake_ida)


def test_the_gate_worker_pipe_is_utf8_on_both_ends(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    settings = _fake_settings(tmp_path)

    captured: dict[str, Any] = {}
    real_popen = subprocess.Popen

    def fake_popen(cmd: list[str], **kwargs: Any) -> subprocess.Popen[Any]:
        captured.update(kwargs)
        return real_popen([sys.executable, "-c", _GATE_CHILD], **kwargs)

    monkeypatch.setattr(gate_mod.subprocess, "Popen", fake_popen)

    result = run_idalib_gate(binary, settings, timeout=60.0)

    assert captured["encoding"] == "utf-8"
    assert captured["errors"] == "replace"
    assert captured["env"]["PYTHONIOENCODING"] == "utf-8:replace"
    # The child printed the name ensure_ascii=False through the production
    # pipe; with both ends pinned it arrives exactly, not as U+FFFD.
    assert result.payload["name"] == _NON_ASCII


def test_the_session_worker_pipe_is_utf8_on_both_ends(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    settings = _fake_settings(tmp_path)

    captured: dict[str, Any] = {}
    real_popen = subprocess.Popen

    def fake_popen(cmd: list[str], **kwargs: Any) -> subprocess.Popen[Any]:
        captured.update(kwargs)
        return real_popen([sys.executable, "-c", _WORKER_CHILD], **kwargs)

    monkeypatch.setattr(client_mod.subprocess, "Popen", fake_popen)

    worker = IdaWorkerClient(binary, settings, startup_timeout=60.0)
    try:
        assert captured["encoding"] == "utf-8"
        assert captured["errors"] == "replace"
        assert captured["env"]["PYTHONIOENCODING"] == "utf-8:replace"
        assert worker.metadata["name"] == _NON_ASCII
    finally:
        worker.terminate()


def test_the_windows_ocr_worker_env_pins_utf8(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bmp = tmp_path / "shot.bmp"
    bmp.write_bytes(b"BM")

    captured: dict[str, Any] = {}

    def fake_run_ocr(
        command: list[str], *, timeout: float, env: Any = None
    ) -> ui_ocr._OcrOutput:
        captured["command"] = command
        captured["env"] = env
        return ui_ocr._OcrOutput(
            0, json.dumps({"ok": True, "text": _NON_ASCII}, ensure_ascii=False), ""
        )

    monkeypatch.setattr(ui_ocr, "_run_ocr", fake_run_ocr)

    payload = ui_ocr.ocr_bmp_windows(bmp)

    assert captured["env"]["PYTHONIOENCODING"] == "utf-8:replace"
    assert payload["text"] == _NON_ASCII
