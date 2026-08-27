"""Coverage for tiny process entry modules that no other suite imports."""

from __future__ import annotations

import importlib
import json
import sys

import pytest

import headless_re_mcp.core._windows_ocr_worker as ocr_worker


def test_ocr_worker_prints_the_payload_as_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["worker", "shot.bmp", "zh-CN"])
    monkeypatch.setattr(
        ocr_worker,
        "_ocr_bmp_windows_inprocess",
        lambda path, *, language: {"text": f"{path} via {language}"},
    )
    ocr_worker.main()
    assert json.loads(capsys.readouterr().out) == {"text": "shot.bmp via zh-CN"}


def test_package_main_re_exports_the_cli_entrypoint() -> None:
    module = importlib.import_module("headless_re_mcp.__main__")
    from headless_re_mcp.cli import main

    assert module.main is main
