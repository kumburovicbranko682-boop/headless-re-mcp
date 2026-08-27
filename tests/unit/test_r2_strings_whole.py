"""r2.strings whole=true scans the whole file (izzj), not just data sections."""

from __future__ import annotations

import ast
from dataclasses import replace
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.r2.client import _require_allowed_command
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.tools.r2 import build_r2_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_r2_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            for keyword in decorator.keywords:
                if (
                    keyword.arg == "name"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value == name
                ):
                    return ast.get_docstring(node) or ""
    return ""


def _write_minimal_pe(path: Path) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")
    path.write_bytes(image)


class _CommandTrackingR2:
    """A stand-in R2Client that records the command list each run receives."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        self.commands: list[list[str]] = []

    def run(
        self, binary: Path, commands: list[str], *, timeout: float = 30.0
    ) -> dict[str, Any]:
        del binary, timeout
        self.commands.append(list(commands))
        return {"raw": "[]", "commands": list(commands), "parsed": True, "items": [], "count": 0}


def test_r2_strings_whole_switches_izj_to_izzj(tmp_path: Path, monkeypatch: Any) -> None:
    """The default is the data-section scan; whole=true is the whole-file scan.

    izj only sees strings in sections r2 classifies as data, so a packer that
    tucks its payload strings into a non-standard or non-loaded section hides
    them from the default listing. whole=true must switch the command to izzj
    (whole file) so those strings are recoverable; the default must stay izj so
    the common case is not made noisier for everyone.
    """
    tracker = _CommandTrackingR2()
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.R2Client",
        lambda *args, **kwargs: tracker,
    )
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]

        default = service.r2_strings(session_id)
        assert default.ok, default.error
        assert tracker.commands[-1] == ["izj"]

        whole = service.r2_strings(session_id, whole=True)
        assert whole.ok, whole.error
        assert tracker.commands[-1] == ["izzj"]
    finally:
        service.close_all()


def test_r2_izzj_is_whitelisted() -> None:
    # Both scans must pass the launch whitelist; izzj is the new one and would
    # otherwise be rejected as "not whitelisted" before r2 ever runs.
    _require_allowed_command("izj")
    _require_allowed_command("izzj")


def test_r2_strings_docstring_names_the_whole_file_scan() -> None:
    doc = _tool_docstring("r2.strings")
    assert doc, "r2.strings is missing its docstring"
    assert "whole" in doc
    assert "izzj" in doc
    assert "izj" in doc
