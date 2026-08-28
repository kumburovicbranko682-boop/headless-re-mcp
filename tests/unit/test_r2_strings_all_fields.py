"""r2.strings_all must run izzj (whole-image), not izj (data sections only)."""

from __future__ import annotations

import ast
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.r2.client import (
    R2Error,
    _require_allowed_command,
)
from headless_re_mcp.backends.r2.mapping import _MAX_ITEMS, enrich_r2_payload
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


class _CapturingR2:
    """Fake R2Client whose run() records the command list and returns izzj rows."""

    def __init__(self, entries: list[dict[str, Any]]) -> None:
        self._entries = entries
        self.commands: list[str] = []

    def run(
        self, binary: Path, commands: list[str], *, timeout: float = 30.0
    ) -> dict[str, Any]:
        del timeout
        self.commands = list(commands)
        return enrich_r2_payload(
            {"raw": json.dumps(self._entries), "commands": commands},
            binary=binary,
        )


def test_r2_strings_all_issues_izzj_not_izj(tmp_path: Path, monkeypatch: Any) -> None:
    """The whole point of the tool: it must scan the image with izzj.

    r2.strings runs izj (data sections only); r2.strings_all runs izzj (whole
    binary). If the service issued izj here the tool would be a duplicate that
    silently drops every string outside a data section -- exactly the ones the
    tool exists to surface. So assert the command the service put on the wire is
    izzj, and that the rows still come back enriched into string/address items.
    """
    entries = [
        {"string": "https://c2.example/beacon", "vaddr": 0x1400, "section": ".text",
         "type": "ascii"},
        {"string": "in-overlay-marker", "vaddr": 0x9000, "section": "", "type": "ascii"},
    ]
    tracker = _CapturingR2(entries)
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

        result = service.r2_strings_all(session_id)
        assert result.ok, result.error
        assert result.data is not None
        # The distinguishing behaviour: izzj (whole image), never izj.
        assert tracker.commands == ["izzj"]
        found = {item["string"] for item in result.data["items"]}
        assert "https://c2.example/beacon" in found
        assert "in-overlay-marker" in found
        # A whole-image hit outside a named section still maps by its vaddr.
        outside = next(
            item for item in result.data["items"]
            if item["string"] == "in-overlay-marker"
        )
        assert isinstance(outside.get("address"), dict)
    finally:
        service.close_all()


def test_r2_strings_all_discloses_when_the_list_was_cut(tmp_path: Path) -> None:
    """A whole-image scan hits the 4096 cap far sooner, so the cut must show.

    Same disclosure contract as r2.strings (items_truncated/items_total/
    items_limit, and no strings/truncated/has_more field), so "these are all the
    strings" is never a wrong read on a large or crafted image.
    """
    binary = tmp_path / "f.exe"
    binary.write_bytes(b"MZ" + b"\x00" * 200)
    entries = [
        {
            "string": f"s{index}",
            "vaddr": 0x140001000 + index,
            "section": ".text",
            "type": "ascii",
        }
        for index in range(_MAX_ITEMS + 7)
    ]
    payload = enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["izzj"]},
        binary=binary,
    )
    assert payload["count"] == _MAX_ITEMS
    assert len(payload["items"]) == _MAX_ITEMS
    assert payload["items_truncated"] is True
    assert payload["items_total"] == _MAX_ITEMS + 7
    assert payload["items_limit"] == _MAX_ITEMS
    assert "truncated" not in payload
    assert "has_more" not in payload
    assert "strings" not in payload


def test_izzj_is_whitelisted_alongside_izj() -> None:
    """izzj must pass the command gate; a near-miss must still be rejected.

    run() rejects any command not on the whitelist, so if izzj were not added
    the tool would fault every call. Guard that izj (data scan) and izzj (whole
    image) both pass, while a typo'd izzzj is refused as invalid_params -- the
    gate stays a whitelist, not a substring match.
    """
    _require_allowed_command("izj")
    _require_allowed_command("izzj")
    with pytest.raises(R2Error) as excinfo:
        _require_allowed_command("izzzj")
    assert excinfo.value.code == "invalid_params"


def test_r2_strings_all_docstring_contrasts_with_the_data_scan() -> None:
    """The docstring must tell an agent when to reach past r2.strings.

    It has to name izzj, contrast with r2.strings/izj (data sections only), name
    the items_truncated disclosure the whole-image scan trips sooner, and keep
    the "no strings field" invariant the other r2 readers state.
    """
    doc = _tool_docstring("r2.strings_all")
    assert "izzj" in doc
    assert "izj" in doc
    assert "r2.strings" in doc
    assert "items_truncated" in doc
    assert "no strings" in doc
