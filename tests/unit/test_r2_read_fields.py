"""r2.read must collapse a pxj int array to exact hex and disclose a short read."""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.r2.client import (
    _MAX_READ_BYTES,
    R2Client,
    R2Error,
    _require_allowed_command,
)
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


def _canned(values: list[int]) -> Any:
    """A fake R2Client.run returning ``values`` as a pxj JSON int array."""

    def run(binary: Path, commands: list[str], *, timeout: float = 30.0) -> dict[str, Any]:
        return {"raw": json.dumps(values), "commands": commands}

    return run


def test_r2_read_collapses_the_byte_array_to_exact_hex(tmp_path: Path, monkeypatch: Any) -> None:
    """A pxj int array must come back as lowercase hex with a mapped address.

    The whole point of a data read is byte fidelity: an embedded key or blob has
    to survive as the exact bytes, so the JSON int array pxj emits collapses to a
    hex string (no separators), the count matches, and the requested vaddr is
    both the mapped ``address`` and the raw ``address_va`` -- the r2 line's own
    address convention, not frida's raw int.
    """
    binary = tmp_path / "f.bin"
    binary.write_bytes(b"MZ" + b"\x00" * 200)
    values = [0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01]
    client = R2Client(executable=Path("/nonexistent-r2"))
    monkeypatch.setattr(client, "run", _canned(values))
    out = client.read_bytes(binary, 0x1000, size=len(values))
    assert out["encoding"] == "hex"
    assert out["data"] == "7f454c460201"
    assert bytes.fromhex(out["data"]) == bytes(values)
    assert out["count"] == len(values)
    assert out["size"] == len(values)
    assert out["parsed"] is True
    assert out["address_va"] == 0x1000
    assert isinstance(out.get("address"), dict)
    assert out["address"].get("va") == 0x1000
    # A full read (as many bytes as asked) must not claim a short read.
    assert "short_read" not in out
    doc = _tool_docstring("r2.read")
    assert "hex" in doc
    assert "short_read" in doc
    assert "address_va" in doc


def test_r2_read_discloses_a_short_read(tmp_path: Path, monkeypatch: Any) -> None:
    """Fewer bytes than asked must set short_read, not silently look complete.

    pxj returns only what is mapped at the address; a window running off the end
    of a section returns a short array. Reading that as "the whole blob" is the
    exact wrong call, so count < size and short_read is flagged.
    """
    binary = tmp_path / "f.bin"
    binary.write_bytes(b"MZ" + b"\x00" * 200)
    client = R2Client(executable=Path("/nonexistent-r2"))
    monkeypatch.setattr(client, "run", _canned([0xDE, 0xAD]))
    out = client.read_bytes(binary, 0x2000, size=16)
    assert out["count"] == 2
    assert out["size"] == 16
    assert out["short_read"] is True
    assert out["data"] == "dead"


def test_r2_read_survives_a_non_array_output(tmp_path: Path, monkeypatch: Any) -> None:
    """A pxj that returned no array must be empty, not crash or lie.

    If r2 emitted a banner or an error instead of the int array, the read yields
    zero bytes with parsed False rather than raising -- a clean empty answer the
    caller can see, matching how the other r2 readers report an unparsable run.
    """
    binary = tmp_path / "f.bin"
    binary.write_bytes(b"MZ" + b"\x00" * 200)
    client = R2Client(executable=Path("/nonexistent-r2"))

    def run(binary: Path, commands: list[str], *, timeout: float = 30.0) -> dict[str, Any]:
        return {"raw": "[x] Cannot open", "commands": commands}

    monkeypatch.setattr(client, "run", run)
    out = client.read_bytes(binary, 0x3000, size=8)
    assert out["count"] == 0
    assert out["data"] == ""
    assert out["parsed"] is False
    assert out["short_read"] is True


def test_r2_read_rejects_bad_address_and_size(tmp_path: Path) -> None:
    """Address/size are validated before any r2 spawn, as invalid_params."""
    binary = tmp_path / "f.bin"
    binary.write_bytes(b"MZ" + b"\x00" * 200)
    client = R2Client(executable=Path("/nonexistent-r2"))
    with pytest.raises(R2Error) as neg:
        client.read_bytes(binary, -1, size=8)
    assert neg.value.code == "invalid_params"
    with pytest.raises(R2Error) as zero:
        client.read_bytes(binary, 0x10, size=0)
    assert zero.value.code == "invalid_params"
    with pytest.raises(R2Error) as huge:
        client.read_bytes(binary, 0x10, size=_MAX_READ_BYTES + 1)
    assert huge.value.code == "invalid_params"


def test_pxj_whitelist_caps_the_window() -> None:
    """The command whitelist itself caps pxj, as defense in depth.

    read_bytes clamps size before building the command, but the whitelist is the
    last gate: a bounded pxj passes, an over-cap one is refused as not
    whitelisted so no unbounded read can slip through another path.
    """
    _require_allowed_command("pxj 64 @ 0x1000")
    _require_allowed_command(f"pxj {_MAX_READ_BYTES} @ 0x1000")
    with pytest.raises(R2Error) as info:
        _require_allowed_command(f"pxj {_MAX_READ_BYTES + 1} @ 0x1000")
    assert info.value.code == "invalid_params"
