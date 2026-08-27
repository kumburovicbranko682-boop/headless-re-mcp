"""r2's plt==0 / UT64_MAX sentinels must not become a fabricated va-0 address.

radare2's ``iij`` reports every import, and for one with no PLT stub -- the
loader entry ``__libc_start_main``, a weak ``__gmon_start__`` -- it sets
``plt`` to 0. That 0 is a marker, not a location. ``enrich_r2_payload`` fed the
first non-negative address-like field into an ``Address``, so ``plt: 0`` minted
``address: {va: 0}`` and r2.imports claimed those symbols lived at the null
address -- an invented call target a reverse engineer could chase. r2 likewise
uses UT64_MAX (0xFFFFFFFFFFFFFFFF) as "no offset" for a .bss export's paddr.

These tests pin that neither sentinel becomes an Address, that a real PLT stub
still resolves, and that the raw ``plt`` field is preserved verbatim either way.
A live gate proves the same against a real radare2 reading a real ELF.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

from headless_re_mcp.backends.r2.mapping import _UT64_MAX, enrich_r2_payload
from headless_re_mcp.core.models import Architecture
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


def _pe64(tmp_path: Path) -> Path:
    pe = tmp_path / "demo64.exe"
    image = bytearray(0x200)
    image[0:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x94:0x96] = (0xF0).to_bytes(2, "little")
    image[0x98:0x9A] = (0x20B).to_bytes(2, "little")
    image[0xB0:0xB8] = (0x140000000).to_bytes(8, "little")
    pe.write_bytes(bytes(image))
    return pe


def test_import_with_plt_zero_carries_no_fabricated_address(tmp_path: Path) -> None:
    """The bug: plt 0 (no stub) used to become address {va: 0}."""
    payload = enrich_r2_payload(
        {
            "raw": json.dumps(
                [
                    {"name": "__libc_start_main", "plt": 0, "bind": "GLOBAL"},
                    {"name": "printf", "plt": 0x140001000, "bind": "GLOBAL"},
                    {"name": "__gmon_start__", "plt": 0, "bind": "WEAK"},
                ]
            ),
            "commands": ["iij"],
        },
        binary=_pe64(tmp_path),
        architecture=Architecture.X64,
    )
    items = {entry["name"]: entry for entry in payload["items"]}

    # The two stub-less imports carry no address at all, not one at va 0.
    assert "address" not in items["__libc_start_main"]
    assert "address" not in items["__gmon_start__"]
    # ...but the raw plt sentinel is preserved verbatim for a reader that wants it.
    assert items["__libc_start_main"]["plt"] == 0
    assert items["__gmon_start__"]["plt"] == 0

    # A real PLT stub still resolves to a full Address.
    assert items["printf"]["address"]["va"] == 0x140001000
    assert items["printf"]["address"]["rva"] == 0x1000


def test_ut64_max_offset_is_not_turned_into_an_address(tmp_path: Path) -> None:
    """A .bss export's paddr is UT64_MAX; only its real vaddr should map."""
    with_vaddr = enrich_r2_payload(
        {
            "raw": json.dumps(
                [{"name": "state", "vaddr": 0x140002000, "paddr": _UT64_MAX}]
            ),
            "commands": ["iEj"],
        },
        binary=_pe64(tmp_path),
        architecture=Architecture.X64,
    )
    assert with_vaddr["items"][0]["address"]["va"] == 0x140002000

    # An entry whose only offset-like field is the sentinel maps to nothing,
    # rather than to an address at 0xFFFFFFFFFFFFFFFF.
    sentinel_only = enrich_r2_payload(
        {
            "raw": json.dumps([{"name": "nobody", "paddr": _UT64_MAX}]),
            "commands": ["iEj"],
        },
        binary=_pe64(tmp_path),
        architecture=Architecture.X64,
    )
    assert "address" not in sentinel_only["items"][0]


def test_r2_imports_docstring_explains_the_plt_zero_case() -> None:
    doc = " ".join(_tool_docstring("r2.imports").split())
    assert "plt of 0" in doc or "plt 0" in doc
    assert "no address" in doc
    # The old promise of a lib field is gone; r2 5.x omits it for these imports.
    assert "va/rva/module" in doc
    assert "no integer address" in doc
