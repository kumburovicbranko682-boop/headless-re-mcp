"""r2's raw item keys must stay stable across the 5.x -> 6.x field renames.

radare2 6.x renamed two raw keys the r2.* tools pass through: ``aflj`` moved a
function's entry from ``offset`` to ``addr``, and ``iij`` moved an import's
library from ``lib`` to ``libname``. The mapped ``address`` object reads either
spelling, so the *location* survives -- but the r2.functions / r2.imports
docstrings promise ``offset`` and ``lib`` by name, and CI pins radare2 to the
distro's older 5.x where those keys still exist, so a drift here would ship a
tool whose documented fields silently vanish for anyone on a current r2.

enrich_r2_payload restores the documented spelling when only the newer one is
present. These tests feed the 6.x shape (which CI's r2 never emits) and pin
that the old, documented keys come back with the same value, and that the
docstrings still name them so the alias and the contract cannot drift apart.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

from headless_re_mcp.backends.r2.mapping import enrich_r2_payload
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


def _pe(tmp_path: Path) -> Path:
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


def test_functions_from_r2_6x_still_expose_offset(tmp_path: Path) -> None:
    """A 6.x ``aflj`` row carries ``addr``; the payload must still name ``offset``.

    The function entry is the same address either way; only the key changed.
    Restoring ``offset`` keeps r2.functions' documented field present so a
    caller enumerating functions reads the same shape on radare2 5.x and 6.x.
    """
    payload = enrich_r2_payload(
        {
            "raw": json.dumps([{"addr": 0x140001920, "name": "entry0", "size": 32}]),
            "commands": ["aflj"],
        },
        binary=_pe(tmp_path),
        architecture=Architecture.X64,
    )
    item = payload["items"][0]
    assert item["offset"] == 0x140001920
    assert item["offset"] == item["addr"]
    assert item["address"]["va"] == 0x140001920
    assert "offset" in _tool_docstring("r2.functions")


def test_functions_do_not_overwrite_an_offset_r2_already_gave(tmp_path: Path) -> None:
    """On 5.x the row already has ``offset``; the alias must not clobber it.

    The alias fills a missing key, it does not rewrite one r2 supplied. If a row
    ever carried both, ``offset`` is the authoritative documented field and the
    restore must leave it untouched rather than overwriting it from ``addr``.
    """
    payload = enrich_r2_payload(
        {
            "raw": json.dumps(
                [{"offset": 0x140001000, "addr": 0x140009999, "name": "f", "size": 8}]
            ),
            "commands": ["aflj"],
        },
        binary=_pe(tmp_path),
        architecture=Architecture.X64,
    )
    assert payload["items"][0]["offset"] == 0x140001000


def test_imports_from_r2_6x_still_expose_lib(tmp_path: Path) -> None:
    """A 6.x ``iij`` row names the library ``libname``; restore ``lib``.

    The library name is real, non-redundant attribution -- unlike the address it
    is not recoverable from any other field -- so r2.imports' documented ``lib``
    must survive the rename or a caller loses which DLL an import resolves to.
    """
    payload = enrich_r2_payload(
        {
            "raw": json.dumps(
                [{"name": "NtClose", "plt": 0x140001000, "libname": "ntdll"}]
            ),
            "commands": ["iij"],
        },
        binary=_pe(tmp_path),
        architecture=Architecture.X64,
    )
    item = payload["items"][0]
    assert item["lib"] == "ntdll"
    assert item["lib"] == item["libname"]
    assert item["address"]["va"] == 0x140001000
    assert "lib" in _tool_docstring("r2.imports")


def test_imports_do_not_overwrite_a_lib_r2_already_gave(tmp_path: Path) -> None:
    """When r2 supplies ``lib`` (5.x), the restore leaves it authoritative."""
    payload = enrich_r2_payload(
        {
            "raw": json.dumps(
                [{"name": "NtClose", "plt": 0x140001000, "lib": "ntdll", "libname": "OTHER"}]
            ),
            "commands": ["iij"],
        },
        binary=_pe(tmp_path),
        architecture=Architecture.X64,
    )
    assert payload["items"][0]["lib"] == "ntdll"
