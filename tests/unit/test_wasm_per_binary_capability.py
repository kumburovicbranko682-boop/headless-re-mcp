"""wasm.wat and wasm.info each need their OWN wabt binary, resolved independently.

wabt ships ``wasm2wat`` and ``wasm-objdump`` as two separate executables, and
``WasmClient`` resolves them one at a time -- so a box can have ``wasm2wat`` on
PATH but not ``wasm-objdump`` (a partial install, a distro that packages them
apart, one symlinked but not the other). ``wat`` uses ``wasm2wat``; ``info`` uses
``wasm-objdump``. Each op therefore checks the specific tool it needs inside
``_require_input`` (``tool is None`` -> ``capability_unavailable``) and only then
narrows it with ``assert self._objdump is not None`` for the type checker.

That per-op check, not the ``available`` property, is what makes ``info`` degrade
cleanly when only ``wasm-objdump`` is missing. ``available`` reports on
``wasm2wat`` alone, so an ``info`` that leaned on it -- a plausible "just check
available" simplification -- would sail past the gate on a wasm2wat-only box and
hit the ``assert`` on a ``None`` objdump: an ``AssertionError``, which the service
files as an ``internal_error`` incident (logged, paged) rather than the plain
"this tool isn't installed" a caller can act on. The ordering matters too: the
tool check runs before the file-exists and ``\\0asm`` magic checks, so a missing
binary is reported as missing even for a perfectly valid module.

Nothing pinned this. The existing wasm tests drive both binaries present. These
pin each direction: only ``wasm2wat`` present -> ``info`` on a *valid* module is
``capability_unavailable`` (never the assert); only ``wasm-objdump`` present ->
``wat`` is ``capability_unavailable`` while ``info`` gets *past* the capability
gate to the file check, proving the resolution and the gate are per-binary.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

import headless_re_mcp.backends.jsre.client as jsre_client
from headless_re_mcp.backends.jsre.client import JsReError, WasmClient

# A real, minimal WebAssembly module: the four-byte magic plus version 1. It
# passes _looks_like_wasm, so the capability gate is the only thing that can stop
# an op on it -- which is exactly what these tests want to observe.
_VALID_WASM = b"\x00asm\x01\x00\x00\x00"


def _wabt_binary_name(tool: str) -> str:
    return tool + (".exe" if os.name == "nt" else "")


def _wabt_dir_with(tmp_path: Path, *tools: str) -> Path:
    """A wabt directory holding only the named tool stubs.

    The stubs are never executed by these tests: the missing-binary op stops at
    the capability gate, and the present-binary op is only ever driven far enough
    to reach the file-exists check, not to spawn. They exist so
    ``_resolve_wabt_tool``'s ``is_file()`` check resolves the ones that should be
    present and leaves the others ``None``.
    """
    wabt = tmp_path / "wabt"
    wabt.mkdir(exist_ok=True)
    for tool in tools:
        (wabt / _wabt_binary_name(tool)).write_text("stub", encoding="utf-8")
    return wabt


@pytest.fixture(autouse=True)
def _no_path_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin resolution to the wabt directory under test.

    ``_resolve_wabt_tool`` falls back to ``shutil.which`` when the directory does
    not hold a tool. On a CI box that actually has wabt installed that fallback
    would find the "missing" binary and defeat the test, so neutralise it: the
    only tools that resolve are the stubs a test chose to write.
    """
    monkeypatch.setattr(jsre_client.shutil, "which", lambda name: None)


def _wasm_module(tmp_path: Path) -> Path:
    module = tmp_path / "module.wasm"
    module.write_bytes(_VALID_WASM)
    return module


def test_info_degrades_when_only_wasm2wat_is_present(tmp_path: Path) -> None:
    """objdump missing, wasm2wat present: info is capability_unavailable, not the assert.

    The client reports ``available`` (that tracks wasm2wat) yet ``info`` must
    still refuse cleanly. Driving it with a *valid* module rules out the file or
    magic checks doing the refusing -- only the per-op objdump gate can, and it
    must fire before the ``assert self._objdump is not None`` two lines down.
    """
    client = WasmClient(wabt=_wabt_dir_with(tmp_path, "wasm2wat"))
    assert client.available is True
    assert client._objdump is None

    with pytest.raises(JsReError) as caught:
        client.info(_wasm_module(tmp_path))

    assert caught.value.code == "capability_unavailable"
    assert "wasm-objdump" in caught.value.message


def test_wat_degrades_when_only_wasm_objdump_is_present(tmp_path: Path) -> None:
    """wasm2wat missing, objdump present: wat is capability_unavailable...

    ...and, the other half of "per-binary", ``info`` gets *past* the capability
    gate on the same client -- it resolves objdump, so it reaches the file-exists
    check and reports ``not_found`` for a path that is not there, rather than
    ``capability_unavailable``. If resolution were shared or gated on ``available``
    these two would not disagree.
    """
    client = WasmClient(wabt=_wabt_dir_with(tmp_path, "wasm-objdump"))
    assert client.available is False
    assert client._objdump is not None

    with pytest.raises(JsReError) as caught:
        client.wat(_wasm_module(tmp_path))
    assert caught.value.code == "capability_unavailable"
    assert "wasm2wat" in caught.value.message

    with pytest.raises(JsReError) as reached:
        client.info(tmp_path / "not-there.wasm")
    assert reached.value.code == "not_found"


def test_wat_degrades_and_info_reaches_input_when_only_wasm2wat_is_present(
    tmp_path: Path,
) -> None:
    """The mirror of the objdump-only case, to pin wat's own binary the same way.

    With only wasm2wat, ``wat`` resolves it and reaches the file check
    (``not_found`` for a missing path), while ``info`` -- needing objdump -- is
    ``capability_unavailable``. Together with the test above, every op is pinned
    to check its own tool, in both present/absent directions.
    """
    client = WasmClient(wabt=_wabt_dir_with(tmp_path, "wasm2wat"))

    with pytest.raises(JsReError) as reached:
        client.wat(tmp_path / "not-there.wasm")
    assert reached.value.code == "not_found"

    with pytest.raises(JsReError) as caught:
        client.info(_wasm_module(tmp_path))
    assert caught.value.code == "capability_unavailable"
