"""``wasm.info`` and ``wasm.wat`` invoke *distinct* wabt tools, resolved per name.

``WasmClient(wabt)`` resolves two different binaries from the one ``wabt``
argument and each entry point runs its own::

    self._wasm2wat = _resolve_wabt_tool(wabt, "wasm2wat")
    self._objdump = _resolve_wabt_tool(wabt, "wasm-objdump")
    ...
    def wat(...):  _run([str(self._wasm2wat), str(resolved)], ...)
    def info(...): _run([str(self._objdump), "-h", "-x", str(resolved)], ...)

Two contracts live here and every existing wasm test leaves both inert:

* **Each entry point runs the right tool, with the right flags.** ``wat`` must
  spawn ``wasm2wat`` and ``info`` must spawn ``wasm-objdump -h -x`` -- they are
  different programs with different output, and ``info`` prints nothing useful
  without both ``-h`` (section headers) and ``-x`` (section details). The current
  tests pass a single binary path and stub ``run_bounded`` with a fake that
  *ignores its argv* and returns canned bytes, so swapping the two tools, or
  dropping ``-x``, changes nothing they observe.

* **A wabt *directory* resolves each tool by its own name.** Operators point the
  setting at a wabt install (or its ``bin/``), not at one executable;
  ``_resolve_wabt_tool`` then joins ``wabt / name`` (and falls back to
  ``wabt / "bin" / name``). No test passes a directory, so the join -- and the
  fact that ``wasm2wat`` and ``wasm-objdump`` resolve to *separate* files under
  it -- is never exercised.

These capture the argv from a directory-configured client, so the tool
selection, the ``-h -x`` flags, and the directory resolution are all pinned.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import patch

from headless_re_mcp.backends.common.bounded_run import Completed
from headless_re_mcp.backends.jsre.client import WasmClient


def _wabt_dir(tmp_path: Path, *, under_bin: bool) -> Path:
    """A wabt directory holding both tools, either directly or under bin/."""
    root = tmp_path / "wabt"
    holder = (root / "bin") if under_bin else root
    holder.mkdir(parents=True)
    (holder / "wasm2wat").write_bytes(b"")
    (holder / "wasm-objdump").write_bytes(b"")
    return root


def _module(tmp_path: Path) -> Path:
    module = tmp_path / "m.wasm"
    module.write_bytes(b"\x00asm\x01\x00\x00\x00")
    return module


def _capture() -> tuple[list[list[str]], Any]:
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        calls.append([str(part) for part in cmd])
        return Completed(0, b"(module)", b"")

    return calls, fake_run


def test_info_spawns_wasm_objdump_with_headers_and_details(tmp_path: Path) -> None:
    """``info`` runs ``wasm-objdump -h -x <module>`` -- not wasm2wat, not fewer flags."""
    wabt = _wabt_dir(tmp_path, under_bin=False)
    module = _module(tmp_path)
    calls, fake_run = _capture()

    with patch("headless_re_mcp.backends.jsre.client.run_bounded", fake_run):
        WasmClient(wabt).info(module)

    assert len(calls) == 1
    argv = calls[0]
    assert Path(argv[0]).name == "wasm-objdump"
    assert argv[1:] == ["-h", "-x", str(module)]


def test_wat_spawns_wasm2wat(tmp_path: Path) -> None:
    """``wat`` runs ``wasm2wat <module>`` -- the other tool, no objdump flags."""
    wabt = _wabt_dir(tmp_path, under_bin=False)
    module = _module(tmp_path)
    calls, fake_run = _capture()

    with patch("headless_re_mcp.backends.jsre.client.run_bounded", fake_run):
        WasmClient(wabt).wat(module)

    assert len(calls) == 1
    argv = calls[0]
    assert Path(argv[0]).name == "wasm2wat"
    assert argv[1:] == [str(module)]
    assert "-h" not in argv and "-x" not in argv


def test_a_wabt_install_root_resolves_each_tool_under_bin(tmp_path: Path) -> None:
    """Pointed at an install root, each tool resolves to its own file in bin/.

    The two entry points must not collapse onto one binary: ``wat`` picks
    ``bin/wasm2wat`` and ``info`` picks ``bin/wasm-objdump``.
    """
    wabt = _wabt_dir(tmp_path, under_bin=True)
    module = _module(tmp_path)
    calls, fake_run = _capture()

    client = WasmClient(wabt)
    assert client._wasm2wat == wabt / "bin" / "wasm2wat"
    assert client._objdump == wabt / "bin" / "wasm-objdump"

    with patch("headless_re_mcp.backends.jsre.client.run_bounded", fake_run):
        client.wat(module)
        client.info(module)

    assert Path(calls[0][0]).name == "wasm2wat"
    assert Path(calls[1][0]).name == "wasm-objdump"
