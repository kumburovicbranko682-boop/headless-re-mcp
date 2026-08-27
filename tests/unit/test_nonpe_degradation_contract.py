"""When a non-PE backend is absent, its tools must degrade, never crash.

The README promises the optional backends "degrade to an envelope" rather than
blocking readiness, and every non-PE client is written to raise
``capability_unavailable`` when its executable is missing. Nothing pinned that
end to end, though: a refactor that let a raw ``FileNotFoundError`` escape the
client would surface to an agent as an ``internal_error`` incident -- "file a
bug" -- instead of the honest "install this backend". This forces every
CLI-backed non-PE tool into the absent state deterministically (all backend
paths unset, ``shutil.which`` stubbed to find nothing) and asserts the service
returns a clean ``capability_unavailable`` envelope, never ``internal_error``
and never a raised exception.

adbutils / androguard / frida / playwright / mitmproxy are Python modules, not
CLIs, so ``shutil.which`` does not gate them; their absence is covered by the
per-backend degradation tests. This gate covers the shell-out backends -- r2,
Ghidra, webcrack, wabt -- whose availability is exactly a ``which`` lookup.
"""

from __future__ import annotations

import shutil
from collections.abc import Callable
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Result
from headless_re_mcp.core.service import AnalysisService, JsonObject


def _write_minimal_pe(path: Path, machine: int = 0x8664) -> None:
    """A byte-valid PE so session creation succeeds without any backend."""
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = machine.to_bytes(2, "little")
    path.write_bytes(image)


def _service_with_no_backends(tmp_path: Path) -> AnalysisService:
    # Every optional backend path defaults to None on Settings; naming the PE
    # ones here documents that the whole optional surface is off, not just some.
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        r2=None,
        ghidra_home=None,
        webcrack=None,
        wabt=None,
        artifact_root=tmp_path / "artifacts",
    )
    return AnalysisService(settings)


def test_shellout_nonpe_tools_degrade_to_capability_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Every non-PE client resolves its executable through shutil.which; stubbing
    # it to None makes "backend absent" deterministic regardless of what the
    # host actually has on PATH, so this gate means the same thing everywhere.
    monkeypatch.setattr(shutil, "which", lambda *_args, **_kwargs: None)

    pe = tmp_path / "sample.exe"
    _write_minimal_pe(pe)
    js = tmp_path / "app.js"
    js.write_text("var x = 1;", encoding="utf-8")
    wasm = tmp_path / "mod.wasm"
    wasm.write_bytes(b"\x00asm\x01\x00\x00\x00")

    service = _service_with_no_backends(tmp_path)
    try:
        created = service.create_session(str(pe))
        assert created.ok, created.error
        assert created.data is not None
        session_id = created.data["session"]["id"]

        # (label, call) so a failure names the exact tool that misbehaved.
        checks: list[tuple[str, Callable[[], Result[JsonObject]]]] = [
            ("r2.open", lambda: service.r2_open(session_id)),
            ("r2.info", lambda: service.r2_info(session_id)),
            ("r2.functions", lambda: service.r2_functions(session_id)),
            ("r2.strings", lambda: service.r2_strings(session_id)),
            ("r2.imports", lambda: service.r2_imports(session_id)),
            ("r2.exports", lambda: service.r2_exports(session_id)),
            ("r2.disasm", lambda: service.r2_disasm(session_id, 0x1000)),
            ("r2.xrefs", lambda: service.r2_xrefs(session_id, 0x1000)),
            ("ghidra.analyze", lambda: service.ghidra_analyze(session_id)),
            ("ghidra.functions", lambda: service.ghidra_functions(session_id)),
            ("ghidra.symbols", lambda: service.ghidra_symbols(session_id)),
            ("ghidra.xrefs", lambda: service.ghidra_xrefs(session_id, "0x1000")),
            ("ghidra.decompile", lambda: service.ghidra_decompile(session_id, "main")),
            ("js.deobfuscate", lambda: service.js_deobfuscate(str(js))),
            ("js.beautify", lambda: service.js_beautify(str(js))),
            ("js.unpack_bundle", lambda: service.js_unpack_bundle(str(js))),
            ("wasm.wat", lambda: service.wasm_wat(str(wasm))),
            ("wasm.info", lambda: service.wasm_info(str(wasm))),
        ]
        for label, call in checks:
            result = call()
            assert not result.ok, f"{label} unexpectedly succeeded with no backend"
            assert result.error is not None, label
            assert result.error.code == "capability_unavailable", (
                f"{label} degraded with {result.error.code!r}, not capability_unavailable "
                f"(internal_error here would tell an agent to file a bug)"
            )
    finally:
        service.close_all()
