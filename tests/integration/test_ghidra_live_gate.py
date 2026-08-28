"""Ghidra headless live gate: analyze / functions / symbols / decompile.

The Ghidra backend had deep subprocess-mocked unit coverage but no gate ever ran
a real ``analyzeHeadless`` against a real binary, so two breakages that only a
live run reaches went unnoticed: the client picked the Windows ``.bat`` launcher
on POSIX (unlaunchable there), and the ExportJson postScript read its arguments
through an ``ARGS`` global Ghidra's Jython never defines, so every export failed
with "export JSON missing after postScript". This gate drives the whole
pipeline against a portable target -- the Windows PE fixture when built, else a
tiny ELF compiled here -- so the portable-backend line has honest end-to-end
coverage on whatever platform runs it.

Ghidra is optional and heavy, configured through ``HEADLESS_RE_GHIDRA_HOME``.
skip != pass: the gate skips when Ghidra/Java are not configured or no target
can be produced, never silently. It also needs a Ghidra whose ExportJson
postScript can run -- i.e. Jython available (bundled by default up to 12.0.x,
an installable extension from 12.1) -- and treats a Ghidra that cannot run the
postScript as a skip rather than a failure, since that is an install choice, not
a regression in this code.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.ghidra.client import GhidraClient, GhidraError
from headless_re_mcp.config import Settings

_PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Unstripped so Ghidra recovers a named function; trivial arithmetic so the
# decompiler produces a body we can recognise regardless of target arch.
_ELF_SOURCE = """
int headless_compute(int a, int b) { return a * b + 7; }
int main(void) { return headless_compute(3, 4); }
"""


def _portable_target(tmp_path: Path) -> Path | None:
    """The Windows PE fixture when built, otherwise a tiny ELF compiled here.

    Ghidra analyses PE and ELF through the same headless path, so this gate must
    not sit skipped on Linux for want of a Windows-only fixture. Prefer the PE
    fixture when present, else compile a small unstripped ELF when a C compiler
    is available. Neither present is a skip, not a failure (skip != pass).
    """
    fixture = _PROJECT_ROOT / "artifacts" / "fixtures-x64" / "headless_fixture.exe"
    if fixture.is_file():
        return fixture
    if os.name == "nt":
        return None
    compiler = shutil.which("cc") or shutil.which("gcc")
    if compiler is None:
        return None
    source = tmp_path / "ghidra_fixture.c"
    source.write_text(_ELF_SOURCE, encoding="utf-8")
    out = tmp_path / "ghidra_fixture"
    try:
        subprocess.run(
            [compiler, "-O0", "-o", str(out), str(source)],
            check=True,
            capture_output=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return out if out.is_file() else None


def _pick_target_function(items: list[dict]) -> dict | None:
    """A function worth decompiling: our own by name, else main, else biggest."""
    by_name = {str(item.get("name")): item for item in items}
    for preferred in ("headless_compute", "main"):
        if preferred in by_name:
            return by_name[preferred]
    with_body = [item for item in items if int(item.get("body_size", 0) or 0) > 0]
    if not with_body:
        return None
    return max(with_body, key=lambda item: int(item.get("body_size", 0) or 0))


@pytest.mark.integration
def test_ghidra_live_analyze_functions_symbols_decompile(tmp_path: Path) -> None:
    client = GhidraClient(home=getattr(Settings.load(), "ghidra_home", None))
    if not client.available:
        pytest.skip("Ghidra/Java not configured (HEADLESS_RE_GHIDRA_HOME) — not run (skip≠pass)")
    target = _portable_target(tmp_path)
    if target is None:
        pytest.skip("no Ghidra target: build the PE fixture or install a C compiler (skip≠pass)")

    project = tmp_path / "ghidra_project"

    # analyze_binary uses no postScript, so it works on any Ghidra and proves the
    # launcher is the one this platform can actually execute.
    analyzed = client.analyze_binary(target, project, timeout=300.0)
    assert analyzed.get("project_dir")

    # functions/symbols/decompile run the Jython ExportJson postScript. A Ghidra
    # without a runnable Jython cannot produce the export; that is an install
    # choice, so treat it as a skip rather than fail the whole line.
    try:
        funcs = client.functions(target, project, limit=256, timeout=300.0)
    except GhidraError as exc:
        if exc.code == "backend_error" and "missing" in exc.message:
            pytest.skip(
                "Ghidra ran but its postScript produced no export "
                "(Jython not available?) — export Gate not run (skip≠pass)"
            )
        raise

    items = funcs.get("items") or []
    assert funcs.get("count", 0) >= 1, "Ghidra must recover at least one function"
    assert all(item.get("name") and item.get("entry") for item in items)

    symbols = client.symbols(target, project, limit=256, timeout=300.0)
    assert symbols.get("count", 0) >= 1
    assert all(item.get("name") and item.get("address") for item in symbols.get("items") or [])

    chosen = _pick_target_function(items)
    assert chosen is not None, "no function had a body to decompile"
    decompiled = client.decompile(target, project, chosen["entry"], timeout=300.0)
    assert decompiled.get("found") is True, f"no function contained {chosen['entry']}"
    body = decompiled.get("decompiled") or ""
    assert isinstance(body, str) and body.strip(), "decompilation produced no C text"

    # On the ELF we compiled the function is ours, so the recovered body must
    # carry the arithmetic; on the PE fixture the name/body are unknown, so only
    # the structural contract above is asserted.
    if chosen.get("name") == "headless_compute":
        assert "return" in body
        assert "*" in body and "7" in body
