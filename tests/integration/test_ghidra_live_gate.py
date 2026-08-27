"""Ghidra live gate: analyze + bounded JSON export on any host. skip != pass.

Ghidra is a *portable* backend: analyzeHeadless plus a Java export script that
runs on Linux, macOS and Windows alike, unlike the Windows-only idalib/x64dbg
chain. This gate proves the whole surface end to end -- launcher discovery,
import/analyze, and the functions/symbols/xrefs/decompile exports -- against a
PE that is committed in-tree, so it actually runs on a Linux CI runner whenever
a Ghidra install is present instead of only on Windows.

It skips (never silently passes) when Ghidra is not configured, and prefers the
Windows-built fixture when that exists but falls back to the committed PE.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.ghidra.client import GhidraClient
from headless_re_mcp.config import Settings

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_BUILT_FIXTURE = _PROJECT_ROOT / "artifacts" / "fixtures-x64" / "headless_fixture.exe"
_COMMITTED_FIXTURE = _PROJECT_ROOT / "fixtures" / "upx" / "console_fixture-x64.pre-upx.exe"
# analyzeHeadless does a full import + auto-analysis per call, and each export
# tool re-imports, so give the JVM real headroom on a shared CI box.
_TIMEOUT = 300.0


def _client() -> GhidraClient:
    client = GhidraClient(home=getattr(Settings.load(), "ghidra_home", None))
    if not client.available:
        pytest.skip("Ghidra analyzeHeadless not configured — live Gate not run (skip != pass)")
    return client


def _gate_fixture() -> Path:
    if _BUILT_FIXTURE.is_file():
        return _BUILT_FIXTURE
    if _COMMITTED_FIXTURE.is_file():
        return _COMMITTED_FIXTURE
    pytest.skip(f"no Ghidra fixture available: {_BUILT_FIXTURE} nor {_COMMITTED_FIXTURE}")


@pytest.mark.integration
def test_ghidra_analyze_imports_the_binary(tmp_path: Path) -> None:
    client = _client()
    fixture = _gate_fixture()
    result = client.analyze_binary(fixture, tmp_path / "proj", timeout=_TIMEOUT)
    # The project is deleted after analyze; the note is the contract the tool
    # descriptions promise (do not read what this produced).
    assert "deleted" in result["note"]


@pytest.mark.integration
def test_ghidra_functions_and_symbols_export(tmp_path: Path) -> None:
    client = _client()
    fixture = _gate_fixture()

    funcs = client.functions(fixture, tmp_path / "fn", limit=16, timeout=_TIMEOUT)
    assert funcs.get("count", 0) >= 1
    first = funcs["items"][0]
    # The Java export replaced a Jython script; assert the exact field contract
    # the client and tool catalog promise so a silent shape drift is caught.
    assert set(first) >= {"name", "entry", "body_size"}
    assert isinstance(first["body_size"], int)

    syms = client.symbols(fixture, tmp_path / "sym", limit=16, timeout=_TIMEOUT)
    assert syms.get("count", 0) >= 1
    sym = syms["items"][0]
    assert set(sym) >= {"name", "address", "type"}


@pytest.mark.integration
def test_ghidra_xrefs_and_decompile_at_a_real_function(tmp_path: Path) -> None:
    client = _client()
    fixture = _gate_fixture()

    funcs = client.functions(fixture, tmp_path / "fn", limit=64, timeout=_TIMEOUT)
    entry = funcs["items"][0]["entry"]

    xrefs = client.xrefs(fixture, tmp_path / "xr", entry, limit=16, timeout=_TIMEOUT)
    assert isinstance(xrefs.get("items"), list)
    assert isinstance(xrefs.get("has_more"), bool)
    for ref in xrefs["items"]:
        assert set(ref) >= {"from", "to", "type"}

    decompiled = client.decompile(fixture, tmp_path / "dc", entry, timeout=_TIMEOUT)
    assert "decompiled" in decompiled
    assert decompiled.get("truncated") is False
    assert decompiled.get("function")


@pytest.mark.integration
def test_ghidra_decompile_and_xrefs_at_a_non_function_address_stay_empty(tmp_path: Path) -> None:
    """A bad target must fail soft: empty result, no crash, no internal_error.

    Agents routinely point decompile/xrefs at an address that turns out to be
    data, padding, or below the image base. 0x0 is in no function and has no
    references, so the export must come back as a clean empty envelope -- not an
    exception and not a half-formed object. A regression that let the Java export
    throw (or the client surface internal_error) on a missing function would be
    caught here.
    """
    client = _client()
    fixture = _gate_fixture()

    decompiled = client.decompile(fixture, tmp_path / "dc0", "0x0", timeout=_TIMEOUT)
    assert decompiled["mode"] == "decompile"
    assert decompiled["decompiled"] == ""
    assert decompiled["truncated"] is False
    # No function contains 0x0, so the name/entry pair is omitted rather than
    # echoed as empty strings an agent might mistake for a real function.
    assert "function" not in decompiled

    xrefs = client.xrefs(fixture, tmp_path / "xr0", "0x0", limit=8, timeout=_TIMEOUT)
    assert xrefs["count"] == 0
    assert xrefs["items"] == []
    assert xrefs["has_more"] is False
