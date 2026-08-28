"""ghidra.functions/symbols/xrefs must reject a non-integer limit.

The ghidra.* tool schemas type ``limit`` as an integer, but only the MCP
transport runs that pydantic validation: the agent and OpenAI-bridge transports
call the bound handler directly, so a hostile limit reaches the backend
unchecked. Before the fix ``_export_unlocked`` fed the value straight to
``int(limit)``, so a float (inf from a JSON 1e400), nan, null, a non-numeric
string, or a container raised OverflowError/ValueError/TypeError -- none a
GhidraError, so the service's ``except BaseException`` filed an internal_error
incident for what is only a bad row cap. The guard now runs before the
capability probe, so a bad limit fails fast and is rejected without Ghidra
installed.
"""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.ghidra.client as ghidra_client
from headless_re_mcp.backends.common.bounded_run import Completed
from headless_re_mcp.backends.ghidra.client import GhidraClient, GhidraError

_HOSTILE = [
    math.inf,
    -math.inf,
    math.nan,
    None,
    "abc",
    "",
    {},
    [],
    True,
    False,
]


def _binary(tmp_path: Path) -> Path:
    path = tmp_path / "sample.exe"
    path.write_bytes(b"MZ")
    return path


def _configured_client(tmp_path: Path) -> GhidraClient:
    home = tmp_path / "ghidra"
    support = home / "support"
    support.mkdir(parents=True)
    (support / "analyzeHeadless.bat").write_text("@echo off\n", encoding="utf-8")
    client = GhidraClient(home=home)
    client.java = tmp_path / "java.exe"
    client.java.write_bytes(b"")
    return client


@pytest.mark.parametrize("bad", _HOSTILE)
def test_functions_hostile_limit_is_invalid_params(tmp_path: Path, bad: object) -> None:
    """Even unconfigured, a bad limit is invalid_params, not a probe or a crash."""
    client = GhidraClient(home=None)
    with pytest.raises(GhidraError) as excinfo:
        client.functions(_binary(tmp_path), tmp_path / "project", limit=bad)  # type: ignore[arg-type]
    assert excinfo.value.code == "invalid_params"


@pytest.mark.parametrize("bad", _HOSTILE)
def test_symbols_hostile_limit_is_invalid_params(tmp_path: Path, bad: object) -> None:
    client = GhidraClient(home=None)
    with pytest.raises(GhidraError) as excinfo:
        client.symbols(_binary(tmp_path), tmp_path / "project", limit=bad)  # type: ignore[arg-type]
    assert excinfo.value.code == "invalid_params"


@pytest.mark.parametrize("bad", _HOSTILE)
def test_xrefs_hostile_limit_is_invalid_params(tmp_path: Path, bad: object) -> None:
    client = GhidraClient(home=None)
    with pytest.raises(GhidraError) as excinfo:
        client.xrefs(_binary(tmp_path), tmp_path / "project", "0x401000", limit=bad)  # type: ignore[arg-type]
    assert excinfo.value.code == "invalid_params"


def test_hostile_limit_on_a_configured_client_never_spawns_the_jvm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With Ghidra configured the pre-fix int(inf) crashed before the spawn; the
    guard now rejects it as invalid_params without recording a run."""
    calls: list[list[str]] = []

    def spy_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        calls.append([str(part) for part in cmd])
        return Completed(0, b"", b"")

    monkeypatch.setattr(ghidra_client, "run_bounded", spy_run)
    client = _configured_client(tmp_path)
    with pytest.raises(GhidraError) as excinfo:
        client.functions(_binary(tmp_path), tmp_path / "project", limit=math.inf)
    assert excinfo.value.code == "invalid_params"
    assert calls == []


def test_valid_limit_passes_the_guard_and_reaches_the_capability_check(
    tmp_path: Path,
) -> None:
    """A well-formed limit must not be turned away; it clears the guard and then
    hits the real capability gate on an unconfigured client."""
    client = GhidraClient(home=None)
    with pytest.raises(GhidraError) as excinfo:
        client.functions(_binary(tmp_path), tmp_path / "project", limit=10**9)
    assert excinfo.value.code == "capability_unavailable"
    # int-like strings are valid bounds too.
    with pytest.raises(GhidraError) as excinfo:
        client.functions(_binary(tmp_path), tmp_path / "project", limit="64")  # type: ignore[arg-type]
    assert excinfo.value.code == "capability_unavailable"
