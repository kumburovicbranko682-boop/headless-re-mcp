"""Ghidra's launcher failures must map to structured errors, not incidents.

``_run_headless`` is the single choke point every Ghidra tool goes through --
``analyze_binary`` calls it directly, and ``functions`` / ``symbols`` / ``xrefs``
/ ``decompile`` reach it through ``_export``. It wraps ``run_bounded`` and turns
its two failure modes into structured ``GhidraError``s:

* ``TimedOut`` -> ``timeout`` carrying ``killed_pids``. analyzeHeadless is a
  shell script that starts a JVM; when the deadline fires the launcher bounds
  and kills that whole tree, and the reply has to name what it stopped rather
  than reporting a bare "timed out" for a JVM that was still analysing.
* ``OSError`` -> ``backend_error``. A launcher that is present but cannot be run
  -- not marked executable, or gone between discovery and spawn -- makes Popen
  raise ``OSError``. The adapter maps it here on purpose, with a comment noting
  the parity with the jadx/apktool/jsre/windbg adapters: uncaught, it would
  surface as an ``internal_error`` incident (logged, paged) rather than the
  backend problem it is -- a bad Ghidra install miscast as a tool bug.

Neither mapping was pinned: the existing Ghidra tests drive ``run_bounded``
return values (exit codes and written JSON) but never make it raise. So dropping
the ``except OSError`` clause, or re-coding the timeout, would silently turn a
misconfigured install back into an internal_error incident or a hang report with
no killed-pid trail. These tests make ``run_bounded`` raise each failure and pin
the mapping at both entry points (the direct ``analyze_binary`` and the
``_export``-backed ``functions``).
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.ghidra.client as ghidra_client
from headless_re_mcp.backends.common.bounded_run import TimedOut


def _client(tmp_path: Path) -> ghidra_client.GhidraClient:
    home = tmp_path / "ghidra"
    (home / "support").mkdir(parents=True)
    (home / "support" / "analyzeHeadless.bat").write_text("@echo off\n", encoding="utf-8")
    client = ghidra_client.GhidraClient(home=home)
    client.java = tmp_path / "java.exe"
    client.java.write_bytes(b"")
    return client


def _binary(tmp_path: Path) -> Path:
    path = tmp_path / "sample.exe"
    path.write_bytes(b"MZ")
    return path


# Both entry points funnel through _run_headless: analyze_binary calls it
# directly, functions reaches it via _export. Parametrise so the mapping is
# pinned on both, not just the one that happens to be refactored past.
def _call_functions(client: ghidra_client.GhidraClient, binary: Path, project: Path) -> Any:
    return client.functions(binary, project)


def _call_analyze(client: ghidra_client.GhidraClient, binary: Path, project: Path) -> Any:
    return client.analyze_binary(binary, project)


_ENTRY_POINTS: list[tuple[str, Callable[..., Any]]] = [
    ("functions", _call_functions),
    ("analyze_binary", _call_analyze),
]


@pytest.mark.parametrize("name, entry", _ENTRY_POINTS, ids=[e[0] for e in _ENTRY_POINTS])
def test_a_timed_out_launcher_maps_to_timeout_with_the_killed_pids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, entry: Callable[..., Any]
) -> None:
    def raise_timeout(cmd: list[str], **kwargs: Any) -> Any:
        del cmd, kwargs
        raise TimedOut(timeout=180.0, killed=[4242, 4243])

    monkeypatch.setattr(ghidra_client, "run_bounded", raise_timeout)
    client = _client(tmp_path)

    with pytest.raises(ghidra_client.GhidraError) as caught:
        entry(client, _binary(tmp_path), tmp_path / f"proj_{name}")

    assert caught.value.code == "timeout", name
    # The JVM tree that was stopped must be named, so the caller knows the
    # analyze did not simply keep running unattended.
    assert caught.value.details.get("killed_pids") == [4242, 4243], name


@pytest.mark.parametrize("name, entry", _ENTRY_POINTS, ids=[e[0] for e in _ENTRY_POINTS])
def test_an_unlaunchable_headless_maps_to_backend_error_not_an_incident(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, entry: Callable[..., Any]
) -> None:
    def raise_oserror(cmd: list[str], **kwargs: Any) -> Any:
        del cmd, kwargs
        # What Popen raises for a launcher that exists but is not executable, or
        # that vanished between discovery and spawn.
        raise OSError(13, "Permission denied")

    monkeypatch.setattr(ghidra_client, "run_bounded", raise_oserror)
    client = _client(tmp_path)

    with pytest.raises(ghidra_client.GhidraError) as caught:
        entry(client, _binary(tmp_path), tmp_path / f"proj_{name}")

    # backend_error, not a raw OSError escaping to the service as internal_error.
    assert caught.value.code == "backend_error", name
    assert "failed to launch analyzeHeadless" in caught.value.message, name
