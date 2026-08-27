"""The doctor must not call webcrack ready when node cannot run it.

webcrack is a Node CLI: the client launches it directly and it shells out to
``node`` (it needs Node 22 or 24). The old probe found the ``webcrack`` launcher
and reported a plain "detected"; on a host with the launcher but no ``node`` on
PATH every js.* call then failed at launch, with nothing in the doctor to have
warned -- and node is checked nowhere else, so the webcrack probe is the only
place that gap can surface. These pin that it now does.
"""

from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path

import pytest

import headless_re_mcp.doctor as doctor_module
from headless_re_mcp.config import Settings
from headless_re_mcp.doctor import ProbeStatus, probe_webcrack, run_doctor

_EXE = ".cmd" if os.name == "nt" else ""


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    base = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )
    return replace(base, **overrides)


def _which(monkeypatch: pytest.MonkeyPatch, resolver) -> None:
    monkeypatch.setattr(doctor_module.shutil, "which", resolver)


def test_configured_webcrack_without_node_stays_detected_but_flags_node(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """webcrack present, node absent: detected (not ready) with a Node remediation."""
    _which(monkeypatch, lambda _cmd: None)
    webcrack = tmp_path / f"webcrack{_EXE}"
    webcrack.write_bytes(b"")

    probe = probe_webcrack(_settings(tmp_path, webcrack=webcrack))

    assert probe.status == ProbeStatus.DETECTED
    assert probe.details["node"] is None
    assert "node is not on PATH" in probe.summary
    assert "Node.js" in (probe.remediation or "")


def test_configured_webcrack_with_node_reports_node_and_no_remediation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    node = "/usr/local/bin/node"
    _which(monkeypatch, lambda cmd: node if cmd == "node" else None)
    webcrack = tmp_path / f"webcrack{_EXE}"
    webcrack.write_bytes(b"")

    probe = probe_webcrack(_settings(tmp_path, webcrack=webcrack))

    assert probe.status == ProbeStatus.DETECTED
    assert probe.details["node"] == node
    assert "node is not on PATH" not in probe.summary
    assert probe.remediation is None


def test_missing_webcrack_is_left_untouched_and_never_mentions_node(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No launcher at all is a plain MISSING; node is moot until webcrack resolves."""
    _which(monkeypatch, lambda _cmd: None)

    probe = probe_webcrack(_settings(tmp_path))

    assert probe.status == ProbeStatus.MISSING
    assert "node" not in probe.details


def test_webcrack_found_on_path_still_checks_for_node(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The reachable case: webcrack is on PATH from npm, but the service has no node.

    The launcher resolves through PATH rather than a configured path, so the node
    check has to run on that branch too -- not only for configured tools.
    """
    _which(monkeypatch, lambda cmd: "/opt/npm/bin/webcrack" if cmd == "webcrack" else None)

    probe = probe_webcrack(_settings(tmp_path))

    assert probe.status == ProbeStatus.DETECTED
    assert "command detected" in probe.summary
    assert "node is not on PATH" in probe.summary
    assert probe.details["node"] is None


def test_run_doctor_routes_webcrack_through_the_node_aware_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End to end: a configured webcrack with no node reads as detected-not-ready."""
    _which(monkeypatch, lambda _cmd: None)
    webcrack = tmp_path / f"webcrack{_EXE}"
    webcrack.write_bytes(b"")

    report = run_doctor(_settings(tmp_path, webcrack=webcrack))
    by_name = {probe.name: probe for probe in report.probes}

    assert by_name["webcrack"].status == ProbeStatus.DETECTED
    assert by_name["webcrack"].details["node"] is None
    assert "node is not on PATH" in by_name["webcrack"].summary
