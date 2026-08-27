"""The agent transport invokes tool handlers directly and never enforces the
``timeout`` schema bound (``le=1800`` for apk.*, ``le=1200`` for js unpack). A
deadline that skipped that check used to reach ``run_bounded`` intact, so a
jadx / apktool / node child could keep a core busy and a lock on the sample long
after the orchestrator abandoned the worker thread at its own ceiling. Each
subprocess client now re-applies the ceiling before it starts the child.
"""

from __future__ import annotations

import math
from pathlib import Path

import pytest

import headless_re_mcp.backends.apktool.client as apktool_client
import headless_re_mcp.backends.jadx.client as jadx_client
import headless_re_mcp.backends.jsre.client as jsre_client
from headless_re_mcp.backends.common.bounded_run import Completed, bound_timeout


def test_bound_timeout_caps_the_high_end_and_leaves_sane_values_alone() -> None:
    assert bound_timeout(10**9, ceiling=1800.0) == 1800.0
    assert bound_timeout(1800.0, ceiling=1800.0) == 1800.0
    assert bound_timeout(42.0, ceiling=1800.0) == 42.0


def test_bound_timeout_collapses_non_finite_deadlines_to_the_ceiling() -> None:
    assert bound_timeout(math.inf, ceiling=1200.0) == 1200.0
    assert bound_timeout(math.nan, ceiling=1200.0) == 1200.0


def test_bound_timeout_leaves_a_non_positive_value_for_run_bounded_to_reject() -> None:
    # run_bounded treats <= 0 as an immediate timeout; the clamp does not turn a
    # zero deadline into the ceiling, which would run a would-be instant call for
    # the full budget.
    assert bound_timeout(0.0, ceiling=1800.0) == 0.0
    assert bound_timeout(-5.0, ceiling=1800.0) == -5.0


def _capture(monkeypatch: pytest.MonkeyPatch, module: object) -> dict[str, float]:
    seen: dict[str, float] = {}

    def fake_run(
        cmd: list[str], *, timeout: float, creationflags: int = 0, **_: object
    ) -> Completed:
        seen["timeout"] = timeout
        return Completed(returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr(module, "run_bounded", fake_run)
    return seen


def test_apktool_run_clamps_an_agent_supplied_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _capture(monkeypatch, apktool_client)
    apktool_client._run(["apktool", "d"], timeout=10**9)
    assert seen["timeout"] == apktool_client._MAX_TIMEOUT_S == 1800.0


def test_jsre_run_clamps_an_agent_supplied_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _capture(monkeypatch, jsre_client)
    jsre_client._run(["node", "deob.js"], timeout=math.inf)
    assert seen["timeout"] == jsre_client._MAX_TIMEOUT_S == 1200.0


def test_jadx_run_clamps_an_agent_supplied_deadline(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen = _capture(monkeypatch, jadx_client)
    executable = tmp_path / "jadx"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")
    client = jadx_client.JadxClient(executable)
    client._run(apk, ["--output-dir", str(tmp_path / "out")], tmp_path / "out", timeout=10**9)
    assert seen["timeout"] == jadx_client._MAX_TIMEOUT_S == 1800.0


def test_an_in_range_deadline_reaches_the_child_unchanged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = _capture(monkeypatch, apktool_client)
    apktool_client._run(["apktool", "d"], timeout=120.0)
    assert seen["timeout"] == 120.0
