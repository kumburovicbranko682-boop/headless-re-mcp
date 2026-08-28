"""Caller timeouts are bounded at the CLI-adapter boundary.

The apk (jadx/apktool), web (webcrack/wabt), and radare2 CLI adapters take a
``timeout`` from the tool arguments and hand it to ``run_bounded``. The MCP
schema declares ``0 < timeout <= max``, but the agent transport invokes handlers
straight from model arguments with no schema enforcement, the same gap
``frida._bound_timeout`` already guards. A non-positive value would otherwise
make ``run_bounded`` launch a JVM/node/r2 only to kill it at once and report a
misleading timeout, and a huge one would let a tool that hangs on hostile input
hold a worker for as long as the caller named.

The windbg (cdb) adapter shares this contract -- it clamps at its ``_run_dump``
(le=300) and ``_run_process`` (le=120) chokepoints -- but its tests need a
stubbed cdb and dump file, so they live with the other cdb guards in
``test_windbg_input_guards.py`` rather than being duplicated here.
"""

from __future__ import annotations

import math
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.apktool import client as apktool_mod
from headless_re_mcp.backends.common.bounded_run import InvalidTimeout, clamp_cli_timeout
from headless_re_mcp.backends.jadx import client as jadx_mod
from headless_re_mcp.backends.jsre import client as jsre_mod
from headless_re_mcp.backends.r2 import client as r2_mod


class _Recorder:
    """Stand in for run_bounded, capturing the deadline it was handed."""

    def __init__(self) -> None:
        self.timeouts: list[float] = []

    def __call__(self, cmd: list[str], *, timeout: float, creationflags: int = 0, **_: Any) -> Any:
        self.timeouts.append(timeout)
        return SimpleNamespace(
            stdout=b"", stderr=b"", returncode=0, stdout_truncated=False, stderr_truncated=False
        )


class TestClampCliTimeout:
    def test_a_value_in_range_passes_through(self) -> None:
        assert clamp_cli_timeout(30.0, maximum=600.0) == 30.0

    def test_a_value_over_the_ceiling_is_capped(self) -> None:
        assert clamp_cli_timeout(10**9, maximum=600.0) == 600.0

    def test_non_positive_and_nan_are_rejected(self) -> None:
        for bad in (0.0, -1.0, -600.0, math.nan):
            with pytest.raises(InvalidTimeout):
                clamp_cli_timeout(bad, maximum=600.0)


class TestApktoolRunBoundsTheTimeout:
    def test_a_non_positive_timeout_is_refused_before_spawning(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        recorder = _Recorder()
        monkeypatch.setattr(apktool_mod, "run_bounded", recorder)
        with pytest.raises(apktool_mod.ApktoolError) as info:
            apktool_mod._run(["apktool", "d"], timeout=-1.0)
        assert info.value.code == "invalid_params"
        assert recorder.timeouts == []

    def test_a_huge_timeout_is_capped_to_the_schema_ceiling(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        recorder = _Recorder()
        monkeypatch.setattr(apktool_mod, "run_bounded", recorder)
        apktool_mod._run(["apktool", "d"], timeout=10**9)
        assert recorder.timeouts == [apktool_mod._MAX_TIMEOUT_S]


class TestJsReRunBoundsTheTimeout:
    def test_a_non_positive_timeout_is_refused_before_spawning(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        recorder = _Recorder()
        monkeypatch.setattr(jsre_mod, "run_bounded", recorder)
        with pytest.raises(jsre_mod.JsReError) as info:
            jsre_mod._run(["webcrack", "a.js"], timeout=0.0)
        assert info.value.code == "invalid_params"
        assert recorder.timeouts == []

    def test_the_ceiling_is_the_one_the_caller_passes(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        recorder = _Recorder()
        monkeypatch.setattr(jsre_mod, "run_bounded", recorder)
        # js.deobfuscate / wasm.* default to 600; js.unpack_bundle asks for 1200.
        jsre_mod._run(["webcrack", "a.js"], timeout=10**9)
        jsre_mod._run(["webcrack", "-o"], timeout=10**9, maximum=jsre_mod._MAX_UNPACK_TIMEOUT_S)
        assert recorder.timeouts == [jsre_mod._MAX_TIMEOUT_S, jsre_mod._MAX_UNPACK_TIMEOUT_S]


class TestJadxRunBoundsTheTimeout:
    def test_a_non_positive_timeout_is_refused_before_the_capability_check(
        self, tmp_path: Path
    ) -> None:
        # The guard is the first thing _run does, so an unconfigured jadx still
        # reports the bad parameter rather than capability_unavailable.
        client = jadx_mod.JadxClient(None)
        with pytest.raises(jadx_mod.JadxError) as info:
            client._run(tmp_path / "app.apk", [], tmp_path / "out", timeout=-5.0)
        assert info.value.code == "invalid_params"


class TestR2RunBoundsTheTimeout:
    """r2 shares run_bounded with its siblings but was missed by the first pass.

    Every r2 tool schema declares ``0 < timeout <= 120``; the run() method fed
    that straight into run_bounded, so a non-positive timeout from the agent
    transport spawned r2 and then reported ``timeout`` for what was really a bad
    parameter.
    """

    def test_a_non_positive_timeout_is_refused_before_the_capability_check(
        self, tmp_path: Path
    ) -> None:
        # Guard first, so even an unconfigured r2 names the bad parameter rather
        # than capability_unavailable -- matching the jadx contract.
        client = r2_mod.R2Client(executable=None)
        binary = tmp_path / "sample.bin"
        binary.write_bytes(b"\x7fELF")
        with pytest.raises(r2_mod.R2Error) as info:
            client.run(binary, ["i"], timeout=-1.0)
        assert info.value.code == "invalid_params"

    def test_a_huge_timeout_is_capped_to_the_schema_ceiling(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        recorder = _Recorder()
        monkeypatch.setattr(r2_mod, "run_bounded", recorder)
        binary = tmp_path / "sample.bin"
        binary.write_bytes(b"\x7fELF")
        # A dummy executable file makes .available true without needing r2 on
        # the host; run_bounded is mocked, so it is never actually launched.
        fake_r2 = tmp_path / "r2"
        fake_r2.write_text("#!/bin/sh\n")
        client = r2_mod.R2Client(executable=fake_r2)
        client.run(binary, ["i"], timeout=10**9)
        assert recorder.timeouts == [r2_mod._MAX_TIMEOUT_S]
