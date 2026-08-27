"""The service layer forwards the r2 analysis pass and fails closed on abuse.

The tool layer's ``analysis_pass`` is proven to reach the service, and the
client is proven to validate and run the pass -- this pins the seam between
them: each session-based r2 method hands the caller's pass to the client
verbatim (default staying ``aa``), and a pass the allowlist rejects comes back
as a structured ``invalid_params`` failure without ever spawning radare2.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.r2.client as r2_module
from headless_re_mcp.backends.common.bounded_run import Completed
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


def _write_minimal_pe(path: Path) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")
    path.write_bytes(image)


def test_r2_service_methods_pass_the_analysis_choice_to_the_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_r2 = tmp_path / "r2"
    fake_r2.write_bytes(b"")
    monkeypatch.setenv("HEADLESS_RE_R2", str(fake_r2))
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)

    service = AnalysisService(Settings.load())
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None
    session_id = str(created.data["session"]["id"])

    scripts: list[str] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        script = next(cmd[i + 1] for i, arg in enumerate(cmd) if arg == "-c")
        scripts.append(script)
        return Completed(0, b"[]", b"")

    monkeypatch.setattr(r2_module, "run_bounded", fake_run)

    # The default stays the shallow pass on every method.
    assert service.r2_xrefs_from(session_id, 0x1000).ok
    assert scripts[-1] == "aa\naxffj @ 4096\nq"

    # A caller-chosen pass reaches the spawned script verbatim, per method.
    assert service.r2_disasm(session_id, 0x1000, count=4, analysis="aaa").ok
    assert scripts[-1] == "aaa\npdj 4 @ 4096\nq"
    assert service.r2_xrefs(session_id, 0x1000, analysis="aar").ok
    assert scripts[-1] == "aar\naxj @ 4096\nq"
    assert service.r2_xrefs_to(session_id, 0x1000, analysis="aac").ok
    assert scripts[-1] == "aac\naxtj @ 4096\nq"
    assert service.r2_xrefs_from(session_id, 0x1000, analysis="aaa").ok
    assert scripts[-1] == "aaa\naxffj @ 4096\nq"

    # A pass the allowlist rejects is a structured failure, not a spawn: the
    # client refuses before launching, and the service maps that refusal to
    # the invalid_params envelope every r2 error takes.
    spawned_before = len(scripts)
    denied = service.r2_xrefs_from(session_id, 0x1000, analysis="aaa;!echo pwned")
    assert not denied.ok and denied.error is not None
    assert denied.error.code == "invalid_params", denied.error
    assert "not whitelisted" in denied.error.message, denied.error
    assert len(scripts) == spawned_before, scripts[spawned_before:]
