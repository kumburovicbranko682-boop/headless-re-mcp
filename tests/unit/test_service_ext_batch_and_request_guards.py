"""Guard branches of the batch and static-request paths in ``service_ext``.

Four narrow contracts, none of which need radare2, Ghidra or IDA installed:

* ``_r2_request`` re-checks the session *after* the r2 subprocess returns, so
  a session that was closed while radare2 ran is refused instead of having a
  backend and timeline entry recorded onto a corpse.
* ``_ghidra_export`` refuses ``xrefs``/``decompile`` without an address at the
  helper level -- the typed public wrappers cannot pass ``None``, but internal
  callers reach the helper directly and must get ``invalid_params``, not a
  crash inside the Ghidra client.
* ``batch_analyze`` bounds the batch size and reports each sample's failure on
  its own entry -- a missing file or a failed static open marks that entry,
  never the whole batch.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core import service_ext
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.service_ext import _ghidra_export


def _write_minimal_pe(path: Path) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")
    path.write_bytes(image)


@pytest.fixture
def service(tmp_path: Path) -> Any:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    svc = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    created = svc.create_session(str(binary))
    assert created.ok and created.data is not None, created.error
    svc._session_id = created.data["session"]["id"]  # type: ignore[attr-defined]
    svc._binary = binary  # type: ignore[attr-defined]
    try:
        yield svc
    finally:
        svc.close_all()


def _sid(service: Any) -> str:
    return str(service._session_id)


# ---------------------------------------------------------------------------
# _r2_request: the session is re-checked after the subprocess ran.
# ---------------------------------------------------------------------------
def test_an_r2_request_refuses_a_session_that_closed_while_r2_ran(
    service: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The pre-check passes -- the session is open when r2 starts -- and the
    close lands while the subprocess runs. Without the re-check the result
    would be recorded as a backend and timeline entry on a closed session."""
    sid = _sid(service)
    ran: list[list[str]] = []

    class _CloseOutFromUnder:
        def __init__(self, *_a: Any, **_k: Any) -> None:
            pass

        def run(
            self, binary: Path, commands: list[str], *, timeout: float = 30.0
        ) -> dict[str, Any]:
            ran.append(list(commands))
            closed = service.close_session(sid)
            assert closed.ok, closed.error
            return {"commands": list(commands), "results": ["arch x86"]}

    monkeypatch.setattr(service_ext, "R2Client", _CloseOutFromUnder)

    result = service.r2_info(sid)

    assert ran == [["i"]], "the r2 run itself completed before the refusal"
    assert result.ok is False
    assert result.error is not None
    assert "cannot run in" in result.error.message


# ---------------------------------------------------------------------------
# _ghidra_export: address-dependent modes without an address.
# ---------------------------------------------------------------------------
def test_the_ghidra_export_helper_refuses_xrefs_without_an_address(service: Any) -> None:
    result = _ghidra_export(service, _sid(service), "xrefs", limit=8, timeout=5.0)
    assert result.ok is False
    assert result.error is not None
    assert "address required" in result.error.message


def test_the_ghidra_export_helper_refuses_decompile_without_an_address(service: Any) -> None:
    result = _ghidra_export(service, _sid(service), "decompile", timeout=5.0)
    assert result.ok is False
    assert result.error is not None
    assert "address required" in result.error.message


# ---------------------------------------------------------------------------
# batch_analyze: size bound and per-entry failures.
# ---------------------------------------------------------------------------
def test_batch_analyze_rejects_more_than_32_binaries(service: Any) -> None:
    binary = str(service._binary)
    result = service.batch_analyze([binary] * 33, max_workers=1, open_static=False)
    assert result.ok is False
    assert result.error is not None
    assert "at most 32" in result.error.message


def test_batch_analyze_marks_only_the_unreadable_sample_as_failed(
    service: Any, tmp_path: Path
) -> None:
    """One bad path must not abort the batch: its entry carries the create
    error while the good sample still gets a session."""
    good = str(service._binary)
    missing = str(tmp_path / "not-there.bin")

    result = service.batch_analyze([good, missing], max_workers=1, open_static=False)

    assert result.ok is True and result.data is not None
    entries = result.data["entries"]
    assert [entry["binary"] for entry in entries] == [good, missing]
    assert entries[0]["ok"] is True and entries[0]["session_id"] is not None
    assert entries[1]["ok"] is False and entries[1]["session_id"] is None
    assert "error" in entries[1]
    assert result.data["succeeded"] == 1
    assert result.data["failed"] == 1


def test_batch_analyze_reports_a_failed_static_open_on_the_entry(service: Any) -> None:
    """With ``open_static`` requested and no IDA on the box, the session is
    still created but the entry must say the static open failed -- an entry
    marked ok with no analyser behind it would be a lie."""
    result = service.batch_analyze([str(service._binary)], max_workers=1, open_static=True)

    assert result.ok is True and result.data is not None
    (entry,) = result.data["entries"]
    assert entry["session_id"] is not None, "the session itself was created"
    assert entry["static_open"] is False
    assert entry["ok"] is False
    assert "error" in entry
    assert result.data["failed"] == 1
