"""Fail-closed coverage for the remaining model ``to_dict`` serialization guards.

``UpxResult``, ``ExeinfopeScanResult``, ``DieScanResult`` and the service-layer
``_session_json`` helper all refuse to hand a non-object payload to callers
rather than silently forwarding a malformed envelope. The happy paths run
throughout the unpack, detection, and session suites; these pin the ``TypeError``
guard itself, which a well-formed pydantic model can never trip on its own, so
the guard is driven with a patched ``model_dump``. This mirrors
``test_report_serialization_guards.py`` for the report models.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from headless_re_mcp.core.models import Architecture, Session
from headless_re_mcp.core.service import _session_json
from headless_re_mcp.detection.die import DieScanResult
from headless_re_mcp.detection.exeinfope import ExeinfopeScanResult
from headless_re_mcp.detection.models import DetectionSource, ScanMode
from headless_re_mcp.unpack.upx import UpxOperation, UpxResult

_GUARD_MATCH = "did not serialize to an object"


def _upx_result() -> UpxResult:
    now = datetime.now(UTC)
    return UpxResult(
        operation=UpxOperation.TEST,
        executable=Path("upx"),
        input_path=Path("sample.exe"),
        input_sha256="a" * 64,
        input_size=0,
        ok=True,
        stdout="tested",
        stderr="",
        returncode=0,
        started_at=now,
        finished_at=now,
    )


def _exeinfope_result() -> ExeinfopeScanResult:
    return ExeinfopeScanResult(
        path=Path("sample.exe"),
        size=0,
        mode=ScanMode.NORMAL,
        findings=(),
        source=DetectionSource(name="exeinfope", status="completed", summary="fake"),
        raw_log="",
        log_path=Path("exeinfope.log"),
        stdout="",
        stderr="",
        returncode=0,
        scanned_at=datetime.now(UTC),
    )


def _die_result() -> DieScanResult:
    return DieScanResult(
        path=Path("sample.exe"),
        size=0,
        mode=ScanMode.NORMAL,
        findings=(),
        source=DetectionSource(name="diec", status="completed", summary="fake"),
        raw={"detects": []},
        raw_json='{"detects": []}',
        stdout='{"detects": []}',
        stderr="",
        returncode=0,
        scanned_at=datetime.now(UTC),
    )


def _session() -> Session:
    return Session(binary=Path("sample.exe"), sha256="a" * 64, architecture=Architecture.X64)


def test_upx_result_to_dict_returns_the_serialized_object() -> None:
    value = _upx_result().to_dict()
    assert value["operation"] == UpxOperation.TEST.value
    assert value["ok"] is True
    assert value["input_sha256"] == "a" * 64


def test_upx_result_to_dict_refuses_a_non_object_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _upx_result()
    monkeypatch.setattr(
        UpxResult, "model_dump", lambda self, mode="python": ["not", "an", "object"]
    )
    with pytest.raises(TypeError, match=_GUARD_MATCH):
        result.to_dict()


def test_exeinfope_result_to_dict_returns_the_serialized_object() -> None:
    value = _exeinfope_result().to_dict()
    assert value["returncode"] == 0
    assert value["findings"] == []


def test_exeinfope_result_to_dict_refuses_a_non_object_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _exeinfope_result()
    monkeypatch.setattr(
        ExeinfopeScanResult, "model_dump", lambda self, mode="python": ["not", "an", "object"]
    )
    with pytest.raises(TypeError, match=_GUARD_MATCH):
        result.to_dict()


def test_die_result_to_dict_returns_the_serialized_object() -> None:
    value = _die_result().to_dict()
    assert value["raw"] == {"detects": []}
    assert value["returncode"] == 0


def test_die_result_to_dict_refuses_a_non_object_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _die_result()
    monkeypatch.setattr(
        DieScanResult, "model_dump", lambda self, mode="python": ["not", "an", "object"]
    )
    with pytest.raises(TypeError, match=_GUARD_MATCH):
        result.to_dict()


def test_session_json_returns_the_serialized_object() -> None:
    value = _session_json(_session())
    assert value["sha256"] == "a" * 64
    assert isinstance(value, dict)


def test_session_json_refuses_a_non_object_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _session()
    monkeypatch.setattr(
        Session, "model_dump", lambda self, mode="python": ["not", "an", "object"]
    )
    with pytest.raises(TypeError, match=_GUARD_MATCH):
        _session_json(session)
