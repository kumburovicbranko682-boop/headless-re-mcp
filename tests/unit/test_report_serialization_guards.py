"""Fail-closed coverage for the report models' to_dict serialization guards.

``DetectionReport.to_dict`` and ``UnpackRecommendation.to_dict`` refuse to hand
a non-object payload to callers rather than silently returning a malformed
envelope. The happy paths run throughout the detection and unpack suites; these
pin the TypeError guard itself, which a well-formed pydantic model can never
trip on its own.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.detection.models import (
    DetectionReport,
    ImportSummary,
    PeSummary,
    ScanMode,
    SignatureSummary,
    TlsSummary,
)
from headless_re_mcp.unpack.recommend import UnpackRecommendation


def _recommendation() -> UnpackRecommendation:
    return UnpackRecommendation(route="none", confidence=0.0, rationale="no packer signals")


def _report() -> DetectionReport:
    pe = PeSummary(
        machine=0x8664,
        architecture="x64",
        subsystem=3,
        characteristics=0x22,
        dll_characteristics=0x160,
        image_base=0x140000000,
        image_size=0x1000,
        entry_point_rva=0x100,
        entry_point_section=".text",
        entry_point_executable=True,
        section_alignment=0x1000,
        file_alignment=0x200,
        linker_version="14.0",
        sections=(),
        imports=ImportSummary(library_count=0, function_count=0, ordinal_count=0),
        tls=TlsSummary(present=False, callback_count=0),
        overlay_offset=0,
        overlay_size=0,
        dotnet=False,
        signature=SignatureSummary(status="absent", certificate_offset=0, certificate_size=0),
    )
    return DetectionReport(
        path=Path("sample.exe"),
        sha256="ab" * 32,
        size=1024,
        scanned_at=datetime(2026, 1, 1, tzinfo=UTC),
        mode=ScanMode.NORMAL,
        format="pe",
        architecture="x64",
        pe=pe,
        findings=(),
        sources=(),
    )


def test_recommendation_to_dict_returns_the_serialized_object() -> None:
    value = _recommendation().to_dict()
    assert value["route"] == "none"
    assert value["authoritative"] is False


def test_recommendation_to_dict_refuses_a_non_object_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recommendation = _recommendation()
    monkeypatch.setattr(
        UnpackRecommendation,
        "model_dump",
        lambda self, mode="python": ["not", "an", "object"],
    )
    with pytest.raises(TypeError, match="did not serialize to an object"):
        recommendation.to_dict()


def test_detection_report_to_dict_returns_the_serialized_object() -> None:
    value = _report().to_dict()
    assert value["format"] == "pe"
    assert value["pe"]["architecture"] == "x64"


def test_detection_report_to_dict_refuses_a_non_object_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = _report()

    def _broken(self: DetectionReport, mode: str = "python") -> list[Any]:
        return ["not", "an", "object"]

    monkeypatch.setattr(DetectionReport, "model_dump", _broken)
    with pytest.raises(TypeError, match="did not serialize to an object"):
        report.to_dict()
