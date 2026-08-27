"""Post-scan branching in the detection service, driven with a stubbed scan.

``detect_explain`` and ``packer_classify`` both run a fresh bounded detection
scan and then shape its report; ``unpack_recommend`` builds on the second. That
shaping -- a blank finding id, a scan that failed, a report or findings list
that came back the wrong type, a finding that is or is not present, the
packer/protector/obfuscator filter and its conclusion -- is pure given the
scan's Result, so it is exercised here by stubbing ``detect_scan`` rather than
launching DIE / Exeinfo PE. ``_register_detection_artifact`` turning a
registration failure into a warning is covered the same way.
"""

from __future__ import annotations

from typing import Any

import pytest

from headless_re_mcp.core.results import _failure, _success
from headless_re_mcp.core.service_detect import (
    DetectAnalysisMixin,
    _register_detection_artifact,
)
from headless_re_mcp.detection import FindingCategory


class _StubbedScan(DetectAnalysisMixin):
    """A detection mixin whose scan is canned, so only the shaping runs."""

    def __init__(self, scan_result: Any, registry: Any = None) -> None:
        self._scan_result = scan_result
        if registry is not None:
            self.registry = registry

    def detect_scan(self, session_id: str, **_kwargs: Any) -> Any:
        return self._scan_result


def _report_result(report: Any) -> Any:
    return _success({"report": report}, session_id="s", backend="detection")


# ---- detect_explain ---------------------------------------------------------


def test_a_blank_finding_id_is_rejected_before_scanning() -> None:
    svc = _StubbedScan(_report_result({"findings": []}))
    result = svc.detect_explain("s", "   ")
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_request"


def test_a_failed_scan_is_returned_unchanged() -> None:
    failed = _failure(RuntimeError("scanner down"), session_id="s", backend="detection")
    svc = _StubbedScan(failed)
    result = svc.detect_explain("s", "F1")
    assert result is failed


def test_a_report_that_is_not_a_dict_is_an_error() -> None:
    svc = _StubbedScan(_report_result(["not", "a", "dict"]))
    result = svc.detect_explain("s", "F1")
    assert not result.ok
    assert result.error is not None
    assert "invalid report" in result.error.message


def test_a_findings_field_that_is_not_a_list_is_an_error() -> None:
    svc = _StubbedScan(_report_result({"findings": {"oops": True}}))
    result = svc.detect_explain("s", "F1")
    assert not result.ok
    assert result.error is not None
    assert "invalid findings list" in result.error.message


def test_a_missing_finding_reports_finding_not_found() -> None:
    report = {"findings": [{"id": "other"}], "sha256": "ab", "path": "/x"}
    svc = _StubbedScan(_report_result(report))
    result = svc.detect_explain("s", "F1")
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "finding_not_found"
    assert result.error.details["finding_id"] == "F1"


def test_a_present_finding_comes_back_with_its_report_context() -> None:
    finding = {"id": "F1", "name": "UPX"}
    report = {"findings": [finding], "sha256": "deadbeef", "path": "/tmp/sample"}
    svc = _StubbedScan(_report_result(report))
    result = svc.detect_explain("s", "F1")
    assert result.ok
    assert result.data is not None
    assert result.data["finding"] == finding
    assert result.data["sha256"] == "deadbeef"
    assert result.data["path"] == "/tmp/sample"


# ---- _register_detection_artifact ------------------------------------------


def test_a_registration_failure_becomes_a_warning_not_an_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The helper re-imports _register_capture from service_ext each call, so
    # patching it there is what the call sees.
    import headless_re_mcp.core.service_ext as service_ext

    monkeypatch.setattr(
        service_ext, "_register_capture", lambda *a, **k: {"artifact_error": "disk full"}
    )
    warnings = _register_detection_artifact(
        object(), "s", "/tmp/die.json", kind="die_raw", tool="die"
    )
    assert warnings == [
        "could not register the bounded die artifact for collection: disk full"
    ]


def test_a_clean_registration_yields_no_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    import headless_re_mcp.core.service_ext as service_ext

    monkeypatch.setattr(
        service_ext, "_register_capture", lambda *a, **k: {"artifact_id": "cap-1"}
    )
    warnings = _register_detection_artifact(
        object(), "s", "/tmp/die.json", kind="die_raw", tool="die"
    )
    assert warnings == []


# ---- packer_classify --------------------------------------------------------


class _FakeSession:
    architecture = None


class _FakeRegistry:
    def __init__(self) -> None:
        self.updated: list[Any] = []

    def get(self, _session_id: str) -> _FakeSession:
        return _FakeSession()

    def update_metadata(self, _session_id: str, hint: Any) -> None:
        self.updated.append(hint)


def test_packer_classify_rejects_a_non_dict_report() -> None:
    svc = _StubbedScan(_report_result("nope"), registry=_FakeRegistry())
    result = svc.packer_classify("s")
    assert not result.ok
    assert result.error is not None
    assert "invalid report" in result.error.message


def test_packer_classify_keeps_only_packer_like_findings() -> None:
    report = {
        "findings": [
            {"id": "a", "category": FindingCategory.PACKER.value},
            {"id": "b", "category": FindingCategory.PROTECTOR.value},
            {"id": "c", "category": "compiler"},
        ],
        "sha256": "ab",
    }
    registry = _FakeRegistry()
    svc = _StubbedScan(_report_result(report), registry=registry)
    result = svc.packer_classify("s")
    assert result.ok
    assert result.data is not None
    ids = [c["id"] for c in result.data["candidates"]]
    assert ids == ["a", "b"]
    assert result.data["conclusion"] == "candidates"
    assert result.data["claims_universal_unpack"] is False
    assert registry.updated, "a stealth hint should have been persisted"


def test_packer_classify_reports_none_detected_when_nothing_matches() -> None:
    report = {"findings": [{"id": "c", "category": "compiler"}], "sha256": "ab"}
    svc = _StubbedScan(_report_result(report), registry=_FakeRegistry())
    result = svc.packer_classify("s")
    assert result.ok
    assert result.data is not None
    assert result.data["candidates"] == []
    assert result.data["conclusion"] == "none_detected"
