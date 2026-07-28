"""Detection / packer classify / unpack recommend ops."""

from __future__ import annotations

from pathlib import Path
from typing import Any


from headless_re_mcp.core.models import Result, RpcError
from headless_re_mcp.core.results import _failure, _success
from headless_re_mcp.core.session import file_sha256
from headless_re_mcp.detection import (
    DetectionSource,
    FindingCategory,
    PeFormatError,
    ScanMode,
    scan_pe,
)
from headless_re_mcp.detection.die import DieScanError, DieScanResult
from headless_re_mcp.detection.exeinfope import (
    ExeinfopeScanError,
    ExeinfopeScanResult,
)


JsonObject = dict[str, Any]


def _detection_timeout(timeout: float) -> float:
    from headless_re_mcp.core.service import _detection_timeout as real

    return real(timeout)


def _write_die_artifact(*args: Any, **kwargs: Any) -> Path:
    from headless_re_mcp.core.service import _write_die_artifact as real

    return real(*args, **kwargs)


def _write_exeinfope_artifact(*args: Any, **kwargs: Any) -> Path:
    from headless_re_mcp.core.service import _write_exeinfope_artifact as real

    return real(*args, **kwargs)


def _exeinfope_log_path(artifact_root: Path, session_id: str) -> Path:
    from headless_re_mcp.core.service import _exeinfope_log_path as real

    return real(artifact_root, session_id)


class DetectAnalysisMixin:
    """Detection / packer classify / unpack recommend ops."""

    def detect_scan(
        self,
        session_id: str,
        *,
        mode: ScanMode | str = ScanMode.NORMAL,
        use_die: bool = True,
        use_exeinfope: bool = False,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        """Run built-in PE detection plus optional DIE / Exeinfo PE second opinions."""
        try:
            session = self.registry.get(session_id)
            parsed_mode = ScanMode(mode)
            bounded_timeout = _detection_timeout(timeout)
            if type(use_die) is not bool:
                raise ValueError("use_die must be a boolean")
            if type(use_exeinfope) is not bool:
                raise ValueError("use_exeinfope must be a boolean")

            current_sha = file_sha256(session.binary)
            if current_sha != session.sha256:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="input_changed",
                        message="session input changed after session creation",
                        details={
                            "session_id": session_id,
                            "expected_sha256": session.sha256,
                            "actual_sha256": current_sha,
                        },
                    ),
                )

            report = scan_pe(session.binary, mode=parsed_mode)
            findings = list(report.findings)
            sources = list(report.sources)
            warnings = list(report.warnings)
            if not use_die:
                sources.append(
                    DetectionSource(
                        name="diec",
                        status="disabled",
                        summary="external Detect It Easy scan was disabled by the caller",
                    )
                )
            elif self.settings.diec is None:
                sources.append(
                    DetectionSource(
                        name="diec",
                        status="unavailable",
                        summary="no external Detect It Easy CLI is configured",
                    )
                )
                warnings.append(
                    "Detect It Easy is unavailable; only bounded built-in PE findings are returned"
                )
            else:
                try:
                    die_result = self._die_scanner(
                        self.settings.diec,
                        session.binary,
                        mode=parsed_mode,
                        timeout=bounded_timeout,
                    )
                except DieScanError as exc:
                    sources.append(
                        DetectionSource(
                            name="diec",
                            status="failed",
                            summary=str(exc),
                        )
                    )
                    warnings.append(
                        "Detect It Easy scan failed "
                        f"({exc.code}); built-in findings are still valid"
                    )
                else:
                    findings.extend(die_result.findings)
                    die_source = die_result.source
                    try:
                        artifact = _write_die_artifact(
                            self.settings.artifact_root,
                            session_id,
                            die_result,
                        )
                    except OSError as exc:
                        warnings.append(f"could not persist bounded Detect It Easy artifact: {exc}")
                    else:
                        die_source = die_source.model_copy(update={"artifact": artifact})
                    sources.append(die_source)

            if not use_exeinfope:
                sources.append(
                    DetectionSource(
                        name="exeinfope",
                        status="disabled",
                        summary=(
                            "optional Exeinfo PE second-opinion scan was disabled by the caller"
                        ),
                    )
                )
            elif self.settings.exeinfope is None:
                sources.append(
                    DetectionSource(
                        name="exeinfope",
                        status="unavailable",
                        summary="no external Exeinfo PE executable is configured",
                    )
                )
                warnings.append(
                    "Exeinfo PE is unavailable; DIE/built-in findings are returned "
                    "without that cross-check"
                )
            else:
                try:
                    log_path = _exeinfope_log_path(self.settings.artifact_root, session_id)
                    exeinfo_result = self._exeinfope_scanner(
                        self.settings.exeinfope,
                        session.binary,
                        log_path=log_path,
                        mode=parsed_mode,
                        timeout=bounded_timeout,
                    )
                except ExeinfopeScanError as exc:
                    sources.append(
                        DetectionSource(
                            name="exeinfope",
                            status="failed",
                            summary=str(exc),
                        )
                    )
                    warnings.append(
                        "Exeinfo PE second-opinion scan failed "
                        f"({exc.code}); other findings remain valid and are not "
                        "merged into one verdict"
                    )
                else:
                    findings.extend(exeinfo_result.findings)
                    exeinfo_source = exeinfo_result.source
                    try:
                        artifact = _write_exeinfope_artifact(
                            self.settings.artifact_root,
                            session_id,
                            exeinfo_result,
                        )
                    except OSError as exc:
                        warnings.append(f"could not persist bounded Exeinfo PE artifact: {exc}")
                    else:
                        exeinfo_source = exeinfo_source.model_copy(update={"artifact": artifact})
                    sources.append(exeinfo_source)

            merged = report.model_copy(
                update={
                    "findings": tuple(findings),
                    "sources": tuple(sources),
                    "warnings": tuple(warnings),
                }
            )
            return _success(
                {
                    "report": merged.to_dict(),
                    "die_enabled": use_die,
                    "exeinfope_enabled": use_exeinfope,
                    "claims_universal_unpack": False,
                },
                session_id=session_id,
                backend="detection",
            )
        except (PeFormatError, DieScanError, ExeinfopeScanError) as exc:
            return _failure(exc, session_id=session_id, backend="detection")
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend="detection")

    def detect_explain(
        self,
        session_id: str,
        finding_id: str,
        *,
        mode: ScanMode | str = ScanMode.NORMAL,
        use_die: bool = True,
        use_exeinfope: bool = False,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        """Return one finding and its evidence from a fresh bounded detection scan."""
        if not isinstance(finding_id, str) or not finding_id.strip():
            return _failure(ValueError("finding_id must not be blank"), session_id=session_id)
        result = self.detect_scan(
            session_id,
            mode=mode,
            use_die=use_die,
            use_exeinfope=use_exeinfope,
            timeout=timeout,
        )
        if not result.ok or result.data is None:
            return result
        report = result.data.get("report")
        if not isinstance(report, dict):
            return _failure(
                RuntimeError("detection scan returned an invalid report"),
                session_id=session_id,
                backend="detection",
            )
        findings = report.get("findings")
        if not isinstance(findings, list):
            return _failure(
                RuntimeError("detection report has an invalid findings list"),
                session_id=session_id,
                backend="detection",
            )
        finding = next(
            (item for item in findings if isinstance(item, dict) and item.get("id") == finding_id),
            None,
        )
        if finding is None:
            return Result[JsonObject](
                ok=False,
                error=RpcError(
                    code="finding_not_found",
                    message=f"detection finding not found: {finding_id}",
                    details={"finding_id": finding_id},
                ),
            )
        return _success(
            {"finding": finding, "sha256": report.get("sha256"), "path": report.get("path")},
            session_id=session_id,
            backend="detection",
        )

    def packer_classify(
        self,
        session_id: str,
        *,
        mode: ScanMode | str = ScanMode.NORMAL,
        use_die: bool = True,
        use_exeinfope: bool = False,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        """Return packer/protector/obfuscator candidates without forcing a conclusion."""
        result = self.detect_scan(
            session_id,
            mode=mode,
            use_die=use_die,
            use_exeinfope=use_exeinfope,
            timeout=timeout,
        )
        if not result.ok or result.data is None:
            return result
        report = result.data.get("report")
        if not isinstance(report, dict):
            return _failure(
                RuntimeError("detection scan returned an invalid report"),
                session_id=session_id,
                backend="detection",
            )
        findings = report.get("findings")
        if not isinstance(findings, list):
            return _failure(
                RuntimeError("detection report has an invalid findings list"),
                session_id=session_id,
                backend="detection",
            )
        candidates = [
            finding
            for finding in findings
            if isinstance(finding, dict)
            and finding.get("category")
            in {
                FindingCategory.PACKER.value,
                FindingCategory.PROTECTOR.value,
                FindingCategory.OBFUSCATOR.value,
            }
        ]
        return _success(
            {
                "candidates": candidates,
                "conclusion": "candidates" if candidates else "none_detected",
                "report_sha256": report.get("sha256"),
                "claims_universal_unpack": False,
            },
            session_id=session_id,
            backend="detection",
        )

    def unpack_recommend(
        self,
        session_id: str,
        *,
        mode: ScanMode | str = ScanMode.NORMAL,
        use_die: bool = True,
        timeout: float = 30.0,
        force_route: str | None = None,
    ) -> Result[JsonObject]:
        """Return a non-authoritative unpack route from detection candidates."""
        classified = self.packer_classify(
            session_id,
            mode=mode,
            use_die=use_die,
            timeout=timeout,
        )
        if not classified.ok or classified.data is None:
            return classified
        candidates = classified.data.get("candidates")
        if not isinstance(candidates, list):
            candidates = []
        try:
            session = self.registry.get(session_id)
            pe_report = scan_pe(session.binary)
            pe_vm_like = pe_suggests_vm_protector(
                finding_ids=tuple(item.id for item in pe_report.findings),
                section_names=tuple(section.name for section in pe_report.pe.sections),
            )
            recommendation = recommend_unpack_route(
                candidates,
                pe_dotnet=pe_report.pe.dotnet,
                pe_vm_like=pe_vm_like,
                force_route=force_route,
            )
            return _success(
                {
                    "recommendation": recommendation.to_dict(),
                    "candidates": candidates,
                    "pe_vm_like": pe_vm_like,
                    "force_route": force_route,
                    "authoritative": False,
                },
                session_id=session_id,
                backend="unpack",
            )
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend="unpack")

