from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

JsonObject = dict[str, Any]


class ScanMode(StrEnum):
    NORMAL = "normal"
    DEEP = "deep"
    HEURISTIC = "heuristic"
    AGGRESSIVE = "aggressive"


class FindingCategory(StrEnum):
    FILE_FORMAT = "file_format"
    PACKER = "packer"
    COMPILER = "compiler"
    LINKER = "linker"
    INSTALLER = "installer"
    OBFUSCATOR = "obfuscator"
    PROTECTOR = "protector"
    RUNTIME = "runtime"
    ANOMALY = "anomaly"


class FindingSeverity(StrEnum):
    INFO = "info"
    HINT = "hint"
    WARNING = "warning"


class DetectionEvidence(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: str
    description: str
    details: JsonObject = Field(default_factory=dict)


class DetectionFinding(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    category: FindingCategory
    name: str
    summary: str
    confidence: float = Field(ge=0.0, le=1.0)
    severity: FindingSeverity = FindingSeverity.INFO
    source: str
    evidence: tuple[DetectionEvidence, ...] = ()


class SectionSummary(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    virtual_address: int = Field(ge=0)
    virtual_size: int = Field(ge=0)
    raw_offset: int = Field(ge=0)
    raw_size: int = Field(ge=0)
    characteristics: int = Field(ge=0)
    permissions: str
    entropy: float = Field(ge=0.0, le=8.0)


class ImportSummary(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    library_count: int = Field(ge=0)
    function_count: int = Field(ge=0)
    ordinal_count: int = Field(ge=0)
    libraries: tuple[str, ...] = ()
    suspicious_apis: tuple[str, ...] = ()
    truncated: bool = False


class TlsSummary(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    present: bool
    callback_count: int = Field(ge=0)
    callbacks: tuple[int, ...] = ()
    truncated: bool = False


class SignatureSummary(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    status: str
    certificate_offset: int = Field(ge=0)
    certificate_size: int = Field(ge=0)


class PeSummary(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    machine: int = Field(ge=0)
    architecture: str
    subsystem: int = Field(ge=0)
    characteristics: int = Field(ge=0)
    dll_characteristics: int = Field(ge=0)
    image_base: int = Field(ge=0)
    image_size: int = Field(ge=0)
    entry_point_rva: int = Field(ge=0)
    entry_point_section: str | None
    entry_point_executable: bool
    section_alignment: int = Field(ge=0)
    file_alignment: int = Field(ge=0)
    linker_version: str
    sections: tuple[SectionSummary, ...]
    imports: ImportSummary
    tls: TlsSummary
    overlay_offset: int = Field(ge=0)
    overlay_size: int = Field(ge=0)
    dotnet: bool
    signature: SignatureSummary


class DetectionSource(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    status: str
    version: str | None = None
    duration_ms: int = Field(default=0, ge=0)
    summary: str | None = None
    artifact: str | None = None


class DetectionReport(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: int = 1
    path: Path
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size: int = Field(ge=0)
    scanned_at: datetime
    mode: ScanMode
    format: str
    architecture: str
    pe: PeSummary
    findings: tuple[DetectionFinding, ...]
    sources: tuple[DetectionSource, ...]
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> JsonObject:
        value = self.model_dump(mode="json")
        if not isinstance(value, dict):
            raise TypeError("detection report did not serialize to an object")
        return value