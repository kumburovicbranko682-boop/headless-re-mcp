from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Generic, TypeVar
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Architecture(StrEnum):
    X86 = "x86"
    X64 = "x64"


class SessionState(StrEnum):
    CREATED = "created"
    OPENING = "opening"
    READY = "ready"
    RUNNING = "running"
    SUSPENDED = "suspended"
    CLOSING = "closing"
    CLOSED = "closed"
    FAILED = "failed"


class BackendKind(StrEnum):
    IDA = "ida"
    X64DBG = "x64dbg"
    RADARE2 = "radare2"
    GHIDRA = "ghidra"
    FRIDA = "frida"
    WINDBG = "windbg"
    APK = "apk"
    ADB = "adb"
    WEB = "web"
    PROXY = "proxy"


class TargetKind(StrEnum):
    """What kind of artifact a session is bound to.

    The debugger-oriented tools assume a local PE with a known machine type.
    Android and browser targets share the session lifecycle, artifacts and
    knowledge store but cannot answer PE questions, so every tool that needs a
    PE says so explicitly rather than failing deep inside a backend.

    BINARY is any other local executable image -- ELF, Mach-O -- that the
    portable backends (radare2, Ghidra) analyse the same way they analyse a PE.
    It has a local file but no PE machine type, so PE-only tools (IDA, x64dbg)
    refuse it with a target_mismatch while r2.* and ghidra.* run against it.
    """

    PE = "pe"
    APK = "apk"
    WEB = "web"
    BINARY = "binary"


class TargetMismatch(RuntimeError):
    """A tool was invoked against a session whose target cannot serve it."""

    def __init__(
        self,
        message: str,
        *,
        expected: tuple[TargetKind, ...] = (),
        actual: TargetKind | None = None,
    ) -> None:
        super().__init__(message)
        self.code = "target_mismatch"
        self.message = message
        self.details: dict[str, Any] = {
            "expected_targets": [item.value for item in expected],
            "actual_target": actual.value if actual is not None else None,
        }


class Address(BaseModel):
    model_config = ConfigDict(frozen=True)

    module: str | None = None
    rva: int | None = Field(default=None, ge=0)
    va: int | None = Field(default=None, ge=0)
    architecture: Architecture | None = None

    @model_validator(mode="after")
    def require_coordinate(self) -> Address:
        if self.rva is None and self.va is None:
            raise ValueError("an address requires rva or va")
        if self.rva is not None and not self.module:
            raise ValueError("module is required when rva is present")
        return self

    def resolve(self, module_base: int | None = None) -> int:
        if self.va is not None:
            return self.va
        if module_base is None or self.rva is None:
            raise ValueError("module_base is required to resolve an RVA")
        return module_base + self.rva


class ModuleSelector(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        json_schema_extra={
            "anyOf": [
                {"required": ["base"]},
                {"required": ["path"]},
                {"required": ["name"]},
            ]
        },
    )

    base: int | None = Field(
        default=None,
        gt=0,
        strict=True,
        description="Exact loaded module base address",
    )
    path: str | None = Field(
        default=None,
        max_length=32767,
        strict=True,
        description="Exact normalized runtime module path",
    )
    name: str | None = Field(
        default=None,
        max_length=512,
        strict=True,
        description="Unique runtime module file name",
    )
    sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-fA-F]{64}$",
        strict=True,
        description="Optional expected SHA-256 for file identity verification",
    )

    @field_validator("path", "name")
    @classmethod
    def require_nonblank_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("module selector text must not be blank")
        return normalized

    @field_validator("sha256")
    @classmethod
    def normalize_sha256(cls, value: str | None) -> str | None:
        return value.casefold() if value is not None else None

    @model_validator(mode="after")
    def require_locator(self) -> ModuleSelector:
        if self.base is None and self.path is None and self.name is None:
            raise ValueError("module selector requires base, path, or name")
        return self


class BackendHandle(BaseModel):
    kind: BackendKind
    worker_id: str
    pid: int | None = None
    endpoint: str | None = None
    capabilities: frozenset[str] = frozenset()


class Session(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex)
    target: TargetKind = TargetKind.PE
    binary: Path | None = None
    locator: str | None = None
    sha256: str | None = None
    architecture: Architecture | None = None
    state: SessionState = SessionState.CREATED
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    backends: dict[BackendKind, BackendHandle] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def require_binary(self) -> Path:
        """Return the on-disk artifact, or explain why this session has none."""
        if self.binary is None:
            raise TargetMismatch(
                f"session target {self.target.value} is not backed by a local file",
                expected=(TargetKind.PE, TargetKind.APK, TargetKind.BINARY),
                actual=self.target,
            )
        return self.binary

    def require_target(self, *expected: TargetKind) -> Path:
        if self.target not in expected:
            names = ", ".join(item.value for item in expected)
            raise TargetMismatch(
                f"this tool requires a {names} session, but the session target is "
                f"{self.target.value}",
                expected=expected,
                actual=self.target,
            )
        return self.require_binary()

    def require_pe(self) -> Path:
        return self.require_target(TargetKind.PE)

    def require_architecture(self) -> Architecture:
        if self.architecture is None:
            raise TargetMismatch(
                f"session target {self.target.value} has no PE machine type",
                expected=(TargetKind.PE,),
                actual=self.target,
            )
        return self.architecture

    def require_locator(self) -> str:
        if not self.locator:
            raise TargetMismatch(
                f"session target {self.target.value} has no locator",
                expected=(TargetKind.WEB,),
                actual=self.target,
            )
        return self.locator


def _clip_error_text(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return f"{value[:limit]}...({len(value)} chars)"


class RpcError(BaseModel):
    code: str
    message: str
    details: dict[str, Any] = Field(default_factory=dict)
    retryable: bool = False

    @field_validator("message")
    @classmethod
    def bound_message(cls, value: str) -> str:
        # Caller-controlled text (a session id, a path) used to be copied into
        # the envelope verbatim. Measured: a 200,000 character session_id made
        # a 400,229 byte error, twice, because the same string sat in message
        # and in details.
        return _clip_error_text(value, 2048)

    @field_validator("details")
    @classmethod
    def bound_details(cls, value: dict[str, Any]) -> dict[str, Any]:
        return {
            key: _clip_error_text(item, 1024) if isinstance(item, str) else item
            for key, item in value.items()
        }


T = TypeVar("T")


class Result(BaseModel, Generic[T]):
    ok: bool
    data: T | None = None
    error: RpcError | None = None
    meta: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_envelope(self) -> Result[T]:
        if self.ok and self.error is not None:
            raise ValueError("successful result cannot contain an error")
        if not self.ok and self.error is None:
            raise ValueError("failed result requires an error")
        return self
