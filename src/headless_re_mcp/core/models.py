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
    binary: Path
    sha256: str
    architecture: Architecture
    state: SessionState = SessionState.CREATED
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    backends: dict[BackendKind, BackendHandle] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class RpcError(BaseModel):
    code: str
    message: str
    details: dict[str, Any] = Field(default_factory=dict)
    retryable: bool = False


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
