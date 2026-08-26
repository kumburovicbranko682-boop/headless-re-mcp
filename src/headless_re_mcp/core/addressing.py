from __future__ import annotations

import ntpath
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from headless_re_mcp.core.models import (
    Architecture,
    BackendKind,
    ModuleSelector,
    Session,
)
from headless_re_mcp.core.session import detect_pe_architecture, file_sha256

JsonObject = dict[str, Any]
CoordinateKind = Literal["static", "runtime"]
RebasedCoordinateKind = Literal["preferred", "runtime"]
ModuleMatchBasis = Literal["base", "path", "name"]


class AddressSyncError(ValueError):
    def __init__(self, code: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.code = code
        self.details = details


@dataclass(frozen=True, slots=True)
class ModuleIdentity:
    name: str
    path: str
    sha256: str
    architecture: Architecture

    @classmethod
    def from_session(cls, session: Session) -> ModuleIdentity:
        binary = session.require_pe()
        path = str(binary)
        return cls(
            # Runtime module data can contain Windows paths even when a Linux
            # host is inspecting persisted session metadata.
            name=ntpath.basename(path) or binary.name,
            path=path,
            sha256=session.sha256 or "",
            architecture=session.require_architecture(),
        )

    def to_dict(self) -> JsonObject:
        return {
            "name": self.name,
            "path": self.path,
            "sha256": self.sha256,
            "architecture": self.architecture.value,
        }


@dataclass(frozen=True, slots=True)
class RuntimeModule:
    base: int
    size: int
    name: str
    path: str

    def to_dict(self) -> JsonObject:
        return {
            "base": self.base,
            "size": self.size,
            "name": self.name,
            "path": self.path,
        }


@dataclass(frozen=True, slots=True)
class RuntimeModuleCatalog:
    modules: tuple[RuntimeModule, ...]

    @classmethod
    def from_result(cls, payload: object) -> RuntimeModuleCatalog:
        if not isinstance(payload, dict):
            raise AddressSyncError(
                "module_list_invalid",
                "x64dbg module result must be an object",
            )
        raw_modules = payload.get("modules")
        if not isinstance(raw_modules, list):
            raise AddressSyncError(
                "module_list_invalid",
                "x64dbg module result does not contain a modules array",
            )
        count = _require_integer(
            payload.get("count"),
            field="count",
            code="module_list_invalid",
        )
        if count != len(raw_modules):
            raise AddressSyncError(
                "module_list_invalid",
                "x64dbg module count does not match the modules array",
                count=count,
                actual=len(raw_modules),
            )
        modules = tuple(
            _runtime_module(raw, index=index)
            for index, raw in enumerate(raw_modules)
        )
        bases = [module.base for module in modules]
        if len(bases) != len(set(bases)):
            raise AddressSyncError(
                "module_list_invalid",
                "x64dbg module list contains duplicate base addresses",
            )
        return cls(modules=modules)

    def to_dict(self) -> JsonObject:
        return {
            "modules": [module.to_dict() for module in self.modules],
            "count": len(self.modules),
        }

    def select(self, selector: ModuleSelector) -> tuple[RuntimeModule, ModuleMatchBasis]:
        candidates = self.modules
        if selector.base is not None:
            basis: ModuleMatchBasis = "base"
            candidates = tuple(
                module for module in candidates if module.base == selector.base
            )
        elif selector.path is not None:
            basis = "path"
            expected_path = _normalize_windows_path(selector.path)
            candidates = tuple(
                module
                for module in candidates
                if _normalize_windows_path(module.path) == expected_path
            )
        else:
            assert selector.name is not None
            basis = "name"
            expected_name = selector.name.casefold()
            candidates = tuple(
                module
                for module in candidates
                if _runtime_module_name(module).casefold() == expected_name
            )

        if not candidates:
            raise AddressSyncError(
                "module_not_found",
                "no loaded runtime module matches the explicit selector",
                selector=selector.model_dump(mode="json", exclude_none=True),
            )
        if len(candidates) > 1:
            raise AddressSyncError(
                "module_ambiguous",
                "multiple loaded runtime modules match the explicit selector",
                selector=selector.model_dump(mode="json", exclude_none=True),
                count=len(candidates),
                bases=[module.base for module in candidates],
            )

        module = candidates[0]
        mismatches: JsonObject = {}
        if selector.path is not None and (
            _normalize_windows_path(module.path)
            != _normalize_windows_path(selector.path)
        ):
            mismatches["path"] = module.path
        if selector.name is not None and (
            _runtime_module_name(module).casefold() != selector.name.casefold()
        ):
            mismatches["name"] = _runtime_module_name(module)
        if mismatches:
            raise AddressSyncError(
                "module_identity_mismatch",
                "the selected runtime module does not satisfy all identity constraints",
                selector=selector.model_dump(mode="json", exclude_none=True),
                actual=mismatches,
            )
        return module, basis


@dataclass(frozen=True, slots=True)
class RebasedModuleMapping:
    identity: ModuleIdentity
    preferred_base: int
    image_size: int
    runtime: RuntimeModule
    match_basis: ModuleMatchBasis

    @property
    def rebase_delta(self) -> int:
        return self.runtime.base - self.preferred_base

    def to_dict(self) -> JsonObject:
        return {
            "module": self.identity.to_dict(),
            "match_basis": self.match_basis,
            "rebase_delta": self.rebase_delta,
            "preferred": {
                "base": self.preferred_base,
                "size": self.image_size,
                "name": self.identity.name,
                "path": self.identity.path,
            },
            "runtime": self.runtime.to_dict(),
        }

    def translate(self, source: RebasedCoordinateKind, address: int) -> JsonObject:
        _require_address(address)
        source_base = self.preferred_base if source == "preferred" else self.runtime.base
        target_base = self.runtime.base if source == "preferred" else self.preferred_base
        if not source_base <= address < source_base + self.image_size:
            raise AddressSyncError(
                "address_out_of_range",
                f"address 0x{address:X} is outside the {source} module range",
                coordinate=source,
                address=address,
                base=source_base,
                size=self.image_size,
            )
        rva = address - source_base
        target_address = target_base + rva
        preferred_address = address if source == "preferred" else target_address
        runtime_address = target_address if source == "preferred" else address
        return {
            "module": self.identity.to_dict(),
            "rva": rva,
            "rebase_delta": self.rebase_delta,
            "source": source,
            "target": "runtime" if source == "preferred" else "preferred",
            "match_basis": self.match_basis,
            "preferred": {
                "base": self.preferred_base,
                "size": self.image_size,
                "address": preferred_address,
                "name": self.identity.name,
                "path": self.identity.path,
            },
            "runtime": {
                **self.runtime.to_dict(),
                "address": runtime_address,
            },
        }


@dataclass(frozen=True, slots=True)
class ModuleAddressSpace:
    backend: BackendKind
    base: int
    size: int
    name: str
    path: str

    def to_rva(self, address: int) -> int:
        _require_address(address)
        if not self.base <= address < self.base + self.size:
            raise AddressSyncError(
                "address_out_of_range",
                f"address 0x{address:X} is outside the {self.backend.value} module range",
                backend=self.backend.value,
                address=address,
                base=self.base,
                size=self.size,
            )
        return address - self.base

    def from_rva(self, rva: int) -> int:
        _require_address(rva, field="rva")
        if rva >= self.size:
            raise AddressSyncError(
                "address_out_of_range",
                f"RVA 0x{rva:X} is outside the {self.backend.value} module range",
                backend=self.backend.value,
                rva=rva,
                base=self.base,
                size=self.size,
            )
        return self.base + rva

    def coordinate(self, address: int) -> JsonObject:
        return {
            "backend": self.backend.value,
            "base": self.base,
            "size": self.size,
            "address": address,
            "name": self.name,
            "path": self.path,
        }


@dataclass(frozen=True, slots=True)
class ModuleMapping:
    identity: ModuleIdentity
    static: ModuleAddressSpace
    runtime: ModuleAddressSpace
    match_basis: Literal["path", "name"]

    def translate(self, source: CoordinateKind, address: int) -> JsonObject:
        source_space, target_space = (
            (self.static, self.runtime)
            if source == "static"
            else (self.runtime, self.static)
        )
        rva = source_space.to_rva(address)
        target_address = target_space.from_rva(rva)
        static_address = address if source == "static" else target_address
        runtime_address = target_address if source == "static" else address
        return {
            "module": self.identity.to_dict(),
            "rva": rva,
            "rebase_delta": self.runtime.base - self.static.base,
            "source": source,
            "target": "runtime" if source == "static" else "static",
            "match_basis": self.match_basis,
            "static": self.static.coordinate(static_address),
            "runtime": self.runtime.coordinate(runtime_address),
        }


def build_main_module_mapping(
    session: Session,
    static_metadata: JsonObject,
    runtime_module_result: JsonObject,
    runtime_metadata: JsonObject,
) -> ModuleMapping:
    identity = ModuleIdentity.from_session(session)
    _validate_runtime_architecture(identity, runtime_metadata)
    static_base = _require_integer(
        static_metadata.get("image_base"),
        field="image_base",
        code="static_metadata_invalid",
    )
    catalog = RuntimeModuleCatalog.from_result(runtime_module_result)
    runtime_module, match_basis = _select_main_module(identity, catalog.modules)
    runtime_base = runtime_module.base
    runtime_size = runtime_module.size
    runtime_name = runtime_module.name or identity.name
    runtime_path = runtime_module.path

    return ModuleMapping(
        identity=identity,
        static=ModuleAddressSpace(
            backend=BackendKind.IDA,
            base=static_base,
            size=runtime_size,
            name=identity.name,
            path=identity.path,
        ),
        runtime=ModuleAddressSpace(
            backend=BackendKind.X64DBG,
            base=runtime_base,
            size=runtime_size,
            name=runtime_name,
            path=runtime_path,
        ),
        match_basis=match_basis,
    )


def build_rebased_module_mapping(
    runtime_module_result: JsonObject,
    runtime_metadata: JsonObject,
    selector: ModuleSelector,
) -> RebasedModuleMapping:
    catalog = RuntimeModuleCatalog.from_result(runtime_module_result)
    runtime_module, match_basis = catalog.select(selector)
    module_path = _resolve_runtime_module_path(runtime_module.path)
    architecture, preferred_base, image_size = _read_pe_image_layout(module_path)
    runtime_architecture = _runtime_architecture(runtime_metadata)
    if architecture != runtime_architecture:
        raise AddressSyncError(
            "architecture_mismatch",
            "selected module and x64dbg backend architectures do not match",
            expected=runtime_architecture.value,
            actual=architecture.value,
        )
    if image_size != runtime_module.size:
        raise AddressSyncError(
            "module_size_mismatch",
            "loaded module size does not match the selected PE image",
            path=str(module_path),
            expected=image_size,
            actual=runtime_module.size,
        )

    sha256 = file_sha256(module_path)
    if selector.sha256 is not None and sha256 != selector.sha256:
        raise AddressSyncError(
            "module_identity_mismatch",
            "selected module SHA-256 does not match the explicit selector",
            path=str(module_path),
            expected=selector.sha256,
            actual=sha256,
        )
    identity = ModuleIdentity(
        name=runtime_module.name or module_path.name,
        path=str(module_path),
        sha256=sha256,
        architecture=architecture,
    )
    return RebasedModuleMapping(
        identity=identity,
        preferred_base=preferred_base,
        image_size=image_size,
        runtime=runtime_module,
        match_basis=match_basis,
    )


def _runtime_architecture(runtime_metadata: JsonObject) -> Architecture:
    raw_architecture = runtime_metadata.get("architecture")
    if not isinstance(raw_architecture, str):
        raise AddressSyncError(
            "runtime_metadata_invalid",
            "x64dbg metadata does not contain a valid architecture",
            architecture=raw_architecture,
        )
    try:
        return Architecture(raw_architecture.casefold())
    except ValueError as exc:
        raise AddressSyncError(
            "runtime_metadata_invalid",
            "x64dbg metadata contains an unsupported architecture",
            architecture=raw_architecture,
        ) from exc


def _validate_runtime_architecture(
    identity: ModuleIdentity,
    runtime_metadata: JsonObject,
) -> None:
    runtime_architecture = _runtime_architecture(runtime_metadata)
    if runtime_architecture != identity.architecture:
        raise AddressSyncError(
            "architecture_mismatch",
            "session binary and x64dbg backend architectures do not match",
            expected=identity.architecture.value,
            actual=runtime_architecture.value,
        )


def _select_main_module(
    identity: ModuleIdentity,
    modules: tuple[RuntimeModule, ...],
) -> tuple[RuntimeModule, Literal["path", "name"]]:
    expected_path = _normalize_windows_path(identity.path)
    path_matches = tuple(
        module
        for module in modules
        if _normalize_windows_path(module.path) == expected_path
    )
    if len(path_matches) == 1:
        return path_matches[0], "path"
    if len(path_matches) > 1:
        raise AddressSyncError(
            "module_ambiguous",
            "multiple runtime modules match the session binary path",
            path=identity.path,
            count=len(path_matches),
        )

    expected_name = identity.name.casefold()
    name_matches = tuple(
        module
        for module in modules
        if _runtime_module_name(module).casefold() == expected_name
    )
    if len(name_matches) == 1:
        return name_matches[0], "name"
    if len(name_matches) > 1:
        raise AddressSyncError(
            "module_ambiguous",
            "multiple runtime modules match the session binary name",
            name=identity.name,
            count=len(name_matches),
        )
    raise AddressSyncError(
        "module_not_found",
        "the session binary is not present in the runtime module list",
        name=identity.name,
        path=identity.path,
    )


def _runtime_module(
    value: object,
    *,
    index: int,
) -> RuntimeModule:
    if not isinstance(value, dict):
        raise AddressSyncError(
            "module_list_invalid",
            "x64dbg module entries must be objects",
            index=index,
        )
    record = {str(key): item for key, item in value.items()}
    base = _require_integer(
        record.get("base"),
        field="base",
        code="module_list_invalid",
        positive=True,
    )
    size = _require_integer(
        record.get("size"),
        field="size",
        code="module_list_invalid",
        positive=True,
    )
    name = record.get("name")
    path = record.get("path")
    if not isinstance(name, str) or not isinstance(path, str):
        raise AddressSyncError(
            "module_list_invalid",
            "x64dbg module name and path must be strings",
            index=index,
        )
    normalized_name = name.strip()
    normalized_path = path.strip()
    if not normalized_name and not normalized_path:
        raise AddressSyncError(
            "module_list_invalid",
            "x64dbg module entry requires a name or path",
            index=index,
        )
    return RuntimeModule(
        base=base,
        size=size,
        name=normalized_name or ntpath.basename(normalized_path),
        path=normalized_path,
    )


def _runtime_module_name(module: RuntimeModule) -> str:
    return module.name or ntpath.basename(module.path)


def _resolve_runtime_module_path(value: str) -> Path:
    raw = value.strip()
    if raw.startswith("\\??\\") or raw.startswith("\\\\?\\"):
        raw = raw[4:]
    if not raw:
        raise AddressSyncError(
            "module_file_unavailable",
            "selected runtime module does not report a file path",
        )
    try:
        path = Path(raw).resolve(strict=True)
    except OSError as exc:
        raise AddressSyncError(
            "module_file_unavailable",
            "selected runtime module file is unavailable",
            path=raw,
        ) from exc
    if not path.is_file():
        raise AddressSyncError(
            "module_file_unavailable",
            "selected runtime module path is not a file",
            path=str(path),
        )
    return path


def _read_pe_image_layout(path: Path) -> tuple[Architecture, int, int]:
    try:
        architecture = detect_pe_architecture(path)
        with path.open("rb") as stream:
            dos = stream.read(64)
            pe_offset = int.from_bytes(dos[0x3C:0x40], "little")
            stream.seek(pe_offset)
            file_header = stream.read(24)
            if len(file_header) != 24 or file_header[:4] != b"PE\0\0":
                raise ValueError("invalid PE file header")
            optional_size = int.from_bytes(file_header[20:22], "little")
            optional = stream.read(optional_size)
    except (OSError, ValueError) as exc:
        raise AddressSyncError(
            "module_file_invalid",
            "selected runtime module is not a supported PE image",
            path=str(path),
        ) from exc

    if len(optional) < 60:
        raise AddressSyncError(
            "module_file_invalid",
            "selected runtime module has a truncated PE optional header",
            path=str(path),
        )
    magic = int.from_bytes(optional[0:2], "little")
    expected_magic = 0x10B if architecture == Architecture.X86 else 0x20B
    image_base_offset = 28 if architecture == Architecture.X86 else 24
    image_base_size = 4 if architecture == Architecture.X86 else 8
    if magic != expected_magic or len(optional) < image_base_offset + image_base_size:
        raise AddressSyncError(
            "module_file_invalid",
            "selected runtime module optional header is inconsistent",
            path=str(path),
        )
    preferred_base = int.from_bytes(
        optional[image_base_offset : image_base_offset + image_base_size],
        "little",
    )
    image_size = int.from_bytes(optional[56:60], "little")
    if preferred_base <= 0 or image_size <= 0:
        raise AddressSyncError(
            "module_file_invalid",
            "selected runtime module has invalid image bounds",
            path=str(path),
            image_base=preferred_base,
            image_size=image_size,
        )
    return architecture, preferred_base, image_size


def _normalize_windows_path(value: str) -> str:
    raw = value.strip().replace("/", "\\")
    if raw.startswith("\\??\\"):
        raw = raw[4:]
    return ntpath.normcase(ntpath.normpath(raw)) if raw else ""


def _require_integer(
    value: object,
    *,
    field: str,
    code: str,
    positive: bool = False,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise AddressSyncError(code, f"{field} must be an integer", field=field, value=value)
    if value < 0 or (positive and value == 0):
        qualifier = "positive" if positive else "non-negative"
        raise AddressSyncError(
            code,
            f"{field} must be {qualifier}",
            field=field,
            value=value,
        )
    return value


def _require_address(value: int, *, field: str = "address") -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AddressSyncError(
            "invalid_address",
            f"{field} must be a non-negative integer",
            field=field,
            value=value,
        )