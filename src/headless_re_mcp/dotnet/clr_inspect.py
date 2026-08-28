"""Bounded CLR / .NET assembly inspection (no external deobfuscator)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from headless_re_mcp.detection.pe import PeFormatError, scan_pe

JsonObject = dict[str, Any]

_DIRECTORY_COM_DESCRIPTOR = 14
_CLR_METADATA_SIG = b"BSJB"
_FLAG_ILONLY = 0x00000001
_FLAG_32BITREQUIRED = 0x00000002
_FLAG_IL_LIBRARY = 0x00000004
_FLAG_STRONGNAMESIGNED = 0x00000008
_FLAG_NATIVE_ENTRYPOINT = 0x00000010
_FLAG_32BITPREFERRED = 0x00020000


class DotnetKind(StrEnum):
    NOT_DOTNET = "not_dotnet"
    CLR_HINT = "clr_directory_hint"
    PURE_MANAGED = "pure_managed"
    MIXED_MODE = "mixed_mode"


class DotnetInspectError(ValueError):
    """Raised when the input is not a verifiable .NET assembly for tooling."""

    def __init__(self, code: str, message: str, *, details: JsonObject | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.details = details or {}


@dataclass(frozen=True, slots=True)
class MetadataStats:
    type_count: int | None = None
    method_count: int | None = None
    field_count: int | None = None
    resource_count: int | None = None
    strings_heap_bytes: int | None = None
    us_heap_bytes: int | None = None
    source: str = "metadata_tables"

    def to_dict(self) -> JsonObject:
        return {
            "type_count": self.type_count,
            "method_count": self.method_count,
            "field_count": self.field_count,
            "resource_count": self.resource_count,
            "strings_heap_bytes": self.strings_heap_bytes,
            "us_heap_bytes": self.us_heap_bytes,
            "source": self.source,
        }


@dataclass(frozen=True, slots=True)
class DotnetInspectReport:
    path: str
    sha256: str
    architecture: str
    is_dotnet: bool
    kind: DotnetKind
    verified_clr: bool
    runtime_major: int | None
    runtime_minor: int | None
    metadata_version: str | None
    entry_point_token: int | None
    flags: int | None
    flags_decoded: tuple[str, ...]
    streams: tuple[str, ...]
    module_name: str | None
    assembly_name: str | None
    note: str
    metadata_stats: MetadataStats | None = None

    def to_dict(self) -> JsonObject:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "architecture": self.architecture,
            "is_dotnet": self.is_dotnet,
            "kind": self.kind.value,
            "verified_clr": self.verified_clr,
            "runtime_major": self.runtime_major,
            "runtime_minor": self.runtime_minor,
            "metadata_version": self.metadata_version,
            "entry_point_token": self.entry_point_token,
            "flags": self.flags,
            "flags_decoded": list(self.flags_decoded),
            "streams": list(self.streams),
            "module_name": self.module_name,
            "assembly_name": self.assembly_name,
            "metadata_stats": (
                self.metadata_stats.to_dict() if self.metadata_stats is not None else None
            ),
            "note": self.note,
            "claims_universal_unpack": False,
        }


def inspect_dotnet(path: str | Path, *, require_verified: bool = False) -> DotnetInspectReport:
    """Inspect CLR headers/metadata. Does not run de4dot or mutate the file."""
    target = Path(path).expanduser().resolve(strict=True)
    pe_report = scan_pe(target)
    try:
        from headless_re_mcp.detection import pe as pe_mod

        data = pe_mod._read_pe_bytes(target)  # noqa: SLF001
        # Reuse layout helpers via private APIs carefully through scan already done.
        layout = pe_mod._parse_layout(data)  # noqa: SLF001
    except Exception as exc:  # pragma: no cover - scan_pe already validated
        raise DotnetInspectError("invalid_pe", str(exc)) from exc

    rva, size = pe_mod._directory(layout, _DIRECTORY_COM_DESCRIPTOR)  # noqa: SLF001
    if rva == 0 and size == 0:
        report = DotnetInspectReport(
            path=str(target),
            sha256=pe_report.sha256,
            architecture=pe_report.architecture,
            is_dotnet=False,
            kind=DotnetKind.NOT_DOTNET,
            verified_clr=False,
            runtime_major=None,
            runtime_minor=None,
            metadata_version=None,
            entry_point_token=None,
            flags=None,
            flags_decoded=(),
            streams=(),
            module_name=None,
            assembly_name=None,
            note="no COM descriptor directory; not a .NET assembly",
        )
        if require_verified:
            raise DotnetInspectError(
                "not_dotnet",
                "input is not a .NET assembly (no CLR directory)",
                details=report.to_dict(),
            )
        return report

    try:
        header_off = pe_mod._rva_to_offset(layout, rva, size=max(size, 72))  # noqa: SLF001
        header = pe_mod._slice(data, header_off, max(min(size or 72, 72), 72))  # noqa: SLF001
    except PeFormatError:
        report = DotnetInspectReport(
            path=str(target),
            sha256=pe_report.sha256,
            architecture=pe_report.architecture,
            is_dotnet=True,
            kind=DotnetKind.CLR_HINT,
            verified_clr=False,
            runtime_major=None,
            runtime_minor=None,
            metadata_version=None,
            entry_point_token=None,
            flags=None,
            flags_decoded=(),
            streams=(),
            module_name=None,
            assembly_name=None,
            note="COM directory present but COR20 header unreadable",
        )
        if require_verified:
            raise DotnetInspectError(
                "clr_unverified",
                "CLR directory hint only; refuse external .NET tools",
                details=report.to_dict(),
            ) from None
        return report

    major = int.from_bytes(header[4:6], "little")
    minor = int.from_bytes(header[6:8], "little")
    meta_rva = int.from_bytes(header[8:12], "little")
    meta_size = int.from_bytes(header[12:16], "little")
    flags = int.from_bytes(header[16:20], "little")
    entry_token = int.from_bytes(header[20:24], "little")

    metadata_version: str | None = None
    streams: list[str] = []
    module_name: str | None = None
    assembly_name: str | None = None
    metadata_stats: MetadataStats | None = None
    verified = False
    note = "COR20 present"

    if meta_rva and meta_size >= 16:
        try:
            meta_off = pe_mod._rva_to_offset(layout, meta_rva, size=min(meta_size, 0x10000))  # noqa: SLF001
            meta = pe_mod._slice(data, meta_off, min(meta_size, 0x10000))  # noqa: SLF001
            if meta[:4] == _CLR_METADATA_SIG:
                verified = True
                (
                    metadata_version,
                    streams,
                    module_name,
                    assembly_name,
                    metadata_stats,
                ) = _parse_metadata_root(meta)
                note = "verified COR20 + BSJB metadata"
            else:
                note = "COR20 MetaData RVA does not point at BSJB"
        except PeFormatError:
            note = "COR20 MetaData RVA not mappable"

    kind = _classify_kind(verified=verified, flags=flags)
    report = DotnetInspectReport(
        path=str(target),
        sha256=pe_report.sha256,
        architecture=pe_report.architecture,
        is_dotnet=True,
        kind=kind,
        verified_clr=verified,
        runtime_major=major,
        runtime_minor=minor,
        metadata_version=metadata_version,
        entry_point_token=entry_token,
        flags=flags,
        flags_decoded=_decode_flags(flags),
        streams=tuple(streams),
        module_name=module_name,
        assembly_name=assembly_name,
        note=note,
        metadata_stats=metadata_stats,
    )
    if require_verified and not verified:
        raise DotnetInspectError(
            "clr_unverified",
            "CLR not verified; refuse external .NET tools",
            details=report.to_dict(),
        )
    return report


def _classify_kind(*, verified: bool, flags: int) -> DotnetKind:
    if not verified:
        return DotnetKind.CLR_HINT
    if flags & _FLAG_NATIVE_ENTRYPOINT or not (flags & _FLAG_ILONLY):
        return DotnetKind.MIXED_MODE
    return DotnetKind.PURE_MANAGED


def _decode_flags(flags: int) -> tuple[str, ...]:
    names: list[str] = []
    mapping = (
        (_FLAG_ILONLY, "ILONLY"),
        (_FLAG_32BITREQUIRED, "32BITREQUIRED"),
        (_FLAG_IL_LIBRARY, "IL_LIBRARY"),
        (_FLAG_STRONGNAMESIGNED, "STRONGNAMESIGNED"),
        (_FLAG_NATIVE_ENTRYPOINT, "NATIVE_ENTRYPOINT"),
        (_FLAG_32BITPREFERRED, "32BITPREFERRED"),
    )
    for bit, name in mapping:
        if flags & bit:
            names.append(name)
    return tuple(names)


def _parse_metadata_root(
    meta: bytes,
) -> tuple[str | None, list[str], str | None, str | None, MetadataStats | None]:
    if len(meta) < 16 or meta[:4] != _CLR_METADATA_SIG:
        return None, [], None, None, None
    version_len = int.from_bytes(meta[12:16], "little")
    if version_len < 0 or 16 + version_len > len(meta):
        return None, [], None, None, None
    version_raw = meta[16 : 16 + version_len]
    version = version_raw.split(b"\0", 1)[0].decode("utf-8", errors="replace")
    # Align version block to 4 bytes.
    version_padded = (version_len + 3) & ~3
    cursor = 16 + version_padded
    if cursor + 4 > len(meta):
        return version, [], None, None, None
    stream_count = int.from_bytes(meta[cursor + 2 : cursor + 4], "little")
    cursor += 4
    streams: list[str] = []
    stream_map: dict[str, tuple[int, int]] = {}
    for _ in range(stream_count):
        if cursor + 8 > len(meta):
            break
        offset = int.from_bytes(meta[cursor : cursor + 4], "little")
        size = int.from_bytes(meta[cursor + 4 : cursor + 8], "little")
        cursor += 8
        name_end = meta.find(b"\0", cursor)
        if name_end < 0:
            break
        name = meta[cursor:name_end].decode("ascii", errors="replace")
        name_len = name_end - cursor + 1
        name_padded = (name_len + 3) & ~3
        cursor += name_padded
        streams.append(name)
        stream_map[name] = (offset, size)

    module_name: str | None = None
    assembly_name: str | None = None
    stats: MetadataStats | None = None
    try:
        module_name, assembly_name, stats = _parse_tables_and_names(meta, stream_map)
    except Exception:
        module_name = None
        assembly_name = None
        stats = None
    return version, streams, module_name, assembly_name, stats


def _parse_tables_and_names(
    meta: bytes,
    stream_map: dict[str, tuple[int, int]],
) -> tuple[str | None, str | None, MetadataStats | None]:
    """Best-effort Module/Assembly names + table row counts from #~ + heaps."""
    tables_key = "#~" if "#~" in stream_map else ("#-" if "#-" in stream_map else None)
    strings_key = "#Strings" if "#Strings" in stream_map else None
    if tables_key is None:
        return None, None, None
    t_off, t_size = stream_map[tables_key]
    tables = meta[t_off : t_off + t_size]
    strings = b""
    strings_heap_bytes: int | None = None
    if strings_key is not None:
        s_off, s_size = stream_map[strings_key]
        strings = meta[s_off : s_off + s_size]
        strings_heap_bytes = s_size
    us_heap_bytes = stream_map["#US"][1] if "#US" in stream_map else None
    if len(tables) < 24:
        return None, None, None
    heap_sizes = tables[6]
    string_index_size = 4 if (heap_sizes & 0x01) else 2
    valid = int.from_bytes(tables[8:16], "little")
    cursor = 24
    row_counts: dict[int, int] = {}
    for bit in range(64):
        if valid & (1 << bit):
            if cursor + 4 > len(tables):
                return None, None, None
            row_counts[bit] = int.from_bytes(tables[cursor : cursor + 4], "little")
            cursor += 4

    stats = MetadataStats(
        type_count=row_counts.get(0x02),
        method_count=row_counts.get(0x06),
        field_count=row_counts.get(0x04),
        resource_count=row_counts.get(0x28),
        strings_heap_bytes=strings_heap_bytes,
        us_heap_bytes=us_heap_bytes,
        source="metadata_tables",
    )

    def read_string_index(buf: bytes, at: int) -> tuple[int, int]:
        if string_index_size == 4:
            return int.from_bytes(buf[at : at + 4], "little"), 4
        return int.from_bytes(buf[at : at + 2], "little"), 2

    def string_at(index: int) -> str | None:
        if index <= 0 or index >= len(strings):
            return None
        end = strings.find(b"\0", index)
        if end < 0:
            end = len(strings)
        return strings[index:end].decode("utf-8", errors="replace")

    module_name: str | None = None
    assembly_name: str | None = None
    if not strings:
        return None, None, stats
    # ``cursor`` points at the first table's first row. Module is table 0, so
    # its row starts here; a 2-byte Generation precedes its Name index.
    if row_counts.get(0x00):
        name_idx, _ = read_string_index(tables, cursor + 2)
        module_name = string_at(name_idx)
    if row_counts.get(0x20):
        # The Assembly table sits after every lower-numbered table, and real
        # assemblies always carry tables between Module and Assembly (TypeRef,
        # TypeDef, MethodDef, ...). The old walk advanced row-by-row and bailed
        # at the first table it did not special-case, so it never reached
        # Assembly and assembly_name came back null for every real input. Sum
        # the preceding tables' row sizes with the enumerator's shared ECMA-335
        # schema instead (deferred import: metadata_enum imports this module).
        from headless_re_mcp.dotnet.metadata_enum import table_start_offset

        guid_index_size = 4 if (heap_sizes & 0x02) else 2
        blob_index_size = 4 if (heap_sizes & 0x04) else 2
        try:
            asm_off = table_start_offset(
                row_counts,
                0x20,
                table_data_offset=cursor,
                string_index_size=string_index_size,
                blob_index_size=blob_index_size,
                guid_index_size=guid_index_size,
            )
        except DotnetInspectError:
            # A valid-mask bit we cannot size makes every following table's
            # offset unknowable; drop the assembly name rather than read a
            # string from a guessed offset.
            return module_name, None, stats
        # Assembly row: HashAlgId(4) + Major/Minor/Build/Rev(2 each) + Flags(4)
        # + PublicKey(blob) precede Name.
        name_at = asm_off + 16 + blob_index_size
        if name_at + string_index_size <= len(tables):
            name_idx, _ = read_string_index(tables, name_at)
            assembly_name = string_at(name_idx)
    return module_name, assembly_name, stats
