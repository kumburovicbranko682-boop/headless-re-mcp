"""Bounded CLR / .NET assembly inspection (no external deobfuscator)."""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from headless_re_mcp.detection.pe import PeFormatError, scan_pe
from headless_re_mcp.dotnet.tables import (
    CUSTOM_ATTRIBUTE_TYPE_TABLES,
    HAS_CUSTOM_ATTRIBUTE_TABLES,
    MEMBER_REF_PARENT_TABLES,
    RESOLUTION_SCOPE_TABLES,
    coded_index_size,
    simple_index_size,
    table_row_size,
)

JsonObject = dict[str, Any]

_DIRECTORY_COM_DESCRIPTOR = 14
_CLR_METADATA_SIG = b"BSJB"
# A real app references a few dozen assemblies at most; the cap bounds a
# hostile row count without losing anything from an honest image.
_MAX_ASSEMBLY_REFS = 64
# ModuleRef names the unmanaged DLLs the assembly P/Invokes into -- kernel32,
# a bundled native .dll, and so on. The same cap bounds a lying row count.
_MAX_MODULE_REFS = 64
# The TargetFramework walk scans TypeRef, MemberRef and CustomAttribute rows;
# real assemblies keep the attribute among the first rows of each (the
# metadata slice is capped at 64 KiB anyway), so the cap only bounds a lying
# row count, not an honest image.
_MAX_TFA_SCAN_ROWS = 4096
_TFA_NAME = "TargetFrameworkAttribute"
_TFA_NAMESPACE = "System.Runtime.Versioning"
# HasCustomAttribute tag 14 = Assembly (II.24.2.6); row 1 is the manifest
# assembly, the only place TargetFrameworkAttribute is ever attached.
_TFA_ASSEMBLY_PARENT = (1 << 5) | 14
# MemberRefParent tag 1 = TypeRef; CustomAttributeType tag 3 = MemberRef.
_MEMBER_REF_PARENT_TYPEREF_TAG = 1
_CUSTOM_ATTRIBUTE_TYPE_MEMBERREF_TAG = 3
_FLAG_ILONLY = 0x00000001
_FLAG_32BITREQUIRED = 0x00000002
_FLAG_IL_LIBRARY = 0x00000004
_FLAG_STRONGNAMESIGNED = 0x00000008
_FLAG_NATIVE_ENTRYPOINT = 0x00000010
_FLAG_32BITPREFERRED = 0x00020000
# The public-key token is the strong name's identity -- what the GAC and every
# assembly-binding reference pin, the managed analogue of an APK signing
# certificate's SHA-256 or a Mach-O CodeDirectory hash. It is derived from the
# Assembly row's PublicKey blob the same way ECMA-335 II.6.3 / every runtime
# does: the low 8 bytes of the key's SHA-1, in reverse order.
_PUBLIC_KEY_TOKEN_BYTES = 8
# The COR20 EntryPointToken's table byte when it names a managed method: the
# MethodDef table (a File token, 0x26, points at another module instead and
# resolves to no local name). Resolving the row through MethodDef.Name and the
# owning TypeDef's MethodList range names where execution starts -- the managed
# analogue of a WASM start function's resolved name or an APK's launcher
# activity, where the raw token is just a number.
_TOKEN_TABLE_METHODDEF = 0x06


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
    # The Assembly table's four-part version and the Module table's MVID -- a
    # per-build GUID. Together they are the managed analogue of a native
    # binary's soname/build-id: the assembly's declared identity plus a
    # fingerprint that changes on every recompile, which triage keys off.
    assembly_version: str | None = None
    mvid: str | None = None
    # The AssemblyRef table: which assemblies this one links against, each with
    # the version it was compiled for -- the managed analogue of an ELF's
    # DT_NEEDED list or a Mach-O's dylibs.
    assembly_refs: tuple[JsonObject, ...] = ()
    # The ModuleRef table: the unmanaged DLLs the assembly P/Invokes into --
    # its native (rather than managed) dependencies, the interop counterpart to
    # assembly_refs and the closest managed analogue to a native DT_NEEDED.
    module_refs: tuple[str, ...] = ()
    # The TargetFrameworkAttribute string the compiler stamps on the assembly
    # (e.g. ".NETCoreApp,Version=v8.0"): the platform the build targets -- the
    # managed analogue of a Mach-O LC_BUILD_VERSION or an ELF ABI-tag note.
    # None when the assembly does not carry the attribute (pre-4.0 binaries,
    # hand-built images).
    target_framework: str | None = None
    # The Assembly row's public-key token (hex): the strong name's identity, or
    # None when the assembly carries no public key (a private, non-strong-named
    # build). This is the "who signed it" of the managed world, alongside the
    # STRONGNAMESIGNED COR20 flag which says whether it was actually signed.
    public_key_token: str | None = None
    # The entry point resolved to a name ("Namespace.Type::Method"): where
    # execution starts, the way ildasm/monodis mark it with .entrypoint --
    # entry_point_token is just the number this resolves. None for a library
    # (token 0), a File-token entry point in another module, or a token the
    # tables cannot back.
    entry_point_name: str | None = None

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
            "assembly_version": self.assembly_version,
            "mvid": self.mvid,
            "assembly_refs": list(self.assembly_refs),
            "module_refs": list(self.module_refs),
            "target_framework": self.target_framework,
            "public_key_token": self.public_key_token,
            "entry_point_name": self.entry_point_name,
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
    assembly_version: str | None = None
    mvid: str | None = None
    assembly_refs: tuple[JsonObject, ...] = ()
    module_refs: tuple[str, ...] = ()
    target_framework: str | None = None
    public_key_token: str | None = None
    entry_point_name: str | None = None
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
                    assembly_version,
                    mvid,
                    assembly_refs,
                    module_refs,
                    target_framework,
                    public_key_token,
                    entry_point_name,
                    metadata_stats,
                ) = _parse_metadata_root(meta, entry_token)
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
        assembly_version=assembly_version,
        mvid=mvid,
        assembly_refs=assembly_refs,
        module_refs=module_refs,
        target_framework=target_framework,
        public_key_token=public_key_token,
        entry_point_name=entry_point_name,
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
    entry_token: int,
) -> tuple[
    str | None,
    list[str],
    str | None,
    str | None,
    str | None,
    str | None,
    tuple[JsonObject, ...],
    tuple[str, ...],
    str | None,
    str | None,
    str | None,
    MetadataStats | None,
]:
    if len(meta) < 16 or meta[:4] != _CLR_METADATA_SIG:
        return None, [], None, None, None, None, (), (), None, None, None, None
    version_len = int.from_bytes(meta[12:16], "little")
    if version_len < 0 or 16 + version_len > len(meta):
        return None, [], None, None, None, None, (), (), None, None, None, None
    version_raw = meta[16 : 16 + version_len]
    version = version_raw.split(b"\0", 1)[0].decode("utf-8", errors="replace")
    # Align version block to 4 bytes.
    version_padded = (version_len + 3) & ~3
    cursor = 16 + version_padded
    if cursor + 4 > len(meta):
        return version, [], None, None, None, None, (), (), None, None, None, None
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
    assembly_version: str | None = None
    mvid: str | None = None
    refs: tuple[JsonObject, ...] = ()
    mod_refs: tuple[str, ...] = ()
    framework: str | None = None
    public_key_token: str | None = None
    entry_name: str | None = None
    stats: MetadataStats | None = None
    try:
        (
            module_name,
            assembly_name,
            assembly_version,
            mvid,
            refs,
            mod_refs,
            framework,
            public_key_token,
            entry_name,
            stats,
        ) = _parse_tables_and_names(meta, stream_map, entry_token)
    except Exception:
        module_name = None
        assembly_name = None
        assembly_version = None
        mvid = None
        refs = ()
        mod_refs = ()
        framework = None
        public_key_token = None
        entry_name = None
        stats = None
    return (
        version,
        streams,
        module_name,
        assembly_name,
        assembly_version,
        mvid,
        refs,
        mod_refs,
        framework,
        public_key_token,
        entry_name,
        stats,
    )


def _packed_uint(data: bytes, pos: int) -> tuple[int, int] | None:
    """ECMA-335 II.23.2 compressed unsigned integer at ``pos``.

    Returns ``(value, position_after)`` or None on a truncated or malformed
    encoding (first byte 111xxxxx is reserved).
    """
    if pos >= len(data):
        return None
    first = data[pos]
    if first & 0x80 == 0:
        return first, pos + 1
    if first & 0xC0 == 0x80:
        if pos + 2 > len(data):
            return None
        return ((first & 0x3F) << 8) | data[pos + 1], pos + 2
    if first & 0xE0 == 0xC0:
        if pos + 4 > len(data):
            return None
        value = (
            ((first & 0x1F) << 24) | (data[pos + 1] << 16) | (data[pos + 2] << 8) | data[pos + 3]
        )
        return value, pos + 4
    return None


def _custom_attr_fixed_string(blob: bytes) -> str | None:
    """The single SerString fixed argument of a custom-attribute value blob.

    ECMA-335 II.23.3: a u16 prolog 0x0001, then the fixed arguments. For an
    attribute whose ctor takes one string (TargetFrameworkAttribute does) that
    is one SerString: 0xFF for null, otherwise a packed length + that many
    UTF-8 bytes. The named-argument tail that follows is not read.
    """
    if len(blob) < 3 or int.from_bytes(blob[0:2], "little") != 0x0001:
        return None
    if blob[2] == 0xFF:
        return None
    decoded = _packed_uint(blob, 2)
    if decoded is None:
        return None
    length, start = decoded
    if start + length > len(blob):
        return None
    return blob[start : start + length].decode("utf-8", errors="replace")


def _parse_tables_and_names(
    meta: bytes,
    stream_map: dict[str, tuple[int, int]],
    entry_token: int,
) -> tuple[
    str | None,
    str | None,
    str | None,
    str | None,
    tuple[JsonObject, ...],
    tuple[str, ...],
    str | None,
    str | None,
    str | None,
    MetadataStats | None,
]:
    """Best-effort Module/Assembly identity + table row counts from #~ + heaps.

    Returns ``(module_name, assembly_name, assembly_version, mvid,
    assembly_refs, module_refs, target_framework, public_key_token,
    entry_point_name, stats)``.
    """
    tables_key = "#~" if "#~" in stream_map else ("#-" if "#-" in stream_map else None)
    strings_key = "#Strings" if "#Strings" in stream_map else None
    if tables_key is None:
        return None, None, None, None, (), (), None, None, None, None
    t_off, t_size = stream_map[tables_key]
    tables = meta[t_off : t_off + t_size]
    strings = b""
    strings_heap_bytes: int | None = None
    if strings_key is not None:
        s_off, s_size = stream_map[strings_key]
        strings = meta[s_off : s_off + s_size]
        strings_heap_bytes = s_size
    guids = b""
    if "#GUID" in stream_map:
        g_off, g_size = stream_map["#GUID"]
        guids = meta[g_off : g_off + g_size]
    blob_heap = b""
    if "#Blob" in stream_map:
        b_off, b_size = stream_map["#Blob"]
        blob_heap = meta[b_off : b_off + b_size]
    us_heap_bytes = stream_map["#US"][1] if "#US" in stream_map else None
    if len(tables) < 24:
        return None, None, None, None, (), (), None, None, None, None
    heap_sizes = tables[6]
    string_index_size = 4 if (heap_sizes & 0x01) else 2
    valid = int.from_bytes(tables[8:16], "little")
    cursor = 24
    row_counts: dict[int, int] = {}
    for bit in range(64):
        if valid & (1 << bit):
            if cursor + 4 > len(tables):
                return None, None, None, None, (), (), None, None, None, None
            row_counts[bit] = int.from_bytes(tables[cursor : cursor + 4], "little")
            cursor += 4
    # A row count is a number out of the assembly; a claim that could not fit
    # in this #~ stream even at the 2-byte minimum row width is a lie. Left
    # unclamped it does worse than overstate one table: coded-index widths are
    # derived from row counts (II.24.2.6), so one absurd count silently
    # re-sizes *other* tables' rows and desyncs the whole walk behind them.
    # The stream's own size is the bound -- derived from the file rather than
    # picked, the same rule metadata_enum applies when iterating rows.
    max_rows = max((len(tables) - cursor) // 2, 0)
    row_counts = {bit: min(count, max_rows) for bit, count in row_counts.items()}

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

    guid_index_size = 4 if (heap_sizes & 0x02) else 2
    blob_index_size = 4 if (heap_sizes & 0x04) else 2

    def read_guid_index(buf: bytes, at: int) -> int:
        return int.from_bytes(buf[at : at + guid_index_size], "little")

    def guid_at(index: int) -> str | None:
        # The #GUID heap is 1-based: index N is the Nth 16-byte GUID. Rendered
        # the way .NET's Guid.ToString() does (first three groups little-endian),
        # which is what every managed tool prints, so it can be matched by eye.
        if index <= 0:
            return None
        start = (index - 1) * 16
        if start + 16 > len(guids):
            return None
        return str(uuid.UUID(bytes_le=guids[start : start + 16]))

    def blob_at(index: int) -> bytes | None:
        # #Blob entries start with a packed length; index 0 is the empty blob.
        if index <= 0 or index >= len(blob_heap):
            return None
        decoded = _packed_uint(blob_heap, index)
        if decoded is None:
            return None
        length, start = decoded
        if start + length > len(blob_heap):
            return None
        return blob_heap[start : start + length]

    module_name: str | None = None
    assembly_name: str | None = None
    assembly_version: str | None = None
    mvid: str | None = None
    assembly_refs: list[JsonObject] = []
    module_refs: list[str] = []
    public_key_token: str | None = None
    # The TargetFramework walk: TypeRef rows naming the attribute type, then
    # MemberRef rows for its .ctor, then the CustomAttribute row on the
    # Assembly whose value blob carries the framework string. The tables come
    # up in exactly that bit order (0x01 < 0x0A < 0x0C), so each stage only
    # needs what the previous one collected.
    tfa_typerefs: set[int] = set()
    tfa_ctors: set[int] = set()
    target_framework: str | None = None
    # The entry-point walk: TypeDef rows (0x02) record (Name, Namespace,
    # MethodList) so the owning type of any method row is known, then the
    # MethodDef row (0x06) the token names yields the method name -- again in
    # exactly the table order the tables stream comes up in.
    entry_row = entry_token & 0x00FFFFFF
    wanted_method = entry_row if (entry_token >> 24) == _TOKEN_TABLE_METHODDEF else 0
    typedef_spans: list[tuple[int, int, int]] = []  # (methodlist, name_idx, ns_idx)
    entry_method: str | None = None
    entry_point_name: str | None = None
    if not strings:
        return None, None, None, None, (), (), None, None, None, stats
    # Walk the tables in ascending order, sizing each one so the offset lands
    # on the next. The Module table (0x00) is first, but the Assembly table
    # (0x20) sits behind TypeDef/Field/MethodDef and friends -- an assembly
    # without those is not a real one -- so reaching its name means stepping
    # over every table between them, not bailing at the first unknown row.
    offset = cursor
    for bit in range(64):
        rows = row_counts.get(bit)
        if not rows:
            continue
        row_size = table_row_size(
            row_counts, string_index_size, blob_index_size, guid_index_size, bit
        )
        if row_size is None:
            break
        if bit == 0x00:  # Module: Generation(2), Name(str), Mvid(guid)
            name_idx, _ = read_string_index(tables, offset + 2)
            module_name = string_at(name_idx)
            mvid = guid_at(read_guid_index(tables, offset + 2 + string_index_size))
        elif bit == 0x01:  # TypeRef: ResolutionScope(coded), Name(str), Namespace(str)
            scope_size = coded_index_size(row_counts, RESOLUTION_SCOPE_TABLES, 2)
            for i in range(min(rows, _MAX_TFA_SCAN_ROWS)):
                at = offset + i * row_size + scope_size
                name_idx, advance = read_string_index(tables, at)
                ns_idx, _ = read_string_index(tables, at + advance)
                if string_at(name_idx) == _TFA_NAME and string_at(ns_idx) == _TFA_NAMESPACE:
                    tfa_typerefs.add(i + 1)
        elif bit == 0x02 and wanted_method:  # TypeDef: Flags, Name, Namespace, ...
            # ... Extends(coded), FieldList, MethodList. Each row's MethodList
            # is the first MethodDef it owns; the spans locate any method's
            # declaring type. The scan is bounded by the (clamped) row count
            # and stops at a truncated row, like every other walk here.
            extends_size = coded_index_size(row_counts, (0x02, 0x01, 0x1B), 2)
            field_list_size = simple_index_size(row_counts, 0x04)
            mlist_at = 4 + string_index_size * 2 + extends_size + field_list_size
            mlist_size = simple_index_size(row_counts, 0x06)
            for i in range(rows):
                at = offset + i * row_size
                if at + row_size > len(tables):
                    break
                name_idx, advance = read_string_index(tables, at + 4)
                ns_idx, _ = read_string_index(tables, at + 4 + advance)
                mlist = int.from_bytes(tables[at + mlist_at : at + mlist_at + mlist_size], "little")
                typedef_spans.append((mlist, name_idx, ns_idx))
        elif bit == 0x06 and wanted_method:  # MethodDef: RVA(4), ImplFlags(2), Flags(2), Name...
            if wanted_method <= rows:
                at = offset + (wanted_method - 1) * row_size
                if at + row_size <= len(tables):
                    name_idx, _ = read_string_index(tables, at + 8)
                    entry_method = string_at(name_idx)
        elif bit == 0x0A and tfa_typerefs:  # MemberRef: Class(coded), Name(str), Sig(blob)
            parent_size = coded_index_size(row_counts, MEMBER_REF_PARENT_TABLES, 3)
            for i in range(min(rows, _MAX_TFA_SCAN_ROWS)):
                at = offset + i * row_size
                parent = int.from_bytes(tables[at : at + parent_size], "little")
                if parent & 0x7 != _MEMBER_REF_PARENT_TYPEREF_TAG:
                    continue
                if (parent >> 3) not in tfa_typerefs:
                    continue
                name_idx, _ = read_string_index(tables, at + parent_size)
                if string_at(name_idx) == ".ctor":
                    tfa_ctors.add(i + 1)
        elif bit == 0x0C and tfa_ctors:  # CustomAttribute: Parent, Type, Value(blob)
            parent_size = coded_index_size(row_counts, HAS_CUSTOM_ATTRIBUTE_TABLES, 5)
            type_size = coded_index_size(row_counts, CUSTOM_ATTRIBUTE_TYPE_TABLES, 3)
            for i in range(min(rows, _MAX_TFA_SCAN_ROWS)):
                at = offset + i * row_size
                parent = int.from_bytes(tables[at : at + parent_size], "little")
                if parent != _TFA_ASSEMBLY_PARENT:
                    continue
                type_at = at + parent_size
                ctor = int.from_bytes(tables[type_at : type_at + type_size], "little")
                if ctor & 0x7 != _CUSTOM_ATTRIBUTE_TYPE_MEMBERREF_TAG:
                    continue
                if (ctor >> 3) not in tfa_ctors:
                    continue
                value_at = at + parent_size + type_size
                blob_idx = int.from_bytes(tables[value_at : value_at + blob_index_size], "little")
                value = blob_at(blob_idx)
                framework = _custom_attr_fixed_string(value) if value is not None else None
                if framework:
                    target_framework = framework
                    break
        elif bit == 0x1A:  # ModuleRef: a single Name -- an unmanaged P/Invoke DLL
            for i in range(min(rows, _MAX_MODULE_REFS)):
                name_idx, _ = read_string_index(tables, offset + i * row_size)
                ref_name = string_at(name_idx)
                if ref_name is not None:
                    module_refs.append(ref_name)
        elif bit == 0x20:  # Assembly: HashAlg(4), Major/Minor/Build/Revision(2 each), ...
            major = int.from_bytes(tables[offset + 4 : offset + 6], "little")
            minor = int.from_bytes(tables[offset + 6 : offset + 8], "little")
            build = int.from_bytes(tables[offset + 8 : offset + 10], "little")
            revision = int.from_bytes(tables[offset + 10 : offset + 12], "little")
            assembly_version = f"{major}.{minor}.{build}.{revision}"
            # PublicKey blob index sits right after the fixed fields + Flags(4);
            # a non-empty key is the assembly's strong-name identity, and its
            # token is the low 8 bytes of the key's SHA-1, reversed.
            pk_at = offset + 4 + 2 + 2 + 2 + 2 + 4
            pk_idx = int.from_bytes(tables[pk_at : pk_at + blob_index_size], "little")
            public_key = blob_at(pk_idx)
            if public_key:
                public_key_token = (
                    hashlib.sha1(public_key).digest()[-_PUBLIC_KEY_TOKEN_BYTES:][::-1].hex()  # noqa: S324
                )
            # Name follows the fixed fields + Flags(4) + PublicKey blob index.
            name_at = pk_at + blob_index_size
            name_idx, _ = read_string_index(tables, name_at)
            assembly_name = string_at(name_idx)
        elif bit == 0x23:  # AssemblyRef: the assemblies this one links against
            for i in range(min(rows, _MAX_ASSEMBLY_REFS)):
                at = offset + i * row_size
                # Major/Minor/Build/Revision(2 each), Flags(4), then
                # PublicKeyOrToken(blob) before the Name -- no HashAlgId here,
                # unlike the Assembly row above.
                version_parts = [
                    int.from_bytes(tables[at + j : at + j + 2], "little") for j in (0, 2, 4, 6)
                ]
                name_at = at + 8 + 4 + blob_index_size
                name_idx, _ = read_string_index(tables, name_at)
                ref_name = string_at(name_idx)
                if ref_name is None:
                    continue
                assembly_refs.append(
                    {
                        "name": ref_name,
                        "version": ".".join(str(part) for part in version_parts),
                    }
                )
        offset += row_size * rows
    if entry_method:
        # The owning type is the last TypeDef whose MethodList starts at or
        # before the entry row (II.22.37: each row owns the methods from its
        # MethodList up to the next row's). Rendered the way ildasm/monodis
        # spell it: Namespace.Type::Method, namespace omitted when empty.
        owner: tuple[int, int] | None = None
        for mlist, name_idx, ns_idx in typedef_spans:
            if 1 <= mlist <= wanted_method:
                owner = (name_idx, ns_idx)
        entry_point_name = entry_method
        if owner is not None:
            type_name = string_at(owner[0])
            namespace = string_at(owner[1])
            if type_name:
                qualified = f"{namespace}.{type_name}" if namespace else type_name
                entry_point_name = f"{qualified}::{entry_method}"
    return (
        module_name,
        assembly_name,
        assembly_version,
        mvid,
        tuple(assembly_refs),
        tuple(module_refs),
        target_framework,
        public_key_token,
        entry_point_name,
        stats,
    )
