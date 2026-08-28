from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic

from headless_re_mcp.core.models import Architecture
from headless_re_mcp.detection.models import (
    DetectionEvidence,
    DetectionFinding,
    DetectionReport,
    DetectionSource,
    FindingCategory,
    FindingSeverity,
    ImportSummary,
    PeSummary,
    ScanMode,
    SectionSummary,
    SignatureSummary,
    TlsSummary,
)

_DEFAULT_MAX_FILE_SIZE = 256 * 1024 * 1024
_READ_CHUNK_BYTES = 1024 * 1024
_MAX_SECTIONS = 96
_MAX_IMPORT_LIBRARIES = 256
_MAX_IMPORT_FUNCTIONS = 16_384
_MAX_TLS_CALLBACKS = 128
_MAX_C_STRING = 4096
_IMAGE_SCN_MEM_EXECUTE = 0x20000000
_IMAGE_SCN_MEM_READ = 0x40000000
_IMAGE_SCN_MEM_WRITE = 0x80000000
_DIRECTORY_IMPORT = 1
_DIRECTORY_SECURITY = 4
_DIRECTORY_TLS = 9
_DIRECTORY_COM_DESCRIPTOR = 14
# IMAGE_COR20_HEADER: cb + versions + MetaData IMAGE_DATA_DIRECTORY starts at +8.
_CLR_HEADER_METADATA_OFF = 8
_CLR_HEADER_MIN_READ = 16
_CLR_METADATA_SIG = b"BSJB"
_SUSPICIOUS_APIS = frozenset(
    {
        "createprocessa",
        "createprocessw",
        "getprocaddress",
        "loadlibrarya",
        "loadlibraryexw",
        "loadlibraryw",
        "ntallocatevirtualmemory",
        "ntprotectvirtualmemory",
        "rtlmovememory",
        "virtualalloc",
        "virtualallocex",
        "virtualprotect",
        "virtualprotectex",
        "writeprocessmemory",
    }
)


class PeFormatError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _Section:
    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_offset: int
    characteristics: int

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & _IMAGE_SCN_MEM_EXECUTE)

    @property
    def writable(self) -> bool:
        return bool(self.characteristics & _IMAGE_SCN_MEM_WRITE)

    @property
    def readable(self) -> bool:
        return bool(self.characteristics & _IMAGE_SCN_MEM_READ)

    @property
    def mapped_size(self) -> int:
        return max(self.virtual_size, self.raw_size)


@dataclass(frozen=True, slots=True)
class _Layout:
    machine: int
    architecture: Architecture
    characteristics: int
    subsystem: int
    dll_characteristics: int
    image_base: int
    image_size: int
    entry_point_rva: int
    section_alignment: int
    file_alignment: int
    linker_version: str
    size_of_headers: int
    directories: tuple[tuple[int, int], ...]
    sections: tuple[_Section, ...]


def _read_pe_bytes(
    path: Path, max_file_size: int = _DEFAULT_MAX_FILE_SIZE
) -> bytes:
    """Read at most the scanner's input budget, including under file growth.

    The budget is ``max_file_size + 1`` so an input sitting exactly at or past
    the limit is still seen and refused, and ``stat()`` is deliberately not
    trusted because the file can grow between the check and the read. The read
    is chunked rather than a single ``read(max_file_size + 1)``: a buffered
    ``read(n)`` pre-allocates all ``n`` bytes before shrinking, so the one-shot
    form spiked the whole budget -- 256 MiB at the default cap -- of transient
    heap on every scan whatever the file's real size, and scan_pe runs on every
    binary and twice per .NET enumeration. A short read means EOF on a regular
    file, so a file under one chunk still costs a single ``read`` of exactly the
    budget (the I/O bound is unchanged); only a file large enough to fill a
    chunk pays for more, and never more than the bytes actually present.
    """
    budget = max_file_size + 1
    buffer = bytearray()
    with path.open("rb") as stream:
        while len(buffer) < budget:
            want = min(_READ_CHUNK_BYTES, budget - len(buffer))
            chunk = stream.read(want)
            buffer.extend(chunk)
            if len(chunk) < want:
                break
    if len(buffer) > max_file_size:
        raise PeFormatError(
            f"input exceeds the {max_file_size}-byte built-in scan limit: {path}"
        )
    return bytes(buffer)


def scan_pe(
    path: Path,
    *,
    mode: ScanMode = ScanMode.NORMAL,
    max_file_size: int = _DEFAULT_MAX_FILE_SIZE,
) -> DetectionReport:
    if isinstance(max_file_size, bool) or not isinstance(max_file_size, int):
        raise TypeError("max_file_size must be an integer")
    if max_file_size < 0:
        raise ValueError("max_file_size must not be negative")
    started = monotonic()
    # resolve() without strict=True, and check is_file() before stat(), so a
    # missing input surfaces as the structured PeFormatError below rather than a
    # raw FileNotFoundError from resolve()/stat().
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise PeFormatError(f"input is not a regular file: {resolved}")
    stat = resolved.stat()
    if stat.st_size > max_file_size:
        raise PeFormatError(
            f"input exceeds the {max_file_size}-byte built-in scan limit: {resolved}"
        )
    # Do not use read_bytes() after the size check: the file can grow between
    # those operations and force an unbounded allocation before we notice.
    data = _read_pe_bytes(resolved, max_file_size)
    layout = _parse_layout(data)
    sections = tuple(_section_summary(data, section) for section in layout.sections)
    imports = _parse_imports(data, layout)
    tls = _parse_tls(data, layout)
    signature = _signature_summary(data, layout)
    overlay_offset, overlay_size = _overlay(data, layout, signature)
    entry_section = _section_for_rva(layout.sections, layout.entry_point_rva)
    clr_status = _classify_clr(data, layout)
    dotnet = clr_status is not None
    pe = PeSummary(
        machine=layout.machine,
        architecture=layout.architecture.value,
        subsystem=layout.subsystem,
        characteristics=layout.characteristics,
        dll_characteristics=layout.dll_characteristics,
        image_base=layout.image_base,
        image_size=layout.image_size,
        entry_point_rva=layout.entry_point_rva,
        entry_point_section=entry_section.name if entry_section is not None else None,
        entry_point_executable=bool(entry_section and entry_section.executable),
        section_alignment=layout.section_alignment,
        file_alignment=layout.file_alignment,
        linker_version=layout.linker_version,
        sections=sections,
        imports=imports,
        tls=tls,
        overlay_offset=overlay_offset,
        overlay_size=overlay_size,
        dotnet=dotnet,
        signature=signature,
    )
    findings = _build_findings(pe, clr_status=clr_status)
    duration_ms = max(0, int((monotonic() - started) * 1000))
    return DetectionReport(
        path=resolved,
        sha256=hashlib.sha256(data).hexdigest(),
        size=len(data),
        scanned_at=datetime.now(UTC),
        mode=mode,
        format="PE",
        architecture=layout.architecture.value,
        pe=pe,
        findings=findings,
        sources=(
            DetectionSource(
                name="builtin.pe",
                status="completed",
                version="1",
                duration_ms=duration_ms,
                summary="bounded PE structural analysis",
            ),
        ),
    )


def _parse_layout(data: bytes) -> _Layout:
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise PeFormatError("input does not contain a valid DOS header")
    pe_offset = _u32(data, 0x3C)
    if pe_offset < 0x40 or pe_offset + 24 > len(data):
        raise PeFormatError("PE header offset is outside the input")
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise PeFormatError("input does not contain a valid PE signature")

    file_header = pe_offset + 4
    machine = _u16(data, file_header)
    architecture = _architecture(machine)
    section_count = _u16(data, file_header + 2)
    optional_size = _u16(data, file_header + 16)
    characteristics = _u16(data, file_header + 18)
    if not 1 <= section_count <= _MAX_SECTIONS:
        raise PeFormatError(f"PE section count is outside the supported range: {section_count}")

    optional_offset = file_header + 20
    optional_end = optional_offset + optional_size
    if optional_end > len(data):
        raise PeFormatError("PE optional header is truncated")
    magic = _u16(data, optional_offset)
    expected_magic = 0x10B if architecture == Architecture.X86 else 0x20B
    minimum_optional_size = 96 if architecture == Architecture.X86 else 112
    if magic != expected_magic or optional_size < minimum_optional_size:
        raise PeFormatError("PE optional header is inconsistent with its machine type")

    image_base_offset = optional_offset + (28 if architecture == Architecture.X86 else 24)
    image_base = (
        _u32(data, image_base_offset)
        if architecture == Architecture.X86
        else _u64(data, image_base_offset)
    )
    entry_point_rva = _u32(data, optional_offset + 16)
    section_alignment = _u32(data, optional_offset + 32)
    file_alignment = _u32(data, optional_offset + 36)
    image_size = _u32(data, optional_offset + 56)
    size_of_headers = _u32(data, optional_offset + 60)
    subsystem = _u16(data, optional_offset + 68)
    dll_characteristics = _u16(data, optional_offset + 70)
    linker_version = f"{data[optional_offset + 2]}.{data[optional_offset + 3]}"
    directory_count_offset = optional_offset + (
        92 if architecture == Architecture.X86 else 108
    )
    directory_offset = optional_offset + (96 if architecture == Architecture.X86 else 112)
    directory_count = min(_u32(data, directory_count_offset), 16)
    if directory_offset + directory_count * 8 > optional_end:
        raise PeFormatError("PE data directory array is truncated")
    directories = tuple(
        (_u32(data, directory_offset + index * 8), _u32(data, directory_offset + index * 8 + 4))
        for index in range(directory_count)
    )

    sections_offset = optional_end
    if sections_offset + section_count * 40 > len(data):
        raise PeFormatError("PE section table is truncated")
    section_table_end = sections_offset + section_count * 40
    sections = tuple(
        _parse_section(data, sections_offset + index * 40)
        for index in range(section_count)
    )
    _validate_layout(
        data,
        image_base=image_base,
        image_size=image_size,
        section_alignment=section_alignment,
        file_alignment=file_alignment,
        size_of_headers=size_of_headers,
        section_table_end=section_table_end,
        sections=sections,
    )
    return _Layout(
        machine=machine,
        architecture=architecture,
        characteristics=characteristics,
        subsystem=subsystem,
        dll_characteristics=dll_characteristics,
        image_base=image_base,
        image_size=image_size,
        entry_point_rva=entry_point_rva,
        section_alignment=section_alignment,
        file_alignment=file_alignment,
        linker_version=linker_version,
        size_of_headers=size_of_headers,
        directories=directories,
        sections=sections,
    )


def _architecture(machine: int) -> Architecture:
    if machine == 0x014C:
        return Architecture.X86
    if machine == 0x8664:
        return Architecture.X64
    raise PeFormatError(f"unsupported PE machine: 0x{machine:04X}")


def _parse_section(data: bytes, offset: int) -> _Section:
    raw_name = data[offset : offset + 8].split(b"\0", 1)[0]
    name = raw_name.decode("ascii", errors="replace") or "<unnamed>"
    return _Section(
        name=name,
        virtual_size=_u32(data, offset + 8),
        virtual_address=_u32(data, offset + 12),
        raw_size=_u32(data, offset + 16),
        raw_offset=_u32(data, offset + 20),
        characteristics=_u32(data, offset + 36),
    )


def _validate_layout(
    data: bytes,
    *,
    image_base: int,
    image_size: int,
    section_alignment: int,
    file_alignment: int,
    size_of_headers: int,
    section_table_end: int,
    sections: tuple[_Section, ...],
) -> None:
    if image_base <= 0 or image_size <= 0:
        raise PeFormatError("PE image base and image size must be positive")
    if section_alignment <= 0 or file_alignment <= 0:
        raise PeFormatError("PE section and file alignments must be positive")
    if size_of_headers <= 0 or size_of_headers > len(data):
        raise PeFormatError("PE SizeOfHeaders is outside the input")
    if image_size < size_of_headers or section_table_end > size_of_headers:
        raise PeFormatError("PE headers exceed SizeOfImage or SizeOfHeaders")

    virtual_ranges: list[tuple[int, int, str]] = []
    raw_ranges: list[tuple[int, int, str]] = []
    for section in sections:
        raw_end = section.raw_offset + section.raw_size
        image_end = section.virtual_address + section.mapped_size
        if raw_end > len(data):
            raise PeFormatError(f"section raw data is truncated: {section.name}")
        if section.raw_size and section.raw_offset < size_of_headers:
            raise PeFormatError(f"section raw data overlaps PE headers: {section.name}")
        if image_end > image_size:
            raise PeFormatError(f"section exceeds SizeOfImage: {section.name}")
        if section.mapped_size:
            virtual_ranges.append((section.virtual_address, image_end, section.name))
        if section.raw_size:
            raw_ranges.append((section.raw_offset, raw_end, section.name))

    for ranges, label in ((virtual_ranges, "virtual"), (raw_ranges, "raw")):
        ranges.sort(key=lambda item: (item[0], item[1], item[2]))
        previous: tuple[int, int, str] | None = None
        for current in ranges:
            if previous is not None and current[0] < previous[1]:
                raise PeFormatError(
                    f"PE sections have overlapping {label} ranges: "
                    f"{previous[2]} and {current[2]}"
                )
            previous = current


def _section_summary(data: bytes, section: _Section) -> SectionSummary:
    raw = data[section.raw_offset : section.raw_offset + section.raw_size]
    return SectionSummary(
        name=section.name,
        virtual_address=section.virtual_address,
        virtual_size=section.virtual_size,
        raw_offset=section.raw_offset,
        raw_size=section.raw_size,
        characteristics=section.characteristics,
        permissions="".join(
            (
                "R" if section.readable else "-",
                "W" if section.writable else "-",
                "X" if section.executable else "-",
            )
        ),
        entropy=_entropy(raw),
    )


def _parse_imports(data: bytes, layout: _Layout) -> ImportSummary:
    import_rva, import_size = _directory(layout, _DIRECTORY_IMPORT)
    if import_rva == 0 or import_size == 0:
        return ImportSummary(library_count=0, function_count=0, ordinal_count=0)
    if import_size < 20:
        raise PeFormatError("PE import directory is smaller than one descriptor")
    descriptor_offset, raw_limit = _rva_raw_span(layout, import_rva, size=20)
    descriptor_limit = min(len(data), raw_limit, descriptor_offset + import_size)
    libraries: list[str] = []
    suspicious: set[str] = set()
    function_count = 0
    ordinal_count = 0
    truncated = False
    pointer_size = 4 if layout.architecture == Architecture.X86 else 8
    ordinal_flag = 1 << (31 if pointer_size == 4 else 63)

    while descriptor_offset + 20 <= descriptor_limit:
        values = tuple(_u32(data, descriptor_offset + index * 4) for index in range(5))
        if values == (0, 0, 0, 0, 0):
            break
        original_first_thunk, _, _, name_rva, first_thunk = values
        if len(libraries) >= _MAX_IMPORT_LIBRARIES:
            truncated = True
            break
        name_offset, name_limit = _rva_raw_span(layout, name_rva, size=1)
        library = _read_c_string(data, name_offset, limit=name_limit)
        libraries.append(library)
        thunk_rva = original_first_thunk or first_thunk
        if thunk_rva == 0:
            raise PeFormatError("PE import descriptor has no thunk table")
        thunk_offset, thunk_limit = _rva_raw_span(layout, thunk_rva, size=pointer_size)
        while thunk_offset + pointer_size <= min(len(data), thunk_limit):
            thunk = int.from_bytes(data[thunk_offset : thunk_offset + pointer_size], "little")
            if thunk == 0:
                break
            if function_count >= _MAX_IMPORT_FUNCTIONS:
                truncated = True
                break
            function_count += 1
            if thunk & ordinal_flag:
                ordinal_count += 1
            else:
                name_offset, name_limit = _rva_raw_span(layout, thunk, size=3)
                api = _read_c_string(data, name_offset + 2, limit=name_limit)
                if api.casefold() in _SUSPICIOUS_APIS:
                    suspicious.add(api)
            thunk_offset += pointer_size
        if truncated:
            break
        descriptor_offset += 20
    else:
        truncated = True

    return ImportSummary(
        library_count=len(libraries),
        function_count=function_count,
        ordinal_count=ordinal_count,
        libraries=tuple(libraries),
        suspicious_apis=tuple(sorted(suspicious, key=str.casefold)),
        truncated=truncated,
    )


def _parse_tls(data: bytes, layout: _Layout) -> TlsSummary:
    tls_rva, tls_size = _directory(layout, _DIRECTORY_TLS)
    if tls_rva == 0 or tls_size == 0:
        return TlsSummary(present=False, callback_count=0)
    structure_size = 24 if layout.architecture == Architecture.X86 else 40
    pointer_size = 4 if layout.architecture == Architecture.X86 else 8
    if tls_size < structure_size:
        raise PeFormatError("PE TLS directory is smaller than its architecture-specific header")
    tls_offset, _ = _rva_raw_span(layout, tls_rva, size=structure_size)
    callbacks_field = tls_offset + (12 if pointer_size == 4 else 24)
    callbacks_va = int.from_bytes(
        data[callbacks_field : callbacks_field + pointer_size], "little"
    )
    if callbacks_va == 0:
        return TlsSummary(present=True, callback_count=0)
    if callbacks_va < layout.image_base:
        raise PeFormatError("TLS callback array VA precedes ImageBase")
    callbacks_rva = callbacks_va - layout.image_base
    callback_offset, callback_limit = _rva_raw_span(layout, callbacks_rva, size=pointer_size)
    callbacks: list[int] = []
    truncated = False
    while callback_offset + pointer_size <= min(len(data), callback_limit):
        callback = int.from_bytes(
            data[callback_offset : callback_offset + pointer_size], "little"
        )
        if callback == 0:
            break
        if len(callbacks) >= _MAX_TLS_CALLBACKS:
            truncated = True
            break
        callbacks.append(callback)
        callback_offset += pointer_size
    else:
        truncated = True
    return TlsSummary(
        present=True,
        callback_count=len(callbacks),
        callbacks=tuple(callbacks),
        truncated=truncated,
    )


def _signature_summary(data: bytes, layout: _Layout) -> SignatureSummary:
    offset, size = _directory(layout, _DIRECTORY_SECURITY)
    if offset == 0 and size == 0:
        return SignatureSummary(status="absent", certificate_offset=0, certificate_size=0)
    # The security directory is the one PE directory expressed as a file
    # offset (not an RVA).  A non-zero half, an unaligned offset, or a span
    # beyond EOF is metadata corruption rather than an unsigned image.
    if offset == 0 or size == 0 or offset % 8:
        return SignatureSummary(
            status="malformed",
            certificate_offset=offset,
            certificate_size=size,
        )
    end = offset + size
    if end < offset or end > len(data):
        return SignatureSummary(
            status="malformed",
            certificate_offset=offset,
            certificate_size=size,
        )
    return SignatureSummary(
        status="present_unverified",
        certificate_offset=offset,
        certificate_size=size,
    )


def _overlay(
    data: bytes,
    layout: _Layout,
    signature: SignatureSummary,
) -> tuple[int, int]:
    image_end = max(
        (section.raw_offset + section.raw_size for section in layout.sections),
        default=layout.size_of_headers,
    )
    if signature.status == "present_unverified":
        image_end = max(image_end, signature.certificate_offset + signature.certificate_size)
    image_end = min(image_end, len(data))
    return image_end, len(data) - image_end


def _classify_clr(data: bytes, layout: _Layout) -> str | None:
    """Classify COM descriptor honesty: absent, directory-only hint, or verified.

    Returns ``None`` when the COM descriptor directory is empty, ``\"hint\"`` when
    the directory is populated but COR20/BSJB cannot be confirmed from mapped
    bytes, and ``\"verified\"`` when a readable COR20 header points at BSJB
    metadata.
    """

    rva, size = _directory(layout, _DIRECTORY_COM_DESCRIPTOR)
    if rva == 0 and size == 0:
        return None
    # Directory present: only claim a real CLR header when MetaData+BSJB map.
    try:
        header_need = _CLR_HEADER_MIN_READ
        if 0 < size < header_need:
            return "hint"
        map_size = header_need if size == 0 else min(size, max(header_need, 72))
        offset = _rva_to_offset(layout, rva, size=map_size)
        header = _slice(data, offset, map_size)
        meta_rva = int.from_bytes(
            header[_CLR_HEADER_METADATA_OFF : _CLR_HEADER_METADATA_OFF + 4], "little"
        )
        meta_size = int.from_bytes(
            header[_CLR_HEADER_METADATA_OFF + 4 : _CLR_HEADER_METADATA_OFF + 8],
            "little",
        )
        if meta_rva == 0 or meta_size < len(_CLR_METADATA_SIG):
            return "hint"
        meta_off = _rva_to_offset(layout, meta_rva, size=len(_CLR_METADATA_SIG))
        if _slice(data, meta_off, len(_CLR_METADATA_SIG)) != _CLR_METADATA_SIG:
            return "hint"
    except PeFormatError:
        return "hint"
    return "verified"


def _build_findings(
    pe: PeSummary,
    *,
    clr_status: str | None = None,
) -> tuple[DetectionFinding, ...]:
    findings: list[DetectionFinding] = [
        DetectionFinding(
            id="builtin:format:pe",
            category=FindingCategory.FILE_FORMAT,
            name="Portable Executable",
            summary=f"Supported {pe.architecture} PE image",
            confidence=1.0,
            source="builtin.pe",
            evidence=(
                DetectionEvidence(
                    kind="header",
                    description="PE signature and machine type are structurally valid",
                    details={"machine": pe.machine, "architecture": pe.architecture},
                ),
            ),
        )
    ]
    if pe.dotnet:
        verified = clr_status == "verified"
        findings.append(
            DetectionFinding(
                id="builtin:runtime:dotnet",
                category=FindingCategory.RUNTIME,
                name=".NET CLR",
                summary=(
                    "CLR runtime header is present"
                    if verified
                    else "CLR directory hint"
                ),
                confidence=0.99 if verified else 0.55,
                source="builtin.pe",
                evidence=(
                    DetectionEvidence(
                        kind="data_directory",
                        description=(
                            "COM descriptor maps to a COR20 header with BSJB metadata"
                            if verified
                            else (
                                "COM descriptor directory is populated; "
                                "CLR header/metadata not verified from mapped span"
                            )
                        ),
                        details={"clr_status": clr_status or "hint"},
                    ),
                ),
            )
        )
    section_names = {section.name.upper() for section in pe.sections}
    if {"UPX0", "UPX1"} & section_names or any(
        name.startswith("UPX") for name in section_names
    ):
        # Structural hint only: standard UPX leaves UPX0/UPX1 section names.
        # Modified stubs may still fail official `upx -t` / `upx -d`.
        findings.append(
            DetectionFinding(
                id="builtin:packer:upx-sections",
                category=FindingCategory.PACKER,
                name="UPX",
                summary="Section names match the common UPX stub layout (UPX0/UPX1)",
                confidence=0.85,
                source="builtin.pe",
                evidence=(
                    DetectionEvidence(
                        kind="section_name",
                        description="Observed UPX-style section names",
                        details={"sections": sorted(section_names)},
                    ),
                ),
            )
        )
    if not pe.entry_point_executable:
        findings.append(
            _anomaly(
                "entry-point-not-executable",
                "Entry point is not mapped by an executable section",
                0.95,
                {"entry_point_rva": pe.entry_point_rva, "section": pe.entry_point_section},
                severity=FindingSeverity.WARNING,
            )
        )
    for section in pe.sections:
        if section.permissions == "RWX":
            findings.append(
                _anomaly(
                    f"rwx-section:{section.name}",
                    f"Section {section.name} is readable, writable, and executable",
                    0.9,
                    {"section": section.name, "permissions": section.permissions},
                    severity=FindingSeverity.WARNING,
                )
            )
        if section.entropy >= 7.2 and section.raw_size >= 512:
            findings.append(
                _anomaly(
                    f"high-entropy:{section.name}",
                    f"Section {section.name} has high entropy; this is only a packing hint",
                    min(0.9, 0.55 + (section.entropy - 7.2) * 0.4),
                    {
                        "section": section.name,
                        "entropy": section.entropy,
                        "raw_size": section.raw_size,
                    },
                )
            )
        if section.virtual_size > max(section.raw_size * 8, section.raw_size + 1024 * 1024):
            findings.append(
                _anomaly(
                    f"virtual-raw-gap:{section.name}",
                    f"Section {section.name} has an unusually large virtual/raw size gap",
                    0.65,
                    {
                        "section": section.name,
                        "virtual_size": section.virtual_size,
                        "raw_size": section.raw_size,
                    },
                )
            )
    if pe.imports.library_count <= 1 and pe.imports.function_count <= 8:
        findings.append(
            _anomaly(
                "sparse-imports",
                "Import table is sparse; this can occur in loaders or small benign programs",
                0.55,
                {
                    "library_count": pe.imports.library_count,
                    "function_count": pe.imports.function_count,
                },
            )
        )
    if pe.imports.suspicious_apis:
        findings.append(
            _anomaly(
                "loader-apis",
                "Import table contains APIs commonly used by runtime loaders",
                0.55,
                {"apis": list(pe.imports.suspicious_apis)},
            )
        )
    if pe.tls.callback_count:
        findings.append(
            _anomaly(
                "tls-callbacks",
                "TLS callbacks execute before the normal entry point",
                0.65,
                {"callback_count": pe.tls.callback_count},
            )
        )
    if pe.overlay_size:
        findings.append(
            _anomaly(
                "overlay",
                "Data exists after the mapped image and certificate table",
                0.5,
                {"offset": pe.overlay_offset, "size": pe.overlay_size},
            )
        )
    if not _alignment_is_conventional(pe.section_alignment, pe.file_alignment):
        findings.append(
            _anomaly(
                "unusual-alignment",
                "PE section or file alignment is unusual",
                0.7,
                {
                    "section_alignment": pe.section_alignment,
                    "file_alignment": pe.file_alignment,
                },
            )
        )
    if pe.signature.status == "malformed":
        findings.append(
            _anomaly(
                "malformed-certificate-directory",
                "Certificate directory extends beyond the input",
                0.95,
                {
                    "offset": pe.signature.certificate_offset,
                    "size": pe.signature.certificate_size,
                },
                severity=FindingSeverity.WARNING,
            )
        )
    return tuple(findings)


def _anomaly(
    suffix: str,
    summary: str,
    confidence: float,
    details: dict[str, object],
    *,
    severity: FindingSeverity = FindingSeverity.HINT,
) -> DetectionFinding:
    return DetectionFinding(
        id=f"builtin:anomaly:{suffix}",
        category=FindingCategory.ANOMALY,
        name=suffix.replace("-", " "),
        summary=summary,
        confidence=confidence,
        severity=severity,
        source="builtin.pe",
        evidence=(
            DetectionEvidence(
                kind="pe_heuristic",
                description=summary,
                details=details,
            ),
        ),
    )


def _directory(layout: _Layout, index: int) -> tuple[int, int]:
    return layout.directories[index] if index < len(layout.directories) else (0, 0)


def _section_for_rva(sections: tuple[_Section, ...], rva: int) -> _Section | None:
    return next(
        (
            section
            for section in sections
            if section.virtual_address <= rva < section.virtual_address + section.mapped_size
        ),
        None,
    )


def _rva_raw_span(layout: _Layout, rva: int, *, size: int) -> tuple[int, int]:
    """Map an RVA and return its file offset plus the containing raw limit.

    Directory tables and thunk arrays must not be allowed to run into the next
    section (or an overlay).  Keeping the raw limit alongside the mapped
    offset makes all bounded table readers use the same PE mapping rules.
    """

    if rva < 0 or size <= 0:
        raise PeFormatError("RVA mapping requires a non-negative RVA and positive size")
    end = rva + size
    if end < rva:  # defensive guard for callers that may pass untrusted integers
        raise PeFormatError("RVA mapping overflows")
    if rva < layout.size_of_headers:
        if end > layout.size_of_headers:
            raise PeFormatError(f"RVA points outside PE headers: 0x{rva:X}")
        return rva, layout.size_of_headers
    section = _section_for_rva(layout.sections, rva)
    if section is None:
        raise PeFormatError(f"RVA is not mapped by the PE image: 0x{rva:X}")
    delta = rva - section.virtual_address
    if delta + size > section.raw_size:
        raise PeFormatError(f"RVA points outside section raw data: 0x{rva:X}")
    offset = section.raw_offset + delta
    return offset, section.raw_offset + section.raw_size


def _rva_to_offset(layout: _Layout, rva: int, *, size: int) -> int:
    return _rva_raw_span(layout, rva, size=size)[0]


def _read_c_string(data: bytes, offset: int, *, limit: int | None = None) -> str:
    if offset < 0 or offset >= len(data):
        raise PeFormatError("string offset is outside the input")
    upper_bound = len(data) if limit is None else min(len(data), limit)
    if upper_bound <= offset:
        raise PeFormatError("string offset is outside its PE section")
    end = data.find(b"\0", offset, min(upper_bound, offset + _MAX_C_STRING + 1))
    if end < 0:
        raise PeFormatError("PE string is unterminated or exceeds the bounded limit")
    return data[offset:end].decode("utf-8", errors="replace")


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    length = len(data)
    result = -sum(
        (count / length) * math.log2(count / length)
        for count in counts
        if count
    )
    return round(result, 4)


def _alignment_is_conventional(section_alignment: int, file_alignment: int) -> bool:
    if not _is_power_of_two(file_alignment) or not 0x200 <= file_alignment <= 0x10000:
        return False
    if not _is_power_of_two(section_alignment):
        return False
    return section_alignment >= file_alignment


def _is_power_of_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0


def _u16(data: bytes, offset: int) -> int:
    return int.from_bytes(_slice(data, offset, 2), "little")


def _u32(data: bytes, offset: int) -> int:
    return int.from_bytes(_slice(data, offset, 4), "little")


def _u64(data: bytes, offset: int) -> int:
    return int.from_bytes(_slice(data, offset, 8), "little")


def _slice(data: bytes, offset: int, size: int) -> bytes:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise PeFormatError("PE structure is truncated")
    return data[offset : offset + size]
