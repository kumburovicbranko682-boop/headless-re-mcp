from __future__ import annotations

import struct
import tracemalloc
from dataclasses import dataclass
from pathlib import Path

import pytest

from headless_re_mcp.detection import PeFormatError, ScanMode, scan_pe
from headless_re_mcp.detection.models import (
    DetectionEvidence,
    DetectionFinding,
    FindingCategory,
    ImportSummary,
    SectionSummary,
    SignatureSummary,
    TlsSummary,
)

_IMAGE_SCN_MEM_EXECUTE = 0x20000000
_IMAGE_SCN_MEM_READ = 0x40000000
_IMAGE_SCN_MEM_WRITE = 0x80000000
_IMAGE_SCN_CODE = 0x00000020
_IMAGE_SCN_INITIALIZED_DATA = 0x00000040


def _align(value: int, alignment: int) -> int:
    if alignment <= 1:
        return value
    return ((value + alignment - 1) // alignment) * alignment


@dataclass
class _SyntheticSection:
    name: str
    virtual_address: int
    raw_offset: int
    data: bytearray
    virtual_size: int
    characteristics: int


class _SyntheticPe:
    """Small deterministic PE writer used to exercise the parser itself.

    The writer deliberately emits both PE32 and PE32+ headers and places every
    directory in a section, so tests do not rely on a host compiler or a
    platform-specific executable.
    """

    def __init__(self, architecture: str) -> None:
        if architecture not in {"x86", "x64"}:
            raise ValueError(architecture)
        self.architecture = architecture
        self.machine = 0x14C if architecture == "x86" else 0x8664
        self.image_base = 0x00400000 if architecture == "x86" else 0x140000000
        self.pointer_size = 4 if architecture == "x86" else 8
        self.magic = 0x10B if architecture == "x86" else 0x20B
        self.optional_size = 0xE0 if architecture == "x86" else 0xF0
        self.section_alignment = 0x1000
        self.file_alignment = 0x200
        self.subsystem = 3
        self.entry_point_rva = 0x1000
        self.dll_characteristics = 0x8160
        self.sections: list[_SyntheticSection] = []
        self.directories: dict[int, tuple[int, int]] = {}
        self._next_va = 0x1000
        self._next_raw = 0x400

    def add_section(
        self,
        name: str,
        *,
        size: int = 0x400,
        characteristics: int = _IMAGE_SCN_MEM_READ | _IMAGE_SCN_INITIALIZED_DATA,
        virtual_size: int | None = None,
    ) -> _SyntheticSection:
        if size <= 0:
            raise ValueError("section size must be positive")
        section = _SyntheticSection(
            name=name,
            virtual_address=self._next_va,
            raw_offset=self._next_raw,
            data=bytearray(size),
            virtual_size=size if virtual_size is None else virtual_size,
            characteristics=characteristics,
        )
        self.sections.append(section)
        self._next_va += _align(max(section.virtual_size, size), self.section_alignment)
        self._next_raw += _align(size, self.file_alignment)
        return section

    def rva(self, section: _SyntheticSection, offset: int = 0) -> int:
        if not 0 <= offset <= len(section.data):
            raise ValueError("section offset outside raw data")
        return section.virtual_address + offset

    def write(self, section: _SyntheticSection, offset: int, payload: bytes) -> None:
        end = offset + len(payload)
        if offset < 0 or end > len(section.data):
            raise ValueError("section write outside raw data")
        section.data[offset:end] = payload

    def add_imports(
        self,
        section: _SyntheticSection,
        libraries: list[tuple[str, list[str | int]]],
        *,
        terminate: bool = True,
    ) -> None:
        pointer_size = self.pointer_size
        ordinal_flag = 1 << (31 if pointer_size == 4 else 63)
        descriptor_size = 20
        thunk_offset = 0x100
        name_offset = 0x240
        hint_name_offset = 0x2C0
        for index, (library, functions) in enumerate(libraries):
            descriptor_offset = index * descriptor_size
            thunk_rva = self.rva(section, thunk_offset)
            first_thunk_rva = self.rva(section, thunk_offset + pointer_size * (len(functions) + 1))
            name_rva = self.rva(section, name_offset)
            self.write(section, name_offset, library.encode("ascii") + b"\0")
            name_offset += len(library) + 1
            for thunk_index, function in enumerate(functions):
                if isinstance(function, int):
                    value = ordinal_flag | function
                else:
                    hint_name_rva = self.rva(section, hint_name_offset)
                    self.write(
                        section,
                        hint_name_offset,
                        struct.pack("<H", 0) + function.encode("ascii") + b"\0",
                    )
                    hint_name_offset += 2 + len(function) + 1
                    value = hint_name_rva
                self.write(
                    section,
                    thunk_offset + thunk_index * pointer_size,
                    value.to_bytes(pointer_size, "little"),
                )
            self.write(
                section,
                thunk_offset + len(functions) * pointer_size,
                b"\0" * pointer_size,
            )
            self.write(
                section,
                thunk_offset + pointer_size * (len(functions) + 1),
                b"\0" * pointer_size,
            )
            self.write(
                section,
                descriptor_offset,
                struct.pack(
                    "<IIIII",
                    thunk_rva,
                    0,
                    0,
                    name_rva,
                    first_thunk_rva,
                ),
            )
            thunk_offset += pointer_size * (len(functions) + 2)
        descriptor_count = len(libraries) + (1 if terminate else 0)
        self.directories[1] = (self.rva(section), descriptor_count * descriptor_size)

    def add_tls(
        self, section: _SyntheticSection, callbacks: list[int], *, terminate: bool = True
    ) -> None:
        pointer_size = self.pointer_size
        callback_offset = 0x100
        callback_values = callbacks + ([0] if terminate else [])
        for index, callback in enumerate(callback_values):
            value = (
                0
                if callback == 0
                else (callback if callback >= self.image_base else self.image_base + callback)
            )
            self.write(
                section,
                callback_offset + index * pointer_size,
                value.to_bytes(pointer_size, "little"),
            )
        callbacks_va = self.image_base + self.rva(section, callback_offset)
        if self.architecture == "x86":
            directory = struct.pack("<IIIIII", 0, 0, 0, callbacks_va, 0, 0)
        else:
            directory = struct.pack("<QQQQII", 0, 0, 0, callbacks_va, 0, 0)
        self.write(section, 0, directory)
        self.directories[9] = (self.rva(section), len(directory))

    def build(
        self,
        *,
        certificate: bytes = b"",
        overlay: bytes = b"",
        certificate_directory: tuple[int, int] | None = None,
    ) -> bytes:
        pe_offset = 0x80
        optional_offset = pe_offset + 4 + 20
        section_table_offset = optional_offset + self.optional_size
        size_of_headers = _align(
            section_table_offset + len(self.sections) * 40, self.file_alignment
        )
        max_raw_end = max(
            (section.raw_offset + len(section.data) for section in self.sections),
            default=size_of_headers,
        )
        certificate_offset = _align(max_raw_end, 8)
        if certificate:
            self.directories[4] = (certificate_offset, len(certificate))
        elif certificate_directory is not None:
            self.directories[4] = certificate_directory
        image_end = max(
            (
                section.virtual_address + max(section.virtual_size, len(section.data))
                for section in self.sections
            ),
            default=size_of_headers,
        )
        image_size = _align(image_end, self.section_alignment)
        total_size = (
            max_raw_end,
            certificate_offset + len(certificate),
            certificate_offset + len(certificate) + len(overlay),
        )
        data = bytearray(max(total_size))
        data[0:2] = b"MZ"
        struct.pack_into("<I", data, 0x3C, pe_offset)
        data[pe_offset : pe_offset + 4] = b"PE\0\0"
        file_header = pe_offset + 4
        characteristics = 0x2022 if self.architecture == "x64" else 0x0102
        struct.pack_into(
            "<HHIIIHH",
            data,
            file_header,
            self.machine,
            len(self.sections),
            0,
            0,
            0,
            self.optional_size,
            characteristics,
        )
        optional = bytearray(self.optional_size)
        struct.pack_into("<HBB", optional, 0, self.magic, 14, 44)
        struct.pack_into("<I", optional, 16, self.entry_point_rva)
        if self.architecture == "x86":
            struct.pack_into("<I", optional, 28, self.image_base)
            directory_count_offset = 92
            directory_offset = 96
        else:
            struct.pack_into("<Q", optional, 24, self.image_base)
            directory_count_offset = 108
            directory_offset = 112
        struct.pack_into("<II", optional, 32, self.section_alignment, self.file_alignment)
        struct.pack_into("<II", optional, 56, image_size, size_of_headers)
        struct.pack_into("<HH", optional, 68, self.subsystem, self.dll_characteristics)
        struct.pack_into("<I", optional, directory_count_offset, 16)
        for index, (rva_or_offset, size) in self.directories.items():
            if 0 <= index < 16:
                struct.pack_into("<II", optional, directory_offset + index * 8, rva_or_offset, size)
        data[optional_offset : optional_offset + self.optional_size] = optional
        for index, section in enumerate(self.sections):
            offset = section_table_offset + index * 40
            encoded_name = section.name.encode("ascii", errors="replace")[:8]
            data[offset : offset + 8] = encoded_name.ljust(8, b"\0")
            struct.pack_into(
                "<IIII",
                data,
                offset + 8,
                section.virtual_size,
                section.virtual_address,
                len(section.data),
                section.raw_offset,
            )
            struct.pack_into("<I", data, offset + 36, section.characteristics)
            data[section.raw_offset : section.raw_offset + len(section.data)] = section.data
        if certificate:
            data[certificate_offset : certificate_offset + len(certificate)] = certificate
            data[certificate_offset + len(certificate) :] = overlay
        elif overlay:
            data[max_raw_end : max_raw_end + len(overlay)] = overlay
        return bytes(data)


def _sample(
    architecture: str,
    *,
    imports: bool = True,
    tls: bool = True,
    certificate: bytes = b"",
    overlay: bytes = b"",
    dotnet: bool = True,
    rwx: bool = True,
    high_entropy: bool = True,
    tls_terminate: bool = True,
    import_terminate: bool = True,
) -> bytes:
    pe = _SyntheticPe(architecture)
    text_characteristics = _IMAGE_SCN_MEM_READ | _IMAGE_SCN_MEM_EXECUTE | _IMAGE_SCN_CODE
    if rwx:
        text_characteristics |= _IMAGE_SCN_MEM_WRITE
    text = pe.add_section(".text", size=0x400, characteristics=text_characteristics)
    idata = pe.add_section(".idata", size=0x600)
    tls_section = pe.add_section(
        ".tls", size=0x100 + 3 * pe.pointer_size if tls_terminate else 0x100 + 2 * pe.pointer_size
    )
    packed = pe.add_section(".packed", size=0x400)
    if high_entropy:
        packed.data[:] = bytes(range(256)) * 4
    if imports:
        pe.add_imports(
            idata,
            [
                ("KERNEL32.dll", ["LoadLibraryW", "VirtualProtect", 7]),
                ("USER32.dll", ["MessageBoxW"]),
            ],
            terminate=import_terminate,
        )
    if tls:
        pe.add_tls(tls_section, [0x1100, 0x1200], terminate=tls_terminate)
    if dotnet:
        pe.directories[14] = (pe.rva(text, 0x100), 72)
    return pe.build(certificate=certificate, overlay=overlay)


@pytest.mark.parametrize("architecture", ["x86", "x64"])
def test_scan_synthetic_x86_and_x64_covers_structural_fields(
    tmp_path: Path, architecture: str
) -> None:
    path = tmp_path / f"sample-{architecture}.exe"
    path.write_bytes(_sample(architecture, certificate=b"CERTIFICATE" * 2, overlay=b"OVERLAY"))

    report = scan_pe(path, mode=ScanMode.DEEP)

    assert report.format == "PE"
    assert report.architecture == architecture
    assert report.mode is ScanMode.DEEP
    assert report.size == path.stat().st_size
    assert report.sha256
    assert report.pe.machine == (0x14C if architecture == "x86" else 0x8664)
    assert report.pe.subsystem == 3
    assert report.pe.entry_point_section == ".text"
    assert report.pe.entry_point_executable
    assert {section.name for section in report.pe.sections} == {
        ".text",
        ".idata",
        ".tls",
        ".packed",
    }
    assert report.pe.signature.status == "present_unverified"
    assert report.pe.signature.certificate_size == 22
    assert report.pe.overlay_size == 7
    assert report.pe.dotnet


@pytest.mark.parametrize("architecture", ["x86", "x64"])
def test_imports_tls_entropy_rwx_and_dotnet_findings(tmp_path: Path, architecture: str) -> None:
    path = tmp_path / f"features-{architecture}.exe"
    path.write_bytes(_sample(architecture))
    report = scan_pe(path)

    assert report.pe.imports.library_count == 2
    assert report.pe.imports.function_count == 4
    assert report.pe.imports.ordinal_count == 1
    assert report.pe.imports.libraries == ("KERNEL32.dll", "USER32.dll")
    assert report.pe.imports.suspicious_apis == ("LoadLibraryW", "VirtualProtect")
    assert not report.pe.imports.truncated
    assert report.pe.tls.present
    assert report.pe.tls.callback_count == 2
    assert report.pe.tls.callbacks == (
        0x401100 if architecture == "x86" else 0x140001100,
        0x401200 if architecture == "x86" else 0x140001200,
    )
    assert not report.pe.tls.truncated
    packed = next(section for section in report.pe.sections if section.name == ".packed")
    assert packed.entropy == 8.0
    assert packed.permissions == "R--"
    assert any(finding.id == "builtin:anomaly:rwx-section:.text" for finding in report.findings)
    assert any(finding.id == "builtin:anomaly:high-entropy:.packed" for finding in report.findings)
    dotnet = next(f for f in report.findings if f.id == "builtin:runtime:dotnet")
    # Synthetic sample only populates the COM directory — honesty path is a hint.
    assert dotnet.summary == "CLR directory hint"
    assert dotnet.confidence == 0.55


def test_tls_and_import_tables_are_bounded_to_raw_section(tmp_path: Path) -> None:
    path = tmp_path / "truncated-tables.exe"
    path.write_bytes(
        _sample("x64", tls_terminate=False, import_terminate=False, overlay=b"\x01" * 64)
    )

    report = scan_pe(path)

    assert report.pe.imports.truncated
    assert report.pe.tls.truncated
    # The callback reader must not consume the overlay as additional callback
    # addresses.  The bounded table contains at most the two emitted entries.
    assert report.pe.tls.callback_count == 2
    assert report.pe.overlay_size == 64


def test_overlay_without_certificate_starts_after_last_raw_section(tmp_path: Path) -> None:
    path = tmp_path / "overlay.exe"
    path.write_bytes(_sample("x86", certificate=b"", overlay=b"tail"))

    report = scan_pe(path)

    assert report.pe.signature.status == "absent"
    assert report.pe.overlay_size == 4
    assert report.pe.overlay_offset + report.pe.overlay_size == report.size


@pytest.mark.parametrize(
    ("directory", "expected_status"),
    [((0, 12), "malformed"), ((0x100000, 8), "malformed"), ((0x409, 8), "malformed")],
)
def test_certificate_directory_metadata_is_not_mistaken_for_unsigned(
    tmp_path: Path,
    directory: tuple[int, int],
    expected_status: str,
) -> None:
    pe = _SyntheticPe("x64")
    pe.add_section(
        ".text", size=0x400, characteristics=_IMAGE_SCN_MEM_READ | _IMAGE_SCN_MEM_EXECUTE
    )
    path = tmp_path / "certificate-metadata.exe"
    path.write_bytes(pe.build(certificate_directory=directory))

    report = scan_pe(path)

    assert report.pe.signature.status == expected_status
    assert report.pe.signature.certificate_offset == directory[0]
    assert report.pe.signature.certificate_size == directory[1]


@pytest.mark.parametrize(
    "mutator",
    [
        lambda data: data[:1],
        lambda data: data[:0x40],
        lambda data: data[:0x80] + b"NOPE" + data[0x84:],
        lambda data: data[:0x178],
        lambda data: data[:-1],
    ],
)
def test_truncated_or_bad_pe_is_rejected(tmp_path: Path, mutator: object) -> None:
    source = _sample("x86", imports=False, tls=False, dotnet=False)
    malformed = mutator(source)  # type: ignore[operator]
    path = tmp_path / "malformed.exe"
    path.write_bytes(malformed)

    with pytest.raises(PeFormatError):
        scan_pe(path)


def test_import_directory_smaller_than_descriptor_is_rejected(tmp_path: Path) -> None:
    pe = _SyntheticPe("x64")
    idata = pe.add_section(".idata", size=0x400)
    pe.add_imports(idata, [("KERNEL32.dll", ["ExitProcess"])])
    pe.directories[1] = (pe.rva(idata), 19)
    path = tmp_path / "short-import.exe"
    path.write_bytes(pe.build())

    with pytest.raises(PeFormatError, match="import directory"):
        scan_pe(path)


def test_size_limit_is_inclusive_and_validated(tmp_path: Path) -> None:
    path = tmp_path / "bounded.exe"
    path.write_bytes(_sample("x64", imports=False, tls=False, dotnet=False))
    size = path.stat().st_size

    assert scan_pe(path, max_file_size=size).size == size
    with pytest.raises(PeFormatError, match="scan limit"):
        scan_pe(path, max_file_size=size - 1)
    with pytest.raises(ValueError, match="must not be negative"):
        scan_pe(path, max_file_size=-1)
    with pytest.raises(TypeError, match="must be an integer"):
        scan_pe(path, max_file_size=True)  # type: ignore[arg-type]


def test_scan_reads_only_one_byte_beyond_the_configured_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "bounded-read.exe"
    payload = _sample("x64", imports=False, tls=False, dotnet=False)
    path.write_bytes(payload)
    requested: list[int] = []
    real_open = Path.open

    class BoundedReader:
        def __init__(self) -> None:
            self.stream = real_open(path, "rb")

        def __enter__(self) -> BoundedReader:
            self.stream.__enter__()
            return self

        def __exit__(self, *args: object) -> None:
            self.stream.__exit__(*args)

        def read(self, size: int = -1) -> bytes:
            requested.append(size)
            return self.stream.read(size)

    monkeypatch.setattr(Path, "open", lambda *_args, **_kwargs: BoundedReader())

    assert scan_pe(path, max_file_size=len(payload)).size == len(payload)
    assert requested == [len(payload) + 1]


def test_scan_allocation_tracks_file_size_not_the_configured_limit(
    tmp_path: Path,
) -> None:
    """A tiny input must not cost the whole budget in transient heap.

    ``_read_pe_bytes`` reads up to ``max_file_size + 1`` bytes, but a buffered
    ``read(n)`` allocates all ``n`` bytes before shrinking. The old single-call
    ``read(max_file_size + 1)`` therefore spiked the full budget -- 256 MiB at
    the default cap -- on every scan, whatever the file's real size, and scan_pe
    runs on every binary and twice per .NET enumeration. Chunking keeps the
    allocation proportional to what is actually there; pin that so nobody
    reintroduces the one-shot read.
    """
    path = tmp_path / "tiny.exe"
    path.write_bytes(_sample("x64", imports=False, tls=False, dotnet=False))
    assert path.stat().st_size < 64 * 1024

    tracemalloc.start()
    try:
        report = scan_pe(path)  # default max_file_size is 256 MiB
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert report.size == path.stat().st_size
    # The pre-fix peak was the full 256 MiB budget; anything near that means the
    # scanner is again allocating the cap rather than the file.
    assert peak < 8 * 1024 * 1024, f"scan of a {report.size}-byte file peaked at {peak} bytes"


def test_entry_point_at_section_end_is_not_executable(tmp_path: Path) -> None:
    pe = _SyntheticPe("x86")
    text = pe.add_section(
        ".text",
        size=0x200,
        characteristics=_IMAGE_SCN_MEM_READ | _IMAGE_SCN_MEM_EXECUTE,
    )
    pe.entry_point_rva = pe.rva(text, len(text.data))
    path = tmp_path / "entry-boundary.exe"
    path.write_bytes(pe.build())

    report = scan_pe(path)

    assert report.pe.entry_point_section is None
    assert not report.pe.entry_point_executable
    assert any(
        finding.id == "builtin:anomaly:entry-point-not-executable" for finding in report.findings
    )


def test_model_boundaries_and_frozen_extra_forbid() -> None:
    assert (
        SectionSummary(
            name=".text",
            virtual_address=0,
            virtual_size=0,
            raw_offset=0,
            raw_size=0,
            characteristics=0,
            permissions="---",
            entropy=0,
        ).permissions
        == "---"
    )
    assert ImportSummary(library_count=0, function_count=0, ordinal_count=0).truncated is False
    assert TlsSummary(present=False, callback_count=0).callbacks == ()
    assert (
        SignatureSummary(status="absent", certificate_offset=0, certificate_size=0).status
        == "absent"
    )
    with pytest.raises(ValueError):
        DetectionEvidence(kind="x", description="x", details={}, extra="nope")  # type: ignore[call-arg]
    with pytest.raises(ValueError):
        DetectionFinding(
            id="x",
            category=FindingCategory.ANOMALY,
            name="x",
            summary="x",
            confidence=1.1,
            source="x",
        )


@pytest.mark.parametrize(
    ("relative_path", "expected_architecture"),
    [
        ("artifacts/fixtures-x86/console_fixture.exe", "x86"),
        ("artifacts/fixtures-x64/console_fixture.exe", "x64"),
    ],
)
def test_compiled_fixture_if_present(relative_path: str, expected_architecture: str) -> None:
    path = Path(relative_path)
    if not path.is_file():
        pytest.skip("compiled fixture is not available in this checkout")

    report = scan_pe(path)

    assert report.architecture == expected_architecture
    assert report.pe.entry_point_executable
    assert report.pe.sections


def test_dotnet_minimal_clr_hint_fixture_is_directory_hint_only() -> None:
    """COM-directory stub must not claim a verified CLR runtime header."""
    path = Path(__file__).resolve().parents[2] / "fixtures" / "dotnet" / "minimal_clr_hint.exe"
    assert path.is_file(), f"missing fixture: {path}"

    report = scan_pe(path)

    assert report.pe.dotnet is True
    finding = next(f for f in report.findings if f.id == "builtin:runtime:dotnet")
    assert finding.summary == "CLR directory hint"
    assert finding.confidence == 0.55
    assert finding.confidence < 0.99
    assert finding.evidence[0].details.get("clr_status") == "hint"


# Byte offsets into a built x64 _SyntheticPe (PE header at 0x80). These pin the
# fields the parser reads straight from the DOS/COFF/optional header, so a test
# can corrupt exactly one and drive a single guard without depending on a
# compiled fixture. The hostile-input suite reaches these by mutating a real
# binary, but that suite skips when no native build exists; driving the same
# guards off the synthetic writer makes them run in every environment.
_X64_FILE_HEADER = 0x84
_X64_MACHINE = _X64_FILE_HEADER  # u16
_X64_SECTION_COUNT = _X64_FILE_HEADER + 2  # u16
_X64_OPTIONAL_SIZE = _X64_FILE_HEADER + 16  # u16
_X64_OPTIONAL = _X64_FILE_HEADER + 20  # optional header start
_X64_MAGIC = _X64_OPTIONAL  # u16
_X64_IMAGE_BASE = _X64_OPTIONAL + 24  # u64 (PE32+)
_X64_SECTION_ALIGNMENT = _X64_OPTIONAL + 32  # u32
_X64_FILE_ALIGNMENT = _X64_OPTIONAL + 36  # u32
_X64_IMAGE_SIZE = _X64_OPTIONAL + 56  # u32
_X64_SIZE_OF_HEADERS = _X64_OPTIONAL + 60  # u32


def _patched_x64(offset: int, fmt: str, value: int) -> bytes:
    data = bytearray(_sample("x64", imports=False, tls=False, dotnet=False))
    struct.pack_into(fmt, data, offset, value)
    return bytes(data)


@pytest.mark.parametrize(
    ("offset", "fmt", "value", "match"),
    [
        (_X64_MACHINE, "<H", 0xFFFF, "unsupported PE machine"),
        (_X64_SECTION_COUNT, "<H", 0, "section count is outside"),
        (_X64_SECTION_COUNT, "<H", 0xFFFF, "section count is outside"),
        (_X64_OPTIONAL_SIZE, "<H", 0xFFFF, "optional header is truncated"),
        (_X64_MAGIC, "<H", 0, "inconsistent with its machine type"),
    ],
)
def test_corrupt_pe_header_field_is_rejected_by_name(
    tmp_path: Path,
    offset: int,
    fmt: str,
    value: int,
    match: str,
) -> None:
    """One corrupt header field, one specific PeFormatError.

    Each case corrupts a single field the parser reads directly from the
    DOS/COFF/optional header -- an unsupported machine, a section count outside
    the supported range, an optional header claiming to run past the input, and
    a magic that disagrees with the machine -- and must raise a message that
    names the fault rather than a generic failure or something the result
    envelope cannot classify.
    """
    path = tmp_path / "corrupt-header.exe"
    path.write_bytes(_patched_x64(offset, fmt, value))
    with pytest.raises(PeFormatError, match=match):
        scan_pe(path)


@pytest.mark.parametrize(
    ("offset", "fmt", "value", "match"),
    [
        (_X64_IMAGE_BASE, "<Q", 0, "image base and image size must be positive"),
        (_X64_SECTION_ALIGNMENT, "<I", 0, "section and file alignments must be positive"),
        (_X64_FILE_ALIGNMENT, "<I", 0, "section and file alignments must be positive"),
        (_X64_SIZE_OF_HEADERS, "<I", 0x7FFFFFFF, "SizeOfHeaders is outside the input"),
        (_X64_IMAGE_SIZE, "<I", 0x100, "headers exceed SizeOfImage"),
    ],
)
def test_inconsistent_pe_layout_invariant_is_rejected(
    tmp_path: Path,
    offset: int,
    fmt: str,
    value: int,
    match: str,
) -> None:
    """_validate_layout enforces the cross-field invariants a loader relies on.

    A positive image base and size, positive alignments, a SizeOfHeaders that
    fits the input, and an image at least as large as its own headers are each
    a separate guard. A crafted header that violates one must be refused with
    the matching message rather than parsed into a nonsensical layout.
    """
    path = tmp_path / "bad-layout.exe"
    path.write_bytes(_patched_x64(offset, fmt, value))
    with pytest.raises(PeFormatError, match=match):
        scan_pe(path)


def test_overlapping_section_virtual_ranges_are_rejected(tmp_path: Path) -> None:
    """Two sections mapped to the same VA cannot both own that memory.

    Section overlap is a classic malformed/obfuscated layout; the range sort in
    _validate_layout must catch it and name both sections rather than let the
    image parse into ambiguous RVA mappings.
    """
    pe = _SyntheticPe("x64")
    first = pe.add_section(
        ".text", size=0x400, characteristics=_IMAGE_SCN_MEM_READ | _IMAGE_SCN_MEM_EXECUTE
    )
    second = pe.add_section(".data", size=0x400)
    second.virtual_address = first.virtual_address
    path = tmp_path / "overlap.exe"
    path.write_bytes(pe.build())
    with pytest.raises(PeFormatError, match="overlapping virtual ranges"):
        scan_pe(path)


@pytest.mark.parametrize("field", ["file_alignment", "section_alignment"])
def test_unconventional_alignment_is_flagged(tmp_path: Path, field: str) -> None:
    """A positive but non-power-of-two alignment is a heuristic anomaly.

    _validate_layout only requires alignments to be positive; _build_findings
    separately flags either alignment when it falls outside the conventional
    power-of-two range (here 0x300 / 0x1800), which packers and hand-built
    images exhibit. Both the file and section fields drive the same finding.
    """
    pe = _SyntheticPe("x64")
    pe.add_section(
        ".text", size=0x400, characteristics=_IMAGE_SCN_MEM_READ | _IMAGE_SCN_MEM_EXECUTE
    )
    setattr(pe, field, 0x300 if field == "file_alignment" else 0x1800)
    path = tmp_path / "odd-alignment.exe"
    path.write_bytes(pe.build())

    report = scan_pe(path)

    assert any(f.id == "builtin:anomaly:unusual-alignment" for f in report.findings)


def _clr_sample(*, meta: str) -> bytes:
    """A synthetic image whose COM descriptor points at a COR20 header.

    ``meta`` selects what the header's MetaData directory points at: ``bsjb`` a
    mapped BSJB signature (verifiable), ``other`` mapped non-BSJB bytes,
    ``unmapped`` an RVA in no section (the reader raises), and ``short`` a
    directory too small to be a COR20 header at all.
    """
    pe = _SyntheticPe("x64")
    text = pe.add_section(
        ".text", size=0x600, characteristics=_IMAGE_SCN_MEM_READ | _IMAGE_SCN_MEM_EXECUTE
    )
    if meta == "short":
        pe.directories[14] = (pe.rva(text, 0x100), 8)
        return pe.build()
    marker_offset = 0x200
    if meta == "unmapped":
        meta_rva = 0x7F000000
    else:
        meta_rva = pe.rva(text, marker_offset)
        pe.write(text, marker_offset, b"BSJB" if meta == "bsjb" else b"NOPE")
    header_offset = 0x100
    cor20 = bytearray(72)
    # IMAGE_COR20_HEADER: the MetaData IMAGE_DATA_DIRECTORY (rva, size) sits at +8.
    struct.pack_into("<II", cor20, 8, meta_rva, 16)
    pe.write(text, header_offset, bytes(cor20))
    pe.directories[14] = (pe.rva(text, header_offset), 72)
    return pe.build()


@pytest.mark.parametrize(
    ("meta", "expected_status"),
    [
        ("bsjb", "verified"),
        ("other", "hint"),
        ("unmapped", "hint"),
        ("short", "hint"),
    ],
)
def test_clr_classification_only_claims_verified_for_mapped_bsjb(
    tmp_path: Path,
    meta: str,
    expected_status: str,
) -> None:
    """_classify_clr must earn "verified"; every uncertain shape stays a hint.

    Verified requires a readable COR20 header whose MetaData directory maps to a
    BSJB signature. A populated directory whose metadata is non-BSJB, points
    outside any section, or is too small to be a COR20 header all degrade to a
    hint rather than overclaim a .NET runtime that cannot be confirmed from the
    mapped bytes.
    """
    path = tmp_path / f"clr-{meta}.exe"
    path.write_bytes(_clr_sample(meta=meta))

    report = scan_pe(path)

    assert report.pe.dotnet is True
    finding = next(f for f in report.findings if f.id == "builtin:runtime:dotnet")
    assert finding.evidence[0].details.get("clr_status") == expected_status
    if expected_status == "verified":
        assert finding.confidence == 0.99
        assert finding.summary == "CLR runtime header is present"
    else:
        assert finding.confidence == 0.55


def test_scan_pe_refuses_a_non_regular_file(tmp_path: Path) -> None:
    """A directory (or any non-file) resolves and stats but is not a PE input.

    scan_pe resolves the path strictly and stats it before reading; the
    is_file guard rejects a directory with a named PeFormatError rather than
    attempting to open it and surfacing an opaque OSError to the caller.
    """
    directory = tmp_path / "not-a-file"
    directory.mkdir()
    with pytest.raises(PeFormatError, match="not a regular file"):
        scan_pe(directory)


def _tls_pe(callbacks_va: int) -> bytes:
    """An x64 image whose TLS directory carries a chosen AddressOfCallBacks.

    The parser reads the callback-array VA straight out of the TLS directory;
    driving that field lets a test exercise the empty (zero) and the
    below-ImageBase cases without a real callback table.
    """
    pe = _SyntheticPe("x64")
    pe.add_section(
        ".text", size=0x400, characteristics=_IMAGE_SCN_MEM_READ | _IMAGE_SCN_MEM_EXECUTE
    )
    tls = pe.add_section(".tls", size=0x100)
    # x64 IMAGE_TLS_DIRECTORY: AddressOfCallBacks is the 4th pointer (offset 24).
    directory = struct.pack("<QQQQII", 0, 0, 0, callbacks_va, 0, 0)
    pe.write(tls, 0, directory)
    pe.directories[9] = (pe.rva(tls, 0), len(directory))
    return pe.build()


def test_tls_directory_smaller_than_its_header_is_rejected(tmp_path: Path) -> None:
    """A TLS directory too small to hold its architecture header is malformed.

    _parse_tls checks the declared directory size against the fixed x86/x64 TLS
    header before mapping anything, so a size below that (here 8 < 40) is
    refused rather than read into a short buffer.
    """
    pe = _SyntheticPe("x64")
    text = pe.add_section(
        ".text", size=0x400, characteristics=_IMAGE_SCN_MEM_READ | _IMAGE_SCN_MEM_EXECUTE
    )
    pe.directories[9] = (pe.rva(text, 0), 8)
    path = tmp_path / "short-tls.exe"
    path.write_bytes(pe.build())
    with pytest.raises(PeFormatError, match="TLS directory is smaller"):
        scan_pe(path)


def test_tls_callback_array_before_imagebase_is_rejected(tmp_path: Path) -> None:
    """A callback-array VA below ImageBase cannot be a real callback pointer.

    The array VA is absolute; subtracting ImageBase must not underflow into a
    bogus RVA, so a VA that precedes ImageBase is refused by name.
    """
    path = tmp_path / "tls-before-base.exe"
    path.write_bytes(_tls_pe(callbacks_va=0x100))
    with pytest.raises(PeFormatError, match="precedes ImageBase"):
        scan_pe(path)


def test_tls_present_with_no_callback_array_reports_zero(tmp_path: Path) -> None:
    """A TLS directory whose AddressOfCallBacks is zero is present but empty.

    A null callback pointer is legitimate: the image has a TLS directory but
    registers no callbacks, and the summary must say present with a zero count
    rather than reject the image or invent a callback.
    """
    path = tmp_path / "tls-empty.exe"
    path.write_bytes(_tls_pe(callbacks_va=0))

    report = scan_pe(path)

    assert report.pe.tls.present is True
    assert report.pe.tls.callback_count == 0


def test_upx_section_names_are_flagged(tmp_path: Path) -> None:
    """Sections named UPX0/UPX1 are the common UPX stub layout.

    This is a structural hint only, but the finding must fire on the section
    names alone so a packed image is surfaced even without running upx.
    """
    pe = _SyntheticPe("x64")
    pe.add_section(
        "UPX0", size=0x400, characteristics=_IMAGE_SCN_MEM_READ | _IMAGE_SCN_MEM_EXECUTE
    )
    pe.add_section(
        "UPX1", size=0x400, characteristics=_IMAGE_SCN_MEM_READ | _IMAGE_SCN_MEM_EXECUTE
    )
    path = tmp_path / "upx.exe"
    path.write_bytes(pe.build())

    report = scan_pe(path)

    assert any(f.id == "builtin:packer:upx-sections" for f in report.findings)


def test_large_virtual_raw_gap_is_flagged(tmp_path: Path) -> None:
    """A section that maps far larger than its raw data is a packing hint.

    A virtual size vastly exceeding the raw size (here 2 MiB of virtual over a
    1 KiB raw section) is how a packer reserves room to unpack into; the
    heuristic must flag that gap.
    """
    pe = _SyntheticPe("x64")
    pe.add_section(
        ".text", size=0x400, characteristics=_IMAGE_SCN_MEM_READ | _IMAGE_SCN_MEM_EXECUTE
    )
    pe.add_section(".big", size=0x400, virtual_size=0x200000)
    path = tmp_path / "vgap.exe"
    path.write_bytes(pe.build())

    report = scan_pe(path)

    assert any(f.id.startswith("builtin:anomaly:virtual-raw-gap") for f in report.findings)
