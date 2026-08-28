"""Cross-validate the PE resource claims (VS_VERSIONINFO, manifest UAC) against pefile.

A session over a PE now reports its version resource tool-free -- the identity
Explorer's Details pane shows and malware routinely fakes: the numeric
file/product versions from VS_FIXEDFILEINFO and the StringFileInfo table
(CompanyName, ProductName, OriginalFilename, ...). The resource-tree walk to
the RT_VERSION leaf, the block-tree decode and the UTF-16 string reads are all
ours, so pefile referees them: it parses the same resource into its own
VS_FIXEDFILEINFO and StringTable structures, which this compares against the
reader's facts string for string. One case compiles a real PE with Mono's mcs,
whose linker builds the version resource from assembly attributes -- a producer
neither builder controls; the other plants a hand-built resource tree so the
decode is also gated on a shape no compiler smoothed over.

The same session also reports the RT_MANIFEST UAC claim (loader-enforced,
unlike the version strings): requestedExecutionLevel and uiAccess out of the
trustInfo block. The reader scrapes the XML with element-anchored byte
regexes, so the gate referees it with a genuinely different stack: pefile
walks the resource tree to the raw manifest bytes and ElementTree parses the
XML for the attributes. The mcs-built PE doubles as the negative: Mono's
linker emits no RT_MANIFEST, and both sides must agree it is absent.

pefile ships in the project's ``pe`` extra; mcs comes from mono-mcs in CI. skip
!= pass: each test skips only when its own referee is unavailable.
"""

from __future__ import annotations

import shutil
import struct
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.core.service import AnalysisService


def _pefile() -> Any | None:
    try:
        import pefile
    except ImportError:
        return None
    return pefile


def _vs_node(
    key: str, value: bytes, value_len: int, children: list[bytes], w_type: int = 0
) -> bytes:
    body = bytearray(key.encode("utf-16-le") + b"\x00\x00")
    while (6 + len(body)) % 4:
        body += b"\x00"
    body += value
    for child in children:
        while (6 + len(body)) % 4:
            body += b"\x00"
        body += child
    return struct.pack("<HHH", 6 + len(body), value_len, w_type) + bytes(body)


def _version_blob(strings: dict[str, str]) -> bytes:
    """A VS_VERSIONINFO blob: fixed versions 3.1.4.1 / 2.7.1.8 plus ``strings``."""
    fixed = struct.pack(
        "<IIIIII",
        0xFEEF04BD,
        0x0001_0000,
        (3 << 16) | 1,
        (4 << 16) | 1,
        (2 << 16) | 7,
        (1 << 16) | 8,
    ) + b"\x00" * 28
    entries = []
    for key, value in strings.items():
        text = value.encode("utf-16-le") + b"\x00\x00"
        entries.append(_vs_node(key, text, len(value) + 1, [], w_type=1))
    table = _vs_node("040904b0", b"", 0, entries)
    info = _vs_node("StringFileInfo", b"", 0, [table])
    return _vs_node("VS_VERSION_INFO", fixed, len(fixed), [info])


def _pe_with_version_resource(blob: bytes, type_id: int = 16) -> bytes:
    """A minimal PE whose resource tree holds ``blob`` as ``type_id``/1/0x409.

    The three-level tree (type -> name 1 -> language 0x409 -> data entry) is
    laid out by hand, independently of the reader's own test builder, so the
    walk is gated on a resource directory neither implementation generated.
    Type 16 is RT_VERSION; type 24 is RT_MANIFEST.
    """
    sect_rva = 0x1000
    sec = bytearray(0x60)
    # Root directory: one ID entry, the type -> subdirectory at +0x18.
    struct.pack_into("<HH", sec, 12, 0, 1)
    struct.pack_into("<II", sec, 16, type_id, 0x8000_0018)
    # Name directory: one ID entry, name 1 -> subdirectory at +0x30.
    struct.pack_into("<HH", sec, 0x18 + 12, 0, 1)
    struct.pack_into("<II", sec, 0x18 + 16, 1, 0x8000_0030)
    # Language directory: one ID entry, lang 0x409 -> data entry at +0x48.
    struct.pack_into("<HH", sec, 0x30 + 12, 0, 1)
    struct.pack_into("<II", sec, 0x30 + 16, 0x409, 0x48)
    struct.pack_into("<IIII", sec, 0x48, sect_rva + 0x60, len(blob), 0, 0)
    sec += blob
    if len(sec) % 0x200:
        sec += b"\x00" * (0x200 - len(sec) % 0x200)

    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    opt_size = 0xF0
    coff = b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, opt_size, 0x0102)
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x20B)
    struct.pack_into("<Q", opt, 24, 0x1_4000_0000)
    struct.pack_into("<I", opt, 32, 0x1000)  # SectionAlignment
    struct.pack_into("<I", opt, 36, 0x200)  # FileAlignment
    struct.pack_into("<I", opt, 56, sect_rva + len(sec))  # SizeOfImage
    struct.pack_into("<I", opt, 108, 16)  # NumberOfRvaAndSizes
    struct.pack_into("<II", opt, 112 + 2 * 8, sect_rva, len(sec))  # resource dir

    raw_off = 0x40 + len(coff) + opt_size + 40
    if raw_off % 0x200:
        raw_off += 0x200 - (raw_off % 0x200)
    struct.pack_into("<I", opt, 60, raw_off)  # SizeOfHeaders

    sect = bytearray(40)
    sect[0:5] = b".rsrc"
    struct.pack_into("<I", sect, 8, len(sec))
    struct.pack_into("<I", sect, 12, sect_rva)
    struct.pack_into("<I", sect, 16, len(sec))
    struct.pack_into("<I", sect, 20, raw_off)
    struct.pack_into("<I", sect, 36, 0x40000040)

    out = bytearray(dos + coff + opt + sect)
    if len(out) < raw_off:
        out += b"\x00" * (raw_off - len(out))
    return bytes(out + sec)


def _pefile_version(pefile_mod: Any, binary: Path) -> tuple[str, str, dict[str, str]]:
    """pefile's view: dotted fixed versions plus the StringFileInfo entries."""
    pe = pefile_mod.PE(str(binary))
    fixed = pe.VS_FIXEDFILEINFO[0]

    def dotted(ms: int, ls: int) -> str:
        return f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"

    strings: dict[str, str] = {}
    for info in getattr(pe, "FileInfo", []):
        for entry in info:
            if entry.Key != b"StringFileInfo":
                continue
            for table in entry.StringTable:
                for key, value in table.entries.items():
                    strings.setdefault(
                        key.decode("utf-8", errors="replace"),
                        value.decode("utf-8", errors="replace"),
                    )
    return (
        dotted(fixed.FileVersionMS, fixed.FileVersionLS),
        dotted(fixed.ProductVersionMS, fixed.ProductVersionLS),
        strings,
    )


def _session_version(binary: Path) -> dict[str, Any]:
    service = AnalysisService()
    try:
        created = service.create_session(str(binary))
        assert created.ok, created.error
        info = created.data["session"]["metadata"]["pe"]["version_info"]
        assert isinstance(info, dict)
        return info
    finally:
        service.close_all()


@pytest.mark.integration
def test_a_planted_version_resource_agrees_with_pefile(tmp_path: Path) -> None:
    pefile_mod = _pefile()
    if pefile_mod is None:
        pytest.skip("pefile not installed — PE version-info gate not run (skip != pass)")

    strings = {
        "CompanyName": "Contoso Ltd",
        "ProductName": "Widget Engine",
        "OriginalFilename": "widget.exe",
        "FileDescription": "Widget update helper",
    }
    binary = tmp_path / "widget.exe"
    binary.write_bytes(_pe_with_version_resource(_version_blob(strings)))

    # Independent ground truth: pefile walks the resource tree and decodes the
    # block structure itself. It must see the planted claim, so it is a
    # genuine second opinion.
    file_version, product_version, pefile_strings = _pefile_version(pefile_mod, binary)
    assert file_version == "3.1.4.1"
    assert product_version == "2.7.1.8"
    assert pefile_strings == strings

    info = _session_version(binary)
    assert info["file_version"] == file_version
    assert info["product_version"] == product_version
    assert info["strings"] == pefile_strings


def _pefile_manifest(pefile_mod: Any, binary: Path) -> tuple[str | None, bool | None] | None:
    """The referee's UAC view: pefile finds the raw RT_MANIFEST bytes, then a
    real XML parse (ElementTree, namespace-blind on the tag) reads the
    requestedExecutionLevel element's level and uiAccess attributes. None
    means no manifest resource at all -- absence must agree too.
    """
    pe = pefile_mod.PE(str(binary))
    root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if root is None:
        return None
    for entry in root.entries:
        if entry.id != 24:  # RT_MANIFEST
            continue
        name_dir = entry.directory.entries[0]
        lang_dir = name_dir.directory.entries[0]
        data = lang_dir.data.struct
        raw = pe.get_memory_mapped_image()[data.OffsetToData : data.OffsetToData + data.Size]
        level: str | None = None
        ui_access: bool | None = None
        for element in ET.fromstring(raw.decode("utf-8")).iter():
            if element.tag.rsplit("}", 1)[-1] != "requestedExecutionLevel":
                continue
            level = element.attrib.get("level")
            declared = element.attrib.get("uiAccess")
            if declared is not None:
                ui_access = declared.lower() == "true"
            break
        return level, ui_access
    return None


def _session_manifest(binary: Path) -> dict[str, Any]:
    service = AnalysisService()
    try:
        created = service.create_session(str(binary))
        assert created.ok, created.error
        manifest = created.data["session"]["metadata"]["pe"]["manifest"]
        assert isinstance(manifest, dict)
        return manifest
    finally:
        service.close_all()


@pytest.mark.integration
@pytest.mark.parametrize(
    ("level", "ui_access"),
    [
        ("requireAdministrator", "true"),
        ("highestAvailable", "false"),
        ("asInvoker", None),
    ],
)
def test_a_planted_uac_manifest_agrees_with_pefile_and_elementtree(
    tmp_path: Path, level: str, ui_access: str | None
) -> None:
    pefile_mod = _pefile()
    if pefile_mod is None:
        pytest.skip("pefile not installed — PE manifest gate not run (skip != pass)")

    ui = f' uiAccess="{ui_access}"' if ui_access is not None else ""
    xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">'
        '<trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"><security>'
        f'<requestedPrivileges><requestedExecutionLevel level="{level}"{ui}/>'
        "</requestedPrivileges></security></trustInfo></assembly>"
    ).encode()
    binary = tmp_path / "claimed.exe"
    binary.write_bytes(_pe_with_version_resource(xml, type_id=24))

    # Independent ground truth: pefile's resource walk plus a real XML parse.
    # It must see the planted claim, so it is a genuine second opinion.
    referee = _pefile_manifest(pefile_mod, binary)
    assert referee is not None
    referee_level, referee_ui = referee
    assert referee_level == level

    manifest = _session_manifest(binary)
    assert manifest["present"] is True
    assert manifest["requested_execution_level"] == referee_level
    assert manifest.get("ui_access") == referee_ui


@pytest.mark.integration
def test_an_mcs_built_pe_has_no_manifest_on_both_sides(tmp_path: Path) -> None:
    pefile_mod = _pefile()
    if pefile_mod is None:
        pytest.skip("pefile not installed — PE manifest gate not run (skip != pass)")
    mcs = shutil.which("mcs")
    if mcs is None:
        pytest.skip("mcs (mono-mcs) not installed — compiler-PE gate not run (skip != pass)")

    # Mono's linker emits no RT_MANIFEST resource, so a real compiler output
    # is the negative: the referee and the reader must both call it absent.
    source = tmp_path / "hello.cs"
    source.write_text('class P { static void Main() { System.Console.WriteLine("hi"); } }\n')
    binary = tmp_path / "hello.exe"
    subprocess.run(
        [mcs, f"-out:{binary}", str(source)], check=True, capture_output=True, timeout=120
    )

    assert _pefile_manifest(pefile_mod, binary) is None
    assert _session_manifest(binary) == {"present": False}


@pytest.mark.integration
def test_an_mcs_built_version_resource_agrees_with_pefile(tmp_path: Path) -> None:
    pefile_mod = _pefile()
    if pefile_mod is None:
        pytest.skip("pefile not installed — PE version-info gate not run (skip != pass)")
    mcs = shutil.which("mcs")
    if mcs is None:
        pytest.skip("mcs (mono-mcs) not installed — compiler-PE gate not run (skip != pass)")

    # Mono's linker builds the RT_VERSION resource from assembly attributes --
    # a version resource laid out by a producer neither test builder controls.
    source = tmp_path / "hello.cs"
    source.write_text(
        "using System.Reflection;\n"
        '[assembly: AssemblyTitle("Hello Tool")]\n'
        '[assembly: AssemblyCompany("Acme Corp")]\n'
        '[assembly: AssemblyFileVersion("2.3.4.5")]\n'
        'class P { static void Main() { System.Console.WriteLine("hi"); } }\n'
    )
    binary = tmp_path / "hello.exe"
    subprocess.run(
        [mcs, f"-out:{binary}", str(source)], check=True, capture_output=True, timeout=120
    )

    file_version, product_version, pefile_strings = _pefile_version(pefile_mod, binary)
    # The attributes must have landed, so the referee reads a real identity.
    assert file_version == "2.3.4.5"
    assert pefile_strings["CompanyName"] == "Acme Corp"
    assert pefile_strings["FileDescription"] == "Hello Tool"

    info = _session_version(binary)
    assert info["file_version"] == file_version
    assert info["product_version"] == product_version
    assert info["strings"] == pefile_strings
