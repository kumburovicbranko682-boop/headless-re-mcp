"""Mach-O is a first-class target: it opens, PE tools refuse it, r2/ghidra take it.

classify_target used to funnel every non-PE/APK/web file into PE, and
create_session then raised "not a PE file", so a Mach-O -- the native macOS/iOS
image the radare2 and Ghidra lines exist to handle -- could not open a session.
These tests pin that a Mach-O (thin or fat) now classifies as macho, opens with
its machine type when we model it, and routes: PE-only tools answer
target_mismatch while the cross-platform backends are reached. They also pin
the one real hazard -- the fat magic 0xCAFEBABE is the Java class magic too --
so a Java .class is never mistaken for a Mach-O.
"""

from __future__ import annotations

import struct
from pathlib import Path

from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Architecture, TargetKind
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.session import (
    classify_target,
    detect_macho_architecture,
)

_CPU_X86 = 7
_CPU_X86_64 = 0x01000007
_CPU_ARM64 = 0x0100000C


def _thin(path: Path, magic: bytes, cputype: int, order: str) -> Path:
    path.write_bytes(magic + int(cputype).to_bytes(4, order) + b"\x00" * 24)
    return path


def _fat(path: Path, magic: bytes, nfat: int) -> Path:
    path.write_bytes(magic + struct.pack(">I", nfat) + b"\x00" * 40)
    return path


def _java_class(path: Path, *, minor: int = 0, major: int = 52) -> Path:
    path.write_bytes(b"\xca\xfe\xba\xbe" + struct.pack(">HH", minor, major) + b"\x00" * 20)
    return path


def _service(tmp_path: Path) -> AnalysisService:
    return AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
        )
    )


class TestMachoClassification:
    def test_thin_images_classify_as_macho_in_both_byte_orders(
        self, tmp_path: Path
    ) -> None:
        le64 = _thin(tmp_path / "le64", b"\xcf\xfa\xed\xfe", _CPU_X86_64, "little")
        le32 = _thin(tmp_path / "le32", b"\xce\xfa\xed\xfe", _CPU_X86, "little")
        be32 = _thin(tmp_path / "be32", b"\xfe\xed\xfa\xce", 18, "big")  # ppc
        for path in (le64, le32, be32):
            assert classify_target(path) is TargetKind.MACHO, path

    def test_fat_images_classify_as_macho(self, tmp_path: Path) -> None:
        assert (
            classify_target(_fat(tmp_path / "fat", b"\xca\xfe\xba\xbe", 2))
            is TargetKind.MACHO
        )
        assert (
            classify_target(_fat(tmp_path / "fat64", b"\xca\xfe\xba\xbf", 3))
            is TargetKind.MACHO
        )

    def test_a_java_class_file_is_not_read_as_a_fat_macho(self, tmp_path: Path) -> None:
        """0xCAFEBABE is both FAT_MAGIC and the Java class magic.

        A Java class puts major_version where a fat header puts its slice
        count; major_version is always >= 45, above any real slice count, so
        the fat magic is accepted only below that. A misread would send a Java
        class into the Mach-O path instead of leaving it to the PE fallback.
        """
        assert classify_target(_java_class(tmp_path / "A.class")) is not TargetKind.MACHO
        # Java 21 with a preview minor version keeps the same property.
        assert (
            classify_target(_java_class(tmp_path / "B.class", minor=0xFFFF, major=65))
            is not TargetKind.MACHO
        )


class TestMachoArchitecture:
    def test_thin_machines_map_and_others_are_none(self, tmp_path: Path) -> None:
        le64 = _thin(tmp_path / "x64", b"\xcf\xfa\xed\xfe", _CPU_X86_64, "little")
        le32 = _thin(tmp_path / "x86", b"\xce\xfa\xed\xfe", _CPU_X86, "little")
        arm = _thin(tmp_path / "arm64", b"\xcf\xfa\xed\xfe", _CPU_ARM64, "little")
        assert detect_macho_architecture(le64) is Architecture.X64
        assert detect_macho_architecture(le32) is Architecture.X86
        assert detect_macho_architecture(arm) is None

    def test_a_fat_image_has_no_single_architecture(self, tmp_path: Path) -> None:
        assert detect_macho_architecture(_fat(tmp_path / "fat", b"\xca\xfe\xba\xbe", 2)) is None

    def test_a_truncated_header_is_none(self, tmp_path: Path) -> None:
        short = tmp_path / "short"
        short.write_bytes(b"\xcf\xfa\xed")
        assert detect_macho_architecture(short) is None


class TestMachoSessionRouting:
    def test_macho_session_opens_with_its_machine_type(self, tmp_path: Path) -> None:
        service = _service(tmp_path)
        try:
            path = _thin(tmp_path / "prog", b"\xcf\xfa\xed\xfe", _CPU_X86_64, "little")
            created = service.create_session(str(path))
            assert created.ok, created.error
            session = created.data["session"]
            assert session["target"] == "macho"
            assert session["architecture"] == "x64"
        finally:
            service.close_all()

    def test_pe_only_tool_refuses_macho_but_r2_is_reached(self, tmp_path: Path) -> None:
        service = _service(tmp_path)
        try:
            path = _thin(tmp_path / "prog", b"\xcf\xfa\xed\xfe", _CPU_X86_64, "little")
            session_id = service.create_session(str(path)).data["session"]["id"]

            opened = service.open_static(session_id)
            assert opened.ok is False
            assert opened.error is not None
            assert opened.error.code == "target_mismatch"

            r2 = service.r2_open(session_id)
            if not r2.ok:
                assert r2.error is not None
                assert r2.error.code != "target_mismatch"
        finally:
            service.close_all()
