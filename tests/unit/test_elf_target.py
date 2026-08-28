"""ELF is a first-class target: it opens, PE tools refuse it, r2/ghidra accept it.

Before this, classify_target funnelled every non-PE, non-APK, non-web file into
PE, and create_session then called detect_pe_architecture, which raised "not a
PE file". So a Linux ELF -- the natural input for the radare2 and Ghidra lines
on Linux -- could not even open a session. These tests pin that an ELF now
classifies as ELF, opens with its machine type when we model it, and routes:
PE-only tools answer target_mismatch while the cross-platform backends are
reached (capability_unavailable when the CLI is absent, never target_mismatch).
"""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Architecture, TargetKind
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.session import (
    classify_target,
    detect_elf_architecture,
)


def _elf(path: Path, e_machine: int, *, bits64: bool = True, little: bool = True) -> Path:
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4] = 2 if bits64 else 1
    header[5] = 1 if little else 2
    header[6] = 1
    order = "little" if little else "big"
    header[16:18] = (2).to_bytes(2, order)  # ET_EXEC
    header[18:20] = e_machine.to_bytes(2, order)
    path.write_bytes(bytes(header))
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


class TestElfClassification:
    def test_elf_magic_classifies_as_elf_whatever_the_name(self, tmp_path: Path) -> None:
        assert classify_target(_elf(tmp_path / "prog", 0x3E)) is TargetKind.ELF
        # A shared object has no APK/web suffix, so it reaches the magic check.
        assert classify_target(_elf(tmp_path / "libfoo.so", 0x3E)) is TargetKind.ELF

    def test_a_non_elf_file_is_unchanged(self, tmp_path: Path) -> None:
        pe = tmp_path / "app.exe"
        pe.write_bytes(b"MZ" + b"\x00" * 62)
        assert classify_target(pe) is TargetKind.PE


class TestElfArchitecture:
    def test_known_machines_map_and_others_are_none_not_an_error(
        self, tmp_path: Path
    ) -> None:
        assert detect_elf_architecture(_elf(tmp_path / "a", 0x3E)) is Architecture.X64
        assert (
            detect_elf_architecture(_elf(tmp_path / "b", 0x03, bits64=False))
            is Architecture.X86
        )
        # AArch64 is a real ELF radare2/Ghidra can open, but not a machine type
        # this tool models -- None, never a raise.
        assert detect_elf_architecture(_elf(tmp_path / "c", 0xB7)) is None
        # A big-endian x86-64 machine field is still read with the right order.
        assert (
            detect_elf_architecture(_elf(tmp_path / "d", 0x3E, little=False))
            is Architecture.X64
        )

    def test_a_truncated_or_missing_header_is_none(self, tmp_path: Path) -> None:
        short = tmp_path / "short"
        short.write_bytes(b"\x7fELF")
        assert detect_elf_architecture(short) is None
        assert detect_elf_architecture(tmp_path / "nope") is None


class TestElfSessionRouting:
    def test_elf_session_opens_with_its_machine_type(self, tmp_path: Path) -> None:
        service = _service(tmp_path)
        try:
            created = service.create_session(str(_elf(tmp_path / "prog_x64", 0x3E)))
            assert created.ok, created.error
            session = created.data["session"]
            assert session["target"] == "elf"
            assert session["architecture"] == "x64"
        finally:
            service.close_all()

    def test_an_unmodelled_machine_still_opens(self, tmp_path: Path) -> None:
        service = _service(tmp_path)
        try:
            created = service.create_session(str(_elf(tmp_path / "prog_arm", 0xB7)))
            assert created.ok, created.error
            session = created.data["session"]
            assert session["target"] == "elf"
            assert session["architecture"] is None
        finally:
            service.close_all()

    def test_pe_only_tool_refuses_elf_but_r2_is_reached(self, tmp_path: Path) -> None:
        service = _service(tmp_path)
        try:
            session_id = service.create_session(
                str(_elf(tmp_path / "prog", 0x3E))
            ).data["session"]["id"]

            # A PE-only static backend says target_mismatch, not a crash.
            opened = service.open_static(session_id)
            assert opened.ok is False
            assert opened.error is not None
            assert opened.error.code == "target_mismatch"

            # radare2 is cross-platform: the ELF passes the target check and
            # reaches the availability check. Absent r2 that is
            # capability_unavailable; what matters is it is never
            # target_mismatch, which would mean ELF was rejected as a target.
            r2 = service.r2_open(session_id)
            if not r2.ok:
                assert r2.error is not None
                assert r2.error.code != "target_mismatch"
        finally:
            service.close_all()
