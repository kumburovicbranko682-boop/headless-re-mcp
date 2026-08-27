"""M11 fat Mach-O slice selection, end to end against a real radare2.

A universal binary carries several architecture slices; without direction r2
picks one by a host-dependent rule, so a fat session's coordinates stay va-only.
This gate builds a real x86_64 + arm64 fat, opens it as a session, and drives
r2.functions through the service with slice_arch set each way. It asserts the
service and r2 converge: the payload's architecture and image_base match the
slice the caller asked for (arm64 -> its own __TEXT base, x86_64 -> its own),
r2's own ``iI`` names the same arch for that selection, and the two selections
disagree on the base -- proving the flag actually switched slices rather than
being ignored. Without slice_arch the fat stays va-only (no image_base). The
guard also rejects a slice this fat does not contain. skip != pass when
radare2/rizin is missing.
"""

from __future__ import annotations

import shutil
import struct
import tempfile
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_LE64 = b"\xcf\xfa\xed\xfe"
_CPUTYPE = {"x64": 0x01000007, "arm64": 0x0100000C}
_BASE = {"x64": 0x100000000, "arm64": 0x140000000}


def _thin_with_text(cputype: int, text_vmaddr: int) -> bytes:
    order = "<"

    def seg(name: str, vmaddr: int, fileoff: int, filesize: int) -> bytes:
        body = struct.pack(order + "II", 0x19, 72) + name.encode().ljust(16, b"\x00")
        body += struct.pack(order + "QQQQ", vmaddr, 0x1000, fileoff, filesize)
        body += struct.pack(order + "IIII", 0, 5, 0, 0)
        return body

    cmds = seg("__PAGEZERO", 0, 0, 0) + seg("__TEXT", text_vmaddr, 0, 0x1000)
    header = _LE64 + struct.pack(order + "IIIII", cputype, 3, 2, 2, len(cmds))
    header += struct.pack(order + "II", 0, 0)
    return (header + cmds).ljust(0x1000, b"\x00")


def _write_fat(path: Path) -> Path:
    blobs = [
        (_CPUTYPE["x64"], _thin_with_text(_CPUTYPE["x64"], _BASE["x64"])),
        (_CPUTYPE["arm64"], _thin_with_text(_CPUTYPE["arm64"], _BASE["arm64"])),
    ]
    cursor = (8 + 20 * len(blobs) + 0xFFF) & ~0xFFF
    placed: list[tuple[int, int, bytes]] = []
    for cputype, blob in blobs:
        placed.append((cputype, cursor, blob))
        cursor += (len(blob) + 0xFFF) & ~0xFFF
    header = b"\xca\xfe\xba\xbe" + struct.pack(">I", len(blobs))
    for cputype, offset, blob in placed:
        header += struct.pack(">IIIII", cputype, 3, offset, len(blob), 12)
    image = bytearray(header)
    for _cputype, offset, blob in placed:
        image = image.ljust(offset, b"\x00") + blob
    path.write_bytes(bytes(image))
    return path


@pytest.mark.integration
def test_m11_fat_slice_selection_agrees_with_r2() -> None:
    if shutil.which("r2") is None and shutil.which("rizin") is None:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip != pass)")

    with tempfile.TemporaryDirectory() as tmp:
        fat = _write_fat(Path(tmp) / "universal")
        service = AnalysisService(Settings.load())
        try:
            created = service.create_session(str(fat))
            assert created.ok and created.data is not None, created.error
            session = created.data["session"]
            assert session["target"] == "macho", session
            # A fat has no single architecture until a slice is chosen.
            assert session["architecture"] is None, session
            slices = session["metadata"]["macho"]["slices"]
            assert {s["architecture"] for s in slices} == {"x64", "arm64"}, slices
            sid = str(session["id"])

            # Each selection: the enriched coordinate frame is the selected
            # slice's own, and r2's identity for that selection agrees.
            for arch in ("x64", "arm64"):
                funcs = service.r2_functions(sid, slice_arch=arch, timeout=60.0)
                assert funcs.ok and funcs.data is not None, funcs.error
                assert funcs.data["architecture"] == arch, funcs.data
                assert funcs.data["image_base"] == _BASE[arch], funcs.data

                info = service.r2_info(sid, slice_arch=arch, timeout=60.0)
                assert info.ok and info.data is not None, info.error
                raw = str(info.data.get("raw", ""))
                r2_arch = "arm" if arch == "arm64" else "x86"
                assert f"arch     {r2_arch}" in raw, raw

            # The two selections truly land on different slices, not one default.
            assert _BASE["x64"] != _BASE["arm64"]

            # Unselected: no slice is chosen, so the fat stays honestly va-only.
            plain = service.r2_functions(sid, timeout=60.0)
            assert plain.ok and plain.data is not None, plain.error
            assert "image_base" not in plain.data, plain.data
            assert "architecture" not in plain.data, plain.data

            # A slice this fat does not contain is refused before r2 is spawned.
            missing = service.r2_functions(sid, slice_arch="arm", timeout=60.0)
            assert missing.ok is False
            assert missing.error is not None
            assert missing.error.code == "invalid_params"
        finally:
            service.close_all()
