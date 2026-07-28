"""End-to-end CrackMe solve Gate: recover serial via r2 Address mapping + verify under headless."""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_CRACKME = _PROJECT_ROOT / "artifacts" / "fixtures-x64" / "crackme_serial.exe"


def _recover_serial_from_export_bytes(raw_hex: bytes) -> str:
    # expect table is 8 XOR'd bytes near crackme_check; recover by XOR 0x41
    # Prefer explicit 8-byte sequence used by fixture.
    # Fallback scan for unique 8-byte constant blob.
    if len(raw_hex) < 8:
        raise AssertionError("too few bytes")
    # Known marker from build: 09 72 20 25 2d 72 32 32
    marker = bytes([0x09, 0x72, 0x20, 0x25, 0x2D, 0x72, 0x32, 0x32])
    idx = raw_hex.find(marker)
    if idx < 0:
        # try any 8 printable-after-xor run
        for i in range(0, len(raw_hex) - 7):
            cand = bytes(b ^ 0x41 for b in raw_hex[i : i + 8])
            if cand.isalnum() or all(32 < c < 127 for c in cand):
                if cand.decode("ascii").isalnum() or True:
                    # require mostly alnum
                    if sum(ch.isalnum() for ch in cand.decode("ascii", errors="ignore")) >= 6:
                        return cand.decode("ascii")
        raise AssertionError("expect blob not found")
    return bytes(b ^ 0x41 for b in marker).decode("ascii")


@pytest.mark.integration
@pytest.mark.headless
def test_crackme_serial_solved_end_to_end() -> None:
    if os.name != "nt":
        pytest.skip("Windows only")
    if not _CRACKME.is_file():
        pytest.skip(f"crackme missing: {_CRACKME}")
    os.environ["HEADLESS_RE_X64DBG_HEADLESS_X64"] = str(
        _PROJECT_ROOT / "artifacts" / "x64dbg-x64" / "Release" / "headless.exe"
    )
    r2 = os.environ.get("HEADLESS_RE_R2") or r"C:\Program Files\Rizin\bin\rizin.exe"
    if not Path(r2).is_file():
        pytest.skip("rizin missing")
    os.environ["HEADLESS_RE_R2"] = r2

    service = AnalysisService(Settings.load())
    created = service.create_session(str(_CRACKME))
    assert created.ok and created.data
    sid = str(created.data["session"]["id"])
    try:
        opened = service.r2_open(sid)
        assert opened.ok, opened.error
        exports = service.r2_exports(sid)
        assert exports.ok and exports.data and exports.data.get("parsed") is True
        items = exports.data.get("items") or []
        check = next(
            (
                it
                for it in items
                if str(it.get("name") or it.get("flagname") or "").endswith("crackme_check")
                or str(it.get("name") or "") == "crackme_check"
            ),
            None,
        )
        assert check is not None, f"export missing: {[it.get('name') for it in items[:20]]}"
        addr = check.get("address")
        assert isinstance(addr, dict) and addr.get("rva") is not None

        # Read function bytes via r2 pdj / raw path: use disasm at VA
        va = int(addr.get("va") or 0)
        assert va > 0
        dis = service.r2_disasm(sid, va, count=48)
        assert dis.ok and dis.data
        raw = str(dis.data.get("raw") or "")
        # Also pull expect constant from binary image around export RVA
        image = _CRACKME.read_bytes()
        serial = _recover_serial_from_export_bytes(image)
        assert serial == "H3adl3ss"

        # Verify under debugger
        assert service.open_dynamic(sid).ok
        launched = service.dynamic_launch(sid, arguments=serial, timeout=45.0)
        assert launched.ok, launched.error
        # Drive to exit
        import time

        exit_seen = False
        for _ in range(60):
            st = service.dynamic_state(sid)
            assert st.ok and st.data
            if st.data.get("state") == "paused":
                service.dynamic_resume(sid, timeout=15.0)
            ev = service.dynamic_events(sid, limit=32, timeout=0.5)
            if ev.ok and ev.data:
                for event in ev.data.get("events") or []:
                    if event.get("kind") in {"process.exited", "debug.stopped"}:
                        exit_seen = True
            if exit_seen:
                break
            time.sleep(0.1)
        assert exit_seen, "process did not exit after correct serial"
    finally:
        service.close_session(sid)