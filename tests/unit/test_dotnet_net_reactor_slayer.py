"""M6.3 NETReactorSlayer adapter unit tests (mocked process)."""

from __future__ import annotations

import struct
from pathlib import Path

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.session import file_sha256
from headless_re_mcp.dotnet.net_reactor_slayer import NetReactorSlayerResult


def _write_verified_clr_pe(path: Path) -> None:
    image = bytearray(0x800)
    pe_offset = 0x80
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    file_header = pe_offset + 4
    struct.pack_into("<HHIIIHH", image, file_header, 0x8664, 1, 0, 0, 0, 0xF0, 0x2022)
    optional = file_header + 20
    struct.pack_into("<HBB", image, optional, 0x20B, 14, 0)
    struct.pack_into("<I", image, optional + 16, 0x1000)
    struct.pack_into("<Q", image, optional + 24, 0x140000000)
    struct.pack_into("<II", image, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", image, optional + 56, 0x2000, 0x200)
    struct.pack_into("<HH", image, optional + 68, 3, 0x8160)
    struct.pack_into("<I", image, optional + 108, 16)
    dir_base = optional + 112
    struct.pack_into("<II", image, dir_base + 14 * 8, 0x1100, 72)
    section = optional + 0xF0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x400, 0x1000, 0x400, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    cor_off = 0x300
    struct.pack_into("<I", image, cor_off, 72)
    struct.pack_into("<HH", image, cor_off + 4, 2, 5)
    struct.pack_into("<II", image, cor_off + 8, 0x1200, 0x40)
    struct.pack_into("<I", image, cor_off + 16, 0x1)
    struct.pack_into("<I", image, cor_off + 20, 0x06000001)
    meta_off = 0x400
    version = b"v4.0.30319\0"
    version_padded = version + b"\0" * ((4 - (len(version) % 4)) % 4)
    image[meta_off : meta_off + 4] = b"BSJB"
    struct.pack_into("<HH", image, meta_off + 4, 1, 1)
    struct.pack_into("<I", image, meta_off + 8, 0)
    struct.pack_into("<I", image, meta_off + 12, len(version))
    image[meta_off + 16 : meta_off + 16 + len(version_padded)] = version_padded
    cursor = meta_off + 16 + len(version_padded)
    struct.pack_into("<HH", image, cursor, 0, 0)
    path.write_bytes(image)


def test_dotnet_reactor_unpack_mocked(tmp_path: Path) -> None:
    binary = tmp_path / "managed.exe"
    _write_verified_clr_pe(binary)
    nrs = tmp_path / "NETReactorSlayer.CLI.exe"
    nrs.write_bytes(b"placeholder")
    artifact_root = tmp_path / "artifacts"

    def fake_runner(
        executable: Path,
        input_path: Path,
        output_path: Path,
        *,
        input_sha256: str,
        timeout: float = 120.0,
        max_file_size: int = 0,
        max_output_size: int = 0,
    ) -> NetReactorSlayerResult:
        del timeout, max_file_size, max_output_size
        assert executable == nrs
        assert file_sha256(input_path) == input_sha256
        output_path.write_bytes(input_path.read_bytes())
        return NetReactorSlayerResult(
            executable=str(executable),
            input_path=str(input_path),
            output_path=str(output_path.resolve()),
            input_sha256=input_sha256,
            output_sha256=file_sha256(output_path),
            returncode=0,
            stdout="Saved to: managed_Slayed.exe",
            stderr="",
            duration_ms=1,
        )

    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=artifact_root,
            net_reactor_slayer=nrs,
        ),
        net_reactor_slayer_runner=fake_runner,
    )
    session_id = service.create_session(str(binary)).data["session"]["id"]
    result = service.dotnet_reactor_unpack(session_id)
    assert result.ok
    assert result.data is not None
    assert result.data["claims_universal_unpack"] is False
    assert result.data["authorized_samples_only"] is True
    out = Path(result.data["net_reactor_slayer"]["output_path"])
    assert out.is_file()
    assert file_sha256(binary) == result.data["net_reactor_slayer"]["input_sha256"]


def test_doctor_reports_net_reactor_slayer_missing(tmp_path: Path) -> None:
    from headless_re_mcp.doctor import run_doctor

    report = run_doctor(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path,
            net_reactor_slayer=None,
        )
    )
    probes = {item.name: item for item in report.probes}
    assert probes["net_reactor_slayer"].status.value == "missing"


def _pid_is_running(pid: int) -> bool:
    """True only for a live process. A zombie after SIGKILL counts as dead."""
    import os

    if os.name != "nt":
        stat = Path(f"/proc/{pid}/stat")
        if not stat.is_file():
            return False
        try:
            return stat.read_text(encoding="ascii").split()[2] != "Z"
        except OSError:
            return False
    import ctypes

    handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
    if not handle:
        return False
    exit_code = ctypes.c_ulong(0)
    ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
    ctypes.windll.kernel32.CloseHandle(handle)
    return exit_code.value == 259


def test_a_timed_out_nrs_probe_kills_what_it_started(tmp_path: Path) -> None:
    """subprocess.run left the child of a NETReactorSlayer probe wrapper running.

    Measured: a script that spawned a sleeper returned in 0.40s and left the
    child in state S.
    """
    import os
    import stat
    import sys
    import time

    from headless_re_mcp.dotnet.net_reactor_slayer import probe_net_reactor_slayer

    marker = tmp_path / "child.pid"
    fake = tmp_path / ("nrs.cmd" if os.name == "nt" else "nrs")
    body = tmp_path / "fake_nrs.py"
    body.write_text(
        "import subprocess, sys, time\n"
        f"marker = {str(marker)!r}\n"
        "child = subprocess.Popen([sys.executable, '-c', "
        "'import time\\nwhile True: time.sleep(0.2)'])\n"
        "open(marker, 'w', encoding='ascii').write(str(child.pid))\n"
        "while True:\n"
        "    time.sleep(0.2)\n",
        encoding="utf-8",
    )
    if os.name == "nt":
        fake.write_text(f'@echo off\n"{sys.executable}" "{body}" %*\n', encoding="utf-8")
    else:
        script = f"#!{sys.executable}\n" + body.read_text(encoding="utf-8")
        fake.write_text(script, encoding="utf-8")
        fake.chmod(fake.stat().st_mode | stat.S_IEXEC)

    started = time.monotonic()
    ok, _text = probe_net_reactor_slayer(fake, timeout=0.4)
    elapsed = time.monotonic() - started

    assert ok is False
    assert elapsed < 3.0
    child = int(marker.read_text(encoding="ascii").strip())
    assert _pid_is_running(child) is False
