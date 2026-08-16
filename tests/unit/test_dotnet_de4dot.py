"""M6.2 de4dot adapter unit tests (mocked process)."""

from __future__ import annotations

import struct
from pathlib import Path

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.session import file_sha256
from headless_re_mcp.dotnet.de4dot import De4dotResult


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


def test_dotnet_deobfuscate_mocked(tmp_path: Path) -> None:
    binary = tmp_path / "managed.exe"
    _write_verified_clr_pe(binary)
    de4dot = tmp_path / "de4dot.exe"
    de4dot.write_bytes(b"placeholder")
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
    ) -> De4dotResult:
        del timeout, max_file_size, max_output_size
        assert executable == de4dot
        assert file_sha256(input_path) == input_sha256
        output_path.write_bytes(input_path.read_bytes())
        return De4dotResult(
            executable=str(executable),
            input_path=str(input_path),
            output_path=str(output_path.resolve()),
            input_sha256=input_sha256,
            output_sha256=file_sha256(output_path),
            returncode=0,
            stdout="ok",
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
            de4dot=de4dot,
        ),
        de4dot_runner=fake_runner,
    )
    session_id = service.create_session(str(binary)).data["session"]["id"]
    result = service.dotnet_deobfuscate(session_id)
    assert result.ok and result.data is not None
    assert result.data["claims_universal_unpack"] is False
    assert result.data["input_unchanged"] is True
    out = Path(result.data["de4dot"]["output_path"])
    assert out.is_file()
    assert str(artifact_root.resolve()) in str(out.resolve())

    verified = service.dotnet_verify(session_id, str(out))
    assert verified.ok and verified.data is not None
    assert verified.data["ok"] is True


def test_dotnet_verify_rejects_other_session_artifact(tmp_path: Path) -> None:
    binary_a = tmp_path / "managed-a.exe"
    binary_b = tmp_path / "managed-b.exe"
    _write_verified_clr_pe(binary_a)
    _write_verified_clr_pe(binary_b)
    artifact_root = tmp_path / "artifacts"

    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=artifact_root,
            de4dot=None,
        )
    )
    session_a = service.create_session(str(binary_a)).data["session"]["id"]
    session_b = service.create_session(str(binary_b)).data["session"]["id"]

    foreign_dir = artifact_root / "dotnet" / session_b
    foreign_dir.mkdir(parents=True, exist_ok=True)
    foreign = foreign_dir / "de4dot-foreign.exe"
    foreign.write_bytes(binary_b.read_bytes())

    rejected = service.dotnet_verify(session_a, str(foreign))
    assert not rejected.ok
    assert rejected.error is not None
    assert rejected.error.code == "invalid_params"
    assert "session" in rejected.error.message.lower()

    owned_dir = artifact_root / "dotnet" / session_a
    owned_dir.mkdir(parents=True, exist_ok=True)
    owned = owned_dir / "de4dot-owned.exe"
    owned.write_bytes(binary_a.read_bytes())
    accepted = service.dotnet_verify(session_a, str(owned))
    assert accepted.ok and accepted.data is not None
    assert accepted.data["ok"] is True


def test_doctor_reports_de4dot_missing(tmp_path: Path) -> None:
    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
            de4dot=None,
        )
    )
    report = service.doctor().data
    assert report is not None
    probes = {item["name"]: item for item in report["probes"]}
    assert probes["de4dot"]["status"] == "missing"


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


def test_a_hung_de4dot_probe_is_a_failure_and_kills_what_it_started(tmp_path: Path) -> None:
    """A wedged de4dot used to look available and leave its children running.

    Measured: three argv attempts at 0.4s each returned ok=True with empty text
    in 1.205s and left three sleeper children in state S. Doctor then marked
    the CLI READY. A hang is not an unknown flag.
    """
    import os
    import stat
    import sys
    import time

    from headless_re_mcp.dotnet.de4dot import probe_de4dot_version

    markers = tmp_path / "pids"
    markers.mkdir()
    fake = tmp_path / ("de4dot.cmd" if os.name == "nt" else "de4dot")
    body = tmp_path / "fake_de4dot.py"
    body.write_text(
        "import os, subprocess, sys, time\n"
        f"d = {str(markers)!r}\n"
        "child = subprocess.Popen([sys.executable, '-c', "
        "'import time\\nwhile True: time.sleep(0.2)'])\n"
        "open(os.path.join(d, f'{os.getpid()}-{child.pid}'), 'w').write('1')\n"
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
    ok, text = probe_de4dot_version(fake, timeout=0.4)
    elapsed = time.monotonic() - started

    assert ok is False
    assert text == ""
    assert elapsed < 1.0, "a hang must not walk the rest of the flag list"
    children = [int(path.name.split("-")[1]) for path in markers.iterdir()]
    assert children, "the wrapper must have started a child"
    assert all(_pid_is_running(pid) is False for pid in children)
