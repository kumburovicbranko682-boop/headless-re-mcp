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
    assert result.data.get("artifact_id")
    listed = service.artifacts_list(session_id)
    assert listed.ok and listed.data is not None
    assert listed.data["total"] == 1
    assert listed.data["artifacts"][0]["kind"] == "de4dot_unpacked"

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


def _alive(pid: int) -> bool:
    import os

    if os.name != "nt":
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        return True
    import ctypes

    handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
    if not handle:
        return False
    try:
        code = ctypes.c_ulong()
        ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
        return code.value == 259
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


def _hanging_launcher(tmp_path: Path) -> tuple[Path, Path]:
    import os
    import sys

    body = (
        "import subprocess, sys, time\n"
        "from pathlib import Path\n"
        "child = subprocess.Popen([sys.executable, '-c', "
        "'import time\\nwhile True: time.sleep(0.2)'])\n"
        "marker = Path(__file__).with_suffix('.children')\n"
        "marker.write_text(marker.read_text() + str(child.pid) + '\\n' "
        "if marker.is_file() else str(child.pid) + '\\n')\n"
        "while True:\n"
        "    time.sleep(0.2)\n"
    )
    script = tmp_path / "de4dot_launcher.py"
    marker = script.with_suffix(".children")
    if os.name == "nt":
        script.write_text(body, encoding="utf-8")
        wrapper = tmp_path / "de4dot.cmd"
        wrapper.write_text(f'@echo off\r\n"{sys.executable}" "{script}" %*\r\n', encoding="utf-8")
        return wrapper, marker
    script.write_text("#!/usr/bin/env python3\n" + body, encoding="utf-8")
    script.chmod(0o755)
    return script, marker


def test_a_hanging_probe_is_not_ready_and_leaves_no_children(tmp_path: Path) -> None:
    """Measured: three argv attempts, 1.2s, ok=True, three children still alive."""
    import os
    import time

    from headless_re_mcp.dotnet.de4dot import probe_de4dot_version

    stub, marker = _hanging_launcher(tmp_path)
    children: list[int] = []
    try:
        ok, output = probe_de4dot_version(stub, timeout=0.4)
        assert ok is False
        assert output == ""

        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            if marker.is_file() and marker.read_text().strip():
                break
            time.sleep(0.05)
        if marker.is_file():
            children = [int(line) for line in marker.read_text().split() if line.strip()]
        for pid in children:
            while _alive(pid) and time.monotonic() < deadline:
                time.sleep(0.05)
            assert _alive(pid) is False, f"probe child {pid} outlived the probe"
    finally:
        for pid in children:
            if _alive(pid):
                os.kill(pid, 9)


def test_a_probe_that_prints_de4dot_is_ready(tmp_path: Path) -> None:
    import os

    from headless_re_mcp.dotnet.de4dot import probe_de4dot_version

    if os.name == "nt":
        stub = tmp_path / "de4dot.cmd"
        stub.write_text("@echo off\r\necho de4dot 3.1.0\r\n", encoding="utf-8")
    else:
        stub = tmp_path / "de4dot"
        stub.write_text(
            "#!/usr/bin/env python3\nimport sys\nprint('de4dot 3.1.0')\nsys.exit(0)\n",
            encoding="utf-8",
        )
        stub.chmod(0o755)
    ok, output = probe_de4dot_version(stub, timeout=5.0)
    assert ok is True
    assert "de4dot" in output.casefold()


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
