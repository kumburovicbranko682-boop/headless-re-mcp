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


def test_de4dot_probe_is_false_when_every_invocation_fails(tmp_path: Path) -> None:
    """A file that never answers used to be reported as de4dot.

    Measured: a 30s sleeper, timeout 0.4s, came back ok=True output=''
    after three timed-out argv variants. Doctor then marked the CLI
    READY. An unattended run would spend the night on a tool that
    cannot start.
    """
    from headless_re_mcp.dotnet.de4dot import probe_de4dot_version

    hanging = tmp_path / "hang"
    hanging.write_text(
        "#!/usr/bin/env python3\nimport time\ntime.sleep(30)\n",
        encoding="utf-8",
    )
    hanging.chmod(0o755)
    ok, output = probe_de4dot_version(hanging, timeout=0.4)
    assert ok is False
    assert output == ""

    other = tmp_path / "other"
    other.write_text("#!/usr/bin/env python3\nimport sys\nsys.exit(2)\n", encoding="utf-8")
    other.chmod(0o755)
    ok_other, output_other = probe_de4dot_version(other, timeout=0.4)
    assert ok_other is False
    assert output_other == ""


def test_de4dot_probe_timeout_kills_what_the_launcher_started(tmp_path: Path) -> None:
    """subprocess.run killed the probe and left the work running.

    Measured: a launcher that started a sleeper, timeout 0.4s, left three
    orphans (one per argv variant) reparented to pid 1.
    """
    import os
    import time

    from headless_re_mcp.dotnet.de4dot import probe_de4dot_version

    pid_path = tmp_path / "child.pid"
    sleeper = tmp_path / "sleeper.py"
    sleeper.write_text("import time\ntime.sleep(30)\n", encoding="utf-8")
    launcher = tmp_path / "launch"
    launcher.write_text(
        "#!/usr/bin/env python3\n"
        "import subprocess, sys\n"
        f"child = subprocess.Popen([sys.executable, {str(sleeper)!r}])\n"
        f"open({str(pid_path)!r}, 'a').write(str(child.pid) + '\\n')\n",
        encoding="utf-8",
    )
    launcher.chmod(0o755)
    ok, _output = probe_de4dot_version(launcher, timeout=0.4)
    assert ok is False
    assert pid_path.is_file()
    pids = [int(line) for line in pid_path.read_text().split() if line.strip()]
    assert pids
    deadline = time.monotonic() + 2.0
    alive = set(pids)
    while time.monotonic() < deadline and alive:
        remaining = set()
        for pid in alive:
            try:
                os.kill(pid, 0)
            except OSError:
                continue
            remaining.add(pid)
        alive = remaining
        if alive:
            time.sleep(0.05)
    assert alive == set(), f"probe left orphans {sorted(alive)}"
