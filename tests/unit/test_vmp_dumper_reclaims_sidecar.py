"""VMPDump's PE beside the live module must not survive a successful copy."""

from __future__ import annotations

import struct
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.core.session import file_sha256
from headless_re_mcp.unpack.vmp_dumper import run_vmp_dumper


def _write_minimal_pe(path: Path) -> None:
    image = bytearray(0x400)
    pe_offset = 0x80
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    path.write_bytes(image)


def test_vmp_dumper_unlinks_the_sidecar_after_copying_to_the_artifact(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A successful dump used to leave a full PE next to the sample.

    Measured: run_vmp_dumper copied 1024 bytes to the artifact destination
    and left sample.VMPDump.exe (also 1024 bytes) in the sample directory.
    artifacts.gc and session.close cannot see that sidecar, so each dump
    in an unattended loop grows the volume beside the live module.
    """
    sample = tmp_path / "sample.exe"
    _write_minimal_pe(sample)
    produced = tmp_path / "sample.VMPDump.exe"
    dest = tmp_path / "artifacts" / "dumped.exe"
    exe = tmp_path / "vmpdump.exe"
    exe.write_bytes(b"MZ")

    def fake_capture(*_args: object, **_kwargs: object) -> SimpleNamespace:
        _write_minimal_pe(produced)
        return SimpleNamespace(
            stdout=f"File written to: {produced}\n",
            stderr="",
            returncode=0,
            stdout_exceeded=False,
            stderr_exceeded=False,
        )

    monkeypatch.setattr(
        "headless_re_mcp.unpack.vmp_dumper._capture_process",
        fake_capture,
    )
    result = run_vmp_dumper(
        exe,
        sample,
        dest,
        input_sha256=file_sha256(sample),
        pid=1234,
    )
    assert result.dump_ok is True
    assert dest.is_file()
    assert dest.stat().st_size == 1024
    assert sample.is_file()
    assert not produced.exists()
