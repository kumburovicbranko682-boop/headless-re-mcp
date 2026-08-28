"""Hermetic coverage for the bounded VMPDump adapter honesty checks.

VMPDump is an optional, user-configured, x64-only CLI; the adapter never
bundles it and never claims universal unpack. These tests mock the process
runner so they run on any platform and exercise: argv whitelisting, the
``File written to:`` parser, the PE sniff, the imports-rebuilt inference, the
output-PE fallback scan (filtering, mtime floor, missing / ambiguous), the
run_vmp_dumper fail-closed guards (missing exe / non-file input / existing or
mutated output / capture failure / output-limit / copy failure / sidecar
retention), and the probe classification.
"""

from __future__ import annotations

import os
import shutil
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

from headless_re_mcp.backends.common.bounded_run import BoundedCancelled
from headless_re_mcp.core.session import file_sha256
from headless_re_mcp.unpack import vmp_dumper as vd
from headless_re_mcp.unpack.vmp_dumper import (
    VmpDumperError,
    VmpDumperErrorCode,
    build_vmpdump_argv,
    parse_vmpdump_written_path,
    probe_vmp_dumper,
    run_vmp_dumper,
)


def _write_minimal_pe(path: Path) -> None:
    image = bytearray(0x400)
    pe_offset = 0x80
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    path.write_bytes(bytes(image))


def _capture(
    *, stdout: str = "", stderr: str = "", returncode: int = 0,
    stdout_exceeded: bool = False, stderr_exceeded: bool = False,
) -> SimpleNamespace:
    return SimpleNamespace(
        stdout=stdout,
        stderr=stderr,
        returncode=returncode,
        stdout_exceeded=stdout_exceeded,
        stderr_exceeded=stderr_exceeded,
    )


# --- build_vmpdump_argv --------------------------------------------------


def test_build_argv_happy_with_ep_and_disable_reloc() -> None:
    argv = build_vmpdump_argv(
        Path("/tools/vmpdump.exe"),
        pid=42,
        module_name="mod.dll",
        entry_point_rva=0x1234,
        disable_reloc=True,
    )
    assert argv[1] == "42"
    assert argv[2] == "mod.dll"
    assert "-ep=1234" in argv
    assert "-disable-reloc" in argv


def test_build_argv_rejects_non_positive_pid() -> None:
    with pytest.raises(VmpDumperError) as excinfo:
        build_vmpdump_argv(Path("x"), pid=0)
    assert excinfo.value.code == VmpDumperErrorCode.INVALID_ARGUMENT


def test_build_argv_rejects_shell_metacharacters_in_module() -> None:
    with pytest.raises(VmpDumperError) as excinfo:
        build_vmpdump_argv(Path("x"), pid=1, module_name='evil"|name')
    assert excinfo.value.code == VmpDumperErrorCode.INVALID_ARGUMENT


def test_build_argv_rejects_negative_entry_point() -> None:
    with pytest.raises(VmpDumperError) as excinfo:
        build_vmpdump_argv(Path("x"), pid=1, entry_point_rva=-1)
    assert excinfo.value.code == VmpDumperErrorCode.INVALID_ARGUMENT


# --- parse_vmpdump_written_path ------------------------------------------


def test_parse_written_path_extracts_quoted_path() -> None:
    assert parse_vmpdump_written_path('File written to: "C:/out/x.exe"') == Path(
        "C:/out/x.exe"
    )


def test_parse_written_path_none_without_marker() -> None:
    assert parse_vmpdump_written_path("nothing to see") is None


def test_parse_written_path_none_when_blank() -> None:
    assert parse_vmpdump_written_path('File written to: ""') is None


# --- _is_pe_file ---------------------------------------------------------


def test_is_pe_file_rejects_missing_short_and_malformed(tmp_path: Path) -> None:
    assert vd._is_pe_file(tmp_path / "missing.bin") is False

    short = tmp_path / "short.bin"
    short.write_bytes(b"MZ")
    assert vd._is_pe_file(short) is False

    not_mz = tmp_path / "notmz.bin"
    not_mz.write_bytes(b"XY" + b"\0" * 0x50)
    assert vd._is_pe_file(not_mz) is False

    bad_offset = tmp_path / "badoff.bin"
    img = bytearray(0x40)
    img[:2] = b"MZ"
    struct.pack_into("<I", img, 0x3C, 0x10)  # pe_offset < 0x40
    bad_offset.write_bytes(bytes(img))
    assert vd._is_pe_file(bad_offset) is False

    no_sig = tmp_path / "nosig.bin"
    img2 = bytearray(0x100)
    img2[:2] = b"MZ"
    struct.pack_into("<I", img2, 0x3C, 0x80)
    no_sig.write_bytes(bytes(img2))  # no PE\0\0 at offset
    assert vd._is_pe_file(no_sig) is False

    valid = tmp_path / "valid.bin"
    _write_minimal_pe(valid)
    assert vd._is_pe_file(valid) is True


# --- _infer_imports_rebuilt ----------------------------------------------


def test_infer_imports_rebuilt_markers() -> None:
    assert vd._infer_imports_rebuilt("Successfully converted call at 0x1", "") is True
    assert vd._infer_imports_rebuilt("Found 12 calls to 5 imports", "") is True
    assert vd._infer_imports_rebuilt("", "IAT rebuilt cleanly") is True
    assert vd._infer_imports_rebuilt("no useful signal", "") is False


# --- _collect_output_pe --------------------------------------------------


def test_collect_output_pe_prefers_written_path(tmp_path: Path) -> None:
    pe = tmp_path / "out.exe"
    _write_minimal_pe(pe)
    got = vd._collect_output_pe(
        stdout=f"File written to: {pe}", stderr="", mtime_floor=0.0, search_roots=[]
    )
    assert got == pe


def test_collect_output_pe_fallback_filters_and_picks_newest(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "subdir").mkdir()  # not a file
    (root / "unrelated.exe").write_bytes(b"MZ")  # name lacks vmpdump marker
    (root / "a.VMPDump.bin").write_bytes(b"not a pe")  # named but not a PE
    old = root / "old.VMPDump.exe"
    _write_minimal_pe(old)
    os.utime(old, (1.0, 1.0))  # below the mtime floor
    new = root / "new.VMPDump.exe"
    _write_minimal_pe(new)
    os.utime(new, (10_000.0, 10_000.0))

    got = vd._collect_output_pe(
        stdout="no path here",
        stderr="",
        mtime_floor=5_000.0,
        search_roots=[root, tmp_path / "does-not-exist"],
    )
    assert got == new


def test_collect_output_pe_skips_unreadable_root(tmp_path: Path) -> None:
    root = tmp_path / "noaccess"
    root.mkdir()
    root.chmod(0o000)
    try:
        with pytest.raises(VmpDumperError) as excinfo:
            vd._collect_output_pe(
                stdout="", stderr="", mtime_floor=0.0, search_roots=[root]
            )
        # iterdir raises, the root is skipped, so no candidate PE is found.
        assert excinfo.value.code == VmpDumperErrorCode.OUTPUT_MISSING
    finally:
        root.chmod(0o755)


def test_collect_output_pe_missing_raises(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(VmpDumperError) as excinfo:
        vd._collect_output_pe(
            stdout="", stderr="", mtime_floor=0.0, search_roots=[empty]
        )
    assert excinfo.value.code == VmpDumperErrorCode.OUTPUT_MISSING


def test_collect_output_pe_ambiguous_raises(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    first = root / "one.VMPDump.exe"
    second = root / "two.VMPDump.exe"
    _write_minimal_pe(first)
    _write_minimal_pe(second)
    os.utime(first, (10_000.0, 10_000.0))
    os.utime(second, (10_000.0, 10_000.0))
    with pytest.raises(VmpDumperError) as excinfo:
        vd._collect_output_pe(
            stdout="", stderr="", mtime_floor=0.0, search_roots=[root]
        )
    assert excinfo.value.code == VmpDumperErrorCode.OUTPUT_AMBIGUOUS


# --- run_vmp_dumper ------------------------------------------------------


def _sample(tmp_path: Path) -> tuple[Path, Path]:
    exe = tmp_path / "vmpdump.exe"
    exe.write_bytes(b"MZ")
    sample = tmp_path / "sample.exe"
    _write_minimal_pe(sample)
    return exe, sample


def test_run_rejects_missing_executable(tmp_path: Path) -> None:
    _, sample = _sample(tmp_path)
    with pytest.raises(VmpDumperError) as excinfo:
        run_vmp_dumper(
            tmp_path / "gone.exe",
            sample,
            tmp_path / "out.exe",
            input_sha256=file_sha256(sample),
            pid=1,
        )
    assert excinfo.value.code == VmpDumperErrorCode.EXECUTABLE_NOT_FOUND


def test_run_rejects_non_file_input(tmp_path: Path) -> None:
    exe, _ = _sample(tmp_path)
    input_dir = tmp_path / "inputdir"
    input_dir.mkdir()
    with pytest.raises(VmpDumperError) as excinfo:
        run_vmp_dumper(
            exe, input_dir, tmp_path / "out.exe", input_sha256="x", pid=1
        )
    assert excinfo.value.code == VmpDumperErrorCode.INPUT_NOT_FOUND


def test_run_reports_a_missing_input_as_structured_not_a_raw_oserror(tmp_path: Path) -> None:
    # resolve(strict=True) used to raise FileNotFoundError before the
    # not-a-file branch could run, so a path that does not exist escaped as a
    # raw OSError (leaking the absolute path) instead of INPUT_NOT_FOUND.
    exe, _ = _sample(tmp_path)
    missing = tmp_path / "nope.exe"
    with pytest.raises(VmpDumperError) as excinfo:
        run_vmp_dumper(exe, missing, tmp_path / "out.exe", input_sha256="x", pid=1)
    assert excinfo.value.code == VmpDumperErrorCode.INPUT_NOT_FOUND
    assert excinfo.value.details.get("input_path") == str(missing)


def test_run_rejects_existing_destination(tmp_path: Path) -> None:
    exe, sample = _sample(tmp_path)
    dest = tmp_path / "out.exe"
    dest.write_bytes(b"already here")
    with pytest.raises(VmpDumperError) as excinfo:
        run_vmp_dumper(
            exe, sample, dest, input_sha256=file_sha256(sample), pid=1
        )
    assert excinfo.value.code == VmpDumperErrorCode.INVALID_ARGUMENT


def test_run_detects_input_sha_mismatch(tmp_path: Path) -> None:
    exe, sample = _sample(tmp_path)
    with pytest.raises(VmpDumperError) as excinfo:
        run_vmp_dumper(
            exe,
            sample,
            tmp_path / "out.exe",
            input_sha256="deadbeef",
            pid=1,
        )
    assert excinfo.value.code == VmpDumperErrorCode.INVALID_ARGUMENT


def test_run_reraises_bounded_cancelled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, sample = _sample(tmp_path)

    def _cancel(*_a: object, **_k: object) -> SimpleNamespace:
        raise BoundedCancelled()

    monkeypatch.setattr(vd, "_capture_process", _cancel)
    with pytest.raises(BoundedCancelled):
        run_vmp_dumper(
            exe, sample, tmp_path / "out.exe", input_sha256=file_sha256(sample), pid=1
        )


def test_run_wraps_capture_failure_as_process_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, sample = _sample(tmp_path)

    def _boom(*_a: object, **_k: object) -> SimpleNamespace:
        raise RuntimeError("spawn failed")

    monkeypatch.setattr(vd, "_capture_process", _boom)
    with pytest.raises(VmpDumperError) as excinfo:
        run_vmp_dumper(
            exe, sample, tmp_path / "out.exe", input_sha256=file_sha256(sample), pid=1
        )
    assert excinfo.value.code == VmpDumperErrorCode.PROCESS_FAILED


def test_run_rejects_output_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, sample = _sample(tmp_path)
    monkeypatch.setattr(
        vd, "_capture_process", lambda *a, **k: _capture(stdout_exceeded=True)
    )
    with pytest.raises(VmpDumperError) as excinfo:
        run_vmp_dumper(
            exe, sample, tmp_path / "out.exe", input_sha256=file_sha256(sample), pid=1
        )
    assert excinfo.value.code == VmpDumperErrorCode.OUTPUT_LIMIT


def test_run_detects_input_mutation_during_dump(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, sample = _sample(tmp_path)

    def _mutate(*_a: object, **_k: object) -> SimpleNamespace:
        sample.write_bytes(b"MZ" + b"\x01" * 0x400)  # change the source under us
        return _capture(stdout="done")

    monkeypatch.setattr(vd, "_capture_process", _mutate)
    with pytest.raises(VmpDumperError) as excinfo:
        run_vmp_dumper(
            exe, sample, tmp_path / "out.exe", input_sha256=file_sha256(sample), pid=1
        )
    assert excinfo.value.code == VmpDumperErrorCode.INVALID_ARGUMENT


def test_run_maps_nonzero_exit_without_output_to_process_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, sample = _sample(tmp_path)
    monkeypatch.setattr(
        vd, "_capture_process", lambda *a, **k: _capture(returncode=3)
    )
    with pytest.raises(VmpDumperError) as excinfo:
        run_vmp_dumper(
            exe,
            sample,
            tmp_path / "out.exe",
            input_sha256=file_sha256(sample),
            pid=1,
            search_roots=[tmp_path / "empty-root"],
        )
    assert excinfo.value.code == VmpDumperErrorCode.PROCESS_FAILED


def test_run_propagates_output_missing_on_clean_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, sample = _sample(tmp_path)
    empty_root = tmp_path / "empty-root"
    empty_root.mkdir()
    monkeypatch.setattr(
        vd, "_capture_process", lambda *a, **k: _capture(stdout="ran ok", returncode=0)
    )
    with pytest.raises(VmpDumperError) as excinfo:
        run_vmp_dumper(
            exe,
            sample,
            tmp_path / "out.exe",
            input_sha256=file_sha256(sample),
            pid=1,
            search_roots=[empty_root],
        )
    assert excinfo.value.code == VmpDumperErrorCode.OUTPUT_MISSING


def test_run_wraps_copy_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, sample = _sample(tmp_path)
    produced = tmp_path / "sample.VMPDump.exe"

    def _fake(*_a: object, **_k: object) -> SimpleNamespace:
        _write_minimal_pe(produced)
        return _capture(stdout=f"File written to: {produced}")

    def _copy_boom(_src: object, _dst: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(vd, "_capture_process", _fake)
    monkeypatch.setattr(shutil, "copy2", _copy_boom)
    with pytest.raises(VmpDumperError) as excinfo:
        run_vmp_dumper(
            exe, sample, tmp_path / "out.exe", input_sha256=file_sha256(sample), pid=1
        )
    assert excinfo.value.code == VmpDumperErrorCode.PROCESS_FAILED


def test_run_success_defaults_roots_and_infers_rebuilt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, sample = _sample(tmp_path)
    produced = sample.parent / "sample.VMPDump.exe"

    def _fake(*_a: object, **_k: object) -> SimpleNamespace:
        _write_minimal_pe(produced)
        return _capture(
            stdout=f"Found 4 calls to 2 imports\nFile written to: {produced}",
        )

    monkeypatch.setattr(vd, "_capture_process", _fake)
    dest = tmp_path / "artifacts" / "dumped.exe"
    result = run_vmp_dumper(
        exe, sample, dest, input_sha256=file_sha256(sample), pid=99, module_name="m"
    )
    assert result.dump_ok is True
    assert result.imports_rebuilt is True
    assert result.vm_restored is False
    assert result.pid == 99
    assert dest.is_file()
    assert not produced.exists()  # sidecar reclaimed
    payload = result.to_dict()
    assert payload["claims_universal_unpack"] is False
    assert payload["supported_arch"] == "x64"


def test_run_keeps_input_when_produced_is_the_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, sample = _sample(tmp_path)

    # VMPDump reports the source path itself; the adapter must copy but never
    # unlink the original input.
    monkeypatch.setattr(
        vd, "_capture_process", lambda *a, **k: _capture(stdout=f"File written to: {sample}")
    )
    dest = tmp_path / "artifacts" / "dumped.exe"
    result = run_vmp_dumper(
        exe, sample, dest, input_sha256=file_sha256(sample), pid=7
    )
    assert result.dump_ok is True
    assert dest.is_file()
    assert sample.is_file()  # original preserved


# --- probe_vmp_dumper ----------------------------------------------------


def test_probe_missing_executable(tmp_path: Path) -> None:
    ok, text = probe_vmp_dumper(tmp_path / "nope.exe")
    assert ok is False
    assert text == ""


def test_probe_marker_match(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    exe = tmp_path / "vmpdump.exe"
    exe.write_bytes(b"MZ")
    monkeypatch.setattr(
        vd,
        "run_bounded",
        lambda *a, **k: SimpleNamespace(
            stdout=b"VMProtect usage: vmpdump <pid>", stderr=b"", returncode=1
        ),
    )
    ok, text = probe_vmp_dumper(exe)
    assert ok is True
    assert "VMProtect" in text


def test_probe_returncode_heuristic_without_markers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "vmpdump.exe"
    exe.write_bytes(b"MZ")
    monkeypatch.setattr(
        vd,
        "run_bounded",
        lambda *a, **k: SimpleNamespace(stdout=b"random banner", stderr=b"", returncode=0),
    )
    ok, text = probe_vmp_dumper(exe)
    assert ok is True
    assert "random banner" in text


def test_probe_no_markers_and_no_text_is_false(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "vmpdump.exe"
    exe.write_bytes(b"MZ")
    monkeypatch.setattr(
        vd,
        "run_bounded",
        lambda *a, **k: SimpleNamespace(stdout=b"", stderr=b"", returncode=2),
    )
    ok, text = probe_vmp_dumper(exe)
    assert ok is False
    assert text == ""


def test_probe_runner_error_is_false(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "vmpdump.exe"
    exe.write_bytes(b"MZ")

    def _boom(*_a: object, **_k: object) -> SimpleNamespace:
        raise OSError("cannot exec")

    monkeypatch.setattr(vd, "run_bounded", _boom)
    ok, text = probe_vmp_dumper(exe)
    assert ok is False
    assert text == ""


def test_run_requires_live_debuggee_pid(tmp_path: Path) -> None:
    exe, sample = _sample(tmp_path)
    with pytest.raises(VmpDumperError) as excinfo:
        run_vmp_dumper(
            exe,
            sample,
            tmp_path / "out.exe",
            input_sha256=file_sha256(sample),
            pid=None,
        )
    # File-only mode is unsupported by upstream; a live pid is mandatory.
    assert excinfo.value.code == VmpDumperErrorCode.DEBUGGEE_REQUIRED
