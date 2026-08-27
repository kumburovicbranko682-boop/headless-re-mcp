"""Branch coverage for the radare2/rizin backend and its address mapping.

The r2 client is a one-shot CLI adapter: it clamps the caller deadline, refuses
a backend that is not installed or a binary that is not there, whitelists the
commands it will run, and maps a launch failure to backend_error rather than an
internal fault. The mapping layer turns r2's ``*j`` JSON into unified Address
records and reads the PE preferred base straight from the header without
spawning r2. These fakes drive the validation, degradation, and header-parsing
branches without a real radare2 install; the live gate
(tests/integration/test_m11_r2_live_gate.py) pins the real tool.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from headless_re_mcp.backends.common.bounded_run import Completed, TimedOut
from headless_re_mcp.backends.r2 import client as r2_client
from headless_re_mcp.backends.r2.client import R2Client, R2Error, _discover
from headless_re_mcp.backends.r2.mapping import (
    enrich_r2_payload,
    parse_r2_json,
    pe_preferred_base,
)
from headless_re_mcp.core.models import Architecture

MP = pytest.MonkeyPatch


def _write_pe(
    path: Path,
    *,
    pe_offset: int = 0x80,
    optional_size: int = 0xF0,
    magic: int = 0x20B,
    image_base: int = 0x140000000,
    size: int = 0x400,
) -> Path:
    image = bytearray(size)
    image[0:2] = b"MZ"
    image[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    image[pe_offset + 20 : pe_offset + 22] = optional_size.to_bytes(2, "little")
    opt = pe_offset + 24
    image[opt : opt + 2] = magic.to_bytes(2, "little")
    if magic == 0x10B:
        image[opt + 28 : opt + 32] = (image_base & 0xFFFFFFFF).to_bytes(4, "little")
    else:
        image[opt + 24 : opt + 32] = image_base.to_bytes(8, "little")
    path.write_bytes(bytes(image))
    return path


def _fake_completed(monkeypatch: MP, stdout: bytes, *, returncode: int = 0) -> None:
    monkeypatch.setattr(
        r2_client,
        "run_bounded",
        lambda *a, **k: Completed(returncode=returncode, stdout=stdout, stderr=b""),
    )


class TestRunGuards:
    def test_run_rejects_a_nonpositive_timeout(self, tmp_path: Path) -> None:
        binary = _write_pe(tmp_path / "f.exe")
        with pytest.raises(R2Error) as excinfo:
            R2Client(Path(sys.executable)).run(binary, ["i"], timeout=0)
        assert excinfo.value.code == "invalid_params"

    def test_run_reports_capability_unavailable(self, tmp_path: Path) -> None:
        binary = _write_pe(tmp_path / "f.exe")
        client = R2Client(tmp_path / "no-such-r2")
        assert client.available is False
        with pytest.raises(R2Error) as excinfo:
            client.run(binary, ["i"])
        assert excinfo.value.code == "capability_unavailable"

    def test_run_reports_a_missing_binary(self, tmp_path: Path) -> None:
        with pytest.raises(R2Error) as excinfo:
            R2Client(Path(sys.executable)).run(tmp_path / "gone.exe", ["i"])
        assert excinfo.value.code == "not_found"

    def test_run_rejects_a_command_off_the_whitelist(self, tmp_path: Path) -> None:
        binary = _write_pe(tmp_path / "f.exe")
        with pytest.raises(R2Error) as excinfo:
            R2Client(Path(sys.executable)).run(binary, ["!rm -rf /"])
        assert excinfo.value.code == "invalid_params"

    def test_run_maps_a_timeout(self, tmp_path: Path, monkeypatch: MP) -> None:
        binary = _write_pe(tmp_path / "f.exe")

        def _boom(*_a: object, **_k: object) -> None:
            raise TimedOut(0.8, killed=[123])

        monkeypatch.setattr(r2_client, "run_bounded", _boom)
        with pytest.raises(R2Error) as excinfo:
            R2Client(Path(sys.executable)).run(binary, ["i"])
        assert excinfo.value.code == "timeout"
        assert excinfo.value.details.get("killed_pids") == [123]

    def test_run_maps_a_launch_oserror_to_backend_error(
        self, tmp_path: Path, monkeypatch: MP
    ) -> None:
        binary = _write_pe(tmp_path / "f.exe")

        def _boom(*_a: object, **_k: object) -> None:
            raise PermissionError("not executable")

        monkeypatch.setattr(r2_client, "run_bounded", _boom)
        with pytest.raises(R2Error) as excinfo:
            R2Client(Path(sys.executable)).run(binary, ["i"])
        assert excinfo.value.code == "backend_error"

    def test_run_maps_a_nonzero_exit(self, tmp_path: Path, monkeypatch: MP) -> None:
        binary = _write_pe(tmp_path / "f.exe")
        _fake_completed(monkeypatch, b"", returncode=3)
        monkeypatch.setattr(
            r2_client,
            "run_bounded",
            lambda *a, **k: Completed(returncode=3, stdout=b"", stderr=b"boom"),
        )
        with pytest.raises(R2Error) as excinfo:
            R2Client(Path(sys.executable)).run(binary, ["i"])
        assert excinfo.value.code == "backend_error"
        assert excinfo.value.details.get("exit_code") == 3


class TestOpenDisasmXrefs:
    def test_open_reports_a_missing_binary(self, tmp_path: Path) -> None:
        with pytest.raises(R2Error) as excinfo:
            R2Client(Path(sys.executable)).open(tmp_path / "gone.exe")
        assert excinfo.value.code == "not_found"

    def test_open_validates_and_summarizes(self, tmp_path: Path, monkeypatch: MP) -> None:
        binary = _write_pe(tmp_path / "f.exe")
        _fake_completed(monkeypatch, b"arch x86\nbits 64\n")
        out = R2Client(Path(sys.executable)).open(binary)
        assert out["opened"] is True
        assert out["binary"] == str(binary)
        assert "arch x86" in out["info"]

    def test_disasm_rejects_a_bad_address(self, tmp_path: Path) -> None:
        binary = _write_pe(tmp_path / "f.exe")
        client = R2Client(Path(sys.executable))
        with pytest.raises(R2Error) as excinfo:
            client.disasm(binary, -1)
        assert excinfo.value.code == "invalid_params"
        with pytest.raises(R2Error):
            client.disasm(binary, True)  # bool is not int here

    def test_disasm_rejects_a_bad_count(self, tmp_path: Path) -> None:
        binary = _write_pe(tmp_path / "f.exe")
        client = R2Client(Path(sys.executable))
        with pytest.raises(R2Error) as excinfo:
            client.disasm(binary, 0x1000, count=0)
        assert excinfo.value.code == "invalid_params"
        with pytest.raises(R2Error):
            client.disasm(binary, 0x1000, count=513)

    def test_disasm_returns_enriched_items(self, tmp_path: Path, monkeypatch: MP) -> None:
        binary = _write_pe(tmp_path / "f.exe")
        _fake_completed(
            monkeypatch, json.dumps([{"offset": 0x140001000, "opcode": "nop"}]).encode()
        )
        out = R2Client(Path(sys.executable)).disasm(binary, 0x140001000, count=1)
        assert out["address_va"] == 0x140001000
        assert out["count"] == 1
        assert out["items"] and out["items"][0]["opcode"] == "nop"

    def test_xrefs_rejects_a_bad_address(self, tmp_path: Path) -> None:
        binary = _write_pe(tmp_path / "f.exe")
        with pytest.raises(R2Error) as excinfo:
            R2Client(Path(sys.executable)).xrefs(binary, -5)
        assert excinfo.value.code == "invalid_params"

    def test_xrefs_returns_enriched_edges(self, tmp_path: Path, monkeypatch: MP) -> None:
        binary = _write_pe(tmp_path / "f.exe")
        _fake_completed(
            monkeypatch, json.dumps([{"from": 0x140001000, "to": 0x140001010}]).encode()
        )
        out = R2Client(Path(sys.executable)).xrefs(binary, 0x140001000)
        assert out["address_va"] == 0x140001000
        assert out["items"][0]["from_address"]["va"] == 0x140001000
        assert out["items"][0]["to_address"]["va"] == 0x140001010


class TestDiscover:
    def test_discover_returns_the_first_name_on_path(self, monkeypatch: MP) -> None:
        monkeypatch.setattr(
            r2_client.shutil, "which", lambda name: "/usr/bin/r2" if name == "r2" else None
        )
        assert _discover() == Path("/usr/bin/r2")

    def test_discover_prefers_rizin_when_r2_absent(self, monkeypatch: MP) -> None:
        monkeypatch.setattr(
            r2_client.shutil,
            "which",
            lambda name: "/opt/rizin" if name == "rizin" else None,
        )
        assert _discover() == Path("/opt/rizin")

    def test_discover_returns_none_when_nothing_found(self, monkeypatch: MP) -> None:
        monkeypatch.setattr(r2_client.shutil, "which", lambda name: None)
        assert _discover() is None


class TestPePreferredBase:
    def test_directory_target_degrades_to_none(self, tmp_path: Path) -> None:
        assert pe_preferred_base(tmp_path) == (None, None)

    def test_non_pe_bytes_degrade_to_none(self, tmp_path: Path) -> None:
        f = tmp_path / "not-a-pe"
        f.write_bytes(b"MZ" + b"\x00" * 0x50)  # e_lfanew points nowhere useful
        assert pe_preferred_base(f) == (None, None)

    def test_tiny_non_mz_file_degrades(self, tmp_path: Path) -> None:
        f = tmp_path / "tiny"
        f.write_bytes(b"hello")  # under 0x40 bytes and not an MZ image
        assert pe_preferred_base(f) == (None, None)

    def test_mz_without_pe_signature_degrades(self, tmp_path: Path) -> None:
        f = tmp_path / "fake.exe"
        image = bytearray(0x200)
        image[0:2] = b"MZ"
        image[0x3C:0x40] = (0x40).to_bytes(4, "little")  # in-window, but no PE there
        f.write_bytes(bytes(image))
        assert pe_preferred_base(f) == (None, None)

    def test_short_optional_header_degrades(self, tmp_path: Path) -> None:
        f = _write_pe(tmp_path / "short.exe", optional_size=0x0A)
        assert pe_preferred_base(f) == (None, None)

    def test_unknown_magic_degrades(self, tmp_path: Path) -> None:
        f = _write_pe(tmp_path / "weird.exe", magic=0x999)
        assert pe_preferred_base(f) == (None, None)

    def test_x86_image_base_is_read(self, tmp_path: Path) -> None:
        f = _write_pe(tmp_path / "x86.exe", magic=0x10B, image_base=0x00400000)
        arch, base = pe_preferred_base(f)
        assert arch is Architecture.X86
        assert base == 0x00400000

    def test_x64_image_base_is_read(self, tmp_path: Path) -> None:
        f = _write_pe(tmp_path / "x64.exe", magic=0x20B, image_base=0x140000000)
        arch, base = pe_preferred_base(f)
        assert arch is Architecture.X64
        assert base == 0x140000000

    def test_zero_image_base_returns_arch_without_base(self, tmp_path: Path) -> None:
        f = _write_pe(tmp_path / "nobase.exe", magic=0x20B, image_base=0)
        arch, base = pe_preferred_base(f)
        assert arch is Architecture.X64
        assert base is None

    def test_oversized_optional_header_triggers_a_reread(self, tmp_path: Path) -> None:
        # optional_size 0xFFFF pushes the header end past the 64 KiB first read,
        # so the parser must seek back and read again to reach the magic.
        f = _write_pe(
            tmp_path / "big.exe",
            optional_size=0xFFFF,
            magic=0x20B,
            image_base=0x140000000,
            size=66000,
        )
        arch, base = pe_preferred_base(f)
        assert arch is Architecture.X64
        assert base == 0x140000000


class TestParseAndEnrich:
    def test_parse_returns_none_for_empty(self) -> None:
        assert parse_r2_json("") is None
        assert parse_r2_json("   ") is None

    def test_parse_skips_invalid_json_prefixes(self) -> None:
        raw = 'banner {bad json}\n[{"offset": 4096}]'
        value = parse_r2_json(raw)
        assert value == [{"offset": 4096}]

    def test_parse_returns_none_when_nothing_decodes(self) -> None:
        assert parse_r2_json("[oops not json") is None

    def test_enrich_reports_unparsed_for_non_json(self, tmp_path: Path) -> None:
        f = _write_pe(tmp_path / "f.exe")
        out = enrich_r2_payload({"raw": "not json at all", "commands": ["i"]}, binary=f)
        assert out["parsed"] is False

    def test_enrich_without_pe_base_omits_arch_and_image_base(self, tmp_path: Path) -> None:
        f = tmp_path / "raw.bin"
        f.write_bytes(b"this is not a PE at all, just some bytes for r2")
        out = enrich_r2_payload({"raw": "[]"}, binary=f)
        assert "image_base" not in out
        assert "architecture" not in out
        assert out["parsed"] is True

    def test_enrich_stores_a_dict_payload_as_info(self, tmp_path: Path) -> None:
        f = _write_pe(tmp_path / "f.exe")
        out = enrich_r2_payload({"raw": '{"arch": "x86", "bits": 64}'}, binary=f)
        assert out["parsed"] is True
        assert out["info"] == {"arch": "x86", "bits": 64}

    def test_enrich_skips_non_dict_entries_and_missing_addresses(self, tmp_path: Path) -> None:
        f = _write_pe(tmp_path / "f.exe")
        raw = json.dumps([1, "str", {"note": "no address here"}])
        out = enrich_r2_payload({"raw": raw}, binary=f)
        assert out["count"] == 1  # the two non-dicts were dropped
        assert "address" not in out["items"][0]

    def test_enrich_reads_string_addresses(self, tmp_path: Path) -> None:
        f = _write_pe(tmp_path / "f.exe")
        raw = json.dumps(
            [{"offset": "0x140002000"}, {"offset": "not-a-number", "vaddr": 0x140003000}]
        )
        out = enrich_r2_payload({"raw": raw}, binary=f)
        assert out["items"][0]["address"]["va"] == 0x140002000
        assert out["items"][1]["address"]["va"] == 0x140003000

    def test_enrich_ignores_a_negative_request_address(self, tmp_path: Path) -> None:
        f = _write_pe(tmp_path / "f.exe")
        out = enrich_r2_payload({"raw": "[]", "address": -1}, binary=f)
        # A negative request address cannot map, so no Address object is set.
        assert out["address"] == -1
        assert "address_va" not in out

    def test_enrich_flags_item_truncation(self, tmp_path: Path, monkeypatch: MP) -> None:
        import headless_re_mcp.backends.r2.mapping as mapping

        monkeypatch.setattr(mapping, "_MAX_ITEMS", 2)
        f = _write_pe(tmp_path / "f.exe")
        raw = json.dumps([{"offset": 0x1000 + i} for i in range(5)])
        out = enrich_r2_payload({"raw": raw}, binary=f)
        assert out["items_truncated"] is True
        assert out["items_total"] == 5
        assert out["count"] == 2
