"""Cross-validate the .NET managed-resource payload census against Mono.

A session over a managed PE now lists embedded ManifestResources whose bytes
open with executable magic -- the .NET packer's store, where a protector keeps
the real (often encrypted) stage-two assembly and loads it with Assembly.Load
at runtime. Landing on those bytes means walking the metadata tables to the
ManifestResource row, reading its Offset into the CLI header's Resources
directory, and stepping over its length prefix: all ours. Mono's ``monodis``
referees it end to end. ``monodis --mresources`` is an independent ECMA-335
parser that reads the same ManifestResource table and Resources directory and
writes each embedded resource's raw bytes to a file named after it; a magic
sniff here classifies those extracted files, no code of ours involved. The
reader's census must name exactly the resources Mono extracts with executable
magic -- same name, same kind, same byte size -- and stay silent on the benign
JSON Mono also extracts.

monodis ships in Debian/Ubuntu's ``mono-utils``; skip != pass -- the gate skips,
naming the missing tool, only when monodis is not installed (or the builder is
absent).
"""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "dotnet"
_BUILDER = _FIXTURES / "build_minimal_dotnet.py"
_NESTED_ASSEMBLY = _FIXTURES / "minimal_clr_hint.exe"

# An independent magic table (not imported from the reader): the whole point is
# a second implementation agreeing. MZ carries a 0x40-byte floor like the reader.
_MAGIC: tuple[tuple[bytes, str], ...] = (
    (b"\x7fELF", "elf"),
    (b"dex\n", "dex"),
    (b"PK\x03\x04", "zip"),
    (b"\xcf\xfa\xed\xfe", "macho"),
    (b"MZ", "pe"),
)


def _sniff(data: bytes) -> str | None:
    for magic, kind in _MAGIC:
        if data.startswith(magic):
            if kind == "pe" and len(data) < 0x40:
                return None
            return kind
    return None


def _build_packed(resources: list[tuple[str, bytes]]) -> bytes:
    spec = importlib.util.spec_from_file_location("_dotnet_builder", _BUILDER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.build(resources=resources)  # type: ignore[no-any-return]


def _monodis_extract(assembly: Path, scratch: Path) -> dict[str, bytes]:
    """Every embedded resource Mono extracts, ``{name: bytes}``.

    ``monodis --mresources`` writes each embedded ManifestResource to a file
    named after the resource in the working directory -- an entirely separate
    ECMA-335 read of the same table and Resources blob our reader walks.
    """
    result = subprocess.run(
        ["monodis", "--mresources", str(assembly)],
        capture_output=True,
        text=True,
        cwd=scratch,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr or result.stdout
    return {p.name: p.read_bytes() for p in scratch.iterdir() if p.is_file()}


@pytest.mark.integration
def test_managed_resource_census_agrees_with_monodis(tmp_path: Path) -> None:
    if not _BUILDER.is_file():
        pytest.skip(f"builder missing: {_BUILDER} (skip != pass)")
    if shutil.which("monodis") is None:
        pytest.skip("monodis (mono-utils) not installed — .NET cross-check not run (skip != pass)")

    # A packer's shape: the real assembly kept as an embedded resource, a native
    # loader beside it, a zipped payload, and one honest config the packer left
    # in the clear. The nested assembly is a genuine managed PE (the committed
    # minimal_clr_hint.exe), so the "pe" verdict rides on real bytes.
    nested = _NESTED_ASSEMBLY.read_bytes() if _NESTED_ASSEMBLY.is_file() else b"MZ" + bytes(0x60)
    planted: dict[str, bytes] = {
        "Stage2.Payload": nested,
        "loader.bin": b"\x7fELF" + b"\x00" * 0x60,
        "bundle.pak": b"PK\x03\x04" + b"\x00" * 0x60,
        "app.config.json": b'{"env": "prod"}\n',  # benign: extracted, never flagged
    }
    assembly = tmp_path / "packed.exe"
    assembly.write_bytes(_build_packed(list(planted.items())))

    # Independent ground truth: Mono extracts every embedded resource itself.
    scratch = tmp_path / "extracted"
    scratch.mkdir()
    extracted = _monodis_extract(assembly, scratch)
    # Mono must see every resource we planted, byte for byte -- proving the file
    # is a genuine assembly and fixing the ground truth the census is judged by.
    assert extracted == planted, sorted(extracted)

    # What an independent sniff of Mono's extracted bytes says is executable.
    expected = {
        name: kind
        for name, data in extracted.items()
        if (kind := _sniff(data)) is not None
    }
    assert expected == {"Stage2.Payload": "pe", "loader.bin": "elf", "bundle.pak": "zip"}

    # The reader, driven through the service exactly as a client reaches it.
    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
        )
    )
    try:
        session_id = service.create_session(str(assembly)).data["session"]["id"]
        census = service.registry.get(session_id).metadata["dotnet"]["resource_payloads"]
    finally:
        service.close_all()

    # Name for name, kind for kind: the reader flags exactly the resources Mono
    # extracted with executable magic, and reports each one's true byte size.
    reader = {entry["name"]: entry["kind"] for entry in census}
    assert reader == expected
    reader_sizes = {entry["name"]: entry["size"] for entry in census}
    for name in expected:
        assert reader_sizes[name] == len(extracted[name])
    # The honest config Mono also extracted is absent from the census.
    assert "app.config.json" not in reader
