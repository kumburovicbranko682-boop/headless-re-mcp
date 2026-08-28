"""Cross-validate the .NET high-entropy resource census against mono and radare2.

A session over a managed PE now flags embedded ManifestResources whose bytes
measure near-random with no magic to explain them -- the exact ConfuserEx /
.NET-Reactor shape: the protected stage-two assembly is stored encrypted, then
inflated at runtime behind Assembly.Load, so it opens with no magic and only
the Shannon measure gives it away. Every link in the reader's chain is ours
(the metadata-table walk, the Resources-directory read, the measure), so the
gate rebuilds the whole answer through an independent pipeline: ``mcs``
compiles the carrier assembly (a real compiler, not a hand-packed fixture),
``monodis --mresources`` extracts every embedded resource through Mono's own
ECMA-335 parser, and radare2's ``ph entropy`` measures the extracted files.
The referee numbers are pushed through the census's published contract (skip
self-declaring magic; flag at or past 7.2 bits per byte for resources of 256
bytes or more, rounded to two decimals) and the flag lists must match record
for record.

The planted assembly also carries a PNG-magic resource with the same random
tail as the flagged blob: radare2 confirms it *is* near-random, and the census
must still skip it -- the media-magic rule at work, not a missed measurement.
A resource-free mcs build is the real-world negative: an empty census must be
the shared answer.

mcs and monodis come from the workflow's mono-mcs and mono-utils installs;
radare2 from its r2 deb. skip != pass: each test skips only when its own
referee is unavailable.
"""

from __future__ import annotations

import shutil
import subprocess
import zlib
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.core.service import AnalysisService

# The census's published contract, restated as the referee's rules.
_THRESHOLD = 7.2
_MIN_SIZE = 256
# Heads that already explain near-random bytes (the reader's published skip
# list, restated independently): executables/containers, media, .resources.
_SELF_DECLARING = (
    b"dex\n",
    b"\x7fELF",
    b"PK\x03\x04",
    b"MZ",
    b"\x00asm",
    b"\x89PNG",
    b"\xff\xd8\xff",
    b"GIF8",
    b"RIFF",
    b"OggS",
    b"ID3",
    b"\x1f\x8b",
    b"wOFF",
    b"wOF2",
    b"\x28\xb5\x2f\xfd",
    b"\xce\xca\xef\xbe",
)

_HELLO_CS = 'class P { static void Main() { System.Console.Write("hi"); } }\n'


def _session_flags(assembly: Path) -> tuple[list[dict[str, Any]], int]:
    service = AnalysisService()
    try:
        created = service.create_session(str(assembly))
        assert created.ok, created.error
        facts = created.data["session"]["metadata"]["dotnet"]
        return facts["high_entropy_resources"], facts["high_entropy_resource_count"]
    finally:
        service.close_all()


def _mcs_build(mcs: str, tmp_path: Path, resources: dict[str, bytes]) -> Path:
    source = tmp_path / "hello.cs"
    source.write_text(_HELLO_CS)
    assembly = tmp_path / "carrier.exe"
    args = [mcs, f"-out:{assembly}", str(source)]
    for name, data in resources.items():
        blob = tmp_path / f"res_{name}"
        blob.write_bytes(data)
        args.append(f"-resource:{blob},{name}")
    subprocess.run(args, check=True, capture_output=True, timeout=120)
    return assembly


def _monodis_extract(assembly: Path, scratch: Path) -> dict[str, Path]:
    """Every embedded resource Mono extracts, ``{name: extracted file}``."""
    scratch.mkdir()
    result = subprocess.run(
        ["monodis", "--mresources", str(assembly)],
        capture_output=True,
        text=True,
        cwd=scratch,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr or result.stdout
    return {p.name: p for p in scratch.iterdir() if p.is_file()}


def _r2_entropy(r2: str, extracted: Path) -> float:
    size = extracted.stat().st_size
    result = subprocess.run(
        [r2, "-q", "-n", "-c", f"b {size}; ph entropy", str(extracted)],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    return float(result.stdout.strip())


def _referee_flags(r2: str, extracted: dict[str, Path]) -> list[dict[str, Any]]:
    """The census rebuilt from Mono's extractions and radare2's measure."""
    flags: list[dict[str, Any]] = []
    for name in sorted(extracted):
        path = extracted[name]
        size = path.stat().st_size
        if size < _MIN_SIZE:
            continue
        with path.open("rb") as handle:
            head = handle.read(0x40)
        if any(head.startswith(magic) for magic in _SELF_DECLARING) or head[4:8] == b"ftyp":
            continue
        entropy = _r2_entropy(r2, path)
        if entropy >= _THRESHOLD:
            flags.append({"name": name, "entropy": round(entropy, 2), "size": size})
    return flags


@pytest.mark.integration
def test_an_encrypted_shaped_resource_measures_like_monodis_plus_radare2(
    tmp_path: Path,
) -> None:
    mcs = shutil.which("mcs")
    if mcs is None:
        pytest.skip("mcs (mono-mcs) not installed — .NET entropy gate not run (skip != pass)")
    if shutil.which("monodis") is None:
        pytest.skip("monodis (mono-utils) missing — extraction referee not run (skip != pass)")
    r2 = shutil.which("r2")
    if r2 is None:
        pytest.skip("radare2 not installed — measurement referee missing (skip != pass)")

    # A real deflate stream is what a protector actually stores; the PNG decoy
    # carries the same random tail but declares itself in its magic.
    corpus = " ".join(f"record {i} value {i * i}" for i in range(20000)).encode()
    blob = zlib.compress(corpus, level=9)
    planted = {
        "Stage2.enc": blob,
        "Decoy.png": b"\x89PNG\r\n\x1a\n" + blob,
        "App.config": b'{"env": "prod"}\n' * 40,
    }
    assembly = _mcs_build(mcs, tmp_path, planted)

    flags, count = _session_flags(assembly)
    assert count == 1
    assert [flag["name"] for flag in flags] == ["Stage2.enc"]
    assert flags[0]["entropy"] >= _THRESHOLD

    extracted = _monodis_extract(assembly, tmp_path / "extracted")
    # Mono must see every planted resource: the ground truth is fixed by an
    # independent ECMA-335 parser, not by re-reading our own walk.
    assert set(planted) <= set(extracted)
    assert flags == _referee_flags(r2, extracted)
    # The decoy is genuinely near-random -- radare2 says so over Mono's own
    # extraction -- and the census still skips it: the published magic rule
    # at work, not a missed measurement.
    assert _r2_entropy(r2, extracted["Decoy.png"]) >= _THRESHOLD


@pytest.mark.integration
def test_a_plain_mcs_build_is_clean_for_both(tmp_path: Path) -> None:
    mcs = shutil.which("mcs")
    if mcs is None:
        pytest.skip("mcs (mono-mcs) not installed — .NET entropy gate not run (skip != pass)")
    if shutil.which("monodis") is None:
        pytest.skip("monodis (mono-utils) missing — extraction referee not run (skip != pass)")
    r2 = shutil.which("r2")
    if r2 is None:
        pytest.skip("radare2 not installed — measurement referee missing (skip != pass)")

    assembly = _mcs_build(mcs, tmp_path, {"App.config": b'{"env": "prod"}\n' * 40})
    flags, count = _session_flags(assembly)
    assert flags == []
    assert count == 0
    # A stock compiler and an honest config: the empty census must be the
    # shared answer through the independent pipeline too.
    extracted = _monodis_extract(assembly, tmp_path / "extracted")
    assert _referee_flags(r2, extracted) == []
