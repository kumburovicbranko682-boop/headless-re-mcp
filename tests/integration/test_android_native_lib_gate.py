"""Cross-validate the APK native-library (JNI surface) facts against readelf.

An APK session reports each bundled ``lib/<abi>/*.so`` parsed with the same
tool-free ELF reader a native session uses: soname, DT_NEEDED, and the JNI
binding surface -- exported ``Java_*`` symbols (statically registered native
methods) and ``JNI_OnLoad`` (dynamic registration). That reader and the
committed fixture are both ours, so nothing proved the per-member view matches
an independent decoder on a real library. Two checks close that:

* a probe built by the real toolchain: gcc compiles a shared object with a JNI
  export surface (two ``Java_*`` methods, a ``JNI_OnLoad``, a non-JNI export
  and a static helper that must stay invisible), it is packed into an APK, and
  the session facts are compared against what readelf says about the very same
  bytes -- symbols from ``--dyn-syms``, soname/needed from ``-d``;
* the committed fixture's hand-built .so, decoded by readelf: the gate fails
  if binutils reads a different soname, dependency list or export set than the
  fixture intends, so a malformed fixture cannot silently keep passing unit
  tests that share its assumptions.

gcc and readelf ship with the CI runner image (the same pair the ELF search
path and constructor gates use). skip != pass: each test skips, naming the
missing tool, only when gcc or readelf is absent.
"""

from __future__ import annotations

import re
import shutil
import struct
import subprocess
import zipfile
from pathlib import Path

import pytest

from headless_re_mcp.core.service import AnalysisService

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "android" / "minimal.apk"

_PROBE_C = """
int JNI_OnLoad(void* vm, void* reserved) { return 0x00010006; }
const char* Java_com_example_probe_Native_secret(void* env, void* clazz) { return "s"; }
int Java_com_example_probe_Native_add(void* env, void* clazz, int a, int b) { return a + b; }
int probe_plain_export(int x) { return x * 2; }
static int probe_hidden_helper(int x) { return x + 1; }
int probe_uses_helper(int x) { return probe_hidden_helper(x); }
"""

# readelf --dyn-syms -W: "   5: 0000...1119    24 FUNC    GLOBAL DEFAULT   10 JNI_OnLoad"
_DYNSYM_RE = re.compile(
    r"^\s*\d+:\s+[0-9a-fA-F]+\s+\S+\s+(\S+)\s+(GLOBAL|WEAK)\s+\S+\s+(\S+)\s+(\S+)\s*$",
    re.MULTILINE,
)
_NEEDED_RE = re.compile(r"\(NEEDED\)\s+Shared library: \[(.+?)\]")
_SONAME_RE = re.compile(r"\(SONAME\)\s+Library soname: \[(.+?)\]")


def _readelf_exports(readelf: str, library: Path) -> set[str]:
    """The defined GLOBAL/WEAK dynamic symbol names, per readelf --dyn-syms."""
    result = subprocess.run(
        [readelf, "--dyn-syms", "-W", str(library)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    exports: set[str] = set()
    for match in _DYNSYM_RE.finditer(result.stdout):
        _typ, _bind, ndx, name = match.groups()
        if ndx != "UND" and name:
            exports.add(name.split("@")[0])
    return exports


def _readelf_dynamic(readelf: str, library: Path) -> tuple[str | None, set[str]]:
    """The (soname, needed set) from readelf -d."""
    result = subprocess.run(
        [readelf, "-d", str(library)], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr
    soname = _SONAME_RE.search(result.stdout)
    return (
        soname.group(1) if soname else None,
        set(_NEEDED_RE.findall(result.stdout)),
    )


def _readelf_wx_loads(readelf: str, library: Path) -> int:
    """How many LOAD rows readelf -l -W prints with both W and E in Flg."""
    result = subprocess.run(
        [readelf, "-l", "-W", str(library)], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr
    count = 0
    for line in result.stdout.splitlines():
        tokens = line.split()
        if len(tokens) < 8 or tokens[0] != "LOAD":
            continue
        # Everything between MemSiz and Align is the Flg column, which may
        # split on spaces ("R E") or not ("RWE").
        flags = "".join(tokens[6:-1])
        if "W" in flags and "E" in flags:
            count += 1
    return count


def _session_native_libs(apk: Path) -> list[dict]:
    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        assert created.ok, created.error
        return created.data["session"]["metadata"]["apk"]["native_libs"]
    finally:
        service.close_all()


@pytest.mark.integration
def test_apk_jni_surface_agrees_with_readelf_on_a_gcc_probe(tmp_path: Path) -> None:
    gcc = shutil.which("gcc")
    if gcc is None:
        pytest.skip("gcc not installed — JNI surface gate not run (skip != pass)")
    readelf = shutil.which("readelf")
    if readelf is None:
        pytest.skip("readelf (binutils) not installed — JNI surface gate not run (skip != pass)")

    source = tmp_path / "probe.c"
    source.write_text(_PROBE_C, encoding="utf-8")
    library = tmp_path / "libjniprobe.so"
    compile_result = subprocess.run(
        [gcc, "-shared", "-fPIC", "-Wl,-soname,libjniprobe.so", "-o", str(library), str(source)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert compile_result.returncode == 0, compile_result.stderr

    apk = tmp_path / "probe.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("lib/x86_64/libjniprobe.so", library.read_bytes())

    (lib,) = _session_native_libs(apk)
    assert lib["path"] == "lib/x86_64/libjniprobe.so"
    assert lib["abi"] == "x86_64"
    assert lib["arch"] == "x86-64"

    # The JNI surface, re-derived from readelf's decode of the same bytes: the
    # Java_* exports and JNI_OnLoad must match name for name, and the linker's
    # own additions (probe_plain_export, _init/_fini...) must not leak into the
    # java_natives sample -- nor may the static helper appear anywhere.
    exports = _readelf_exports(readelf, library)
    assert set(lib["java_natives"]) == {e for e in exports if e.startswith("Java_")}
    assert set(lib["java_natives"]) == {
        "Java_com_example_probe_Native_add",
        "Java_com_example_probe_Native_secret",
    }
    assert lib["jni_onload"] is ("JNI_OnLoad" in exports)
    assert lib["jni_onload"] is True
    assert "probe_plain_export" in exports  # exported, but rightly not "JNI"
    assert not any("probe_hidden_helper" in name for name in lib["java_natives"])

    # Identity and dependencies, against readelf -d on the same file: the
    # soname the link stamped and whatever libc the toolchain pulled in.
    soname, needed = _readelf_dynamic(readelf, library)
    assert lib["soname"] == soname == "libjniprobe.so"
    assert set(lib["needed"]) == needed

    # A stock toolchain build maps nothing writable and executable at once;
    # the record's W^X census must agree with readelf's Flg column on zero.
    assert lib["wx_segments"] == _readelf_wx_loads(readelf, library) == 0


@pytest.mark.integration
def test_a_packed_library_shape_counts_wx_like_readelf(tmp_path: Path) -> None:
    """A bundled .so with a writable-executable mapping is the packer shape.

    Android packers ship exactly this: a stub .so that unpacks the real code
    into a region it maps W+X. The gate plants one RWE PT_LOAD among clean
    ones, lets readelf's program-header decode referee the count, and requires
    the APK record to carry the same number.
    """
    readelf = shutil.which("readelf")
    if readelf is None:
        pytest.skip("readelf (binutils) not installed — W^X gate not run (skip != pass)")

    body = bytearray()
    for index, p_flags in enumerate([0x5, 0x6, 0x7]):  # R+X, R+W, and the violation
        phdr = bytearray(56)
        struct.pack_into("<I", phdr, 0, 1)  # PT_LOAD
        struct.pack_into("<I", phdr, 4, p_flags)
        struct.pack_into("<Q", phdr, 16, 0x1000 * (index + 1))  # p_vaddr
        struct.pack_into("<Q", phdr, 32, 0x100)  # p_filesz
        struct.pack_into("<Q", phdr, 40, 0x100)  # p_memsz
        body += phdr
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01" + bytes(9),
        3,  # ET_DYN
        62,  # x86-64
        1, 0, 64, 0, 0, 64, 56, 3, 64, 0, 0,
    )
    library = tmp_path / "libpacked.so"
    library.write_bytes(ehdr + bytes(body))
    # readelf must see the planted RWE row, so it is a genuine second opinion.
    assert _readelf_wx_loads(readelf, library) == 1

    apk = tmp_path / "packed.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("lib/x86_64/libpacked.so", library.read_bytes())

    (lib,) = _session_native_libs(apk)
    assert lib["wx_segments"] == 1


@pytest.mark.integration
def test_committed_fixture_library_is_real_elf_per_readelf(tmp_path: Path) -> None:
    """binutils must decode the hand-built fixture .so the way the reader does.

    The fixture's libraries are emitted byte for byte by the APK builder; if
    that encoder drifted from the ELF spec, the unit tests (which share its
    assumptions) would keep passing. readelf is the independent referee: the
    soname, dependency list and export set it reads from the extracted member
    must be exactly the facts the session reports for it.
    """
    if not _FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_FIXTURE}")
    readelf = shutil.which("readelf")
    if readelf is None:
        pytest.skip("readelf (binutils) not installed — JNI surface gate not run (skip != pass)")

    extracted = tmp_path / "libnative.so"
    with zipfile.ZipFile(_FIXTURE) as archive:
        extracted.write_bytes(archive.read("lib/x86_64/libnative.so"))

    exports = _readelf_exports(readelf, extracted)
    soname, needed = _readelf_dynamic(readelf, extracted)

    libs = _session_native_libs(_FIXTURE)
    by_abi = {lib["abi"]: lib for lib in libs}
    lib = by_abi["x86_64"]
    assert set(lib["java_natives"]) | {"JNI_OnLoad"} == exports
    assert lib["jni_onload"] is ("JNI_OnLoad" in exports)
    assert lib["soname"] == soname == "libnative.so"
    assert set(lib["needed"]) == needed == {"liblog.so"}
    assert lib["java_natives"] == ["Java_com_example_headless_Sample_getSecret"]
