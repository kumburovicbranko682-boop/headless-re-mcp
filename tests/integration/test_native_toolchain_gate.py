"""Native platform/search-path facts vs binutils/llvm on real toolchain output.

Two triage themes the other native gates cannot cover from system binaries:

- Universal (fat) Mach-O slices -- macOS ships x86_64+arm64 containers as the
  norm, and each slice is a complete thin Mach-O whose facts can differ, so
  the session describes every slice in full. llvm-lipo builds the container
  (and page-aligns the slices to nonzero offsets), then referees the arch
  census while llvm-objdump's per-arch decode referees a slice's dylibs.
- Text relocations (ELF DT_TEXTREL/DF_TEXTREL) -- the dynamic W^X violation:
  the loader remaps code writable to relocate it. Stock -fPIC output never
  carries the marker, so the positive case builds a real non-PIC shared
  object (-fno-pic -mcmodel=large -Wl,-z,notext) whose dynamic table readelf
  -d must also call TEXTREL, with a plain PIC link as the negative.
- Search paths (ELF DT_RPATH/DT_RUNPATH, Mach-O LC_RPATH) -- a first-order
  hijack/supply-chain fact, since a writable or relative entry lets an attacker
  plant a library the loader picks up. System binaries almost never carry one,
  so the positive case needs binaries that do: gcc links an ELF probe with a
  known rpath (old tags) and another with a known runpath (new tags), and
  readelf -d must agree entry for entry; the committed Mach-O fixture carries
  an LC_RPATH that llvm-objdump --macho (LLVM's independent, strict Mach-O
  decoder, which rejected the fixture's earlier 4-byte-aligned load commands)
  must report identically.
- Target platform / minimum system version (ELF NT_GNU_ABI_TAG, Mach-O
  LC_BUILD_VERSION) -- which Unix and how old a kernel/OS. A plain gcc link
  carries the ABI-tag note readelf -n decodes as "OS: Linux, ABI: x.y.z", and
  the fixture's LC_BUILD_VERSION is what the r2 gate checks against radare2's
  os line; here llvm-objdump confirms its platform/minos/sdk. The same plain
  link also carries the DT_VERNEED chain (which GLIBC_x.y tags of which
  libraries the loader must satisfy -- the library-level minimum-runtime
  fact), which readelf -V must decode identically.
- Provided symbol versions (ELF DT_VERDEF) -- the export side of the versioned
  symbol story: the version nodes a shared object defines as its ABI contract.
  A library linked with a version script carries the Verdef chain readelf -V
  renders as its "Version definition section", which the reader must match node
  for node (BASE flag and inherited parents included).
- The load-time constructor surface (ELF DT_INIT/DT_INIT_ARRAY, Mach-O
  S_MOD_INIT_FUNC_POINTERS sections): the code the loader runs before the
  entry point -- where implants and anti-debug hooks hide, since they fire
  before any breakpoint on main. gcc builds a library with two real
  constructors and a destructor, and readelf -d must agree on the INIT/FINI
  presence and every ARRAYSZ-derived count; the Mach-O fixture's
  __mod_init_func/__mod_term_func pointers are re-counted from llvm-objdump's
  section decode.
- The symbol surface (ELF .dynsym, Mach-O LC_SYMTAB), both sides of one split:
  exports (the object's public API, the raw-symbol complement to DT_VERDEF)
  and imports (the undefined symbols the loader must resolve -- capability at
  symbol granularity, where DT_NEEDED / LC_LOAD_DYLIB only name libraries). A
  plain shared library's default-visibility globals and its libc calls land on
  the two sides of readelf --dyn-syms, which the reader must match name for
  name; the Mach-O fixture's external nlist entries are what llvm-nm
  --defined-only / --undefined-only --extern-only print (GNU nm cannot read
  Mach-O), and the reader must make the identical split.
- The branch-protection posture (ELF NT_GNU_PROPERTY_TYPE_0) -- the forward-
  edge CFI / shadow-stack answer that pairs with PE's cfg bit: gcc
  -fcf-protection stamps IBT/SHSTK feature bits the loader and CPU enforce,
  and readelf -n prints the same names. Three real compiles (full / branch /
  none) must read back as exactly the feature sets readelf decodes -- the
  "none" build still carries a property note (ISA-needed), so it also proves
  the reader distinguishes "note without the feature entry" from "protected".
- The overlay (data appended past the mapped image), the PE line's classic
  dropper-payload fact brought to ELF and Mach-O: the image end is re-derived
  from readelf's header/section decode (ELF) and llvm-objdump's segment and
  symtab decode (Mach-O), a pristine binary must report none, and a copy with
  bytes appended must report exactly those bytes at exactly that offset.
- The FORTIFY_SOURCE posture (ELF __*_chk wrapper imports) -- the checksec
  column beside nx/relro/canary/pie: a -D_FORTIFY_SOURCE build routes bounded
  libc calls through fortified wrappers, each named __<func>_chk and imported
  from libc. gcc compiles the same source at -D_FORTIFY_SOURCE=2 and at =0,
  and the reader's fortify_source / fortified_functions must match the
  __*_chk set readelf --dyn-syms shows in each build -- present in the
  fortified one, empty in the plain one. The Mach-O side is the same fact off
  the mangled ___*_chk imports: a synthetic image carrying them reads
  fortified against llvm-nm's undefined-extern set, and the committed fixture
  (canaried, imports end in _fail/_guard) reads a definitive False.
- The weak imports (ELF .dynsym STB_WEAK + SHN_UNDEF) -- optional capability
  the loader leaves null when unresolved rather than failing to start, the
  ELF pair to a Mach-O weak dylib and a PE delay import. A library with a
  real weak extern carries the weak undefined entry readelf --dyn-syms marks
  "WEAK ... UND", which the reader's weak_imports subset must match name for
  name while keeping the whole set in imported_symbols.
- The dylib dependency classes (Mach-O LC_LOAD_WEAK_DYLIB / LC_REEXPORT_DYLIB)
  -- the optional-capability channel (dyld leaves a missing weak dylib's
  symbols null, so the image probes at runtime: the Mach-O pair to PE delay
  imports) and API forwarding (a facade whose exports live elsewhere). A
  synthetic dylib carrying all three command kinds must split in the reader
  exactly as llvm-objdump's load-command decode does.
- The separate-debug-file link (ELF .gnu_debuglink) -- where the stripped
  symbols went, the ELF pair to the PE pdb-path fact. The gate replays the
  distro strip pipeline (objcopy --only-keep-debug / --strip-debug /
  --add-gnu-debuglink) so the record's producer is the real one, then
  referees the name through readelf's raw section dump and the checksum
  through zlib's independent CRC32 of the debug file's actual bytes.
- The dyld exports trie (LC_DYLD_INFO's export pair / LC_DYLD_EXPORTS_TRIE)
  -- the loader's authoritative export list, the surface that survives strip
  when LC_SYMTAB's externals do not. The trie's ULEB offsets, edge-string
  accumulation and terminal detection are all ours, so llvm-objdump
  --exports-trie (LLVM's own decoder of the same structure) referees the
  name set on a shared-prefix trie a naive reader would misread.

skip != pass when a tool is missing; gcc/readelf ship with the CI runner and
llvm is installed on the Linux lane.
"""

from __future__ import annotations

import re
import shutil
import struct
import subprocess
import zlib
from pathlib import Path
from typing import Any, cast

import pytest

from headless_re_mcp.core.service import AnalysisService

_MACHO_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "native" / "minimal.macho"

# readelf -d prints e.g. " 0x...f (RPATH)  Library rpath: [/opt/lib:$ORIGIN]".
_READELF_RPATH_RE = re.compile(r"\(RPATH\)\s+Library rpath: \[([^\]]*)\]")
_READELF_RUNPATH_RE = re.compile(r"\(RUNPATH\)\s+Library runpath: \[([^\]]*)\]")
# readelf -n prints the GNU ABI tag as "    OS: Linux, ABI: 3.2.0".
_READELF_ABI_RE = re.compile(r"OS: (\w+), ABI: (\d+\.\d+\.\d+)")
# readelf -V renders the Verneed chain as "File: libc.so.6  Cnt: 3" record
# lines followed by one "Name: GLIBC_2.34  Flags: ..." line per version tag.
_READELF_VERNEED_FILE_RE = re.compile(r"Version: 1\s+File: (\S+)\s+Cnt: \d+")
_READELF_VERNEED_NAME_RE = re.compile(r"Name: (\S+)\s+Flags:")
# readelf -V renders each Verdef node as "... Flags: BASE  Index: 1  Cnt: 1
# Name: libprobe.so.1", with any inherited parent on a following
# "Parent 1: PROBE_1.0" line.
_READELF_VERDEF_NAME_RE = re.compile(r"Flags:\s+(\S+).*?\bName:\s+(\S+)")
_READELF_VERDEF_PARENT_RE = re.compile(r"Parent \d+:\s+(\S+)")
_READELF_SECTION_RE = re.compile(r"^Version \w+ section")

# A tiny library that defines two symbols bound to two version nodes, the
# second inheriting the first -- enough for ld to emit a three-node Verdef
# section (the BASE soname node plus the two script nodes).
_LIB_C = "int probe_one(void){return 1;}\nint probe_two(void){return 2;}\n"
_VERSION_SCRIPT = (
    "PROBE_1.0 { global: probe_one; local: *; };\n"
    "PROBE_2.0 { global: probe_two; } PROBE_1.0;\n"
)
_LIB_SONAME = "libprobe.so.1"

# A library with two load-time constructors and one destructor: the loader
# runs these before any breakpoint on an entry point could fire, which is why
# the init surface is a first-order triage fact. gcc places each
# __attribute__((constructor)) in .init_array (plus whatever the CRT adds,
# e.g. frame_dummy), so the known lower bounds are two init entries and one
# fini entry, and readelf -d prints the same INIT/FINI/ARRAYSZ tags the
# reader derives its counts from.
_CTORS_C = (
    "static int state;\n"
    "__attribute__((constructor)) static void boot_one(void){state = 1;}\n"
    "__attribute__((constructor)) static void boot_two(void){state = 2;}\n"
    "__attribute__((destructor)) static void teardown(void){state = 0;}\n"
    "int ctor_state(void){return state;}\n"
)
# readelf -d prints " 0x... (INIT_ARRAYSZ)  24 (bytes)" and bare "(INIT)".
_READELF_INIT_SZ_RE = re.compile(r"\(INIT_ARRAYSZ\)\s+(\d+) \(bytes\)")
_READELF_FINI_SZ_RE = re.compile(r"\(FINI_ARRAYSZ\)\s+(\d+) \(bytes\)")
_READELF_PREINIT_SZ_RE = re.compile(r"\(PREINIT_ARRAYSZ\)\s+(\d+) \(bytes\)")

# A plain library (no version script) whose default-visibility globals become
# the .dynsym exports the reader must recover -- functions and a datum, plus a
# static helper that must stay out of the dynamic table -- and whose call to
# puts becomes an undefined .dynsym entry, the known import on the other side
# of the same split.
_EXPORTS_C = (
    "extern int puts(const char *);\n"
    "int exp_counter = 7;\n"
    "int exp_add(int a, int b){return a+b;}\n"
    "int exp_mul(int a, int b){return a*b;}\n"
    "static int helper(int x){return x+1;}\n"
    "int exp_use(int x){return helper(x)+exp_counter;}\n"
    'int exp_report(void){return puts("probe");}\n'
)
_KNOWN_EXPORTS = {"exp_counter", "exp_add", "exp_mul", "exp_use", "exp_report"}
_KNOWN_IMPORTS = {"puts"}

# A library that probes for an optional symbol before calling it: the weak
# extern becomes an STB_WEAK + SHN_UNDEF .dynsym entry (the loader leaves it
# null when unresolved), while the plain libc call stays a hard import. This
# is the optional-capability pattern the weak_imports fact exists to surface.
_WEAK_C = (
    "extern int optional_probe(int) __attribute__((weak));\n"
    "extern int puts(const char *);\n"
    "int weak_run(void){\n"
    "    if (optional_probe) return optional_probe(1);\n"
    '    return puts("fallback");\n'
    "}\n"
)

# A library whose bounded string calls route through libc's fortified wrappers
# under -D_FORTIFY_SOURCE: strcpy/memcpy/sprintf into a fixed buffer become
# __strcpy_chk / __memcpy_chk / __sprintf_chk imports. Compiled at =0 the same
# source imports the plain functions instead, so the two builds bracket the
# FORTIFY posture the reader must tell apart.
_FORTIFY_C = (
    "#include <string.h>\n"
    "#include <stdio.h>\n"
    "int fort_run(const char *s, const char *t){\n"
    "    char buf[64];\n"
    "    strcpy(buf, s);\n"
    "    memcpy(buf + 8, t, 8);\n"
    '    sprintf(buf + 16, "%s", t);\n'
    "    return puts(buf);\n"
    "}\n"
)
# readelf -W --dyn-syms rows: "Num: Value Size Type Bind Vis Ndx Name".
_READELF_DYNSYM_RE = re.compile(
    r"^\s*\d+:\s+\S+\s+\S+\s+\S+\s+(\S+)\s+\S+\s+(\S+)\s+(\S+)"
)

# llvm-objdump --macho --all-headers prints the LC_BUILD_VERSION block as
# "cmd LC_BUILD_VERSION" followed by platform/sdk/minos lines.
_LLVM_BUILD_VERSION_RE = re.compile(
    r"cmd LC_BUILD_VERSION\n"
    r"\s*cmdsize \d+\n"
    r"\s*platform (\S+)\n"
    r"\s*sdk (\S+)\n"
    r"\s*minos (\S+)"
)
# ... and its trailing build_tool_version entries as "tool ld" / "version
# 1053.12" line pairs.
_LLVM_TOOL_RE = re.compile(r"^\s*tool (\S+)\n\s*version (\S+)$", re.MULTILINE)
# readelf -p .comment rows: "  [    20]  GCC: (Ubuntu ...) 13.2.0" with a hex
# section offset in the brackets.
_READELF_COMMENT_RE = re.compile(r"^\s*\[\s*[0-9a-f]+\]\s+(.*)$", re.MULTILINE | re.IGNORECASE)


def _llvm_macho_sections(objdump: str, binary: Path) -> list[dict[str, Any]]:
    """Each section's fields as llvm-objdump --macho --all-headers prints them.

    The otool-style output renders one block per section ("sectname __text" /
    "size 0x..." / "type S_REGULAR" lines); a plain line walk collects them
    into dicts, so the caller can re-derive any section-typed fact from
    LLVM's independent (and strict) decode.
    """
    result = subprocess.run(
        [objdump, "--macho", "--all-headers", str(binary)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    sections: list[dict[str, Any]] = []
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        key, value = parts
        if key == "sectname":
            sections.append({"sectname": value})
        elif sections and key in ("segname", "type"):
            sections[-1][key] = value
        elif sections and key == "size":
            sections[-1]["size"] = int(value, 16)
    return sections

_PROBE_C = "int main(void) { return 0; }\n"
# $ORIGIN exercises the loader token passthrough; the reader must not expand it.
_SEARCH_PATH = "/opt/probe/lib:$ORIGIN/../lib"
_SEARCH_LIST = ["/opt/probe/lib", "$ORIGIN/../lib"]


def _compile_probe(gcc: str, tmp_path: Path, name: str, *link_args: str) -> Path:
    source = tmp_path / "probe.c"
    source.write_text(_PROBE_C)
    out = tmp_path / name
    result = subprocess.run(
        [gcc, str(source), "-o", str(out), *link_args],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    return out


def _readelf_paths(readelf: str, binary: Path) -> tuple[list[str] | None, list[str] | None]:
    """``(rpath, runpath)`` as readelf -d decodes them, None when a tag is absent."""
    result = subprocess.run(
        [readelf, "-d", str(binary)], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr

    def parse(pattern: re.Pattern[str]) -> list[str] | None:
        match = pattern.search(result.stdout)
        if match is None:
            return None
        return [part for part in match.group(1).split(":") if part]

    return parse(_READELF_RPATH_RE), parse(_READELF_RUNPATH_RE)


def _readelf_version_needs(readelf: str, binary: Path) -> list[dict[str, Any]]:
    """The Verneed chain as readelf -V decodes it, in the reader's fact shape.

    readelf renders each Verneed record as a "Version: 1  File: ...  Cnt: n"
    line followed by one "Name: ...  Flags: ..." line per Vernaux, so the
    names after a File line belong to that file -- rebuilt here with a real
    line walk over the "Version needs" section only.
    """
    result = subprocess.run(
        [readelf, "-V", str(binary)], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr
    parts = result.stdout.split("Version needs section", 1)
    needs: list[dict[str, Any]] = []
    if len(parts) < 2:
        return needs
    for line in parts[1].splitlines():
        file_match = _READELF_VERNEED_FILE_RE.search(line)
        if file_match:
            needs.append({"file": file_match.group(1), "versions": []})
            continue
        name_match = _READELF_VERNEED_NAME_RE.search(line)
        if name_match and needs:
            needs[-1]["versions"].append(name_match.group(1))
    return needs


def _readelf_version_defs(readelf: str, binary: Path) -> list[dict[str, Any]]:
    """The Verdef chain as readelf -V decodes it, in the reader's fact shape.

    readelf renders each version node as a "... Flags: BASE ... Name: X" line
    (BASE marking the node that names the object), with any inherited parent on
    a following "Parent n: Y" line. Walked over the "Version definition
    section" only, so a version-needs or symbols section in the same output
    cannot leak into the result.
    """
    result = subprocess.run(
        [readelf, "-V", str(binary)], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr
    defs: list[dict[str, Any]] = []
    in_section = False
    for line in result.stdout.splitlines():
        if _READELF_SECTION_RE.match(line.strip()):
            in_section = "Version definition section" in line
            continue
        if not in_section:
            continue
        name_match = _READELF_VERDEF_NAME_RE.search(line)
        if name_match:
            defs.append(
                {
                    "name": name_match.group(2),
                    "base": name_match.group(1) == "BASE",
                    "parents": [],
                }
            )
            continue
        parent_match = _READELF_VERDEF_PARENT_RE.search(line)
        if parent_match and defs:
            defs[-1]["parents"].append(parent_match.group(1))
    return defs


def _readelf_dyn_symbols(readelf: str, binary: Path) -> tuple[set[str], set[str]]:
    """The (exported, imported) symbol names as readelf --dyn-syms decodes them.

    Splits the GLOBAL/WEAK rows the same way the reader does -- a decimal Ndx
    means defined here (an export), UND means the loader's to resolve (an
    import), and reserved indices (ABS and friends) are neither -- from
    readelf's independent walk of .dynsym, so the decoders can be compared name
    for name. -W keeps readelf from truncating long names; any @version suffix
    is dropped.
    """
    result = subprocess.run(
        [readelf, "-W", "--dyn-syms", str(binary)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    exports: set[str] = set()
    imports: set[str] = set()
    for line in result.stdout.splitlines():
        match = _READELF_DYNSYM_RE.match(line)
        if not match:
            continue
        bind, ndx, name = match.group(1), match.group(2), match.group(3)
        if bind not in ("GLOBAL", "WEAK") or not name:
            continue
        if ndx.isdigit():
            exports.add(name.split("@")[0])
        elif ndx == "UND":
            imports.add(name.split("@")[0])
    return exports, imports


def _readelf_fortified(readelf: str, binary: Path) -> set[str]:
    """The __*_chk fortified-wrapper imports readelf --dyn-syms shows as UND.

    The same set checksec's FORTIFY column counts: an undefined dynamic symbol
    named ``__<func>_chk``. The ``__`` prefix keeps a user symbol that merely
    ends in _chk out, matching the reader's rule.
    """
    result = subprocess.run(
        [readelf, "-W", "--dyn-syms", str(binary)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    fortified: set[str] = set()
    for line in result.stdout.splitlines():
        match = _READELF_DYNSYM_RE.match(line)
        if not match:
            continue
        ndx, name = match.group(2), match.group(3).split("@")[0]
        if ndx == "UND" and name.startswith("__") and name.endswith("_chk"):
            fortified.add(name)
    return fortified


def _readelf_weak_imports(readelf: str, binary: Path) -> set[str]:
    """The weakly bound undefined names readelf --dyn-syms marks WEAK ... UND.

    The same STB_WEAK + SHN_UNDEF intersection the reader's weak_imports fact
    is: a hard GLOBAL import is excluded, a weak *definition* (a real Ndx) is
    excluded, only the optional-and-unresolved subset remains.
    """
    result = subprocess.run(
        [readelf, "-W", "--dyn-syms", str(binary)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    weak: set[str] = set()
    for line in result.stdout.splitlines():
        match = _READELF_DYNSYM_RE.match(line)
        if not match:
            continue
        bind, ndx, name = match.group(1), match.group(2), match.group(3)
        if bind == "WEAK" and ndx == "UND" and name:
            weak.add(name.split("@")[0])
    return weak


def _session_native(service: AnalysisService, binary: Path) -> tuple[str, dict[str, Any]]:
    created = service.create_session(str(binary))
    assert created.ok, created.error
    session = created.data["session"]
    assert session["target"] == "native"
    return str(session["id"]), cast(dict[str, Any], session["metadata"]["native"])


@pytest.mark.integration
def test_elf_search_paths_agree_with_readelf(tmp_path: Path) -> None:
    gcc = shutil.which("gcc") or shutil.which("cc")
    if gcc is None:
        pytest.skip("no C compiler installed — toolchain gate not run (skip != pass)")
    readelf = shutil.which("readelf")
    if readelf is None:
        pytest.skip("readelf (binutils) not installed — toolchain gate not run (skip != pass)")

    # --disable-new-dtags asks the linker for the old tag, --enable-new-dtags
    # for the new one; together they cover both loader-precedence variants.
    rpath_bin = _compile_probe(
        gcc, tmp_path, "probe_rpath", f"-Wl,--disable-new-dtags,-rpath,{_SEARCH_PATH}"
    )
    runpath_bin = _compile_probe(
        gcc, tmp_path, "probe_runpath", f"-Wl,--enable-new-dtags,-rpath,{_SEARCH_PATH}"
    )

    service = AnalysisService()
    sessions: list[str] = []
    try:
        session_id, rpath_facts = _session_native(service, rpath_bin)
        sessions.append(session_id)
        session_id, runpath_facts = _session_native(service, runpath_bin)
        sessions.append(session_id)

        # The tool-free reader names the exact paths the link line requested.
        assert rpath_facts["rpath"] == _SEARCH_LIST
        assert "runpath" not in rpath_facts
        assert runpath_facts["runpath"] == _SEARCH_LIST
        assert "rpath" not in runpath_facts

        # readelf decodes the same dynamic table independently; both views of
        # both binaries must agree, including which tag is absent.
        assert _readelf_paths(readelf, rpath_bin) == (_SEARCH_LIST, None)
        assert _readelf_paths(readelf, runpath_bin) == (None, _SEARCH_LIST)

        # The freshly linked probes also exercise the rest of the dynamic-table
        # reading on real toolchain output rather than hand-built fixtures.
        for facts in (rpath_facts, runpath_facts):
            assert facts["linking"] == "dynamic"
            assert any(name.startswith("libc.so") for name in facts["needed"])
            assert facts["entry"] > 0
    finally:
        for session_id in sessions:
            service.close_session(session_id)


def _readelf_textrel(readelf: str, binary: Path) -> bool:
    """readelf -d's verdict: a (TEXTREL) tag row or TEXTREL in the (FLAGS) row."""
    result = subprocess.run(
        [readelf, "-d", str(binary)], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr
    for line in result.stdout.splitlines():
        if "(TEXTREL)" in line:
            return True
        if "(FLAGS)" in line and "TEXTREL" in line.split(")", 1)[1]:
            return True
    return False


@pytest.mark.integration
def test_elf_textrel_agrees_with_readelf(tmp_path: Path) -> None:
    gcc = shutil.which("gcc") or shutil.which("cc")
    if gcc is None:
        pytest.skip("no C compiler installed — textrel gate not run (skip != pass)")
    readelf = shutil.which("readelf")
    if readelf is None:
        pytest.skip("readelf (binutils) not installed — textrel gate not run (skip != pass)")

    # The real producer of text relocations: a non-PIC shared object embeds
    # absolute addresses in code the loader must patch in place, so the
    # linker -- told to allow it with -z notext -- records DT_TEXTREL and the
    # DF_TEXTREL flag. -mcmodel=large keeps gcc from folding the address into
    # a RIP-relative form the linker could resolve without a text reloc.
    source = tmp_path / "textrel.c"
    source.write_text("int shared_value = 7;\nlong grab(void) { return (long)&shared_value; }\n")
    dirty = tmp_path / "textrel.so"
    compile_result = subprocess.run(
        [
            gcc,
            "-fno-pic",
            "-mcmodel=large",
            "-shared",
            "-Wl,-z,notext",
            str(source),
            "-o",
            str(dirty),
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if compile_result.returncode != 0:
        pytest.skip(
            "toolchain refuses a non-PIC shared object — textrel gate not run (skip != pass)"
        )
    # A stock PIC link is the negative: no loader-visible write into text.
    clean = _compile_probe(gcc, tmp_path, "probe_textrel_clean")

    # readelf decodes the same dynamic table independently, and the positive
    # must be real on its side before the reader's verdict counts.
    assert _readelf_textrel(readelf, dirty) is True
    assert _readelf_textrel(readelf, clean) is False

    service = AnalysisService()
    sessions: list[str] = []
    try:
        session_id, dirty_facts = _session_native(service, dirty)
        sessions.append(session_id)
        session_id, clean_facts = _session_native(service, clean)
        sessions.append(session_id)
        assert dirty_facts["textrel"] is True
        assert clean_facts["textrel"] is False
    finally:
        for session_id in sessions:
            service.close_session(session_id)


@pytest.mark.integration
def test_elf_abi_tag_agrees_with_readelf(tmp_path: Path) -> None:
    gcc = shutil.which("gcc") or shutil.which("cc")
    if gcc is None:
        pytest.skip("no C compiler installed — ABI-tag gate not run (skip != pass)")
    readelf = shutil.which("readelf")
    if readelf is None:
        pytest.skip("readelf (binutils) not installed — ABI-tag gate not run (skip != pass)")

    # A plain link carries the GNU ABI-tag note every toolchain emits.
    probe = _compile_probe(gcc, tmp_path, "probe_abi")
    result = subprocess.run(
        [readelf, "-n", str(probe)], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr
    match = _READELF_ABI_RE.search(result.stdout)
    if match is None:
        pytest.skip("toolchain emitted no ABI-tag note — gate not run (skip != pass)")
    readelf_os = match.group(1).lower()
    readelf_kernel = match.group(2)

    service = AnalysisService()
    session_id = None
    try:
        session_id, native = _session_native(service, probe)
        # The tool-free ABI-tag walk and readelf -n decode the same note into
        # the same OS name and minimum kernel version.
        assert native["abi_os"] == readelf_os
        assert native["min_kernel"] == readelf_kernel
    finally:
        if session_id is not None:
            service.close_session(session_id)


# readelf -n renders the *_FEATURE_1_AND property as one "x86 feature: IBT,
# SHSTK" (or "AArch64 feature: BTI, PAC") line; other property types print
# differently ("x86 feature used:", "x86 ISA needed:"), so the bare "feature:"
# match is specific to the mask this gate checks.
_READELF_CF_FEATURE_RE = re.compile(r"\b(?:x86|AArch64) feature: ([^\n]+)")


def _readelf_cf_features(readelf: str, binary: Path) -> set[str]:
    """The branch-protection feature names readelf -n decodes, lowercased."""
    result = subprocess.run(
        [readelf, "-n", str(binary)], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr
    features: set[str] = set()
    for match in _READELF_CF_FEATURE_RE.finditer(result.stdout):
        features.update(part.strip().lower() for part in match.group(1).split(",") if part.strip())
    return features


@pytest.mark.integration
def test_elf_cf_protection_agrees_with_readelf(tmp_path: Path) -> None:
    """The cf_protection census against readelf -n over three real compiles.

    gcc -fcf-protection={full,branch,none} produces the three postures a
    triage must tell apart: IBT+SHSTK, IBT alone, and unprotected. The "none"
    build still carries a GNU property note (the ISA-needed entry), so the
    empty answer proves the reader walks the property array rather than
    keying on the note's mere presence.
    """
    gcc = shutil.which("gcc") or shutil.which("cc")
    if gcc is None:
        pytest.skip("no C compiler installed — cf-protection gate not run (skip != pass)")
    readelf = shutil.which("readelf")
    if readelf is None:
        pytest.skip("readelf (binutils) not installed — cf-protection gate not run (skip != pass)")

    source = tmp_path / "probe.c"
    source.write_text(_PROBE_C)
    probes: dict[str, Path] = {}
    for mode in ("full", "branch", "none"):
        out = tmp_path / f"probe_cf_{mode}"
        result = subprocess.run(
            [gcc, f"-fcf-protection={mode}", str(source), "-o", str(out)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            # Non-x86 toolchains reject the flag; the posture cannot be built.
            pytest.skip("gcc does not support -fcf-protection — gate not run (skip != pass)")
        probes[mode] = out

    service = AnalysisService()
    sessions: list[str] = []
    try:
        for mode, expected in (("full", {"ibt", "shstk"}), ("branch", {"ibt"}), ("none", set())):
            truth = _readelf_cf_features(readelf, probes[mode])
            # readelf really sees the posture the compile asked for -- the
            # referee is reading the note, not echoing the request.
            assert truth == expected, (mode, truth)
            session_id, native = _session_native(service, probes[mode])
            sessions.append(session_id)
            # The tool-free property walk and readelf -n name the same
            # features -- including the empty answer for the unprotected
            # build, whose note still carries an ISA-needed property.
            assert native["cf_protection"] == sorted(truth), mode
    finally:
        for session_id in sessions:
            service.close_session(session_id)


@pytest.mark.integration
def test_elf_version_needs_agree_with_readelf(tmp_path: Path) -> None:
    gcc = shutil.which("gcc") or shutil.which("cc")
    if gcc is None:
        pytest.skip("no C compiler installed — verneed gate not run (skip != pass)")
    readelf = shutil.which("readelf")
    if readelf is None:
        pytest.skip("readelf (binutils) not installed — verneed gate not run (skip != pass)")

    # A plain dynamic link imports versioned libc symbols, so the linker emits
    # the DT_VERNEED chain this gate cross-checks.
    probe = _compile_probe(gcc, tmp_path, "probe_verneed")
    ground_truth = _readelf_version_needs(readelf, probe)
    if not ground_truth:
        pytest.skip("toolchain emitted no version-needs chain — gate not run (skip != pass)")

    service = AnalysisService()
    session_id = None
    try:
        session_id, native = _session_native(service, probe)
        # The tool-free Verneed walk and readelf -V decode the same chain:
        # the same libraries in the same order, each demanding the same
        # version tags in the same order.
        assert native["version_needs"] == ground_truth
        # And the chain is the real thing: a freshly linked probe demands at
        # least one GLIBC_x.y tag out of libc.
        libc = next(
            (need for need in ground_truth if str(need["file"]).startswith("libc.so")), None
        )
        assert libc is not None, ground_truth
        assert libc["versions"], ground_truth
        assert all(str(tag).startswith("GLIBC_") for tag in libc["versions"])
    finally:
        if session_id is not None:
            service.close_session(session_id)


@pytest.mark.integration
def test_elf_version_defs_agree_with_readelf(tmp_path: Path) -> None:
    gcc = shutil.which("gcc") or shutil.which("cc")
    if gcc is None:
        pytest.skip("no C compiler installed — verdef gate not run (skip != pass)")
    readelf = shutil.which("readelf")
    if readelf is None:
        pytest.skip("readelf (binutils) not installed — verdef gate not run (skip != pass)")

    # A shared library linked with a version script provides the DT_VERDEF
    # chain this gate cross-checks -- the export side of the versioned-symbol
    # story the verneed gate covers for imports.
    source = tmp_path / "lib.c"
    source.write_text(_LIB_C)
    script = tmp_path / "version.map"
    script.write_text(_VERSION_SCRIPT)
    lib = tmp_path / "libprobe.so"
    result = subprocess.run(
        [
            gcc, "-shared", "-fPIC", "-o", str(lib), str(source),
            f"-Wl,--version-script={script}", f"-Wl,-soname,{_LIB_SONAME}",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    ground_truth = _readelf_version_defs(readelf, lib)
    if not ground_truth:
        pytest.skip("toolchain emitted no version-defs chain — gate not run (skip != pass)")

    service = AnalysisService()
    session_id = None
    try:
        session_id, native = _session_native(service, lib)
        # The tool-free Verdef walk and readelf -V decode the same chain: the
        # same nodes in the same order, each with the same BASE flag and the
        # same inherited parents.
        assert native["version_defs"] == ground_truth
        # And it is the real thing the version script asked for: a BASE node
        # naming the library (its soname) plus the two script nodes, the
        # second inheriting the first.
        assert native["version_defs"] == [
            {"name": _LIB_SONAME, "base": True, "parents": []},
            {"name": "PROBE_1.0", "base": False, "parents": []},
            {"name": "PROBE_2.0", "base": False, "parents": ["PROBE_1.0"]},
        ]
        # The BASE node names the object itself -- the same string DT_SONAME
        # reports -- so the two provider-side facts agree.
        assert native["soname"] == _LIB_SONAME
    finally:
        if session_id is not None:
            service.close_session(session_id)


@pytest.mark.integration
def test_elf_exported_symbols_agree_with_readelf(tmp_path: Path) -> None:
    gcc = shutil.which("gcc") or shutil.which("cc")
    if gcc is None:
        pytest.skip("no C compiler installed — exports gate not run (skip != pass)")
    readelf = shutil.which("readelf")
    if readelf is None:
        pytest.skip("readelf (binutils) not installed — exports gate not run (skip != pass)")

    # A plain shared library (no version script) exports its default-visibility
    # globals through .dynsym -- the export surface this gate cross-checks.
    source = tmp_path / "exports.c"
    source.write_text(_EXPORTS_C)
    lib = tmp_path / "libexports.so"
    result = subprocess.run(
        [gcc, "-shared", "-fPIC", "-O2", "-o", str(lib), str(source)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    truth_exports, truth_imports = _readelf_dyn_symbols(readelf, lib)
    assert truth_exports >= _KNOWN_EXPORTS, truth_exports
    assert truth_imports >= _KNOWN_IMPORTS, truth_imports

    service = AnalysisService()
    session_id = None
    try:
        session_id, native = _session_native(service, lib)
        reader_exports = set(native["exported_symbols"])
        reader_imports = set(native["imported_symbols"])
        # The tool-free .dynsym walk and readelf --dyn-syms make the exact same
        # split -- including whatever globals the toolchain injected on either
        # side, since both apply the one rule to the one table.
        assert reader_exports == truth_exports
        assert reader_imports == truth_imports
        # And the library's own API is really in there (static helper excluded),
        # with its libc call on the import side.
        assert reader_exports >= _KNOWN_EXPORTS
        assert "helper" not in reader_exports
        assert reader_imports >= _KNOWN_IMPORTS
    finally:
        if session_id is not None:
            service.close_session(session_id)


@pytest.mark.integration
def test_elf_fortify_source_agrees_with_readelf(tmp_path: Path) -> None:
    """The FORTIFY posture against readelf, at -D_FORTIFY_SOURCE=2 and =0.

    The fortified build routes its bounded string calls through __*_chk
    wrappers; the plain build imports the ordinary functions. The reader's
    fortify_source / fortified_functions must match readelf's __*_chk set in
    each -- non-empty and True for the fortified library, empty and False for
    the plain one, so the gate proves both directions on real toolchain output.
    """
    gcc = shutil.which("gcc") or shutil.which("cc")
    if gcc is None:
        pytest.skip("no C compiler installed — fortify gate not run (skip != pass)")
    readelf = shutil.which("readelf")
    if readelf is None:
        pytest.skip("readelf (binutils) not installed — fortify gate not run (skip != pass)")

    source = tmp_path / "fortify.c"
    source.write_text(_FORTIFY_C)

    def build(level: int, name: str) -> Path:
        out = tmp_path / name
        result = subprocess.run(
            # -O2 is required for glibc to expand the calls into _chk wrappers.
            [
                gcc, "-O2", f"-D_FORTIFY_SOURCE={level}", "-shared", "-fPIC",
                "-o", str(out), str(source),
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, result.stderr
        return out

    fortified_lib = build(2, "libfort2.so")
    plain_lib = build(0, "libfort0.so")

    truth_fortified = _readelf_fortified(readelf, fortified_lib)
    truth_plain = _readelf_fortified(readelf, plain_lib)
    # The fortified build really pulls in wrappers and the plain one really
    # does not, so readelf is a genuine second opinion in both directions.
    assert truth_fortified, "fortified build imported no __*_chk wrappers"
    assert truth_plain == set()

    service = AnalysisService()
    sessions: list[str] = []
    try:
        session_id, fortified_facts = _session_native(service, fortified_lib)
        sessions.append(session_id)
        # The tool-free import walk and readelf name the same wrapper set, and
        # the reader flags the posture on.
        assert set(fortified_facts["fortified_functions"]) == truth_fortified
        assert fortified_facts["fortify_source"] is True
        # And the wrappers really are in there (strcpy is the reliable one;
        # the optimiser may fold the others).
        assert "__strcpy_chk" in fortified_facts["fortified_functions"]

        session_id, plain_facts = _session_native(service, plain_lib)
        sessions.append(session_id)
        # The plain build reads a definitive negative, not a missing fact.
        assert plain_facts["fortify_source"] is False
        assert plain_facts["fortified_functions"] == []
    finally:
        for session_id in sessions:
            service.close_session(session_id)


@pytest.mark.integration
def test_elf_weak_imports_agree_with_readelf(tmp_path: Path) -> None:
    """The weak-import subset against readelf --dyn-syms.

    A library that probes for an optional symbol before calling it carries the
    weak undefined .dynsym entry readelf marks "WEAK ... UND" -- optional
    capability, the ELF pair to a Mach-O weak dylib. The reader's weak_imports
    must match readelf's WEAK+UND set name for name, stay a subset of
    imported_symbols, and leave the hard libc import out of the weak list.
    """
    gcc = shutil.which("gcc") or shutil.which("cc")
    if gcc is None:
        pytest.skip("no C compiler installed — weak-import gate not run (skip != pass)")
    readelf = shutil.which("readelf")
    if readelf is None:
        pytest.skip("readelf (binutils) not installed — weak-import gate not run (skip != pass)")

    source = tmp_path / "weak.c"
    source.write_text(_WEAK_C)
    lib = tmp_path / "libweak.so"
    result = subprocess.run(
        [gcc, "-shared", "-fPIC", "-O2", "-o", str(lib), str(source)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr

    truth_weak = _readelf_weak_imports(readelf, lib)
    _truth_exports, truth_imports = _readelf_dyn_symbols(readelf, lib)
    # readelf really sees the planted weak extern and a hard libc import, so
    # it is a genuine second opinion.
    assert "optional_probe" in truth_weak
    assert "puts" in truth_imports and "puts" not in truth_weak

    service = AnalysisService()
    session_id = None
    try:
        session_id, native = _session_native(service, lib)
        reader_weak = set(native["weak_imports"])
        reader_imports = set(native["imported_symbols"])
        # The tool-free .dynsym walk and readelf select the same weak subset,
        # whatever CRT weak stubs (__gmon_start__ and friends) the toolchain
        # injected, since both apply the one WEAK+UND rule to the one table.
        assert reader_weak == truth_weak
        # The subset really is a subset, and the hard import stays out of it.
        assert reader_weak <= reader_imports
        assert "optional_probe" in reader_weak
        assert "puts" in reader_imports
        assert "puts" not in reader_weak
    finally:
        if session_id is not None:
            service.close_session(session_id)


@pytest.mark.integration
def test_elf_init_funcs_agree_with_readelf(tmp_path: Path) -> None:
    gcc = shutil.which("gcc") or shutil.which("cc")
    if gcc is None:
        pytest.skip("no C compiler installed — init gate not run (skip != pass)")
    readelf = shutil.which("readelf")
    if readelf is None:
        pytest.skip("readelf (binutils) not installed — init gate not run (skip != pass)")

    # A shared library with two real __attribute__((constructor)) functions
    # and one destructor -- the load-time code surface this gate cross-checks.
    source = tmp_path / "ctors.c"
    source.write_text(_CTORS_C)
    lib = tmp_path / "libctors.so"
    result = subprocess.run(
        [gcc, "-shared", "-fPIC", "-O2", "-o", str(lib), str(source)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr

    dynamic = subprocess.run(
        [readelf, "-d", str(lib)], capture_output=True, text=True, timeout=60
    )
    assert dynamic.returncode == 0, dynamic.stderr

    def truth_count(pattern: re.Pattern[str]) -> int:
        match = pattern.search(dynamic.stdout)
        # A 64-bit image's init/fini arrays hold 8-byte function pointers, so
        # readelf's byte size over 8 is the entry count -- the same derivation
        # the reader makes from the same ARRAYSZ tags.
        return int(match.group(1)) // 8 if match else 0

    service = AnalysisService()
    session_id = None
    try:
        session_id, native = _session_native(service, lib)
        init_funcs = native["init_funcs"]
        # The tool-free walk and readelf -d decode the same dynamic table:
        # legacy INIT/FINI presence and every array count, tag for tag.
        assert init_funcs["has_init"] is ("(INIT)" in dynamic.stdout)
        assert init_funcs["has_fini"] is ("(FINI)" in dynamic.stdout)
        assert init_funcs["init_array"] == truth_count(_READELF_INIT_SZ_RE)
        assert init_funcs["fini_array"] == truth_count(_READELF_FINI_SZ_RE)
        assert init_funcs["preinit_array"] == truth_count(_READELF_PREINIT_SZ_RE)
        # And the two constructors and the destructor the source declared are
        # really in there, whatever the CRT added on top.
        assert init_funcs["init_array"] >= 2
        assert init_funcs["fini_array"] >= 1
    finally:
        if session_id is not None:
            service.close_session(session_id)


@pytest.mark.integration
def test_macho_rpath_agrees_with_llvm_objdump() -> None:
    objdump = shutil.which("llvm-objdump")
    if objdump is None:
        pytest.skip("llvm-objdump not installed — Mach-O rpath gate not run (skip != pass)")
    if not _MACHO_FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_MACHO_FIXTURE}")

    # llvm-objdump validates every load command before it prints anything (it
    # is what caught the fixture's earlier 4-byte-aligned commands), so a zero
    # exit is itself a well-formedness check on the committed image.
    result = subprocess.run(
        [objdump, "--macho", "--rpaths", str(_MACHO_FIXTURE)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    # Output is the file name line, then one search path per line.
    llvm_rpaths = [
        line.strip()
        for line in result.stdout.splitlines()
        if line.strip() and not line.strip().endswith(":")
    ]
    assert llvm_rpaths, result.stdout

    service = AnalysisService()
    session_id = None
    try:
        session_id, native = _session_native(service, _MACHO_FIXTURE)
        # The tool-free LC_RPATH walk and LLVM's decoder name the same paths,
        # verbatim (no @loader_path expansion) and in the same order.
        assert native["rpath"] == llvm_rpaths == ["@loader_path/../Frameworks"]
    finally:
        if session_id is not None:
            service.close_session(session_id)


@pytest.mark.integration
def test_macho_dylib_versions_agree_with_llvm_objdump() -> None:
    """Each dependency's version contract, verbatim against LLVM's decode.

    dylib_command carries the current/compatibility pair the image was linked
    against -- the Mach-O pair to ELF version_needs. llvm-objdump
    --dylibs-used decodes and renders the same pair per dependency, so the
    reader's strings must match name for name, field for field.
    """
    objdump = shutil.which("llvm-objdump")
    if objdump is None:
        pytest.skip("llvm-objdump not installed — dylib-version gate not run (skip != pass)")
    if not _MACHO_FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_MACHO_FIXTURE}")

    result = subprocess.run(
        [objdump, "--macho", "--dylibs-used", str(_MACHO_FIXTURE)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    # One line per dependency: "\t<name> (compatibility version X, current version Y)".
    printed = {
        match.group(1): {"compat": match.group(2), "current": match.group(3)}
        for match in re.finditer(
            r"^\s*(\S+) \(compatibility version (\S+), current version (\S+)\)",
            result.stdout,
            re.M,
        )
    }
    assert printed, result.stdout

    service = AnalysisService()
    session_id = None
    try:
        session_id, native = _session_native(service, _MACHO_FIXTURE)
        assert native["dylib_versions"] == printed
        assert printed["/usr/lib/libSystem.B.dylib"] == {"compat": "1.0.0", "current": "1.0.0"}
    finally:
        if session_id is not None:
            service.close_session(session_id)


@pytest.mark.integration
def test_macho_source_version_agrees_with_llvm_objdump(tmp_path: Path) -> None:
    """The self-declared source stamp, refereed by LLVM's strict decoder.

    The committed fixture carries no LC_SOURCE_VERSION (absence must read
    absent), so the positive case appends one into a copy -- the fixture's
    load-command region has headroom before the first section's bytes -- and
    llvm-objdump both revalidates the patched image (it rejects malformed
    commands outright) and prints the stamp the reader must reproduce,
    including the drop-trailing-zeros-to-three-fields rendering.
    """
    objdump = shutil.which("llvm-objdump")
    if objdump is None:
        pytest.skip("llvm-objdump not installed — source-version gate not run (skip != pass)")
    if not _MACHO_FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_MACHO_FIXTURE}")

    raw = bytearray(_MACHO_FIXTURE.read_bytes())
    ncmds, sizeofcmds = struct.unpack_from("<II", raw, 16)
    stamp = (61040 << 40) | (5 << 30) | (17 << 20)  # 61040.5.17: d and e drop off
    struct.pack_into("<IIQ", raw, 32 + sizeofcmds, 0x2A, 16, stamp)
    struct.pack_into("<II", raw, 16, ncmds + 1, sizeofcmds + 16)
    stamped = tmp_path / "stamped.macho"
    stamped.write_bytes(raw)

    result = subprocess.run(
        [objdump, "--macho", "--private-headers", str(stamped)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr  # LLVM accepted the patched image
    match = re.search(r"cmd LC_SOURCE_VERSION\n\s*cmdsize \d+\n\s*version (\S+)", result.stdout)
    assert match, result.stdout

    service = AnalysisService()
    session_id = None
    try:
        session_id, native = _session_native(service, stamped)
        assert native["source_version"] == match.group(1) == "61040.5.17"
        service.close_session(session_id)
        # The unpatched fixture: no command, no stamp -- on either side.
        session_id, plain = _session_native(service, _MACHO_FIXTURE)
        assert "source_version" not in plain
    finally:
        if session_id is not None:
            service.close_session(session_id)


@pytest.mark.integration
def test_macho_build_version_agrees_with_llvm_objdump() -> None:
    objdump = shutil.which("llvm-objdump")
    if objdump is None:
        pytest.skip("llvm-objdump not installed — Mach-O platform gate not run (skip != pass)")
    if not _MACHO_FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_MACHO_FIXTURE}")

    result = subprocess.run(
        [objdump, "--macho", "--all-headers", str(_MACHO_FIXTURE)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    match = _LLVM_BUILD_VERSION_RE.search(result.stdout)
    assert match, result.stdout
    llvm_platform, llvm_sdk, llvm_minos = match.groups()

    service = AnalysisService()
    session_id = None
    try:
        session_id, native = _session_native(service, _MACHO_FIXTURE)
        # The tool-free LC_BUILD_VERSION walk and LLVM's decoder answer the
        # Apple-binary identity questions with the same strings.
        assert native["platform"] == llvm_platform == "macos"
        assert native["min_os"] == llvm_minos == "13.0"
        assert native["sdk"] == llvm_sdk == "14.2"
    finally:
        if session_id is not None:
            service.close_session(session_id)


@pytest.mark.integration
def test_elf_comment_toolchain_agrees_with_readelf(tmp_path: Path) -> None:
    gcc = shutil.which("gcc") or shutil.which("cc")
    readelf = shutil.which("readelf")
    if gcc is None:
        pytest.skip("gcc not installed — ELF toolchain gate not run (skip != pass)")
    if readelf is None:
        pytest.skip("readelf not installed — ELF toolchain gate not run (skip != pass)")

    # A real compiler's .comment: GCC records itself at every compile, so the
    # probe carries at least one provenance string neither side invented.
    probe = _compile_probe(gcc, tmp_path, "probe.bin")
    result = subprocess.run(
        [readelf, "-p", ".comment", str(probe)], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr
    readelf_records: list[str] = []
    for match in _READELF_COMMENT_RE.finditer(result.stdout):
        text = match.group(1).strip()
        if text and text not in readelf_records:
            readelf_records.append(text)
    assert readelf_records, result.stdout

    service = AnalysisService()
    session_id = None
    try:
        session_id, native = _session_native(service, probe)
        # The tool-free .comment read and readelf print the same compiler
        # records, string for string and in section order.
        assert native["toolchain"] == readelf_records
    finally:
        if session_id is not None:
            service.close_session(session_id)


def _macho_with_build_tools() -> bytes:
    """A minimal 64-bit Mach-O whose LC_BUILD_VERSION carries two tool entries.

    Built here independently of the reader's unit builder: one arm64 header and
    one load command claiming macOS 14.0 / SDK 14.5, ld 1053.12 and clang 15.0.
    llvm-objdump's strict decode doubles as the well-formedness check.
    """
    command = struct.pack(
        "<IIIIII",
        0x32,  # LC_BUILD_VERSION
        40,
        1,  # PLATFORM_MACOS
        14 << 16,  # minos 14.0
        (14 << 16) | (5 << 8),  # sdk 14.5
        2,  # ntools
    )
    command += struct.pack("<II", 3, (1053 << 16) | (12 << 8))  # TOOL_LD 1053.12
    command += struct.pack("<II", 1, 15 << 16)  # TOOL_CLANG 15.0
    header = struct.pack(
        "<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, len(command), 0, 0
    )
    return header + command


@pytest.mark.integration
def test_macho_build_tools_agree_with_llvm_objdump(tmp_path: Path) -> None:
    objdump = shutil.which("llvm-objdump")
    if objdump is None:
        pytest.skip("llvm-objdump not installed — Mach-O tool gate not run (skip != pass)")

    binary = tmp_path / "tools.macho"
    binary.write_bytes(_macho_with_build_tools())
    result = subprocess.run(
        [objdump, "--macho", "--all-headers", str(binary)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    # llvm-objdump validates every load command before printing, so a zero
    # exit is itself a well-formedness check on the synthetic image.
    assert result.returncode == 0, result.stderr
    llvm_tools = [
        {"tool": tool, "version": version}
        for tool, version in _LLVM_TOOL_RE.findall(result.stdout)
    ]
    # LLVM must see the planted rows, so it is a genuine second opinion.
    assert llvm_tools == [
        {"tool": "ld", "version": "1053.12"},
        {"tool": "clang", "version": "15.0"},
    ]

    service = AnalysisService()
    session_id = None
    try:
        session_id, native = _session_native(service, binary)
        # The tool-free ntools walk and LLVM's decoder name the same
        # toolchain, tool for tool and version for version.
        assert native["build_tools"] == llvm_tools
    finally:
        if session_id is not None:
            service.close_session(session_id)


def _macho_dylib_command(cmd_kind: int, name: str) -> bytes:
    """One dylib_command: cmd/cmdsize, lc_str offset 24, then the padded name."""
    raw = name.encode() + b"\x00"
    total = (24 + len(raw) + 7) & ~7  # 8-align, the width llvm-objdump enforces
    body = struct.pack("<IIIIII", cmd_kind, total, 24, 0, 0x10000, 0x10000)
    return body + raw.ljust(total - 24, b"\x00")


def _macho_with_dylib_classes(plain: str, weak: str, fronted: str) -> bytes:
    """A minimal MH_DYLIB carrying one dylib command of each dependency class.

    Built here independently of the reader's unit builder: LC_ID_DYLIB first
    (llvm-objdump rejects a dylib without one), then a plain LC_LOAD_DYLIB, a
    weak and a reexported dependency. LLVM's strict decode doubles as the
    well-formedness check on the synthetic image.
    """
    commands = (
        _macho_dylib_command(0x0D, "/usr/lib/libprobe.dylib")  # LC_ID_DYLIB
        + _macho_dylib_command(0x0C, plain)  # LC_LOAD_DYLIB
        + _macho_dylib_command(0x80000018, weak)  # LC_LOAD_WEAK_DYLIB
        + _macho_dylib_command(0x8000001F, fronted)  # LC_REEXPORT_DYLIB
    )
    header = struct.pack(
        "<IIIIIIII", 0xFEEDFACF, 0x01000007, 3, 6, 4, len(commands), 0x4, 0
    )  # x86_64 MH_DYLIB, MH_DYLDLINK
    return header + commands


# llvm-objdump --macho --all-headers prints each dylib command as a "cmd
# LC_LOAD_DYLIB" line followed by "name /usr/lib/x.dylib (offset 24)".
_LLVM_DYLIB_NAME_RE = re.compile(r"^\s*name (\S+) \(offset \d+\)$")


def _llvm_dylib_classes(objdump: str, binary: Path, *extra: str) -> dict[str, list[str]]:
    """``{command kind: [names]}`` as llvm-objdump decodes the load commands."""
    result = subprocess.run(
        [objdump, "--macho", "--all-headers", *extra, str(binary)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    classes: dict[str, list[str]] = {}
    current = ""
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] == "cmd":
            current = parts[1]
            continue
        match = _LLVM_DYLIB_NAME_RE.match(line)
        if match and current.endswith("_DYLIB"):
            classes.setdefault(current, []).append(match.group(1))
    return classes


@pytest.mark.integration
def test_macho_dylib_classes_agree_with_llvm_objdump(tmp_path: Path) -> None:
    """The weak/reexport split against LLVM's decode of the same commands.

    All three names must land in ``dylibs`` in command order, with exactly
    the weak one in ``weak_dylibs`` and the fronted one in
    ``reexported_dylibs`` -- the same classes llvm-objdump prints, and the
    committed fixture (plain dependencies only) must read empty subsets in
    both views.
    """
    objdump = shutil.which("llvm-objdump")
    if objdump is None:
        pytest.skip("llvm-objdump not installed — dylib-class gate not run (skip != pass)")

    plain = "/usr/lib/libSystem.B.dylib"
    weak = "/usr/lib/swift/libswiftCore.dylib"
    fronted = "/usr/lib/libcore_real.dylib"
    binary = tmp_path / "classes.dylib"
    binary.write_bytes(_macho_with_dylib_classes(plain, weak, fronted))

    truth = _llvm_dylib_classes(objdump, binary)
    # LLVM really sees one command of each class, so it is a genuine referee.
    assert truth["LC_LOAD_DYLIB"] == [plain]
    assert truth["LC_LOAD_WEAK_DYLIB"] == [weak]
    assert truth["LC_REEXPORT_DYLIB"] == [fronted]

    service = AnalysisService()
    sessions: list[str] = []
    try:
        session_id, native = _session_native(service, binary)
        sessions.append(session_id)
        assert native["dylibs"] == [plain, weak, fronted]
        assert native["weak_dylibs"] == truth["LC_LOAD_WEAK_DYLIB"]
        assert native["reexported_dylibs"] == truth["LC_REEXPORT_DYLIB"]
        # And the dylib's own name stayed out of the dependency list.
        assert native["install_name"] == "/usr/lib/libprobe.dylib"

        if _MACHO_FIXTURE.is_file():
            fixture_truth = _llvm_dylib_classes(objdump, _MACHO_FIXTURE)
            assert "LC_LOAD_WEAK_DYLIB" not in fixture_truth
            assert "LC_REEXPORT_DYLIB" not in fixture_truth
            session_id, fixture_facts = _session_native(service, _MACHO_FIXTURE)
            sessions.append(session_id)
            assert fixture_facts["dylibs"] == fixture_truth.get("LC_LOAD_DYLIB", [])
            assert fixture_facts["weak_dylibs"] == []
            assert fixture_facts["reexported_dylibs"] == []
    finally:
        for session_id in sessions:
            service.close_session(session_id)


def _universal_thin(cputype: int, cpusubtype: int, flags: int, commands: bytes = b"") -> bytes:
    """One MH_EXECUTE slice for lipo: a mach_header_64 plus its load commands."""
    ncmds = 1 if commands else 0
    header = struct.pack(
        "<IIIIIIII", 0xFEEDFACF, cputype, cpusubtype, 2, ncmds, len(commands), flags, 0
    )
    return header + commands


@pytest.mark.integration
def test_universal_binary_slices_agree_with_llvm_lipo_and_objdump(tmp_path: Path) -> None:
    """Per-slice facts of a real lipo-built universal binary against LLVM.

    macOS ships x86_64+arm64 universal binaries as the norm, and each slice
    is a complete thin Mach-O whose facts can genuinely differ -- so the
    session must describe every slice in full, not just list architectures.
    The universal container here is assembled by llvm-lipo itself (which
    page-aligns the slices to nonzero offsets and rejects malformed thin
    input, doubling as the well-formedness check), llvm-lipo -archs referees
    the arch census, and llvm-objdump's per-arch load-command decode referees
    that the x86-64 slice's dylib list was read from the right offset.
    """
    lipo = shutil.which("llvm-lipo") or shutil.which("llvm-lipo-18")
    if lipo is None:
        pytest.skip("llvm-lipo not installed — universal-binary gate not run (skip != pass)")
    objdump = shutil.which("llvm-objdump")
    if objdump is None:
        pytest.skip("llvm-objdump not installed — universal-binary gate not run (skip != pass)")

    # Two deliberately different slices: a dynamic PIE x86-64 executable with
    # one dependency, and a static arm64 image with none.
    dylib = "/usr/lib/libSystem.B.dylib"
    x86 = tmp_path / "thin_x86.macho"
    x86.write_bytes(
        _universal_thin(
            0x01000007,  # CPU_TYPE_X86_64
            3,  # CPU_SUBTYPE_X86_64_ALL
            0x00200000 | 0x4,  # MH_PIE | MH_DYLDLINK
            _macho_dylib_command(0x0C, dylib),
        )
    )
    arm = tmp_path / "thin_arm.macho"
    arm.write_bytes(_universal_thin(0x0100000C, 0, 0))  # CPU_TYPE_ARM64, static
    universal = tmp_path / "universal.macho"
    result = subprocess.run(
        [lipo, "-create", str(x86), str(arm), "-output", str(universal)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr

    # Referee 1: lipo's own arch census of the container it just built.
    archs = subprocess.run(
        [lipo, "-archs", str(universal)], capture_output=True, text=True, timeout=60
    )
    assert archs.returncode == 0, archs.stderr
    assert archs.stdout.split() == ["x86_64", "arm64"]

    # Referee 2: LLVM's per-arch decode of the x86-64 slice's load commands,
    # which can only agree if the reader pulled the slice from lipo's real
    # (page-aligned, nonzero) offset rather than the start of the file.
    truth = _llvm_dylib_classes(objdump, universal, "--arch=x86_64")
    assert truth["LC_LOAD_DYLIB"] == [dylib]

    service = AnalysisService()
    session_id: str | None = None
    try:
        session_id, native = _session_native(service, universal)
        assert native["format"] == "macho-universal"
        assert native["slice_count"] == 2
        assert native["architectures"] == ["x86-64", "arm64"]
        first, second = native["slices"]
        assert first["arch"] == "x86-64"
        assert first["pie"] is True
        assert first["linking"] == "dynamic"
        assert first["dylibs"] == truth["LC_LOAD_DYLIB"]
        assert second["arch"] == "arm64"
        assert second["pie"] is False
        assert second["linking"] == "static"
    finally:
        if session_id is not None:
            service.close_session(session_id)


def _llvm_nm_names(nm: str, binary: Path, *selectors: str) -> set[str]:
    """The symbol names llvm-nm prints under the given selection flags.

    One "<addr> <type> <name>" per line (the address column is blank for
    undefined symbols); the name is always the last field.
    """
    result = subprocess.run(
        [nm, *selectors, str(binary)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    return {
        line.split()[-1]
        for line in result.stdout.splitlines()
        if line.strip() and not line.rstrip().endswith(":")
    }


def _macho_with_undefined_symbols(names: list[str]) -> bytes:
    """A 64-bit MH_EXECUTE whose LC_SYMTAB holds the given undefined externals.

    Built here independently of the reader's unit builder: each name becomes an
    N_EXT|N_UNDF nlist entry (n_sect 0, n_value 0), the shape dyld resolves at
    load. llvm-nm's decode doubles as the well-formedness check, so a zero exit
    certifies the synthetic image, not just the reader's read of it.
    """
    strtab = bytearray(b"\x00")
    nlists = bytearray()
    for name in names:
        strx = len(strtab)
        strtab += name.encode() + b"\x00"
        nlists += struct.pack("<IBBHQ", strx, 0x01, 0, 0, 0)  # n_type N_EXT|N_UNDF
    symoff = 32 + 24  # header + one LC_SYMTAB command
    stroff = symoff + len(nlists)
    command = struct.pack("<IIIIII", 0x02, 24, symoff, len(names), stroff, len(strtab))
    header = struct.pack(
        "<IIIIIIII", 0xFEEDFACF, 0x01000007, 0, 2, 1, len(command), 0, 0
    )  # x86_64 MH_EXECUTE
    return header + command + bytes(nlists) + bytes(strtab)


@pytest.mark.integration
def test_macho_fortify_source_agrees_with_llvm_nm(tmp_path: Path) -> None:
    """The Mach-O FORTIFY posture against llvm-nm, both directions.

    A synthetic image importing ___strcpy_chk / ___memcpy_chk (the mangled
    fortified wrappers) alongside a plain _printf must read fortify_source
    True with exactly the two wrappers, matching the __*_chk subset of
    llvm-nm's undefined externs; the committed fixture (canaried, its imports
    end in _fail/_guard) must read a definitive False in both views.
    """
    nm = shutil.which("llvm-nm")
    if nm is None:
        pytest.skip("llvm-nm not installed — Mach-O fortify gate not run (skip != pass)")

    binary = tmp_path / "fortify.macho"
    binary.write_bytes(
        _macho_with_undefined_symbols(["___strcpy_chk", "___memcpy_chk", "_printf"])
    )
    llvm_imports = _llvm_nm_names(nm, binary, "--undefined-only", "--extern-only")
    truth_fortified = {
        name for name in llvm_imports if name.startswith("__") and name.endswith("_chk")
    }
    # llvm-nm really sees the two wrappers (and only those), so it is a genuine
    # second opinion on the synthetic image.
    assert truth_fortified == {"___strcpy_chk", "___memcpy_chk"}

    service = AnalysisService()
    sessions: list[str] = []
    try:
        session_id, native = _session_native(service, binary)
        sessions.append(session_id)
        assert native["fortify_source"] is True
        assert set(native["fortified_functions"]) == truth_fortified

        # Negative agreement on the real fixture: its imports are the canary
        # pair, which end in _fail/_guard, so no fortify in either view.
        if _MACHO_FIXTURE.is_file():
            fixture_imports = _llvm_nm_names(
                nm, _MACHO_FIXTURE, "--undefined-only", "--extern-only"
            )
            assert not {
                n for n in fixture_imports if n.startswith("__") and n.endswith("_chk")
            }
            session_id, fixture_facts = _session_native(service, _MACHO_FIXTURE)
            sessions.append(session_id)
            assert fixture_facts["fortify_source"] is False
            assert fixture_facts["fortified_functions"] == []
    finally:
        for session_id in sessions:
            service.close_session(session_id)


@pytest.mark.integration
def test_macho_symbol_surface_agrees_with_llvm_nm() -> None:
    nm = shutil.which("llvm-nm")
    if nm is None:
        pytest.skip("llvm-nm not installed — Mach-O symbol gate not run (skip != pass)")
    if not _MACHO_FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_MACHO_FIXTURE}")

    # llvm-nm --defined-only --extern-only lists exactly the exported symbols
    # (defined here, externally visible) and --undefined-only --extern-only the
    # imports dyld must resolve; GNU nm cannot read Mach-O at all, so llvm's is
    # the independent decoder.
    llvm_exports = _llvm_nm_names(nm, _MACHO_FIXTURE, "--defined-only", "--extern-only")
    llvm_imports = _llvm_nm_names(nm, _MACHO_FIXTURE, "--undefined-only", "--extern-only")
    assert llvm_exports and llvm_imports

    service = AnalysisService()
    session_id = None
    try:
        session_id, native = _session_native(service, _MACHO_FIXTURE)
        # The tool-free LC_SYMTAB walk and llvm-nm make the same split, name
        # for name: the one function the fixture defines on the export side,
        # its stack_chk pair on the import side.
        assert set(native["exported_symbols"]) == llvm_exports == {"_main"}
        expected_imports = {"___stack_chk_fail", "___stack_chk_guard"}
        assert set(native["imported_symbols"]) == llvm_imports == expected_imports
    finally:
        if session_id is not None:
            service.close_session(session_id)


@pytest.mark.integration
def test_macho_init_surface_agrees_with_llvm_objdump() -> None:
    objdump = shutil.which("llvm-objdump")
    if objdump is None:
        pytest.skip("llvm-objdump not installed — Mach-O init gate not run (skip != pass)")
    if not _MACHO_FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_MACHO_FIXTURE}")

    # Re-derive the constructor surface from LLVM's independent section
    # decode: the typed sections' sizes over their entry widths, the same
    # arithmetic the reader applies to the same headers.
    sections = _llvm_macho_sections(objdump, _MACHO_FIXTURE)
    assert sections, "llvm-objdump printed no sections"
    truth_init = truth_term = 0
    for sect in sections:
        if sect.get("type") == "S_MOD_INIT_FUNC_POINTERS":
            truth_init += sect["size"] // 8
        elif sect.get("type") == "S_MOD_TERM_FUNC_POINTERS":
            truth_term += sect["size"] // 8
        elif sect.get("type") == "S_INIT_FUNC_OFFSETS":
            truth_init += sect["size"] // 4

    service = AnalysisService()
    session_id = None
    try:
        session_id, native = _session_native(service, _MACHO_FIXTURE)
        # The tool-free section walk and llvm-objdump count the same load-time
        # surface: the fixture's one constructor and one destructor pointer.
        assert native["init_funcs"] == {"mod_init": truth_init, "mod_term": truth_term}
        assert native["init_funcs"] == {"mod_init": 1, "mod_term": 1}
    finally:
        if session_id is not None:
            service.close_session(session_id)


# readelf -h: "Start of section headers: 14032 (bytes into file)" and the
# section-header count/size lines that place the table's end.
_READELF_SHOFF_RE = re.compile(r"Start of section headers:\s+(\d+)")
_READELF_SHNUM_RE = re.compile(r"Number of section headers:\s+(\d+)")
_READELF_SHENTSIZE_RE = re.compile(r"Size of section headers:\s+(\d+)")
# readelf -S -W rows: "[ 1] .interp PROGBITS 00...0002a8 0002a8 00001c ..." --
# name, type, address, then the file offset and size columns this parse needs.
_READELF_SH_ROW_RE = re.compile(
    r"^\s*\[\s*\d+\]\s+\S+\s+(\S+)\s+[0-9a-fA-F]+\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)",
    re.MULTILINE,
)


def _readelf_image_end(readelf: str, binary: Path) -> int:
    """The ELF image end per readelf: headers, tables and section contents.

    max(section-header-table end, every non-NOBITS section's offset + size) --
    an independent re-derivation of the same "where does the mapped image
    stop" answer the reader computes, from binutils' decode of the file.
    """
    header = subprocess.run(
        [readelf, "-h", str(binary)], capture_output=True, text=True, timeout=60
    )
    assert header.returncode == 0, header.stderr
    shoff = _READELF_SHOFF_RE.search(header.stdout)
    shnum = _READELF_SHNUM_RE.search(header.stdout)
    shentsize = _READELF_SHENTSIZE_RE.search(header.stdout)
    assert shoff and shnum and shentsize, header.stdout
    end = int(shoff.group(1)) + int(shnum.group(1)) * int(shentsize.group(1))
    sections = subprocess.run(
        [readelf, "-S", "-W", str(binary)], capture_output=True, text=True, timeout=60
    )
    assert sections.returncode == 0, sections.stderr
    for sh_type, offset_hex, size_hex in _READELF_SH_ROW_RE.findall(sections.stdout):
        if sh_type != "NOBITS":
            end = max(end, int(offset_hex, 16) + int(size_hex, 16))
    return end


@pytest.mark.integration
def test_elf_overlay_agrees_with_readelf(tmp_path: Path) -> None:
    gcc = shutil.which("gcc") or shutil.which("cc")
    if gcc is None:
        pytest.skip("no C compiler installed — overlay gate not run (skip != pass)")
    readelf = shutil.which("readelf")
    if readelf is None:
        pytest.skip("readelf (binutils) not installed — overlay gate not run (skip != pass)")

    probe = _compile_probe(gcc, tmp_path, "probe_overlay")
    image_end = _readelf_image_end(readelf, probe)
    pristine_size = probe.stat().st_size
    # binutils agrees the toolchain's own output maps every byte: the file
    # ends exactly where the image does, so "no overlay" is the right answer.
    assert image_end == pristine_size

    payload = b"OVERLAY-PAYLOAD!" * 8
    padded = tmp_path / "probe_padded"
    padded.write_bytes(probe.read_bytes() + payload)

    service = AnalysisService()
    sessions: list[str] = []
    try:
        session_id, clean_facts = _session_native(service, probe)
        sessions.append(session_id)
        assert "overlay" not in clean_facts
        # The reader must place the appended bytes exactly at readelf's image
        # end -- same offset, same size, on real toolchain output.
        session_id, padded_facts = _session_native(service, padded)
        sessions.append(session_id)
        assert padded_facts["overlay"] == {
            "offset": image_end,
            "size": len(payload),
            "kind": None,  # prose payload: no magic, the honest non-answer
        }
    finally:
        for session_id in sessions:
            service.close_session(session_id)


def _llvm_macho_image_end(objdump: str, binary: Path) -> int:
    """The Mach-O image end per llvm-objdump: segments, symtab and strings.

    Walks the otool-style --all-headers output, tracking which load command
    each key/value line belongs to, and takes the furthest byte any segment
    (fileoff + filesize) or the LC_SYMTAB tables (symoff + nsyms entries,
    stroff + strsize) reach -- LLVM's independent answer to where the mapped
    image stops.
    """
    result = subprocess.run(
        [objdump, "--macho", "--all-headers", str(binary)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    end = 0
    fields: dict[str, int] = {}
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        key, value = parts
        if key == "cmd":
            fields = {}
            continue
        if key in ("fileoff", "filesize", "symoff", "nsyms", "stroff", "strsize"):
            try:
                fields[key] = int(value)
            except ValueError:
                continue
            if "fileoff" in fields and "filesize" in fields and fields["filesize"] > 0:
                end = max(end, fields["fileoff"] + fields["filesize"])
            if "symoff" in fields and "nsyms" in fields:
                end = max(end, fields["symoff"] + fields["nsyms"] * 16)  # nlist_64
            if "stroff" in fields and "strsize" in fields:
                end = max(end, fields["stroff"] + fields["strsize"])
    return end


@pytest.mark.integration
def test_macho_overlay_agrees_with_llvm_objdump(tmp_path: Path) -> None:
    objdump = shutil.which("llvm-objdump")
    if objdump is None:
        pytest.skip("llvm-objdump not installed — Mach-O overlay gate not run (skip != pass)")
    if not _MACHO_FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_MACHO_FIXTURE}")

    image_end = _llvm_macho_image_end(objdump, _MACHO_FIXTURE)
    assert image_end == _MACHO_FIXTURE.stat().st_size

    payload = b"MACHO-OVERLAY!" * 4
    padded = tmp_path / "padded.macho"
    padded.write_bytes(_MACHO_FIXTURE.read_bytes() + payload)

    service = AnalysisService()
    sessions: list[str] = []
    try:
        session_id, clean_facts = _session_native(service, _MACHO_FIXTURE)
        sessions.append(session_id)
        assert "overlay" not in clean_facts
        session_id, padded_facts = _session_native(service, padded)
        sessions.append(session_id)
        # The appended bytes land exactly at LLVM's image end, byte for byte.
        assert padded_facts["overlay"] == {
            "offset": image_end,
            "size": len(payload),
            "kind": None,  # prose payload: no magic, the honest non-answer
        }
    finally:
        for session_id in sessions:
            service.close_session(session_id)


# llvm-objdump prints the encryption command as otool does: one field per line.
_LLVM_CRYPT_RE = re.compile(r"^\s*(cryptoff|cryptsize|cryptid)\s+(\d+)\s*$", re.MULTILINE)


def _fairplay_shaped_macho() -> bytes:
    """A thin Mach-O with the FairPlay-encrypted layout, strict enough for LLVM.

    One __TEXT segment mapping the whole 0x300-byte file and one
    LC_ENCRYPTION_INFO_64 marking 0x100..0x300 as ciphertext (cryptid 1).
    llvm-objdump refuses an encryption range that runs past the file, so the
    probe carries the real bytes -- passing its decode certifies the shape,
    not just the header fields.
    """
    segment = bytearray(72)
    segment[0:4] = (0x19).to_bytes(4, "little")  # LC_SEGMENT_64
    segment[4:8] = (72).to_bytes(4, "little")
    segment[8:14] = b"__TEXT"
    # vmaddr / vmsize / fileoff / filesize, then maxprot/initprot r-x.
    struct.pack_into("<QQQQ", segment, 24, 0x100000000, 0x300, 0, 0x300)
    struct.pack_into("<iiII", segment, 56, 5, 5, 0, 0)
    encryption = (
        (0x2C).to_bytes(4, "little")  # LC_ENCRYPTION_INFO_64
        + (24).to_bytes(4, "little")
        + (0x100).to_bytes(4, "little")  # cryptoff
        + (0x200).to_bytes(4, "little")  # cryptsize
        + (1).to_bytes(4, "little")  # cryptid: FairPlay
        + (0).to_bytes(4, "little")  # pad
    )
    cmds = bytes(segment) + encryption
    header = (
        b"\xcf\xfa\xed\xfe"
        + (0x01000007).to_bytes(4, "little")  # cputype x86_64
        + (0).to_bytes(4, "little")
        + (2).to_bytes(4, "little")  # MH_EXECUTE
        + (2).to_bytes(4, "little")  # ncmds
        + len(cmds).to_bytes(4, "little")
        + (0x4).to_bytes(4, "little")  # MH_DYLDLINK
        + (0).to_bytes(4, "little")
    )
    blob = bytearray(0x300)
    blob[: len(header) + len(cmds)] = header + cmds
    return bytes(blob)


@pytest.mark.integration
def test_macho_encryption_range_agrees_with_llvm_objdump(tmp_path: Path) -> None:
    """The encryption_info triple against LLVM's decode of the same command.

    The reader now maps which file bytes FairPlay leaves as ciphertext
    (cryptoff/cryptsize) and the scheme id -- the first triage fact for an
    App Store binary, since static analysis over that range reads garbage.
    The field offsets and the unit fixtures are both ours; llvm-objdump
    decodes the very same load command (and validates the range really sits
    inside the file), so its three printed fields must equal the reader's
    triple exactly -- and the committed fixture must read as carrying no such
    command in both views.
    """
    objdump = shutil.which("llvm-objdump")
    if objdump is None:
        pytest.skip("llvm-objdump not installed — Mach-O encryption gate not run (skip != pass)")

    probe = tmp_path / "fairplay.macho"
    probe.write_bytes(_fairplay_shaped_macho())
    result = subprocess.run(
        [objdump, "--macho", "--all-headers", str(probe)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert "LC_ENCRYPTION_INFO_64" in result.stdout
    llvm_fields = {key: int(value) for key, value in _LLVM_CRYPT_RE.findall(result.stdout)}

    service = AnalysisService()
    sessions: list[str] = []
    try:
        session_id, facts = _session_native(service, probe)
        sessions.append(session_id)
        assert facts["encrypted"] is True
        assert facts["encryption_info"] == {
            "offset": llvm_fields["cryptoff"],
            "size": llvm_fields["cryptsize"],
            "cryptid": llvm_fields["cryptid"],
        }
        assert facts["encryption_info"] == {"offset": 0x100, "size": 0x200, "cryptid": 1}
        # The whole range the reader marks opaque really is inside the file --
        # the same containment LLVM enforced by decoding without error.
        info = facts["encryption_info"]
        assert info["offset"] + info["size"] <= probe.stat().st_size

        # Negative agreement on the committed fixture: no command, no range,
        # in LLVM's decode and the reader's facts alike.
        if _MACHO_FIXTURE.is_file():
            fixture_dump = subprocess.run(
                [objdump, "--macho", "--all-headers", str(_MACHO_FIXTURE)],
                capture_output=True,
                text=True,
                timeout=60,
            )
            assert fixture_dump.returncode == 0, fixture_dump.stderr
            assert "LC_ENCRYPTION_INFO" not in fixture_dump.stdout
            session_id, fixture_facts = _session_native(service, _MACHO_FIXTURE)
            sessions.append(session_id)
            assert fixture_facts["encrypted"] is False
            assert "encryption_info" not in fixture_facts
    finally:
        for session_id in sessions:
            service.close_session(session_id)


@pytest.mark.integration
def test_elf_debuglink_agrees_with_objcopy_and_zlib(tmp_path: Path) -> None:
    """The .gnu_debuglink fact vs a real strip pipeline's own record.

    objcopy --add-gnu-debuglink is the producer every distro's packaging uses:
    it computes the CRC32 of the separate debug file and writes the record
    this reader parses. The gate replays that pipeline (split the debug info
    out, strip, link back by name), then referees the filename through
    readelf's raw section dump and the checksum through zlib's independent
    CRC32 -- if the reader's alignment step or byte order were wrong, the hex
    would not match the digest of the actual file on disk.
    """
    gcc = shutil.which("gcc") or shutil.which("cc")
    if gcc is None:
        pytest.skip("no C compiler installed — debuglink gate not run (skip != pass)")
    objcopy = shutil.which("objcopy")
    if objcopy is None:
        pytest.skip("objcopy not installed — debuglink gate not run (skip != pass)")
    readelf = shutil.which("readelf")
    if readelf is None:
        pytest.skip("readelf not installed — debuglink gate not run (skip != pass)")

    binary = _compile_probe(gcc, tmp_path, "app", "-g")
    debug = tmp_path / "app.debug"
    for step in (
        [objcopy, "--only-keep-debug", "app", "app.debug"],
        [objcopy, "--strip-debug", "app"],
        [objcopy, "--add-gnu-debuglink=app.debug", "app"],
    ):
        done = subprocess.run(step, cwd=tmp_path, capture_output=True, text=True, timeout=120)
        assert done.returncode == 0, done.stderr

    # Ground truth one: the CRC objcopy wrote is by definition the CRC32 of
    # the debug file's bytes; zlib computes it with an implementation the
    # reader does not share.
    expected_crc = f"{zlib.crc32(debug.read_bytes()) & 0xFFFFFFFF:08x}"
    # Ground truth two: readelf's raw dump of the section must carry the name,
    # so the comparison below cannot pass on a section the pipeline never
    # wrote. Kept as bytes: the dump ends with the CRC's raw bytes, which are
    # whatever the checksum happens to be, not valid UTF-8.
    dump = subprocess.run(
        [readelf, "--string-dump=.gnu_debuglink", str(binary)],
        capture_output=True,
        timeout=60,
    )
    assert dump.returncode == 0, dump.stderr.decode(errors="replace")
    assert b"app.debug" in dump.stdout

    service = AnalysisService()
    sessions: list[str] = []
    try:
        session_id, facts = _session_native(service, binary)
        sessions.append(session_id)
        assert facts["debug_link"] == {"filename": "app.debug", "crc32": expected_crc}

        # Negative agreement: the same compile without the pipeline carries no
        # record, and the fact stays absent rather than reading garbage.
        plain = _compile_probe(gcc, tmp_path, "plain")
        session_id, plain_facts = _session_native(service, plain)
        sessions.append(session_id)
        assert "debug_link" not in plain_facts
    finally:
        for session_id in sessions:
            service.close_session(session_id)


def _trie_uleb(value: int) -> bytes:
    out = bytearray()
    while True:
        low = value & 0x7F
        value >>= 7
        out.append(low | 0x80 if value else low)
        if not value:
            return bytes(out)


def _macho_with_exports_trie(groups: dict[str, list[str]]) -> bytes:
    """A 64-bit Mach-O whose LC_DYLD_INFO_ONLY names a two-level exports trie.

    ``groups`` maps a shared prefix to its suffixes: the root fans out one
    edge per prefix into a mid node, whose edges end in terminal nodes -- the
    shape a real linker emits for symbols sharing a stem, and the one a
    reader that fails to accumulate edge strings misreads. Built here
    independently of the unit builder (which lays out a flat, one-level
    trie). Offsets are resolved to a fixed point so ULEB widths match.
    """
    prefixes = sorted(groups)
    terminal = bytes([2, 0, 0, 0])
    mid_offsets = {prefix: 0 for prefix in prefixes}
    leaf_offsets: dict[tuple[str, str], int] = {
        (prefix, suffix): 0 for prefix in prefixes for suffix in groups[prefix]
    }
    while True:
        blob = bytearray([0, len(prefixes)])
        for prefix in prefixes:
            blob += prefix.encode() + b"\x00" + _trie_uleb(mid_offsets[prefix])
        new_mid: dict[str, int] = {}
        for prefix in prefixes:
            new_mid[prefix] = len(blob)
            blob += bytes([0, len(groups[prefix])])
            for suffix in groups[prefix]:
                blob += suffix.encode() + b"\x00" + _trie_uleb(leaf_offsets[(prefix, suffix)])
        new_leaf: dict[tuple[str, str], int] = {}
        pos = len(blob)
        for prefix in prefixes:
            for suffix in groups[prefix]:
                new_leaf[(prefix, suffix)] = pos
                pos += len(terminal)
        if new_mid == mid_offsets and new_leaf == leaf_offsets:
            trie = bytes(blob) + terminal * len(leaf_offsets)
            break
        mid_offsets, leaf_offsets = new_mid, new_leaf

    cmd = bytearray(48)
    cmd[0:4] = (0x80000022).to_bytes(4, "little")  # LC_DYLD_INFO_ONLY
    cmd[4:8] = (48).to_bytes(4, "little")
    cmd[40:44] = (32 + 48).to_bytes(4, "little")  # export_off: right after cmds
    cmd[44:48] = len(trie).to_bytes(4, "little")
    header = (
        b"\xcf\xfa\xed\xfe"
        + (0x01000007).to_bytes(4, "little")
        + (0).to_bytes(4, "little")
        # MH_EXECUTE: LLVM's strict decoder demands an LC_ID_DYLIB from a
        # dylib filetype, which this single-command probe deliberately lacks.
        + (2).to_bytes(4, "little")
        + (1).to_bytes(4, "little")
        + (48).to_bytes(4, "little")
        + (0).to_bytes(4, "little")
        + (0).to_bytes(4, "little")
    )
    return header + bytes(cmd) + trie


# llvm-objdump --exports-trie prints one "0xADDR  _name" row per export.
_LLVM_EXPORT_ROW_RE = re.compile(r"^0x[0-9a-fA-F]+\s+(\S+)\s*$", re.MULTILINE)


@pytest.mark.integration
def test_macho_dyld_exports_agree_with_llvm_objdump(tmp_path: Path) -> None:
    """The dyld exports-trie fact vs LLVM's decoder of the same structure.

    The trie is the loader's authoritative export list -- what survives strip
    when LC_SYMTAB's externals do not. The probe's symbols share stems
    (_probe_open/_probe_close, _teardown), so a reader emitting edge
    substrings instead of accumulated paths, or stopping at the first
    terminal, cannot match LLVM's name set.
    """
    objdump = shutil.which("llvm-objdump")
    if objdump is None:
        pytest.skip("llvm-objdump not installed — exports-trie gate not run (skip != pass)")

    probe = tmp_path / "trie.macho"
    probe.write_bytes(
        _macho_with_exports_trie({"_probe_": ["open", "close"], "_tear": ["down"]})
    )

    # Independent ground truth: LLVM walks the same ULEB offsets and edge
    # strings with its own decoder; the set must be the one we planted, so
    # the comparison below cannot pass vacuously.
    result = subprocess.run(
        [objdump, "--macho", "--exports-trie", str(probe)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    llvm_names = sorted(_LLVM_EXPORT_ROW_RE.findall(result.stdout))
    assert llvm_names == ["_probe_close", "_probe_open", "_teardown"]

    service = AnalysisService()
    sessions: list[str] = []
    try:
        session_id, facts = _session_native(service, probe)
        sessions.append(session_id)
        assert facts["dyld_exports"] == llvm_names
        # The stripped-dylib shape this fact exists for: no LC_SYMTAB, so the
        # symtab-derived surface is silent while the trie still answers.
        assert "exported_symbols" not in facts

        # Negative agreement on the committed fixture: no trie command in
        # LLVM's decode, no dyld_exports fact from the reader.
        if _MACHO_FIXTURE.is_file():
            fixture_dump = subprocess.run(
                [objdump, "--macho", "--exports-trie", str(_MACHO_FIXTURE)],
                capture_output=True,
                text=True,
                timeout=60,
            )
            assert fixture_dump.returncode == 0, fixture_dump.stderr
            assert not _LLVM_EXPORT_ROW_RE.findall(fixture_dump.stdout)
            session_id, fixture_facts = _session_native(service, _MACHO_FIXTURE)
            sessions.append(session_id)
            assert "dyld_exports" not in fixture_facts
    finally:
        for session_id in sessions:
            service.close_session(session_id)
