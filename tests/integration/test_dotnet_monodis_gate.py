"""Cross-validate the pure-Python .NET reader against Mono's monodis.

The other metadata gate (``test_dotnet_metadata_gate``) proves the pure-Python
ECMA-335 reader against the committed ``minimal_assembly.exe`` -- but that
fixture is built by our own ``build_minimal_dotnet.py`` and read by our own
``clr_inspect``, so a shared assumption between builder and reader would pass
unseen, and nothing proves the fixture is a genuine assembly rather than
something only our reader accepts. This gate closes that loop with an
independent parser: Mono's ``monodis`` must parse the same file and agree on
every identity fact the reader surfaces -- assembly name and version, module
name, MVID, the dependency lists, the target framework, the strong-name
public-key token, the type list, the resolved entry point (the method
monodis marks ``.entrypoint``), and the module initializer (the ``.cctor``
monodis renders as a global method). It is the .NET analogue of the native
gate cross-checking the entry point against radare2 and Ghidra, and the proxy
gate cross-checking the HAR reader against real mitmproxy output.

monodis ships in Debian/Ubuntu's ``mono-utils``; skip != pass -- the gate skips,
naming the missing tool, only when monodis is not installed.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "dotnet" / "minimal_assembly.exe"

_ASM_NAME_RE = re.compile(r"^Name:\s+(.+?)\s*$", re.MULTILINE)
_ASM_VERSION_RE = re.compile(r"^Version:\s+(.+?)\s*$", re.MULTILINE)
# "1: MyModule.dll 1 {8B8A2C3D-4E5F-6071-8293-A4B5C6D7E8F9}"
_MODULE_RE = re.compile(r"^\d+:\s+(\S+)\s+\d+\s+\{([0-9A-Fa-f-]+)\}", re.MULTILINE)
# "2: Sample (flist=1, mlist=1, flags=0x100001, extends=0x0)"
_TYPEDEF_RE = re.compile(r"^\d+:\s+(.+?)\s+\(flist=", re.MULTILINE)
# monodis --assemblyref prints each row as "1: Version=4.0.0.0" with the
# referenced assembly's name on the following indented line.
_ASSEMBLYREF_RE = re.compile(r"^\d+:\s+Version=(\S+)\s*\n\s+Name=(\S+)", re.MULTILINE)
# monodis --moduleref prints "1: kernel32.dll" per row under a header line.
_MODULEREF_RE = re.compile(r"^\d+:\s+(\S+)\s*$", re.MULTILINE)
# monodis --customattr fully decodes each CustomAttribute row -- parent, the
# ctor resolved through TypeRef/AssemblyRef, and the value blob's string:
# `1: Assembly: 1: instance void class [mscorlib]System.Runtime.Versioning
#  .TargetFrameworkAttribute::'.ctor'(string) [".NETFramework,Version=v4.8"]`
_TFA_CA_RE = re.compile(
    r"^\d+:\s+Assembly:.*TargetFrameworkAttribute::'\.ctor'\(string\)\s+\[\"([^\"]+)\"\]",
    re.MULTILINE,
)
# monodis --assembly dumps the public key as hex rows under a "Dump:" line,
# each "0x........: bb bb bb ...". These lines carry the raw key bytes Mono
# reads from the same file -- the ground truth for what the token derives from.
_PUBKEY_DUMP_RE = re.compile(r"^0x[0-9a-fA-F]+:\s+((?:[0-9a-fA-F]{2}\s+)+)$", re.MULTILINE)
# Full disassembly closes every method block with "} // end of method
# Type::Name"; the block carrying the ".entrypoint" directive is where Mono
# says execution starts.
_METHOD_END_RE = re.compile(r"//\s*end of method\s+(\S+)")
# Module-scope methods (owned by TypeDef row 1, <Module>) are rendered as
# *global* methods: the header sits outside every .class block under a
# "// method line N" marker (N is the MethodDef row monodis read it from)
# and the block closes with "end of global method NAME" -- a type's own
# .cctor would close with "end of method Type::.cctor" instead.
_GLOBAL_CCTOR_LINE_RE = re.compile(
    r"//\s*method line (\d+)\s*\n\s*\.method[^\n]*\n[^\n]*'\.cctor'"
)
# monodis --implmap prints each P/Invoke row as
# "1: void class Sample::NativeBeep() 256 (Beep kernel32.dll)" -- the managed
# wrapper's full signature, the MappingFlags in decimal, then the ImportName
# and ImportScope DLL in parentheses: Mono's own decode of the same
# (native symbol, module) pair the reader reports.
_IMPLMAP_ROW_RE = re.compile(r"^\d+:\s+.*::(\w+)\(\)\s+(\d+)\s+\((\S+)\s+(\S+)\)\s*$", re.MULTILINE)


def _monodis_public_key(assembly_dump: str) -> bytes:
    """The Assembly row's public key as Mono independently decodes it.

    monodis prints the key between the ``PublicKey:`` and ``Culture:`` lines as
    one or more hex dump rows; this stitches those bytes back together.
    """
    section = assembly_dump.split("PublicKey:", 1)[-1].split("Culture:", 1)[0]
    key = bytearray()
    for row in _PUBKEY_DUMP_RE.findall(section):
        key.extend(int(b, 16) for b in row.split())
    return bytes(key)


def _monodis(*args: str) -> str:
    result = subprocess.run(
        ["monodis", *args, str(_FIXTURE)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    # monodis exits 0 and writes the dump to stdout. The fixture carries real
    # member signature blobs (monodis asserts on malformed ones), so even the
    # no-argument full disassembly parses it end to end.
    assert result.returncode == 0, result.stderr or result.stdout
    return result.stdout


def _monodis_file(binary: Path, *args: str) -> str:
    """monodis's dump of an arbitrary assembly (the fixture-independent form)."""
    result = subprocess.run(
        ["monodis", *args, str(binary)], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr or result.stdout
    return result.stdout


def _service(tmp_path: Path) -> AnalysisService:
    return AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
        )
    )


@pytest.mark.integration
def test_pure_python_reader_agrees_with_monodis(tmp_path: Path) -> None:
    if not _FIXTURE.is_file():
        pytest.skip(
            "minimal .NET fixture missing; run fixtures/dotnet/build_minimal_dotnet.py"
            " (skip != pass)"
        )
    if shutil.which("monodis") is None:
        pytest.skip("monodis (mono-utils) not installed — .NET cross-check not run (skip != pass)")

    # Independent ground truth: Mono parses the assembly, module and typedef
    # tables straight from the file, with no code of ours involved.
    assembly_dump = _monodis("--assembly")
    mono_name = _ASM_NAME_RE.search(assembly_dump)
    mono_version = _ASM_VERSION_RE.search(assembly_dump)
    assert mono_name and mono_version, assembly_dump

    module_dump = _monodis("--module")
    mono_module = _MODULE_RE.search(module_dump)
    assert mono_module, module_dump
    mono_module_name = mono_module.group(1)
    mono_mvid = mono_module.group(2).lower()

    typedef_dump = _monodis("--typedef")
    # monodis prints the <Module> pseudo-type as "(null)"; drop it so what
    # remains is the set of real named types, the same set enumerate reports
    # once its own <Module> entry is removed.
    mono_types = {name for name in _TYPEDEF_RE.findall(typedef_dump) if name != "(null)"}
    assert mono_types, typedef_dump

    # The AssemblyRef table -- the managed DT_NEEDED. Sizing this row wrong is
    # an easy bug (it is NOT the Assembly row's shape), and every table walked
    # behind it lands offset when it happens, so Mono's independent decode of
    # name and version per row is the check that matters most here.
    assemblyref_dump = _monodis("--assemblyref")
    mono_refs = {(name, version) for version, name in _ASSEMBLYREF_RE.findall(assemblyref_dump)}
    assert mono_refs, assemblyref_dump

    # The ModuleRef table -- the native complement to AssemblyRef: the unmanaged
    # DLLs the assembly P/Invokes into. It sits just before Assembly in the
    # walk, on the other side of it from AssemblyRef, so Mono agreeing on this
    # too brackets the row-sizing check from both directions. The regex matches
    # only "N: name" rows, so monodis's "ModuleRef Table" header is ignored.
    moduleref_dump = _monodis("--moduleref")
    mono_modrefs = set(_MODULEREF_RE.findall(moduleref_dump))
    assert mono_modrefs, moduleref_dump

    # The pure-Python reader, driven through the service exactly as a client
    # would reach it.
    service = _service(tmp_path)
    try:
        session_id = service.create_session(str(_FIXTURE)).data["session"]["id"]
        report = service.dotnet_inspect(session_id, require_verified=True)
        assert report.ok, report.error
        facts = report.data

        # Every identity fact the reader surfaces must match Mono's, byte for
        # byte -- proving the reader is right and the fixture is a real assembly.
        assert facts["assembly_name"] == mono_name.group(1)
        assert facts["assembly_version"] == mono_version.group(1)
        assert facts["module_name"] == mono_module_name
        assert str(facts["mvid"]).lower() == mono_mvid

        # The strong-name identity -- "who signed it" in the managed world.
        # Mono reads the public key straight out of the Assembly row; the token
        # is the low 8 bytes of that key's SHA-1, reversed (ECMA-335 II.6.3),
        # the same derivation the CLR, ildasm and sn use. Deriving it from
        # Mono's independently-decoded key bytes proves the reader hashed the
        # right blob; the published b77a5c561934e089 anchors it externally.
        mono_key = _monodis_public_key(assembly_dump)
        assert mono_key, assembly_dump
        expected_token = hashlib.sha1(mono_key).digest()[-8:][::-1].hex()  # noqa: S324
        assert facts["public_key_token"] == expected_token
        assert facts["public_key_token"] == "b77a5c561934e089"
        # The dependency list, ref for ref: name and compiled-against version
        # must both match Mono's decode of the same AssemblyRef rows.
        reader_refs = {(ref["name"], ref["version"]) for ref in facts["assembly_refs"]}
        assert reader_refs == mono_refs
        # The native P/Invoke dependency list must match Mono's ModuleRef decode.
        assert set(facts["module_refs"]) == mono_modrefs

        # The target framework: Mono resolves the CustomAttribute row on the
        # assembly through the ctor's MemberRef and TypeRef, parses the ctor
        # signature blob, and decodes the value blob's SerString all by
        # itself -- so this one string agreeing proves the whole attribute
        # chain (coded indexes, ctor resolution, #Blob) reads identically.
        customattr_dump = _monodis("--customattr")
        mono_tfa = _TFA_CA_RE.search(customattr_dump)
        assert mono_tfa, customattr_dump
        assert facts["target_framework"] == mono_tfa.group(1)

        # The resource sits behind the AssemblyRef table in the walk, so its
        # name coming back clean proves the reader stepped over those rows at
        # their true width -- Mono's --manifest names the same resource.
        manifest_dump = _monodis("--manifest")
        enumerated_resources = service.dotnet_enumerate(session_id, "resources", limit=16)
        assert enumerated_resources.ok, enumerated_resources.error
        for resource in enumerated_resources.data["items"]:
            assert f"'{resource['name']}'" in manifest_dump

        enumerated = service.dotnet_enumerate(session_id, "types", limit=64)
        assert enumerated.ok, enumerated.error
        reader_types = {t["name"] for t in enumerated.data["items"] if t["name"] != "<Module>"}
        assert reader_types == mono_types
    finally:
        service.close_all()


@pytest.mark.integration
def test_entry_point_name_agrees_with_monodis_entrypoint(tmp_path: Path) -> None:
    if not _FIXTURE.is_file():
        pytest.skip(
            "minimal .NET fixture missing; run fixtures/dotnet/build_minimal_dotnet.py"
            " (skip != pass)"
        )
    if shutil.which("monodis") is None:
        pytest.skip("monodis (mono-utils) not installed — .NET cross-check not run (skip != pass)")

    # Independent ground truth: Mono's full disassembly resolves the COR20
    # EntryPointToken itself and marks that one method body with .entrypoint.
    # The enclosing block's end comment names it Type::Method -- exactly the
    # rendering the reader's entry_point_name uses.
    full_dump = _monodis()
    assert full_dump.count(".entrypoint") == 1, full_dump
    mono_entry: str | None = None
    seen_entrypoint = False
    for line in full_dump.splitlines():
        if line.strip() == ".entrypoint":
            seen_entrypoint = True
        elif seen_entrypoint:
            match = _METHOD_END_RE.search(line)
            if match:
                mono_entry = match.group(1)
                break
    assert mono_entry, full_dump

    service = _service(tmp_path)
    try:
        session_id = service.create_session(str(_FIXTURE)).data["session"]["id"]
        report = service.dotnet_inspect(session_id, require_verified=True)
        assert report.ok, report.error
        # The reader resolves the same token through MethodDef.Name and the
        # owning TypeDef's MethodList span; both spell where execution starts
        # identically -- the managed analogue of the WASM start-function name.
        assert report.data["entry_point_name"] == mono_entry == "Sample::Run"
    finally:
        service.close_all()


@pytest.mark.integration
def test_module_initializer_agrees_with_monodis(tmp_path: Path) -> None:
    """The tool-free module-initializer fact against Mono's global-method decode.

    The module initializer -- the static .cctor owned by <Module> (TypeDef
    row 1) -- runs at module load, before the entry point: the managed
    code-before-main, where obfuscators put their stubs. The reader finds it
    by walking <Module>'s MethodList span itself; Mono independently resolves
    the same ownership when it renders the method as a *global* method (a
    type's .cctor would close as "end of method Type::.cctor" instead), under
    a "// method line N" marker naming the row it decoded. The two must agree
    that the initializer exists and sit in the same MethodDef row -- the
    managed analogue of the ELF gate cross-checking DT_INIT against readelf.
    """
    if not _FIXTURE.is_file():
        pytest.skip(
            "minimal .NET fixture missing; run fixtures/dotnet/build_minimal_dotnet.py"
            " (skip != pass)"
        )
    if shutil.which("monodis") is None:
        pytest.skip("monodis (mono-utils) not installed — .NET cross-check not run (skip != pass)")

    # Independent ground truth: Mono places the .cctor at module scope.
    full_dump = _monodis()
    assert "end of global method .cctor" in full_dump, full_dump
    line_match = _GLOBAL_CCTOR_LINE_RE.search(full_dump)
    assert line_match, full_dump
    mono_row = int(line_match.group(1))

    service = _service(tmp_path)
    try:
        session_id = service.create_session(str(_FIXTURE)).data["session"]["id"]
        report = service.dotnet_inspect(session_id, require_verified=True)
        assert report.ok, report.error
        token = report.data["module_initializer_token"]
        assert token is not None, "reader found no module initializer where monodis did"
        # Row for row: the reader's token names the same MethodDef row Mono
        # printed the global .cctor from.
        assert token == 0x06000000 | mono_row
        assert token == 0x06000001
    finally:
        service.close_all()


@pytest.mark.integration
def test_pinvoke_imports_agree_with_monodis_implmap(tmp_path: Path) -> None:
    """The tool-free P/Invoke import map against Mono's ImplMap decode.

    pinvoke_imports is the symbol-level native import surface: which native
    function each P/Invoke binds (the ImportName the runtime resolves) and in
    which DLL -- the managed analogue of an ELF's undefined dynamic symbols,
    which the native gate cross-checks against readelf. Mono decodes the same
    ImplMap rows itself for ``--implmap`` (and renders the binding as
    ``pinvokeimpl ("dll" as "name")`` in the full disassembly), so the two
    must agree pair for pair. The fixture's wrapper (NativeBeep) and import
    (Beep) deliberately differ: a reader echoing MethodDef names instead of
    ImportName cannot pass.
    """
    if not _FIXTURE.is_file():
        pytest.skip(
            "minimal .NET fixture missing; run fixtures/dotnet/build_minimal_dotnet.py"
            " (skip != pass)"
        )
    if shutil.which("monodis") is None:
        pytest.skip("monodis (mono-utils) not installed — .NET cross-check not run (skip != pass)")

    # Independent ground truth: Mono's own ImplMap table decode.
    implmap_dump = _monodis("--implmap")
    mono_rows = _IMPLMAP_ROW_RE.findall(implmap_dump)
    assert mono_rows, implmap_dump
    mono_imports = [(name, module) for _wrapper, _flags, name, module in mono_rows]

    service = _service(tmp_path)
    try:
        session_id = service.create_session(str(_FIXTURE)).data["session"]["id"]
        report = service.dotnet_inspect(session_id, require_verified=True)
        assert report.ok, report.error
        reader_imports = [
            (entry["name"], entry["module"]) for entry in report.data["pinvoke_imports"]
        ]
        # Pair for pair, in row order: the same native symbols from the same
        # DLLs, and specifically the renamed import -- not the wrapper.
        assert reader_imports == mono_imports
        assert reader_imports == [("Beep", "kernel32.dll")]
        assert mono_rows[0][0] == "NativeBeep"  # the wrapper Mono names differs
    finally:
        service.close_all()


@pytest.mark.integration
def test_session_assembly_refs_agree_with_monodis(tmp_path: Path) -> None:
    """The session-level managed dependency surface against Mono's decode.

    ``assembly_refs`` is the tool-free session fact -- the .NET pair to ELF
    needed / Mach-O dylibs / PE imports, the same rows the dotnet.inspect deep
    reader lists. The row-sizing walk to the 0x23 table is the reader's own,
    so Mono's independent ``--assemblyref`` decode referees it row for row,
    name and version both, in table order.
    """
    if not _FIXTURE.is_file():
        pytest.skip(
            "minimal .NET fixture missing; run fixtures/dotnet/build_minimal_dotnet.py"
            " (skip != pass)"
        )
    if shutil.which("monodis") is None:
        pytest.skip("monodis (mono-utils) not installed — .NET cross-check not run (skip != pass)")

    assemblyref_dump = _monodis("--assemblyref")
    mono_refs = [(name, version) for version, name in _ASSEMBLYREF_RE.findall(assemblyref_dump)]
    assert mono_refs, assemblyref_dump

    service = _service(tmp_path)
    try:
        created = service.create_session(str(_FIXTURE))
        assert created.ok, created.error
        refs = created.data["session"]["metadata"]["dotnet"]["assembly_refs"]
        assert [(ref["name"], ref["version"]) for ref in refs] == mono_refs
    finally:
        service.close_all()


@pytest.mark.integration
def test_session_module_initializer_agrees_with_monodis(tmp_path: Path) -> None:
    """The session-level module-initializer token against Mono's global .cctor.

    ``module_initializer_token`` is now a tool-free session fact -- the
    managed member of the code-before-main family (PE TLS callback / ELF
    init_func / WASM start), the <Module>::.cctor the CLR runs before any
    entry point. The session reader walks <Module>'s MethodList span itself,
    so Mono's independent global-method decode referees it row for row on the
    fixture, and an mcs program with no module initializer pins the honest
    None: absence of the fact, agreed by both sides.
    """
    if not _FIXTURE.is_file():
        pytest.skip(
            "minimal .NET fixture missing; run fixtures/dotnet/build_minimal_dotnet.py"
            " (skip != pass)"
        )
    if shutil.which("monodis") is None:
        pytest.skip("monodis (mono-utils) not installed — .NET cross-check not run (skip != pass)")

    full_dump = _monodis()
    assert "end of global method .cctor" in full_dump, full_dump
    line_match = _GLOBAL_CCTOR_LINE_RE.search(full_dump)
    assert line_match, full_dump
    mono_row = int(line_match.group(1))

    service = _service(tmp_path)
    try:
        created = service.create_session(str(_FIXTURE))
        assert created.ok, created.error
        token = created.data["session"]["metadata"]["dotnet"]["module_initializer_token"]
        # Row for row: the session token names the same MethodDef row Mono
        # printed the global .cctor from.
        assert token == 0x06000000 | mono_row
        assert token == 0x06000001
    finally:
        service.close_all()

    mcs = shutil.which("mcs")
    if mcs is None:
        return  # the fixture leg already ran; the negative leg needs a compiler
    source = tmp_path / "plain.cs"
    source.write_text('class P { static void Main() { System.Console.WriteLine("hi"); } }\n')
    binary = tmp_path / "plain.exe"
    subprocess.run(
        [mcs, f"-out:{binary}", str(source)], check=True, capture_output=True, timeout=120
    )
    # Referee: an ordinary program declares no global .cctor at all.
    assert "end of global method .cctor" not in _monodis_file(binary)

    service = _service(tmp_path)
    try:
        created = service.create_session(str(binary))
        assert created.ok, created.error
        assert created.data["session"]["metadata"]["dotnet"]["module_initializer_token"] is None
    finally:
        service.close_all()


@pytest.mark.integration
def test_session_pinvoke_imports_agree_with_monodis_implmap(tmp_path: Path) -> None:
    """The session-level native import surface against Mono's ImplMap decode.

    ``pinvoke_imports`` is the tool-free session fact -- the other half of
    the dependency split next to ``assembly_refs``, the .NET pair to a PE
    import table at symbol level, the same pairs the dotnet.inspect deep
    reader lists. The row-sizing walk through ModuleRef to ImplMap is the
    session reader's own, so Mono's independent ``--implmap`` decode
    referees it pair for pair.
    """
    if not _FIXTURE.is_file():
        pytest.skip(
            "minimal .NET fixture missing; run fixtures/dotnet/build_minimal_dotnet.py"
            " (skip != pass)"
        )
    if shutil.which("monodis") is None:
        pytest.skip("monodis (mono-utils) not installed — .NET cross-check not run (skip != pass)")

    implmap_dump = _monodis("--implmap")
    mono_imports = [
        (name, module) for _wrapper, _flags, name, module in _IMPLMAP_ROW_RE.findall(implmap_dump)
    ]
    assert mono_imports == [("Beep", "kernel32.dll")], implmap_dump

    service = _service(tmp_path)
    try:
        created = service.create_session(str(_FIXTURE))
        assert created.ok, created.error
        imports = created.data["session"]["metadata"]["dotnet"]["pinvoke_imports"]
        assert [(entry["name"], entry["module"]) for entry in imports] == mono_imports
    finally:
        service.close_all()


@pytest.mark.integration
def test_session_pinvoke_imports_of_an_mcs_assembly_agree_with_monodis(tmp_path: Path) -> None:
    """The same fact on a compiler's assembly neither builder controls.

    mcs lays out ModuleRef and ImplMap itself -- more tables in front, its
    own row order, real MemberForwarded indexes -- and one import is renamed
    via EntryPoint so a reader echoing wrapper names cannot pass. A second
    assembly with no DllImport at all pins the empty answer: purely managed
    code reports an empty native import surface, not a missing fact.
    """
    if shutil.which("monodis") is None:
        pytest.skip("monodis (mono-utils) not installed — .NET cross-check not run (skip != pass)")
    mcs = shutil.which("mcs")
    if mcs is None:
        pytest.skip("mcs (mono-mcs) not installed — compiler assembly gate not run (skip != pass)")

    source = tmp_path / "caller.cs"
    source.write_text(
        "using System.Runtime.InteropServices;\n"
        "class P {\n"
        '  [DllImport("libc", EntryPoint="getpid")] static extern int NativePid();\n'
        '  [DllImport("user32.dll")] static extern bool MessageBeep();\n'
        "  static void Main() { }\n"
        "}\n"
    )
    binary = tmp_path / "caller.exe"
    subprocess.run(
        [mcs, f"-out:{binary}", str(source)], check=True, capture_output=True, timeout=120
    )

    dump = subprocess.run(
        ["monodis", "--implmap", str(binary)], capture_output=True, text=True, timeout=60
    )
    assert dump.returncode == 0, dump.stderr or dump.stdout
    mono_rows = _IMPLMAP_ROW_RE.findall(dump.stdout)
    mono_imports = [(name, module) for _wrapper, _flags, name, module in mono_rows]
    # Referee sanity: both bindings landed, and the renamed one reads as its
    # native EntryPoint, not the managed wrapper.
    assert set(mono_imports) == {("getpid", "libc"), ("MessageBeep", "user32.dll")}, dump.stdout
    assert {wrapper for wrapper, _f, _n, _m in mono_rows} == {"NativePid", "MessageBeep"}

    empty_source = tmp_path / "managed.cs"
    empty_source.write_text("class Q { static void Main() { } }\n")
    managed_only = tmp_path / "managed.exe"
    subprocess.run(
        [mcs, f"-out:{managed_only}", str(empty_source)],
        check=True,
        capture_output=True,
        timeout=120,
    )

    service = _service(tmp_path)
    try:
        created = service.create_session(str(binary))
        assert created.ok, created.error
        imports = created.data["session"]["metadata"]["dotnet"]["pinvoke_imports"]
        assert [(entry["name"], entry["module"]) for entry in imports] == mono_imports

        created = service.create_session(str(managed_only))
        assert created.ok, created.error
        assert created.data["session"]["metadata"]["dotnet"]["pinvoke_imports"] == []
    finally:
        service.close_all()


@pytest.mark.integration
def test_session_assembly_refs_of_an_mcs_assembly_agree_with_monodis(tmp_path: Path) -> None:
    """The same fact on a compiler's assembly neither builder controls.

    mcs links hello.exe against the runtime library on its own terms (its
    mscorlib's real version, not our fixture's planted 4.0.0.0), so agreement
    here proves the walk on metadata laid out by a real compiler -- more
    tables, wider heaps -- rather than by either of our builders.
    """
    if shutil.which("monodis") is None:
        pytest.skip("monodis (mono-utils) not installed — .NET cross-check not run (skip != pass)")
    mcs = shutil.which("mcs")
    if mcs is None:
        pytest.skip("mcs (mono-mcs) not installed — compiler assembly gate not run (skip != pass)")

    source = tmp_path / "hello.cs"
    source.write_text('class P { static void Main() { System.Console.WriteLine("hi"); } }\n')
    binary = tmp_path / "hello.exe"
    subprocess.run(
        [mcs, f"-out:{binary}", str(source)], check=True, capture_output=True, timeout=120
    )

    dump = subprocess.run(
        ["monodis", "--assemblyref", str(binary)], capture_output=True, text=True, timeout=60
    )
    assert dump.returncode == 0, dump.stderr or dump.stdout
    mono_refs = [(name, version) for version, name in _ASSEMBLYREF_RE.findall(dump.stdout)]
    # Referee sanity: a real hello-world links at least its runtime library.
    assert ("mscorlib" in {name for name, _v in mono_refs}) or mono_refs, dump.stdout

    service = _service(tmp_path)
    try:
        created = service.create_session(str(binary))
        assert created.ok, created.error
        refs = created.data["session"]["metadata"]["dotnet"]["assembly_refs"]
        assert [(ref["name"], ref["version"]) for ref in refs] == mono_refs
    finally:
        service.close_all()


@pytest.mark.integration
def test_session_target_framework_agrees_with_monodis(tmp_path: Path) -> None:
    """The session-level target framework against Mono's CustomAttribute decode.

    ``target_framework`` is now a tool-free session fact -- the .NET member
    of the declared-platform family (PE subsystem/os version, ELF minimum
    kernel, Mach-O minos, APK min/target SDK): the TargetFrameworkAttribute
    string resolved through TypeRef, the .ctor MemberRef and the Assembly's
    CustomAttribute row. Mono resolves that same chain and decodes the value
    blob's SerString entirely by itself, so the one string agreeing on the
    fixture proves the session walk end to end. The mcs leg pins agreement on
    a compiler-produced assembly either way: whatever Mono decodes (or its
    absence), the session must report the same.
    """
    if not _FIXTURE.is_file():
        pytest.skip(
            "minimal .NET fixture missing; run fixtures/dotnet/build_minimal_dotnet.py"
            " (skip != pass)"
        )
    if shutil.which("monodis") is None:
        pytest.skip("monodis (mono-utils) not installed — .NET cross-check not run (skip != pass)")

    mono_tfa = _TFA_CA_RE.search(_monodis("--customattr"))
    assert mono_tfa, "the fixture stamps TargetFrameworkAttribute"

    service = _service(tmp_path)
    try:
        created = service.create_session(str(_FIXTURE))
        assert created.ok, created.error
        declared = created.data["session"]["metadata"]["dotnet"]["target_framework"]
        assert declared == mono_tfa.group(1)
        assert declared == ".NETFramework,Version=v4.8"
    finally:
        service.close_all()

    mcs = shutil.which("mcs")
    if mcs is None:
        return  # the fixture leg already ran; this leg needs a compiler
    source = tmp_path / "plain.cs"
    source.write_text('class P { static void Main() { System.Console.WriteLine("hi"); } }\n')
    binary = tmp_path / "plain.exe"
    subprocess.run(
        [mcs, f"-out:{binary}", str(source)], check=True, capture_output=True, timeout=120
    )
    # Referee first: whatever Mono decodes off the compiled assembly -- a
    # framework string or no attribute at all -- is the expected answer.
    mcs_tfa = _TFA_CA_RE.search(_monodis_file(binary, "--customattr"))
    expected = mcs_tfa.group(1) if mcs_tfa else None

    service = _service(tmp_path)
    try:
        created = service.create_session(str(binary))
        assert created.ok, created.error
        assert created.data["session"]["metadata"]["dotnet"]["target_framework"] == expected
    finally:
        service.close_all()


@pytest.mark.integration
def test_session_assembly_identity_agrees_with_monodis(tmp_path: Path) -> None:
    """The session-level identity facts against Mono's own table decode.

    ``assembly_name``, ``assembly_version``, ``public_key_token`` and
    ``mvid`` are now tool-free session facts -- the .NET member of the
    declared-identity family (PE VS_VERSIONINFO, ELF soname/build-id, Mach-O
    install_name/LC_UUID, APK package/version). Mono decodes the Assembly and
    Module rows entirely by itself, so each fact is refereed independently:
    name and version off ``--assembly``, the MVID off ``--module``'s GUID,
    and the token re-derived from Mono's own dump of the public key bytes
    (SHA-1 low eight, reversed -- ECMA-335 II.6.3). The mcs leg re-runs the
    same referee on a compiler-produced assembly whose MVID is fresh every
    build and which carries no strong name: agreement there proves nothing
    is echoed from the fixture, and the honest None for the token.
    """
    if not _FIXTURE.is_file():
        pytest.skip(
            "minimal .NET fixture missing; run fixtures/dotnet/build_minimal_dotnet.py"
            " (skip != pass)"
        )
    if shutil.which("monodis") is None:
        pytest.skip("monodis (mono-utils) not installed — .NET cross-check not run (skip != pass)")

    assembly_dump = _monodis("--assembly")
    mono_name = _ASM_NAME_RE.search(assembly_dump)
    mono_version = _ASM_VERSION_RE.search(assembly_dump)
    assert mono_name and mono_version, assembly_dump
    mono_module = _MODULE_RE.search(_monodis("--module"))
    assert mono_module, "monodis must decode the Module row"
    mono_key = _monodis_public_key(assembly_dump)
    assert mono_key, assembly_dump
    expected_token = hashlib.sha1(mono_key).digest()[-8:][::-1].hex()  # noqa: S324

    service = _service(tmp_path)
    try:
        created = service.create_session(str(_FIXTURE))
        assert created.ok, created.error
        facts = created.data["session"]["metadata"]["dotnet"]
        assert facts["assembly_name"] == mono_name.group(1)
        assert facts["assembly_version"] == mono_version.group(1)
        assert facts["mvid"] == mono_module.group(2).lower()
        assert facts["public_key_token"] == expected_token
        assert facts["public_key_token"] == "b77a5c561934e089"
    finally:
        service.close_all()

    mcs = shutil.which("mcs")
    if mcs is None:
        return  # the fixture leg already ran; this leg needs a compiler
    source = tmp_path / "plain.cs"
    source.write_text('class P { static void Main() { System.Console.WriteLine("hi"); } }\n')
    binary = tmp_path / "plain.exe"
    subprocess.run(
        [mcs, f"-out:{binary}", str(source)], check=True, capture_output=True, timeout=120
    )
    plain_assembly = _monodis_file(binary, "--assembly")
    plain_name = _ASM_NAME_RE.search(plain_assembly)
    plain_version = _ASM_VERSION_RE.search(plain_assembly)
    assert plain_name and plain_version, plain_assembly
    plain_module = _MODULE_RE.search(_monodis_file(binary, "--module"))
    assert plain_module, "monodis must decode the compiled Module row"

    service = _service(tmp_path)
    try:
        created = service.create_session(str(binary))
        assert created.ok, created.error
        facts = created.data["session"]["metadata"]["dotnet"]
        assert facts["assembly_name"] == plain_name.group(1)
        assert facts["assembly_version"] == plain_version.group(1)
        # The MVID is freshly generated per compile: matching it proves the
        # session read this file's Module row, not anything remembered.
        assert facts["mvid"] == plain_module.group(2).lower()
        # mcs without -keyfile emits no public key: the honest answer is None.
        assert facts["public_key_token"] is None
    finally:
        service.close_all()


# monodis --typedef prints each row's flags too; visibility is the low three
# bits (ECMA-335 II.23.1.15) and 1 is Public -- Mono's own decode of the same
# bit the session reader tests.
_TYPEDEF_FLAGS_RE = re.compile(
    r"^\d+:\s+(.+?)\s+\(flist=\d+, mlist=\d+, flags=(0x[0-9a-fA-F]+)", re.MULTILINE
)


@pytest.mark.integration
def test_session_public_types_agree_with_monodis(tmp_path: Path) -> None:
    """The session-level managed export surface against Mono's TypeDef decode.

    ``public_types`` is now a tool-free session fact -- the .NET member of
    the capability-surface family (PE export table, ELF/Mach-O exported
    symbols, WASM exports): every top-level TypeDef whose visibility bits
    read Public. Mono prints each row's name and flags off its own walk, so
    filtering Mono's rows by the Public visibility must reproduce the session
    list name for name. The mcs leg compiles one public and one internal
    class: the split proves the reader tests the visibility bits, not just
    row presence.
    """
    if not _FIXTURE.is_file():
        pytest.skip(
            "minimal .NET fixture missing; run fixtures/dotnet/build_minimal_dotnet.py"
            " (skip != pass)"
        )
    if shutil.which("monodis") is None:
        pytest.skip("monodis (mono-utils) not installed — .NET cross-check not run (skip != pass)")

    def mono_public_types(dump: str) -> list[str]:
        return [
            name
            for name, flags in _TYPEDEF_FLAGS_RE.findall(dump)
            if int(flags, 16) & 0x7 == 0x1
        ]

    expected = mono_public_types(_monodis("--typedef"))
    assert expected == ["Sample"], expected

    service = _service(tmp_path)
    try:
        created = service.create_session(str(_FIXTURE))
        assert created.ok, created.error
        facts = created.data["session"]["metadata"]["dotnet"]
        assert facts["public_types"] == expected
        assert facts["public_type_count"] == len(expected)
    finally:
        service.close_all()

    mcs = shutil.which("mcs")
    if mcs is None:
        return  # the fixture leg already ran; this leg needs a compiler
    source = tmp_path / "split.cs"
    source.write_text(
        "namespace Deep { public class Exposed { } }\n"
        'internal class Hidden { static void Main() { System.Console.WriteLine("hi"); } }\n'
    )
    binary = tmp_path / "split.exe"
    subprocess.run(
        [mcs, f"-out:{binary}", str(source)], check=True, capture_output=True, timeout=120
    )
    plain_expected = mono_public_types(_monodis_file(binary, "--typedef"))
    # Referee sanity: Mono sees exactly the public half of the split.
    assert plain_expected == ["Deep.Exposed"], plain_expected

    service = _service(tmp_path)
    try:
        created = service.create_session(str(binary))
        assert created.ok, created.error
        facts = created.data["session"]["metadata"]["dotnet"]
        assert facts["public_types"] == plain_expected
        assert facts["public_type_count"] == 1
    finally:
        service.close_all()


# monodis --customattr's decode of a DebuggableAttribute row: the modern
# (DebuggingModes) shape prints its int32 as "[258]", the 1.x (bool, bool)
# shape as "[true, false]" -- one lazy group captures either payload.
_DEBUGGABLE_CA_RE = re.compile(
    r"System\.Diagnostics\.DebuggableAttribute::'\.ctor'\([^)]*\)\s+\[([^\]]+)\]"
)


def _session_debuggable(tmp_path: Path, binary: Path) -> dict[str, object] | None:
    service = _service(tmp_path)
    try:
        created = service.create_session(str(binary))
        assert created.ok, created.error
        facts = created.data["session"]["metadata"]["dotnet"]["debuggable"]
        return facts  # type: ignore[no-any-return]
    finally:
        service.close_all()


@pytest.mark.integration
def test_session_debuggable_agrees_with_monodis(tmp_path: Path) -> None:
    """The managed build-posture stamp against Mono's CustomAttribute decode.

    ``debuggable`` is now a tool-free session fact: DebuggableAttribute's
    DebuggingModes word, the release-vs-debug tell (DisableOptimizations set
    means the JIT runs the IL as written). Three legs, all refereed by
    monodis's own attribute decode. A real ``mcs -debug+`` build must carry
    the modern (DebuggingModes) int32 the referee prints, mode word for mode
    word, with the optimizer-disabled bit set (a debug build that didn't
    disable optimizations would pass vacuously). The same source at
    ``-debug-`` must carry nothing on both sides: None is the honest release
    answer, not a default. And the fixture builder's (bool, bool) variant --
    the 1.x .ctor shape no modern compiler emits -- must decode to the same
    booleans monodis prints, proving the runtime's folding rule rather than
    an int32-only happy path. skip != pass when either tool is missing.
    """
    if shutil.which("monodis") is None:
        pytest.skip("monodis (mono-utils) not installed — .NET cross-check not run (skip != pass)")
    mcs = shutil.which("mcs")
    if mcs is None:
        pytest.skip("mcs (mono-mcs) not installed — compiler legs not run (skip != pass)")

    source = tmp_path / "hello.cs"
    source.write_text('class P { static void Main() { System.Console.WriteLine("hi"); } }\n')
    debug_build = tmp_path / "hello_debug.exe"
    release_build = tmp_path / "hello_release.exe"
    subprocess.run(
        [mcs, "-debug+", f"-out:{debug_build}", str(source)],
        check=True,
        capture_output=True,
        timeout=120,
    )
    subprocess.run(
        [mcs, "-debug-", f"-out:{release_build}", str(source)],
        check=True,
        capture_output=True,
        timeout=120,
    )

    # Leg 1: the debug build. Referee first -- whatever mode word Mono
    # decodes off the assembly is the expected answer, and it must be a
    # genuine debug stamp or the comparison proves nothing.
    printed = _DEBUGGABLE_CA_RE.search(_monodis_file(debug_build, "--customattr"))
    assert printed, "mcs -debug+ stamps DebuggableAttribute"
    referee_modes = int(printed.group(1))
    assert referee_modes & 0x100, "a debug build disables JIT optimizations"
    debuggable = _session_debuggable(tmp_path, debug_build)
    assert debuggable is not None
    assert debuggable["modes"] == referee_modes
    assert debuggable["jit_optimizer_disabled"] is True

    # Leg 2: the release build. The referee sees no attribute; the session
    # must answer None rather than inventing a zero-mode claim.
    assert _DEBUGGABLE_CA_RE.search(_monodis_file(release_build, "--customattr")) is None
    assert _session_debuggable(tmp_path, release_build) is None

    # Leg 3: the 1.x (bool, bool) shape out of the fixture builder. Mono
    # prints the two booleans it decoded; the session must fold them the way
    # the runtime does -- tracking to Default, the optimizer flag to
    # DisableOptimizations -- and nothing else.
    import importlib.util

    builder = _FIXTURE.parent / "build_minimal_dotnet.py"
    spec = importlib.util.spec_from_file_location("_dotnet_builder", builder)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    legacy = tmp_path / "legacy_debuggable.exe"
    legacy.write_bytes(module.build(debuggable=(True, False)))
    printed = _DEBUGGABLE_CA_RE.search(_monodis_file(legacy, "--customattr"))
    assert printed, "monodis decodes the (bool, bool) .ctor variant"
    assert printed.group(1) == "true, false"
    assert _session_debuggable(tmp_path, legacy) == {
        "modes": 0x001,
        "jit_tracking": True,
        "edit_and_continue": False,
        "jit_optimizer_disabled": False,
    }


# monodis --exported prints each ExportedType row as
# "1: Real.Thing is in assemblyref 1, index=0, flags=0x200000".
_EXPORTED_RE = re.compile(
    r"^\d+: (\S+) is in assemblyref (\d+), index=\d+, flags=0x([0-9a-fA-F]+)$", re.M
)


@pytest.mark.integration
def test_session_type_forwards_agree_with_monodis(tmp_path: Path) -> None:
    """The managed API-redirection surface against monodis --exported.

    A session now reads forwarder ExportedType rows -- the .NET pair to PE
    forwarded exports and Mach-O reexported dylibs, and the mechanism real
    facade assemblies (System.Runtime) are built from. The 0x27 table walk,
    the tdForwarder filter and the Implementation coded-index decode are all
    ours, so a real compiler provides the rows: mcs builds a library and a
    facade that TypeForwardedTo-redirects two of its types (one namespaced,
    one bare), and monodis --exported must print exactly the rows the reader
    hands back -- type for type, destination assembly for destination
    assembly, through monodis's own assemblyref resolution. The library
    itself must read the honest empty list. skip != pass.
    """
    if shutil.which("monodis") is None:
        pytest.skip("monodis (mono-utils) not installed — .NET cross-check not run (skip != pass)")
    mcs = shutil.which("mcs")
    if mcs is None:
        pytest.skip("mcs (mono-mcs) not installed — compiler assembly gate not run (skip != pass)")

    lib_source = tmp_path / "real_home.cs"
    lib_source.write_text(
        "namespace Real { public class Thing { public static int N() { return 1; } } }\n"
        "public class Bare { }\n"
    )
    library = tmp_path / "real_home.dll"
    subprocess.run(
        [mcs, "-target:library", f"-out:{library}", str(lib_source)],
        check=True,
        capture_output=True,
        timeout=120,
    )
    facade_source = tmp_path / "facade.cs"
    facade_source.write_text(
        "using System.Runtime.CompilerServices;\n"
        "[assembly: TypeForwardedTo(typeof(Real.Thing))]\n"
        "[assembly: TypeForwardedTo(typeof(Bare))]\n"
    )
    facade = tmp_path / "facade.dll"
    subprocess.run(
        [mcs, "-target:library", f"-r:{library}", f"-out:{facade}", str(facade_source)],
        check=True,
        capture_output=True,
        timeout=120,
    )

    # The referee's view: every forwarder row (flag 0x00200000), its type name
    # and its destination resolved through monodis's own assemblyref dump.
    ref_dump = _monodis_file(facade, "--assemblyref")
    ref_names = [name for _version, name in _ASSEMBLYREF_RE.findall(ref_dump)]
    expected = []
    for full_name, ref_index, flags in _EXPORTED_RE.findall(_monodis_file(facade, "--exported")):
        if int(flags, 16) & 0x00200000:
            expected.append({"type": full_name, "assembly": ref_names[int(ref_index) - 1]})
    # Referee sanity: both forwards landed, pointing at the real library.
    assert {"type": "Real.Thing", "assembly": "real_home"} in expected, expected
    assert {"type": "Bare", "assembly": "real_home"} in expected, expected

    service = _service(tmp_path)
    try:
        created = service.create_session(str(facade))
        assert created.ok, created.error
        assert created.data["session"]["metadata"]["dotnet"]["type_forwards"] == expected

        # The library forwards nothing: the empty list, not an invention.
        created = service.create_session(str(library))
        assert created.ok, created.error
        assert created.data["session"]["metadata"]["dotnet"]["type_forwards"] == []
    finally:
        service.close_all()
