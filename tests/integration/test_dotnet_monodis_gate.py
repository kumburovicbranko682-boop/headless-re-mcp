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
