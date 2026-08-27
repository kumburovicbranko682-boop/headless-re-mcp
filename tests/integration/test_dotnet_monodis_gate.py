"""Cross-validate the pure-Python .NET reader against Mono's monodis.

The other metadata gate (``test_dotnet_metadata_gate``) proves the pure-Python
ECMA-335 reader against the committed ``minimal_assembly.exe`` -- but that
fixture is built by our own ``build_minimal_dotnet.py`` and read by our own
``clr_inspect``, so a shared assumption between builder and reader would pass
unseen, and nothing proves the fixture is a genuine assembly rather than
something only our reader accepts. This gate closes that loop with an
independent parser: Mono's ``monodis`` must parse the same file and agree on
every identity fact the reader surfaces -- assembly name and version, module
name, MVID, and the type list. It is the .NET analogue of the native gate
cross-checking the entry point against radare2 and Ghidra, and the proxy gate
cross-checking the HAR reader against real mitmproxy output.

monodis ships in Debian/Ubuntu's ``mono-utils``; skip != pass -- the gate skips,
naming the missing tool, only when monodis is not installed.
"""

from __future__ import annotations

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


def _monodis(*args: str) -> str:
    result = subprocess.run(
        ["monodis", *args, str(_FIXTURE)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    # monodis exits 0 and writes the dump to stdout; stderr carries only the
    # signature-parse warnings our minimal method blobs trigger, which this gate
    # does not read.
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
        # The dependency list, ref for ref: name and compiled-against version
        # must both match Mono's decode of the same AssemblyRef rows.
        reader_refs = {(ref["name"], ref["version"]) for ref in facts["assembly_refs"]}
        assert reader_refs == mono_refs

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
