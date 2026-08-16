from __future__ import annotations

import ast
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_every_tool_tells_the_model_what_it_does() -> None:
    """A tool with no docstring reaches the model as its own name and nothing else.

    That is not a documentation gap, it is a correctness one for a caller with
    nobody to ask. Measured over the live stdio transport: 33 of 263 tools
    arrived with no description, and the names of several actively mislead --
    sessions.unclean lists every open session including the ones in use, and
    frida.attach detaches before the reply is read.
    """
    undescribed: list[str] = []
    for path in sorted((ROOT / "src" / "headless_re_mcp" / "tools").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            name = _tool_name(node)
            if name is not None and ast.get_docstring(node) is None:
                undescribed.append(name)

    assert not undescribed, f"these tools reach the model as a bare name: {undescribed}"


def _tool_name(node: ast.FunctionDef) -> str | None:
    """The name a @tools.tool(name=...) decorator publishes, if there is one."""
    for decorator in node.decorator_list:
        if not isinstance(decorator, ast.Call):
            continue
        target = decorator.func
        if not (isinstance(target, ast.Attribute) and target.attr == "tool"):
            continue
        for keyword in decorator.keywords:
            if keyword.arg == "name" and isinstance(keyword.value, ast.Constant):
                return str(keyword.value.value)
    return None


def test_public_root_and_script_entries_are_deliberately_small() -> None:
    """Pin the entry points so the root and scripts/ cannot silently accumulate.

    Exact sets rather than a size bound: the point is that adding a new public
    entry point is a decision someone has to make on purpose.
    """
    root_python = {path.name for path in ROOT.glob("*.py")}
    assert root_python == {"setup.py", "start_web.py", "openai_bridge.py"}
    release_scripts = {path.name for path in (ROOT / "scripts").iterdir() if path.is_file()}
    assert release_scripts == {
        "release.ps1",
        "sync_upstream.ps1",
        "pack_upx.ps1",
        "build_deps_bundle.ps1",
        "build_handoff_zip.ps1",
        "build_msi.ps1",
        "build_native_portable.ps1",
        "build_portable.ps1",
        "install_die_portable.ps1",
        "install_service.ps1",
        "sync_external_x64dbg.ps1",
        "verify_msi.ps1",
    }


def test_no_root_python_entry_still_references_the_retired_bootstrap() -> None:
    """first_setup.py was replaced by setup.py; nothing may still call it."""
    searched = [*ROOT.glob("*.py"), *(ROOT / "scripts").glob("*.ps1"), ROOT / "README.md"]
    offenders = [
        path.name
        for path in searched
        if path.is_file() and "first_setup" in path.read_text(encoding="utf-8")
    ]
    assert offenders == []


def test_git_does_not_track_generated_or_temporary_files() -> None:
    completed = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        capture_output=True,
        check=True,
    )
    tracked = [Path(item) for item in completed.stdout.decode().split("\0") if item]
    banned_parts = {
        "node_modules",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".tmp",
        "tmp",
        "temp",
        "build",
        "dist",
    }
    banned_suffixes = {
        ".pyc",
        ".pyo",
        ".log",
        ".tmp",
        ".bak",
        ".dmp",
        ".idb",
        ".i64",
        ".msi",
        ".whl",
        ".wixobj",
    }
    offenders = [
        str(path)
        for path in tracked
        if banned_parts.intersection(path.parts) or path.suffix.lower() in banned_suffixes
    ]
    assert offenders == []


def test_gitignore_covers_local_build_and_test_residue() -> None:
    ignored = (ROOT / ".gitignore").read_text(encoding="utf-8")
    for required in (
        "node_modules/",
        "__pycache__/",
        ".pytest_cache/",
        ".mypy_cache/",
        ".ruff_cache/",
        ".tmp-*/",
        "*.tmp",
        "*.part",
        "artifacts/*",
    ):
        assert required in ignored


def _spawn_call_sites() -> list[tuple[Path, int, str]]:
    """Every subprocess-spawning call under src/, with how it was invoked."""
    import ast

    spawners = {"run", "Popen", "call", "check_call", "check_output"}
    sites: list[tuple[Path, int, str]] = []
    for path in sorted((ROOT / "src").rglob("*.py")):
        # utf-8-sig so this reports on spawning, not on an unrelated BOM.
        tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
        # Names that hold window-suppressing kwargs, so `**opts` can be trusted.
        suppressors = {"no_window_popen_kwargs", "_creation_options"}
        carriers: set[str] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            for target in node.targets:
                # opts = no_window_popen_kwargs()
                if (
                    isinstance(target, ast.Name)
                    and isinstance(node.value, ast.Call)
                    and isinstance(node.value.func, ast.Name)
                    and node.value.func.id in suppressors
                ):
                    carriers.add(target.id)
                # opts["creationflags"] = ... , the other idiom in this repo
                if (
                    isinstance(target, ast.Subscript)
                    and isinstance(target.value, ast.Name)
                    and isinstance(target.slice, ast.Constant)
                    and target.slice.value == "creationflags"
                ):
                    carriers.add(target.value.id)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not isinstance(func, ast.Attribute) or func.attr not in spawners:
                continue
            if not (isinstance(func.value, ast.Name) and func.value.id == "subprocess"):
                continue
            how = "unsuppressed"
            for kw in node.keywords:
                if kw.arg == "creationflags":
                    how = "creationflags"
                    break
                if kw.arg is None:  # **kwargs
                    value = kw.value
                    unpacks_helper_call = (
                        isinstance(value, ast.Call)
                        and isinstance(value.func, ast.Name)
                        and value.func.id in suppressors
                    )
                    unpacks_carrier = isinstance(value, ast.Name) and value.id in carriers
                    if unpacks_helper_call or unpacks_carrier:
                        how = "helper"
                        break
            sites.append((path.relative_to(ROOT), node.lineno, how))
    return sites


def test_every_spawned_subprocess_suppresses_its_console_window() -> None:
    """No call under src/ may pop a console window on Windows.

    This service is built to run unattended, often over RDP or as a scheduled
    task, and it spawns constantly: debugger backends, unpackers, detectors,
    the supervisor's own child on every restart, the isolation step on every
    sample. One unsuppressed spawn means a window appearing on someone's
    desktop -- and in a restart loop, a window every few seconds.

    Enforced statically because the flag is easy to forget on a new call site
    and the symptom only shows on Windows, so it survives review on any other
    platform.
    """
    offenders = [
        f"{path}:{line}" for path, line, how in _spawn_call_sites() if how == "unsuppressed"
    ]
    assert offenders == [], (
        "these spawn a visible console window; pass **no_window_popen_kwargs() "
        f"or creationflags=: {offenders}"
    )


def test_the_console_suppression_guard_can_actually_see_a_violation() -> None:
    """Guard the guard: a parser that matches nothing would pass silently."""
    sites = _spawn_call_sites()
    assert len(sites) >= 10, f"expected to find the known spawn sites, saw {len(sites)}"
    assert {how for _, _, how in sites} <= {"creationflags", "helper", "unsuppressed"}
    assert any(how == "helper" for _, _, how in sites)
    assert any(how == "creationflags" for _, _, how in sites)

def test_every_long_lived_backend_ties_its_worker_to_this_process() -> None:
    """A worker that outlives the service is a leak nothing later can reach.

    Both of these hold a debugger for the life of a session: idalib keeps the
    database in memory and is measured in gigabytes, and x64dbg owns the
    debuggee. A hard kill of the service -- which is what stopping a scheduled
    task does, and what the supervisor's own job object now does to it -- runs
    no cleanup, so an ungrouped worker survives with nothing attached to it.
    """
    import ast

    owners = (
        ROOT / "src" / "headless_re_mcp" / "backends" / "ida" / "client.py",
        ROOT / "src" / "headless_re_mcp" / "backends" / "x64dbg" / "client.py",
        # The CLI tools go through one runner, and the same argument applies to
        # them: jadx, apktool and Ghidra start a JVM that will happily keep
        # analysing a sample after the service that asked for it is gone.
        ROOT / "src" / "headless_re_mcp" / "backends" / "common" / "bounded_run.py",
    )
    for path in owners:
        tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
        grouped = any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "assign_to_process_group"
            for node in ast.walk(tree)
        )
        assert grouped, f"{path.relative_to(ROOT)} spawns a worker without grouping it"


def test_no_python_source_is_written_in_the_wrong_encoding() -> None:
    """A BOM is invisible in an editor and breaks tools that read plain UTF-8.

    CPython tolerates one, so a BOM'd file imports and tests green while any
    tool doing read_text("utf-8") -> ast.parse dies on U+FEFF. Twenty-two files
    had picked one up from an editor writing UTF-8-with-signature, which is the
    kind of damage that stays invisible until something downstream trips on it.

    The NUL check is the same failure without the marker in front of it: a file
    written as UTF-16 with no BOM looks like text with a NUL after every
    character, and CPython does not tolerate that at all. Checking only the
    first four bytes missed it, because there is nothing distinctive there.
    """
    offenders = []
    for path in [*(ROOT / "src").rglob("*.py"), *(ROOT / "tests").rglob("*.py")]:
        raw = path.read_bytes()
        if raw.startswith(b"\xef\xbb\xbf"):
            offenders.append(f"{path.relative_to(ROOT)} (utf-8 BOM)")
        elif raw.startswith((b"\xff\xfe", b"\xfe\xff")):
            offenders.append(f"{path.relative_to(ROOT)} (utf-16 BOM -- file is corrupt)")
        elif b"\x00" in raw:
            offenders.append(f"{path.relative_to(ROOT)} (NUL byte -- probably utf-16, no BOM)")
    assert offenders == [], f"rewrite as plain UTF-8: {offenders}"


def test_session_recover_warns_that_it_replaces_the_session() -> None:
    """Recovery hands back a different session id, and the old one is dead.

    Measured against a killed IDA worker: recover answers ok with a new
    session_id, the old id answers invalid_request from then on, and asking to
    recover the old id again is refused the same way. A caller that keeps its
    original id is stuck with no way back, and the only thing that tells it
    otherwise is a field in the reply it has no reason to read.
    """
    source = (ROOT / "src" / "headless_re_mcp" / "tools" / "meta.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    described = ""
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and _tool_name(node) == "session.recover":
            described = ast.get_docstring(node) or ""
    assert described, "session.recover must describe itself"
    assert "replaced is true" in described
    assert "new session_id" in described or "previous_session_id" in described
    assert "invalid_request" in described
