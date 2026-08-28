"""No code in the package may run a command through a shell.

Every subprocess in ``headless_re_mcp`` is spawned from an argv *list* handed
straight to ``exec`` -- never through ``/bin/sh``. That is what makes the whole
tool surface injection-safe by construction: a caller-supplied path, package id
or filter is one element of ``argv`` and cannot be reparsed into extra commands,
so there is no host-side analogue of the device-shell hazard the adb injection
guard polices. (adbutils' ``device.shell`` reaches a shell on the *device*; that
surface is frozen separately in ``test_adb_shell_command_injection_guard``.)

A few PE-line adapters already assert their own ``_creation_options()["shell"]``
is ``False`` (``test_upx``, ``test_detection_exeinfope``, ``test_detection_die``),
but that is per-call prose: it says nothing about the non-PE backends -- jsre,
apktool, jadx, adb, and the shared ``bounded_run`` runner -- that also spawn CLI
tools, and it would not notice a brand-new module shelling out. This guard lifts
the invariant to the whole package with one AST scan, so the moment any file --
PE or not -- introduces ``shell=True``, a ``"shell": True`` creation-options
entry, or ``os.system`` / ``os.popen``, it fails here rather than shipping a
host command-injection vector.

``shell=False`` is the safe form and is left alone; only a shell that is enabled
(or a dynamic value that *could* be enabled, which review must turn into an
explicit ``False``) is a violation.
"""

from __future__ import annotations

import ast
from pathlib import Path

import headless_re_mcp

_SUBPROCESS_SPAWNERS = frozenset({"Popen", "run", "call", "check_call", "check_output"})


def _package_files() -> list[Path]:
    return sorted(Path(headless_re_mcp.__file__).parent.rglob("*.py"))


def _is_false(node: ast.expr) -> bool:
    """True only for the literal ``False`` -- the one safe value for ``shell``."""
    return isinstance(node, ast.Constant) and node.value is False


def _shell_and_os_exec_violations(
    tree: ast.AST, module: str
) -> tuple[list[str], list[str]]:
    """Return (shell-enabling sites, os.system/os.popen sites) in one module.

    A shell violation is a ``shell=`` keyword or a ``"shell":`` dict entry whose
    value is anything but the literal ``False`` -- ``shell=True`` and a variable
    that could be truthy both count, forcing review to pin it to ``False``.
    """
    shell: list[str] = []
    os_exec: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for keyword in node.keywords:
                if keyword.arg == "shell" and not _is_false(keyword.value):
                    shell.append(f"{module}:{node.lineno} {ast.unparse(node.func)}(shell=...)")
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr in {"system", "popen"}
                and isinstance(func.value, ast.Name)
                and func.value.id == "os"
            ):
                os_exec.append(f"{module}:{node.lineno} {ast.unparse(node)}")
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values, strict=True):
                if (
                    isinstance(key, ast.Constant)
                    and key.value == "shell"
                    and not _is_false(value)
                ):
                    shell.append(f'{module}:{node.lineno} {{"shell": {ast.unparse(value)}}}')
    return shell, os_exec


def _surface_counts(tree: ast.AST) -> tuple[int, int]:
    """(subprocess spawner calls, ``"shell": False`` dict entries) in a module.

    Feeds the non-vacuity check: the first proves the walk reaches real spawn
    sites, the second proves the *dict* arm (which catches a creation-options
    ``"shell": True``) actually sees the ``_creation_options`` dicts it guards.
    """
    subprocess_calls = 0
    shell_false_dicts = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and func.value.id == "subprocess"
                and func.attr in _SUBPROCESS_SPAWNERS
            ):
                subprocess_calls += 1
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values, strict=True):
                if isinstance(key, ast.Constant) and key.value == "shell" and _is_false(value):
                    shell_false_dicts += 1
    return subprocess_calls, shell_false_dicts


def _scan_package() -> tuple[list[str], list[str], int, int]:
    shell: list[str] = []
    os_exec: list[str] = []
    subprocess_calls = 0
    shell_false_dicts = 0
    for path in _package_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        module = path.name
        s, o = _shell_and_os_exec_violations(tree, module)
        shell += s
        os_exec += o
        calls, dicts = _surface_counts(tree)
        subprocess_calls += calls
        shell_false_dicts += dicts
    return shell, os_exec, subprocess_calls, shell_false_dicts


def test_no_code_enables_a_shell() -> None:
    shell, _, _, _ = _scan_package()
    assert shell == [], (
        "these sites run a command through a shell (shell=True or a non-False "
        "shell value), so a caller-supplied argument can be reparsed into extra "
        "commands -- pass an argv list with shell=False instead: " + str(shell)
    )


def test_no_code_calls_os_system_or_os_popen() -> None:
    _, os_exec, _, _ = _scan_package()
    assert os_exec == [], (
        "os.system / os.popen run their argument through a shell; use "
        "subprocess with an argv list and shell=False: " + str(os_exec)
    )


def test_scan_reaches_the_subprocess_surface() -> None:
    """Non-vacuity: a broken walk would let the checks above pass on nothing, so
    pin that the scan actually reaches the spawn sites and creation-options dicts
    it is meant to police."""
    _, _, subprocess_calls, shell_false_dicts = _scan_package()
    assert subprocess_calls >= 10, (
        f"the subprocess scan looks broken, saw only {subprocess_calls} spawn calls"
    )
    assert shell_false_dicts >= 1, (
        "the dict arm never saw a `\"shell\": False` creation-options entry, so a "
        "`\"shell\": True` in such a dict would slip past this guard"
    )


def test_the_guard_catches_synthetic_shell_execution() -> None:
    """Non-vacuity of the detector itself: feed it the exact shapes it must catch
    and confirm each is flagged, so the all-green package result above means the
    invariant holds, not that the checker is inert."""
    keyword = ast.parse("subprocess.Popen(cmd, shell=True)")
    dict_form = ast.parse('subprocess.Popen(cmd, **{\"shell\": True})')
    dynamic = ast.parse("subprocess.run(cmd, shell=flag)")
    system = ast.parse('os.system(f"rm {path}")')
    popen = ast.parse("os.popen(cmd)")

    assert _shell_and_os_exec_violations(keyword, "x")[0], "missed shell=True keyword"
    assert _shell_and_os_exec_violations(dict_form, "x")[0], "missed \"shell\": True dict"
    assert _shell_and_os_exec_violations(dynamic, "x")[0], "missed a dynamic shell= value"
    assert _shell_and_os_exec_violations(system, "x")[1], "missed os.system"
    assert _shell_and_os_exec_violations(popen, "x")[1], "missed os.popen"

    safe = ast.parse('subprocess.Popen(argv, **{"shell": False})')
    assert _shell_and_os_exec_violations(safe, "x") == ([], []), "flagged the safe shell=False form"
