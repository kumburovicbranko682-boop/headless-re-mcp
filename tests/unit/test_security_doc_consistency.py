"""SECURITY.md's switch table must keep naming things that exist.

The quick-reference table maps config keys to environment variables and
promises behavior for each. A rename in Settings or in the env plumbing would
leave the security document steering operators at a knob that no longer turns
anything -- the worst place for fiction. The docs also cite specific contract
test files as the thing enforcing those promises; a moved test would turn the
citation into reassurance about a guard that no longer runs.
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path

import pytest

import headless_re_mcp.config as config_module
from headless_re_mcp.config import Settings

ROOT = Path(__file__).resolve().parents[2]


def test_the_switch_table_names_real_settings_fields_and_env_vars() -> None:
    text = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    rows = re.findall(r"^\| `(\w+)`[^|]*\| `(HEADLESS_RE_\w+)` \|", text, re.M)
    assert len(rows) >= 4, "the switch table went missing or was reformatted"

    fields = set(Settings.__dataclass_fields__)
    loader_source = inspect.getsource(config_module)
    for config_key, env_var in rows:
        assert config_key in fields, f"SECURITY.md names a non-existent setting: {config_key}"
        assert f'"{env_var}"' in loader_source, (
            f"SECURITY.md promises {env_var} but config.py never reads it"
        )


@pytest.mark.parametrize("doc", ["SECURITY.md", "README.md", "CONTRIBUTING.md"])
def test_every_test_file_the_docs_cite_exists(doc: str) -> None:
    text = (ROOT / doc).read_text(encoding="utf-8")
    cited = set(re.findall(r"tests/[\w/]+\.py", text))
    if doc == "SECURITY.md":
        assert cited, "SECURITY.md should cite its enforcing contract tests"
    for rel in sorted(cited):
        assert (ROOT / rel).is_file(), f"{doc} cites {rel}, which does not exist"


def _contributing_gate_commands() -> list[str]:
    """The first fenced bash block under CONTRIBUTING's 质量门 header."""
    text = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    after = text.split("## 质量门", 1)[1]
    block = re.search(r"```bash\n(.*?)```", after, re.S)
    assert block is not None, "CONTRIBUTING's 质量门 lost its command block"
    commands = []
    for line in block.group(1).splitlines():
        command = line.split("#", 1)[0].strip()
        if command:
            commands.append(command)
    return commands


def test_the_documented_quality_gate_matches_the_ci_workflow() -> None:
    """CONTRIBUTING tells a contributor to run the CI gate locally.

    If CI renamed a step's command, the documented local gate would drift from
    what actually blocks the PR -- someone runs the doc's command, it passes,
    and CI still rejects them. Pin every documented gate command (comments
    stripped) to a literal occurrence in ci.yml, plus the install extra.
    """
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    commands = _contributing_gate_commands()
    assert commands, "no gate commands parsed from CONTRIBUTING"
    missing = [command for command in commands if command not in ci]
    assert not missing, f"CONTRIBUTING documents gate commands CI does not run: {missing}"

    # The install extra CONTRIBUTING hands new contributors must be the one CI
    # installs, or a fresh clone is set up differently from the gate.
    assert 'pip install -e ".[test,dev,web]"' in ci
    contributing = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    assert 'pip install -e ".[test,dev,web]"' in contributing

    # ...and each of those extras must be a real optional-dependency group, or
    # the documented install line fails on a fresh clone.
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    groups = pyproject.split("[project.optional-dependencies]", 1)[1].split("\n[", 1)[0]
    for extra in ("test", "dev", "web"):
        assert re.search(rf"^{extra} =", groups, re.M), (
            f"documented install extra '{extra}' is not a pyproject optional-dependency"
        )
