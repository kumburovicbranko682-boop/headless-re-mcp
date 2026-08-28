from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import headless_re_mcp.cli as cli_module
import headless_re_mcp.core.capabilities_catalog as capabilities_module
from headless_re_mcp.backends.windbg.client import WindbgError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.readiness import readiness_report
from headless_re_mcp.core.service_ext import _windbg_client
from headless_re_mcp.core.service_ui import _unsupported_ui
from headless_re_mcp.doctor import DoctorReport, Probe, ProbeStatus
from headless_re_mcp.platform_support import runtime_platform_report


def test_linux_x86_64_platform_report_names_core_scope() -> None:
    report = runtime_platform_report(
        os_name="posix",
        system="Linux",
        machine="x86_64",
    )

    assert report["core_supported"] is True
    assert report["support_level"] == "core"
    assert report["package_format"] == "wheel_or_sdist"
    assert report["windows_only_status"] == "unsupported_on_platform"


def test_linux_non_x86_64_is_not_claimed_supported() -> None:
    report = runtime_platform_report(
        os_name="posix",
        system="Linux",
        machine="aarch64",
    )

    assert report["core_supported"] is False
    assert report["support_level"] == "unsupported"


@pytest.mark.skipif(sys.platform != "linux", reason="Linux installer contract")
def test_linux_installer_resolves_repo_independently_of_working_directory(
    tmp_path: Path,
) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    captured_requirement = tmp_path / "requirement.txt"
    fake_python = tmp_path / "python"
    fake_python.write_text(
        """#!/usr/bin/env bash
set -euo pipefail
if [[ "${1-}" == "-c" ]]; then
  exit 0
fi
if [[ "${1-}" == "-m" && "${2-}" == "pip" ]]; then
  printf '%s' "${5-}" > "${CAPTURE_REQUIREMENT}"
fi
""",
        encoding="utf-8",
    )
    fake_python.chmod(0o755)

    env = os.environ.copy()
    env["PYTHON"] = str(fake_python)
    env["CAPTURE_REQUIREMENT"] = str(captured_requirement)
    subprocess.run(
        [str(repo_root / "scripts" / "install-linux.sh")],
        cwd=tmp_path,
        env=env,
        check=True,
    )

    assert captured_requirement.read_text(encoding="utf-8") == f"{repo_root}[pe,web]"


def _installer_harness(tmp_path: Path) -> tuple[dict[str, str], dict[str, Path]]:
    """Fake python/sudo/apt-get/curl/unzip so installer runs capture side effects only."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_python = bin_dir / "python"
    # The editable install is the pip call with -e; every other pip invocation
    # (PyGhidra) is appended to its own log so neither capture clobbers the
    # other.
    fake_python.write_text(
        """#!/usr/bin/env bash
set -euo pipefail
if [[ "${1-}" == "-c" ]]; then
  if [[ "${2-}" == *playwright* ]]; then
    exit "${FAKE_PLAYWRIGHT_MISSING:-0}"
  fi
  exit 0
fi
if [[ "${1-}" == "-m" && "${2-}" == "pip" ]]; then
  if [[ "${4-}" == "-e" ]]; then
    printf '%s' "${5-}" > "${CAPTURE_REQUIREMENT}"
  else
    printf '%s\\n' "$*" >> "${CAPTURE_PIP_OTHER}"
  fi
fi
if [[ "${1-}" == "-m" && "${2-}" == "playwright" ]]; then
  printf '%s' "$*" > "${CAPTURE_PLAYWRIGHT}"
fi
""",
        encoding="utf-8",
    )
    fake_python.chmod(0o755)
    fake_sudo = bin_dir / "sudo"
    fake_sudo.write_text('#!/usr/bin/env bash\nexec "$@"\n', encoding="utf-8")
    fake_sudo.chmod(0o755)
    fake_apt = bin_dir / "apt-get"
    fake_apt.write_text(
        '#!/usr/bin/env bash\nprintf \'%s\\n\' "$*" >> "${CAPTURE_APT}"\n',
        encoding="utf-8",
    )
    fake_apt.chmod(0o755)
    fake_curl = bin_dir / "curl"
    fake_curl.write_text(
        """#!/usr/bin/env bash
printf '%s\\n' "$*" >> "${CAPTURE_CURL}"
exit "${FAKE_CURL_FAIL:-0}"
""",
        encoding="utf-8",
    )
    fake_curl.chmod(0o755)
    fake_unzip = bin_dir / "unzip"
    fake_unzip.write_text(
        '#!/usr/bin/env bash\nprintf \'%s\\n\' "$*" >> "${CAPTURE_UNZIP}"\n',
        encoding="utf-8",
    )
    fake_unzip.chmod(0o755)

    captures = {
        "requirement": tmp_path / "requirement.txt",
        "playwright": tmp_path / "playwright.txt",
        "apt": tmp_path / "apt.txt",
        "pip_other": tmp_path / "pip_other.txt",
        "curl": tmp_path / "curl.txt",
        "unzip": tmp_path / "unzip.txt",
    }
    env = os.environ.copy()
    env["PYTHON"] = str(fake_python)
    env["PATH"] = f"{bin_dir}:{env['PATH']}"
    env["CAPTURE_REQUIREMENT"] = str(captures["requirement"])
    env["CAPTURE_PLAYWRIGHT"] = str(captures["playwright"])
    env["CAPTURE_APT"] = str(captures["apt"])
    env["CAPTURE_PIP_OTHER"] = str(captures["pip_other"])
    env["CAPTURE_CURL"] = str(captures["curl"])
    env["CAPTURE_UNZIP"] = str(captures["unzip"])
    # Point the Ghidra unpack root into the sandbox so an opt-in run neither
    # finds a real ~/ghidra (skipping the download this harness observes) nor
    # writes outside tmp_path.
    env["HEADLESS_RE_GHIDRA_ROOT"] = str(tmp_path / "ghidra-root")
    env.pop("HEADLESS_RE_EXTRAS", None)
    env.pop("HEADLESS_RE_INSTALL_BACKENDS", None)
    env.pop("HEADLESS_RE_INSTALL_GHIDRA", None)
    env.pop("FAKE_PLAYWRIGHT_MISSING", None)
    env.pop("FAKE_CURL_FAIL", None)
    return env, captures


def _run_installer(tmp_path: Path, env: dict[str, str]) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    subprocess.run(
        [str(repo_root / "scripts" / "install-linux.sh")],
        cwd=tmp_path,
        env=env,
        check=True,
    )


@pytest.mark.skipif(sys.platform != "linux", reason="Linux installer contract")
def test_linux_installer_fetches_the_playwright_browser_when_present(
    tmp_path: Path,
) -> None:
    """A Playwright install without its browser cannot drive web.* at all."""
    env, captures = _installer_harness(tmp_path)

    _run_installer(tmp_path, env)

    recorded = captures["playwright"].read_text(encoding="utf-8")
    assert recorded == "-m playwright install chromium"


@pytest.mark.skipif(sys.platform != "linux", reason="Linux installer contract")
def test_linux_installer_skips_the_browser_fetch_without_playwright(
    tmp_path: Path,
) -> None:
    env, captures = _installer_harness(tmp_path)
    env["FAKE_PLAYWRIGHT_MISSING"] = "1"

    _run_installer(tmp_path, env)

    assert not captures["playwright"].exists()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux installer contract")
def test_linux_installer_backend_provisioning_is_opt_in_and_mirrors_ci(
    tmp_path: Path,
) -> None:
    """The FOSS backend set the installer provisions is the set CI proves."""
    env, captures = _installer_harness(tmp_path)

    _run_installer(tmp_path, env)
    assert not captures["apt"].exists(), "backend provisioning must stay opt-in"

    env["HEADLESS_RE_INSTALL_BACKENDS"] = "1"
    _run_installer(tmp_path, env)

    lines = captures["apt"].read_text(encoding="utf-8").splitlines()
    assert lines[0] == "update"
    install_args = lines[1].split()
    assert install_args[:2] == ["install", "-y"]
    packages = set(install_args[2:])
    assert {"radare2", "upx-ucl", "wabt", "apktool", "apksigner", "adb"} <= packages

    repo_root = Path(__file__).resolve().parents[2]
    ci_text = (repo_root / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    ci_packages = {
        package
        for line in ci_text.splitlines()
        if "apt-get install -y" in line
        for package in line.split("apt-get install -y", 1)[1].split()
    }
    assert packages <= ci_packages, "installer provisions a package CI never proves"


def _ci_ghidra_pin(repo_root: Path) -> tuple[str, str]:
    """The (version, date) of the Ghidra release the CI workflow installs."""
    ci_text = (repo_root / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    version = re.search(r"GHIDRA_VERSION=(\S+)", ci_text)
    date = re.search(r"GHIDRA_DATE=(\S+)", ci_text)
    assert version and date, "ci.yml no longer pins a Ghidra release"
    return version.group(1), date.group(1)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux installer contract")
def test_linux_installer_ghidra_provisioning_is_opt_in_and_pins_the_ci_release(
    tmp_path: Path,
) -> None:
    """The Ghidra the installer fetches is the exact release CI proves.

    Ghidra is the one portable backend apt cannot supply, so the installer
    fetches an upstream release -- but an installer pin that drifts from the
    CI pin hands users a Ghidra no gate ever ran against, which is how the
    r2 5.x/6.x key drift shipped. This drives the real script against a fake
    curl/unzip/pip and asserts three things: nothing is fetched without the
    switch, the download URL names CI's exact version+date, and PyGhidra is
    installed --no-index from the wheels that same release vendors.
    """
    env, captures = _installer_harness(tmp_path)

    _run_installer(tmp_path, env)
    assert not captures["curl"].exists(), "Ghidra provisioning must stay opt-in"

    env["HEADLESS_RE_INSTALL_GHIDRA"] = "1"
    _run_installer(tmp_path, env)

    repo_root = Path(__file__).resolve().parents[2]
    version, date = _ci_ghidra_pin(repo_root)
    (curl_line,) = captures["curl"].read_text(encoding="utf-8").splitlines()
    expected_url = (
        "https://github.com/NationalSecurityAgency/ghidra/releases/download/"
        f"Ghidra_{version}_build/ghidra_{version}_PUBLIC_{date}.zip"
    )
    assert expected_url in curl_line, curl_line

    ghidra_home = tmp_path / "ghidra-root" / f"ghidra_{version}_PUBLIC"
    (unzip_line,) = captures["unzip"].read_text(encoding="utf-8").splitlines()
    assert f"-d {tmp_path / 'ghidra-root'}" in unzip_line, unzip_line

    (pip_line,) = captures["pip_other"].read_text(encoding="utf-8").splitlines()
    assert "--no-index" in pip_line and pip_line.endswith("pyghidra"), pip_line
    assert str(ghidra_home / "Ghidra" / "Features" / "PyGhidra" / "pypkg" / "dist") in pip_line


@pytest.mark.skipif(sys.platform != "linux", reason="Linux installer contract")
def test_linux_installer_ghidra_download_failure_is_best_effort(
    tmp_path: Path,
) -> None:
    """A failed Ghidra fetch warns and moves on; it must not abort the install
    (set -e) or claim PyGhidra against a home that does not exist."""
    env, captures = _installer_harness(tmp_path)
    env["HEADLESS_RE_INSTALL_GHIDRA"] = "1"
    env["FAKE_CURL_FAIL"] = "22"

    _run_installer(tmp_path, env)

    assert captures["curl"].exists(), "the fetch was attempted"
    assert not captures["pip_other"].exists(), (
        "PyGhidra must not be installed when the Ghidra download failed"
    )


@pytest.mark.skipif(os.name == "nt", reason="Linux platform defaults")
def test_linux_settings_do_not_enable_hidden_desktop_by_default(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("HEADLESS_RE_HIDDEN_DESKTOP", raising=False)
    settings = Settings.load(config_path=tmp_path / "missing.json")

    assert settings.hidden_desktop is False


@pytest.mark.skipif(os.name == "nt", reason="Linux readiness contract")
def test_linux_readiness_reports_core_platform_scope(tmp_path: Path) -> None:
    class Repository:
        def list_unclean_sessions(
            self,
            *,
            offset: int = 0,
            limit: int = 100,
        ) -> list[object]:
            del offset, limit
            return []

        def check_writable(self) -> None:
            return None

    report = readiness_report(
        repository=Repository(),
        artifact_root=tmp_path / "artifacts",
        open_sessions=0,
        backends=[],
        telemetry_log=None,
    )

    assert report["ready"] is True
    assert report["platform"]["name"] == "linux"
    assert report["platform"]["support_level"] == "core"
    assert report["platform"]["windows_only_status"] == "unsupported_on_platform"


@pytest.mark.skipif(os.name == "nt", reason="Linux platform contract")
def test_x64dbg_gate_cli_returns_platform_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = cli_module.main(["gate-xdbg", "--architecture", "x64"])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert payload["results"][0]["error"]["code"] == "unsupported_on_platform"


@pytest.mark.skipif(os.name == "nt", reason="Linux platform contract")
def test_windows_only_service_helpers_return_platform_errors(tmp_path: Path) -> None:
    with pytest.raises(WindbgError) as caught:
        _windbg_client(SimpleNamespace(settings=SimpleNamespace(cdb=tmp_path / "cdb")))
    assert caught.value.code == "unsupported_on_platform"

    ui = _unsupported_ui("session", "ui.windows.list")
    assert ui.ok is False
    assert ui.error is not None
    assert ui.error.code == "unsupported_on_platform"
    assert ui.error.details["current_platform"] == "linux"


def test_capability_catalog_uses_unsupported_probe_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = DoctorReport(
        (
            Probe("platform", ProbeStatus.READY, "supported"),
            Probe("python", ProbeStatus.READY, "supported"),
            Probe("x64dbg_headless_binaries", ProbeStatus.UNSUPPORTED, "Windows only"),
            Probe("win32_ui", ProbeStatus.UNSUPPORTED, "Windows only"),
            Probe("windbg", ProbeStatus.UNSUPPORTED, "Windows only"),
        ),
        required_probes=frozenset({"platform", "python"}),
    )
    monkeypatch.setattr(capabilities_module, "run_doctor", lambda _settings=None: report)

    statuses = {
        item["id"]: item["status"]
        for item in capabilities_module.list_capabilities()
    }
    assert statuses["x64dbg.headless"] == "unsupported_on_platform"
    assert statuses["ui.win32"] == "unsupported_on_platform"
    assert statuses["windbg.cdb"] == "unsupported_on_platform"


# PE / .NET / IDA static gates that are not Windows-only (they run on Linux)
# yet do not belong in the portable non-PE Linux CI job: each needs a
# proprietary backend (IDA) or a PE/.NET fixture and self-skips on a plain
# Linux runner, so listing them would only add skips. Kept explicit so the
# partition below is total -- every integration gate is classified exactly
# once, which is what forces a newly added portable gate into the CI list.
_PE_STATIC_EXCLUDED_FROM_LINUX_CI = frozenset(
    {
        "test_dotnet_m6_gate.py",
        "test_idalib_gate.py",
        "test_m8_static_batch1_gate.py",
        "test_m8_static_write_gate.py",
        "test_mcp_static_idalib.py",
    }
)


def _windows_only_modules(conftest_path: Path) -> set[str]:
    """Read _WINDOWS_ONLY_MODULES from the integration conftest without importing it.

    ast-parsing avoids importing a pytest conftest as a plain module (which
    would register its fixtures/hooks); the value is a frozenset literal of
    string constants, so pulling the constants straight out of the assignment
    is exact and has no runtime dependency on pytest collection.
    """
    tree = ast.parse(conftest_path.read_text(encoding="utf-8"))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(
            isinstance(target, ast.Name) and target.id == "_WINDOWS_ONLY_MODULES"
            for target in node.targets
        ):
            continue
        # frozenset({...}) -> the set literal is the sole call argument.
        call = node.value
        assert isinstance(call, ast.Call), "expected frozenset(...) literal"
        (set_literal,) = call.args
        assert isinstance(set_literal, ast.Set)
        return {
            element.value
            for element in set_literal.elts
            if isinstance(element, ast.Constant) and isinstance(element.value, str)
        }
    raise AssertionError("_WINDOWS_ONLY_MODULES not found in integration conftest")


def _linux_ci_gate_list(ci_yaml: str) -> list[str]:
    """The integration gate filenames the linux-integration job runs.

    ci.yml references tests/integration test files in exactly one place -- the
    'Non-PE integration gates' step -- so every such token in the file is a
    member of that explicit list. Returned as a list so a duplicate entry
    (a real copy-paste mistake) is visible to the caller.
    """
    return re.findall(r"tests/integration/(test_[a-z0-9_]+\.py)", ci_yaml)


def test_every_integration_gate_is_classified_for_linux_ci() -> None:
    """Adding a portable gate without wiring CI must fail here, not go unnoticed.

    The linux-integration job runs an explicit file list, so a new non-PE gate
    that is not added to it simply never runs in CI -- silent, since the job
    still goes green on the gates it does list. Enforce a total partition of
    every tests/integration gate into exactly one of: Windows-only (skipped by
    the conftest on Linux), PE/IDA-static (self-skips, excluded by design), or
    the Linux CI list. A gate that falls in none, or in two, fails this test.
    """
    repo_root = Path(__file__).resolve().parents[2]
    integration_dir = repo_root / "tests" / "integration"
    all_gates = {path.name for path in integration_dir.glob("test_*.py")}

    windows_only = _windows_only_modules(integration_dir / "conftest.py")
    ci_yaml = (repo_root / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    ci_list = _linux_ci_gate_list(ci_yaml)
    ci_set = set(ci_list)

    # A duplicated or stale (nonexistent) CI entry is itself a bug.
    assert len(ci_list) == len(ci_set), f"duplicate entry in the linux CI gate list: {ci_list}"
    missing_files = ci_set - all_gates
    assert not missing_files, (
        f"linux CI lists gate files that do not exist: {sorted(missing_files)}"
    )

    # The exclusion buckets must not name a gate that no longer exists either.
    # A stale entry outlives the file it excused, and later silently re-excuses a
    # new gate that reuses the name -- the same silent skip this partition guards
    # against, just entered through the exclusion list instead of omission.
    stale_windows_only = windows_only - all_gates
    assert not stale_windows_only, (
        "_WINDOWS_ONLY_MODULES names integration gates that no longer exist: "
        f"{sorted(stale_windows_only)}"
    )
    stale_pe_static = _PE_STATIC_EXCLUDED_FROM_LINUX_CI - all_gates
    assert not stale_pe_static, (
        "_PE_STATIC_EXCLUDED_FROM_LINUX_CI names integration gates that no longer exist: "
        f"{sorted(stale_pe_static)}"
    )

    classified = ci_set | windows_only | _PE_STATIC_EXCLUDED_FROM_LINUX_CI
    unclassified = all_gates - classified
    assert not unclassified, (
        "these integration gates are classified nowhere -- add each to the "
        "linux-integration job in ci.yml (portable non-PE), to _WINDOWS_ONLY_MODULES "
        "in the integration conftest, or to _PE_STATIC_EXCLUDED_FROM_LINUX_CI: "
        f"{sorted(unclassified)}"
    )

    # The three buckets must not overlap, or the classification is ambiguous.
    assert not (ci_set & windows_only), sorted(ci_set & windows_only)
    assert not (ci_set & _PE_STATIC_EXCLUDED_FROM_LINUX_CI), sorted(
        ci_set & _PE_STATIC_EXCLUDED_FROM_LINUX_CI
    )
    assert not (windows_only & _PE_STATIC_EXCLUDED_FROM_LINUX_CI), sorted(
        windows_only & _PE_STATIC_EXCLUDED_FROM_LINUX_CI
    )
