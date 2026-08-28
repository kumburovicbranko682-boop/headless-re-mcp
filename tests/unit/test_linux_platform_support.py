from __future__ import annotations

import json
import os
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


def test_platform_key_recognises_windows_spellings_and_unknown_systems() -> None:
    from headless_re_mcp.platform_support import platform_key

    assert platform_key(os_name="nt", system="Windows") == "windows"
    assert platform_key(os_name="posix", system="Windows") == "windows"
    assert platform_key(os_name="posix", system="Haiku") == "haiku"
    assert platform_key(os_name="java", system="") == "java"
    assert platform_key(os_name="", system="") == "unknown"


def test_a_windows_x86_64_host_reports_full_support() -> None:
    report = runtime_platform_report(
        os_name="nt",
        system="Windows",
        machine="AMD64",
    )

    assert report["core_supported"] is True
    assert report["support_level"] == "full"
    assert report["package_format"] == "wheel_sdist_or_msi"
    assert report["windows_only_status"] == "ready"


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
