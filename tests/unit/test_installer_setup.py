"""The one-click installer's orchestration, download loop and summary.

test_installer.py covers manifest validation, safe extraction and bundle
configuration. Left untested were the download transport itself, the
run_one_click_setup flow that stitches download/extract/configure/IDA/doctor
together, and the summary printer -- the parts a real install actually walks.
These drive them through the module's seams (no network, no real config
writes) so the platform branches, the IDA required/optional split and the
bounded-download refusals run on every platform.
"""

from __future__ import annotations

import io
import os as _real_os
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.installer as installer


class _OsProxy:
    """A stand-in for installer's os module that only overrides ``name``.

    Patching the shared ``os.name`` to ``"nt"`` changes ``Path.home()`` for the
    whole process, and the installer's lazy ``web.setup`` import walks a chain
    that resolves the home directory at import time. Overriding only the
    attribute installer reads keeps that blast radius contained.
    """

    def __init__(self, name: str) -> None:
        self.name = name

    def __getattr__(self, item: str) -> Any:
        return getattr(_real_os, item)


def _set_platform(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    monkeypatch.setattr(installer, "os", _OsProxy(name))


InstallError = installer.InstallError
_download_one = installer._download_one
_find_bundle_root = installer._find_bundle_root
_is_safe_download_url = installer._is_safe_download_url
print_setup_summary = installer.print_setup_summary
run_one_click_setup = installer.run_one_click_setup


# --------------------------------------------------------------------------
# URL safety and bundle-root discovery.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "safe"),
    [
        ("https://example.test/a.zip", True),
        ("http://example.test/a.zip", False),  # not https
        ("https://user:pw@example.test/a.zip", False),  # credentials
        ("https://user@example.test/a.zip", False),  # username only
        ("https:///a.zip", False),  # no host
    ],
)
def test_is_safe_download_url(url: str, safe: bool) -> None:
    assert _is_safe_download_url(url) is safe


def test_find_bundle_root_direct_nested_and_ambiguous(tmp_path: Path) -> None:
    direct = tmp_path / "direct"
    direct.mkdir()
    (direct / "MANIFEST.json").write_text("{}")
    assert _find_bundle_root(direct) == direct.resolve()

    nested = tmp_path / "nested"
    (nested / "inner").mkdir(parents=True)
    (nested / "inner" / "MANIFEST.json").write_text("{}")
    assert _find_bundle_root(nested) == (nested / "inner").resolve()

    ambiguous = tmp_path / "ambiguous"
    (ambiguous / "a").mkdir(parents=True)
    (ambiguous / "b").mkdir(parents=True)
    (ambiguous / "a" / "MANIFEST.json").write_text("{}")
    (ambiguous / "b" / "MANIFEST.json").write_text("{}")
    assert _find_bundle_root(ambiguous) is None

    assert _find_bundle_root(tmp_path / "missing") is None


# --------------------------------------------------------------------------
# _download_one transport.
# --------------------------------------------------------------------------


class _FakeResponse(io.BytesIO):
    def __init__(self, body: bytes, *, status: int = 200, content_length: str | None = None):
        super().__init__(body)
        self.status = status
        headers = {}
        if content_length is not None:
            headers["Content-Length"] = content_length
        self.headers = headers

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def _patch_urlopen(monkeypatch: pytest.MonkeyPatch, response: _FakeResponse) -> None:
    monkeypatch.setattr("urllib.request.urlopen", lambda *_a, **_k: response)


def test_download_one_writes_the_expected_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = b"A" * 4096
    _patch_urlopen(monkeypatch, _FakeResponse(body, content_length=str(len(body))))
    dest = tmp_path / "out.bin"
    _download_one("https://host.test/a.zip", dest, expected_size=len(body))
    assert dest.read_bytes() == body


def test_download_one_rejects_a_non_https_url(tmp_path: Path) -> None:
    with pytest.raises(InstallError, match="credential-free HTTPS"):
        _download_one("http://host.test/a.zip", tmp_path / "x", expected_size=1)


def test_download_one_rejects_an_http_error_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_urlopen(monkeypatch, _FakeResponse(b"", status=503))
    with pytest.raises(InstallError, match="HTTP 503"):
        _download_one("https://host.test/a.zip", tmp_path / "x", expected_size=1)


def test_download_one_rejects_a_content_length_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_urlopen(monkeypatch, _FakeResponse(b"AAA", content_length="999"))
    with pytest.raises(InstallError, match="size header mismatch"):
        _download_one("https://host.test/a.zip", tmp_path / "x", expected_size=3)


def test_download_one_refuses_a_body_over_the_pinned_size(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # No Content-Length header, but the body runs past the pinned size: the
    # stream must be cut rather than written unbounded.
    _patch_urlopen(monkeypatch, _FakeResponse(b"A" * 5000))
    with pytest.raises(InstallError, match="exceeded the pinned release size"):
        _download_one("https://host.test/a.zip", tmp_path / "x", expected_size=1024)


def test_download_one_refuses_a_short_body(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_urlopen(monkeypatch, _FakeResponse(b"AA"))
    with pytest.raises(InstallError, match="incomplete"):
        _download_one("https://host.test/a.zip", tmp_path / "x", expected_size=1024)


def test_download_release_reports_every_source_that_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release = {
        "schema_version": 1,
        "tag": "t",
        "asset": "deps.zip",
        "size": 10,
        "sha256": "0" * 64,
        "never_bundles_ida": True,
        "download_urls": ["https://a.test/x.zip", "https://b.test/x.zip"],
    }
    monkeypatch.setattr(installer, "load_dependency_release", lambda: release)

    def always_fail(url: str, destination: Path, *, expected_size: int) -> None:
        raise urllib.error.URLError("nope")

    monkeypatch.setattr(installer, "_download_one", always_fail)
    with pytest.raises(InstallError, match="all dependency release sources failed") as caught:
        installer.download_dependency_release(tmp_path / "dl")
    # Both mirrors are named in the aggregated failure summary.
    assert "a.test" in str(caught.value) and "b.test" in str(caught.value)


# --------------------------------------------------------------------------
# configure_dependency_bundle branch coverage.
# --------------------------------------------------------------------------


def _write_bundle(root: Path, included: list[Any]) -> None:
    import json

    root.mkdir(parents=True, exist_ok=True)
    (root / "MANIFEST.json").write_text(
        json.dumps(
            {"schema_version": 1, "never_bundles_ida": True, "included": included, "missing": []}
        )
    )


def test_configure_rejects_a_path_escaping_the_bundle(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    _write_bundle(root, [{"id": "upx", "path": "../../etc/passwd"}])
    with pytest.raises(InstallError, match="invalid executable paths"):
        installer.configure_dependency_bundle(root)


def test_configure_requires_both_headless_runtimes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "bundle"
    (root / "tools" / "upx").mkdir(parents=True)
    (root / "tools" / "upx" / "upx.exe").write_bytes(b"MZ")
    # Only an optional tool present, plus an unknown id and a non-dict entry
    # that must both be skipped rather than crash.
    _write_bundle(
        root,
        [
            {"id": "upx", "path": "tools/upx/upx.exe"},
            {"id": "unknown-tool", "path": "whatever"},
            "not-a-dict",
        ],
    )
    monkeypatch.setattr(installer, "update_config_values", lambda values: tmp_path / "c.json")
    with pytest.raises(InstallError, match="missing an x86 or x64 headless runtime"):
        installer.configure_dependency_bundle(root)


# --------------------------------------------------------------------------
# run_one_click_setup orchestration.
# --------------------------------------------------------------------------


def _fake_report(ready: bool) -> SimpleNamespace:
    probe = SimpleNamespace(name="python", status=SimpleNamespace(value="ready"), summary="ok")
    return SimpleNamespace(ready=ready, probes=[probe])


def _install_common_stubs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, doctor_ready: bool = True
) -> dict[str, Any]:
    captured: dict[str, Any] = {"config_updates": []}
    settings = SimpleNamespace(
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        upx=None,
        diec=None,
        cdb=None,
        de4dot=None,
        net_reactor_slayer=None,
        ida_home=None,
    )
    monkeypatch.setattr(installer, "Settings", SimpleNamespace(load=lambda: settings))
    monkeypatch.setattr(installer, "default_config_path", lambda: tmp_path / "config.json")
    monkeypatch.setattr(installer, "discover_ida_home", lambda: None)
    monkeypatch.setattr(
        installer,
        "update_config_values",
        lambda values: captured["config_updates"].append(values) or (tmp_path / "config.json"),
    )
    monkeypatch.setattr(
        "headless_re_mcp.config_generate.export_mcp_environment",
        lambda settings, persist, config_path=None: {"ok": True, "written": {"bundle": "b"}},
    )
    monkeypatch.setattr(
        "headless_re_mcp.doctor.run_doctor", lambda settings: _fake_report(doctor_ready)
    )
    return captured


def test_run_one_click_setup_on_linux_skips_the_windows_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_platform(monkeypatch, "posix")
    _install_common_stubs(monkeypatch, tmp_path)

    result = run_one_click_setup(non_interactive=True)

    assert result["platform"] == "linux"
    assert result["ida_configured"] is False
    assert result["ok"] is True
    step_names = [s["step"] for s in result["steps"]]
    assert "windows_dependency_release" in step_names
    assert "generate_mcp" in step_names and "doctor" in step_names
    windows_step = next(s for s in result["steps"] if s["step"] == "windows_dependency_release")
    assert windows_step["status"] == "unsupported_on_platform"
    # IDA optional on Linux: the configure_ida step reports it as not required.
    ida_step = next(s for s in result["steps"] if s["step"] == "configure_ida")
    assert ida_step["ok"] is True and ida_step["status"] == "optional"


def test_run_one_click_setup_on_windows_downloads_and_configures_ida(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_platform(monkeypatch, "nt")
    _install_common_stubs(monkeypatch, tmp_path)
    monkeypatch.setattr(
        installer, "download_dependency_release", lambda d: {"ok": True, "archive": "a.zip"}
    )
    monkeypatch.setattr(
        installer, "extract_dependency_release", lambda a, d: {"ok": True, "root": str(tmp_path)}
    )
    monkeypatch.setattr(
        installer, "configure_dependency_bundle", lambda r: {"ok": True, "configured": {}}
    )
    monkeypatch.setattr(
        installer, "validate_ida_home", lambda home: {"ok": True, "path": str(home)}
    )
    monkeypatch.setattr(
        "headless_re_mcp.web.setup.configure_ida",
        lambda *, ida_home, activate: {"ok": True, "ida_home": str(ida_home)},
    )

    result = run_one_click_setup(ida_home=tmp_path / "ida", non_interactive=True)

    assert result["platform"] == "windows"
    assert result["ida_configured"] is True
    step_names = [s["step"] for s in result["steps"]]
    assert step_names[:3] == ["download_release", "extract_release", "configure_release"]
    assert "configure_ida" in step_names


def test_run_one_click_setup_raises_when_ida_validation_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_platform(monkeypatch, "nt")
    _install_common_stubs(monkeypatch, tmp_path)
    monkeypatch.setattr(
        installer, "download_dependency_release", lambda d: {"ok": True, "archive": "a"}
    )
    monkeypatch.setattr(
        installer, "extract_dependency_release", lambda a, d: {"ok": True, "root": str(tmp_path)}
    )
    monkeypatch.setattr(installer, "configure_dependency_bundle", lambda r: {"ok": True})
    monkeypatch.setattr(
        installer, "validate_ida_home", lambda home: {"ok": False, "message": "bad ida"}
    )
    with pytest.raises(InstallError, match="bad ida"):
        run_one_click_setup(ida_home=tmp_path / "ida", non_interactive=True)


def test_run_one_click_setup_raises_when_activation_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_platform(monkeypatch, "posix")
    _install_common_stubs(monkeypatch, tmp_path)
    monkeypatch.setattr(
        installer, "validate_ida_home", lambda home: {"ok": True, "path": str(home)}
    )
    monkeypatch.setattr(
        "headless_re_mcp.web.setup.configure_ida",
        lambda *, ida_home, activate: {"ok": False, "code": "activation_failed"},
    )
    with pytest.raises(InstallError, match="IDA configuration failed"):
        run_one_click_setup(ida_home=tmp_path / "ida", non_interactive=True, download_release=False)


def test_run_one_click_setup_reports_ida_required_when_absent_on_windows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_platform(monkeypatch, "nt")
    _install_common_stubs(monkeypatch, tmp_path, doctor_ready=False)
    monkeypatch.setattr(
        installer, "download_dependency_release", lambda d: {"ok": True, "archive": "a"}
    )
    monkeypatch.setattr(
        installer, "extract_dependency_release", lambda a, d: {"ok": True, "root": str(tmp_path)}
    )
    monkeypatch.setattr(installer, "configure_dependency_bundle", lambda r: {"ok": True})

    result = run_one_click_setup(non_interactive=True)
    assert result["ida_configured"] is False
    ida_step = next(s for s in result["steps"] if s["step"] == "configure_ida")
    assert ida_step["status"] == "required" and ida_step["ok"] is False
    assert result["ok"] is False  # doctor not ready


# --------------------------------------------------------------------------
# print_setup_summary.
# --------------------------------------------------------------------------


def test_print_setup_summary_windows_missing_ida(capsys: pytest.CaptureFixture[str]) -> None:
    print_setup_summary(
        {
            "config_path": "/tmp/config.json",
            "platform": "windows",
            "ida_configured": False,
            "doctor_ready": False,
            "steps": [
                {"step": "download_release", "ok": True},
                {"step": "configure_ida", "ok": False},
            ],
        }
    )
    out = capsys.readouterr().out
    assert "[OK] download_release" in out
    assert "[WARN] configure_ida" in out
    assert "Windows 必需" in out
    assert "doctor.ready = False" in out


def test_print_setup_summary_linux_configured(capsys: pytest.CaptureFixture[str]) -> None:
    print_setup_summary(
        {
            "config_path": "/tmp/config.json",
            "platform": "linux",
            "ida_configured": True,
            "doctor_ready": True,
            "steps": [],
        }
    )
    out = capsys.readouterr().out
    assert "启动 Web" in out
    assert "Windows 必需" not in out and "Linux 可选" not in out  # ida configured
