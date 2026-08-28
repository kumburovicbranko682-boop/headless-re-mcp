"""Guard paths for the apktool / apksigner subprocess client.

The input-validation suite covers the non-zip precheck and the happy handoff to
the JVM, but the client's other refusals -- a missing apk / decoded tree /
keystore, an unconfigured tool, a custom keystore with no password, the
no-resources decode flag, and the backend-error mapping -- plus the shared
``_run`` deadline and launch-failure arcs never ran. These drive the client with
a fake ``run_bounded`` so no real apktool, apksigner or JRE is needed.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apktool import client as apktool_client
from headless_re_mcp.backends.apktool.client import ApktoolClient, ApktoolError, _run
from headless_re_mcp.backends.common.bounded_run import TimedOut


def _executable(path: Path) -> Path:
    # available / signer_available only check is_file(), so any real file
    # stands in for the apktool / apksigner CLI here.
    path.write_text("x\n", encoding="utf-8")
    return path


def _real_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
    return path


class _Completed:
    def __init__(self, stdout: bytes, stderr: bytes, returncode: int) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


# --- _run deadline and launch-failure arcs -----------------------------------


def test_run_maps_a_deadline_to_a_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """A TimedOut from the bounded runner becomes a timeout ApktoolError."""

    def _timed_out(*_args: Any, **_kwargs: Any) -> Any:
        raise TimedOut(1.0, killed=[4321])

    monkeypatch.setattr(apktool_client, "run_bounded", _timed_out)
    with pytest.raises(ApktoolError) as caught:
        _run(["apktool", "d"], timeout=1.0)
    assert caught.value.code == "timeout"
    assert caught.value.details.get("killed_pids") == [4321]


def test_run_maps_a_launch_failure_to_backend_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """An OSError launching the tool becomes a backend_error, not a crash."""

    def _no_exec(*_args: Any, **_kwargs: Any) -> Any:
        raise OSError("no such file")

    monkeypatch.setattr(apktool_client, "run_bounded", _no_exec)
    with pytest.raises(ApktoolError) as caught:
        _run(["apktool", "d"], timeout=1.0)
    assert caught.value.code == "backend_error"


def test_run_rejects_a_non_positive_timeout() -> None:
    """A zero/negative deadline is refused up front as invalid_params."""
    with pytest.raises(ApktoolError) as caught:
        _run(["apktool", "d"], timeout=0.0)
    assert caught.value.code == "invalid_params"


def test_run_decodes_stdout_stderr_and_returncode(monkeypatch: pytest.MonkeyPatch) -> None:
    """A completed run returns decoded stdout/stderr and the integer exit code."""

    def _ok(*_args: Any, **_kwargs: Any) -> Any:
        return _Completed(b"out\xff", b"err", 0)

    monkeypatch.setattr(apktool_client, "run_bounded", _ok)
    stdout, stderr, code = _run(["apktool", "d"], timeout=5.0)
    assert stdout.startswith("out")
    assert stderr == "err"
    assert code == 0


# --- decode guards -----------------------------------------------------------


def test_decode_without_apktool_is_capability_unavailable(tmp_path: Path) -> None:
    client = ApktoolClient(None, None)
    with pytest.raises(ApktoolError) as caught:
        client.decode(_real_apk(tmp_path / "a.apk"), tmp_path / "out")
    assert caught.value.code == "capability_unavailable"


def test_decode_reports_a_missing_apk_as_not_found(tmp_path: Path) -> None:
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    with pytest.raises(ApktoolError) as caught:
        client.decode(tmp_path / "gone.apk", tmp_path / "out")
    assert caught.value.code == "not_found"


def test_decode_passes_the_no_resources_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """no_resources=True adds -r and a successful decode returns the layout."""
    apk = _real_apk(tmp_path / "a.apk")
    out_dir = tmp_path / "out"
    captured: dict[str, list[str]] = {}

    def _run_stub(cmd: list[str], **_kwargs: Any) -> tuple[str, str, int]:
        captured["cmd"] = cmd
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "AndroidManifest.xml").write_text("<m/>", encoding="utf-8")
        (out_dir / "smali").mkdir()
        return "", "", 0

    monkeypatch.setattr(apktool_client, "_run", _run_stub)
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    result = client.decode(apk, out_dir, no_resources=True)
    assert "-r" in captured["cmd"]
    assert result["smali_dirs"] == ["smali"]


def test_decode_maps_a_nonzero_exit_to_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """apktool exiting non-zero (no manifest written) is a backend_error."""
    apk = _real_apk(tmp_path / "a.apk")
    monkeypatch.setattr(apktool_client, "_run", lambda *a, **k: ("", "boom", 1))
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    with pytest.raises(ApktoolError) as caught:
        client.decode(apk, tmp_path / "out")
    assert caught.value.code == "backend_error"
    assert caught.value.details.get("exit_code") == 1


# --- build guards ------------------------------------------------------------


def test_build_without_apktool_is_capability_unavailable(tmp_path: Path) -> None:
    client = ApktoolClient(None, None)
    with pytest.raises(ApktoolError) as caught:
        client.build(tmp_path / "decoded", tmp_path / "out.apk")
    assert caught.value.code == "capability_unavailable"


def test_build_reports_a_missing_decoded_dir_as_not_found(tmp_path: Path) -> None:
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    with pytest.raises(ApktoolError) as caught:
        client.build(tmp_path / "never-decoded", tmp_path / "out.apk")
    assert caught.value.code == "not_found"


def test_build_rejects_a_tree_that_is_not_a_decode_output(tmp_path: Path) -> None:
    """A directory without AndroidManifest.xml is not an apktool decode tree."""
    decoded = tmp_path / "decoded"
    decoded.mkdir()
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    with pytest.raises(ApktoolError) as caught:
        client.build(decoded, tmp_path / "out.apk")
    assert caught.value.code == "invalid_params"


def test_build_maps_a_nonzero_exit_to_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """apktool build failing (no output apk) is a backend_error."""
    decoded = tmp_path / "decoded"
    decoded.mkdir()
    (decoded / "AndroidManifest.xml").write_text("<m/>", encoding="utf-8")
    monkeypatch.setattr(apktool_client, "_run", lambda *a, **k: ("", "build broke", 1))
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    with pytest.raises(ApktoolError) as caught:
        client.build(decoded, tmp_path / "out.apk")
    assert caught.value.code == "backend_error"


def test_build_rejects_a_zero_byte_or_non_zip_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A build that exits 0 but leaves a non-zip apk is still a failed rebuild."""
    decoded = tmp_path / "decoded"
    decoded.mkdir()
    (decoded / "AndroidManifest.xml").write_text("<m/>", encoding="utf-8")
    out_apk = tmp_path / "out.apk"

    def _run_stub(*_args: Any, **_kwargs: Any) -> tuple[str, str, int]:
        out_apk.write_bytes(b"not a zip")
        return "", "", 0

    monkeypatch.setattr(apktool_client, "_run", _run_stub)
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    with pytest.raises(ApktoolError) as caught:
        client.build(decoded, out_apk)
    assert caught.value.code == "backend_error"
    assert "empty or invalid" in caught.value.message


# --- sign guards -------------------------------------------------------------


def test_sign_without_apksigner_is_capability_unavailable(tmp_path: Path) -> None:
    client = ApktoolClient(None, None)
    with pytest.raises(ApktoolError) as caught:
        client.sign(_real_apk(tmp_path / "a.apk"), tmp_path / "signed.apk")
    assert caught.value.code == "capability_unavailable"


def test_sign_reports_a_missing_apk_as_not_found(tmp_path: Path) -> None:
    client = ApktoolClient(None, _executable(tmp_path / "apksigner.bat"))
    with pytest.raises(ApktoolError) as caught:
        client.sign(tmp_path / "gone.apk", tmp_path / "signed.apk")
    assert caught.value.code == "not_found"


def test_sign_reports_a_missing_keystore_as_not_found(tmp_path: Path) -> None:
    apk = _real_apk(tmp_path / "a.apk")
    client = ApktoolClient(None, _executable(tmp_path / "apksigner.bat"))
    with pytest.raises(ApktoolError) as caught:
        client.sign(apk, tmp_path / "signed.apk", keystore=tmp_path / "absent.keystore")
    assert caught.value.code == "not_found"


def test_sign_requires_password_and_alias_for_a_custom_keystore(tmp_path: Path) -> None:
    """A custom keystore has no debug defaults, so both credentials are required."""
    apk = _real_apk(tmp_path / "a.apk")
    keystore = tmp_path / "custom.keystore"
    keystore.write_bytes(b"ks")
    client = ApktoolClient(None, _executable(tmp_path / "apksigner.bat"))
    with pytest.raises(ApktoolError) as caught:
        client.sign(apk, tmp_path / "signed.apk", keystore=keystore)
    assert caught.value.code == "invalid_params"
