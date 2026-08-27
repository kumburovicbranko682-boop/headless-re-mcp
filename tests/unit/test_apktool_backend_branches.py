"""Branch coverage for the apktool/apksigner subprocess backend.

Both CLIs are user-provided JVM launchers, so a missing tool degrades to
capability_unavailable, a non-zip input is refused before paying JVM startup,
and a build that exits 0 but leaves an empty/invalid apk is still a failure.
Signing keeps the keystore password off argv -- it travels in a child-only
environment variable -- and scrubs it from any diagnostic before it reaches
error details. These fakes drive those honesty and degradation branches
without a JRE; the live gate (tests/integration/test_android_re_gate.py) pins
the real tools.
"""

from __future__ import annotations

import sys
import zipfile
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apktool import client as apktool_client
from headless_re_mcp.backends.apktool.client import (
    ApktoolClient,
    ApktoolError,
    _require_apk_zip,
    _run,
)
from headless_re_mcp.backends.common.bounded_run import Completed, TimedOut

MP = pytest.MonkeyPatch
_EXE = Path(sys.executable)


def _zip(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", "manifest")
    return path


class _FakeRun:
    """A stand-in for run_bounded that records calls and stages outputs."""

    def __init__(self, handler: Any) -> None:
        self.handler = handler
        self.calls: list[dict[str, Any]] = []

    def __call__(
        self, cmd: list[str], *, timeout: float, creationflags: int = 0, env: Any = None
    ) -> Completed:
        self.calls.append({"cmd": list(cmd), "env": env, "timeout": timeout})
        return self.handler(list(cmd), env)


def _install(monkeypatch: MP, handler: Any) -> _FakeRun:
    fake = _FakeRun(handler)
    monkeypatch.setattr(apktool_client, "run_bounded", fake)
    return fake


class TestHelpers:
    def test_require_apk_zip_rejects_a_non_zip(self, tmp_path: Path) -> None:
        bogus = tmp_path / "not.apk"
        bogus.write_bytes(b"this is not a zip")
        with pytest.raises(ApktoolError) as excinfo:
            _require_apk_zip(bogus)
        assert excinfo.value.code == "invalid_params"

    def test_require_apk_zip_accepts_a_zip(self, tmp_path: Path) -> None:
        _require_apk_zip(_zip(tmp_path / "ok.apk"))  # no raise

    def test_run_maps_a_timeout(self, monkeypatch: MP) -> None:
        def _boom(_cmd: list[str], _env: Any) -> Completed:
            raise TimedOut(2.0, killed=[42])

        _install(monkeypatch, _boom)
        with pytest.raises(ApktoolError) as excinfo:
            _run(["/opt/apktool", "d"], timeout=30)
        assert excinfo.value.code == "timeout"
        assert excinfo.value.details.get("killed_pids") == [42]

    def test_run_maps_a_launch_oserror(self, monkeypatch: MP) -> None:
        def _boom(_cmd: list[str], _env: Any) -> Completed:
            raise FileNotFoundError("no such tool")

        _install(monkeypatch, _boom)
        with pytest.raises(ApktoolError) as excinfo:
            _run(["/opt/apktool", "d"], timeout=30)
        assert excinfo.value.code == "backend_error"

    def test_run_rejects_a_bad_timeout(self, monkeypatch: MP) -> None:
        _install(monkeypatch, lambda c, e: Completed(returncode=0, stdout=b"", stderr=b""))
        with pytest.raises(ApktoolError) as excinfo:
            _run(["/opt/apktool", "d"], timeout=0)
        assert excinfo.value.code == "invalid_params"


class TestDecode:
    def test_decode_needs_apktool(self, tmp_path: Path) -> None:
        client = ApktoolClient(apktool=None)
        with pytest.raises(ApktoolError) as excinfo:
            client.decode(_zip(tmp_path / "a.apk"), tmp_path / "out")
        assert excinfo.value.code == "capability_unavailable"

    def test_decode_reports_a_missing_apk(self, tmp_path: Path) -> None:
        client = ApktoolClient(apktool=_EXE)
        with pytest.raises(ApktoolError) as excinfo:
            client.decode(tmp_path / "gone.apk", tmp_path / "out")
        assert excinfo.value.code == "not_found"

    def test_decode_success_lists_smali_dirs_and_resources(
        self, tmp_path: Path, monkeypatch: MP
    ) -> None:
        apk = _zip(tmp_path / "a.apk")
        out_dir = tmp_path / "decoded"

        def _handler(cmd: list[str], _env: Any) -> Completed:
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / "AndroidManifest.xml").write_text("m")
            (out_dir / "smali").mkdir()
            (out_dir / "smali_classes2").mkdir()
            (out_dir / "res").mkdir()
            return Completed(returncode=0, stdout=b"", stderr=b"")

        fake = _install(monkeypatch, _handler)
        result = ApktoolClient(apktool=_EXE).decode(apk, out_dir, no_resources=True)
        assert result["smali_dirs"] == ["smali", "smali_classes2"]
        assert result["has_resources"] is True
        assert result["manifest"].endswith("AndroidManifest.xml")
        assert "-r" in fake.calls[0]["cmd"]  # no_resources propagated

    def test_decode_failure_when_manifest_missing(
        self, tmp_path: Path, monkeypatch: MP
    ) -> None:
        apk = _zip(tmp_path / "a.apk")
        _install(
            monkeypatch,
            lambda c, e: Completed(returncode=0, stdout=b"", stderr=b"apktool blew up"),
        )
        with pytest.raises(ApktoolError) as excinfo:
            ApktoolClient(apktool=_EXE).decode(apk, tmp_path / "out")
        assert excinfo.value.code == "backend_error"
        assert "apktool blew up" in excinfo.value.details.get("stderr", "")


class TestBuild:
    def test_build_needs_apktool(self, tmp_path: Path) -> None:
        with pytest.raises(ApktoolError) as excinfo:
            ApktoolClient(apktool=None).build(tmp_path, tmp_path / "out.apk")
        assert excinfo.value.code == "capability_unavailable"

    def test_build_reports_a_missing_dir(self, tmp_path: Path) -> None:
        with pytest.raises(ApktoolError) as excinfo:
            ApktoolClient(apktool=_EXE).build(tmp_path / "nope", tmp_path / "out.apk")
        assert excinfo.value.code == "not_found"

    def test_build_rejects_a_non_decode_tree(self, tmp_path: Path) -> None:
        tree = tmp_path / "tree"
        tree.mkdir()  # no AndroidManifest.xml inside
        with pytest.raises(ApktoolError) as excinfo:
            ApktoolClient(apktool=_EXE).build(tree, tmp_path / "out.apk")
        assert excinfo.value.code == "invalid_params"

    def test_build_success_reports_unsigned(self, tmp_path: Path, monkeypatch: MP) -> None:
        tree = tmp_path / "tree"
        tree.mkdir()
        (tree / "AndroidManifest.xml").write_text("m")
        out_apk = tmp_path / "rebuilt.apk"

        def _handler(cmd: list[str], _env: Any) -> Completed:
            _zip(out_apk)
            return Completed(returncode=0, stdout=b"", stderr=b"")

        _install(monkeypatch, _handler)
        result = ApktoolClient(apktool=_EXE).build(tree, out_apk)
        assert result["signed"] is False
        assert result["size"] > 0
        assert "unsigned" in result["note"]

    def test_build_failure_on_nonzero_exit(self, tmp_path: Path, monkeypatch: MP) -> None:
        tree = tmp_path / "tree"
        tree.mkdir()
        (tree / "AndroidManifest.xml").write_text("m")
        _install(
            monkeypatch,
            lambda c, e: Completed(returncode=1, stdout=b"", stderr=b"brut error"),
        )
        with pytest.raises(ApktoolError) as excinfo:
            ApktoolClient(apktool=_EXE).build(tree, tmp_path / "out.apk")
        assert excinfo.value.code == "backend_error"

    def test_build_rejects_an_empty_output(self, tmp_path: Path, monkeypatch: MP) -> None:
        tree = tmp_path / "tree"
        tree.mkdir()
        (tree / "AndroidManifest.xml").write_text("m")
        out_apk = tmp_path / "empty.apk"

        def _handler(cmd: list[str], _env: Any) -> Completed:
            out_apk.write_bytes(b"")  # exit 0 but no real zip
            return Completed(returncode=0, stdout=b"", stderr=b"")

        _install(monkeypatch, _handler)
        with pytest.raises(ApktoolError) as excinfo:
            ApktoolClient(apktool=_EXE).build(tree, out_apk)
        assert excinfo.value.code == "backend_error"
        assert excinfo.value.details.get("size") == 0


class TestSign:
    def test_sign_needs_apksigner(self, tmp_path: Path) -> None:
        with pytest.raises(ApktoolError) as excinfo:
            ApktoolClient(apksigner=None).sign(_zip(tmp_path / "a.apk"), tmp_path / "o.apk")
        assert excinfo.value.code == "capability_unavailable"

    def test_sign_reports_a_missing_apk(self, tmp_path: Path) -> None:
        with pytest.raises(ApktoolError) as excinfo:
            ApktoolClient(apksigner=_EXE).sign(tmp_path / "gone.apk", tmp_path / "o.apk")
        assert excinfo.value.code == "not_found"

    def test_sign_reports_a_missing_keystore(self, tmp_path: Path) -> None:
        apk = _zip(tmp_path / "a.apk")
        with pytest.raises(ApktoolError) as excinfo:
            ApktoolClient(apksigner=_EXE).sign(
                apk, tmp_path / "o.apk", keystore=tmp_path / "no.keystore"
            )
        assert excinfo.value.code == "not_found"

    def test_sign_requires_password_and_alias_for_a_custom_keystore(
        self, tmp_path: Path
    ) -> None:
        apk = _zip(tmp_path / "a.apk")
        keystore = tmp_path / "custom.keystore"
        keystore.write_bytes(b"ks")
        with pytest.raises(ApktoolError) as excinfo:
            ApktoolClient(apksigner=_EXE).sign(apk, tmp_path / "o.apk", keystore=keystore)
        assert excinfo.value.code == "invalid_params"

    def test_sign_success_passes_password_via_env_not_argv(
        self, tmp_path: Path, monkeypatch: MP
    ) -> None:
        apk = _zip(tmp_path / "a.apk")
        out_apk = tmp_path / "signed.apk"
        debug_ks = tmp_path / "debug.keystore"
        debug_ks.write_bytes(b"ks")
        monkeypatch.setattr(apktool_client, "_DEBUG_KEYSTORE", debug_ks)

        def _handler(cmd: list[str], env: Any) -> Completed:
            if cmd[1] == "sign":
                _zip(out_apk)
            return Completed(returncode=0, stdout=b"", stderr=b"")

        fake = _install(monkeypatch, _handler)
        result = ApktoolClient(apksigner=_EXE).sign(apk, out_apk)
        assert result["signed"] is True
        assert result["debug_keystore"] is True
        sign_call = fake.calls[0]
        # The password reaches the child through env:NAME, never as an argv token
        # (an alias like "androiddebugkey" contains it as a substring, so match
        # whole tokens, and confirm no pass:<secret> form leaked either).
        assert apktool_client._DEBUG_PASSWORD not in sign_call["cmd"]
        assert not any(tok.startswith("pass:") for tok in sign_call["cmd"])
        assert sign_call["env"][apktool_client._PASSWORD_ENV] == apktool_client._DEBUG_PASSWORD
        assert f"env:{apktool_client._PASSWORD_ENV}" in sign_call["cmd"]

    def test_sign_failure_scrubs_the_password_from_stderr(
        self, tmp_path: Path, monkeypatch: MP
    ) -> None:
        apk = _zip(tmp_path / "a.apk")
        keystore = tmp_path / "custom.keystore"
        keystore.write_bytes(b"ks")
        secret = "s3cr3t-pass"

        def _handler(cmd: list[str], env: Any) -> Completed:
            return Completed(
                returncode=1, stdout=b"", stderr=f"bad pass {secret} here".encode()
            )

        _install(monkeypatch, _handler)
        with pytest.raises(ApktoolError) as excinfo:
            ApktoolClient(apksigner=_EXE).sign(
                apk,
                tmp_path / "o.apk",
                keystore=keystore,
                keystore_password=secret,
                key_alias="mykey",
            )
        assert excinfo.value.code == "backend_error"
        stderr = excinfo.value.details.get("stderr", "")
        assert secret not in stderr
        assert "***" in stderr

    def test_sign_reports_a_verify_failure(self, tmp_path: Path, monkeypatch: MP) -> None:
        apk = _zip(tmp_path / "a.apk")
        out_apk = tmp_path / "signed.apk"
        debug_ks = tmp_path / "debug.keystore"
        debug_ks.write_bytes(b"ks")
        monkeypatch.setattr(apktool_client, "_DEBUG_KEYSTORE", debug_ks)

        def _handler(cmd: list[str], env: Any) -> Completed:
            if cmd[1] == "sign":
                _zip(out_apk)
                return Completed(returncode=0, stdout=b"", stderr=b"")
            return Completed(returncode=1, stdout=b"", stderr=b"not signed")

        _install(monkeypatch, _handler)
        with pytest.raises(ApktoolError) as excinfo:
            ApktoolClient(apksigner=_EXE).sign(apk, out_apk)
        assert excinfo.value.code == "backend_error"
        assert "not signed" in excinfo.value.details.get("stderr", "")
