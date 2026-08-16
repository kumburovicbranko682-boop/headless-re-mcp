"""Unit coverage for M11 optional backend invariants (whitelist / kernel gate)."""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client, R2Error
from headless_re_mcp.backends.windbg.client import WindbgClient, WindbgError
from headless_re_mcp.config import Settings
from headless_re_mcp.doctor import DoctorReport, Probe, ProbeStatus


def test_r2_rejects_non_whitelisted_command(tmp_path: Path) -> None:
    binary = tmp_path / "x.exe"
    binary.write_bytes(b"MZ")
    stub = tmp_path / "r2.exe"
    stub.write_bytes(b"")
    client = R2Client(executable=stub)
    with pytest.raises(R2Error) as exc:
        client.run(binary, ["!cmd"])
    assert exc.value.code == "invalid_params"


def test_windbg_kernel_requires_explicit_allow(tmp_path: Path) -> None:
    dump = tmp_path / "a.dmp"
    dump.write_bytes(b"dump")
    denied = WindbgClient(cdb=tmp_path / "cdb.exe", allow_kernel=False)
    with pytest.raises(WindbgError) as exc:
        denied.open_dump(dump, ["lm"], kernel=True)
    assert exc.value.code == "permission_denied"

    allowed = WindbgClient(cdb=tmp_path / "cdb.exe", allow_kernel=True)
    with pytest.raises(WindbgError) as missing:
        allowed.open_dump(dump, ["lm"], kernel=True)
    assert missing.value.code == "capability_unavailable"


def test_windbg_rejects_non_whitelisted_command(tmp_path: Path) -> None:
    dump = tmp_path / "a.dmp"
    dump.write_bytes(b"dump")
    stub = tmp_path / "cdb.exe"
    stub.write_bytes(b"")
    client = WindbgClient(cdb=stub, allow_kernel=False)
    with pytest.raises(WindbgError) as exc:
        client.open_dump(dump, ["!analyze -v"])
    assert exc.value.code == "invalid_params"


def test_settings_exposes_cdb_and_kernel_flag(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("HEADLESS_RE_CDB", raising=False)
    monkeypatch.delenv("HEADLESS_RE_WINDBG_ALLOW_KERNEL", raising=False)
    monkeypatch.setenv("HEADLESS_RE_ARTIFACT_ROOT", str(tmp_path / "art"))
    settings = Settings.load(config_path=tmp_path / "missing.json")
    assert settings.windbg_allow_kernel is False

    cdb = tmp_path / "cdb.exe"
    cdb.write_bytes(b"")
    monkeypatch.setenv("HEADLESS_RE_CDB", str(cdb))
    monkeypatch.setenv("HEADLESS_RE_WINDBG_ALLOW_KERNEL", "1")
    settings2 = Settings.load(config_path=tmp_path / "missing.json")
    assert settings2.cdb is not None
    assert Path(settings2.cdb) == cdb.resolve() or Path(settings2.cdb) == cdb
    assert settings2.windbg_allow_kernel is True


def test_doctor_ready_ignores_optional_backend_missing() -> None:
    report = DoctorReport(
        probes=(
            Probe("python", ProbeStatus.READY, "ok"),
            Probe("ida_idalib", ProbeStatus.READY, "ok"),
            Probe("x64dbg_source", ProbeStatus.READY, "ok"),
            Probe("x64dbg_headless_binaries", ProbeStatus.READY, "ok"),
            Probe("native_toolchain", ProbeStatus.READY, "ok"),
            Probe("radare2", ProbeStatus.MISSING, "missing"),
            Probe("ghidra", ProbeStatus.MISSING, "missing"),
            Probe("frida", ProbeStatus.MISSING, "missing"),
            Probe("windbg", ProbeStatus.MISSING, "missing"),
        )
    )
    assert report.ready is True


def test_windbg_live_pid_boundary(tmp_path: Path) -> None:
    stub = tmp_path / "cdb.exe"
    stub.write_bytes(b"")
    client = WindbgClient(cdb=stub, allow_kernel=False)
    with pytest.raises(WindbgError) as exc:
        client.attach(111, allowed_pid=222)
    assert exc.value.code == "permission_denied"


def test_windbg_live_rejects_non_whitelisted(tmp_path: Path) -> None:
    stub = tmp_path / "cdb.exe"
    stub.write_bytes(b"")
    client = WindbgClient(cdb=stub, allow_kernel=False)
    with pytest.raises(WindbgError) as exc:
        client._run_process(1, ["!analyze -v"], allowed_pid=1, timeout=1.0)
    assert exc.value.code == "invalid_params"


def test_windbg_live_missing_cdb(tmp_path: Path) -> None:
    client = WindbgClient(cdb=tmp_path / "missing-cdb.exe", allow_kernel=False)
    with pytest.raises(WindbgError) as exc:
        client.attach(1, allowed_pid=1)
    assert exc.value.code == "capability_unavailable"


class TestR2OpenSaysWhenInfoWasCut:
    """r2.open sliced the `i` listing at 8000 characters and said nothing.

    Measured: 12_000 characters came back as 8_000 with no truncated, so a
    caller would treat a mid-listing slice as the whole info block.
    """

    def _client(self, tmp_path: Path, raw: str) -> tuple[R2Client, Path]:
        binary = tmp_path / "x.bin"
        binary.write_bytes(b"MZ")
        stub = tmp_path / "r2"
        stub.write_text("#!/bin/sh\n")
        client = R2Client(executable=stub)
        client.run = lambda *args, **kwargs: {"raw": raw, "commands": ["i"]}  # type: ignore[method-assign]
        return client, binary

    def test_a_silent_slice_is_reported(self, tmp_path: Path) -> None:
        client, binary = self._client(tmp_path, "x" * 12_000)
        page = client.open(binary)
        assert len(page["info"]) == 8000
        assert page["truncated"] is True
        assert page["bytes"] == 12_000

    def test_a_short_listing_is_not_labelled_partial(self, tmp_path: Path) -> None:
        client, binary = self._client(tmp_path, "arch x86\n")
        page = client.open(binary)
        assert page["truncated"] is False
        assert page["info"].startswith("arch")


class TestR2TimeoutKillsWhatItStarted:
    """r2 timeout left the process the stub launched still running.

    Measured: a stub that launched sleep 60 still left that child alive
    after subprocess.run timed out at 0.4s, so an overnight r2 that
    forks a helper would keep the process for the rest of the service.
    """

    def test_a_timeout_kills_the_child(self, tmp_path: Path) -> None:
        import os
        import time

        child_pid_file = tmp_path / "child.pid"
        stub = tmp_path / "r2"
        stub.write_text(
            "#!/bin/sh\n"
            f"sleep 60 &\n"
            f"echo $! > {child_pid_file}\n"
            "sleep 60\n",
            encoding="utf-8",
        )
        stub.chmod(0o755)
        binary = tmp_path / "x.exe"
        binary.write_bytes(b"MZ")
        client = R2Client(executable=stub)
        started = time.monotonic()
        with pytest.raises(R2Error) as info:
            client.run(binary, ["i"], timeout=0.4)
        assert info.value.code == "timeout"
        assert time.monotonic() - started < 7.0
        child_pid = int(child_pid_file.read_text(encoding="utf-8").strip())
        still = os.path.exists(f"/proc/{child_pid}")
        if still:
            os.kill(child_pid, 9)
        assert still is False


class TestR2TimeoutEnvelopeIsRetryable:
    """An r2 timeout was reported as a permanent failure.

    Measured: R2Error(code=timeout) through the service path mapped to
    retryable=False. An unattended agent then treats a wedged r2 as
    permanent and stops the overnight job.
    """

    def test_a_timeout_is_retryable(self) -> None:
        from headless_re_mcp.core.results import _failure
        from headless_re_mcp.core.service_ext import _r2_rpc

        result = _failure(_r2_rpc(R2Error("timeout", "r2 timed out")))
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "timeout"
        assert result.error.retryable is True

    def test_a_backend_error_stays_permanent(self) -> None:
        from headless_re_mcp.core.results import _failure
        from headless_re_mcp.core.service_ext import _r2_rpc

        result = _failure(_r2_rpc(R2Error("backend_error", "failed")))
        assert result.error is not None
        assert result.error.retryable is False


class TestGhidraTimeoutEnvelopeIsRetryable:
    """A Ghidra timeout was reported as a permanent failure.

    Measured: GhidraError(code=timeout) through the service path mapped to
    retryable=False. An unattended agent then treats a wedged headless
    run as permanent and stops the overnight job.
    """

    def test_a_timeout_is_retryable(self) -> None:
        from headless_re_mcp.backends.ghidra.client import GhidraError
        from headless_re_mcp.core.results import _failure
        from headless_re_mcp.core.service_ext import _ghidra_rpc

        result = _failure(_ghidra_rpc(GhidraError("timeout", "ghidra timed out")))
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "timeout"
        assert result.error.retryable is True

    def test_a_backend_error_stays_permanent(self) -> None:
        from headless_re_mcp.backends.ghidra.client import GhidraError
        from headless_re_mcp.core.results import _failure
        from headless_re_mcp.core.service_ext import _ghidra_rpc

        result = _failure(_ghidra_rpc(GhidraError("backend_error", "failed")))
        assert result.error is not None
        assert result.error.retryable is False


class TestWindbgTimeoutEnvelopeIsRetryable:
    """A WinDbg timeout was reported as a permanent failure.

    Measured: WindbgError(code=timeout) through the service path mapped to
    retryable=False. An unattended agent then treats a wedged cdb as
    permanent and stops the overnight job.
    """

    def test_a_timeout_is_retryable(self) -> None:
        from headless_re_mcp.core.results import _failure
        from headless_re_mcp.core.service_ext import _windbg_rpc

        result = _failure(_windbg_rpc(WindbgError("timeout", "cdb timed out")))
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "timeout"
        assert result.error.retryable is True

    def test_a_backend_error_stays_permanent(self) -> None:
        from headless_re_mcp.core.results import _failure
        from headless_re_mcp.core.service_ext import _windbg_rpc

        result = _failure(_windbg_rpc(WindbgError("backend_error", "failed")))
        assert result.error is not None
        assert result.error.retryable is False
