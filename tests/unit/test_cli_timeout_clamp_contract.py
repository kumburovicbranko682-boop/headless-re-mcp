"""Every CLI backend clamps its caller-supplied timeout before it spawns.

Five non-PE adapters shell out to an external tool under a deadline: radare2,
jadx, apktool, jsre (webcrack/wabt), and Ghidra's analyzeHeadless. Each tool
schema declares ``0 < timeout <= maximum``, but the agent transport invokes
handlers straight from model arguments with no schema enforcement
(``CommandCatalog.invoke -> spec.handler(**arguments)``) -- the exact gap
``clamp_cli_timeout`` documents. Left unclamped, a non-positive/NaN deadline
makes ``run_bounded`` launch the JVM/node only to kill it on the first loop and
report a misleading ``timeout`` for what is really a bad parameter, and a huge
one lets a tool that hangs on hostile input hold a worker for as long as the
caller named.

Each adapter funnels through ``clamp_cli_timeout`` today, but nothing pinned
that they all still do. Ghidra had already drifted -- it passed the caller's
timeout straight through with no clamp -- and only a per-backend audit caught
it. This test pins the contract for every CLI backend at once, the way the
backend error-shape contract and the ``_dump`` envelope guard are pinned across
their families, so a refactor that drops the clamp from one adapter fails here
instead of in production.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any, NamedTuple

import pytest

import headless_re_mcp.backends.apktool.client as apktool_client
import headless_re_mcp.backends.ghidra.client as ghidra_client
import headless_re_mcp.backends.jadx.client as jadx_client
import headless_re_mcp.backends.jsre.client as jsre_client
import headless_re_mcp.backends.r2.client as r2_client


class _Reached(BaseException):
    """Raised by the run_bounded stub once it recorded the clamped timeout.

    A BaseException (not Exception) so it slips past every adapter's
    ``except (TimedOut, OSError)`` guard and propagates to the test, proving the
    clamped value reached the spawn without needing to fake valid tool output.
    """


class _Adapter(NamedTuple):
    module: Any
    error_cls: type[Exception]
    max_timeout: float
    spawn: Callable[[float], None]


ADAPTER_NAMES = ("radare2", "jadx", "apktool", "jsre", "ghidra")


def _build_adapters(tmp_path: Path) -> dict[str, _Adapter]:
    """Wire each backend so one call reaches its clamp + run_bounded path.

    Availability gating differs per backend (r2/jadx want a real executable and
    input file; apktool/jsre clamp in a module-level ``_run``; ghidra clamps in
    ``_run_headless``), so each spawn closure encapsulates just enough setup to
    make the client available and land on the clamp.
    """
    # radare2: run() clamps first, then needs an executable file and a real
    # binary. "i" is the whitelisted info command.
    r2_exe = tmp_path / "r2"
    r2_exe.write_bytes(b"")
    r2_bin = tmp_path / "sample.bin"
    r2_bin.write_bytes(b"MZ")
    r2 = r2_client.R2Client(executable=r2_exe)

    def r2_spawn(timeout: float) -> None:
        r2.run(r2_bin, ["i"], timeout=timeout)

    # jadx: export_sources -> _run clamps, then wants an executable file and a
    # real apk; the output dir is created for us.
    jadx_exe = tmp_path / "jadx"
    jadx_exe.write_bytes(b"")
    jadx_apk = tmp_path / "app.apk"
    jadx_apk.write_bytes(b"PK\x03\x04")
    jadx = jadx_client.JadxClient(executable=jadx_exe)

    def jadx_spawn(timeout: float) -> None:
        jadx.export_sources(jadx_apk, tmp_path / "jadx_out", timeout=timeout)

    # apktool + jsre expose the clamp in a module-level _run; hit it directly so
    # the contract is pinned without a valid zip/JVM in the way.
    def apktool_spawn(timeout: float) -> None:
        apktool_client._run(["apktool"], timeout=timeout)

    def jsre_spawn(timeout: float) -> None:
        jsre_client._run(["webcrack"], timeout=timeout)

    # ghidra: _run_headless clamps just before run_bounded. Fake a home whose
    # support/analyzeHeadless.bat is discoverable so the client is available.
    ghidra_home = tmp_path / "ghidra"
    (ghidra_home / "support").mkdir(parents=True)
    (ghidra_home / "support" / "analyzeHeadless.bat").write_text("@echo off\n", encoding="utf-8")
    ghidra = ghidra_client.GhidraClient(home=ghidra_home)
    ghidra.java = tmp_path / "java"
    ghidra.java.write_bytes(b"")
    ghidra_bin = tmp_path / "sample.exe"
    ghidra_bin.write_bytes(b"MZ")

    def ghidra_spawn(timeout: float) -> None:
        ghidra._run_headless(
            tmp_path / "proj",
            binary=ghidra_bin,
            extra=[],
            timeout=timeout,
            max_heap="2G",
            delete_project=True,
        )

    return {
        "radare2": _Adapter(
            r2_client, r2_client.R2Error, r2_client._MAX_TIMEOUT_S, r2_spawn
        ),
        "jadx": _Adapter(
            jadx_client, jadx_client.JadxError, jadx_client._MAX_TIMEOUT_S, jadx_spawn
        ),
        "apktool": _Adapter(
            apktool_client,
            apktool_client.ApktoolError,
            apktool_client._MAX_TIMEOUT_S,
            apktool_spawn,
        ),
        "jsre": _Adapter(
            jsre_client, jsre_client.JsReError, jsre_client._MAX_TIMEOUT_S, jsre_spawn
        ),
        "ghidra": _Adapter(
            ghidra_client,
            ghidra_client.GhidraError,
            ghidra_client._MAX_TIMEOUT_S,
            ghidra_spawn,
        ),
    }


@pytest.mark.parametrize("name", ADAPTER_NAMES)
def test_a_huge_caller_timeout_is_clamped_to_the_backend_ceiling(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter = _build_adapters(tmp_path)[name]
    captured: dict[str, Any] = {}

    def record(cmd: list[str], *, timeout: float, **kwargs: Any) -> Any:
        captured["timeout"] = timeout
        raise _Reached

    monkeypatch.setattr(adapter.module, "run_bounded", record)
    with pytest.raises(_Reached):
        adapter.spawn(10**9)
    assert captured["timeout"] == adapter.max_timeout


@pytest.mark.parametrize("name", ADAPTER_NAMES)
@pytest.mark.parametrize("bad", [0.0, -5.0, float("nan")])
def test_a_non_positive_timeout_is_refused_before_the_tool_is_launched(
    name: str, bad: float, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter = _build_adapters(tmp_path)[name]
    captured: dict[str, Any] = {}

    def must_not_spawn(cmd: list[str], *, timeout: float, **kwargs: Any) -> Any:
        captured["timeout"] = timeout
        raise _Reached

    monkeypatch.setattr(adapter.module, "run_bounded", must_not_spawn)
    with pytest.raises(adapter.error_cls) as caught:
        adapter.spawn(bad)
    assert getattr(caught.value, "code", None) == "invalid_params"
    assert "timeout" not in captured
