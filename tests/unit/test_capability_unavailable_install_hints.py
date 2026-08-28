"""capability_unavailable for a missing optional dependency must say the fix.

The CLI entry points (serve-web, native GUI) already answer "what do I
install?" in the error itself. The tool layer answered only "what is
missing": ``proxy.start`` on a bare install said "mitmproxy is not
installed" and stopped there, leaving the caller — typically an LLM agent
that cannot browse pyproject.toml — to guess the extra's name. These tests
pin the remediation: every backend that degrades to capability_unavailable
because an optional Python module is absent names the pip extra to install,
and radare2 (a system binary, not a pip package) names the PATH fix.

All of these force ``_available = False`` directly, so they run hermetically
on any machine — with or without the extras installed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError
from headless_re_mcp.backends.apk.client import ApkClient, ApkError
from headless_re_mcp.backends.frida.client import FridaClient, FridaError
from headless_re_mcp.backends.proxy.client import ProxyBackend, ProxyError
from headless_re_mcp.backends.r2.client import R2Client, R2Error
from headless_re_mcp.backends.web.client import WebBackend, WebError

_PIP_HINTS = [
    ("mitmproxy", 'pip install "headless-re-mcp[proxy]"'),
    ("playwright", 'pip install "headless-re-mcp[browser]"'),
    ("androguard", 'pip install "headless-re-mcp[android]"'),
    ("adbutils", 'pip install "headless-re-mcp[android]"'),
    ("frida", 'pip install "headless-re-mcp[android]"'),
]


def _raise_proxy() -> None:
    backend = ProxyBackend()
    backend._available = False
    backend._check_available()


def _raise_web() -> None:
    backend = WebBackend()
    backend._available = False
    backend._check_available()


def _raise_apk() -> None:
    client = ApkClient()
    client._available = False
    client._require(Path("ignored.apk"))


def _raise_adb() -> None:
    backend = AdbBackend()
    backend._available = False
    backend._adbutils = None
    backend._client()


def _raise_frida() -> None:
    client = FridaClient()
    client._available = False
    client._frida = None
    client._need()


_CASES = [
    pytest.param(_raise_proxy, ProxyError, "mitmproxy", id="proxy-mitmproxy"),
    pytest.param(_raise_web, WebError, "playwright", id="web-playwright"),
    pytest.param(_raise_apk, ApkError, "androguard", id="apk-androguard"),
    pytest.param(_raise_adb, AdbError, "adbutils", id="adb-adbutils"),
    pytest.param(_raise_frida, FridaError, "frida", id="frida-frida"),
]


@pytest.mark.parametrize(("trigger", "error_type", "module"), _CASES)
def test_missing_python_module_error_names_the_pip_extra(
    trigger: object, error_type: type[RuntimeError], module: str
) -> None:
    expected_hint = dict(_PIP_HINTS)[module]
    with pytest.raises(error_type) as caught:
        trigger()  # type: ignore[operator]
    assert caught.value.code == "capability_unavailable"  # type: ignore[attr-defined]
    message = str(caught.value)
    assert module in message, message
    assert expected_hint in message, (
        f"the {module} capability_unavailable message must include the exact "
        f"pip command ({expected_hint}) so a caller can copy-paste the fix"
    )


def test_missing_radare2_error_says_to_put_it_on_path() -> None:
    """r2 is a system binary, not a pip package — the fix is PATH or the knob."""
    client = R2Client()
    client.executable = None
    with pytest.raises(R2Error) as caught:
        client.run(Path("/nonexistent"), ["ij"])
    assert caught.value.code == "capability_unavailable"
    message = str(caught.value)
    assert "PATH" in message, message
    assert "HEADLESS_RE_R2" in message, message
    assert "pip install" not in message, (
        "radare2 cannot be pip-installed; suggesting pip would send the user down a dead end"
    )


# ---------------------------------------------------------------------------
# The "not configured" family: system tools resolved by config.py from a
# HEADLESS_RE_* knob (or PATH). Their messages must name the knob — "apktool
# is not configured" alone tells the caller nothing about *where* to
# configure it.
# ---------------------------------------------------------------------------


def _raise_jadx() -> None:
    from headless_re_mcp.backends.jadx.client import JadxClient

    JadxClient(None)._run(Path("ignored.apk"), [], Path("out"), timeout=10.0)


def _raise_apktool() -> None:
    from headless_re_mcp.backends.apktool.client import ApktoolClient

    ApktoolClient(None, None).decode(Path("ignored.apk"), Path("out"))


def _raise_apksigner() -> None:
    from headless_re_mcp.backends.apktool.client import ApktoolClient

    ApktoolClient(None, None).sign(Path("ignored.apk"), Path("out.apk"))


def _raise_ghidra() -> None:
    from headless_re_mcp.backends.ghidra.client import GhidraClient

    GhidraClient(home=None).analyze_binary(Path("ignored.bin"), Path("proj"))


def _raise_webcrack() -> None:
    from headless_re_mcp.backends.jsre.client import JsClient

    JsClient(None)._require_input(Path("ignored.js"))


def _raise_wabt() -> None:
    from headless_re_mcp.backends.jsre.client import WasmClient

    WasmClient(None)._require_input(Path("ignored.wasm"), None, "wasm2wat")


_KNOB_CASES = [
    pytest.param(_raise_jadx, "HEADLESS_RE_JADX", id="jadx"),
    pytest.param(_raise_apktool, "HEADLESS_RE_APKTOOL", id="apktool"),
    pytest.param(_raise_apksigner, "HEADLESS_RE_APKSIGNER", id="apksigner"),
    pytest.param(_raise_ghidra, "HEADLESS_RE_GHIDRA_HOME", id="ghidra"),
    pytest.param(_raise_webcrack, "HEADLESS_RE_WEBCRACK", id="webcrack"),
    pytest.param(_raise_wabt, "HEADLESS_RE_WABT", id="wabt"),
]


@pytest.mark.parametrize(("trigger", "knob"), _KNOB_CASES)
def test_not_configured_error_names_the_operator_knob(trigger: object, knob: str) -> None:
    with pytest.raises(RuntimeError) as caught:
        trigger()  # type: ignore[operator]
    assert getattr(caught.value, "code", None) == "capability_unavailable"
    message = str(caught.value)
    assert knob in message, (
        f"the not-configured message must name the {knob} knob so the caller "
        f"knows where to point the tool; got: {message}"
    )


# ---------------------------------------------------------------------------
# doctor is the readiness surface for the same dependencies; its MISSING
# probes carry the same remediation in the first-class Probe.remediation
# field (the IDA / x64dbg / Scylla probes set the house style).
# ---------------------------------------------------------------------------


def test_doctor_missing_python_module_probe_names_the_pip_extra(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import importlib.util

    from headless_re_mcp import doctor

    monkeypatch.setattr(importlib.util, "find_spec", lambda module: None)
    for module, extra in (
        ("frida", "android"),
        ("adbutils", "android"),
        ("androguard", "android"),
        ("playwright", "browser"),
        ("mitmproxy", "proxy"),
    ):
        probe = doctor.probe_python_module(module, module)
        assert probe.status == doctor.ProbeStatus.MISSING
        assert probe.remediation == f'pip install "headless-re-mcp[{extra}]"'


def test_doctor_missing_unmapped_module_does_not_guess_a_package_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A module name is not a distribution name; a wrong pip hint is worse than none."""
    import importlib.util

    from headless_re_mcp import doctor

    monkeypatch.setattr(importlib.util, "find_spec", lambda module: None)
    probe = doctor.probe_python_module("nope", "some_unmapped_module")
    assert probe.status == doctor.ProbeStatus.MISSING
    assert probe.remediation is None


def test_doctor_missing_tool_probe_names_path_and_knob(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from types import SimpleNamespace

    from headless_re_mcp import doctor

    monkeypatch.setattr(doctor.shutil, "which", lambda name: None)
    probe = doctor.probe_optional_tool(
        "adb",
        SimpleNamespace(adb=None),  # type: ignore[arg-type]
        "adb",
        ("adb",),
    )
    assert probe.status == doctor.ProbeStatus.MISSING
    assert probe.remediation is not None
    assert "PATH" in probe.remediation
    assert "HEADLESS_RE_ADB" in probe.remediation


def test_doctor_missing_command_probe_says_to_put_it_on_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from headless_re_mcp import doctor

    monkeypatch.setattr(doctor.shutil, "which", lambda name: None)
    probe = doctor.probe_command("java", ("java",))
    assert probe.status == doctor.ProbeStatus.MISSING
    assert probe.remediation is not None
    assert "PATH" in probe.remediation
