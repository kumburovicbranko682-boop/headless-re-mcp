"""Android text/list outputs must fit the transport budget by their encoded size.

apk.manifest, adb logcat, and adb packages were capped by raw character or row
count only, not by the JSON-encoded size the transport actually measures. A
quote-heavy manifest, a quote-heavy logcat, or a list of maximum-length package
names can each encode past the 262144-byte result budget even at the character/
row cap, and bounded_tool_result then discards the whole reply for a ~16 KiB
summary. These tests drive real oversized outputs through the real budget.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.adb.client import AdbBackend
from headless_re_mcp.backends.apk.client import _MAX_MANIFEST_CHARS, ApkClient
from headless_re_mcp.backends.common.json_budget import RESULT_BUDGET_BYTES


def _encoded_size(payload: dict[str, Any]) -> int:
    return len(json.dumps(payload, ensure_ascii=False).encode("utf-8"))


class _ManifestBody:
    def __init__(self, xml: bytes) -> None:
        self._xml = xml

    def get_xml(self) -> bytes:
        return self._xml


class _FakeApk:
    def __init__(self, xml: bytes) -> None:
        self._xml = xml

    def get_android_manifest_axml(self) -> _ManifestBody:
        return _ManifestBody(self._xml)

    def get_package(self) -> str:
        return "com.example.app"


def test_manifest_quote_heavy_xml_is_trimmed_to_the_encoded_budget(
    tmp_path: Path, monkeypatch: Any
) -> None:
    # A real AndroidManifest is dense with attribute quotes; each " becomes \"
    # when JSON-encoded, so even the 200k-char char cap can encode past the
    # budget. An all-quote body makes that unambiguous: ~200k chars encode to
    # ~400k bytes, so fit_json_text must trim below the char cap.
    xml = ('"' * (_MAX_MANIFEST_CHARS + 50_000)).encode("utf-8")
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _FakeApk(xml))

    payload = client.manifest(tmp_path / "app.apk")

    assert payload["truncated"] is True
    assert 0 < len(payload["manifest_xml"]) < _MAX_MANIFEST_CHARS
    assert payload["package"] == "com.example.app"
    assert _encoded_size(payload) <= RESULT_BUDGET_BYTES


class _FakeDev:
    def __init__(self, output: str) -> None:
        self._output = output

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del args, timeout
        return self._output


def _adb_with(output: str, monkeypatch: Any) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: _FakeDev(output)  # type: ignore[method-assign]
    return backend


def test_logcat_budget_cut_keeps_the_newest_lines(monkeypatch: Any) -> None:
    # 1900 quote-heavy lines of ~100 chars: the joined text is under the 200k
    # char cap (so that cap does not fire), but the encoded line array overflows
    # the budget, so the trim must come from the size budget alone. logcat is a
    # most-recent view, so it keeps the newest lines and drops the oldest.
    lines = [f"{index:04d}" + '"' * 96 for index in range(1900)]
    backend = _adb_with("\n".join(lines), monkeypatch)

    payload = backend.logcat("emulator-5554", lines=5000)

    assert payload["truncated"] is True
    assert 0 < len(payload["lines"]) < 1900
    assert payload["lines"][-1].startswith("1899")
    assert not payload["lines"][0].startswith("0000")
    assert _encoded_size(payload) <= RESULT_BUDGET_BYTES


def test_packages_list_is_trimmed_to_the_encoded_budget(monkeypatch: Any) -> None:
    # 1500 packages with 255-char names (the Android maximum), limit 2000: the
    # row cap never fires (1500 < 2000), so has_more must come from the size
    # budget, and the whole list would otherwise be discarded.
    names = [f"com.example.p{index:04d}." + "n" * 235 for index in range(1500)]
    output = "\n".join(f"package:{name}" for name in names)
    backend = _adb_with(output, monkeypatch)

    payload = backend.packages("emulator-5554", limit=2000)

    assert 0 < payload["count"] < 1500
    assert len(payload["packages"]) == payload["count"]
    assert payload["has_more"] is True
    assert _encoded_size(payload) <= RESULT_BUDGET_BYTES
