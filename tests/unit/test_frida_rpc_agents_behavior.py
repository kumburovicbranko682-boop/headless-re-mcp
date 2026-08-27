"""The Frida RPC agent scripts must produce the shapes the client parses.

``frida.modules`` / ``frida.exports`` / ``frida.java.classes`` / ``frida.java.methods``
each inject an agent (``_ENUM_SCRIPT`` / ``_JAVA_SCRIPT``) and read a specific
JSON shape back over ``script.exports_sync``. That JavaScript carries real logic
-- the page caps, the substring filter, and the class enumeration's throw/catch
sentinel that stops at the limit -- yet it runs *nowhere* in the test suite: the
Python tests stub ``create_script`` and the live gate needs a device. A cap that
paged one item short, a filter that matched nothing, or a rename that broke the
class-cap sentinel would ship green and only surface against a real process.

This drives the shipped agents through a mock Frida runtime under Node (the same
``Java`` / ``Process`` / ``ptr`` globals the target provides, stubbed with
deterministic data) and asserts each RPC export returns exactly the contract the
Python client depends on. ``read`` is intentionally left to the memory-read
tests, which own that path; this pins the enumeration logic those tests do not.

Node ships on the GitHub-hosted runners the unit jobs use; when it is genuinely
absent the check skips with an explicit message rather than passing on nothing.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.frida import client as frida_client

# A mock Frida runtime: the globals an in-process agent expects, filled with
# deterministic data so the enumeration/pagination logic has something to page.
# Indirect eval runs the shipped script in global scope, where it wires
# ``rpc.exports``; the harness then calls one export and prints its JSON result.
_HARNESS = r"""
"use strict";
const fs = require("fs");

function NativePtr(v) { this._v = typeof v === "number" ? v : parseInt(v, 0); }
NativePtr.prototype.toString = function () { return "0x" + this._v.toString(16); };
NativePtr.prototype.readByteArray = function (size) {
  const buf = new ArrayBuffer(size);
  const view = new Uint8Array(buf);
  for (let i = 0; i < size; i++) view[i] = i % 256;
  return buf;
};
global.ptr = function (v) { return new NativePtr(v); };

const MODULES = [];
for (let i = 0; i < 5; i++) {
  MODULES.push({
    name: "m" + i,
    base: new NativePtr(0x1000 + i),
    size: 100 + i,
    path: "/lib/m" + i,
  });
}
const EXPORTS_BY_MODULE = {
  "libc.so": {
    name: "libc.so",
    base: new NativePtr(0xbeef),
    enumerateExports: function () {
      return [
        { name: "e0", address: new NativePtr(0x10), type: "function" },
        { name: "e1", address: new NativePtr(0x20), type: "function" },
        { name: "e2", address: new NativePtr(0x30), type: "variable" },
      ];
    },
  },
};
global.Process = {
  enumerateModules: function () { return MODULES; },
  findModuleByName: function (name) { return EXPORTS_BY_MODULE[name] || null; },
};

const CLASSES = ["com.example.A", "com.example.B", "org.other.C", "com.example.D"];
const METHODS_BY_CLASS = { Loaded: ["ma", "mb", "mc", "md"] };
global.Java = {
  perform: function (fn) { fn(); },
  enumerateLoadedClasses: function (cb) {
    for (const name of CLASSES) cb.onMatch(name);
    cb.onComplete();
  },
  use: function (className) {
    if (!(className in METHODS_BY_CLASS)) throw new Error("class not loaded: " + className);
    const methods = METHODS_BY_CLASS[className].map(function (m) {
      return { toString: function () { return m; } };
    });
    return { class: { getDeclaredMethods: function () { return methods; } } };
  },
};
global.send = function () {};
global.rpc = {};

const src = fs.readFileSync(process.argv[2], "utf8");
(0, eval)(src);

const exportName = process.argv[3];
const args = JSON.parse(process.argv[4] || "[]");
const result = global.rpc.exports[exportName].apply(null, args);
process.stdout.write(JSON.stringify(result));
"""


def _node() -> str | None:
    return shutil.which("node")


@pytest.fixture(scope="module")
def harness(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    root = tmp_path_factory.mktemp("frida_rpc")
    paths = {
        "harness": root / "harness.js",
        "enum": root / "enum_agent.js",
        "java": root / "java_agent.js",
    }
    paths["harness"].write_text(_HARNESS, encoding="utf-8")
    # The real shipped agents, not a copy: a change to either is what this guards.
    paths["enum"].write_text(frida_client._ENUM_SCRIPT, encoding="utf-8")
    paths["java"].write_text(frida_client._JAVA_SCRIPT, encoding="utf-8")
    return paths


def _invoke(harness: dict[str, Path], script: str, export: str, args: list[Any]) -> Any:
    node = _node()
    if node is None:
        pytest.skip("node not found — Frida RPC agent behavior not run (skip != pass)")
    completed = subprocess.run(
        [node, str(harness["harness"]), str(harness[script]), export, json.dumps(args)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, (
        f"agent {script}.{export}{args} threw under the mock runtime:\n{completed.stderr.strip()}"
    )
    return json.loads(completed.stdout)


def test_modules_pages_to_the_cap_and_reports_the_true_total(harness: dict[str, Path]) -> None:
    """frida.modules pages on cap; the client reads total to know it stopped."""
    capped = _invoke(harness, "enum", "modules", [2])
    assert [m["name"] for m in capped["modules"]] == ["m0", "m1"]
    assert capped["total"] == 5
    # Each module carries the fields the client copies out verbatim.
    assert set(capped["modules"][0]) == {"name", "base", "size", "path"}
    assert capped["modules"][0]["base"] == "0x1000"

    whole = _invoke(harness, "enum", "modules", [100])
    assert len(whole["modules"]) == 5
    assert whole["total"] == 5


def test_exports_reports_found_and_pages_the_table(harness: dict[str, Path]) -> None:
    found = _invoke(harness, "enum", "exports", ["libc.so", 2])
    assert found["found"] is True
    assert found["module"] == "libc.so"
    assert found["base"] == "0xbeef"
    assert [e["name"] for e in found["exports"]] == ["e0", "e1"]
    assert set(found["exports"][0]) == {"name", "address", "type"}


def test_exports_reports_a_missing_module_as_not_found(harness: dict[str, Path]) -> None:
    """found=false with an empty list means the module was not mapped, not that
    it exports nothing -- the client keys its ``found`` flag off exactly this."""
    missing = _invoke(harness, "enum", "exports", ["missing.so", 5])
    assert missing["found"] is False
    assert missing["exports"] == []


def test_classes_returns_every_loaded_class_by_default(harness: dict[str, Path]) -> None:
    everything = _invoke(harness, "java", "classes", [None, 100])
    assert everything == ["com.example.A", "com.example.B", "org.other.C", "com.example.D"]


def test_classes_applies_the_substring_filter(harness: dict[str, Path]) -> None:
    filtered = _invoke(harness, "java", "classes", ["com.example", 100])
    assert filtered == ["com.example.A", "com.example.B", "com.example.D"]


def test_classes_stops_at_the_limit_via_the_sentinel(harness: dict[str, Path]) -> None:
    """The class enumeration cannot return early from onMatch, so it throws a
    sentinel to stop at the cap and swallows only that sentinel. A limit that
    over-ran (or a sentinel rename that let a real error escape) would break the
    only bound on an enumeration that can list tens of thousands of classes."""
    capped = _invoke(harness, "java", "classes", [None, 2])
    assert capped == ["com.example.A", "com.example.B"]


def test_methods_reports_found_and_pages(harness: dict[str, Path]) -> None:
    loaded = _invoke(harness, "java", "methods", ["Loaded", 3])
    assert loaded["found"] is True
    assert loaded["methods"] == ["ma", "mb", "mc"]


def test_methods_reports_an_unloaded_class_as_not_found(harness: dict[str, Path]) -> None:
    absent = _invoke(harness, "java", "methods", ["NotLoaded", 5])
    assert absent["found"] is False
    assert absent["methods"] == []
