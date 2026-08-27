"""webcrack bundle-unpack live gate: split a real bundle into its modules.

webcrack's headline capability -- splitting a bundled JavaScript file back into
its individual modules (the ``js.n`` / ``unpack_bundle`` tool) -- had no live
coverage: it only ran against a fake webcrack binary in unit tests. That mock
hid a real bug, which this gate exists to pin down: the client pre-creates the
output directory, but the real webcrack refuses to write into a directory that
already exists unless ``--force`` is passed, so every unpack failed against the
actual CLI while the mock (which does not enforce that) stayed green.

The fixture is a self-contained webpack-style bundle with two modules, so the
unpack runs for real with no network and no bundler toolchain, and the gate
reads the split modules back to prove each one's distinctive payload landed in
its own file with the inter-module require preserved.

Skip != pass: the gate skips with a reason when webcrack (and its Node runtime)
is absent, and runs for real when present. CI installs it, so a skip there is a
genuine regression rather than a bare machine.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre.client import JsClient

# A minimal but genuine webpack runtime: a module map, the __webpack_require__
# shim and an entry call. webcrack recognises this as "Bundle: webpack, modules:
# 2" and splits it. Each module carries a distinctive marker so the assertions
# prove real module separation, not just "some files were written".
_ALPHA_MARKER = "ALPHA_MODULE"
_BETA_MARKER = "BETA_PAYLOAD_XYZ"
_BUNDLE = f"""(() => {{
  var __webpack_modules__ = ({{
    "./a.js": ((module, exports, __webpack_require__) => {{
      const b = __webpack_require__("./b.js");
      module.exports = "{_ALPHA_MARKER}_" + b.betaValue;
    }}),
    "./b.js": ((module, exports) => {{
      exports.betaValue = "{_BETA_MARKER}";
    }})
  }});
  var __webpack_module_cache__ = {{}};
  function __webpack_require__(moduleId) {{
    var cachedModule = __webpack_module_cache__[moduleId];
    if (cachedModule !== undefined) return cachedModule.exports;
    var module = (__webpack_module_cache__[moduleId] = {{ exports: {{}} }});
    __webpack_modules__[moduleId](module, module.exports, __webpack_require__);
    return module.exports;
  }}
  var result = __webpack_require__("./a.js");
  console.log(result);
}})();
"""


def _webcrack_path() -> Path | None:
    found = shutil.which("webcrack")
    if not found:
        return None
    path = Path(found)
    return path if path.exists() else None


@pytest.mark.integration
def test_webcrack_splits_a_bundle_into_modules(tmp_path: Path) -> None:
    webcrack = _webcrack_path()
    if webcrack is None:
        pytest.skip("webcrack not installed — unpack Gate not run (skip != pass)")

    bundle = tmp_path / "bundle.js"
    bundle.write_text(_BUNDLE, encoding="utf-8")

    client = JsClient(webcrack)
    assert client.available

    # out_dir is pre-created on purpose: this is exactly the existing-directory
    # case the real webcrack rejects without --force, so a green here proves the
    # client passes it.
    out_dir = tmp_path / "unpacked"
    out_dir.mkdir()
    result = client.unpack_bundle(bundle, out_dir, timeout=180.0)

    assert not result.get("tool_failed"), result.get("stderr")
    # The two source modules must each be emitted as their own file.
    files = set(result.get("files", []))
    assert "a.js" in files, files
    assert "b.js" in files, files
    assert result.get("file_count", 0) >= 2

    root = Path(result["output_dir"])
    a_src = (root / "a.js").read_text(encoding="utf-8")
    b_src = (root / "b.js").read_text(encoding="utf-8")
    # Each module's distinctive payload landed in its own file...
    assert _ALPHA_MARKER in a_src
    assert _BETA_MARKER in b_src
    # ...and the inter-module dependency survived the split as a require.
    assert "b.js" in a_src
