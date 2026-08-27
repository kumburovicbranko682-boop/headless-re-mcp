"""Live gate: webcrack rebuilds a multi-hop webpack module graph.

The web RE gate already unpacks a bundle, but its fixture is a single hop
(entry -> module 1), which cannot show that webcrack reconstructs a dependency
*chain* and rewrites each hop's require to the right neighbour. A real bundle is
a graph, and the risk is that intermediate edges are dropped or that every
rewritten require points back at the entry rather than the module it actually
imports.

This gate unpacks a three-module bundle with a two-hop transitive chain
(entry -> util -> data) and asserts each module is split into its own file, each
webpack ``__webpack_require__(n)`` is rewritten to a relative CommonJS require of
the *next* module in the chain (entry->./1.js, util->./2.js), and the marker
that only the deepest module exports lands in that leaf file alone -- proving the
transitive dependency was carried to the correct depth, not flattened or lost.
Skips honestly when webcrack is missing. skip != pass.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import JsClient
from headless_re_mcp.core.service import AnalysisService

_MARKER = "deep-marker-transitive-4f8a"

# entry(0) -> util(1) -> data(2): a two-hop chain so require rewriting has to
# preserve an intermediate edge, not just entry -> leaf.
_BUNDLE = """(function (modules) {
  var installedModules = {};
  function __webpack_require__(moduleId) {
    if (installedModules[moduleId]) { return installedModules[moduleId].exports; }
    var module = installedModules[moduleId] = { i: moduleId, l: false, exports: {} };
    modules[moduleId].call(module.exports, module, module.exports, __webpack_require__);
    module.l = true;
    return module.exports;
  }
  __webpack_require__.s = 0;
  return __webpack_require__(0);
})([
  function (module, exports, __webpack_require__) {
    var util = __webpack_require__(1);
    console.log(util.describe());
  },
  function (module, exports, __webpack_require__) {
    var data = __webpack_require__(2);
    exports.describe = function () { return "value=" + data.value; };
  },
  function (module, exports) {
    module.exports = { value: "deep-marker-transitive-4f8a" };
  }
]);
"""


@pytest.mark.integration
def test_js_unpack_rebuilds_a_transitive_module_chain(tmp_path: Path) -> None:
    if not JsClient().available:
        pytest.skip("webcrack not installed — JS bundle graph Gate not run (skip != pass)")

    bundle = tmp_path / "bundle.js"
    bundle.write_text(_BUNDLE, encoding="utf-8")

    service = AnalysisService()
    try:
        result = service.js_unpack_bundle(str(bundle))
        assert result.ok, result.error
        assert result.data is not None
        out_dir = Path(result.data["output_dir"])

        written = {
            p.name: p.read_text(encoding="utf-8", errors="replace")
            for p in out_dir.rglob("*")
            if p.is_file()
        }
        # All three modules are split into their own files.
        for name in ("index.js", "1.js", "2.js"):
            assert name in written, list(written)

        entry = written["index.js"]
        util = written["1.js"]
        leaf = written["2.js"]

        # Each hop's webpack require becomes a relative require of the *next*
        # module -- the intermediate edge (util -> data) is preserved, and the
        # entry points at util, not straight at the leaf.
        assert 'require("./1.js")' in entry, entry
        assert "./2.js" not in entry, entry  # the entry does not know the leaf
        assert 'require("./2.js")' in util, util
        assert "util.describe()" in entry, entry

        # The marker only the deepest module exports lands in the leaf alone,
        # and the leaf is a genuine sink (it requires nothing further).
        assert _MARKER in leaf, leaf
        assert "require(" not in leaf, leaf
        assert _MARKER not in entry and _MARKER not in util, written

        # The synthetic module names are relative, never absolute paths that
        # would leak the unpack directory into the recovered source.
        for name, text in written.items():
            if name.endswith(".js") and name != "deobfuscated.js":
                assert str(out_dir) not in text, (name, text)
    finally:
        service.close_all()
